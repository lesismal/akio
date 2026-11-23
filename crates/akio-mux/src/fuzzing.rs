//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::sync::{Arc, Mutex};

use akio_core::fuzzing::{conn_inner, split};
use akio_core::{Acceptor, Conn, DynAcceptor, Handler};

use crate::proxy::{self, ProxyError, ProxyHeader, ProxyProtocol};
use crate::{ClientHello, Decision, Mux, Rule, SniMatcher, tls};

type Log = Arc<Mutex<Vec<(usize, Vec<u8>)>>>;

struct Rec(usize, Log);

impl Acceptor for Rec {
    type Handler = RecConn;
    fn on_open(&self, _c: &Conn<RecConn>) -> RecConn {
        RecConn(self.0, self.1.clone())
    }
}

struct RecConn(usize, Log);

impl Handler for RecConn {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        self.1
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((self.0, data.to_vec()));
    }
}

fn rules() -> Vec<Rule> {
    vec![
        Rule::Tls,
        Rule::Http2,
        Rule::Http1,
        Rule::Http,
        Rule::Socks5,
        Rule::Socks4,
        Rule::Prefix(b"SSH-2.0".to_vec()),
        Rule::Custom(Arc::new(|b: &[u8]| {
            match b.iter().position(|&x| x == b'\n') {
                Some(_) => Decision::Yes,
                None if b.len() < 16 => Decision::NeedMore,
                None => Decision::No,
            }
        })),
    ]
}

/// `mux_sniff`: the protocol sniffing rules and the multiplexer. Built-in rules must be
/// consistent as bytes arrive (a decided prefix stays decided); a connection handed to a route
/// must deliver every byte to it exactly once, in order. `data[0]`: bits 0-2 pick which rules are
/// routed (in order), bit 3 adds a fallback, the high bits set `max_sniff`; `data[1]` splits
/// the reads.
pub fn mux_sniff(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let cfg = data[0];
    let wire = &data[2..];
    // Rule consistency on every prefix.
    for r in rules().iter().take(7) {
        let mut decided: Option<Decision> = None;
        for n in 1..=wire.len().min(64) {
            let d = r.decide(&wire[..n]);
            if let Some(prev) = decided {
                assert_eq!(prev, d, "a decided rule changed its mind");
            } else if d != Decision::NeedMore {
                decided = Some(d);
            }
        }
    }
    // The multiplexer.
    let log: Log = Arc::default();
    let all = rules();
    let first = usize::from(cfg & 7);
    let mut mux = Mux::new().max_sniff_bytes(usize::from(cfg >> 4) * 4);
    for (i, r) in all.into_iter().enumerate().skip(first) {
        mux = mux.route(r, Rec(i, log.clone()));
    }
    if cfg & 8 != 0 {
        mux = mux.fallback(Rec(usize::MAX, log.clone()));
    }
    let inner = conn_inner();
    let mut h = mux.on_open(&inner);
    for p in split(&data[1..]) {
        if !inner.is_open() {
            break; // a backend delivers nothing after a close
        }
        h.on_data(p);
    }
    h.on_close(None);
    let got = log.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((route, _)) = got.first() {
        assert!(
            got.iter().all(|(r, _)| r == route),
            "data went to two routes"
        );
        let bytes: Vec<u8> = got.iter().flat_map(|(_, b)| b.iter().copied()).collect();
        assert_eq!(
            bytes, wire,
            "the route did not get exactly the connection's bytes"
        );
    }
}

/// `mux_tls_hello`: the ClientHello parser and the SNI rules. The parse of every prefix is
/// consistent (`Incomplete` until it turns `Ok` or `Invalid` for good, and an `Ok` hello stays
/// the same); a mux routing by SNI delivers every byte once, in order, to one route, and only a
/// matching hello reaches the SNI route. `data[0]` splits the reads.
pub fn mux_tls_hello(data: &[u8]) {
    let Some(wire) = data.get(1..) else {
        return;
    };
    // Prefix consistency (at most 512 prefixes, evenly spread, plus the whole input).
    let step = (wire.len() / 512).max(1);
    let mut state: Option<Result<Option<String>, ()>> = None;
    for n in (1..=wire.len()).filter(|n| n % step == 0 || *n == wire.len()) {
        let r = match tls::parse_client_hello(&wire[..n]) {
            Ok(h) => {
                assert!(h.consumed() <= n);
                if let Some(s) = h.server_name() {
                    assert!(!s.is_empty() && s.len() <= 255 && s.is_ascii());
                }
                Some(Ok(h.server_name().map(str::to_owned)))
            }
            Err(tls::HelloError::Incomplete) => None,
            Err(_) => Some(Err(())),
        };
        match (&state, r) {
            (None, r) => state = r,
            (Some(prev), Some(r)) => assert_eq!(prev, &r, "a decided hello changed"),
            (Some(_), None) => panic!("a decided hello became incomplete"),
        }
    }
    // The multiplexer.
    let log: Log = Arc::default();
    let sni = SniMatcher::new(["a.example", "*.b.example"]);
    let mux = Mux::new()
        .sniff_timeout(None)
        .max_sniff_bytes(4096)
        .route(Rule::TlsSni(sni.clone()), Rec(0, log.clone()))
        .route(
            Rule::TlsHello(Arc::new(|h: &ClientHello<'_>| h.offers_alpn(b"h2"))),
            Rec(1, log.clone()),
        )
        .route(Rule::Tls, Rec(2, log.clone()))
        .fallback(Rec(usize::MAX, log.clone()));
    let inner = conn_inner();
    let mut h = mux.on_open(&inner);
    for p in split(data) {
        if !inner.is_open() {
            break;
        }
        h.on_data(p);
    }
    h.on_close(None);
    let got = log.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((route, _)) = got.first() {
        assert!(
            got.iter().all(|(r, _)| r == route),
            "data went to two routes"
        );
        let bytes: Vec<u8> = got.iter().flat_map(|(_, b)| b.iter().copied()).collect();
        assert_eq!(
            bytes, wire,
            "the route did not get exactly the connection's bytes"
        );
        if *route == 0 {
            let h = tls::parse_client_hello(wire).expect("the SNI route got a hello");
            assert!(sni.matches(h.server_name().expect("with a server name")));
        }
    }
}

type HeaderLog = Arc<Mutex<(Option<Option<ProxyHeader>>, Vec<u8>)>>;

struct HdrRec(HeaderLog);

impl Acceptor for HdrRec {
    type Handler = HdrConn;
    fn on_open(&self, c: &Conn<HdrConn>) -> HdrConn {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).0 = Some(proxy::header(c).cloned());
        HdrConn(self.0.clone())
    }
}

struct HdrConn(HeaderLog);

impl Handler for HdrConn {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .1
            .extend_from_slice(data);
    }
}

/// `proxy_header`: the PROXY protocol parser and listener layer. Parses of growing prefixes are
/// consistent; a parsed header encodes and parses back to itself; the layer attaches exactly
/// the parsed header and replays exactly the bytes after it. `data[0]`: bit 0 allows a missing
/// header, bits 1-2 drop v1 / v2, the high bits set the size limit; `data[1]` splits the reads.
pub fn proxy_header(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let cfg = data[0];
    let wire = &data[2..];
    let step = (wire.len() / 512).max(1);
    let mut state: Option<Result<(ProxyHeader, usize), ()>> = None;
    for n in (1..=wire.len()).filter(|n| n % step == 0 || *n == wire.len()) {
        let r = match ProxyHeader::parse(&wire[..n]) {
            Ok((h, used)) => {
                assert!(used <= n);
                Some(Ok((h, used)))
            }
            Err(ProxyError::Incomplete) => None,
            Err(_) => Some(Err(())),
        };
        match (&state, r) {
            (None, r) => state = r,
            (Some(prev), Some(r)) => assert_eq!(prev, &r, "a decided header changed"),
            (Some(_), None) => panic!("a decided header became incomplete"),
        }
    }
    let parsed = match ProxyHeader::parse(wire) {
        Ok((h, used)) => {
            let enc = h
                .encode(h.version)
                .expect("a parsed header encodes in its version");
            let (back, n) = ProxyHeader::parse(&enc).expect("an encoded header parses");
            assert_eq!(n, enc.len());
            assert_eq!(back, h, "the header did not survive encoding");
            Some((h, used))
        }
        Err(_) => None,
    };
    // The listener layer.
    let log: HeaderLog = Arc::default();
    let max = 16 + usize::from(cfg >> 3) * 64;
    let pp = ProxyProtocol::new(HdrRec(log.clone()))
        .header_timeout(None)
        .allow_missing(cfg & 1 != 0)
        .versions(cfg & 2 == 0, cfg & 4 == 0)
        .max_header_bytes(max);
    let inner = conn_inner();
    let mut h = DynAcceptor::on_open(&pp, &inner);
    for p in split(&data[1..]) {
        if !inner.is_open() {
            break;
        }
        h.on_data(p);
    }
    h.on_close(None);
    let got = log.lock().unwrap_or_else(|p| p.into_inner());
    match &got.0 {
        None => assert!(got.1.is_empty()),
        Some(None) => {
            assert!(cfg & 1 != 0, "no header passed without allow_missing");
            assert_eq!(got.1, wire);
        }
        Some(Some(hdr)) => {
            let (want, used) = parsed
                .as_ref()
                .expect("the layer accepted an invalid header");
            assert_eq!(hdr, want);
            assert!(*used <= max);
            assert_eq!(got.1, wire[*used..]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use akio_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn seeds() -> Vec<Vec<u8>> {
        let wires: [&[u8]; 8] = [
            b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
            &[0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 1, 0],
            &[5, 1, 0],
            &[4, 1, 0, 80, 127, 0, 0, 1, 0],
            b"SSH-2.0-OpenSSH_9.6\r\n",
            b"hello\nworld",
            b"OPTIONS * HTTP/1.1\r\n\r\n",
        ];
        let mut v = Vec::new();
        for w in wires {
            for (c, s) in [(8u8 | 0xf0, 0u8), (0, 1), (3 | 8 | 0x20, 2)] {
                v.push([&[c, s][..], w].concat());
            }
        }
        v
    }

    fn tls_seeds() -> Vec<Vec<u8>> {
        use crate::tls::tests::{hello_msg, records};
        let mut v = Vec::new();
        for (sni, alpn) in [
            (Some("a.example"), &[][..]),
            (Some("x.b.example"), &[&b"h2"[..]][..]),
            (Some("other.example"), &[&b"h2"[..], b"http/1.1"][..]),
            (None, &[&b"http/1.1"[..]][..]),
        ] {
            let msg = hello_msg(sni, alpn);
            for (rec, split) in [(1 << 14, 0u8), (7, 3), (64, 1)] {
                v.push([&[split][..], &records(&msg, rec)].concat());
            }
        }
        v.push(vec![2, 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 1, 0]);
        v
    }

    fn proxy_seeds() -> Vec<Vec<u8>> {
        let a: std::net::SocketAddr = "192.0.2.1:5000".parse().expect("addr");
        let b: std::net::SocketAddr = "[2001:db8::2]:443".parse().expect("addr");
        let wires: Vec<Vec<u8>> = vec![
            b"PROXY TCP4 192.0.2.1 198.51.100.2 51000 443\r\nGET / HTTP/1.1\r\n\r\n".to_vec(),
            b"PROXY TCP6 2001:db8::1 ::1 1 2\r\nhello".to_vec(),
            b"PROXY UNKNOWN\r\n".to_vec(),
            [
                ProxyHeader::proxy(a, a).encode_v2().expect("v2"),
                b"data".to_vec(),
            ]
            .concat(),
            ProxyHeader::proxy(a, b)
                .with_tlv(proxy::tlv::AUTHORITY, "example.com")
                .with_tlv(proxy::tlv::CRC32C, [0; 4])
                .encode_v2()
                .expect("v2"),
            ProxyHeader::local().encode_v2().expect("v2"),
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        ];
        let mut v = Vec::new();
        for w in wires {
            for (c, s) in [(0xf8u8, 0u8), (0x41, 1), (0xff, 5)] {
                v.push([&[c, s][..], &w].concat());
            }
        }
        v
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "mux_sniff", mux_sniff) > 0);
        assert!(replay(DIR, "mux_tls_hello", mux_tls_hello) > 0);
        assert!(replay(DIR, "proxy_header", proxy_header) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            mux_sniff(s);
        }
        for s in &tls_seeds() {
            mux_tls_hello(s);
        }
        for s in &proxy_seeds() {
            proxy_header(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p akio-mux --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "mux_sniff", &seeds());
        write_target_seeds(DIR, "mux_tls_hello", &tls_seeds());
        write_target_seeds(DIR, "proxy_header", &proxy_seeds());
    }
}
