//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use only::{Acceptor, EngineRef, Handler};
use only_core::fuzzing::{conn, split};

use crate::{Destinations, Socks};

/// `socks_client`: the client side: the SOCKS5/4/4a handshake parsing the proxy's replies
/// (method choice, RFC 1929 status, one or two replies with every address type) both bare and
/// as the proxy tunnel transport the HTTP/WebSocket clients and `SocksClient::dial` use, the
/// UDP datagram header, and UDP fragment reassembly. `data[0]`: bits 0-1 the version (5, 4,
/// 4a), bits 2-3 the command (CONNECT, BIND, UDP ASSOCIATE), bit 4 credentials, bit 5 GSS-API
/// with the toy mechanism (`only_ws::gss::toy`, secret 0x42) and bits 6-7 the protection asked
/// for (none, integrity, confidentiality); `data[1]`
/// splits the proxy's bytes. The bytes after `data[0]` are also read as datagrams (a length
/// byte, a clock step byte, then the datagram) fed to one reassembly queue, and each is opened
/// as a GSS-API protected datagram (RFC 1961 §5, toy mechanism).
pub fn socks_client(data: &[u8]) {
    use only_ws::{
        proxy::{Connect, Refusal},
        socks::{Cmd, Handshake, Target, Version},
    };
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let version = match cfg & 3 {
        1 => Version::Socks4,
        2 => Version::Socks4a,
        _ => Version::Socks5,
    };
    let cmd = match (cfg >> 2) & 3 {
        0 => Cmd::Connect,
        1 => Cmd::Bind,
        _ => Cmd::UdpAssociate,
    };
    let auth = (cfg & 16 != 0).then_some(("u", "p"));
    let target = if version == Version::Socks4 {
        Target::Addr(([1, 2, 3, 4], 80).into())
    } else {
        Target::Name("example.com".into(), 80)
    };
    let h = Handshake::new(version, cmd, target, auth).and_then(|h| {
        // Bit 5: GSS-API with the toy mechanism; bits 6-7 the protection asked for.
        if cfg & 32 == 0 {
            return Ok(h);
        }
        let want = match cfg >> 6 {
            0 => crate::gssapi::Protection::None,
            1 => crate::gssapi::Protection::Integrity,
            _ => crate::gssapi::Protection::Confidentiality,
        };
        let f: only_ws::gss::GssFactory = std::sync::Arc::new(|_: &str| {
            Ok(Box::new(only_ws::gss::toy::Toy::initiator("fuzz", 0x42))
                as Box<dyn crate::gssapi::GssContext>)
        });
        h.gssapi(f, "proxy", want)
    });
    if let Ok(h) = h {
        // Bare: consumed counts stay within what was given, tunnel bytes only after the end.
        let mut bare = h.clone();
        let mut out = Vec::new();
        bare.start(&mut out);
        'feed: for p in split(rest) {
            let mut p = p;
            loop {
                if bare.is_done() {
                    break 'feed;
                }
                match bare.feed(p, &mut out) {
                    Ok((n, reply)) => {
                        assert!(n <= p.len());
                        p = &p[n..];
                        // GSS-API steps, inline; then what was buffered meanwhile.
                        while let Some(job) = bare.take_gss_job() {
                            if bare.gss_done(job.run(), &mut out).is_err()
                                || bare.feed(&[], &mut out).is_err()
                            {
                                break 'feed;
                            }
                        }
                        if reply.is_none() || p.is_empty() {
                            break;
                        }
                    }
                    Err(_) => break 'feed,
                }
            }
        }
        // As the tunnel transport: nothing reaches the application before the tunnel opens.
        let c = Connect::socks(
            Ok(h),
            Refusal::default(),
            only::fn_acceptor(|_c: &only::Conn<Nop>| Nop),
        );
        if let Some(mut t) = c.transport() {
            let (mut plain, mut wire) = (Vec::new(), Vec::new());
            let _ = t.recv(&[], &mut plain, &mut wire);
            for p in split(rest) {
                let was_open = !t.handshaking();
                if t.recv(p, &mut plain, &mut wire).is_err() {
                    break;
                }
                if !was_open && t.handshaking() {
                    assert!(plain.is_empty());
                }
            }
        }
    }
    // Datagrams through one reassembly queue; each also as a GSS-API protected datagram.
    let gss = crate::gssapi::DatagramGss::new(
        std::sync::Arc::new(std::sync::Mutex::new(
            Box::new(only_ws::gss::toy::Toy::acceptor(0x42)) as Box<dyn crate::gssapi::GssContext>,
        )),
        crate::gssapi::Protection::Integrity,
    );
    let mut r = crate::frag::Reassembly::default();
    let mut now = std::time::Instant::now();
    let mut d = rest;
    while let [len, step, tail @ ..] = d {
        let n = usize::from(*len).min(tail.len());
        let (dgram, next) = tail.split_at(n);
        d = next;
        now += std::time::Duration::from_millis(u64::from(*step) * 40);
        if let Ok(inner) = gss.open(dgram) {
            let _ = crate::udp::parse_header(&inner);
        }
        if let Some((frag, dest, h)) = crate::udp::parse_header(dgram) {
            if let crate::frag::Frag::Complete(_, whole) = r.push(now, frag, &dest, &dgram[h..]) {
                assert!(whole.len() <= crate::frag::MAX_DATAGRAM);
            }
        }
    }
}

struct Nop;

impl Handler for Nop {
    fn on_data(&mut self, _c: &only::Conn<Self>, _d: &[u8]) {}
}

/// `socks_request`: a SOCKS5/4/4a server session's handshake parser (greeting, RFC 1929
/// authentication, CONNECT / BIND / UDP ASSOCIATE requests with IPv4, IPv6 and domain targets,
/// the access-control hook) and the UDP ASSOCIATE datagram header parser. There is no engine,
/// so every dial, bind and association fails and name resolution is refused, which ends the
/// session the way a failed upstream does. `data[0]`: bit 0 requires authentication (user
/// `u`, password `p`), bit 1 enables BIND and UDP ASSOCIATE, bit 2 sets a hook refusing port
/// 0; `data[1]` splits the reads. The bytes after `data[0]` are also parsed as a UDP datagram
/// header, whose address must round-trip.
pub fn socks_request(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    // Any destination, so loopback seeds reach the dial path as before.
    let mut socks = Socks::new(EngineRef::new()).destinations(Destinations::Any);
    if data[0] & 1 == 1 {
        socks = socks.auth(|u, p| u == "u" && p == "p");
    }
    if data[0] & 2 == 2 {
        socks = socks.bind(true).udp_associate(true);
    }
    if data[0] & 4 == 4 {
        socks = socks.allow(|r| r.dest().port() != 0);
    }
    if let Some((_, crate::Dest::Addr(a), n)) = crate::udp::parse_header(&data[1..]) {
        let mut h = Vec::new();
        crate::udp::push_header(&mut h, a);
        assert_eq!(h[3..], data[1..][3..n]);
    }
    let c = conn();
    let mut s = socks.on_open(&c);
    for p in split(&data[1..]) {
        s.on_data(&c, p);
    }
    s.on_close(&c, None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn seeds() -> Vec<Vec<u8>> {
        let wires: [(u8, &[u8]); 13] = [
            (0, &[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80]),
            (
                0,
                &[
                    5, 2, 0, 2, 5, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187,
                ],
            ),
            (0, b"\x05\x01\x00\x05\x01\x00\x03\x0bexample.com\x00\x50"),
            (
                1,
                b"\x05\x01\x02\x01\x01u\x01p\x05\x01\x00\x01\x0a\x00\x00\x01\x1f\x90",
            ),
            (1, b"\x05\x01\x02\x01\x01x\x01y"),
            (0, b"\x04\x01\x00\x50\x7f\x00\x00\x01user\x00"),
            (0, b"\x04\x01\x00\x50\x00\x00\x00\x01\x00example.com\x00"),
            (0, &[5, 1, 0, 5, 2, 0, 9, 1, 2, 3, 4, 0, 1]),
            // BIND and UDP ASSOCIATE (enabled, then refused by the hook, then disabled).
            (2, &[5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 0, 21]),
            (2, &[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0]),
            (6, &[5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0]),
            (
                0,
                &[
                    5, 1, 0, 5, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            ),
            // A UDP datagram header (FRAG 0, a domain destination) as the whole input.
            (2, b"\x00\x00\x00\x03\x0bexample.com\x00\x35data"),
        ];
        let mut v = Vec::new();
        for (cfg, w) in wires {
            v.push([&[cfg, 0][..], w].concat());
            v.push([&[cfg, 3][..], w].concat());
        }
        v
    }

    /// `socks_client` seeds: a configuration byte, a split byte, the proxy's bytes.
    fn client_seeds() -> Vec<Vec<u8>> {
        let wires: [(u8, &[u8]); 9] = [
            // SOCKS5 CONNECT: method, reply with IPv4, tunnel bytes.
            (0, &[5, 0, 5, 0, 0, 1, 10, 0, 0, 1, 0, 80, b'h', b'i']),
            // With authentication, an IPv6 reply.
            (
                16,
                &[
                    5, 2, 1, 0, 5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187,
                ],
            ),
            // BIND: two replies, the second with a name.
            (
                4,
                b"\x05\x00\x05\x00\x00\x01\x0a\x00\x00\x01\x04\x00\x05\x00\x00\x03\x04peer\x00\x15",
            ),
            // UDP ASSOCIATE.
            (8, &[5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 4, 56]),
            // Refusals: no method, failed authentication, reply 5.
            (0, &[5, 0xff]),
            (16, &[5, 2, 1, 1]),
            (0, &[5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0]),
            // SOCKS4 and 4a BIND.
            (1, &[0, 0x5a, 0, 0, 0, 0, 0, 0, b'x']),
            (6, &[0, 0x5a, 4, 0, 1, 2, 3, 4, 0, 0x5a, 4, 1, 1, 2, 3, 5]),
        ];
        let mut v = Vec::new();
        for (cfg, w) in wires {
            v.push([&[cfg, 0][..], w].concat());
            v.push([&[cfg, 3][..], w].concat());
        }
        // Fragments as datagrams (length, clock step, datagram): 1, 2, end; then a gap.
        let mut frags = vec![0u8];
        for (f, step, p) in [
            (1u8, 0u8, &b"ab"[..]),
            (2, 1, b"cd"),
            (0x83, 1, b"e"),
            (1, 200, b"x"),
            (0x83, 0, b"z"),
        ] {
            let mut d = vec![0, 0, f, 1, 10, 0, 0, 1, 0, 53];
            d.extend_from_slice(p);
            frags.push(d.len() as u8);
            frags.push(step);
            frags.extend_from_slice(&d);
        }
        v.push(frags);
        v
    }

    #[test]
    fn gssapi_seeds_open_a_protected_tunnel() {
        use only_ws::socks::{Cmd, Handshake, Target, Version};
        for (name, want) in [
            (
                "seed-gssapi-integrity",
                crate::gssapi::Protection::Integrity,
            ),
            (
                "seed-gssapi-confidentiality",
                crate::gssapi::Protection::Confidentiality,
            ),
        ] {
            let data =
                std::fs::read(format!("{DIR}/../../fuzz/corpus/socks_client/{name}")).unwrap();
            let f: only_ws::gss::GssFactory = std::sync::Arc::new(|_: &str| {
                Ok(Box::new(only_ws::gss::toy::Toy::initiator("fuzz", 0x42))
                    as Box<dyn crate::gssapi::GssContext>)
            });
            let mut h = Handshake::new(
                Version::Socks5,
                Cmd::Connect,
                Target::Name("example.com".into(), 80),
                None,
            )
            .unwrap()
            .gssapi(f, "proxy", want)
            .unwrap();
            let mut out = Vec::new();
            h.start(&mut out);
            // One read: what follows the reply here came while a step was pending, which a
            // proxy cannot do (it waits for the request); the handshake drops it.
            let mut p = &data[2..];
            while !h.is_done() {
                let (n, _) = h.feed(p, &mut out).unwrap();
                p = &p[n..];
                while let Some(job) = h.take_gss_job() {
                    h.gss_done(job.run(), &mut out).unwrap();
                }
            }
            let (_, level, _) = h.take_protection().unwrap();
            assert_eq!(level, want);
        }
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "socks_request", socks_request) > 0);
        assert!(replay(DIR, "socks_client", socks_client) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            socks_request(s);
        }
        for s in &client_seeds() {
            socks_client(s);
        }
    }

    /// Regenerates the `socks_client` seeds:
    /// `cargo test -p only-socks --lib write_client_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_client_fuzz_seeds() {
        write_target_seeds(DIR, "socks_client", &client_seeds());
    }

    /// Regenerates the seed files: `cargo test -p only-socks --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "socks_request", &seeds());
    }
}
