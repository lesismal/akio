//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::sync::{Arc, Mutex};

use akio_core::fuzzing::{conn_inner, split};
use akio_core::{Acceptor, Conn, DynAcceptor, Handler};

use crate::{Decision, Mux, Rule};

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

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "mux_sniff", mux_sniff) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            mux_sniff(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p akio-mux --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "mux_sniff", &seeds());
    }
}
