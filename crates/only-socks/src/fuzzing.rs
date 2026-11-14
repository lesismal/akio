//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use only::{Acceptor, EngineRef, Handler};
use only_core::fuzzing::{conn, split};

use crate::Socks;

/// `socks_request`: a SOCKS5/4/4a server session's handshake parser (greeting, RFC 1929
/// authentication, CONNECT requests with IPv4, IPv6 and domain targets). There is no engine,
/// so every dial fails and name resolution is refused, which ends the session the way a
/// failed upstream does. `data[0]`: bit 0 requires authentication (user `u`, password `p`);
/// `data[1]` splits the reads.
pub fn socks_request(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let mut socks = Socks::new(EngineRef::new());
    if data[0] & 1 == 1 {
        socks = socks.auth(|u, p| u == "u" && p == "p");
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
        let wires: [(u8, &[u8]); 8] = [
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
        ];
        let mut v = Vec::new();
        for (cfg, w) in wires {
            v.push([&[cfg, 0][..], w].concat());
            v.push([&[cfg, 3][..], w].concat());
        }
        v
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "socks_request", socks_request) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds() {
            socks_request(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p only-socks --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "socks_request", &seeds());
    }
}
