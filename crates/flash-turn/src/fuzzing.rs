//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.
//!
//! Datagram inputs are a sequence of packets, each prefixed by its length (`u16`, little
//! endian); see [`packets`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::core::{TurnConfig, TurnCore, TurnEnv};
use crate::static_auth;
use crate::stun::Message;

/// Splits `data` into length-prefixed packets (a truncated last one is taken as it is).
pub fn packets(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let n = usize::from(u16::from_le_bytes([data[0], data[1]])).min(data.len() - 2);
        out.push(&data[2..2 + n]);
        data = &data[2 + n..];
    }
    out
}

/// Prefixes each packet with its length (the inverse of [`packets`]).
pub fn join(pkts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in pkts {
        v.extend_from_slice(&(p.len() as u16).to_le_bytes());
        v.extend_from_slice(p);
    }
    v
}

/// `stun_message`: the STUN parser and every accessor, integrity and fingerprint check.
pub fn stun_message(data: &[u8]) {
    let Ok(m) = Message::parse(data) else {
        return;
    };
    let _ = (m.method(), m.class(), m.transaction_id());
    for t in m.attr_types().collect::<Vec<_>>() {
        let _ = m.get(t);
        let _ = m.get_str(t);
        let _ = m.get_u32(t);
        let _ = m.get_xor_addr(t);
        let _ = m.get_addr(t);
        let _ = m.get_xor_addrs(t);
    }
    let _ = m.error_code();
    let _ = m.check_integrity(b"key");
    let _ = m.check_fingerprint();
    let _ = crate::stun::binding_response(data, ([1, 2, 3, 4], 5).into(), Some("f"));
    let _ = crate::stun::parse_binding_response(data, &m.transaction_id());
}

/// The client the TURN fuzz target speaks as, its user and the realm.
pub const CLIENT: SocketAddr =
    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 4000);
/// The user and password the fuzz server accepts.
pub const USER: (&str, &str) = ("u", "p");
/// The fuzz server's realm.
pub const REALM: &str = "r";

struct NullEnv {
    next_port: u16,
}

impl TurnEnv for NullEnv {
    fn send_to_client(&mut self, _client: SocketAddr, data: &[u8]) {
        stun_message(data);
    }
    fn send_to_peer(&mut self, _relay: SocketAddr, _peer: SocketAddr, _data: &[u8]) {}
    fn open_relay(&mut self, _client: SocketAddr, ip: IpAddr) -> io::Result<SocketAddr> {
        self.next_port = self.next_port.wrapping_add(1);
        if self.next_port % 5 == 0 {
            return Err(io::Error::other("no ports"));
        }
        Ok(SocketAddr::new(ip, 50000 + self.next_port))
    }
    fn close_relay(&mut self, _relay: SocketAddr) {}
}

/// A deterministic server (fixed nonce key and clock), so seeds can carry valid nonces.
pub fn turn_core(start: Instant) -> TurnCore {
    let cfg = TurnConfig::new(
        REALM,
        static_auth(REALM, [USER]),
        "192.0.2.1".parse().expect("ip"),
    )
    .allow_private_peers(true);
    let mut c = TurnCore::new(cfg);
    c.fuzz_reset(start);
    c
}

/// `turn_server`: a TURN server fed datagrams. Each packet's first byte picks the source: even
/// from the client, odd from peer `10.0.0.(b/2)` to the first relay, and `0xff` advances the
/// clock by a minute (then sweeps).
pub fn turn_server(data: &[u8]) {
    let start = Instant::now();
    let mut core = turn_core(start);
    let mut env = NullEnv { next_port: 0 };
    let mut now = start;
    for p in packets(data) {
        let Some((&sel, body)) = p.split_first() else {
            continue;
        };
        if sel == 0xff {
            now += Duration::from_secs(60);
            core.handle_timeout(now, &mut env);
        } else if sel % 2 == 0 {
            core.handle_client(now, CLIENT, body, &mut env);
        } else {
            let peer = SocketAddr::new(IpAddr::V4([10, 0, 0, sel / 2].into()), 7000);
            let relay = SocketAddr::new("192.0.2.1".parse().expect("ip"), 50001);
            core.handle_peer(now, relay, peer, body, &mut env);
        }
    }
}

#[cfg(test)]
pub(crate) mod seeds {
    use super::*;
    use crate::stun::{Class, MessageBuilder, Method, attr, long_term_key, transaction_id};

    pub(crate) fn stun_message() -> Vec<Vec<u8>> {
        let tid = [7u8; 12];
        let key = long_term_key("u", "r", "p");
        vec![
            crate::stun::binding_request(tid),
            MessageBuilder::new(Method::ALLOCATE, Class::Request, tid)
                .u32(attr::REQUESTED_TRANSPORT, 17 << 24)
                .attr(attr::USERNAME, b"u")
                .attr(attr::REALM, b"r")
                .attr(attr::NONCE, b"n")
                .integrity(&key)
                .fingerprint()
                .build(),
            MessageBuilder::new(Method::CREATE_PERMISSION, Class::Error, tid)
                .error(401, "Unauthorized")
                .xor_addr(
                    attr::XOR_PEER_ADDRESS,
                    "[2001:db8::1]:9".parse().expect("addr"),
                )
                .addr(attr::MAPPED_ADDRESS, "1.2.3.4:5".parse().expect("addr"))
                .build(),
        ]
    }

    /// A full session: challenge, allocate, permission, channel, send, channel data, peer data.
    pub(crate) fn turn_server() -> Vec<Vec<u8>> {
        let start = Instant::now();
        let core = turn_core(start);
        let nonce = core.fuzz_nonce(start, CLIENT);
        let key = long_term_key(USER.0, REALM, USER.1);
        let auth = |b: MessageBuilder| {
            b.attr(attr::USERNAME, USER.0.as_bytes())
                .attr(attr::REALM, REALM.as_bytes())
                .attr(attr::NONCE, nonce.as_bytes())
                .integrity(&key)
                .fingerprint()
                .build()
        };
        let peer: SocketAddr = "10.0.0.1:7000".parse().expect("addr");
        let req = |m| MessageBuilder::new(m, Class::Request, transaction_id());
        let mut cd = vec![0x40, 0x00, 0x00, 0x03];
        cd.extend_from_slice(b"abc");
        let pkts = vec![
            [&[0u8][..], &crate::stun::binding_request(transaction_id())].concat(),
            [
                &[0u8][..],
                &req(Method::ALLOCATE)
                    .u32(attr::REQUESTED_TRANSPORT, 17 << 24)
                    .build(),
            ]
            .concat(),
            [
                &[0u8][..],
                &auth(req(Method::ALLOCATE).u32(attr::REQUESTED_TRANSPORT, 17 << 24)),
            ]
            .concat(),
            [
                &[0u8][..],
                &auth(req(Method::CREATE_PERMISSION).xor_addr(attr::XOR_PEER_ADDRESS, peer)),
            ]
            .concat(),
            [
                &[0u8][..],
                &auth(
                    req(Method::CHANNEL_BIND)
                        .u32(attr::CHANNEL_NUMBER, 0x4000 << 16)
                        .xor_addr(attr::XOR_PEER_ADDRESS, peer),
                ),
            ]
            .concat(),
            [
                &[0u8][..],
                &MessageBuilder::new(Method::SEND, Class::Indication, transaction_id())
                    .xor_addr(attr::XOR_PEER_ADDRESS, peer)
                    .attr(attr::DATA, b"hello")
                    .build(),
            ]
            .concat(),
            [&[0u8][..], &cd].concat(),
            [&[3u8][..], b"from peer"].concat(),
            [
                &[0u8][..],
                &auth(req(Method::REFRESH).u32(attr::LIFETIME, 0)),
            ]
            .concat(),
            vec![0xff],
        ];
        vec![join(&pkts)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flash_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        let n = replay(DIR, "stun_message", stun_message) + replay(DIR, "turn_server", turn_server);
        assert!(n > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds::stun_message() {
            stun_message(s);
        }
        for s in &seeds::turn_server() {
            turn_server(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p flash-turn --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "stun_message", &seeds::stun_message());
        write_target_seeds(DIR, "turn_server", &seeds::turn_server());
    }
}
