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
    fn open_relay(&mut self, _client: SocketAddr, addr: SocketAddr) -> io::Result<SocketAddr> {
        self.next_port = self.next_port.wrapping_add(1);
        if self.next_port % 7 == 0 {
            return Err(io::Error::other("no ports"));
        }
        let port = if addr.port() == 0 {
            50000 + self.next_port
        } else {
            addr.port()
        };
        Ok(SocketAddr::new(addr.ip(), port))
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

/// `turn_stream`: TURN over a byte stream. The first byte picks the side; the rest is a
/// sequence of length-prefixed reads ([`packets`]).
///
/// - even: the server reads them as one TCP stream ([`FrameReader`](crate::framing::FrameReader)
///   then [`TurnCore`]), as a stream client (ChannelData padded);
/// - odd: a [`Client`](crate::client::Client) over a stream reads them as the server's side
///   (responses, ChannelData, Data indications), sending to a peer and advancing its clock
///   between reads.
pub fn turn_stream(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let start = Instant::now();
    let mut reader = crate::framing::FrameReader::new();
    if mode % 2 == 0 {
        let mut core = turn_core(start);
        let mut env = NullEnv { next_port: 0 };
        for p in packets(rest) {
            let r = reader.push(p, |m| core.handle_client(start, CLIENT, m, &mut env));
            assert!(reader.buffered() < crate::framing::MAX_FRAME);
            if r.is_err() {
                return;
            }
        }
        core.remove_client(CLIENT, &mut env);
        assert_eq!(core.stats().allocations, 0);
    } else {
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("addr");
        let cfg = crate::client::ClientConfig::new(server, USER.0, USER.1).stream(true);
        let mut c = crate::client::Client::new(cfg, start);
        let mut now = start;
        let peer: SocketAddr = "203.0.113.1:9".parse().expect("addr");
        for p in packets(rest) {
            let r = reader.push(p, |m| {
                if let Some((from, d)) = c.handle_input(now, m) {
                    assert!(d.len() <= m.len());
                    let _ = from;
                }
            });
            if r.is_err() {
                return;
            }
            let _ = c.send_to(now, peer, p);
            now += Duration::from_secs(7);
            c.handle_timeout(now);
            while c.poll_transmit().is_some() {}
            while c.poll_event().is_some() {}
            assert!(c.pending_bytes() <= c.config().max_pending);
        }
    }
}

/// The DTLS configuration of the `turn_dtls` server (a certificate made once per process).
fn dtls_config() -> std::sync::Arc<only_dtls::Config> {
    static CFG: std::sync::OnceLock<std::sync::Arc<only_dtls::Config>> =
        std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let id = only_dtls::Identity::generate_self_signed().expect("identity");
        std::sync::Arc::new(
            only_dtls::Config::new(id)
                .with_versions(vec![only_dtls::Version::Dtls13, only_dtls::Version::Dtls12])
                .with_hello_verify(false)
                .with_require_client_certificate(false),
        )
    })
    .clone()
}

/// `turn_dtls`: TURN over DTLS on the server side: datagrams into a client's DTLS session
/// (cookies, handshake, records), whose application data goes to a [`TurnCore`]. The first
/// byte picks the start: even, ClientHellos must bring a valid cookie (as on the listener);
/// odd, a connection exists already (as if the cookie had been checked), so handshakes get
/// further. A packet `0xff` advances the clock by a second and runs the timers.
pub fn turn_dtls(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let start = Instant::now();
    let verifier = std::sync::Arc::new(only_dtls::HelloVerifier::new(start).expect("verifier"));
    let mut s = crate::dtls::DtlsSession::new(dtls_config(), verifier, b"10.0.0.1:4000".to_vec());
    if mode % 2 == 1 {
        s.fuzz_accept(start);
    }
    let mut core = turn_core(start);
    let mut env = NullEnv { next_port: 0 };
    let mut now = start;
    for p in packets(rest) {
        let mut out = crate::dtls::DtlsOutput::default();
        if p == [0xff] {
            now += Duration::from_secs(1);
            s.handle_timeout(now, &mut out);
        } else {
            s.input(now, p, &mut out);
        }
        if out.restarted {
            core.remove_client(CLIENT, &mut env);
        }
        for m in &out.messages {
            core.handle_client(now, CLIENT, m, &mut env);
            let mut sealed = Vec::new();
            s.seal(m, &mut sealed);
        }
        if out.closed {
            core.remove_client(CLIENT, &mut env);
            assert!(!s.is_connected());
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

    /// First flights of DTLS 1.2 and 1.3 clients (with the cookie-less and the accepted start),
    /// a junk record and a timer tick.
    pub(crate) fn turn_dtls() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for versions in [
            vec![only_dtls::Version::Dtls12],
            vec![only_dtls::Version::Dtls13, only_dtls::Version::Dtls12],
        ] {
            let cfg = only_dtls::Config::without_identity().with_versions(versions);
            let mut c = only_dtls::Connection::client(std::sync::Arc::new(cfg), Instant::now())
                .expect("client");
            let mut pkts = Vec::new();
            while let Some(d) = c.poll_transmit() {
                pkts.push(d);
            }
            pkts.push(b"\x17\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x01\x00\x03abc".to_vec());
            pkts.push(vec![0xff]);
            for mode in [0u8, 1] {
                out.push([&[mode][..], &join(&pkts)].concat());
            }
        }
        out
    }

    /// The server session above as one stream (client messages only, ChannelData padded),
    /// cut at odd places; and a client fed a challenge and server messages.
    pub(crate) fn turn_stream() -> Vec<Vec<u8>> {
        let mut stream = Vec::new();
        for p in packets(&turn_server()[0]) {
            if p.first() == Some(&0) {
                let mut m = p[1..].to_vec();
                if crate::stun::is_channel_data(&m) {
                    m.resize(m.len() + crate::framing::channel_data_padding(m.len()), 0);
                }
                stream.extend_from_slice(&m);
            }
        }
        let cuts: Vec<Vec<u8>> = stream.chunks(37).map(<[u8]>::to_vec).collect();
        let server_side = [&[0u8][..], &join(&cuts)].concat();
        let tid = [9u8; 12];
        let challenge = MessageBuilder::new(Method::ALLOCATE, Class::Error, tid)
            .error(401, "Unauthorized")
            .attr(attr::REALM, REALM.as_bytes())
            .attr(attr::NONCE, b"0123456789abcdef")
            .build();
        let data = MessageBuilder::new(Method::DATA, Class::Indication, tid)
            .xor_addr(
                attr::XOR_PEER_ADDRESS,
                "203.0.113.1:9".parse().expect("addr"),
            )
            .attr(attr::DATA, b"payload")
            .build();
        let client_side = [
            &[1u8][..],
            &join(&[challenge, data, vec![0x40, 0, 0, 1, 7, 0, 0, 0]]),
        ]
        .concat();
        vec![server_side, client_side]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        let n = replay(DIR, "stun_message", stun_message)
            + replay(DIR, "turn_server", turn_server)
            + replay(DIR, "turn_stream", turn_stream)
            + replay(DIR, "turn_dtls", turn_dtls);
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
        for s in &seeds::turn_stream() {
            turn_stream(s);
        }
        for s in &seeds::turn_dtls() {
            turn_dtls(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p only-turn --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "stun_message", &seeds::stun_message());
        write_target_seeds(DIR, "turn_server", &seeds::turn_server());
        write_target_seeds(DIR, "turn_stream", &seeds::turn_stream());
        write_target_seeds(DIR, "turn_dtls", &seeds::turn_dtls());
    }
}
