//! Fuzz entry points (cargo feature `fuzzing`): not a public API. `fuzz/fuzz_targets/quic_*`
//! call them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use only_crypto::rand::ChaChaRng;

use crate::TransportConfig;
use crate::proto::cid::ConnectionId;
use crate::proto::coding::Reader;
use crate::proto::conn::{ConnConfig, Connection, Event};
use crate::proto::crypto::{TAG_LEN, initial_keys};
use crate::proto::endpoint::{ConnHandle, DatagramEvent, Endpoint, ServerSetup};
use crate::proto::frame::{self, Frame};
use crate::proto::packet::{self, PacketBuilder, PacketType};
use crate::proto::params::TransportParams;
use crate::proto::ranges::RangeSet;

/// Arbitrary bytes as datagrams: header parsing of every coalesced packet, header protection
/// and AEAD with the Initial keys of the packet's destination ID (both directions), and the
/// frames of whatever decrypts; Version Negotiation and Retry parsing.
pub fn packet(data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let Ok(h) = packet::parse_header(&data[off..], crate::proto::cid::LOCAL_CID_LEN) else {
            return;
        };
        assert!(h.len > 0 && off + h.len <= data.len());
        let pkt = data[off..off + h.len].to_vec();
        off += h.len;
        if h.ty != PacketType::Initial {
            continue;
        }
        for client in [false, true] {
            let k = initial_keys(&h.dcid, client, h.version.max(1));
            let mut p = pkt.clone();
            let Some((n, tpn)) = packet::unprotect_header(&k.remote.header, &mut p, h.pn_offset)
            else {
                continue;
            };
            let pn = packet::decode_pn(None, tpn, n);
            let hl = h.pn_offset + n;
            if p.len() < hl + TAG_LEN {
                continue;
            }
            let (head, rest) = p.split_at_mut(hl);
            let (ct, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
            if k.remote.packet.open(pn, head, ct, tag) {
                frames(ct);
            }
        }
    }
}

/// Arbitrary bytes as a frame sequence: every frame parses or fails cleanly; ACK ranges are
/// well-formed and re-encode identically; transport parameters re-encode to what they
/// decoded from.
pub fn frames(data: &[u8]) {
    let mut r = Reader::new(data);
    while !r.is_empty() {
        let at = r.pos();
        let Ok(f) = frame::parse(&mut r) else {
            break;
        };
        assert!(r.pos() > at);
        match f {
            Frame::Ack { ranges, delay, .. } => {
                let mut set = RangeSet::new();
                for w in ranges.windows(2) {
                    assert!(w[1].end < w[0].start, "ranges descend with gaps");
                }
                for x in &ranges {
                    assert!(x.start < x.end);
                    set.insert(x.clone());
                }
                let mut out = Vec::new();
                frame::put_ack(&mut out, &set, delay, usize::MAX);
                let Ok(Frame::Ack { ranges: back, .. }) = frame::parse(&mut Reader::new(&out))
                else {
                    panic!("ACK does not re-parse");
                };
                assert_eq!(back, ranges);
            }
            Frame::Stream { data: d, .. } | Frame::Crypto { data: d, .. } | Frame::Datagram(d) => {
                assert!(d.end <= data.len());
            }
            _ => {}
        }
    }
    for from_server in [false, true] {
        if let Ok(mut p) = TransportParams::decode(data, from_server) {
            // The preferred address is parsed but not kept, so it does not re-encode.
            p.preferred_address = None;
            assert_eq!(
                TransportParams::decode(&p.encode(), from_server).ok(),
                Some(p)
            );
        }
    }
}

fn tls() -> &'static (only_tls::ServerConfig, only_tls::ClientConfig) {
    static T: OnceLock<(only_tls::ServerConfig, only_tls::ClientConfig)> = OnceLock::new();
    T.get_or_init(|| {
        let (cert, key) = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
        let chain = vec![only_tls::Certificate::from_der(cert.as_der().to_vec())];
        let s = only_tls::ServerConfig::builder(
            chain,
            only_tls::PrivateKey::from_pkcs8_der(key.to_pkcs8_der()),
        )
        .alpn(["fz"])
        .tls13_only(true)
        .build()
        .expect("server tls");
        let c = only_tls::ClientConfig::builder()
            .insecure_skip_verify()
            .alpn(["fz"])
            .tls13_only(true)
            .build()
            .expect("client tls");
        (s, c)
    })
}

struct Pair {
    now: Instant,
    server: Endpoint,
    sconns: HashMap<ConnHandle, Connection>,
    client: Connection,
    caddr: SocketAddr,
    saddr: SocketAddr,
}

impl Pair {
    fn new() -> Pair {
        let (stls, ctls) = tls();
        let mut rng = ChaChaRng::from_seed([7; 32]);
        let t = TransportConfig {
            max_concurrent_bidi_streams: 8,
            max_concurrent_uni_streams: 8,
            stream_receive_window: 64 * 1024,
            receive_window: Some(256 * 1024),
            ..TransportConfig::default()
        };
        let server = Endpoint::with_rng(
            Some(ServerSetup {
                tls: stls.clone(),
                cfg: ConnConfig::new(t.clone(), true),
                retry: false,
            }),
            &mut rng,
        );
        let mut cep = Endpoint::with_rng(None, &mut rng);
        let now = Instant::now();
        let saddr: SocketAddr = "10.0.0.2:443".parse().expect("addr");
        let (_, client) = cep
            .connect(
                now,
                ConnConfig::new(t, true),
                ctls,
                "localhost",
                saddr,
                Vec::new(),
            )
            .expect("connect");
        Pair {
            now,
            server,
            sconns: HashMap::new(),
            client,
            caddr: "10.0.0.1:5000".parse().expect("addr"),
            saddr,
        }
    }

    fn send_to_server(&mut self, from: SocketAddr, d: Vec<u8>) {
        match self.server.handle(self.now, from, &d) {
            Some(DatagramEvent::Conn(h)) => {
                if let Some(c) = self.sconns.get_mut(&h) {
                    c.handle_datagram(self.now, from, d);
                }
            }
            Some(DatagramEvent::New(h, c)) => {
                self.sconns.insert(h, *c);
            }
            _ => {}
        }
    }

    /// Shuttles datagrams both ways a few rounds; the application echoes stream data.
    fn pump(&mut self, rounds: usize) {
        for _ in 0..rounds {
            let mut moved = false;
            while let Some(t) = self.client.poll_transmit(self.now, 4) {
                moved = true;
                let parts: Vec<Vec<u8>> = match t.segment_size {
                    Some(s) => t.data.chunks(s).map(<[u8]>::to_vec).collect(),
                    None => vec![t.data],
                };
                for p in parts {
                    self.send_to_server(self.caddr, p);
                }
            }
            let mut back = Vec::new();
            for c in self.sconns.values_mut() {
                while let Some(t) = c.poll_transmit(self.now, 4) {
                    moved = true;
                    back.push(t.data);
                }
                while let Some(e) = c.poll_event() {
                    if let Event::StreamData(id, d, fin) = e {
                        let _ = c.write(id, d);
                        if fin {
                            let _ = c.finish(id);
                        }
                    }
                }
                while c.poll_endpoint_event().is_some() {}
            }
            for d in back {
                self.client.handle_datagram(self.now, self.saddr, d);
            }
            while self.client.poll_event().is_some() {}
            while self.client.poll_endpoint_event().is_some() {}
            if !moved {
                break;
            }
        }
    }

    fn tick(&mut self, ms: u64) {
        self.now += Duration::from_millis(ms);
        self.client.handle_timeout(self.now);
        for c in self.sconns.values_mut() {
            c.handle_timeout(self.now);
        }
    }
}

/// A client Initial packet with `payload` as its frames, padded to 1200 bytes.
fn forged_initial(dcid: &ConnectionId, payload: &[u8]) -> Vec<u8> {
    forged_initial_v(dcid, payload, packet::VERSION_1)
}

/// [`forged_initial`] in QUIC version `version`.
fn forged_initial_v(dcid: &ConnectionId, payload: &[u8], version: u32) -> Vec<u8> {
    let k = initial_keys(dcid, true, version);
    let mut buf = Vec::with_capacity(1200);
    let b = PacketBuilder::long(
        &mut buf,
        version,
        PacketType::Initial,
        dcid,
        &ConnectionId::default(),
        &[],
        0,
        4,
    );
    buf.extend_from_slice(payload);
    if buf.len() < 1200 - TAG_LEN {
        buf.resize(1200 - TAG_LEN, 0);
    }
    b.finish(&mut buf, &k.local.packet, &k.local.header);
    buf
}

/// A handshaken client/server pair fed operations from `data`: raw datagrams to either side,
/// 1-RTT packets with arbitrary frames protected with valid keys (either direction), Initial
/// packets with arbitrary frames to the server endpoint, and time passing. Nothing panics;
/// the endpoint survives anything.
pub fn connection(data: &[u8]) {
    let mut p = Pair::new();
    p.pump(16);
    let mut r = Reader::new(data);
    while let Some(op) = r.u8() {
        let Some(n) = r.u16() else { break };
        let Some(b) = r.bytes(usize::from(n).min(1400)) else {
            break;
        };
        match op % 6 {
            0 => p.send_to_server(p.caddr, b.to_vec()),
            1 => {
                let from = p.saddr;
                p.client.handle_datagram(p.now, from, b.to_vec());
            }
            2 => {
                if let Some(pkt) = p.client.forge_1rtt(b) {
                    p.send_to_server(p.caddr, pkt);
                }
            }
            3 => {
                let mut forged = Vec::new();
                for c in p.sconns.values_mut() {
                    forged.extend(c.forge_1rtt(b));
                }
                for pkt in forged {
                    let from = p.saddr;
                    p.client.handle_datagram(p.now, from, pkt);
                }
            }
            4 => {
                let dcid = ConnectionId::new(&[op; 8]).expect("cid");
                let from: SocketAddr = "10.0.0.9:9".parse().expect("addr");
                p.send_to_server(from, forged_initial(&dcid, b));
            }
            _ => p.tick(u64::from(n % 2000)),
        }
        p.pump(4);
    }
    p.tick(100);
    p.pump(8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(target: &str) -> Vec<Vec<u8>> {
        let dir = format!("{}/../../fuzz/corpus/{target}", env!("CARGO_MANIFEST_DIR"));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|e| std::fs::read(e.path()).ok())
            .collect()
    }

    fn replay(target: &str, f: fn(&[u8]), step: usize) {
        let files = corpus(target);
        assert!(!files.is_empty(), "fuzz/corpus/{target} is empty");
        for d in files {
            f(&d);
            for cut in [1, d.len() / 2, d.len().saturating_sub(1)] {
                f(&d[..cut.min(d.len())]);
            }
            for i in (0..d.len()).step_by(step) {
                let mut g = d.clone();
                g[i] ^= 0x5a;
                f(&g);
            }
        }
    }

    #[test]
    fn replay_quic_packet() {
        replay("quic_packet", packet, 7);
    }

    #[test]
    fn replay_quic_frame() {
        replay("quic_frame", frames, 1);
    }

    #[test]
    fn replay_quic_conn() {
        replay("quic_conn", connection, 97);
    }

    fn op(out: &mut Vec<u8>, op: u8, b: &[u8]) {
        out.push(op);
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
    }

    /// Regenerates the seed corpora: datagrams of a real handshake and transfer, every frame
    /// type, and connection scripts. `cargo test -p only-quic -- --ignored generate_corpus`.
    #[test]
    #[ignore = "writes fuzz/corpus"]
    fn generate_corpus() {
        use crate::proto::frame::ty;
        let root = format!("{}/../../fuzz/corpus", env!("CARGO_MANIFEST_DIR"));
        let write = |target: &str, name: String, d: &[u8]| {
            let dir = format!("{root}/{target}");
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::write(format!("{dir}/{name}"), d).expect("write");
        };
        // quic_packet: the datagrams of a handshake plus a little stream data.
        let mut p = Pair::new();
        let mut n = 0;
        for round in 0..12 {
            while let Some(t) = p.client.poll_transmit(p.now, 1) {
                write("quic_packet", format!("c{round:02}_{n:02}"), &t.data);
                n += 1;
                p.send_to_server(p.caddr, t.data);
            }
            let mut back = Vec::new();
            for c in p.sconns.values_mut() {
                while let Some(t) = c.poll_transmit(p.now, 1) {
                    back.push(t.data);
                }
            }
            for d in back {
                write("quic_packet", format!("s{round:02}_{n:02}"), &d);
                n += 1;
                p.client.handle_datagram(p.now, p.saddr, d);
            }
            if round == 6 {
                if let Some(id) = p.client.open(crate::Dir::Bi) {
                    let _ = p.client.write(id, crate::Bytes::from_static(b"hello quic"));
                    let _ = p.client.finish(id);
                }
            }
        }
        write(
            "quic_packet",
            "vn".into(),
            &packet::version_negotiation(
                &ConnectionId::new(&[1; 8]).expect("cid"),
                &ConnectionId::new(&[2; 8]).expect("cid"),
                5,
                &[packet::VERSION_1, packet::VERSION_2],
            ),
        );
        // A version 2 Initial (RFC 9369).
        write(
            "quic_packet",
            "initial_v2".into(),
            &forged_initial_v(
                &ConnectionId::new(&[7; 8]).expect("cid"),
                &[1, 0, 0],
                packet::VERSION_2,
            ),
        );
        // quic_frame: one of each frame type.
        let cid = ConnectionId::new(&[9; 8]).expect("cid");
        let mut set = RangeSet::new();
        set.insert(0..5);
        set.insert(9..20);
        let mut frames: Vec<(&str, Vec<u8>)> = Vec::new();
        let mut f = Vec::new();
        frame::put_ack(&mut f, &set, 100, 32);
        frames.push(("ack", f));
        let mut f = Vec::new();
        frame::put_ack_ecn(&mut f, &set, 100, 32, Some([12, 0, 3]));
        frames.push(("ack_ecn", f));
        let mut f = Vec::new();
        frame::put_stream_header(&mut f, 4, 100, 5, true);
        f.extend_from_slice(b"hello");
        frames.push(("stream", f));
        let mut f = Vec::new();
        frame::put_crypto_header(&mut f, 0, 3);
        f.extend_from_slice(b"abc");
        frames.push(("crypto", f));
        let mut f = Vec::new();
        frame::put_new_cid(&mut f, 1, 0, &cid, &[3; 16]);
        frames.push(("new_cid", f));
        let mut f = Vec::new();
        frame::put_close(&mut f, false, 0xa, 8, b"bad");
        frames.push(("close", f));
        let mut f = Vec::new();
        frame::put_datagram(&mut f, b"dgram");
        frames.push(("datagram", f));
        for (name, t, vals) in [
            ("ping", ty::PING, &[][..]),
            ("reset", ty::RESET_STREAM, &[4, 7, 100][..]),
            ("stop", ty::STOP_SENDING, &[4, 9][..]),
            ("max_data", ty::MAX_DATA, &[1 << 20][..]),
            ("max_stream_data", ty::MAX_STREAM_DATA, &[4, 1 << 16][..]),
            ("max_streams", ty::MAX_STREAMS_BIDI, &[100][..]),
            ("blocked", ty::DATA_BLOCKED, &[5][..]),
            ("stream_blocked", ty::STREAM_DATA_BLOCKED, &[4, 5][..]),
            ("streams_blocked", ty::STREAMS_BLOCKED_UNI, &[5][..]),
            ("retire", ty::RETIRE_CONNECTION_ID, &[0][..]),
            ("hs_done", ty::HANDSHAKE_DONE, &[][..]),
        ] {
            let mut f = Vec::new();
            frame::put_simple(&mut f, t, vals);
            frames.push((name, f));
        }
        let mut challenge = vec![ty::PATH_CHALLENGE as u8];
        challenge.extend_from_slice(&[1; 8]);
        frames.push(("challenge", challenge));
        let tp = TransportParams {
            initial_max_data: 1 << 20,
            initial_scid: Some(cid),
            ..TransportParams::default()
        };
        frames.push(("params", tp.encode()));
        let mut all = Vec::new();
        for (name, f) in &frames {
            write("quic_frame", (*name).to_string(), f);
            all.extend_from_slice(f);
        }
        write("quic_frame", "all".into(), &all);
        // quic_conn: scripts of forged frames in both directions, raw datagrams, time.
        for (name, f) in &frames {
            let mut s = Vec::new();
            op(&mut s, 2, f);
            op(&mut s, 3, f);
            op(&mut s, 5, &[0; 300]);
            write("quic_conn", format!("forged_{name}"), &s);
        }
        let mut s = Vec::new();
        op(&mut s, 2, &frames[1].1);
        op(&mut s, 4, &frames[2].1);
        op(&mut s, 0, &[0x40; 40]);
        op(&mut s, 1, &[0xc0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0]);
        op(&mut s, 5, &[0; 1999]);
        write("quic_conn", "mixed".into(), &s);
    }
}
