//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project calls
//! them; the unit tests below replay `fuzz/corpus/<target>` on stable.
//!
//! Stream inputs (`bt_peer_wire`, `bt_mse`) start with a byte that seeds how the stream is cut
//! into reads (`only_core::fuzzing::split`'s convention); datagram inputs (`bt_utp`) are
//! packets each prefixed by its length (`u16`, little endian).

use std::net::SocketAddr;

use crate::bencode;
use crate::dht::{Msg, Node, NodeId};
use crate::magnet::Magnet;
use crate::metainfo::{Info, InfoHash, MetaInfo};
use crate::mse::{CRYPTO_PLAINTEXT, CRYPTO_RC4, Initiator, Receiver};
use crate::tracker::{http, udp};
use crate::utp::{Connection, Header};
use crate::wire::{ExtendedHandshake, Handshake, MetadataMsg, Parser, Pex};

/// Splits `data` into reads: `data[0]` seeds the sizes (0: one read), the rest is the stream.
fn split(data: &[u8]) -> Vec<&[u8]> {
    let Some((&seed, rest)) = data.split_first() else {
        return Vec::new();
    };
    if seed == 0 {
        return vec![rest];
    }
    let mut out = Vec::new();
    let mut x = u32::from(seed) | 1;
    let mut r = rest;
    while !r.is_empty() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let n = (x as usize % usize::from(seed)) + 1;
        let n = n.min(r.len());
        out.push(&r[..n]);
        r = &r[n..];
    }
    out
}

/// Splits `data` into length-prefixed packets (a truncated last one is taken as it is).
fn packets(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let n = usize::from(u16::from_le_bytes([data[0], data[1]])).min(data.len() - 2);
        out.push(&data[2..2 + n]);
        data = &data[2 + n..];
    }
    out
}

/// Bencoding, .torrent files, info dictionaries and magnet links.
pub fn bt_bencode(data: &[u8]) {
    if let Ok(v) = bencode::decode(data) {
        // Canonical re-encoding decodes to the same value.
        let e = bencode::encode(&v);
        assert_eq!(bencode::decode(&e).ok().as_ref(), Some(&v));
    }
    let _ = bencode::decode_prefix(data);
    let _ = bencode::raw_value(data, b"info");
    if let Ok(mi) = MetaInfo::parse(data) {
        // What parses re-encodes to the same info hash.
        let again = MetaInfo::parse(&mi.to_bytes()).map(|m| m.info_hash);
        assert_eq!(again.ok(), Some(mi.info_hash));
        let i = &mi.info;
        for p in 0..i.num_pieces().min(64) {
            let segs = i.piece_segments(p);
            assert_eq!(
                segs.iter().map(|s| s.len).sum::<u64>(),
                u64::from(i.piece_size(p))
            );
        }
    }
    let _ = Info::parse(data);
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(m) = Magnet::parse(s) {
            assert_eq!(Magnet::parse(&m.to_string()).ok(), Some(m));
        }
    }
}

/// The peer wire protocol: handshake, then messages read in arbitrary pieces, with the
/// extension payloads (extension handshake, ut_metadata, ut_pex) decoded.
pub fn bt_peer_wire(data: &[u8]) {
    let _ = Handshake::parse(data.get(1..).unwrap_or_default());
    let mut p = Parser::new(1 << 16);
    for chunk in split(data) {
        p.feed(chunk);
        loop {
            match p.next_message() {
                Ok(Some(crate::wire::Message::Extended { payload, .. })) => {
                    let _ = ExtendedHandshake::decode(&payload);
                    let _ = MetadataMsg::decode(&payload);
                    let _ = Pex::decode(&payload);
                }
                Ok(Some(m)) => {
                    // Every message re-encodes to what decodes back to it.
                    let e = m.encode();
                    assert_eq!(crate::wire::Message::decode(&e[4..]).ok(), Some(m));
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
}

/// KRPC: message parsing, and a DHT node answering whatever arrives.
pub fn bt_krpc(data: &[u8]) {
    if let Some(m) = Msg::parse(data) {
        let _ = Msg::parse(&m.encode());
    }
    let mut n = Node::new(NodeId([7; 20]));
    let from = SocketAddr::from(([10, 1, 2, 3], 6881));
    n.handle(from, data);
    let _ = n.take_outgoing();
    n.get_peers(InfoHash([1; 20]), Some(6881));
    for (to, _) in n.take_outgoing() {
        n.handle(to, data);
    }
    n.tick();
}

/// uTP: header parsing, and a connection accepted from the first SYN taking the rest.
pub fn bt_utp(data: &[u8]) {
    let mut conn: Option<Connection> = None;
    let mut send = Vec::new();
    let mut events = Vec::new();
    for (i, p) in packets(data).into_iter().enumerate() {
        let Some((h, sack, payload)) = Header::parse(p) else {
            continue;
        };
        let now = 1_000 * i as u64;
        match &mut conn {
            None => conn = Some(Connection::accept(&h, now, &mut send)),
            Some(c) => {
                c.on_packet(&h, sack, payload, now, &mut send, &mut events);
                let _ = c.write(payload, now, &mut send);
                c.on_tick(now + 2_000_000, &mut send, &mut events);
            }
        }
        send.clear();
    }
}

/// Tracker responses and requests, HTTP and UDP.
pub fn bt_tracker(data: &[u8]) {
    let _ = http::parse_announce(data);
    let _ = http::parse_scrape(data);
    let _ = udp::parse_reply(data, false);
    let _ = udp::parse_reply(data, true);
    let _ = udp::parse_request(data);
    let _ = http::parse_announce_query(&String::from_utf8_lossy(data));
    let srv = crate::tracker::TrackerServer::new(crate::tracker::TrackerConfig::default());
    let _ = srv.handle_udp(SocketAddr::from(([10, 0, 0, 1], 1000)), data);
    let _ = srv.handle_http(
        std::net::IpAddr::from([10, 0, 0, 1]),
        &String::from_utf8_lossy(data),
    );
}

/// MSE: a receiver and an initiator fed hostile bytes in arbitrary pieces.
pub fn bt_mse(data: &[u8]) {
    let ih = InfoHash([3; 20]);
    let key = crate::mse::req2_hash(&ih);
    let lookup = move |h: &[u8; 20]| (*h == key).then_some(ih);
    let mut r = Receiver::new(CRYPTO_RC4 | CRYPTO_PLAINTEXT);
    let (mut i, _) = Initiator::new(ih, CRYPTO_RC4 | CRYPTO_PLAINTEXT, b"payload".to_vec());
    for chunk in split(data) {
        if r.feed(chunk, &lookup).is_err() {
            break;
        }
    }
    for chunk in split(data) {
        if i.feed(chunk).is_err() {
            break;
        }
    }
}

#[cfg(test)]
pub(crate) mod seeds {
    use super::*;
    use crate::metainfo::Builder;
    use crate::tracker::AnnounceRequest;
    use crate::wire::Message;

    fn join(pkts: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in pkts {
            v.extend_from_slice(&(p.len() as u16).to_le_bytes());
            v.extend_from_slice(p);
        }
        v
    }

    pub(crate) fn bt_bencode() -> Vec<Vec<u8>> {
        let one = Builder::new("a.bin")
            .piece_length(16)
            .tracker("http://t/announce")
            .build_bytes(b"0123456789abcdefXYZ")
            .map(|m| m.to_bytes())
            .unwrap_or_default();
        let files = vec![
            (vec!["d".to_owned(), "x".to_owned()], vec![1u8; 20]),
            (vec!["y".to_owned()], vec![2u8; 9]),
        ];
        let multi = Builder::new("m")
            .piece_length(8)
            .build_files(&files)
            .map(|m| m.to_bytes())
            .unwrap_or_default();
        vec![
            one,
            multi,
            b"d1:ai1e1:bl1:x1:yee".to_vec(),
            format!(
                "magnet:?xt=urn:btih:{}&dn=x&tr=udp%3A%2F%2Ft%3A1",
                "ab".repeat(20)
            )
            .into_bytes(),
        ]
    }

    pub(crate) fn bt_peer_wire() -> Vec<Vec<u8>> {
        let mut s = vec![5u8];
        s.extend_from_slice(&Handshake::new(InfoHash([1; 20]), [2; 20]).encode());
        for m in [
            Message::Bitfield(vec![0xF0]),
            Message::Interested,
            Message::Unchoke,
            Message::Request {
                index: 1,
                begin: 0,
                length: 16384,
            },
            Message::Piece {
                index: 1,
                begin: 0,
                data: vec![9; 40],
            },
            Message::HaveAll,
            Message::AllowedFast(3),
            Message::Extended {
                id: 0,
                payload: ExtendedHandshake::default().encode(),
            },
            Message::Extended {
                id: 1,
                payload: MetadataMsg::Data {
                    piece: 0,
                    total_size: 3,
                    data: b"abc".to_vec(),
                }
                .encode(),
            },
            Message::Extended {
                id: 2,
                payload: Pex {
                    added: vec![SocketAddr::from(([1, 2, 3, 4], 5))],
                    dropped: vec![],
                }
                .encode(),
            },
        ] {
            m.encode_to(&mut s);
        }
        vec![s]
    }

    pub(crate) fn bt_krpc() -> Vec<Vec<u8>> {
        let mut n = Node::new(NodeId([9; 20]));
        n.get_peers(InfoHash([1; 20]), Some(1));
        n.ping(SocketAddr::from(([1, 1, 1, 1], 1)));
        let mut v: Vec<Vec<u8>> = n.take_outgoing().into_iter().map(|(_, b)| b).collect();
        v.push(b"d1:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:nodes26:bbbbbbbbbbbbbbbbbbbb\x7f\0\0\x01\x1a\xe15:token2:tke1:t2:\0\x011:y1:re".to_vec());
        v.push(b"d1:eli201e3:bade1:t2:aa1:y1:ee".to_vec());
        v
    }

    pub(crate) fn bt_utp() -> Vec<Vec<u8>> {
        let mut to_b = Vec::new();
        let mut a = Connection::connect(10, 0, &mut to_b);
        let syn = to_b.clone();
        let (h, _, _) = Header::parse(&syn[0])
            .map(|(h, s, p)| (h, s.map(<[u8]>::to_vec), p.to_vec()))
            .unwrap_or_default();
        let mut to_a = Vec::new();
        let mut b = Connection::accept(&h, 0, &mut to_a);
        let mut ev = Vec::new();
        for p in &to_a {
            if let Some((h, s, pl)) = Header::parse(p) {
                a.on_packet(&h, s, pl, 10, &mut to_b, &mut ev);
            }
        }
        let _ = a.write(&[7u8; 3000], 20, &mut to_b);
        let _ = b.write(b"x", 20, &mut to_a);
        vec![join(&to_b), join(&[syn, to_a].concat())]
    }

    pub(crate) fn bt_tracker() -> Vec<Vec<u8>> {
        let req = AnnounceRequest::new(InfoHash([1; 20]), [2; 20], 6881, 5);
        vec![
            b"d8:completei1e10:incompletei2e8:intervali60e5:peers6:\x7f\0\0\x01\x1a\xe1e".to_vec(),
            b"d5:filesd20:aaaaaaaaaaaaaaaaaaaad8:completei1e10:downloadedi2e10:incompletei3eeee"
                .to_vec(),
            udp::connect_request(1),
            udp::announce_request(5, 2, &req),
            http::announce_url("/announce", &req).into_bytes(),
            vec![
                0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 60, 0, 0, 0, 1, 0, 0, 0, 1, 127, 0, 0, 1, 0x1a,
                0xe1,
            ],
        ]
    }

    pub(crate) fn bt_mse() -> Vec<Vec<u8>> {
        let (_, first) = Initiator::new(InfoHash([3; 20]), CRYPTO_RC4, b"x".to_vec());
        vec![
            [&[7u8][..], &first].concat(),
            [&[0u8][..], &[0x55; 700][..]].concat(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        let n = replay(DIR, "bt_bencode", bt_bencode)
            + replay(DIR, "bt_peer_wire", bt_peer_wire)
            + replay(DIR, "bt_krpc", bt_krpc)
            + replay(DIR, "bt_utp", bt_utp)
            + replay(DIR, "bt_tracker", bt_tracker)
            + replay(DIR, "bt_mse", bt_mse);
        assert!(n > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for (f, s) in [
            (bt_bencode as fn(&[u8]), seeds::bt_bencode()),
            (bt_peer_wire, seeds::bt_peer_wire()),
            (bt_krpc, seeds::bt_krpc()),
            (bt_utp, seeds::bt_utp()),
            (bt_tracker, seeds::bt_tracker()),
            (bt_mse, seeds::bt_mse()),
        ] {
            for x in &s {
                f(x);
            }
        }
    }

    /// Regenerates the seed files: `cargo test -p only-bittorrent --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "bt_bencode", &seeds::bt_bencode());
        write_target_seeds(DIR, "bt_peer_wire", &seeds::bt_peer_wire());
        write_target_seeds(DIR, "bt_krpc", &seeds::bt_krpc());
        write_target_seeds(DIR, "bt_utp", &seeds::bt_utp());
        write_target_seeds(DIR, "bt_tracker", &seeds::bt_tracker());
        write_target_seeds(DIR, "bt_mse", &seeds::bt_mse());
    }
}
