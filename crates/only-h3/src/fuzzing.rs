//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use only_quic::{Dir, Side, StreamId};

use crate::frame::{Piece, Reader, StreamReader};
use crate::qpack::{FieldBuf, SectionError, decode_section};
use crate::qtable::{DecTable, Encoder};
use crate::{H3Config, NoHost, Peer, Qd, Req, Uni, qpack, read_req};

/// Pieces of `data`: `seed` 0 is one piece, else pseudo-random sizes in `1..=seed`.
fn pieces(seed: u8, mut data: &[u8]) -> Vec<&[u8]> {
    if seed == 0 {
        return vec![data];
    }
    let mut x = u32::from(seed) | 0x5bd1_e900;
    let mut out = Vec::new();
    while !data.is_empty() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let n = (x as usize % usize::from(seed) + 1).min(data.len());
        out.push(&data[..n]);
        data = &data[n..];
    }
    out
}

fn frames(max: u64, ps: &[&[u8]]) -> (Vec<(u64, Vec<u8>)>, Option<u64>) {
    let mut r = Reader::default();
    let mut out = Vec::new();
    for p in ps {
        r.push(p);
        loop {
            match r.frame(max) {
                Ok(Some(f)) => out.push(f),
                Ok(None) => break,
                Err(len) => return (out, Some(len)),
            }
        }
    }
    (out, None)
}

/// [`frames`] through `Reader::feed`, which reads in place what it can.
fn fed(max: u64, ps: &[&[u8]]) -> (Vec<(u64, Vec<u8>)>, Option<u64>) {
    let mut r = Reader::default();
    let mut out = Vec::new();
    for p in ps {
        let res = r.feed(
            p,
            max,
            || (),
            |t, f| {
                out.push((t, f.to_vec()));
                Ok(())
            },
        );
        if res.is_err() {
            return (out, Some(0));
        }
    }
    (out, None)
}

/// [`StreamReader::feed_stream`]'s pieces, DATA bytes joined (their split depends on reads).
fn streamed(max: u64, ps: &[&[u8]]) -> (Vec<(u8, Vec<u8>)>, bool) {
    let mut r = StreamReader::default();
    let mut out: Vec<(u8, Vec<u8>)> = Vec::new();
    for p in ps {
        let res = r.feed_stream(
            p,
            max,
            || (),
            |piece| {
                match piece {
                    Piece::Headers(h) => out.push((0, h.to_vec())),
                    Piece::Data(d) => match out.last_mut() {
                        Some((1, v)) => v.extend_from_slice(d),
                        _ => out.push((1, d.to_vec())),
                    },
                    Piece::Skip(t) => out.push((2, t.to_le_bytes().to_vec())),
                }
                Ok(())
            },
        );
        if res.is_err() {
            return (out, true);
        }
    }
    (out, false)
}

/// `h3_frame`: the frame readers (frames must not depend on read boundaries, whether buffered,
/// read in place or streamed) and a peer's unidirectional stream (stream type, control stream
/// SETTINGS and frame rules, QPACK encoder and decoder streams).
/// `data[0]`: bit 0 client side (else server), the rest the frame size limit; `data[1]` splits.
pub fn h3_frame(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let max = u64::from(data[0] >> 1) * 64;
    let wire = &data[2..];
    let ps = pieces(data[1], wire);
    let whole = frames(max, &[wire]);
    assert_eq!(whole, frames(max, &ps));
    // Fed in place, the same frames, and the same point where a frame is too large.
    let m = |(f, e): (Vec<(u64, Vec<u8>)>, Option<u64>)| (f, e.is_some());
    assert_eq!(m(whole.clone()), m(fed(max, &[wire])));
    assert_eq!(m(whole), m(fed(max, &ps)));
    // Streamed: the same pieces however the bytes arrive, up to an error.
    let (a, ae) = streamed(max, &[wire]);
    let (b, be) = streamed(max, &ps);
    assert_eq!(ae, be);
    if !ae {
        assert_eq!(a, b);
    }
    let server = data[0] & 1 == 0;
    let mut u = Uni::Unknown(Reader::default());
    let mut peer = Peer::new(&H3Config::default());
    let mut stop = |_: StreamId, _: u32| {};
    let side = if server { Side::Client } else { Side::Server };
    let id = StreamId::new(side, Dir::Uni, 0);
    for (i, p) in ps.iter().enumerate() {
        let fin = i + 1 == ps.len();
        if crate::on_uni(&mut u, &mut peer, &mut stop, id, p, fin, server).is_err() {
            break;
        }
    }
}

/// `qpack_decode`: field section decoding (static table, literals, Huffman) with `data[0]`
/// setting the size limit; a decoded section re-encodes to one that decodes the same.
pub fn qpack_decode(data: &[u8]) {
    let Some((&m, rest)) = data.split_first() else {
        return;
    };
    let max = if m == 0 {
        usize::MAX
    } else {
        usize::from(m) * 64
    };
    let Ok(fields) = qpack::decode(rest, max) else {
        return;
    };
    let text: Option<Vec<(String, String)>> = fields
        .iter()
        .map(|(n, v)| {
            Some((
                String::from_utf8(n.clone()).ok()?,
                String::from_utf8(v.clone()).ok()?,
            ))
        })
        .collect();
    if let Some(text) = text {
        let mut enc = Vec::new();
        qpack::encode(text.iter().map(|(n, v)| (n.as_str(), v.as_str())), &mut enc);
        assert_eq!(qpack::decode(&enc, usize::MAX).as_ref(), Ok(&fields));
    }
}

/// `qpack_dynamic`: the QPACK dynamic table. `data[0]` sets the table capacity (x16 bytes),
/// `data[1]` splits the encoder stream, `data[2..4]` (little endian) is its length; the rest
/// is a field section. The table must not depend on how the encoder stream arrives; a section
/// that decodes, re-encoded by this side's encoder against a fresh table, decodes the same.
pub fn qpack_dynamic(data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let cap = u64::from(data[0]) * 16;
    let n = usize::from(u16::from_le_bytes([data[2], data[3]])).min(data.len() - 4);
    let (ins, section) = data[4..].split_at(n);
    // The encoder stream whole and in pieces (buffered as `on_uni` does).
    let mut whole = DecTable::new(cap);
    let whole_res = whole.on_encoder_stream(ins);
    let mut split = DecTable::new(cap);
    let mut buf = Vec::new();
    let mut split_err = false;
    for p in pieces(data[1], ins) {
        buf.extend_from_slice(p);
        match split.on_encoder_stream(&buf) {
            Ok(k) => {
                buf.drain(..k);
            }
            Err(_) => {
                split_err = true;
                break;
            }
        }
    }
    assert_eq!(whole_res.is_err(), split_err);
    if split_err {
        return;
    }
    assert_eq!(whole.inserted(), split.inserted());
    for abs in 0..whole.inserted() {
        assert_eq!(whole.get(abs), split.get(abs));
    }
    let mut f = FieldBuf::default();
    match decode_section(section, 64 << 10, &whole, &mut f) {
        Ok(ric) => assert!(ric <= whole.inserted()),
        Err(SectionError::Blocked(ric)) => {
            assert!(ric > whole.inserted());
            return;
        }
        Err(SectionError::Bad(_)) => return,
    }
    let Some(text) = f.strs() else { return };
    let text: Vec<(Vec<u8>, Vec<u8>)> = text
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect();
    if text
        .iter()
        .any(|(n, _)| n.iter().any(u8::is_ascii_uppercase))
    {
        return;
    }
    // Our encoder, three times (fields are inserted the second time) against a peer that
    // acknowledges everything in between.
    let mut e = Encoder::new(cap.max(256), 4096, 0);
    let mut d = DecTable::new(4096);
    for round in 0..3u64 {
        let (mut lines, mut sec) = e.begin(round * 4);
        for (n, v) in &text {
            e.line(&mut lines, &mut sec, n, v);
        }
        let mut out = Vec::new();
        e.end(&mut out, lines, sec);
        let ins = std::mem::take(&mut e.out);
        assert_eq!(d.on_encoder_stream(&ins), Ok(ins.len()));
        let mut g = FieldBuf::default();
        let ric = decode_section(&out, usize::MAX, &d, &mut g).expect("own section");
        let got: Vec<(Vec<u8>, Vec<u8>)> =
            g.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect();
        assert_eq!(got, text);
        if ric > 0 {
            d.section_ack(round * 4, ric);
        }
        d.increment();
        let acks = std::mem::take(&mut d.out);
        assert_eq!(e.on_decoder_stream(&acks), Ok(acks.len()));
    }
}

/// This side's QPACK encoder for checks against other decoders (`examples/qpack-pipe.rs`
/// drives it for `tools/interop/h3/nghttp3-qpack.py`).
pub struct InteropEncoder(Encoder);

impl std::fmt::Debug for InteropEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("InteropEncoder")
            .field(&self.stats())
            .finish()
    }
}

impl InteropEncoder {
    /// An encoder with `capacity` bytes of table for a peer allowing `peer_max_capacity` and
    /// `peer_blocked` blocked streams.
    pub fn new(capacity: u64, peer_max_capacity: u64, peer_blocked: u64) -> InteropEncoder {
        InteropEncoder(Encoder::new(capacity, peer_max_capacity, peer_blocked))
    }

    /// Encodes a field section for `stream` (names lowercase).
    pub fn encode(&mut self, stream: u64, fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let (mut lines, mut sec) = self.0.begin(stream);
        for (n, v) in fields {
            self.0.line(&mut lines, &mut sec, n, v);
        }
        let mut out = Vec::new();
        self.0.end(&mut out, lines, sec);
        out
    }

    /// Encoder stream bytes produced so far.
    pub fn take_encoder_stream(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0.out)
    }

    /// Decoder stream bytes from the peer; the bytes taken, or the error code.
    pub fn on_decoder_stream(&mut self, b: &[u8]) -> Result<usize, u32> {
        self.0.on_decoder_stream(b)
    }

    /// What the encoder did: inserts, duplicates, dynamic-name inserts, dynamic-name lines,
    /// post-base lines, blocking sections; then the Known Received Count and entries inserted.
    pub fn stats(&self) -> [u64; 8] {
        let s = self.0.stats;
        [
            s.inserts,
            s.duplicates,
            s.dyn_name_inserts,
            s.dyn_name_lines,
            s.post_base,
            s.blocking,
            self.0.known(),
            self.0.inserted(),
        ]
    }
}

/// Field names and values `qpack_encoder` draws from: few, so fields repeat, fill the table
/// and share names.
const NAMES: [&str; 8] = [
    "x-a",
    "x-b",
    "server",
    "content-type",
    "x-a-much-longer-header-name",
    "date",
    ":authority",
    "accept-language",
];
const VALUES: [&str; 8] = [
    "1",
    "2",
    "only",
    "text/html",
    "application/x-a-rather-long-media-type-for-the-table",
    "Mon, 16 Nov 2026 00:00:00 GMT",
    "example.com",
    "",
];

/// A field section received by `Far`: its stream, bytes and the fields encoded in it.
type Received = (u64, Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

/// The decoder end of `qpack_encoder`: a table, encoder stream bytes not taken yet, and field
/// sections received but not decoded (per stream, in order).
struct Far {
    d: DecTable,
    ins: Vec<u8>,
    pending: Vec<Received>,
}

impl Far {
    /// Decodes what it can, in order per stream, acknowledging each; the peer's blocked-streams
    /// limit must hold.
    fn decode(&mut self, max_blocked: u64) {
        let mut waiting: Vec<u64> = Vec::new();
        let mut f = FieldBuf::default();
        let mut i = 0;
        while i < self.pending.len() {
            let stream = self.pending[i].0;
            if waiting.contains(&stream) {
                i += 1;
                continue;
            }
            match decode_section(&self.pending[i].1, usize::MAX, &self.d, &mut f) {
                Ok(ric) => {
                    let (_, _, want) = self.pending.remove(i);
                    let got: Vec<(Vec<u8>, Vec<u8>)> =
                        f.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect();
                    assert_eq!(got, want);
                    if ric > 0 {
                        self.d.section_ack(stream, ric);
                    }
                }
                Err(SectionError::Blocked(ric)) => {
                    assert!(ric > self.d.inserted());
                    waiting.push(stream);
                    i += 1;
                }
                Err(SectionError::Bad(e)) => panic!("own section: {e:?}"),
            }
        }
        assert!(waiting.len() as u64 <= max_blocked, "{waiting:?}");
    }

    /// Takes `n` more bytes of the encoder stream.
    fn take(&mut self, wire: &mut Vec<u8>, n: usize) {
        let n = n.min(wire.len());
        self.ins.extend(wire.drain(..n));
        let k = self
            .d
            .on_encoder_stream(&self.ins)
            .expect("own encoder stream");
        self.ins.drain(..k);
    }
}

/// `qpack_encoder`: this side's QPACK encoder (inserts, Duplicate, dynamic and post-base
/// references, blocking within the peer's limit) against our decoder over a link that delays
/// the encoder stream, acknowledgements and increments, and cancels streams. `data[0]` sets the
/// encoder's capacity (x16 bytes), `data[1]` the peer's (x32 bytes) and `data[2]` its blocked
/// streams (0 to 7); then operations. Every section decodes to the fields encoded, the peer
/// never has more blocked streams than it allows, and the tables stay within capacity.
pub fn qpack_encoder(data: &[u8]) {
    if data.len() < 3 {
        return;
    }
    let peer_cap = u64::from(data[1]) * 32;
    let blocked = u64::from(data[2] % 8);
    let mut e = Encoder::new(u64::from(data[0]) * 16, peer_cap, blocked);
    let mut far = Far {
        d: DecTable::new(peer_cap),
        ins: Vec::new(),
        pending: Vec::new(),
    };
    let mut wire = std::mem::take(&mut e.out);
    let mut acks: Vec<u8> = Vec::new();
    // Stream ids are not reused: a cancelled stream's slot moves on to a new id.
    let mut ids = [0u64; 8];
    let mut ops = data[3..].iter().copied();
    while let Some(op) = ops.next() {
        let arg = ops.next().unwrap_or(0);
        match op % 6 {
            0 => {
                // A section of 1 to 6 fields on one of 8 streams.
                let slot = usize::from(arg % 8);
                let stream = (ids[slot] * 8 + slot as u64) * 4;
                let mut fields = Vec::new();
                for _ in 0..=(arg / 8) % 6 {
                    let x = ops.next().unwrap_or(0);
                    let n = NAMES[usize::from(x % 8)].as_bytes().to_vec();
                    let v = VALUES[usize::from(x / 8 % 8)].as_bytes().to_vec();
                    fields.push((n, v));
                }
                let (mut lines, mut sec) = e.begin(stream);
                for (n, v) in &fields {
                    e.line(&mut lines, &mut sec, n, v);
                }
                let mut out = Vec::new();
                e.end(&mut out, lines, sec);
                wire.append(&mut e.out);
                assert!(e.size() <= peer_cap.min(u64::from(data[0]) * 16));
                assert!(e.blocking_streams() <= blocked);
                // Nothing a section still needs is evicted.
                if let Some(m) = e.min_referenced() {
                    assert!(m >= e.dropped());
                }
                assert!(e.dropped() <= e.known());
                far.pending.push((stream, out, fields));
            }
            1 => far.take(&mut wire, usize::from(arg)),
            2 => far.decode(blocked),
            3 => far.d.increment(),
            4 => {
                // The peer abandons a stream that still has a section to decode.
                if !far.pending.is_empty() {
                    let s = far.pending[usize::from(arg) % far.pending.len()].0;
                    far.pending.retain(|p| p.0 != s);
                    far.d.cancel(s);
                    ids[(s / 4 % 8) as usize] += 1;
                }
            }
            _ => {
                // The decoder stream, in pieces.
                acks.append(&mut far.d.out);
                let n = usize::from(arg).min(acks.len());
                let k = e.on_decoder_stream(&acks[..n]).expect("own decoder stream");
                acks.drain(..k);
            }
        }
    }
    // Everything arrives: every section decodes.
    let n = wire.len();
    far.take(&mut wire, n);
    far.decode(blocked);
    assert!(far.pending.is_empty());
    assert_eq!(far.d.inserted(), e.inserted());
    acks.append(&mut far.d.out);
    let k = e.on_decoder_stream(&acks).expect("own decoder stream");
    assert_eq!(k, acks.len());
    #[cfg(test)]
    STATS.with(|s| s.set(Some(e.stats)));
}

// What the last `qpack_encoder` run's encoder did (unit tests check that every kind of
// instruction happens).
#[cfg(test)]
thread_local! {
    static STATS: std::cell::Cell<Option<crate::qtable::EncStats>> =
        const { std::cell::Cell::new(None) };
}

/// `h3_request`: a request stream (HEADERS, DATA, trailers, unknown and forbidden frames, size
/// limits, a body streamed to a sink) and building the request from its field sections, with a
/// QPACK dynamic table (sections may block). `data[0]` splits the reads; its bit 6 streams the
/// body.
pub fn h3_request(data: &[u8]) {
    let Some((&seed, wire)) = data.split_first() else {
        return;
    };
    let cfg = H3Config {
        max_body_bytes: 16 << 10,
        max_field_section_bytes: 4 << 10,
        ..H3Config::default()
    };
    let peer = "127.0.0.1:4433".parse().expect("addr");
    let mut req = Req::default();
    let mut fields = FieldBuf::default();
    let mut dec = DecTable::new(4096);
    let mut blocked = 0;
    let mut host = NoHost(seed & 0x40 != 0);
    let ps = pieces(seed & !0x40, wire);
    for (i, p) in ps.iter().enumerate() {
        let fin = i + 1 == ps.len();
        let mut q = Qd {
            dec: &mut dec,
            blocked: &mut blocked,
            max_blocked: 4,
            stream: 0,
        };
        match read_req(&mut req, &cfg, peer, &mut fields, &mut q, &mut host, p, fin) {
            Ok(Some((r, _))) => {
                assert!(r.body.len() <= cfg.max_body_bytes);
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod seeds {
    use crate::frame::{self, put_frame, put_varint};
    use crate::qpack;

    fn section(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut v = Vec::new();
        qpack::encode(fields.iter().copied(), &mut v);
        v
    }

    fn get() -> Vec<u8> {
        section(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "localhost"),
            (":path", "/index.html"),
            ("user-agent", "fuzz"),
        ])
    }

    pub(super) fn qpack_decode() -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = vec![
            [&[0u8][..], &get()].concat(),
            [
                &[0u8][..],
                &section(&[
                    (":status", "200"),
                    ("x-a", "b"),
                    ("x-long", &"v".repeat(200)),
                ]),
            ]
            .concat(),
            vec![0, 0x00, 0x00, 0xd1],
            vec![
                0, 0x00, 0x00, 0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't',
                b'm', b'l',
            ],
            vec![0, 0x00, 0x00, 0x2f, 0x7f, 0xff, 0xff, 0xff, 0x7f],
            vec![0, 0x01, 0x00, 0x80],
            vec![
                2, 0x00, 0x00, 0x5f, 0x1d, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0,
                0xab, 0x90, 0xf4, 0xff,
            ],
        ];
        // Literal with a literal Huffman-coded name.
        v.push(vec![0, 0, 0, 0x2b, 0x94, 0xe7, 0x81, b'x']);
        v
    }

    /// Encoder runs: a section repeated on one stream with every delivery in between; the
    /// same with the encoder stream late (sections block); a full table (duplicates); a
    /// cancelled stream.
    pub(super) fn qpack_encoder() -> Vec<Vec<u8>> {
        // Sections of 3 fields (arg 16..23: 3 fields on stream arg % 8) then delivery (1),
        // decoding (2), increment (3), cancellation (4) and acknowledgements (5).
        let sec = |stream: u8, f: [u8; 3]| [0, 16 + stream, f[0], f[1], f[2]];
        let deliver = [1, 255, 2, 0, 3, 0, 5, 255];
        let mut v = Vec::new();
        let mut a = vec![64, 128, 0];
        for i in 0..6 {
            a.extend_from_slice(&sec(i % 2, [0x08, 0x13, 0x22]));
            a.extend_from_slice(&deliver);
        }
        v.push(a.clone());
        a[2] = 3;
        v.push(a);
        let mut late = vec![64, 128, 2];
        for i in 0..6 {
            late.extend_from_slice(&sec(i, [0x08, 0x13, 0x24]));
            late.extend_from_slice(&[2, 0, 5, 255]);
        }
        late.extend_from_slice(&deliver);
        v.push(late);
        let mut full = vec![12, 12, 4];
        for i in 0..40u8 {
            full.extend_from_slice(&sec(i % 4, [i % 64, 0x08, (i % 9) * 7]));
            full.extend_from_slice(&deliver);
        }
        v.push(full);
        let mut cancel = vec![64, 128, 4];
        cancel.extend_from_slice(&sec(1, [0x08, 0x13, 0x22]));
        cancel.extend_from_slice(&sec(1, [0x08, 0x13, 0x22]));
        cancel.extend_from_slice(&[4, 0, 5, 255, 1, 255, 2, 0, 5, 255]);
        v.push(cancel);
        v
    }

    pub(super) fn qpack_dynamic() -> Vec<Vec<u8>> {
        let with = |cap: u8, split: u8, ins: &[u8], sec: &[u8]| {
            let mut v = vec![cap, split];
            v.extend_from_slice(&(ins.len() as u16).to_le_bytes());
            v.extend_from_slice(ins);
            v.extend_from_slice(sec);
            v
        };
        // RFC 9204 Appendix B.2 and B.4 (220-byte table: 14 x 16 = 224).
        let b2 = [
            0x3f, 0xbd, 0x01, 0xc0, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm', 0xc1, 0x0c, b'/', b's', b'a', b'm', b'p', b'l',
            b'e', b'/', b'p', b'a', b't', b'h',
        ];
        let mut b4 = b2.to_vec();
        b4.extend_from_slice(&[0x4a]);
        b4.extend_from_slice(b"custom-key");
        b4.push(0x0c);
        b4.extend_from_slice(b"custom-value");
        b4.push(0x02);
        vec![
            with(14, 0, &b2, &[0x03, 0x81, 0x10, 0x11]),
            with(14, 3, &b2, &[0x03, 0x81, 0x10, 0x11]),
            with(14, 1, &b4, &[0x05, 0x00, 0x80, 0xc1, 0x81]),
            with(14, 0, &b4, &[0x05, 0x01, 0x5f, 0x00, 0x01, b'a', 0x10]),
            with(14, 0, &b2[..10], &[0x03, 0x81, 0x10]),
            with(0, 0, &[0x3f, 0x01], &[0x00, 0x00, 0xd1]),
            with(255, 2, &[0x3f, 0xe1, 0x1f, 0x02], &[]),
        ]
    }

    pub(super) fn h3_request() -> Vec<Vec<u8>> {
        let mut a = Vec::new();
        put_frame(&mut a, frame::HEADERS, &get());
        let mut b = Vec::new();
        put_frame(
            &mut b,
            frame::HEADERS,
            &section(&[
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "h"),
                (":path", "/p"),
                ("content-length", "4"),
                ("te", "trailers"),
            ]),
        );
        put_frame(&mut b, 0x21, b"reserved"); // a grease frame type
        put_frame(&mut b, frame::DATA, b"bo");
        put_frame(&mut b, frame::DATA, b"dy");
        put_frame(&mut b, frame::HEADERS, &section(&[("x-trailer", "1")]));
        let mut c = Vec::new();
        put_frame(
            &mut c,
            frame::HEADERS,
            &section(&[(":method", "CONNECT"), (":authority", "example.com:443")]),
        );
        let mut d = Vec::new();
        put_frame(&mut d, frame::SETTINGS, &[]);
        // A section that blocks until the inserts arrive (they never do here).
        let mut e = Vec::new();
        put_frame(&mut e, frame::HEADERS, &[0x02, 0x00, 0x80]);
        put_frame(&mut e, frame::DATA, b"held");
        // An extended CONNECT for a WebSocket, then its bytes.
        let mut w = Vec::new();
        put_frame(
            &mut w,
            frame::HEADERS,
            &section(&[
                (":method", "CONNECT"),
                (":protocol", "websocket"),
                (":scheme", "https"),
                (":authority", "h"),
                (":path", "/ws"),
                ("sec-websocket-version", "13"),
            ]),
        );
        put_frame(&mut w, frame::DATA, &[0x81, 0x80, 1, 2, 3, 4]);
        vec![
            [&[0u8][..], &a].concat(),
            [&[0u8][..], &b].concat(),
            [&[3u8][..], &b].concat(),
            [&[0x40u8][..], &b].concat(),
            [&[0x43u8][..], &b].concat(),
            [&[0u8][..], &e].concat(),
            [&[0u8][..], &w].concat(),
            [&[0u8][..], &c].concat(),
            [&[0u8][..], &d].concat(),
            vec![0, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ]
    }

    pub(super) fn h3_frame() -> Vec<Vec<u8>> {
        let ctrl = crate::control_stream_preamble(&crate::H3Config::default(), false);
        let mut more = ctrl.clone();
        put_frame(&mut more, frame::GOAWAY, &[0]);
        put_frame(&mut more, frame::MAX_PUSH_ID, &[4]);
        put_frame(&mut more, 0x21, b"grease");
        let mut qenc = Vec::new();
        put_varint(&mut qenc, frame::STREAM_QPACK_ENCODER);
        qenc.push(0x20); // set dynamic table capacity 0
        let mut qenc2 = Vec::new();
        put_varint(&mut qenc2, frame::STREAM_QPACK_ENCODER);
        qenc2.extend_from_slice(&[0x3f, 0xe1, 0x1f, 0xc0, 0x01, b'a', 0x00]);
        let mut qdec = Vec::new();
        put_varint(&mut qdec, frame::STREAM_QPACK_DECODER);
        qdec.extend_from_slice(&[0x44, 0x84]);
        let mut ws = crate::control_stream_preamble(&crate::H3Config::default(), true);
        put_frame(&mut ws, frame::DATA, b"x");
        let mut unknown = Vec::new();
        put_varint(&mut unknown, 0x21);
        unknown.extend_from_slice(b"whatever");
        let mut dup = ctrl.clone();
        put_frame(&mut dup, frame::SETTINGS, &[]);
        vec![
            [&[0xfeu8, 0][..], &ctrl].concat(),
            [&[0xfeu8, 2][..], &more].concat(),
            [&[0xffu8, 0][..], &more].concat(),
            [&[0xfeu8, 0][..], &qenc].concat(),
            [&[0xfeu8, 2][..], &qenc2].concat(),
            [&[0xffu8, 0][..], &qdec].concat(),
            [&[0xffu8, 1][..], &ws].concat(),
            [&[0xfeu8, 0][..], &unknown].concat(),
            [&[0xfeu8, 1][..], &dup].concat(),
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
        let n = replay(DIR, "h3_frame", h3_frame)
            + replay(DIR, "qpack_decode", qpack_decode)
            + replay(DIR, "qpack_dynamic", qpack_dynamic)
            + replay(DIR, "qpack_encoder", qpack_encoder)
            + replay(DIR, "h3_request", h3_request);
        assert!(n > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds::h3_frame() {
            h3_frame(s);
        }
        for s in &seeds::qpack_decode() {
            qpack_decode(s);
        }
        for s in &seeds::h3_request() {
            h3_request(s);
        }
        for s in &seeds::qpack_dynamic() {
            qpack_dynamic(s);
        }
        for s in &seeds::qpack_encoder() {
            qpack_encoder(s);
        }
    }

    /// The encoder harness on pseudo-random operation streams (stable stands in for the
    /// fuzzer): the encoder's inserts, duplicates, dynamic and post-base references and
    /// blocking all happen.
    #[test]
    fn qpack_encoder_random() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut total = crate::qtable::EncStats::default();
        for round in 0..3000u32 {
            let mut d = Vec::with_capacity(400);
            for _ in 0..400 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                d.push(x as u8);
            }
            // Mostly sections and deliveries; tables small enough to fill.
            d[0] = 4 + d[0] % 32;
            d[1] = 4 + d[1] % 32;
            if round % 4 == 0 {
                d[2] = 0;
            }
            let s = stats(&d);
            total.inserts += s.inserts;
            total.duplicates += s.duplicates;
            total.dyn_name_inserts += s.dyn_name_inserts;
            total.dyn_name_lines += s.dyn_name_lines;
            total.post_base += s.post_base;
            total.blocking += s.blocking;
        }
        let t = total;
        assert!(
            t.inserts > 0
                && t.duplicates > 0
                && t.dyn_name_inserts > 0
                && t.dyn_name_lines > 0
                && t.post_base > 0
                && t.blocking > 0,
            "{t:?}"
        );
    }

    /// Runs [`qpack_encoder`] and returns what its encoder did.
    fn stats(d: &[u8]) -> crate::qtable::EncStats {
        STATS.with(|s| s.set(None));
        qpack_encoder(d);
        STATS.with(std::cell::Cell::take).unwrap_or_default()
    }

    /// Regenerates the seed files: `cargo test -p only-h3 --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "h3_frame", &seeds::h3_frame());
        write_target_seeds(DIR, "qpack_decode", &seeds::qpack_decode());
        write_target_seeds(DIR, "h3_request", &seeds::h3_request());
        write_target_seeds(DIR, "qpack_dynamic", &seeds::qpack_dynamic());
        write_target_seeds(DIR, "qpack_encoder", &seeds::qpack_encoder());
    }
}
