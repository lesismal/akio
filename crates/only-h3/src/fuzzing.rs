//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use only_quic::{Dir, Side, StreamId};

use crate::frame::Reader;
use crate::{H3Config, Req, Uni, qpack, read_req};

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

/// `h3_frame`: the frame reader (frames must not depend on read boundaries) and a peer's
/// unidirectional stream (stream type, control stream SETTINGS and frame rules, QPACK streams).
/// `data[0]`: bit 0 client side (else server), the rest the frame size limit; `data[1]` splits.
pub fn h3_frame(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let max = u64::from(data[0] >> 1) * 64;
    let wire = &data[2..];
    let ps = pieces(data[1], wire);
    assert_eq!(frames(max, &[wire]), frames(max, &ps));
    let server = data[0] & 1 == 0;
    let mut u = Uni::Unknown(Reader::default());
    let mut ctrl = None;
    let mut stop = |_: StreamId, _: u32| {};
    let side = if server { Side::Client } else { Side::Server };
    let id = StreamId::new(side, Dir::Uni, 0);
    for (i, p) in ps.iter().enumerate() {
        let fin = i + 1 == ps.len();
        if crate::on_uni(&mut u, &mut ctrl, &mut stop, id, p, fin, server).is_err() {
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

/// `h3_request`: a request stream (HEADERS, DATA, trailers, unknown and forbidden frames, size
/// limits) and building the request from its field sections. `data[0]` splits the reads.
pub fn h3_request(data: &[u8]) {
    let Some((&seed, wire)) = data.split_first() else {
        return;
    };
    let cfg = H3Config {
        max_body_bytes: 16 << 10,
        max_field_section_bytes: 4 << 10,
    };
    let peer = "127.0.0.1:4433".parse().expect("addr");
    let mut req = Req::default();
    let ps = pieces(seed, wire);
    for (i, p) in ps.iter().enumerate() {
        let fin = i + 1 == ps.len();
        match read_req(&mut req, &cfg, peer, p, fin) {
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
        vec![
            [&[0u8][..], &a].concat(),
            [&[0u8][..], &b].concat(),
            [&[3u8][..], &b].concat(),
            [&[0u8][..], &c].concat(),
            [&[0u8][..], &d].concat(),
            vec![0, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ]
    }

    pub(super) fn h3_frame() -> Vec<Vec<u8>> {
        let ctrl = crate::control_stream_preamble(1 << 16);
        let mut more = ctrl.clone();
        put_frame(&mut more, frame::GOAWAY, &[0]);
        put_frame(&mut more, frame::MAX_PUSH_ID, &[4]);
        put_frame(&mut more, 0x21, b"grease");
        let mut qenc = Vec::new();
        put_varint(&mut qenc, frame::STREAM_QPACK_ENCODER);
        qenc.push(0x20); // set dynamic table capacity 0
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
    }

    /// Regenerates the seed files: `cargo test -p only-h3 --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "h3_frame", &seeds::h3_frame());
        write_target_seeds(DIR, "qpack_decode", &seeds::qpack_decode());
        write_target_seeds(DIR, "h3_request", &seeds::h3_request());
    }
}
