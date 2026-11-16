//! HTTP/3 server at the frame level: a raw QUIC client sends crafted control, QPACK and request
//! streams and checks the error codes the server closes or resets with (RFC 9114 §8).
#![allow(missing_docs)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use only::{Engine, Listener};
use only_h3::code;
use only_http::{Context, Router};
use only_quic::Bytes;
use only_quic::{Connection, ConnectionError, QuicHandler, StreamId};

// Frame and unidirectional stream types.
const DATA: u64 = 0x0;
const HEADERS: u64 = 0x1;
const SETTINGS: u64 = 0x4;
const PUSH_PROMISE: u64 = 0x5;
const GOAWAY: u64 = 0x7;
const H2_PING: u64 = 0x6;
const STREAM_CONTROL: u64 = 0x0;
const STREAM_PUSH: u64 = 0x1;
const STREAM_QPACK_ENCODER: u64 = 0x2;

fn varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..0x40 => out.push(v as u8),
        0x40..0x4000 => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        0x4000..0x4000_0000 => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes()),
    }
}

fn frame(out: &mut Vec<u8>, ty: u64, payload: &[u8]) {
    varint(out, ty);
    varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn settings(pairs: &[(u64, u64)]) -> Vec<u8> {
    let mut p = Vec::new();
    for &(id, v) in pairs {
        varint(&mut p, id);
        varint(&mut p, v);
    }
    let mut out = Vec::new();
    frame(&mut out, SETTINGS, &p);
    out
}

fn headers(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut block = Vec::new();
    only_h3::qpack::encode(fields.iter().copied(), &mut block);
    let mut out = Vec::new();
    frame(&mut out, HEADERS, &block);
    out
}

fn get(path: &str) -> Vec<u8> {
    headers(&[
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", path),
    ])
}

/// Unidirectional streams to open: (bytes, fin).
type Streams = Vec<(Vec<u8>, bool)>;

#[derive(Debug)]
enum Got {
    Connected,
    Data(StreamId, Vec<u8>, bool),
    Reset(StreamId, u64),
    Stopped(StreamId, u64),
    Closed(Option<u64>),
}

struct Raw(mpsc::Sender<Got>);

impl QuicHandler for Raw {
    fn on_connected(&mut self, _c: &Connection) {
        let _ = self.0.send(Got::Connected);
    }
    fn on_stream_data(&mut self, _c: &Connection, id: StreamId, data: Bytes, fin: bool) {
        let _ = self.0.send(Got::Data(id, data.to_vec(), fin));
    }
    fn on_stream_reset(&mut self, _c: &Connection, id: StreamId, code: u64) {
        let _ = self.0.send(Got::Reset(id, code));
    }
    fn on_stream_stopped(&mut self, _c: &Connection, id: StreamId, code: u64) {
        let _ = self.0.send(Got::Stopped(id, code));
    }
    fn on_close(&mut self, _c: &Connection, r: ConnectionError) {
        let code = match r {
            ConnectionError::ApplicationClosed { code, .. } => Some(code),
            _ => None,
        };
        let _ = self.0.send(Got::Closed(code));
    }
}

fn setup() -> (Arc<Engine>, SocketAddr) {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = only::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let app = Router::new()
        .get("/", |ctx: &mut Context| ctx.text(200, "root"))
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.req().body.clone();
            ctx.bytes(200, "application/octet-stream", b);
        });
    let quic = only_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(only_h3::serve(quic, app)))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr)
}

fn connect(e: &Arc<Engine>, addr: SocketAddr) -> (Connection, mpsc::Receiver<Got>) {
    let (tx, rx) = mpsc::channel();
    let cc = only_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = only_quic::dial(e, addr, "localhost", cc, Raw(tx)).unwrap();
    match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
        Got::Connected => {}
        g => panic!("{g:?}"),
    }
    (c, rx)
}

/// Opens a unidirectional stream carrying `bytes` (and FIN if `fin`).
fn uni(c: &Connection, bytes: Vec<u8>, fin: bool) -> StreamId {
    let id = c.open_uni().unwrap();
    c.send(id, bytes).unwrap();
    if fin {
        c.finish(id).unwrap();
    }
    id
}

fn control(extra: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    varint(&mut b, STREAM_CONTROL);
    b.extend(settings(&[(0x6, 1 << 16)]));
    b.extend_from_slice(extra);
    b
}

fn closed_with(rx: &mpsc::Receiver<Got>) -> Option<u64> {
    loop {
        match rx.recv_timeout(Duration::from_secs(5)).expect("close") {
            Got::Closed(code) => return code,
            _ => continue,
        }
    }
}

/// The response body on `id`, or the reset code.
fn response(rx: &mpsc::Receiver<Got>, id: StreamId) -> Result<Vec<u8>, u64> {
    let mut b = Vec::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(5)).expect("response") {
            Got::Data(i, d, fin) if i == id => {
                b.extend(d);
                if fin {
                    return Ok(b);
                }
            }
            Got::Reset(i, code) if i == id => return Err(code),
            Got::Closed(c) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
}

#[test]
fn control_stream_errors_close_the_connection() {
    let (e, addr) = setup();
    let mut ctrl_goaway = Vec::new();
    varint(&mut ctrl_goaway, STREAM_CONTROL);
    frame(&mut ctrl_goaway, GOAWAY, &[0]);
    let mut push = Vec::new();
    varint(&mut push, STREAM_PUSH);
    let mut h2_settings = Vec::new();
    varint(&mut h2_settings, STREAM_CONTROL);
    h2_settings.extend(settings(&[(0x2, 0)]));
    let mut dup_settings = Vec::new();
    varint(&mut dup_settings, STREAM_CONTROL);
    dup_settings.extend(settings(&[(0x6, 1), (0x6, 2)]));
    let mut data_on_ctrl = Vec::new();
    frame(&mut data_on_ctrl, DATA, b"x");
    let mut ping_on_ctrl = Vec::new();
    frame(&mut ping_on_ctrl, H2_PING, b"12345678");
    let mut push_on_ctrl = Vec::new();
    frame(&mut push_on_ctrl, PUSH_PROMISE, &[0]);
    let mut second_settings = Vec::new();
    second_settings.extend(settings(&[]));
    let mut qpack_enc = Vec::new();
    varint(&mut qpack_enc, STREAM_QPACK_ENCODER);

    let cases: Vec<(&str, Streams, u32)> = vec![
        (
            "no SETTINGS first",
            vec![(ctrl_goaway, false)],
            code::MISSING_SETTINGS,
        ),
        (
            "two control streams",
            vec![(control(&[]), false), (control(&[]), false)],
            code::STREAM_CREATION_ERROR,
        ),
        (
            "push stream from a client",
            vec![(push, false)],
            code::STREAM_CREATION_ERROR,
        ),
        (
            "HTTP/2 setting",
            vec![(h2_settings, false)],
            code::SETTINGS_ERROR,
        ),
        (
            "duplicate setting",
            vec![(dup_settings, false)],
            code::SETTINGS_ERROR,
        ),
        (
            "DATA on control",
            vec![(control(&data_on_ctrl), false)],
            code::FRAME_UNEXPECTED,
        ),
        (
            "HTTP/2 frame on control",
            vec![(control(&ping_on_ctrl), false)],
            code::FRAME_UNEXPECTED,
        ),
        (
            "PUSH_PROMISE on control",
            vec![(control(&push_on_ctrl), false)],
            code::FRAME_UNEXPECTED,
        ),
        (
            "second SETTINGS",
            vec![(control(&second_settings), false)],
            code::FRAME_UNEXPECTED,
        ),
        (
            "control stream closed",
            vec![(control(&[]), true)],
            code::CLOSED_CRITICAL_STREAM,
        ),
        (
            "QPACK stream closed",
            vec![(qpack_enc, true)],
            code::CLOSED_CRITICAL_STREAM,
        ),
    ];
    for (name, streams, want) in cases {
        let (c, rx) = connect(&e, addr);
        for (bytes, fin) in streams {
            uni(&c, bytes, fin);
        }
        assert_eq!(closed_with(&rx), Some(u64::from(want)), "{name}");
    }
    e.shutdown();
    e.wait();
}

#[test]
fn request_stream_errors() {
    let (e, addr) = setup();
    // An unknown unidirectional stream type is stopped, not fatal; GOAWAY on control is fine.
    let (c, rx) = connect(&e, addr);
    let mut goaway = Vec::new();
    frame(&mut goaway, GOAWAY, &[0]);
    uni(&c, control(&goaway), false);
    let mut unknown = Vec::new();
    varint(&mut unknown, 0x21);
    unknown.extend_from_slice(b"whatever");
    let u = uni(&c, unknown, false);
    loop {
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Got::Stopped(id, code) if id == u => {
                assert_eq!(code, u64::from(code::STREAM_CREATION_ERROR));
                break;
            }
            Got::Closed(c) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
    // A valid request still works, with trailers and an unknown frame type in it.
    let id = c.open_bi().unwrap();
    let mut req = headers(&[
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "localhost"),
        (":path", "/echo"),
    ]);
    frame(&mut req, DATA, b"abc");
    frame(&mut req, 0x21, b"reserved");
    req.extend(headers(&[("x-trailer", "1")]));
    c.send(id, req).unwrap();
    c.finish(id).unwrap();
    let body = response(&rx, id).unwrap();
    assert!(body.windows(3).any(|w| w == b"abc"));

    // Malformed requests are stream errors (H3_MESSAGE_ERROR / H3_REQUEST_INCOMPLETE).
    let bad: Vec<Vec<u8>> = vec![
        headers(&[(":method", "GET"), (":scheme", "https"), (":path", "")]),
        headers(&[
            (":method", "GET"),
            ("x", "1"),
            (":scheme", "https"),
            (":path", "/"),
        ]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":x", "1"),
        ]),
        headers(&[
            (":method", "GET"),
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
        ]),
        headers(&[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "h"),
        ]),
        headers(&[(":method", "CONNECT")]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("Upper", "1"),
        ]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("connection", "x"),
        ]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("te", "gzip"),
        ]),
        headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("content-length", "5"),
        ]),
        {
            let mut r = get("/");
            r.extend(headers(&[(":bad", "trailer")]));
            r
        },
        Vec::new(), // no HEADERS at all
    ];
    for (i, req) in bad.into_iter().enumerate() {
        let id = c.open_bi().unwrap();
        if !req.is_empty() {
            c.send(id, req).unwrap();
        }
        c.finish(id).unwrap();
        let r = response(&rx, id);
        assert!(
            r == Err(u64::from(code::MESSAGE_ERROR))
                || r == Err(u64::from(code::REQUEST_INCOMPLETE)),
            "case {i}: {r:?}"
        );
    }
    // CONNECT with an authority only is well formed (and not routed).
    let id = c.open_bi().unwrap();
    c.send(
        id,
        headers(&[(":method", "CONNECT"), (":authority", "h:1")]),
    )
    .unwrap();
    c.finish(id).unwrap();
    assert!(response(&rx, id).is_ok());
    c.close(0, b"");

    // Connection errors on request streams.
    let mut data_first = Vec::new();
    frame(&mut data_first, DATA, b"x");
    let mut three_sections = get("/");
    three_sections.extend(headers(&[("a", "1")]));
    three_sections.extend(headers(&[("b", "2")]));
    let mut data_after_trailers = get("/");
    data_after_trailers.extend(headers(&[("a", "1")]));
    frame(&mut data_after_trailers, DATA, b"x");
    let mut settings_on_req = get("/");
    frame(&mut settings_on_req, SETTINGS, &[]);
    let mut h2_frame_on_req = get("/");
    frame(&mut h2_frame_on_req, H2_PING, &[0; 8]);
    let mut bad_qpack = Vec::new();
    frame(&mut bad_qpack, HEADERS, &[0xff, 0xff, 0xff]);
    for (name, req, want) in [
        ("DATA before HEADERS", data_first, code::FRAME_UNEXPECTED),
        (
            "three field sections",
            three_sections,
            code::FRAME_UNEXPECTED,
        ),
        (
            "DATA after trailers",
            data_after_trailers,
            code::FRAME_UNEXPECTED,
        ),
        (
            "SETTINGS on a request",
            settings_on_req,
            code::FRAME_UNEXPECTED,
        ),
        (
            "HTTP/2 frame on a request",
            h2_frame_on_req,
            code::FRAME_UNEXPECTED,
        ),
        ("bad QPACK", bad_qpack, code::QPACK_DECOMPRESSION_FAILED),
    ] {
        let (c, rx) = connect(&e, addr);
        let id = c.open_bi().unwrap();
        c.send(id, req).unwrap();
        assert_eq!(closed_with(&rx), Some(u64::from(want)), "{name}");
    }

    // A client reset of a pending request is tolerated.
    let (c, rx) = connect(&e, addr);
    let id = c.open_bi().unwrap();
    c.send(id, get("/")).unwrap();
    c.reset(id, 0x10c).unwrap();
    let id = c.open_bi().unwrap();
    c.send(id, get("/")).unwrap();
    c.finish(id).unwrap();
    assert!(response(&rx, id).is_ok());
    e.shutdown();
    e.wait();
}

const STREAM_QPACK_DECODER: u64 = 0x3;

/// Stream bytes (and whether they ended) as they arrive, until `done` says enough.
fn collect(
    rx: &mpsc::Receiver<Got>,
    done: impl Fn(&HashMap<StreamId, (Vec<u8>, bool)>) -> bool,
) -> HashMap<StreamId, (Vec<u8>, bool)> {
    let mut by_stream: HashMap<StreamId, (Vec<u8>, bool)> = HashMap::new();
    while !done(&by_stream) {
        match rx
            .recv_timeout(Duration::from_secs(5))
            .expect("stream data")
        {
            Got::Data(id, d, fin) => {
                let e = by_stream.entry(id).or_default();
                e.0.extend(d);
                e.1 |= fin;
            }
            Got::Closed(c) => panic!("closed: {c:?}"),
            _ => {}
        }
    }
    by_stream
}

/// The server's QPACK decoder stream, if its first bytes are in `m`.
fn decoder_id(m: &HashMap<StreamId, (Vec<u8>, bool)>) -> Option<StreamId> {
    m.iter()
        .find(|(id, (b, _))| {
            id.dir() == only_quic::Dir::Uni && b.first() == Some(&(STREAM_QPACK_DECODER as u8))
        })
        .map(|(id, _)| *id)
}

/// The server's QPACK decoder stream bytes (after its type byte).
fn decoder_stream(m: &HashMap<StreamId, (Vec<u8>, bool)>) -> &[u8] {
    decoder_id(m).map_or(&[], |id| &m[&id].0[1..])
}

/// A field section with Required Insert Count 2 (220-byte table) referencing two inserts by
/// post-base index: `:authority` and `:path` from RFC 9204 Appendix B.2, plus `:method GET`
/// and `:scheme https` from the static table.
fn blocked_get() -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, HEADERS, &[0x03, 0x81, 0xd1, 0xd7, 0x10, 0x11]);
    out
}

/// The encoder stream of RFC 9204 Appendix B.2, minus its type: capacity 220, then two inserts
/// (`:authority www.example.com`, `:path /`).
fn inserts() -> Vec<u8> {
    let mut b = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
    b.extend_from_slice(b"www.example.com");
    b.extend_from_slice(&[0xc1, 0x01, b'/']);
    b
}

#[test]
fn qpack_blocked_streams() {
    let (e, addr) = setup();
    // SETTINGS name our own decoder limits; the server's decoder allows 4 KiB, 16 blocked.
    let (c, rx) = connect(&e, addr);
    uni(&c, control(&[]), false);
    let enc = c.open_uni().unwrap();
    c.send(enc, vec![STREAM_QPACK_ENCODER as u8]).unwrap();
    // Two requests wait for inserts that are not there yet; a third, static, goes through.
    let a = c.open_bi().unwrap();
    let mut req = blocked_get();
    frame(&mut req, 0x21, b"held behind the section");
    c.send(a, req).unwrap();
    c.finish(a).unwrap();
    let b = c.open_bi().unwrap();
    c.send(b, blocked_get()).unwrap();
    c.finish(b).unwrap();
    let s = c.open_bi().unwrap();
    c.send(s, get("/")).unwrap();
    c.finish(s).unwrap();
    assert!(response(&rx, s).is_ok());
    // The inserts arrive in two pieces: both blocked requests are answered.
    let ins = inserts();
    c.send(enc, ins[..7].to_vec()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    c.send(enc, ins[7..].to_vec()).unwrap();
    let ra = response(&rx, a).unwrap();
    let rb = response(&rx, b).unwrap();
    assert!(ra.windows(4).any(|w| w == b"root"), "{ra:?}");
    assert!(rb.windows(4).any(|w| w == b"root"), "{rb:?}");
    c.close(0, b"");

    // Section acknowledgements for both streams arrive on the server's decoder stream (the
    // order of the two depends on the unblocking order), and a blocked stream that is reset
    // is cancelled.
    let (c, rx) = connect(&e, addr);
    uni(&c, control(&[]), false);
    let enc = c.open_uni().unwrap();
    c.send(enc, vec![STREAM_QPACK_ENCODER as u8]).unwrap();
    let a = c.open_bi().unwrap();
    c.send(a, blocked_get()).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    c.reset(a, 0x10c).unwrap();
    let m = collect(&rx, |m| !decoder_stream(m).is_empty());
    // Stream Cancellation of stream 0.
    assert_eq!(decoder_stream(&m), [0x40]);
    let b = c.open_bi().unwrap();
    c.send(b, blocked_get()).unwrap();
    c.finish(b).unwrap();
    c.send(enc, inserts()).unwrap();
    // Section Acknowledgement of stream 4 (Required Insert Count 2 covers both inserts, so
    // no Insert Count Increment), and the response.
    let dec = decoder_id(&m).unwrap();
    let m = collect(&rx, |m| {
        m.contains_key(&dec) && m.get(&b).is_some_and(|(_, fin)| *fin)
    });
    assert_eq!(m[&dec].0, [0x84]);
    // Inserts no section references are acknowledged with an increment.
    let mut more = vec![0xc0, 0x01, b'x'];
    more.extend_from_slice(&[0xc0, 0x01, b'y']);
    c.send(enc, more).unwrap();
    let m = collect(&rx, |m| m.contains_key(&dec));
    assert_eq!(m[&dec].0, [0x02]);
    c.close(0, b"");

    // More blocked streams than the server allows: QPACK_DECOMPRESSION_FAILED.
    let (c, rx) = connect(&e, addr);
    uni(&c, control(&[]), false);
    for _ in 0..17 {
        let id = c.open_bi().unwrap();
        c.send(id, blocked_get()).unwrap();
    }
    assert_eq!(
        closed_with(&rx),
        Some(u64::from(code::QPACK_DECOMPRESSION_FAILED))
    );

    // Encoder stream errors: a capacity above the server's maximum, a reference to an entry
    // that does not exist; a second encoder stream; decoder stream instructions for a table
    // the server never filled.
    let mut over = vec![STREAM_QPACK_ENCODER as u8];
    over.extend_from_slice(&[0x3f, 0xe2, 0x1f]); // 4099
    let mut bad_ref = vec![STREAM_QPACK_ENCODER as u8];
    bad_ref.extend_from_slice(&[0x3f, 0xbd, 0x01, 0x80, 0x01, b'x']);
    let mut ack = vec![STREAM_QPACK_DECODER as u8];
    ack.push(0x80);
    let mut increment = vec![STREAM_QPACK_DECODER as u8];
    increment.push(0x01);
    let enc_only = vec![STREAM_QPACK_ENCODER as u8];
    let cases: Vec<(&str, Streams, u32)> = vec![
        (
            "capacity over the maximum",
            vec![(over, false)],
            code::QPACK_ENCODER_STREAM_ERROR,
        ),
        (
            "insert with a missing name",
            vec![(bad_ref, false)],
            code::QPACK_ENCODER_STREAM_ERROR,
        ),
        (
            "two encoder streams",
            vec![(enc_only.clone(), false), (enc_only, false)],
            code::STREAM_CREATION_ERROR,
        ),
        (
            "acknowledgement of nothing",
            vec![(ack, false)],
            code::QPACK_DECODER_STREAM_ERROR,
        ),
        (
            "increment past the inserts",
            vec![(increment, false)],
            code::QPACK_DECODER_STREAM_ERROR,
        ),
    ];
    for (name, streams, want) in cases {
        let (c, rx) = connect(&e, addr);
        for (bytes, fin) in streams {
            uni(&c, bytes, fin);
        }
        assert_eq!(closed_with(&rx), Some(u64::from(want)), "{name}");
    }

    // The server's SETTINGS: its QPACK limits and extended CONNECT.
    let (c, rx) = connect(&e, addr);
    uni(&c, control(&[]), false);
    let mut want = vec![STREAM_CONTROL as u8];
    want.extend(settings(&[
        (0x1, 4096),
        (0x7, 16),
        (0x6, 64 << 10),
        (0x8, 1),
    ]));
    let m = collect(&rx, |m| {
        m.values()
            .any(|(b, _)| b.first() == Some(&(STREAM_CONTROL as u8)) && b.len() >= want.len())
    });
    let ctrl = m
        .values()
        .map(|(b, _)| b)
        .find(|b| b.first() == Some(&(STREAM_CONTROL as u8)))
        .unwrap();
    let mut want = vec![STREAM_CONTROL as u8];
    want.extend(settings(&[
        (0x1, 4096),
        (0x7, 16),
        (0x6, 64 << 10),
        (0x8, 1),
    ]));
    assert!(ctrl.starts_with(&want), "{ctrl:?}");
    e.shutdown();
    e.wait();
}

#[test]
fn extended_connect_rules() {
    let (e, addr) = setup();
    let (c, rx) = connect(&e, addr);
    uni(&c, control(&[]), false);
    // `:protocol` needs CONNECT with every pseudo-header field.
    for bad in [
        vec![
            (":method", "GET"),
            (":protocol", "websocket"),
            (":scheme", "https"),
            (":authority", "h"),
            (":path", "/"),
        ],
        vec![
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":authority", "h"),
            (":path", "/"),
        ],
        vec![
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "https"),
            (":authority", "h"),
        ],
    ] {
        let id = c.open_bi().unwrap();
        c.send(id, headers(&bad)).unwrap();
        c.finish(id).unwrap();
        assert_eq!(
            response(&rx, id),
            Err(u64::from(code::MESSAGE_ERROR)),
            "{bad:?}"
        );
    }
    // A WebSocket request to a GET route that does not upgrade it: an ordinary answer.
    let id = c.open_bi().unwrap();
    c.send(
        id,
        headers(&[
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "https"),
            (":authority", "h"),
            (":path", "/"),
            ("sec-websocket-version", "13"),
        ]),
    )
    .unwrap();
    let body = response(&rx, id).unwrap();
    assert!(body.windows(4).any(|w| w == b"root"));
    e.shutdown();
    e.wait();
}
