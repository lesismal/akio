//! An extended CONNECT (RFC 9220) answered with a streamed `200` is a tunnel (ADR-113): its
//! bytes reach the handler as a streamed body, the handler's go back as DATA, and the two
//! halves close separately (the response finished, the client's bytes still arrive).
#![allow(missing_docs)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use akio::{Engine, Listener};
use akio_http::{BodyEvent, Context, Headers, Router, Streaming};
use akio_quic::Bytes;
use akio_quic::{Connection, ConnectionError, QuicHandler, StreamId};

const DATA: u64 = 0x0;
const HEADERS: u64 = 0x1;
const SETTINGS: u64 = 0x4;
const STREAM_CONTROL: u64 = 0x0;
const WAIT: Duration = Duration::from_secs(10);

fn varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..0x40 => out.push(v as u8),
        0x40..0x4000 => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        0x4000..0x4000_0000 => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes()),
    }
}

/// A varint at the start of `b`: (value, length), or `None` if incomplete.
fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for x in &b[1..len] {
        v = (v << 8) | u64::from(*x);
    }
    Some((v, len))
}

fn frame(out: &mut Vec<u8>, ty: u64, payload: &[u8]) {
    varint(out, ty);
    varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn data(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    frame(&mut out, DATA, payload);
    out
}

#[derive(Debug)]
enum Got {
    Connected,
    Data(StreamId, Vec<u8>, bool),
    Reset(StreamId, u64),
    Stopped(StreamId, u64),
    Closed,
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
    fn on_close(&mut self, _c: &Connection, _r: ConnectionError) {
        let _ = self.0.send(Got::Closed);
    }
}

fn setup(seen: mpsc::Sender<String>) -> (Arc<Engine>, SocketAddr) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let seen = Arc::new(Mutex::new(seen));
    let seen2 = seen.clone();
    let app = Router::new().fallback(Streaming(move |ctx: &mut Context| {
        // A CONNECT (RFC 9114 §4.4, A134): the target is the authority; a streamed `200`
        // naming it, then the stream's bytes echoed back.
        let target = ctx.req().target.clone();
        let seen = seen2.clone();
        let _ = seen.lock().unwrap().send(format!("connect {target}"));
        let out = Arc::new(Mutex::new(ctx.stream_response(200, Headers::new())));
        if let Some(s) = out.lock().unwrap().as_ref() {
            let _ = s.write(format!("to {target};").as_bytes());
        }
        ctx.on_body(move |_ctx, ev: BodyEvent<'_>| {
            let mut out = out.lock().unwrap();
            match ev {
                BodyEvent::Chunk(b) => {
                    if let Some(s) = out.as_ref() {
                        let _ = s.write(b);
                    }
                }
                BodyEvent::End(_) => {
                    if let Some(s) = out.take() {
                        s.finish();
                    }
                    let _ = seen.lock().unwrap().send("end".into());
                }
                BodyEvent::TooLarge => {}
            }
        });
    }));
    let app = app.get(
        "/tunnel",
        Streaming(move |ctx: &mut Context| {
            let seen = seen.clone();
            let out = Arc::new(Mutex::new(ctx.stream_response(200, Headers::new())));
            ctx.on_body(move |_ctx, ev: BodyEvent<'_>| {
                let mut out = out.lock().unwrap();
                match ev {
                    BodyEvent::Chunk(b) if b == b"bye" => {
                        if let Some(s) = out.take() {
                            let _ = s.write(b"bye");
                            s.finish();
                        }
                    }
                    BodyEvent::Chunk(b) => match out.as_ref() {
                        Some(s) => {
                            let _ = s.write(&[b"echo:".as_slice(), b].concat());
                        }
                        None => {
                            let msg = format!("late {}", String::from_utf8_lossy(b));
                            let _ = seen.lock().unwrap().send(msg);
                        }
                    },
                    BodyEvent::End(_) => {
                        if let Some(s) = out.take() {
                            s.finish();
                        }
                        let _ = seen.lock().unwrap().send("end".into());
                    }
                    BodyEvent::TooLarge => {}
                }
            });
        }),
    );
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, app)))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (Arc::new(e), addr)
}

/// The frames of one request stream as they arrive.
struct Stream {
    id: StreamId,
    buf: Vec<u8>,
    fin: bool,
}

impl Stream {
    /// The next frame (type, payload), reading more as needed; `None` once the stream ended.
    fn frame(&mut self, rx: &mpsc::Receiver<Got>) -> Option<(u64, Vec<u8>)> {
        loop {
            if let Some((ty, a)) = read_varint(&self.buf) {
                if let Some((len, b)) = read_varint(&self.buf[a..]) {
                    let end = a + b + len as usize;
                    if self.buf.len() >= end {
                        let p = self.buf[a + b..end].to_vec();
                        self.buf.drain(..end);
                        return Some((ty, p));
                    }
                }
            }
            if self.fin {
                return None;
            }
            match rx.recv_timeout(WAIT).expect("stream data") {
                Got::Data(i, d, fin) if i == self.id => {
                    self.buf.extend(d);
                    self.fin = fin;
                }
                Got::Reset(i, c) | Got::Stopped(i, c) if i == self.id => {
                    panic!("stream reset or stopped: {c}")
                }
                Got::Closed => panic!("connection closed"),
                _ => {}
            }
        }
    }

    /// DATA payloads until `want` came.
    fn data(&mut self, rx: &mpsc::Receiver<Got>, want: &[u8]) {
        let mut got = Vec::new();
        while got.len() < want.len() {
            match self.frame(rx) {
                Some((DATA, p)) => got.extend(p),
                Some(_) => {}
                None => break,
            }
        }
        assert_eq!(got, want);
    }
}

#[test]
fn a_streamed_200_to_an_extended_connect_is_a_tunnel() {
    let (tx, seen) = mpsc::channel();
    let (e, addr) = setup(tx);
    let (rtx, rx) = mpsc::channel();
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = akio_quic::dial(&e, addr, "localhost", cc, Raw(rtx)).unwrap();
    assert!(matches!(rx.recv_timeout(WAIT).unwrap(), Got::Connected));
    let ctl = c.open_uni().unwrap();
    let mut b = Vec::new();
    varint(&mut b, STREAM_CONTROL);
    let mut p = Vec::new();
    varint(&mut p, 0x6);
    varint(&mut p, 1 << 16);
    frame(&mut b, SETTINGS, &p);
    c.send(ctl, b).unwrap();

    let id = c.open_bi().unwrap();
    let mut block = Vec::new();
    akio_h3::qpack::encode(
        [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "https"),
            (":authority", "localhost"),
            (":path", "/tunnel"),
            ("sec-websocket-version", "13"),
        ],
        &mut block,
    );
    let mut head = Vec::new();
    frame(&mut head, HEADERS, &block);
    c.send(id, head).unwrap();
    let mut s = Stream {
        id,
        buf: Vec::new(),
        fin: false,
    };
    let (ty, _) = s.frame(&rx).expect("the response head");
    assert_eq!(ty, HEADERS);

    c.send(id, data(b"abc")).unwrap();
    s.data(&rx, b"echo:abc");
    // Our half ends: the client's still carries its bytes, until it ends its own.
    c.send(id, data(b"bye")).unwrap();
    s.data(&rx, b"bye");
    assert!(s.frame(&rx).is_none(), "the response finished");
    c.send(id, data(b"late")).unwrap();
    assert_eq!(seen.recv_timeout(WAIT).unwrap(), "late late");
    c.finish(id).unwrap();
    assert_eq!(seen.recv_timeout(WAIT).unwrap(), "end");
    while let Ok(g) = rx.recv_timeout(Duration::from_millis(200)) {
        assert!(
            !matches!(g, Got::Reset(i, _) | Got::Stopped(i, _) if i == id),
            "{g:?}"
        );
    }
    e.shutdown();
    e.wait();
}

/// A CONNECT (RFC 9114 §4.4, A134), `:method` and `:authority` alone: dispatched at its head,
/// before any DATA, and its streamed `200` a tunnel.
#[test]
fn a_streamed_200_to_a_connect_is_a_tunnel() {
    let (tx, seen) = mpsc::channel();
    let (e, addr) = setup(tx);
    let (rtx, rx) = mpsc::channel();
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = akio_quic::dial(&e, addr, "localhost", cc, Raw(rtx)).unwrap();
    assert!(matches!(rx.recv_timeout(WAIT).unwrap(), Got::Connected));
    let id = c.open_bi().unwrap();
    let mut block = Vec::new();
    akio_h3::qpack::encode(
        [(":method", "CONNECT"), (":authority", "example.com:443")],
        &mut block,
    );
    let mut head = Vec::new();
    frame(&mut head, HEADERS, &block);
    c.send(id, head).unwrap();
    assert_eq!(
        seen.recv_timeout(WAIT).unwrap(),
        "connect example.com:443",
        "dispatched before any DATA"
    );
    let mut s = Stream {
        id,
        buf: Vec::new(),
        fin: false,
    };
    let (ty, _) = s.frame(&rx).expect("the response head");
    assert_eq!(ty, HEADERS);
    s.data(&rx, b"to example.com:443;");
    c.send(id, data(b"ping")).unwrap();
    s.data(&rx, b"ping");
    c.finish(id).unwrap();
    assert_eq!(seen.recv_timeout(WAIT).unwrap(), "end");
    assert!(s.frame(&rx).is_none(), "our half ended after the client's");
    e.shutdown();
    e.wait();
}
