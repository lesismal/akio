//! `connect_proxy` relaying a CONNECT on an HTTP/2 stream (RFC 9113 §8.5) and on an HTTP/3
//! stream (RFC 9114 §4.4), A134: bytes both ways with backpressure, several tunnels on one
//! connection, refusals, a client that resets its stream, an upstream that closes, and the idle
//! timeout. HTTP/2 is driven frame by frame over h2c; `AKIO_TEST_BACKEND=uring` serves it on
//! io_uring (HTTP/3 runs on the UDP loop).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Condvar, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, EngineRef, Listener, UringConfig};
use akio_http::{
    H2Config, HttpConfig, Method,
    client::ClientRequest,
    h2client::{H2Client, H2Event, H2Options},
    hpack::{Decoder, Encoder},
    serve_with,
};
use akio_quic::{Bytes, Connection, ConnectionError, QuicHandler, StreamId};
use akio_socks::{Destinations, ProxyConfig, connect_proxy_with};

const WAIT: Duration = Duration::from_secs(10);

fn uring() -> bool {
    std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring")
}

fn backend() -> Backend {
    if uring() {
        let mut v = UringConfig::default();
        v.strict = true;
        Backend::IoUring(v)
    } else {
        Backend::Epoll
    }
}

fn loopback_ok() -> ProxyConfig {
    let mut c = ProxyConfig::default();
    c.destinations = Destinations::Any;
    c
}

/// A thread-per-connection echo server; each connection's end is reported on `closed`.
fn echo_server(closed: Option<mpsc::Sender<()>>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            let closed = closed.clone();
            thread::spawn(move || {
                let mut s = s;
                let mut b = vec![0u8; 64 << 10];
                loop {
                    match s.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                if let Some(c) = closed {
                    let _ = c.send(());
                }
            });
        }
    });
    a
}

/// An upstream that says `hi` and closes.
fn hello_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let _ = s.write_all(b"hi");
        }
    });
    a
}

/// A port nothing listens on.
fn closed_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 7 + seed) % 251) as u8).collect()
}

/// An h2c proxy (prior knowledge) serving `connect_proxy_with(cfg)`.
fn h2_proxy(cfg: ProxyConfig) -> Arc<Engine> {
    let er = EngineRef::new();
    let mut hc = HttpConfig::default();
    hc.h2 = Some(H2Config::default());
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(2)
                    .serve(serve_with(hc, connect_proxy_with(er.clone(), cfg))),
            )
            .client_threads(if uring() { 0 } else { 2 })
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

// ---- an HTTP/2 client driven by hand -------------------------------------------------------

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const CANCEL: u32 = 8;

#[derive(Debug)]
enum Ev {
    Head(u32, u16, bool),
    Data(u32, Vec<u8>, bool),
    Reset(u32, u32),
    GoAway,
}

/// The server's send windows for us: the connection's and each stream's.
#[derive(Default)]
struct Windows {
    conn: i64,
    initial: i64,
    streams: HashMap<u32, i64>,
}

/// What goes out on the connection, in order, written by a thread of its own.
type Writer = mpsc::Sender<Vec<u8>>;

fn send_frame(w: &Writer, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
    let mut b = (payload.len() as u32).to_be_bytes()[1..].to_vec();
    b.push(ty);
    b.push(flags);
    b.extend_from_slice(&sid.to_be_bytes());
    b.extend_from_slice(payload);
    // Fails only once the writer is gone (its write failed, and said so).
    let _ = w.send(b);
}

/// Writes what is queued on `rx` until the connection ends.
fn write_frames(mut s: TcpStream, rx: mpsc::Receiver<Vec<u8>>) {
    for b in rx {
        if let Err(e) = s.write_all(&b) {
            // The proxy closed the connection, or stopped reading it for good.
            return eprintln!("writing to the proxy: {e}");
        }
    }
}

/// One h2c connection: flow control both ways (ours wide open, the server's window heeded),
/// read and written on threads of their own, so that neither waits on the other. The reader
/// must never wait for a write to finish (RFC 9113 §5.2.2: a receiver reads in a timely
/// fashion): the proxy, as every akio connection, stops reading a peer whose output is queued
/// past `Config::write_high_watermark`, so a reader stuck behind a write that waits for the
/// proxy to read (to send a WINDOW_UPDATE, say) would leave both sides waiting for good.
struct H2 {
    w: Writer,
    enc: Encoder,
    win: Arc<(Mutex<Windows>, Condvar)>,
    rx: mpsc::Receiver<Ev>,
    /// Events of other streams that came while one stream's were awaited: the streams of a
    /// connection are answered in no particular order (a literal address and a name to resolve
    /// may connect either way round).
    later: RefCell<VecDeque<Ev>>,
}

impl Ev {
    fn sid(&self) -> Option<u32> {
        match self {
            Ev::Head(s, ..) | Ev::Data(s, ..) | Ev::Reset(s, _) => Some(*s),
            Ev::GoAway => None,
        }
    }
}

/// Reads frames until the connection ends: answers SETTINGS and PING, tracks the windows,
/// gives back the window of every DATA, and hands the stream events on.
fn read_frames(
    mut s: TcpStream,
    w: Writer,
    win: Arc<(Mutex<Windows>, Condvar)>,
    tx: mpsc::Sender<Ev>,
) {
    let mut dec = Decoder::new();
    loop {
        let mut h = [0u8; 9];
        if s.read_exact(&mut h).is_err() {
            return;
        }
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        let (ty, flags) = (h[3], h[4]);
        let sid = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
        let mut p = vec![0; len];
        if s.read_exact(&mut p).is_err() {
            return;
        }
        let ev = match ty {
            SETTINGS if flags & ACK == 0 => {
                let mut g = win.0.lock().unwrap();
                for c in p.chunks_exact(6) {
                    if u16::from_be_bytes([c[0], c[1]]) == 4 {
                        let v = i64::from(u32::from_be_bytes([c[2], c[3], c[4], c[5]]));
                        let delta = v - g.initial;
                        for w in g.streams.values_mut() {
                            *w += delta;
                        }
                        g.initial = v;
                    }
                }
                drop(g);
                win.1.notify_all();
                send_frame(&w, SETTINGS, ACK, 0, &[]);
                None
            }
            WINDOW_UPDATE => {
                let inc = i64::from(u32::from_be_bytes(p[..4].try_into().unwrap()));
                let mut g = win.0.lock().unwrap();
                if sid == 0 {
                    g.conn += inc;
                } else if let Some(w) = g.streams.get_mut(&sid) {
                    *w += inc;
                }
                drop(g);
                win.1.notify_all();
                None
            }
            PING if flags & ACK == 0 => {
                send_frame(&w, PING, ACK, 0, &p);
                None
            }
            HEADERS => {
                let list = dec.decode(&p).unwrap();
                let status = list
                    .iter()
                    .find(|(n, _)| n == b":status")
                    .map_or(0, |(_, v)| std::str::from_utf8(v).unwrap().parse().unwrap());
                Some(Ev::Head(sid, status, flags & END_STREAM != 0))
            }
            DATA => {
                if !p.is_empty() {
                    // Ours stays open: give back what came.
                    let inc = (p.len() as u32).to_be_bytes();
                    send_frame(&w, WINDOW_UPDATE, 0, 0, &inc);
                    send_frame(&w, WINDOW_UPDATE, 0, sid, &inc);
                }
                Some(Ev::Data(sid, p, flags & END_STREAM != 0))
            }
            RST_STREAM => Some(Ev::Reset(
                sid,
                u32::from_be_bytes(p[..4].try_into().unwrap()),
            )),
            GOAWAY => Some(Ev::GoAway),
            _ => None,
        };
        if let Some(ev) = ev
            && tx.send(ev).is_err()
        {
            return;
        }
    }
}

impl H2 {
    fn open(e: &Engine) -> H2 {
        let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
        s.set_write_timeout(Some(WAIT)).unwrap();
        let (w, out) = mpsc::channel();
        let ws = s.try_clone().unwrap();
        thread::spawn(move || write_frames(ws, out));
        w.send(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec())
            .unwrap();
        // INITIAL_WINDOW_SIZE as large as it goes, and the connection's the same.
        send_frame(&w, SETTINGS, 0, 0, &[0, 4, 0x7f, 0xff, 0xff, 0xff]);
        send_frame(
            &w,
            WINDOW_UPDATE,
            0,
            0,
            &(0x7fff_ffffu32 - 65_535).to_be_bytes(),
        );
        let win = Arc::new((
            Mutex::new(Windows {
                conn: 65_535,
                initial: 65_535,
                streams: HashMap::new(),
            }),
            Condvar::new(),
        ));
        let (tx, rx) = mpsc::channel();
        let (w2, win2) = (w.clone(), win.clone());
        thread::spawn(move || read_frames(s, w2, win2, tx));
        H2 {
            w,
            enc: Encoder::new(),
            win,
            rx,
            later: RefCell::default(),
        }
    }

    fn send(&self, ty: u8, flags: u8, sid: u32, payload: &[u8]) {
        send_frame(&self.w, ty, flags, sid, payload);
    }

    fn connect(&mut self, sid: u32, authority: &str) {
        let b = self.enc.encode(
            [(":method", "CONNECT"), (":authority", authority)]
                .iter()
                .map(|(n, v)| (n.as_bytes(), v.as_bytes())),
        );
        {
            let mut g = self.win.0.lock().unwrap();
            let initial = g.initial;
            g.streams.insert(sid, initial);
        }
        self.send(HEADERS, END_HEADERS, sid, &b);
    }

    /// The next stream event.
    fn next(&self) -> Ev {
        if let Some(ev) = self.later.borrow_mut().pop_front() {
            return ev;
        }
        match self.rx.recv_timeout(WAIT).expect("a stream event") {
            Ev::GoAway => panic!("GOAWAY"),
            ev => ev,
        }
    }

    /// The response head on `sid` (status, whether it ended the stream); what other streams
    /// got meanwhile is kept for later, in order.
    fn head(&self, sid: u32) -> (u16, bool) {
        let mut other = Vec::new();
        let head = loop {
            match self.next() {
                Ev::Head(s, status, end) if s == sid => break (status, end),
                // An earlier refusal, answered before its request ended (RFC 9113 §8.1).
                Ev::Reset(s, 0) if s != sid => {}
                ev if ev.sid() != Some(sid) => other.push(ev),
                ev => panic!("{ev:?}"),
            }
        };
        let mut later = self.later.borrow_mut();
        for ev in other.into_iter().rev() {
            later.push_front(ev);
        }
        head
    }

    /// A refusal on `sid`: its status, its body read to the end of the stream.
    fn refused(&self, sid: u32) -> u16 {
        let (status, mut end) = self.head(sid);
        while !end {
            match self.next() {
                Ev::Data(s, _, e) if s == sid => end = e,
                Ev::Reset(s, _) if s == sid => end = true,
                ev => panic!("{ev:?}"),
            }
        }
        status
    }

    /// Sends `data` on `sid` as the server's windows allow (waiting for them, bounded).
    fn write(&self, sid: u32, data: &[u8]) {
        let mut off = 0;
        while off < data.len() {
            let deadline = Instant::now() + WAIT;
            let mut g = self.win.0.lock().unwrap();
            let room = loop {
                let room = g
                    .conn
                    .min(g.streams[&sid])
                    .min(16_384)
                    .min((data.len() - off) as i64);
                if room > 0 {
                    break room;
                }
                let left = deadline
                    .checked_duration_since(Instant::now())
                    .expect("the server's window stayed shut");
                g = self.win.1.wait_timeout(g, left).unwrap().0;
            };
            g.conn -= room;
            *g.streams.get_mut(&sid).unwrap() -= room;
            drop(g);
            let n = room as usize;
            self.send(DATA, 0, sid, &data[off..off + n]);
            off += n;
        }
    }

    /// Reads one DATA into `got` / `ended`.
    fn take(&self, got: &mut HashMap<u32, Vec<u8>>, ended: &mut HashMap<u32, bool>) {
        match self.next() {
            Ev::Data(sid, p, end) => {
                got.entry(sid).or_default().extend(p);
                if end {
                    ended.insert(sid, true);
                }
            }
            ev => panic!("{ev:?}"),
        }
    }
}

/// Two tunnels on one connection, each pushing 4 MiB through an echo upstream: far past the
/// stream window (1 MiB) and the relay's watermark, so both directions are paced. Then the
/// client ends its half: the upstream's send direction is shut once what was sent is written,
/// and the echo server's close, after the last of its answer, ends ours.
#[test]
fn h2_tunnels_both_ways_with_backpressure() {
    let echo = echo_server(None);
    let e = h2_proxy(loopback_ok());
    let mut h = H2::open(&e);
    h.connect(1, &echo.to_string());
    h.connect(3, &format!("localhost:{}", echo.port()));
    assert_eq!(h.head(1), (200, false));
    assert_eq!(h.head(3), (200, false));
    const N: usize = 4 << 20;
    let (a, b) = (pattern(N, 1), pattern(N, 2));
    let (mut got, mut ended) = (HashMap::new(), HashMap::new());
    for chunk in 0..N / (256 << 10) {
        let r = chunk * (256 << 10)..(chunk + 1) * (256 << 10);
        h.write(1, &a[r.clone()]);
        h.write(3, &b[r]);
    }
    h.send(DATA, END_STREAM, 1, &[]);
    h.send(DATA, END_STREAM, 3, &[]);
    while ended.len() < 2 {
        h.take(&mut got, &mut ended);
    }
    for (sid, want) in [(1, &a), (3, &b)] {
        let g = &got[&sid];
        let first = g.iter().zip(want.iter()).position(|(x, y)| x != y);
        assert!(
            g == want,
            "stream {sid}: {} bytes of {}, first difference at {first:?}",
            g.len(),
            want.len()
        );
    }
    stop(&e);
}

#[test]
fn h2_refusals_are_answered() {
    let echo = echo_server(None);
    // The default policy denies loopback: 403, for a literal address and for a name.
    let e = h2_proxy(ProxyConfig::default());
    let mut h = H2::open(&e);
    h.connect(1, &echo.to_string());
    assert_eq!(h.refused(1), 403);
    h.connect(3, &format!("localhost:{}", echo.port()));
    assert_eq!(h.refused(3), 403);
    h.connect(5, "no-port");
    assert_eq!(h.refused(5), 400);
    stop(&e);

    // Nothing listening: 502.
    let e = h2_proxy(loopback_ok());
    let mut h = H2::open(&e);
    h.connect(1, &closed_port().to_string());
    assert_eq!(h.refused(1), 502);
    stop(&e);
}

/// The client resets its stream: the upstream is closed. The upstream closes: our half ends.
#[test]
fn h2_a_reset_closes_the_upstream_and_an_upstream_close_ends_our_half() {
    let (ctx, closed) = mpsc::channel();
    let echo = echo_server(Some(ctx));
    let e = h2_proxy(loopback_ok());
    let mut h = H2::open(&e);
    h.connect(1, &echo.to_string());
    assert_eq!(h.head(1), (200, false));
    let (mut got, mut ended) = (HashMap::new(), HashMap::new());
    h.write(1, b"abc");
    while got.get(&1).map_or(0, Vec::len) < 3 {
        h.take(&mut got, &mut ended);
    }
    h.send(RST_STREAM, 0, 1, &CANCEL.to_be_bytes());
    closed.recv_timeout(WAIT).expect("the upstream closed");

    let hello = hello_server();
    h.connect(3, &hello.to_string());
    assert_eq!(h.head(3), (200, false));
    let mut said = Vec::new();
    loop {
        match h.next() {
            Ev::Data(3, p, end) => {
                said.extend(p);
                if end {
                    break;
                }
            }
            Ev::Reset(3, c) => panic!("reset {c}"),
            _ => {}
        }
    }
    assert_eq!(said, b"hi");
    stop(&e);
}

/// A tunnel idle past `idle_timeout` is reset, and its upstream closed.
#[test]
fn h2_an_idle_tunnel_is_reset() {
    let (ctx, closed) = mpsc::channel();
    let echo = echo_server(Some(ctx));
    let mut cfg = loopback_ok();
    cfg.idle_timeout = Some(Duration::from_millis(300));
    let e = h2_proxy(cfg);
    let mut h = H2::open(&e);
    h.connect(1, &echo.to_string());
    assert_eq!(h.head(1), (200, false));
    let t = Instant::now();
    loop {
        match h.next() {
            Ev::Reset(1, _) => break,
            Ev::Data(1, p, true) if p.is_empty() => {}
            ev => panic!("{ev:?}"),
        }
    }
    assert!(
        t.elapsed() >= Duration::from_millis(250),
        "not before the timeout"
    );
    closed.recv_timeout(WAIT).expect("the upstream closed");
    stop(&e);
}

/// akio's own HTTP/2 client through the proxy (fit's `TestConnectH2C`): `H2Client::open` sends a
/// CONNECT with `:authority` the request's `Host`, its upload the tunnel's way out, its events
/// the way back.
#[test]
fn h2_client_connect_through_the_proxy() {
    let echo = echo_server(None);
    let e = h2_proxy(loopback_ok());
    let client = Engine::builder().client_threads(1).build().unwrap();
    client.start().unwrap();
    let proxy = e.local_addrs()[0];
    let c = H2Client::dial_blocking(&client, proxy, None, H2Options::default()).unwrap();
    let mut req = ClientRequest::get(&format!("http://{proxy}/"));
    req.method = Method::Connect;
    req.headers.set("host", echo.to_string());
    let (tx, rx) = mpsc::channel();
    let up = c.open(req, move |ev| {
        let _ = tx.send(match ev {
            H2Event::Head { status, .. } => format!("head {status}"),
            H2Event::Data(d) => format!("data {}", String::from_utf8_lossy(d)),
            H2Event::Trailers(_) => "trailers".into(),
            H2Event::End => "end".into(),
            H2Event::Error(e) => format!("error {e}"),
        });
    });
    assert_eq!(rx.recv_timeout(WAIT).unwrap(), "head 200");
    let msg = "h2c ".repeat(1000);
    assert!(up.write(msg.as_bytes()));
    let mut got = String::new();
    while got.len() < msg.len() {
        let ev = rx.recv_timeout(WAIT).unwrap();
        got.push_str(ev.strip_prefix("data ").unwrap_or_else(|| panic!("{ev}")));
    }
    assert_eq!(got, msg);
    assert!(up.finish());
    // Our half ends after the client's (the empty DATA that ends it may come first).
    loop {
        match rx.recv_timeout(WAIT).unwrap().as_str() {
            "end" => break,
            "data " => {}
            ev => panic!("{ev}"),
        }
    }
    c.close();
    client.shutdown();
    client.wait();
    stop(&e);
}

// ---- HTTP/3 --------------------------------------------------------------------------------

const H3_DATA: u64 = 0x0;
const H3_HEADERS: u64 = 0x1;

fn varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..0x40 => out.push(v as u8),
        0x40..0x4000 => out.extend_from_slice(&(0x4000 | v as u16).to_be_bytes()),
        0x4000..0x4000_0000 => out.extend_from_slice(&(0x8000_0000 | v as u32).to_be_bytes()),
        _ => out.extend_from_slice(&(0xc000_0000_0000_0000 | v).to_be_bytes()),
    }
}

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

fn h3_frame(ty: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint(&mut out, ty);
    varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

#[derive(Debug)]
enum Got {
    Connected,
    Data(StreamId, Vec<u8>, bool),
    Reset(StreamId),
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
    fn on_stream_reset(&mut self, _c: &Connection, id: StreamId, _code: u64) {
        let _ = self.0.send(Got::Reset(id));
    }
    fn on_close(&mut self, _c: &Connection, _r: ConnectionError) {
        let _ = self.0.send(Got::Closed);
    }
}

/// The frames of one stream: (status of the head, DATA payloads, whether it ended).
fn h3_read(rx: &mpsc::Receiver<Got>, id: StreamId, want: usize) -> (u16, Vec<u8>, bool) {
    let (mut buf, mut fin) = (Vec::new(), false);
    let (mut status, mut body) = (0, Vec::new());
    loop {
        while let Some((ty, a)) = read_varint(&buf) {
            let Some((len, b)) = read_varint(&buf[a..]) else {
                break;
            };
            let end = a + b + len as usize;
            if buf.len() < end {
                break;
            }
            let p = buf[a + b..end].to_vec();
            buf.drain(..end);
            match ty {
                H3_HEADERS => {
                    let fields = akio_h3::qpack::decode(&p, 64 << 10).unwrap();
                    status = fields
                        .iter()
                        .find(|(n, _)| n == b":status")
                        .map_or(0, |(_, v)| std::str::from_utf8(v).unwrap().parse().unwrap());
                }
                H3_DATA => body.extend(p),
                _ => {}
            }
        }
        if fin || (status != 0 && body.len() >= want) {
            return (status, body, fin);
        }
        match rx.recv_timeout(WAIT).expect("stream data") {
            Got::Data(i, d, f) if i == id => {
                buf.extend(d);
                fin = f;
            }
            Got::Reset(i) if i == id => panic!("stream reset"),
            Got::Closed => panic!("connection closed"),
            _ => {}
        }
    }
}

/// A CONNECT on an HTTP/3 stream: relayed both ways, the client's FIN closing the upstream and
/// so ending our half; a refusal answered.
#[test]
fn h3_tunnels_and_refusals() {
    let echo = echo_server(None);
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let er = EngineRef::new();
    let mut cfg = ProxyConfig::default();
    // The echo server only: another port is refused.
    let port = echo.port();
    cfg.destinations = Destinations::Custom(Arc::new(move |a: SocketAddr| a.port() == port));
    let e = Arc::new(
        Engine::builder()
            .listen(
                Listener::udp("127.0.0.1:0".parse().unwrap())
                    .serve(akio_h3::serve(quic, connect_proxy_with(er.clone(), cfg))),
            )
            .client_threads(1)
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    er.set(&e);
    e.start().unwrap();
    let (rtx, rx) = mpsc::channel();
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = akio_quic::dial(&e, e.local_addrs()[0], "localhost", cc, Raw(rtx)).unwrap();
    assert!(matches!(rx.recv_timeout(WAIT).unwrap(), Got::Connected));
    let connect = |authority: &str| {
        let id = c.open_bi().unwrap();
        let mut block = Vec::new();
        akio_h3::qpack::encode(
            [(":method", "CONNECT"), (":authority", authority)],
            &mut block,
        );
        c.send(id, h3_frame(H3_HEADERS, &block)).unwrap();
        id
    };

    let id = connect(&echo.to_string());
    let msg = pattern(200 << 10, 3);
    for chunk in msg.chunks(16 << 10) {
        c.send(id, h3_frame(H3_DATA, chunk)).unwrap();
    }
    let (status, body, _) = h3_read(&rx, id, msg.len());
    assert_eq!(status, 200);
    assert!(body == msg, "echoed intact");
    c.finish(id).unwrap();
    let (_, rest, fin) = h3_read(&rx, id, usize::MAX);
    assert!(rest.is_empty() && fin, "our half ended after the client's");

    let id = connect(&closed_port().to_string());
    let (status, _, _) = h3_read(&rx, id, 0);
    assert_eq!(status, 403);
    e.shutdown();
    e.wait();
}
