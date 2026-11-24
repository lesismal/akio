//! io_uring ring sends (ADR-106, on by default; `AKIO_URING_SENDS=write` turns them off): what
//! `on_data` answers goes out as an `IORING_OP_SEND` / `SENDMSG` the loop submits, while sends
//! from other threads, backpressure, `close_after_send`, the write timeout and peers that go
//! away mid-send behave as with `writev`.
//!
//! Linux only. Skipped where io_uring is unavailable, unless `AKIO_TEST_BACKEND=uring` (then the
//! backend is strict and a missing io_uring fails the run).
#![allow(missing_docs)]
#![cfg(target_os = "linux")]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Conn, Engine, Error, Handler, Listener, UringConfig, fn_acceptor};

fn ring_backend() -> Option<Backend> {
    let strict = std::env::var("AKIO_TEST_BACKEND").as_deref() == Ok("uring");
    if !strict && akio_uring::probe().is_err() {
        eprintln!("io_uring unavailable: skipped");
        return None;
    }
    let mut u = UringConfig::default();
    u.strict = strict;
    Some(Backend::IoUring(u))
}

fn cfg() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

fn engine<H: Handler>(
    cfg: Config,
    threads: usize,
    open: impl Fn(&Conn<H>) -> H + Send + Sync + 'static,
) -> Option<Engine> {
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(ring_backend()?)
                .threads(threads)
                .serve(fn_acceptor(open)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    Some(e)
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

#[test]
fn echoes_many_small_exchanges() {
    let Some(e) = engine(cfg(), 2, |_c: &Conn<Echo>| Echo) else {
        return;
    };
    let clients: Vec<_> = (0..16)
        .map(|i| {
            let mut s = connect(&e);
            thread::spawn(move || {
                for j in 0..300u32 {
                    let msg = format!("client {i} message {j}");
                    s.write_all(msg.as_bytes()).unwrap();
                    let mut buf = vec![0; msg.len()];
                    s.read_exact(&mut buf).unwrap();
                    assert_eq!(buf, msg.as_bytes());
                }
            })
        })
        .collect();
    for c in clients {
        c.join().unwrap();
    }
    stop(&e);
}

#[test]
fn large_echo_with_partial_sends_and_backpressure() {
    // 8 MiB through a tiny watermark: ring sends complete short and reads pause and resume.
    let mut c = cfg();
    c.write_high_watermark = 16 << 10;
    c.read_buffer = 8 << 10;
    let Some(e) = engine(c, 1, |_c: &Conn<Echo>| Echo) else {
        return;
    };
    let data: Vec<u8> = (0..8 << 20).map(|i: usize| (i * 31 % 251) as u8).collect();
    let mut w = connect(&e);
    let mut r = w.try_clone().unwrap();
    let send = data.clone();
    let writer = thread::spawn(move || w.write_all(&send).unwrap());
    let mut got = vec![0u8; data.len()];
    r.read_exact(&mut got).unwrap();
    writer.join().unwrap();
    assert!(got == data, "echoed bytes differ");
    stop(&e);
}

/// Answers each read with a 64 KiB reply (so a ring send is often in flight) and lets other
/// threads send numbered records on the same connection meanwhile.
struct Mixed;
impl Handler for Mixed {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        for _ in data {
            let _ = c.send(&vec![0xffu8; 8 << 13]);
        }
    }
}

#[test]
fn other_threads_sends_keep_their_order_around_ring_sends() {
    let conns: Arc<Mutex<Vec<Conn<Mixed>>>> = Arc::default();
    let reg = conns.clone();
    let Some(e) = engine(cfg(), 1, move |c: &Conn<Mixed>| {
        reg.lock().unwrap().push(c.clone());
        Mixed
    }) else {
        return;
    };
    let mut client = connect(&e);
    while conns.lock().unwrap().is_empty() {
        thread::sleep(Duration::from_millis(5));
    }
    let conn = conns.lock().unwrap()[0].clone();
    let mut poke = client.try_clone().unwrap();
    let poker = thread::spawn(move || {
        for _ in 0..20 {
            poke.write_all(b"p").unwrap();
            thread::sleep(Duration::from_millis(2));
        }
    });
    let senders: Vec<_> = (0..4u32)
        .map(|t| {
            let c = conn.clone();
            thread::spawn(move || {
                for i in 0..2000u32 {
                    let mut rec = [0u8; 8];
                    rec[..4].copy_from_slice(&t.to_be_bytes());
                    rec[4..].copy_from_slice(&i.to_be_bytes());
                    c.send(&rec).unwrap();
                }
            })
        })
        .collect();
    // Records are 8 bytes; replies are runs of 0xff bytes 64 KiB long, never split by a record
    // (each is one `send`), so the stream parses unambiguously: a 0xff first byte (thread ids
    // are < 4) starts a reply.
    let total = 4 * 2000 * 8 + 20 * (8 << 13);
    let mut buf = vec![0u8; total];
    client.read_exact(&mut buf).unwrap();
    poker.join().unwrap();
    for s in senders {
        s.join().unwrap();
    }
    let mut next = [0u32; 4];
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == 0xff {
            assert!(
                buf[i..i + (8 << 13)].iter().all(|&b| b == 0xff),
                "reply split"
            );
            i += 8 << 13;
            continue;
        }
        let rec = &buf[i..i + 8];
        let t = u32::from_be_bytes(rec[..4].try_into().unwrap()) as usize;
        let n = u32::from_be_bytes(rec[4..].try_into().unwrap());
        assert_eq!(n, next[t], "thread {t} records out of order");
        next[t] += 1;
        i += 8;
    }
    assert_eq!(next, [2000; 4]);
    stop(&e);
}

struct Bye;
impl Handler for Bye {
    fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
        let _ = c.send(&vec![7u8; 1 << 20]);
        c.close_after_send();
        assert!(matches!(c.send(b"x"), Err(Error::Closed)));
    }
}

#[test]
fn close_after_send_waits_for_the_ring_send() {
    let Some(e) = engine(cfg(), 1, |_c: &Conn<Bye>| Bye) else {
        return;
    };
    let mut s = connect(&e);
    s.write_all(b"go").unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    assert_eq!(all.len(), 1 << 20);
    assert!(all.iter().all(|&b| b == 7));
    stop(&e);
}

/// Answers, then closes at once, both inside `on_data` (an answer-and-hang-up server): the
/// send is described but not yet submitted when the close is handled in the same batch.
struct SendClose;
impl Handler for SendClose {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        let mut out = b"reply:".to_vec();
        out.extend_from_slice(d);
        out.extend_from_slice(&[b'r'; 2000]);
        let _ = c.send(&out);
        c.close();
    }
}

#[test]
fn a_reply_sent_then_closed_inside_on_data_arrives_whole() {
    let Some(e) = engine(cfg(), 1, |_c: &Conn<SendClose>| SendClose) else {
        return;
    };
    for i in 0..50u32 {
        let mut s = connect(&e);
        let req = format!("req{i}");
        s.write_all(req.as_bytes()).unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).unwrap();
        let mut want = b"reply:".to_vec();
        want.extend_from_slice(req.as_bytes());
        want.extend_from_slice(&[b'r'; 2000]);
        assert!(
            got == want,
            "round {i}: got {} bytes of {}",
            got.len(),
            want.len()
        );
    }
    stop(&e);
}

/// Sends `BIG` bytes per read; counts closes and records their errors.
struct Big(Arc<(AtomicUsize, Mutex<Vec<std::io::ErrorKind>>)>);
const BIG: usize = 8 << 20;
impl Handler for Big {
    fn on_data(&mut self, c: &Conn<Self>, _d: &[u8]) {
        let _ = c.send(&vec![7u8; BIG]);
    }
    fn on_close(&mut self, _c: &Conn<Self>, err: Option<Error>) {
        self.0.0.fetch_add(1, Ordering::SeqCst);
        if let Some(Error::Io(e)) = err {
            self.0.1.lock().unwrap().push(e.kind());
        }
    }
}

#[test]
fn write_timeout_ends_a_ring_send_to_a_stalled_peer() {
    let seen: Arc<(AtomicUsize, Mutex<Vec<std::io::ErrorKind>>)> = Arc::default();
    let s2 = seen.clone();
    let mut c = cfg();
    c.write_timeout = Some(Duration::from_millis(300));
    let Some(e) = engine(c, 1, move |_c: &Conn<Big>| Big(s2.clone())) else {
        return;
    };
    let mut stalled = connect(&e);
    stalled.write_all(b"go").unwrap();
    let t0 = Instant::now();
    while seen.0.load(Ordering::SeqCst) == 0 && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(*seen.1.lock().unwrap(), vec![std::io::ErrorKind::TimedOut]);
    // The loop is still serving after the send it abandoned completes.
    let mut other = connect(&e);
    other.write_all(b"go").unwrap();
    let mut b = vec![0u8; 64 << 10];
    let n = common::read_retry(&mut other, &mut b).unwrap();
    assert!(n > 0);
    drop(stalled);
    stop(&e);
}

#[test]
fn peer_reset_mid_send_closes_once_and_the_loop_goes_on() {
    let seen: Arc<(AtomicUsize, Mutex<Vec<std::io::ErrorKind>>)> = Arc::default();
    let s2 = seen.clone();
    let Some(e) = engine(cfg(), 1, move |_c: &Conn<Big>| Big(s2.clone())) else {
        return;
    };
    for _ in 0..20 {
        let mut s = connect(&e);
        s.write_all(b"go").unwrap();
        let mut b = vec![0u8; 4096];
        let _ = common::read_retry(&mut s, &mut b);
        // Abortive close (RST) while megabytes are still lent to the kernel.
        let s = socket_linger0(s);
        drop(s);
    }
    let t0 = Instant::now();
    while seen.0.load(Ordering::SeqCst) < 20 && t0.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        seen.0.load(Ordering::SeqCst),
        20,
        "on_close once per connection"
    );
    let mut other = connect(&e);
    other.write_all(b"go").unwrap();
    let mut got = 0;
    let mut b = vec![0u8; 64 << 10];
    while got < BIG {
        let n = common::read_retry(&mut other, &mut b).unwrap();
        assert!(n > 0);
        got += n;
    }
    stop(&e);
}

/// `SO_LINGER` 0: closing the socket sends a reset.
fn socket_linger0(s: TcpStream) -> TcpStream {
    use std::os::fd::AsRawFd;
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: a valid socket and a `linger` of the size given.
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const l).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(r, 0);
    s
}
