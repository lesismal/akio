//! A streamed relay's memory stays bounded on every scheduling (akit A303): an upstream that
//! sends 64 MiB as fast as it can, relayed to a client that reads it slowly, with linked
//! backpressure: while more than [`PENDING`] waits in the client's connection the upstream's
//! reads are held (`hold_reads`), and resumed by the client's `on_drain`. Under work stealing
//! (the default on epoll/kqueue) the two connections' rounds run on any of the workers, so the
//! hold is set and released from other threads than the one reading, and the relayed buffers are
//! allocated on one worker and freed on another; the bytes queued for the client and the
//! process's resident memory must stay bounded all the same. Each relayed piece is an exact
//! 64 KiB `Vec` (a full read, copied), a size class of akio-buf's pool, as akit-proxy's response
//! framed by its length sends it. On the backend under test (epoll/kqueue, io_uring with
//! `AKIO_TEST_BACKEND=uring`; event loops with `AKIO_DEFAULT_SCHEDULING=event-loops`).
//!
//! The resident memory is read from `/proc` (Linux); elsewhere only the queue and the bytes are
//! checked. One test in this file: the memory is the process's.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use akio::{Config, Conn, Engine, Handler, Listener, fn_acceptor};

/// What the relay moves.
const SIZE: usize = 64 << 20;
/// How far the resident memory may rise meanwhile: a quarter of what moves (akit's bound).
const MAX_RISE: usize = 16 << 20;
/// How much may wait for the client before the upstream's reads are held.
const PENDING: usize = 64 << 10;
/// The engine's read buffer (its default): one read's worth may arrive after the hold.
const READ: usize = 64 << 10;
/// Workers (or event loops): the more threads free the relay's buffers, the more a per-thread
/// cache of them could hold.
const THREADS: usize = 16;

/// The body: a cycle of a prime length, so that a byte lost, repeated or moved shows.
fn byte(i: usize) -> u8 {
    (i % 251) as u8
}

/// The client's connection: it only receives.
struct Down;

impl Handler for Down {
    fn on_data(&mut self, _c: &Conn<Self>, _data: &[u8]) {}
}

/// The upstream's connection: what it reads goes to the client, paced by the client's queue.
struct Up {
    down: Conn<Down>,
    /// The most bytes seen waiting for the client.
    peak: Arc<AtomicUsize>,
}

impl Handler for Up {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if self.down.send_owned(data.to_vec()).is_err() {
            c.close();
            return;
        }
        let q = self.down.queued_bytes();
        self.peak.fetch_max(q, Ordering::Relaxed);
        if q > PENDING {
            c.hold_reads(true);
            let up = c.clone();
            // At once, on this thread, if the client took it meanwhile.
            self.down.on_drain(move || up.hold_reads(false));
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        self.down.close_after_send();
    }
}

/// The process's resident bytes (Linux).
fn resident() -> Option<usize> {
    let s = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: usize = s.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// The resident memory's peak, sampled every few milliseconds until stopped.
fn sampler(stop: Arc<AtomicBool>) -> Option<thread::JoinHandle<usize>> {
    resident()?;
    Some(thread::spawn(move || {
        let mut peak = 0;
        while !stop.load(Ordering::Relaxed) {
            peak = peak.max(resident().unwrap_or(0));
            thread::sleep(Duration::from_millis(5));
        }
        peak
    }))
}

#[test]
fn relayed_stream_to_a_slow_client_stays_bounded() {
    // The upstream: sends the body as fast as the socket takes it, then closes.
    let origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let producer = thread::spawn(move || {
        let (mut s, _) = origin.accept().unwrap();
        let mut buf = vec![0u8; 256 << 10];
        let mut off = 0;
        while off < SIZE {
            let n = buf.len().min(SIZE - off);
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = byte(off + i);
            }
            s.write_all(&buf[..n]).unwrap();
            off += n;
        }
    });

    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(THREADS)
                .serve(fn_acceptor(move |c: &Conn<Down>| {
                    let _ = tx.lock().unwrap().send(c.clone());
                    Down
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let mut client = TcpStream::connect(e.local_addrs()[0]).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let down = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let base = resident();
    let watch = sampler(stop.clone());

    let peak = Arc::new(AtomicUsize::new(0));
    let (p, d) = (peak.clone(), down.clone());
    e.dial(
        origin_addr,
        fn_acceptor(move |_c: &Conn<Up>| Up {
            down: d.clone(),
            peak: p.clone(),
        }),
        |err| panic!("dial: {err}"),
    );

    // The slow client: a pause after every 4 MiB.
    let mut buf = vec![0u8; 32 << 10];
    let (mut got, mut since) = (0, 0);
    loop {
        let n = common::read_retry(&mut client, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        for (i, b) in buf[..n].iter().enumerate() {
            assert_eq!(*b, byte(got + i), "byte {} differs", got + i);
        }
        got += n;
        since += n;
        if since >= 4 << 20 {
            since = 0;
            thread::sleep(Duration::from_millis(20));
        }
    }
    stop.store(true, Ordering::Relaxed);
    let top = watch.map(|w| w.join().unwrap());
    producer.join().unwrap();
    assert_eq!(got, SIZE, "the whole body");

    // At most one read arrives after the hold.
    let peak = peak.load(Ordering::Relaxed);
    assert!(
        peak <= PENDING + READ,
        "{peak} bytes waited for the client (bound {})",
        PENDING + READ
    );
    if let (Some(base), Some(top)) = (base, top) {
        let rise = top.saturating_sub(base);
        println!(
            "{peak} bytes waited at most; resident memory rose {:.1} MiB",
            rise as f64 / f64::from(1 << 20)
        );
        assert!(
            rise <= MAX_RISE,
            "resident memory rose {} MiB moving {} MiB (bound {} MiB)",
            rise >> 20,
            SIZE >> 20,
            MAX_RISE >> 20
        );
    }
    drop(down);
    e.shutdown();
    e.wait();
}
