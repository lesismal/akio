//! A connection closed while its peer is still sending (akit's A302): the peer is reset, as
//! closing a socket with input unread resets it, on every backend. On io_uring a receive in
//! flight at the close used to take the input after the shutdown, so the close found nothing
//! unread and sent a FIN with the receive window shut: the peer, writing into a zero window,
//! waited for the kernel's FIN-WAIT-2 timeout. A connection closed after it read everything
//! still ends with a FIN. Run on both backends (`AKIO_TEST_BACKEND=uring` for io_uring).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{ErrorKind, Write},
    net::{SocketAddr, TcpStream},
    sync::{Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Conn, Engine, Handler, Listener, fn_acceptor};

/// Far below the kernel's FIN-WAIT-2 timeout (`tcp_fin_timeout`, 60 s by default), far above
/// how long a reset takes on a loaded host.
const DEADLINE: Duration = Duration::from_secs(20);

/// Counts what it reads, and closes once it has read `close_at` bytes (never at 0); reports
/// the count it closed at.
struct Sink {
    close_at: usize,
    seen: usize,
    report: mpsc::Sender<usize>,
}

impl Handler for Sink {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.seen += data.len();
        if self.close_at > 0 && self.seen >= self.close_at && c.is_open() {
            c.close();
            let _ = self.report.send(self.seen);
        }
    }
}

fn engine(acceptor: impl Fn(&Conn<Sink>) -> Sink + Send + Sync + 'static) -> Engine {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(acceptor)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

/// Writes (blocking, `DEADLINE` per write) until a write fails; the error and how long it took.
fn write_until_refused(s: &mut TcpStream) -> (std::io::Error, Duration) {
    s.set_nonblocking(false).unwrap();
    s.set_write_timeout(Some(DEADLINE)).unwrap();
    let chunk = vec![b'x'; 64 << 10];
    let t = Instant::now();
    // Bounded: a peer that kept reading would end the loop too (and fail the test).
    for _ in 0..(1 << 14) {
        match s.write(&chunk) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return (e, t.elapsed()),
        }
    }
    panic!("1 GiB written into a connection its handler closed");
}

fn assert_reset(e: &std::io::Error, took: Duration) {
    assert!(
        matches!(
            e.kind(),
            ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
        ),
        "the writer was not reset (after {took:?}): {e:?}"
    );
    assert!(took < DEADLINE, "the reset took {took:?}");
}

/// The handler closes in the middle of a large upload: the uploader's writes fail promptly.
#[test]
fn a_close_mid_upload_resets_the_writer() {
    let (tx, rx) = mpsc::channel();
    let e = engine(move |_c| Sink {
        close_at: 256 << 10,
        seen: 0,
        report: tx.clone(),
    });
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    let writer = thread::spawn(move || write_until_refused(&mut s));
    let at = rx.recv_timeout(DEADLINE).expect("the handler never closed");
    assert!(at >= 256 << 10);
    let (err, took) = writer.join().unwrap();
    assert_reset(&err, took);
    e.shutdown();
    e.wait();
}

/// Fills the peer's send buffer (and so the receive window on our side) without blocking.
fn fill_window(s: &mut TcpStream) {
    s.set_nonblocking(true).unwrap();
    let chunk = vec![b'x'; 64 << 10];
    let mut sent = 0usize;
    loop {
        match s.write(&chunk) {
            Ok(n) => sent += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("write before the close: {e:?}"),
        }
        assert!(sent < 1 << 30, "the window never filled");
    }
}

/// On its first input, waits (on the I/O thread) for the test to say the window is shut, then
/// closes.
struct Stall {
    started: mpsc::Sender<()>,
    gate: mpsc::Receiver<()>,
}

impl Handler for Stall {
    fn on_data(&mut self, c: &Conn<Self>, _data: &[u8]) {
        if c.is_open() {
            let _ = self.started.send(());
            let _ = self.gate.recv_timeout(DEADLINE);
            c.close();
        }
    }
}

/// The I/O thread is busy in a callback while the peer fills the receive window (on io_uring
/// the receive in flight runs only once the loop enters the kernel again), and the callback
/// then closes: the peer is reset.
#[test]
fn a_close_with_the_window_shut_resets_the_writer() {
    let (started_tx, started) = mpsc::channel();
    let (gate, gate_rx) = mpsc::channel();
    let gate_rx = Mutex::new(Some(gate_rx));
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<Stall>| Stall {
                    started: started_tx.clone(),
                    gate: gate_rx.lock().unwrap().take().expect("one connection"),
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.write_all(b"go").unwrap();
    started
        .recv_timeout(DEADLINE)
        .expect("no input reached the handler");
    fill_window(&mut s);
    gate.send(()).unwrap();
    let (err, took) = write_until_refused(&mut s);
    assert_reset(&err, took);
    e.shutdown();
    e.wait();
}

/// Closed with reads held (input waiting in the kernel, and on io_uring perhaps some read
/// before the hold took effect): the peer is reset too.
#[test]
fn a_close_with_reads_held_resets_the_writer() {
    let (conn_tx, conn_rx) = mpsc::channel::<Conn<Sink>>();
    let (tx, _rx) = mpsc::channel();
    let e = engine(move |c| {
        c.hold_reads(true);
        let _ = conn_tx.send(c.clone());
        Sink {
            close_at: 0,
            seen: 0,
            report: tx.clone(),
        }
    });
    let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    let conn = conn_rx.recv_timeout(DEADLINE).expect("never accepted");
    fill_window(&mut s);
    conn.close();
    let (err, took) = write_until_refused(&mut s);
    assert_reset(&err, took);
    drop(conn);
    e.shutdown();
    e.wait();
}

/// Counts what it is given; reports the count when it closes.
#[cfg(target_os = "linux")]
struct Quiet {
    seen: usize,
    report: mpsc::Sender<usize>,
}

#[cfg(target_os = "linux")]
impl Handler for Quiet {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        self.seen += data.len();
    }
    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<akio::Error>) {
        let _ = self.report.send(self.seen);
    }
}

/// Waits (up to `DEADLINE`) for `s` to be reset: `POLLERR` / `POLLHUP`, which a FIN alone does
/// not raise.
#[cfg(target_os = "linux")]
fn wait_reset(s: &TcpStream) -> Result<Duration, String> {
    use std::os::fd::AsRawFd;
    let t = Instant::now();
    let mut p = libc::pollfd {
        fd: s.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    loop {
        let left = DEADLINE.saturating_sub(t.elapsed()).as_millis() as libc::c_int;
        // SAFETY: one valid pollfd.
        let n = unsafe { libc::poll(&raw mut p, 1, left) };
        if n > 0 {
            return Ok(t.elapsed());
        }
        if n == 0 {
            return Err(format!("no reset after {:?}", t.elapsed()));
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != ErrorKind::Interrupted {
            return Err(format!("poll: {e}"));
        }
    }
}

/// The race behind A302, made certain. Input waits in the kernel while reads are held; then,
/// on the I/O thread and before it next enters the kernel, reads resume and the connection
/// closes. On io_uring the resumed receive reached the kernel after the close's shutdown and
/// took everything queued, so the close found nothing unread: a FIN and no reset (and, had the
/// peer been writing into a shut window, the window never opened again). Input the handler
/// never saw must reset the peer, as on epoll. Event loops on epoll, where the resume only
/// asks for readiness, so the input stays unread there too. Linux only: the BSD stack ends such
/// a connection with a FIN and resets only the peer's next segment.
#[cfg(target_os = "linux")]
#[test]
fn a_close_right_after_resuming_reads_resets_the_peer() {
    let (conn_tx, conn_rx) = mpsc::channel::<Conn<Quiet>>();
    let (tx, closed) = mpsc::channel();
    let e = Engine::builder()
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .scheduling(akio::Scheduling::EventLoops)
                .threads(1)
                .serve(fn_acceptor(move |c: &Conn<Quiet>| {
                    c.hold_reads(true);
                    let _ = conn_tx.send(c.clone());
                    Quiet {
                        seen: 0,
                        report: tx.clone(),
                    }
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    for _ in 0..20 {
        let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
        let conn = conn_rx.recv_timeout(DEADLINE).expect("never accepted");
        // Well inside the first window: it reaches the held socket (what came later would
        // reset the peer whatever the close did).
        s.write_all(&vec![b'x'; 32 << 10]).unwrap();
        // One drain of the loop's commands: the resume arms a receive, the close (a task the
        // first posts) shuts the socket down, and only then does the loop enter the kernel.
        conn.run_on_loop(|_, c| {
            c.hold_reads(false);
            let _ = c.run_on_loop(|_, c| c.close());
        })
        .unwrap();
        // The socket closes once the connection's last handle goes.
        drop(conn);
        let seen = closed.recv_timeout(DEADLINE).expect("never closed");
        assert_eq!(seen, 0, "the handler was given the input");
        if let Err(why) = wait_reset(&s) {
            panic!("the peer was not reset: {why}");
        }
    }
    e.shutdown();
    e.wait();
}

/// Reads a whole request of `LEN` bytes, answers and closes after the answer: the client reads
/// the answer and then the end of the stream, no reset.
struct Answer {
    seen: usize,
}

const LEN: usize = 1 << 20;

impl Handler for Answer {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.seen += data.len();
        if self.seen == LEN {
            c.send(b"done").unwrap();
            c.close_after_send();
        }
    }
}

#[test]
fn a_close_after_reading_everything_ends_with_a_fin() {
    let e = Engine::builder()
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(|_c: &Conn<Answer>| Answer { seen: 0 })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    for _ in 0..20 {
        let mut s = TcpStream::connect(e.local_addrs()[0]).unwrap();
        s.set_read_timeout(Some(DEADLINE)).unwrap();
        s.write_all(&vec![b'r'; LEN]).unwrap();
        let mut got = Vec::new();
        loop {
            let mut b = [0u8; 64];
            match common::read_retry(&mut s, &mut b) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&b[..n]),
                Err(e) => panic!("after {got:?}: {e:?}"),
            }
        }
        assert_eq!(got, b"done");
    }
    e.shutdown();
    e.wait();
}
