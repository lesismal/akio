//! A connection's own bound of the bytes queued for it (ADR-181, akit A234):
//! `Conn::set_max_queued_bytes` in place of the engine's `Config::max_queued_bytes`, just under,
//! at and over it, lowered below what is queued, restored with `None`, and from a thread other
//! than the connection's (on the backend under test: epoll/kqueue, io_uring with
//! `AKIO_TEST_BACKEND=uring`, work stealing with `AKIO_DEFAULT_SCHEDULING=work-stealing`).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Config, Conn, Engine, Error, Handler, Listener, fn_acceptor};

/// The engine's bound.
const ENGINE: usize = 1024;

type Report = Arc<Mutex<mpsc::Sender<String>>>;

struct H {
    report: Report,
}

impl H {
    fn say(&self, s: impl Into<String>) {
        let _ = self.report.lock().unwrap().send(s.into());
    }
}

fn verdict(r: akio::Result<()>) -> &'static str {
    match r {
        Ok(()) => "ok",
        Err(Error::Overloaded) => "overloaded",
        Err(_) => "other",
    }
}

impl Handler for H {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        // Inside a callback the loop corks the connection: every send below is queued, so the
        // bound is met exactly where the test says.
        match data[0] {
            // The connection's own bound: under, at and over it, then the engine's again.
            b'u' => {
                c.set_max_queued_bytes(Some(100_000));
                let mut v = vec![format!("max {}", c.max_queued_bytes())];
                v.push(verdict(c.send(&vec![b'u'; 60_000])).into());
                v.push(format!("room {}", c.inner().send_room()));
                v.push(verdict(c.send(&vec![b'u'; 40_000])).into());
                v.push(verdict(c.send(b"u")).into());
                // Lowered below what is queued: what is queued stays, later sends fail.
                c.set_max_queued_bytes(Some(10));
                v.push(verdict(c.send(b"u")).into());
                c.handle().set_max_queued_bytes(None); // through a handle too
                v.push(format!("max {}", c.max_queued_bytes()));
                v.push(verdict(c.send(b"u")).into());
                self.say(v.join(","));
            }
            // The engine's bound: at it, then over it.
            b'e' => {
                let v = [verdict(c.send(&[b'e'; ENGINE])), verdict(c.send(b"e"))];
                self.say(v.join(","));
            }
            // From another thread, with no callback corking it: the engine's bound refuses a
            // 64 KiB send before any byte is written; the connection's own takes 4 MiB while
            // the peer reads nothing.
            b't' => {
                let (c, report) = (c.clone(), self.report.clone());
                thread::spawn(move || {
                    let mut v = vec![verdict(c.send(&vec![b't'; 64 << 10])).to_string()];
                    c.set_max_queued_bytes(Some(8 << 20));
                    let refused = (0..64)
                        .filter(|_| c.send(&vec![b't'; 64 << 10]).is_err())
                        .count();
                    v.push(format!("refused {refused}"));
                    let _ = report.lock().unwrap().send(v.join(","));
                });
            }
            _ => {}
        }
    }
}

fn start() -> (Engine, mpsc::Receiver<String>) {
    let (tx, rx) = mpsc::channel();
    let report: Report = Arc::new(Mutex::new(tx));
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v.max_queued_bytes = ENGINE;
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<H>| H {
                    report: report.clone(),
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    (e, rx)
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    s.read_exact(&mut b).unwrap();
    b
}

fn next(rx: &mpsc::Receiver<String>) -> String {
    rx.recv_timeout(Duration::from_secs(10)).unwrap()
}

#[test]
fn own_bound_under_at_and_over() {
    let (e, rx) = start();
    let mut s = connect(&e);
    s.write_all(b"u").unwrap();
    assert_eq!(
        next(&rx),
        "max 100000,ok,room 40000,ok,overloaded,overloaded,max 1024,overloaded"
    );
    // Everything accepted is delivered; nothing refused is.
    assert!(read_n(&mut s, 100_000).iter().all(|&b| b == b'u'));

    // Drained: the engine's bound is in force again.
    s.write_all(b"e").unwrap();
    assert_eq!(next(&rx), "ok,overloaded");
    assert!(read_n(&mut s, ENGINE).iter().all(|&b| b == b'e'));

    // A second connection does not inherit the first's bound.
    let mut s2 = connect(&e);
    s2.write_all(b"e").unwrap();
    assert_eq!(next(&rx), "ok,overloaded");
    assert_eq!(read_n(&mut s2, ENGINE).len(), ENGINE);
    e.shutdown();
}

#[test]
fn own_bound_from_another_thread() {
    let (e, rx) = start();
    let mut s = connect(&e);
    s.write_all(b"t").unwrap();
    // The peer reads nothing until every send was answered.
    assert_eq!(next(&rx), "overloaded,refused 0");
    let got = read_n(&mut s, 64 * (64 << 10));
    assert!(got.iter().all(|&b| b == b't'));
    e.shutdown();
}
