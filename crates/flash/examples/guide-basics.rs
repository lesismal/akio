//! Companion of the book's "Concepts" chapters: handlers and acceptors, `Conn` from other
//! threads, the logical pool with ordered responses, backpressure, dialing and shutdown.
//!
//! `cargo run -p flash --example guide-basics` starts a server on a free port, talks to it with
//! a plain `std::net::TcpStream` and a flash-dialed client, then shuts down.

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use flash::{Acceptor, Config, Conn, Engine, Error, Handler, Listener, PoolConfig};

// ANCHOR: handler
/// Per-connection state *is* the handler: one value per connection, only ever touched on the
/// connection's I/O thread, so plain fields (no locks, no `Sync`) are fine.
struct Session {
    lines: u64,
    offloaded: u64,
    buf: Vec<u8>,
}

impl Handler for Session {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        // `data` is borrowed from the I/O thread's read buffer: copy what you keep.
        self.buf.extend_from_slice(data);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            self.lines += 1;
            self.handle_line(c, &line);
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, err: Option<Error>) {
        println!(
            "conn {} closed after {} lines ({err:?})",
            c.id(),
            self.lines
        );
    }
}
// ANCHOR_END: handler

impl Session {
    fn handle_line(&self, c: &Conn<Self>, line: &[u8]) {
        match line {
            // ANCHOR: offload
            b"slow\n" => {
                // Reserve the reply position now (on the I/O thread), fill it from the pool:
                // replies leave in request order even if later requests finish first.
                let Ok(slot) = c.reserve_response() else {
                    return;
                };
                let queued = c.spawn_blocking(
                    || {
                        thread::sleep(Duration::from_millis(50)); // blocking work: DB, file, RPC
                        b"slow done\n".to_vec()
                    },
                    // Back on this connection's I/O thread, with `&mut Session`.
                    move |me: &mut Session, _c, reply| {
                        me.offloaded += 1; // exclusive access to the handler state
                        slot.fill(reply);
                    },
                );
                if let Err(Error::Overloaded) = queued {
                    // The pool queue is full: the slot was dropped with the closure, which
                    // closes the connection. Shed load earlier if that is not what you want.
                }
            }
            // ANCHOR_END: offload
            // ANCHOR: cross_thread
            b"later\n" => {
                // `Conn` is `Clone + Send + Sync`: hand it to any thread.
                let c = c.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(10));
                    // Never blocks; returns Err(Closed) if the connection is gone. A plain
                    // `send` is not held behind reserved-but-unfilled response slots.
                    let _ = c.send(b"later done\n");
                });
            }
            // ANCHOR_END: cross_thread
            b"bye\n" => {
                let _ = c.send(b"bye\n");
                c.close_after_send(); // flush, then close
            }
            other => {
                // A reply to a pipelined request: keep order behind earlier reserved slots.
                if let Ok(slot) = c.reserve_response() {
                    slot.fill(other.to_vec());
                }
            }
        }
    }
}

// ANCHOR: acceptor
/// The acceptor is shared by all I/O threads (`Send + Sync`) and creates one handler per
/// connection.
struct Server {
    opened: AtomicUsize,
}

impl Acceptor for Server {
    type Handler = Session;

    fn on_open(&self, c: &Conn<Session>) -> Session {
        self.opened.fetch_add(1, Ordering::Relaxed);
        let _ = c.send(b"hello\n"); // sending from on_open is fine
        Session {
            lines: 0,
            offloaded: 0,
            buf: Vec::new(),
        }
    }

    fn on_shutdown(&self, c: &Conn<Session>) {
        // Graceful shutdown: say goodbye and close once the goodbye is written.
        let _ = c.send(b"server shutting down\n");
        c.close_after_send();
    }
}
// ANCHOR_END: acceptor

// ANCHOR: backpressure
/// Forwards everything it reads to `out`. When `out` cannot keep up, stop reading here until
/// `out` has drained: memory stays bounded and the slowness propagates to the sender.
/// (Not wired up in this example; flash-socks relays this way in both directions.)
#[allow(dead_code)]
struct Forward<H> {
    out: Conn<H>,
}

impl<H: Handler> Handler for Forward<H> {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if self.out.send(data).is_err() {
            return c.close();
        }
        if self.out.queued_bytes() > 1 << 20 {
            c.hold_reads(true);
            let me = c.clone();
            self.out.on_drain(move || me.hold_reads(false));
        }
    }
}
// ANCHOR_END: backpressure

/// A client handler for `Engine::dial`.
struct Client {
    got: mpsc::Sender<Vec<u8>>,
}

impl Handler for Client {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        let _ = self.got.send(data.to_vec());
    }
}

struct Dialer(mpsc::Sender<Vec<u8>>);

impl Acceptor for Dialer {
    type Handler = Client;
    fn on_open(&self, c: &Conn<Client>) -> Client {
        let _ = c.send(b"ping\n");
        Client {
            got: self.0.clone(),
        }
    }
}

fn read_until(s: &mut TcpStream, want: &[&str]) -> String {
    let mut all = String::new();
    let mut buf = [0u8; 1024];
    while !want.iter().all(|w| all.contains(w)) {
        let n = s.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        all.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    all
}

fn main() -> std::io::Result<()> {
    // ANCHOR: engine
    let cfg = Config {
        idle_timeout: Some(Duration::from_secs(60)),
        shutdown_timeout: Duration::from_secs(5),
        ..Config::default()
    };
    let engine = Arc::new(
        Engine::builder()
            .config(cfg)
            .pool(PoolConfig {
                max_threads: 16,
                ..PoolConfig::default()
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .threads(2)
                    .serve(Server {
                        opened: AtomicUsize::new(0),
                    }),
            )
            .client_threads(1) // threads for Engine::dial
            .build()?,
    );
    engine.start()?; // spawns the I/O threads and returns; `run()` = start + wait
    let addr = engine.local_addrs()[0];
    // ANCHOR_END: engine

    let mut s = TcpStream::connect(addr)?;
    s.write_all(b"slow\nfast\nlater\n")?;
    let got = read_until(&mut s, &["slow done\n", "fast\n", "later done\n"]);
    print!("{got}");
    // `slow` was reserved first, so its reply precedes `fast` although it finished later.
    assert!(got.find("slow done").unwrap() < got.find("fast").unwrap());

    // ANCHOR: dial
    let (tx, rx) = mpsc::channel();
    engine.dial(addr, Dialer(tx), |e| eprintln!("dial failed: {e}"));
    let first = rx.recv_timeout(Duration::from_secs(5)).expect("reply");
    // ANCHOR_END: dial
    println!("dialed client got {:?}", String::from_utf8_lossy(&first));

    // ANCHOR: shutdown
    let e2 = engine.clone();
    thread::spawn(move || e2.shutdown()); // from any thread, e.g. a signal handler
    engine.wait(); // returns once every connection closed (or shutdown_timeout passed)
    // ANCHOR_END: shutdown
    print!("{}", read_until(&mut s, &["shutting down\n"]));
    Ok(())
}
