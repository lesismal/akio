//! Connection write API corners: cork/flush, streamed response slots behind unfinished ones,
//! files, segments on TCP, and sending after close.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

use flash::{Config, Conn, Engine, Error, Handler, Listener, fn_acceptor};

type Report = Arc<Mutex<mpsc::Sender<String>>>;

struct H {
    file: Arc<std::fs::File>,
    report: Report,
}

impl H {
    fn say(&self, s: impl Into<String>) {
        let _ = self.report.lock().unwrap().send(s.into());
    }
}

impl Handler for H {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        for &cmd in data {
            match cmd {
                // Corked writes go out together on flush.
                b'c' => {
                    c.cork();
                    for p in [&b"a"[..], b"b", b"c"] {
                        c.send(p).unwrap();
                    }
                    c.flush().unwrap();
                }
                // A streamed slot behind an unfilled one buffers until it is first in line.
                b's' => {
                    let first = c.reserve_response().unwrap();
                    let second = c.reserve_response().unwrap();
                    let st = second.stream(b"[2:".to_vec());
                    st.write(b"x".to_vec()).unwrap();
                    self.say(format!("queued {}", st.queued_bytes()));
                    // More than max_queued_bytes cannot be held back.
                    match st.write(vec![b'z'; 4096]) {
                        Err(Error::Overloaded) => self.say("overloaded"),
                        other => self.say(format!("unexpected {other:?}")),
                    }
                    first.fill(b"[1]".to_vec());
                    st.write(b"y]".to_vec()).unwrap();
                    st.finish(false);
                }
                // Files: empty, whole, and corked.
                b'f' => {
                    c.inner().send_file(self.file.clone(), 0, 0).unwrap();
                    c.inner().send_file(self.file.clone(), 0, 5).unwrap();
                    c.cork();
                    c.inner().send_file(self.file.clone(), 5, 5).unwrap();
                    c.flush().unwrap();
                }
                // Segments on TCP are just bytes.
                b'g' => {
                    c.send_segments(b"seg".to_vec(), 2).unwrap();
                    c.send_segments(b"ment".to_vec(), 0).unwrap();
                }
                // Sending after close fails with Closed.
                b'x' => {
                    c.close();
                    let r = c.send(b"late");
                    self.say(format!("{r:?} open={}", c.is_open()));
                    // Nothing is queued: flushing a closed connection is a no-op.
                    let r = c.flush();
                    self.say(format!("flush {r:?}"));
                }
                _ => {}
            }
        }
    }
}

fn start() -> (Engine, mpsc::Receiver<String>, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("flash-conn-api-{}", std::process::id()));
    std::fs::write(&path, b"0123456789").unwrap();
    let file = Arc::new(std::fs::File::open(&path).unwrap());
    let (tx, rx) = mpsc::channel();
    let report: Report = Arc::new(Mutex::new(tx));
    let e = Engine::builder()
        .config(Config {
            shutdown_timeout: Duration::from_millis(300),
            max_queued_bytes: 1024,
            ..Config::default()
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse::<SocketAddr>().unwrap())
                .backend(common::backend())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<H>| H {
                    file: file.clone(),
                    report: report.clone(),
                })),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    (e, rx, path)
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn read_n(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut b = vec![0; n];
    s.read_exact(&mut b).unwrap();
    b
}

#[test]
fn write_api_corners() {
    let (e, rx, path) = start();
    let mut s = connect(&e);
    s.write_all(b"c").unwrap();
    assert_eq!(read_n(&mut s, 3), b"abc");

    s.write_all(b"s").unwrap();
    assert_eq!(read_n(&mut s, 9), b"[1][2:xy]");
    let rep: Vec<String> = (0..2)
        .map(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect();
    assert_eq!(rep[1], "overloaded");
    assert!(rep[0].starts_with("queued"), "{rep:?}");

    s.write_all(b"f").unwrap();
    assert_eq!(read_n(&mut s, 10), b"0123456789");

    s.write_all(b"g").unwrap();
    assert_eq!(read_n(&mut s, 7), b"segment");

    s.write_all(b"x").unwrap();
    let r = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        r.starts_with("Err(Closed)") && r.ends_with("open=false"),
        "{r}"
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        "flush Ok(())"
    );
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).unwrap(), 0);

    e.shutdown();
    e.wait();
    let _ = std::fs::remove_file(path);
}
