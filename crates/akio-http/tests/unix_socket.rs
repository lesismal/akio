//! The HTTP client over a Unix-domain socket (`Client::with_unix_socket`, ADR-120), against a
//! plain server on a `std` Unix listener, as the Docker daemon's API is reached.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Headers, Router,
    client::{Client, ClientError, ClientRequest, ResponseBody, ResponseHandler, ResponseHead},
    serve,
};

fn backend() -> Backend {
    match std::env::var("AKIO_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

/// An engine whose dialed connections run on its listener's threads, so on the backend under
/// test (client threads are always epoll).
fn engine() -> Arc<Engine> {
    let e = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(serve(Router::new())),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    Arc::new(e)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// A fresh socket path in the temporary directory (short: `sun_path` is ~100 bytes).
fn sock_path(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = PathBuf::from(format!(
        "/tmp/akio-ux-{}-{tag}-{n}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// Reads one request head; its request line, or `None` at the end of the stream.
fn read_head(r: &mut BufReader<UnixStream>) -> Option<String> {
    let mut first = String::new();
    if r.read_line(&mut first).ok()? == 0 {
        return None;
    }
    loop {
        let mut l = String::new();
        if r.read_line(&mut l).ok()? == 0 || l == "\r\n" {
            break;
        }
    }
    Some(first.trim_end().to_owned())
}

/// A server answering every request on `path` with `answer(request line, stream)`, on threads
/// of its own; how many connections it accepted.
fn server(
    path: &PathBuf,
    answer: impl Fn(&str, &mut UnixStream) -> bool + Send + Sync + 'static,
) -> Arc<AtomicUsize> {
    let l = UnixListener::bind(path).unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let a = accepted.clone();
    let answer = Arc::new(answer);
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            a.fetch_add(1, Ordering::SeqCst);
            let answer = answer.clone();
            thread::spawn(move || {
                let mut w = s.try_clone().unwrap();
                let mut r = BufReader::new(s);
                while let Some(line) = read_head(&mut r) {
                    if !answer(&line, &mut w) {
                        return;
                    }
                }
            });
        }
    });
    accepted
}

#[test]
fn requests_reach_the_socket_and_its_connections_are_reused() {
    let path = sock_path("get");
    let accepted = server(&path, |line, w| {
        let body = format!("you sent {line}");
        write!(
            w,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .is_ok()
    });
    let e = engine();
    // The URL's host is only the `Host` field: nothing is resolved.
    let c = Client::new(e.clone()).with_unix_socket(Some(path.clone()));
    for i in 0..3 {
        let r = c
            .send(ClientRequest::get(&format!(
                "http://docker.invalid/containers/json?n={i}"
            )))
            .wait()
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            String::from_utf8(r.body).unwrap(),
            format!("you sent GET /containers/json?n={i} HTTP/1.1")
        );
    }
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "one kept-alive connection"
    );
    stop(&e);
    let _ = std::fs::remove_file(&path);
}

#[derive(Default)]
struct Seen {
    status: u16,
    chunks: Vec<Vec<u8>>,
    end: bool,
    error: Option<String>,
}

struct Rec {
    seen: Arc<Mutex<Seen>>,
    chunk: mpsc::Sender<()>,
    head: Option<mpsc::Sender<ResponseBody>>,
}

impl ResponseHandler for Rec {
    fn on_head(&mut self, head: ResponseHead, body: ResponseBody) {
        self.seen.lock().unwrap().status = head.status;
        if let Some(h) = self.head.take() {
            let _ = h.send(body);
        }
    }
    fn on_data(&mut self, chunk: &[u8]) {
        self.seen.lock().unwrap().chunks.push(chunk.to_vec());
        let _ = self.chunk.send(());
    }
    fn on_end(&mut self, _: &Headers) {
        self.seen.lock().unwrap().end = true;
        let _ = self.chunk.send(());
    }
    fn on_error(&mut self, e: ClientError) {
        self.seen.lock().unwrap().error = Some(e.to_string());
        let _ = self.chunk.send(());
    }
}

/// An endless stream (as Docker's `/events`) arrives as it is written, and ends with an error
/// when the server cuts it midway.
#[test]
fn a_stream_arrives_as_written_and_a_cut_is_an_error() {
    let path = sock_path("events");
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let go_rx = Arc::new(Mutex::new(go_rx));
    server(&path, move |_, w| {
        let _ = w.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        for i in 0..3 {
            if go_rx.lock().unwrap().recv().is_err() {
                return false;
            }
            let ev = format!("{{\"Type\":\"container\",\"n\":{i}}}\n");
            let _ = write!(w, "{:x}\r\n{ev}\r\n", ev.len());
        }
        // Cut midway: no last chunk.
        let _ = w.shutdown(std::net::Shutdown::Both);
        false
    });
    let e = engine();
    let c = Client::new(e.clone()).with_unix_socket(Some(path.clone()));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (ctx, crx) = mpsc::channel();
    let (htx, hrx) = mpsc::channel();
    c.request_with(
        ClientRequest::get("http://docker/events"),
        Rec {
            seen: seen.clone(),
            chunk: ctx,
            head: Some(htx),
        },
    );
    let _body = hrx.recv_timeout(Duration::from_secs(10)).unwrap();
    for i in 0..3 {
        go_tx.send(()).unwrap();
        crx.recv_timeout(Duration::from_secs(10)).unwrap();
        let s = seen.lock().unwrap();
        assert_eq!(s.chunks.len(), i + 1, "event {i} arrived alone");
    }
    crx.recv_timeout(Duration::from_secs(10)).unwrap();
    let s = seen.lock().unwrap();
    assert_eq!(s.status, 200);
    assert!(!s.end, "a cut stream does not end cleanly");
    assert!(s.error.is_some(), "the cut is an error");
    drop(s);
    stop(&e);
    let _ = std::fs::remove_file(&path);
}

/// No socket at the path, a path too long for `sun_path`, and a socket that closes at once:
/// each is an error, not a hang.
#[test]
fn connect_failures_are_errors() {
    let e = engine();
    let missing = sock_path("missing");
    let c = Client::new(e.clone()).with_unix_socket(Some(missing));
    let r = c
        .send(ClientRequest::get("http://docker/_ping"))
        .wait_timeout(Duration::from_secs(10))
        .expect("an answer");
    assert!(matches!(r, Err(ClientError::Io(_))), "{r:?}");

    let long = PathBuf::from(format!("/tmp/{}", "x".repeat(200)));
    let c = Client::new(e.clone()).with_unix_socket(Some(long));
    let r = c
        .send(ClientRequest::get("http://docker/_ping"))
        .wait_timeout(Duration::from_secs(10))
        .expect("an answer");
    match r {
        Err(ClientError::Io(err)) => {
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        }
        other => panic!("{other:?}"),
    }

    let path = sock_path("closes");
    server(&path, |_, _| false);
    let c = Client::new(e.clone()).with_unix_socket(Some(path.clone()));
    let r = c
        .send(ClientRequest::get("http://docker/_ping"))
        .wait_timeout(Duration::from_secs(10))
        .expect("an answer");
    assert!(r.is_err(), "{r:?}");
    stop(&e);
    let _ = std::fs::remove_file(&path);
}

/// The engine's own `dial_unix`: the connection's addresses are `UNIX_ADDR`, and bytes go both
/// ways.
#[test]
fn engine_dial_unix_addresses_and_bytes() {
    use akio::{Conn, Handler};
    let path = sock_path("raw");
    let l = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut b = [0u8; 4];
        s.read_exact(&mut b).unwrap();
        s.write_all(&b).unwrap();
    });
    struct Echo(mpsc::Sender<(std::net::SocketAddr, std::net::SocketAddr, Vec<u8>)>);
    impl Handler for Echo {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let _ = self.0.send((c.peer_addr(), c.local_addr(), data.to_vec()));
        }
    }
    let e = engine();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    e.dial_unix(
        &path,
        akio::fn_acceptor(move |c: &Conn<Echo>| {
            c.send(b"ping").unwrap();
            Echo(tx.lock().unwrap().clone())
        }),
        |err| panic!("{err}"),
    );
    let (peer, local, data) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!((peer, local), (akio::UNIX_ADDR, akio::UNIX_ADDR));
    assert_eq!(data, b"ping");
    stop(&e);
    let _ = std::fs::remove_file(&path);
}
