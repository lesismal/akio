//! Unix-domain stream listeners (`Listener::unix`, ADR-121): akio-http served on a socket
//! file, its mode, a stale file replaced and one in use refused, added and removed at run
//! time. `AKIO_TEST_BACKEND=uring` runs them on io_uring.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use akio::{Backend, Config, Engine, Listener, UNIX_ADDR, UringConfig};
use akio_http::{Context, Router, serve};

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

fn config() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(500);
    v
}

fn router() -> Router {
    Router::new()
        .get("/peer", |ctx: &mut Context| {
            let p = ctx.peer().to_string();
            ctx.text(200, p);
        })
        .post("/echo", |ctx: &mut Context| {
            let b = ctx.body().to_vec();
            ctx.bytes(200, "application/octet-stream", b);
        })
}

/// A fresh socket path in the temporary directory (short: `sun_path` is ~100 bytes).
fn sock_path(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = PathBuf::from(format!(
        "/tmp/akio-ul-{}-{tag}-{n}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn unix_engine(l: Listener) -> io::Result<Engine> {
    let e = Engine::builder()
        .config(config())
        .listen(l.backend(backend()).threads(2).serve(serve(router())))
        .build()?;
    e.start()?;
    Ok(e)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn connect(path: &PathBuf) -> UnixStream {
    let s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

/// Reads one response: its status and body (`Content-Length` framed).
fn read_response(r: &mut BufReader<UnixStream>) -> (u16, Vec<u8>) {
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    let status = line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut len = 0;
    loop {
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        if l == "\r\n" {
            break;
        }
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).unwrap();
    (status, body)
}

#[test]
fn requests_over_a_unix_listener_with_its_mode() {
    let path = sock_path("get");
    let e = unix_engine(Listener::unix(&path).unix_mode(0o600)).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(e.local_addrs(), vec![UNIX_ADDR]);
    let s = connect(&path);
    let mut w = s.try_clone().unwrap();
    let mut r = BufReader::new(s);
    for _ in 0..3 {
        w.write_all(b"GET /peer HTTP/1.1\r\nHost: admin\r\n\r\n")
            .unwrap();
        let (status, body) = read_response(&mut r);
        assert_eq!(status, 200);
        assert_eq!(
            body,
            UNIX_ADDR.to_string().as_bytes(),
            "the peer is UNIX_ADDR"
        );
    }
    stop(&e);
    let _ = std::fs::remove_file(&path);
}

/// A body larger than the socket buffers both ways, by several clients at once; then a client
/// that leaves midway does not disturb the next.
#[test]
fn large_bodies_and_a_client_cut_midway() {
    let path = sock_path("big");
    let e = unix_engine(Listener::unix(&path)).unwrap();
    let body: Vec<u8> = (0..512 * 1024).map(|i| (i % 251) as u8).collect();
    let body = Arc::new(body);
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let (path, body) = (path.clone(), body.clone());
            std::thread::spawn(move || {
                let s = connect(&path);
                let mut w = s.try_clone().unwrap();
                write!(
                    w,
                    "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .unwrap();
                w.write_all(&body).unwrap();
                let (status, got) = read_response(&mut BufReader::new(s));
                assert_eq!(status, 200);
                assert!(got == *body, "echoed intact");
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    {
        let mut s = connect(&path);
        s.write_all(b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 100000\r\n\r\nabc")
            .unwrap();
    } // dropped midway
    let s = connect(&path);
    let mut w = s.try_clone().unwrap();
    w.write_all(b"GET /peer HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    assert_eq!(read_response(&mut BufReader::new(s)).0, 200);
    stop(&e);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_stale_socket_file_is_replaced_and_one_in_use_refused() {
    // Left behind: bound, then closed without removing the file.
    let path = sock_path("stale");
    drop(UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    let e = unix_engine(Listener::unix(&path)).unwrap();
    let s = connect(&path);
    let mut w = s.try_clone().unwrap();
    w.write_all(b"GET /peer HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    assert_eq!(read_response(&mut BufReader::new(s)).0, 200);

    // In use (by the engine above): refused, and the file is left alone.
    let err = unix_engine(Listener::unix(&path)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert_eq!(
        read_after_reconnect(&path),
        200,
        "the first server still serves"
    );
    stop(&e);
    let _ = std::fs::remove_file(&path);

    // Not a socket: refused, and the file is kept.
    let file = sock_path("file");
    std::fs::write(&file, b"keep me").unwrap();
    let err = unix_engine(Listener::unix(&file)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    assert_eq!(std::fs::read(&file).unwrap(), b"keep me");
    let _ = std::fs::remove_file(&file);
}

fn read_after_reconnect(path: &PathBuf) -> u16 {
    let s = connect(path);
    let mut w = s.try_clone().unwrap();
    w.write_all(b"GET /peer HTTP/1.1\r\nHost: a\r\n\r\n")
        .unwrap();
    read_response(&mut BufReader::new(s)).0
}

#[test]
fn bad_paths_and_a_mode_without_a_unix_listener_are_refused() {
    let long = PathBuf::from(format!("/tmp/{}", "x".repeat(200)));
    let err = unix_engine(Listener::unix(long)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let err =
        unix_engine(Listener::tcp("127.0.0.1:0".parse().unwrap()).unix_mode(0o600)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let path = sock_path("std-mode");
    let std = UnixListener::bind(&path).unwrap();
    let err = unix_engine(Listener::unix_from_std(std).unix_mode(0o600)).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_listener_from_std_is_served() {
    let path = sock_path("std");
    let std = UnixListener::bind(&path).unwrap();
    let e = unix_engine(Listener::unix_from_std(std)).unwrap();
    assert_eq!(read_after_reconnect(&path), 200);
    stop(&e);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn added_and_removed_at_run_time_with_a_filter() {
    let e = Engine::builder()
        .config(config())
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(1)
                .serve(serve(router())),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    let path = sock_path("added");
    let seen = Arc::new(AtomicUsize::new(0));
    let s2 = seen.clone();
    let id = e
        .add_listener(
            Listener::unix(&path)
                .unix_mode(0o600)
                .backend(backend())
                .threads(2)
                .filter(move |peer| {
                    assert_eq!(*peer, UNIX_ADDR);
                    s2.fetch_add(1, Ordering::SeqCst) == 0 // the first only
                })
                .serve(serve(router())),
        )
        .unwrap();
    assert_eq!(read_after_reconnect(&path), 200);
    // The second connection is refused by the filter: closed without an answer.
    let s = connect(&path);
    let mut w = s.try_clone().unwrap();
    let _ = w.write_all(b"GET /peer HTTP/1.1\r\nHost: a\r\n\r\n");
    let mut buf = [0u8; 16];
    assert!(matches!((&s).read(&mut buf), Ok(0) | Err(_)));
    assert_eq!(seen.load(Ordering::SeqCst), 2);

    e.remove_listener(id).unwrap();
    let refused = UnixStream::connect(&path).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
    // The file is the caller's; binding there again replaces it.
    let id = e
        .add_listener(
            Listener::unix(&path)
                .backend(backend())
                .serve(serve(router())),
        )
        .unwrap();
    assert_eq!(read_after_reconnect(&path), 200);
    e.remove_listener(id).unwrap();
    stop(&e);
    let _ = std::fs::remove_file(&path);
}
