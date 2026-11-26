//! A handler's hold on its connection (ADR-180, akit A232): `Context::connection` with
//! `Listener::on_accept`, as akit's console uses them: a connection is closed 300 ms after it
//! was accepted, whatever it sends, unless a request "logs in", which cancels the deadline and
//! gives the connection an idle timeout of its own. HTTP/1.1 and HTTP/2, on the native backend
//! (and io_uring with AKIO_TEST_BACKEND=uring).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashSet,
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, Router,
    client::ClientRequest,
    h2client::{H2Client, H2Options},
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

const DEADLINE: Duration = Duration::from_millis(300);

fn app() -> Router {
    Router::new()
        .get("/", |ctx: &mut Context| {
            let id = ctx.connection().map_or(0, |c| c.id());
            ctx.text(200, id.to_string());
        })
        .get("/login", |ctx: &mut Context| {
            let c = ctx.connection().expect("a connection");
            c.cancel_close();
            c.set_idle_timeout(Some(Duration::from_secs(120))).unwrap();
            ctx.text(200, c.id().to_string());
        })
        .get("/logout", |ctx: &mut Context| {
            // Back on the short rule: closed a deadline from now.
            let c = ctx.connection().expect("a connection");
            c.close_after(DEADLINE).unwrap();
            ctx.text(200, c.id().to_string());
        })
}

/// A server whose listener closes every connection `DEADLINE` after accepting it, and keeps
/// the ids it accepted.
fn start() -> (Arc<Engine>, Arc<Mutex<HashSet<u64>>>) {
    let ids = Arc::new(Mutex::new(HashSet::new()));
    let seen = ids.clone();
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(500);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(2)
                    .on_accept(move |c| {
                        seen.lock().unwrap().insert(c.id());
                        c.close_after(DEADLINE).unwrap();
                    })
                    .serve(serve(app())),
            )
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    (e, ids)
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

/// One HTTP/1.1 request on `s`; the response body, or `None` if the connection is closed.
fn get(s: &mut TcpStream, path: &str) -> Option<String> {
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .ok()?;
    let mut buf = Vec::new();
    let mut b = [0u8; 1024];
    loop {
        let n = loop {
            match s.read(&mut b) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                r => break r,
            }
        };
        match n {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&b[..n]),
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let len: usize = text[..end]
                .lines()
                .find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap();
            if buf.len() >= end + 4 + len {
                return Some(text[end + 4..end + 4 + len].to_string());
            }
        }
    }
}

fn connect(e: &Engine) -> TcpStream {
    let s = TcpStream::connect(e.local_addrs()[0]).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

#[test]
fn http1_without_login_closes_at_the_deadline_whatever_it_sends() {
    let (e, ids) = start();
    let t0 = Instant::now();
    let mut s = connect(&e);
    let id = get(&mut s, "/").expect("served before the deadline");
    assert!(ids.lock().unwrap().contains(&id.parse().unwrap()));
    // Requests every 50 ms do not keep it open.
    let mut closed = None;
    while t0.elapsed() < Duration::from_secs(5) {
        if get(&mut s, "/").is_none() {
            closed = Some(t0.elapsed());
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let at = closed.expect("closed by the deadline");
    assert!(at >= Duration::from_millis(250), "{at:?}");
    assert!(at < Duration::from_secs(3), "{at:?}");
    stop(&e);
}

#[test]
fn http1_login_keeps_the_connection_and_logout_restores_the_deadline() {
    let (e, ids) = start();
    let mut s = connect(&e);
    let id = get(&mut s, "/login").expect("login");
    assert!(ids.lock().unwrap().contains(&id.parse().unwrap()));
    thread::sleep(DEADLINE * 2);
    assert_eq!(
        get(&mut s, "/").as_deref(),
        Some(id.as_str()),
        "kept past the deadline"
    );
    assert_eq!(get(&mut s, "/logout").as_deref(), Some(id.as_str()));
    let t = Instant::now();
    while get(&mut s, "/").is_some() {
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "not closed after logout"
        );
        thread::sleep(Duration::from_millis(50));
    }
    stop(&e);
}

#[test]
fn http2_login_keeps_the_whole_connection() {
    let (e, ids) = start();
    let addr = e.local_addrs()[0];
    let base = format!("http://{addr}");
    let login = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let plain = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let r = login
        .send(ClientRequest::get(&format!("{base}/login")))
        .wait()
        .unwrap();
    let id: u64 = String::from_utf8(r.body).unwrap().parse().unwrap();
    assert!(ids.lock().unwrap().contains(&id));
    let r = plain
        .send(ClientRequest::get(&format!("{base}/")))
        .wait()
        .unwrap();
    let other: u64 = String::from_utf8(r.body).unwrap().parse().unwrap();
    assert_ne!(id, other);
    thread::sleep(DEADLINE * 2);
    // Another stream of the logged-in connection: the same connection, still open.
    let r = login
        .send(ClientRequest::get(&format!("{base}/")))
        .wait()
        .unwrap();
    assert_eq!(String::from_utf8(r.body).unwrap(), id.to_string());
    // The other one was closed at its deadline.
    assert!(
        plain
            .send(ClientRequest::get(&format!("{base}/")))
            .wait()
            .is_err()
    );
    stop(&e);
}
