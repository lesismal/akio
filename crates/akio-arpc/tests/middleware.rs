//! Middleware chains, coders (gzip, appended values) end to end, and the bound on pending calls.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Engine, Listener};
use akio_arpc::{
    CallError, Routes, Server, StreamEvent, Values,
    coder::{Appender, FLAG_BIT_TRACING, Gzip},
    dial_blocking,
    proto::{Cmd, encode},
};

fn engine(server: Option<Server>) -> Arc<Engine> {
    let mut b = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(300);
            v
        })
        .client_threads(1);
    if let Some(s) = server {
        b = b.listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(s),
        );
    }
    let e = Arc::new(b.build().unwrap());
    e.start().unwrap();
    e
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(5), "timed out: {what}");
        thread::sleep(Duration::from_millis(2));
    }
}

const T: Option<Duration> = Some(Duration::from_secs(5));

#[test]
fn chains_run_in_order_wrap_the_handler_and_abort() {
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let push = |l: &Arc<Mutex<Vec<String>>>, s: String| l.lock().unwrap().push(s);
    let (l1, l2, l3, l4, l5) = (
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
    );
    let routes = Routes::new()
        // Registered before the handlers and after: both apply to every method.
        .middleware(move |ctx, next| {
            push(&l1, format!("g1 before {}", ctx.method()));
            ctx.values_mut().set("user", "ann");
            next.run(ctx);
            push(&l1, format!("g1 after responded={}", ctx.responded()));
        })
        .handle("/echo", move |ctx| {
            push(&l2, format!("handler user={:?}", ctx.values().get("user")));
            let b = ctx.body().to_vec();
            ctx.write(&b);
        })
        .method_middleware("/echo", move |ctx, next| {
            push(&l3, "echo mw".into());
            next.run(ctx);
        })
        .middleware(move |ctx, next| {
            push(&l4, "g2".into());
            if ctx.body() == b"forbidden" {
                return ctx.error("aborted"); // the handler never runs
            }
            next.run(ctx);
        })
        // Middleware for a method without a handler: the fallback (here, none) answers.
        .method_middleware("/ghost", move |ctx, next| {
            push(&l5, "ghost mw".into());
            next.run(ctx);
        })
        .handle("/note", |_ctx| {});
    let e = engine(Some(Server::new(Arc::new(routes))));
    let p = dial_blocking(&e, e.local_addrs()[0], Arc::new(Routes::new())).unwrap();

    assert_eq!(p.call("/echo", b"hi", T).wait().unwrap(), b"hi");
    assert_eq!(
        std::mem::take(&mut *log.lock().unwrap()),
        [
            "g1 before /echo",
            "g2",
            "echo mw",
            "handler user=Some([97, 110, 110])",
            "g1 after responded=true",
        ]
    );

    assert_eq!(
        p.call("/echo", b"forbidden", T).wait(),
        Err(CallError::Remote("aborted".into()))
    );
    assert_eq!(
        std::mem::take(&mut *log.lock().unwrap()),
        ["g1 before /echo", "g2", "g1 after responded=true"]
    );

    // Unknown methods run the global chain, then get "method not found".
    assert_eq!(
        p.call("/ghost", b"", T).wait(),
        Err(CallError::Remote(akio_arpc::METHOD_NOT_FOUND.into()))
    );
    assert_eq!(
        std::mem::take(&mut *log.lock().unwrap()),
        [
            "g1 before /ghost",
            "g2",
            "ghost mw",
            "g1 after responded=true"
        ]
    );

    // Notifies go through the chain too.
    assert!(p.notify("/note", b"n"));
    wait_until("notify logged", || log.lock().unwrap().len() == 3);
    assert_eq!(
        std::mem::take(&mut *log.lock().unwrap()),
        ["g1 before /note", "g2", "g1 after responded=true"]
    );
    p.close();
    stop(&e);
}

#[test]
fn client_side_middleware_serves_the_servers_calls() {
    let server = Server::new(Arc::new(Routes::new().handle("/ask", |ctx| {
        let r = ctx.detach();
        ctx.peer()
            .call_async("/client/name", b"", None, move |res| match res {
                Ok(n) => r.write(&n),
                Err(e) => r.error(&e.to_string()),
            });
    })));
    let e = engine(Some(server));
    let client_routes = Routes::new()
        .middleware(|ctx, next| {
            next.run(ctx);
            assert!(ctx.responded());
        })
        .method_middleware("/client/name", |ctx, next| {
            ctx.values_mut().set("name", "bob");
            next.run(ctx);
        })
        .handle("/client/name", |ctx| {
            let n = ctx.values().get("name").unwrap_or_default().to_vec();
            ctx.write(&n);
        });
    let p = dial_blocking(&e, e.local_addrs()[0], Arc::new(client_routes)).unwrap();
    assert_eq!(p.call("/ask", b"", T).wait().unwrap(), b"bob");
    p.close();
    stop(&e);
}

fn coded(r: Routes) -> Routes {
    r.coder(Appender::new("trace", FLAG_BIT_TRACING))
        .coder(Gzip::new(256))
}

#[test]
fn coders_carry_values_compress_and_cover_every_message_kind() {
    let routes = coded(Routes::new())
        .middleware(|ctx, next| {
            // The appended value is visible to middleware before the handler runs.
            if ctx.values().get("trace").is_none() && !ctx.is_notify() {
                return ctx.error("no trace");
            }
            next.run(ctx);
        })
        .handle("/echo", |ctx| {
            let mut b = ctx.values().get("trace").unwrap_or_default().to_vec();
            b.push(b'|');
            b.extend_from_slice(ctx.body());
            ctx.values_mut().set("trace", "answered");
            ctx.write(&b);
        })
        .handle("/later", |ctx| {
            let r = ctx.detach();
            thread::spawn(move || r.write(&vec![b'L'; 100_000]));
        })
        .handle_stream("/upper", |_s| {
            |s: &akio_arpc::Stream, ev: StreamEvent<'_>| match ev {
                StreamEvent::Message(m) => {
                    s.send(&m.to_ascii_uppercase());
                }
                StreamEvent::Eof => {
                    s.close_send();
                }
            }
        });
    let server = Server::new(Arc::new(routes));
    let e = engine(Some(server.clone()));
    let (ntx, nrx) = mpsc::channel();
    let ntx = Mutex::new(ntx);
    let client = coded(Routes::new()).handle("/news", move |ctx| {
        let _ = ntx.lock().unwrap().send(ctx.body().to_vec());
    });
    let p = dial_blocking(&e, e.local_addrs()[0], Arc::new(client)).unwrap();
    let v = Values::new().with("trace", "t-1");

    // Small and big (compressed) calls, values both ways.
    assert_eq!(p.call_with("/echo", b"x", T, &v).wait().unwrap(), b"t-1|x");
    let big = vec![b'z'; 1 << 20];
    let got = p.call_with("/echo", &big, T, &v).wait().unwrap();
    assert_eq!(&got[..4], b"t-1|");
    assert_eq!(&got[4..], &big[..]);
    assert_eq!(
        p.call("/echo", b"x", T).wait(),
        Err(CallError::Remote("no trace".into()))
    );
    // A detached answer is coded too.
    assert_eq!(
        p.call_with("/later", b"", T, &v).wait().unwrap(),
        vec![b'L'; 100_000]
    );
    // Streams and broadcast.
    let (tx, rx) = mpsc::channel();
    let s = p.new_stream("/upper", move |_s, ev| {
        if let StreamEvent::Message(m) = ev {
            let _ = tx.send(m.to_vec());
        }
    });
    let word = vec![b'w'; 5000];
    assert!(s.send(&word));
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        vec![b'W'; 5000]
    );
    s.close_send();
    wait_until("registered", || server.peers().len() == 1);
    server.broadcast("/news", &vec![b'n'; 4096]);
    assert_eq!(
        nrx.recv_timeout(Duration::from_secs(5)).unwrap(),
        vec![b'n'; 4096]
    );
    p.close();
    stop(&e);
}

/// Sends `frame` on a raw connection and reports whether the server closed it.
fn closes_on(addr: std::net::SocketAddr, frame: &[u8]) -> bool {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(frame).unwrap();
    let mut b = [0u8; 64];
    matches!(c.read(&mut b), Ok(0) | Err(_))
}

#[test]
fn coded_frames_are_bounded_and_garbage_closes() {
    let routes = Routes::new()
        .coder(Gzip::new(0))
        .max_body_bytes(10_000)
        .handle("/echo", |ctx| {
            let b = ctx.body().to_vec();
            ctx.write(&b);
        });
    let e = engine(Some(Server::new(Arc::new(routes))));
    let addr = e.local_addrs()[0];
    let gz = |payload: &[u8]| {
        let mut f = encode(Cmd::Request, 0, false, false, "/echo", 1, payload);
        let z = akio_deflate::compress(
            akio_deflate::Format::Gzip,
            akio_deflate::Level::BEST,
            &f[5..],
        );
        f.truncate(5);
        f.extend_from_slice(&z);
        f[4] |= 0x80;
        let n = (f.len() - 16) as u32;
        f[..4].copy_from_slice(&n.to_le_bytes());
        f
    };
    // Just under the limit once inflated: answered.
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(&gz(&[7u8; 9_995])).unwrap();
    let mut head = [0u8; 16];
    c.read_exact(&mut head).unwrap();
    assert_eq!(head[4] & 0x80, 0x80, "the answer is compressed too");
    // A small compressed frame that inflates past the limit (a bomb) closes the connection.
    let bomb = gz(&vec![0u8; 5_000_000]);
    assert!(bomb.len() < 10_000);
    assert!(closes_on(addr, &bomb));
    // Bit set on data that is not gzip.
    let mut bad = encode(Cmd::Request, 0, false, false, "/echo", 1, b"plain");
    bad[4] |= 0x80;
    assert!(closes_on(addr, &bad));
    stop(&e);
}

#[test]
fn pending_calls_are_bounded() {
    let server = Server::new(Arc::new(Routes::new().handle("/never", |ctx| {
        drop(ctx.detach());
    })));
    let e = engine(Some(server));
    let p = dial_blocking(
        &e,
        e.local_addrs()[0],
        Arc::new(Routes::new().max_pending_calls(3)),
    )
    .unwrap();
    let long = Some(Duration::from_secs(60));
    let futs: Vec<_> = (0..3).map(|_| p.call("/never", b"", long)).collect();
    assert_eq!(p.pending_calls(), 3);
    // Over the bound: refused at once, not sent, the others untouched.
    assert_eq!(
        p.call("/never", b"", long).wait(),
        Err(CallError::Overloaded)
    );
    assert_eq!(p.pending_calls(), 3);
    p.close();
    for f in futs {
        assert_eq!(f.wait(), Err(CallError::Closed));
    }
    assert_eq!(p.pending_calls(), 0);
    assert_eq!(CallError::Overloaded.to_string(), "too many pending calls");
    stop(&e);
}
