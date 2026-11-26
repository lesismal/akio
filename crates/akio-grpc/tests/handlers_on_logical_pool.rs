//! `GrpcServer::handlers_on_logical_pool`: handlers on the logical pool, calls of one connection
//! served at the same time, each call's messages still handed over in order.
#![allow(missing_docs)]

use std::{
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Config, Engine, Listener};
use akio_grpc::{CallOptions, Code, GrpcClient, GrpcServer, Status};
use akio_http::h2client::{H2Client, H2Options};

fn on_pool_thread() -> bool {
    thread::current().name() == Some("akio-pool")
}

fn server(on: bool) -> GrpcServer {
    GrpcServer::new()
        .unary("/test.Pool/Block", |_md, req, sink| {
            // Blocks where it runs: only fine on the pool.
            thread::sleep(Duration::from_millis(150));
            sink.send(
                format!(
                    "{} pool={}",
                    String::from_utf8_lossy(&req),
                    on_pool_thread()
                )
                .as_bytes(),
            );
            sink.finish(Status::ok());
        })
        .bidi("/test.Pool/Chat", |_md, sink| {
            let mut n = 0u64;
            Box::new(move |m| match m {
                Some(m) => {
                    n += 1;
                    // Uneven work: order must not depend on it.
                    thread::sleep(Duration::from_millis(n % 3));
                    assert!(on_pool_thread());
                    sink.send(&[b"re:".as_slice(), &m].concat());
                }
                None => sink.finish(Status::ok()),
            })
        })
        .unary("/test.Pool/Panic", |_md, _req, _sink| panic!("handler bug"))
        .handlers_on_logical_pool(on)
}

fn setup(on: bool) -> (Arc<Engine>, GrpcClient) {
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(akio_http::serve(server(on))),
            )
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let h2 = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    (e, GrpcClient::new(h2, &format!("http://{addr}")))
}

#[test]
fn unary_calls_of_one_connection_run_at_once_on_the_pool() {
    for on in [true, false] {
        let (e, c) = setup(on);
        let t = Instant::now();
        let calls: Vec<_> = (0..8)
            .map(|i| {
                let c = c.clone();
                thread::spawn(move || {
                    c.unary(
                        "/test.Pool/Block",
                        i.to_string().as_bytes(),
                        CallOptions::default(),
                    )
                })
            })
            .collect();
        for (i, h) in calls.into_iter().enumerate() {
            assert_eq!(
                h.join().unwrap().unwrap(),
                format!("{i} pool={on}").into_bytes()
            );
        }
        let took = t.elapsed();
        if on {
            // On the I/O thread they take 8 x 150 ms.
            assert!(took < Duration::from_millis(800), "took {took:?}");
        } else {
            assert!(took >= Duration::from_millis(1200), "took {took:?}");
        }
        e.shutdown();
        e.wait();
    }
}

#[test]
fn a_calls_messages_reach_its_pooled_handler_in_order() {
    let (e, c) = setup(true);
    let mut waits = Vec::new();
    let mut gots = Vec::new();
    // Several calls at once, each with its own ordered conversation.
    let sinks: Vec<_> = (0..4)
        .map(|_| {
            let got = Arc::new(Mutex::new(Vec::new()));
            let g = got.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            let s = c.bidi(
                "/test.Pool/Chat",
                CallOptions::default(),
                move |m| g.lock().unwrap().push(String::from_utf8(m).unwrap()),
                move |st, _| {
                    let _ = tx.send(st);
                },
            );
            waits.push(rx);
            gots.push(got);
            s
        })
        .collect();
    for i in 0..60 {
        for s in &sinks {
            s.send(i.to_string().as_bytes());
        }
    }
    for s in &sinks {
        s.close_send();
    }
    let want: Vec<String> = (0..60).map(|i| format!("re:{i}")).collect();
    for (rx, got) in waits.iter().zip(&gots) {
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap().code,
            Code::Ok
        );
        assert_eq!(*got.lock().unwrap(), want);
    }
    e.shutdown();
    e.wait();
}

#[test]
fn a_panicking_pooled_handler_ends_its_call_and_the_connection_goes_on() {
    let (e, c) = setup(true);
    let err = c
        .unary("/test.Pool/Panic", b"", CallOptions::default())
        .unwrap_err();
    assert_eq!(err.code, Code::Internal);
    assert_eq!(
        c.unary("/test.Pool/Block", b"x", CallOptions::default())
            .unwrap(),
        b"x pool=true"
    );
    e.shutdown();
    e.wait();
}
