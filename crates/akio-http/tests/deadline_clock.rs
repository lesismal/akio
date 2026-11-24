//! The deadlines' coarse clock when a shorter timeout lowers the sweeper's tick (ADR-108): a
//! server connection with the default timeouts (a tick of a second) starts the sweeper first,
//! then a client request with a 300 ms header timeout arms it 900 ms later. The deadline must be
//! counted from the arming, not from where the clock stood when the sweeper went to sleep (it
//! fired about 100 ms after the arming before). Its own test binary: the sweeper is per process.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    net::TcpStream,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyEvent, Context, Detached, HttpConfig, Router, Streaming,
    client::{Client, ClientError, ClientRequest},
    serve_with,
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

#[test]
fn a_shorter_timeout_is_counted_from_its_arming() {
    let held = Arc::new(Mutex::new(Vec::<Detached>::new()));
    let h = held.clone();
    let app = Router::new().post(
        "/upload-never",
        Streaming(move |ctx: &mut Context| {
            let h = h.clone();
            ctx.on_body(move |ctx, ev| {
                if let BodyEvent::End(_) = ev {
                    h.lock().unwrap().push(ctx.detach().unwrap());
                }
            });
        }),
    );
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = Config::default();
                v.shutdown_timeout = Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .backend(backend())
                    .threads(1)
                    .serve(serve_with(HttpConfig::default(), app)),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    // A server connection first: its watch (10 s head timeout) starts the sweeper at a 1 s tick.
    let idle = TcpStream::connect(addr).unwrap();
    thread::sleep(Duration::from_millis(50));

    let c = Client::new(e.clone());
    let d = Duration::from_millis(300);
    let (tx, rx) = mpsc::channel();
    let finished = Arc::new(Mutex::new(None::<Instant>));
    let f2 = finished.clone();
    c.request_streamed(
        ClientRequest::post(&format!("http://{addr}/upload-never"), Vec::new())
            .response_header_timeout(d),
        move |body| {
            thread::spawn(move || {
                for _ in 0..3 {
                    body.write(&[b'u'; 100]).unwrap();
                    thread::sleep(Duration::from_millis(300));
                }
                *f2.lock().unwrap() = Some(Instant::now());
                body.finish().unwrap();
            });
        },
        move |r| {
            let _ = tx.send(r);
        },
    );
    let r = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    let after = finished.lock().unwrap().expect("finished").elapsed();
    assert!(matches!(r, Err(ClientError::HeaderTimeout)), "{r:?}");
    assert!(
        after + Duration::from_millis(20) >= d,
        "fired {after:?} after the finish, before the {d:?} timeout"
    );
    drop(idle);
    held.lock().unwrap().clear();
    e.shutdown();
    e.wait();
}
