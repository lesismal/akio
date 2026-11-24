//! The HTTP/1 client's response header and idle timeouts and its cancellation (ADR-108): a head
//! slow to come, a body that stalls, reads held past the idle timeout, a streamed body's header
//! timeout starting at its finish, deadlines left on a reused connection, and requests
//! cancelled before they are sent, while their head is awaited (the server hears the client
//! go) and in the middle of their body.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    BodyEvent, BodyStream, Context, Detached, Headers, HttpConfig, Router, Streaming,
    client::{
        CancelToken, Client, ClientError, ClientRequest, ClientResponse, ResponseBody,
        ResponseHandler, ResponseHead,
    },
    serve_with,
};

const T: Duration = Duration::from_secs(20);

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

/// What the server keeps so that its connections stay open without answering.
#[derive(Default)]
struct Held {
    detached: Vec<Detached>,
    streams: Vec<BodyStream>,
}

/// The server's view: requests that heard their client go, and a signal per request seen.
struct Server {
    held: Arc<Mutex<Held>>,
    gone: Arc<AtomicUsize>,
    seen: Mutex<mpsc::Receiver<()>>,
}

fn app(held: Arc<Mutex<Held>>, gone: Arc<AtomicUsize>, seen: mpsc::Sender<()>) -> Router {
    let (h1, h2, h3) = (held.clone(), held.clone(), held);
    let seen = Mutex::new(seen);
    Router::new()
        .get("/hello", |ctx: &mut Context| ctx.text(200, "hello"))
        // Never answered; the client going is counted.
        .get("/never", move |ctx: &mut Context| {
            let mut d = ctx.detach().unwrap();
            let gone = gone.clone();
            d.on_gone(move || {
                gone.fetch_add(1, Ordering::SeqCst);
            });
            h1.lock().unwrap().detached.push(d);
            let _ = seen.lock().unwrap().send(());
        })
        .get("/slowhead/:ms", |ctx: &mut Context| {
            let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
            let d = ctx.detach().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(ms));
                d.respond(akio_http::Response::text(200, "late"));
            });
        })
        // A head and three bytes, then nothing.
        .get("/stall", move |ctx: &mut Context| {
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            s.write(b"abc").unwrap();
            h2.lock().unwrap().streams.push(s);
        })
        // `n` pieces of 10 bytes, one every `ms`.
        .get("/drip/:n/:ms", |ctx: &mut Context| {
            let n: usize = ctx.param("n").unwrap().parse().unwrap();
            let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            thread::spawn(move || {
                for _ in 0..n {
                    thread::sleep(Duration::from_millis(ms));
                    if s.write(&[b'd'; 10]).is_err() {
                        return;
                    }
                }
                s.finish();
            });
        })
        // Takes the whole body, then never answers.
        .post(
            "/upload-never",
            Streaming(move |ctx: &mut Context| {
                let h3 = h3.clone();
                ctx.on_body(move |ctx, ev| {
                    if let BodyEvent::End(_) = ev {
                        h3.lock().unwrap().detached.push(ctx.detach().unwrap());
                    }
                });
            }),
        )
}

fn start() -> (Arc<Engine>, Server) {
    let held = Arc::new(Mutex::new(Held::default()));
    let gone = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel();
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
                    .threads(2)
                    .serve(serve_with(
                        HttpConfig::default(),
                        app(held.clone(), gone.clone(), tx),
                    )),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let s = Server {
        held,
        gone,
        seen: Mutex::new(rx),
    };
    (e, s)
}

fn stop(e: &Engine, s: Server) {
    drop(std::mem::take(&mut *s.held.lock().unwrap()));
    e.shutdown();
    e.wait();
}

fn url(e: &Engine, path: &str) -> String {
    format!("http://{}{path}", e.local_addrs()[0])
}

fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < limit {
        if f() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    f()
}

fn send(c: &Client, req: ClientRequest) -> mpsc::Receiver<Result<ClientResponse, ClientError>> {
    let (tx, rx) = mpsc::channel();
    c.request(req, move |r| {
        let _ = tx.send(r);
    });
    rx
}

/// What a [`ResponseHandler`] was told, in order.
#[derive(Debug, PartialEq)]
enum Ev {
    Head(u16),
    Data(Vec<u8>),
    End,
    Error(String),
}

struct Rec {
    evs: Arc<Mutex<Vec<Ev>>>,
    done: mpsc::Sender<()>,
    /// Holds the reads at the head for this long, then resumes them.
    hold: Option<Duration>,
}

impl ResponseHandler for Rec {
    fn on_head(&mut self, head: ResponseHead, body: ResponseBody) {
        self.evs.lock().unwrap().push(Ev::Head(head.status));
        if let Some(d) = self.hold {
            body.hold_reads(true);
            thread::spawn(move || {
                thread::sleep(d);
                body.hold_reads(false);
            });
        }
    }
    fn on_data(&mut self, chunk: &[u8]) {
        let mut evs = self.evs.lock().unwrap();
        match evs.last_mut() {
            Some(Ev::Data(v)) => v.extend_from_slice(chunk),
            _ => evs.push(Ev::Data(chunk.to_vec())),
        }
    }
    fn on_end(&mut self, _trailers: &Headers) {
        self.evs.lock().unwrap().push(Ev::End);
        let _ = self.done.send(());
    }
    fn on_error(&mut self, e: ClientError) {
        self.evs.lock().unwrap().push(Ev::Error(format!("{e:?}")));
        let _ = self.done.send(());
    }
}

fn record(
    c: &Client,
    req: ClientRequest,
    hold: Option<Duration>,
) -> (Arc<Mutex<Vec<Ev>>>, mpsc::Receiver<()>) {
    let evs = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel();
    c.request_with(
        req,
        Rec {
            evs: evs.clone(),
            done: tx,
            hold,
        },
    );
    (evs, rx)
}

/// Waits for the handler's end, and a little more to see that nothing follows it.
fn finished(evs: &Arc<Mutex<Vec<Ev>>>, rx: &mpsc::Receiver<()>) -> Vec<Ev> {
    rx.recv_timeout(T).expect("the handler ends");
    thread::sleep(Duration::from_millis(100));
    std::mem::take(&mut *evs.lock().unwrap())
}

#[test]
fn header_timeout_bounds_the_wait_for_the_head_only() {
    let (e, s) = start();
    let c = Client::new(e.clone());
    let d = Duration::from_millis(300);
    // No head: fails past the header timeout, well before the request timeout.
    let t0 = Instant::now();
    let r = send(
        &c,
        ClientRequest::get(&url(&e, "/never"))
            .response_header_timeout(d)
            .timeout(Duration::from_secs(30)),
    )
    .recv_timeout(T)
    .unwrap();
    let took = t0.elapsed();
    assert!(matches!(r, Err(ClientError::HeaderTimeout)), "{r:?}");
    assert!(r.unwrap_err().is_timeout());
    assert!(took >= d && took < Duration::from_secs(5), "{took:?}");
    // The server hears the client go.
    assert!(wait_until(T, || s.gone.load(Ordering::SeqCst) == 1));
    // The same with the response delivered as it arrives: the error alone, no head.
    let (evs, rx) = record(
        &c,
        ClientRequest::get(&url(&e, "/never")).response_header_timeout(d),
        None,
    );
    assert_eq!(finished(&evs, &rx), vec![Ev::Error("HeaderTimeout".into())]);
    // A head within the limit, and a body much longer than it: both fine.
    let r = send(
        &c,
        ClientRequest::get(&url(&e, "/slowhead/100")).response_header_timeout(d),
    )
    .recv_timeout(T)
    .unwrap()
    .unwrap();
    assert_eq!(r.body, b"late");
    let r = send(
        &c,
        ClientRequest::get(&url(&e, "/drip/10/100")).response_header_timeout(d),
    )
    .recv_timeout(T)
    .unwrap()
    .unwrap();
    assert_eq!(r.body.len(), 100);
    stop(&e, s);
}

#[test]
fn idle_timeout_cuts_a_stalled_body_but_not_held_reads() {
    let (e, s) = start();
    let c = Client::new(e.clone());
    let d = Duration::from_millis(300);
    // Three bytes, then silence: the handler has the head and the bytes, then the error.
    let (evs, rx) = record(
        &c,
        ClientRequest::get(&url(&e, "/stall")).response_idle_timeout(d),
        None,
    );
    assert_eq!(
        finished(&evs, &rx),
        vec![
            Ev::Head(200),
            Ev::Data(b"abc".to_vec()),
            Ev::Error("IdleTimeout".into())
        ]
    );
    // Collected whole: the error.
    let r = send(
        &c,
        ClientRequest::get(&url(&e, "/stall"))
            .response_idle_timeout(d)
            .response_header_timeout(d),
    )
    .recv_timeout(T)
    .unwrap();
    assert!(matches!(r, Err(ClientError::IdleTimeout)), "{r:?}");
    // Gaps shorter than the limit: complete.
    let r = send(
        &c,
        ClientRequest::get(&url(&e, "/drip/8/100")).response_idle_timeout(d),
    )
    .recv_timeout(T)
    .unwrap()
    .unwrap();
    assert_eq!(r.body.len(), 80);
    // Reads held for three times the limit: the time held does not count.
    let (evs, rx) = record(
        &c,
        ClientRequest::get(&url(&e, "/drip/8/50")).response_idle_timeout(d),
        Some(Duration::from_millis(900)),
    );
    assert_eq!(
        finished(&evs, &rx),
        vec![Ev::Head(200), Ev::Data(vec![b'd'; 80]), Ev::End]
    );
    stop(&e, s);
}

#[test]
fn a_streamed_body_starts_its_header_timeout_when_finished() {
    let (e, s) = start();
    let c = Client::new(e.clone());
    let d = Duration::from_millis(300);
    let finished_at = Arc::new(Mutex::new(None::<Instant>));
    let f2 = finished_at.clone();
    let (tx, rx) = mpsc::channel();
    let t0 = Instant::now();
    c.request_streamed(
        ClientRequest::post(&url(&e, "/upload-never"), Vec::new()).response_header_timeout(d),
        move |body| {
            thread::spawn(move || {
                // Three times the header timeout writing the body: it does not count.
                for _ in 0..3 {
                    body.write(&[b'u'; 1000]).unwrap();
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
    let r = rx.recv_timeout(T).unwrap();
    let after = finished_at.lock().unwrap().expect("finished").elapsed();
    assert!(matches!(r, Err(ClientError::HeaderTimeout)), "{r:?}");
    assert!(
        t0.elapsed() >= Duration::from_millis(1200),
        "{:?}",
        t0.elapsed()
    );
    assert!(after + Duration::from_millis(50) >= d, "{after:?}");
    stop(&e, s);
}

#[test]
fn deadlines_do_not_outlive_their_request_on_a_reused_connection() {
    let (e, s) = start();
    let c = Client::new(e.clone());
    let short = Duration::from_millis(100);
    for _ in 0..3 {
        let r = send(
            &c,
            ClientRequest::get(&url(&e, "/drip/2/10"))
                .response_header_timeout(short)
                .response_idle_timeout(short),
        )
        .recv_timeout(T)
        .unwrap()
        .unwrap();
        assert_eq!(r.body.len(), 20);
    }
    // The next requests on the pooled connection have no such limits and take longer.
    thread::sleep(Duration::from_millis(300));
    let r = send(&c, ClientRequest::get(&url(&e, "/slowhead/400")))
        .recv_timeout(T)
        .unwrap()
        .unwrap();
    assert_eq!(r.body, b"late");
    let r = send(&c, ClientRequest::get(&url(&e, "/drip/3/250")))
        .recv_timeout(T)
        .unwrap()
        .unwrap();
    assert_eq!(r.body.len(), 30);
    stop(&e, s);
}

#[test]
fn requests_cancelled_at_any_point() {
    let (e, s) = start();
    let c = Client::new(e.clone());
    let seen = s.seen.lock().unwrap();

    // Before it is sent: at once, and nothing reaches the server.
    let token = CancelToken::new();
    token.cancel();
    assert!(token.is_cancelled());
    let r = send(
        &c,
        ClientRequest::get(&url(&e, "/never")).cancel_with(&token),
    )
    .recv_timeout(Duration::from_millis(100))
    .expect("at once");
    assert!(matches!(r, Err(ClientError::Cancelled)), "{r:?}");
    let (evs, rx) = record(
        &c,
        ClientRequest::get(&url(&e, "/never")).cancel_with(&token),
        None,
    );
    assert_eq!(finished(&evs, &rx), vec![Ev::Error("Cancelled".into())]);
    assert!(seen.recv_timeout(Duration::from_millis(200)).is_err());

    // While the head is awaited: the callback is told, the server hears the client go.
    let token = CancelToken::new();
    let rx = send(
        &c,
        ClientRequest::get(&url(&e, "/never")).cancel_with(&token),
    );
    seen.recv_timeout(T)
        .expect("the request reached the server");
    token.cancel();
    let r = rx.recv_timeout(T).unwrap();
    assert!(matches!(r, Err(ClientError::Cancelled)), "{r:?}");
    assert!(wait_until(T, || s.gone.load(Ordering::SeqCst) == 1));
    // A handler is told once.
    let token = CancelToken::new();
    let (evs, rx) = record(
        &c,
        ClientRequest::get(&url(&e, "/never")).cancel_with(&token),
        None,
    );
    seen.recv_timeout(T)
        .expect("the request reached the server");
    token.cancel();
    token.cancel();
    assert_eq!(finished(&evs, &rx), vec![Ev::Error("Cancelled".into())]);
    assert!(wait_until(T, || s.gone.load(Ordering::SeqCst) == 2));

    // In the middle of the body.
    let token = CancelToken::new();
    let (evs, rx) = record(
        &c,
        ClientRequest::get(&url(&e, "/stall")).cancel_with(&token),
        None,
    );
    assert!(wait_until(T, || evs.lock().unwrap().len() == 2));
    token.cancel();
    assert_eq!(
        finished(&evs, &rx),
        vec![
            Ev::Head(200),
            Ev::Data(b"abc".to_vec()),
            Ev::Error("Cancelled".into())
        ]
    );

    // One token for several requests.
    let token = CancelToken::new();
    let rxs: Vec<_> = (0..2)
        .map(|_| {
            send(
                &c,
                ClientRequest::get(&url(&e, "/never")).cancel_with(&token),
            )
        })
        .collect();
    for _ in 0..2 {
        seen.recv_timeout(T)
            .expect("the request reached the server");
    }
    token.cancel();
    for rx in rxs {
        let r = rx.recv_timeout(T).unwrap();
        assert!(matches!(r, Err(ClientError::Cancelled)), "{r:?}");
    }
    assert!(wait_until(T, || s.gone.load(Ordering::SeqCst) == 4));

    // After it is over: nothing, and the connection serves the next request.
    let token = CancelToken::new();
    let r = send(
        &c,
        ClientRequest::get(&url(&e, "/hello")).cancel_with(&token),
    )
    .recv_timeout(T)
    .unwrap()
    .unwrap();
    assert_eq!(r.body, b"hello");
    token.cancel();
    let r = send(&c, ClientRequest::get(&url(&e, "/hello")))
        .recv_timeout(T)
        .unwrap()
        .unwrap();
    assert_eq!(r.body, b"hello");
    drop(seen);
    stop(&e, s);
}
