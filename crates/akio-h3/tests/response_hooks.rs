//! HTTP/3: held response heads and asynchronous body filters (`Context::hold_response_head`,
//! `Context::add_body_filter`, ADR-128): a head held and resumed from another thread, replaced
//! by a local response, its stream reset at its deadline; a body filtered elsewhere, streamed
//! with trailers, whole, held to its end, failing, and a large body paced through it; the
//! request's end heard after the filtered body.
#![allow(missing_docs)]

use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_h3::H3Client;
use akio_http::message::{Headers, Method};
use akio_http::{
    BodyChunk, BodyFilter, BodyStream, Context, End, FilterDone, HeldHead, Request, Response,
    Router,
};

const T: Duration = Duration::from_secs(10);

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<String>>>);

impl Log {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }

    fn end(&self, path: &'static str) -> impl FnOnce(End) + Send + 'static {
        let l = self.clone();
        move |e| l.push(format!("{path} {e:?}"))
    }

    fn of(&self, path: &str) -> Vec<String> {
        let pre = format!("{path} ");
        let mut v: Vec<String> = self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.starts_with(&pre))
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Waits for `want`, in any order.
    fn wait(&self, path: &str, want: &[&str]) {
        let mut want = want.to_vec();
        want.sort_unstable();
        let t0 = Instant::now();
        while t0.elapsed() < T && self.of(path) != want {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(self.of(path), want, "{path}");
    }
}

type Work = dyn FnMut(BodyChunk) -> Result<(Vec<u8>, Headers), ()> + Send;

/// A body filter whose calls are answered a little later, from a thread of their own.
struct Later {
    work: Arc<Mutex<Box<Work>>>,
    log: Log,
    path: &'static str,
}

fn later(
    log: &Log,
    path: &'static str,
    work: impl FnMut(BodyChunk) -> Result<(Vec<u8>, Headers), ()> + Send + 'static,
) -> Later {
    Later {
        work: Arc::new(Mutex::new(Box::new(work))),
        log: log.clone(),
        path,
    }
}

impl BodyFilter for Later {
    fn filter(&mut self, chunk: BodyChunk, done: FilterDone) {
        let work = self.work.clone();
        if chunk.end {
            self.log.push(format!("{} last", self.path));
        }
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(2));
            let r = (work.lock().unwrap())(chunk);
            match r {
                Ok((data, trailers)) => done.done(data, trailers),
                Err(()) => done.fail(),
            }
        });
    }

    fn abort(&mut self) {
        self.log.push(format!("{} abort", self.path));
    }
}

fn upper(log: &Log, path: &'static str) -> Later {
    let mut calls = 0;
    later(log, path, move |c| {
        calls += 1;
        let mut t = c.trailers;
        if c.end {
            t.set("x-calls", calls.to_string());
        }
        Ok((c.data.to_ascii_uppercase(), t))
    })
}

fn hold_all(log: &Log, path: &'static str) -> Later {
    let mut held = Vec::new();
    later(log, path, move |c| {
        held.extend_from_slice(&c.data);
        if !c.end {
            return Ok((Vec::new(), Headers::new()));
        }
        let mut out = b"<".to_vec();
        out.append(&mut held);
        out.push(b'>');
        Ok((out, c.trailers))
    })
}

fn resume_later(h: HeldHead, _: &Request) {
    thread::spawn(move || {
        let mut h = h;
        thread::sleep(Duration::from_millis(20));
        let v = format!("{}", h.status());
        h.headers_mut().set("x-held", v);
        h.resume();
    });
}

fn write_later(s: BodyStream, parts: &'static [&'static str], trailers: bool) {
    thread::spawn(move || {
        for p in parts {
            if s.write(p.as_bytes()).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(3));
        }
        if trailers {
            let mut t = Headers::new();
            t.set("x-in", "1");
            s.finish_with_trailers(t);
        } else {
            s.finish();
        }
    });
}

const BIG: usize = 2 << 20;

fn big_byte(i: usize) -> u8 {
    b'a' + (i % 26) as u8
}

fn write_big(s: BodyStream) {
    thread::spawn(move || {
        let mut at = 0;
        while at < BIG {
            while s.queued_bytes() > 512 << 10 {
                let (tx, rx) = mpsc::channel();
                s.on_drain(move || {
                    let _ = tx.send(());
                });
                if rx.recv_timeout(T).is_err() {
                    return;
                }
            }
            let n = (BIG - at).min(16 << 10);
            let piece: Vec<u8> = (at..at + n).map(big_byte).collect();
            if s.write(&piece).is_err() {
                return;
            }
            at += n;
        }
        s.finish();
    });
}

fn app(log: &Log) -> Router {
    let (l1, l2, l3, l4, l5, l6, l7, l8, l9, l10) = (
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
        log.clone(),
    );
    Router::new()
        .get("/hold/whole", move |ctx: &mut Context| {
            ctx.on_end(l1.end("/hold/whole"));
            ctx.hold_response_head(T, resume_later);
            ctx.text(200, "whole");
        })
        .get("/hold/stream", move |ctx: &mut Context| {
            ctx.on_end(l2.end("/hold/stream"));
            ctx.hold_response_head(T, resume_later);
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            s.write(b"a").unwrap();
            s.write(b"b").unwrap();
            s.finish();
        })
        .get("/hold/local", move |ctx: &mut Context| {
            ctx.on_end(l3.end("/hold/local"));
            ctx.hold_response_head(T, |h: HeldHead, _: &Request| {
                thread::spawn(move || h.respond(Response::text(403, "denied")));
            });
            ctx.text(200, "allowed");
        })
        .get("/hold/timeout", move |ctx: &mut Context| {
            ctx.on_end(l4.end("/hold/timeout"));
            let l = l4.clone();
            ctx.hold_response_head(
                Duration::from_millis(50),
                move |h: HeldHead, _: &Request| {
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(300));
                        l.push(format!("/hold/timeout live {}", h.is_live()));
                        h.resume();
                    });
                },
            );
            ctx.text(200, "late");
        })
        .get("/filter/stream", move |ctx: &mut Context| {
            ctx.on_end(l5.end("/filter/stream"));
            ctx.add_body_filter(upper(&l5, "/filter/stream"));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            write_later(s, &["ab", "cd", "ef"], true);
        })
        .get("/filter/whole", move |ctx: &mut Context| {
            ctx.on_end(l6.end("/filter/whole"));
            ctx.add_body_filter(upper(&l6, "/filter/whole"));
            ctx.text(200, "hello");
        })
        .get("/filter/held", move |ctx: &mut Context| {
            ctx.on_end(l7.end("/filter/held"));
            ctx.hold_response_head(T, resume_later);
            ctx.add_body_filter(hold_all(&l7, "/filter/held"));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            write_later(s, &["x", "y", "z"], false);
        })
        .get("/filter/fail", move |ctx: &mut Context| {
            ctx.on_end(l8.end("/filter/fail"));
            let mut n = 0;
            ctx.add_body_filter(later(&l8, "/filter/fail", move |c| {
                n += 1;
                if n == 2 {
                    return Err(());
                }
                Ok((c.data, c.trailers))
            }));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            thread::spawn(move || {
                for _ in 0..200 {
                    if s.write(b"0123456789").is_err() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                s.finish();
            });
        })
        .get("/filter/head", move |ctx: &mut Context| {
            ctx.add_body_filter(upper(&l9, "/filter/head"));
            ctx.text(200, "head");
        })
        .get("/filter/bigheld", |ctx: &mut Context| {
            ctx.add_body_filter(hold_all(&Log::default(), "/filter/bigheld"));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            write_big(s);
        })
        .get("/filter/big", move |ctx: &mut Context| {
            ctx.on_end(l10.end("/filter/big"));
            ctx.add_body_filter(later(&l10, "/filter/big", |c| Ok((c.data, c.trailers))));
            let s = ctx.stream_response(200, Headers::new()).unwrap();
            write_big(s);
        })
}

#[test]
fn held_heads_and_body_filters() {
    let log = Log::default();
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, app(&log))),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    let body = |r: &Response| String::from_utf8(r.body.clone()).unwrap();
    let trailer = |r: &Response, n: &str| {
        r.trailers
            .as_ref()
            .and_then(|t| t.get(n))
            .map(str::to_owned)
    };

    let r = c.get("/hold/whole", T).unwrap();
    assert_eq!((r.status, body(&r).as_str()), (200, "whole"));
    assert_eq!(r.headers.get("x-held"), Some("200"));
    log.wait("/hold/whole", &["/hold/whole Sent"]);

    let r = c.get("/hold/stream", T).unwrap();
    assert_eq!((r.status, body(&r).as_str()), (200, "ab"));
    assert_eq!(r.headers.get("x-held"), Some("200"));
    log.wait("/hold/stream", &["/hold/stream Sent"]);

    let r = c.get("/hold/local", T).unwrap();
    assert_eq!((r.status, body(&r).as_str()), (403, "denied"));
    log.wait("/hold/local", &["/hold/local Sent"]);

    let t0 = Instant::now();
    let r = c.get("/hold/timeout", T);
    assert!(r.is_err(), "reset at its deadline: {r:?}");
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "reset, not timed out"
    );
    log.wait(
        "/hold/timeout",
        &["/hold/timeout Gone", "/hold/timeout live false"],
    );

    let r = c.get("/filter/stream", T).unwrap();
    assert_eq!((r.status, body(&r).as_str()), (200, "ABCDEF"));
    assert_eq!(trailer(&r, "x-in").as_deref(), Some("1"));
    assert!(trailer(&r, "x-calls").is_some());
    log.wait(
        "/filter/stream",
        &["/filter/stream last", "/filter/stream Sent"],
    );

    let r = c.get("/filter/whole", T).unwrap();
    assert_eq!(body(&r), "HELLO");
    assert_eq!(r.headers.get("content-length"), None);
    assert_eq!(trailer(&r, "x-calls").as_deref(), Some("1"));
    log.wait(
        "/filter/whole",
        &["/filter/whole Sent", "/filter/whole last"],
    );

    let r = c.get("/filter/held", T).unwrap();
    assert_eq!(body(&r), "<xyz>");
    assert_eq!(r.headers.get("x-held"), Some("200"));
    log.wait("/filter/held", &["/filter/held Sent", "/filter/held last"]);

    let r = c.get("/filter/fail", T);
    assert!(r.is_err(), "reset by the failing call: {r:?}");
    log.wait("/filter/fail", &["/filter/fail Gone", "/filter/fail abort"]);

    let r = c
        .request_blocking(Method::Head, "/filter/head", &Headers::new(), Vec::new(), T)
        .unwrap();
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert!(log.of("/filter/head").is_empty());

    let r = c.get("/filter/big", T).unwrap();
    assert_eq!(r.body.len(), BIG);
    assert!(r.body.iter().enumerate().all(|(i, b)| *b == big_byte(i)));
    log.wait("/filter/big", &["/filter/big Sent", "/filter/big last"]);

    // Held to its end, then sent in one write, past the stream's send buffer.
    let r = c.get("/filter/bigheld", T).unwrap();
    assert_eq!(r.body.len(), BIG + 2);
    assert_eq!((r.body[0], r.body[BIG + 1]), (b'<', b'>'));
    assert!(
        r.body[1..=BIG]
            .iter()
            .enumerate()
            .all(|(i, b)| *b == big_byte(i))
    );

    // The connection still serves.
    assert_eq!(body(&c.get("/hold/whole", T).unwrap()), "whole");
    e.shutdown();
    e.wait();
}
