//! HTTP client features of ADR-010: redirects (chains, loops, method rules, cross-origin header
//! stripping), per-request timeouts (HTTP/1 and HTTP/2), proxies (absolute form, `CONNECT`,
//! authentication, refusal, `NO_PROXY`), name resolution off the calling thread.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

#[path = "support/proxy.rs"]
mod proxy;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use only::{Backend, Config, Engine, Listener, UringConfig, tls::Tls};
use only_http::{
    Context, Response, Router,
    client::{Client, ClientError, ClientRequest, Proxy, ProxyRefused, RedirectPolicy},
    h2client::{H2Client, H2Options},
    serve,
};

fn backend() -> Backend {
    match std::env::var("ONLY_TEST_BACKEND").as_deref() {
        Ok("uring") => Backend::IoUring({
            let mut v = UringConfig::default();
            v.strict = true;
            v
        }),
        _ => Backend::Epoll,
    }
}

fn start(acceptor: impl only::Acceptor) -> Arc<Engine> {
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
                .serve(acceptor),
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

fn redirect_to(ctx: &mut Context, status: u16, loc: &str) {
    ctx.respond(Response::new(status).header("Location", loc));
}

/// Redirect fixtures. `/inspect` reports what arrived: method, body length, whether
/// Content-Type, Authorization and Cookie were there.
fn app(loops: Arc<AtomicUsize>) -> Router {
    Router::new().fallback(move |ctx: &mut Context| {
        let path = ctx.path().to_owned();
        let query = ctx.req().query().unwrap_or("").to_owned();
        match path.as_str() {
            "/inspect" => {
                let r = format!(
                    "{} {} ct={} auth={} cookie={}",
                    ctx.method().as_str(),
                    ctx.body().len(),
                    ctx.header("content-type").is_some(),
                    ctx.header("authorization").unwrap_or("-"),
                    ctx.header("cookie").unwrap_or("-"),
                );
                ctx.text(200, r);
            }
            "/chain/a" => redirect_to(ctx, 302, "/chain/b"),
            "/chain/b" => redirect_to(ctx, 301, "c?x=1"), // relative: /chain/c
            "/chain/c" => {
                let q = ctx.req().query().unwrap_or("").to_owned();
                ctx.text(200, format!("end {q}"));
            }
            "/loop" => {
                loops.fetch_add(1, Ordering::SeqCst);
                redirect_to(ctx, 302, "/loop");
            }
            "/no-location" => ctx.respond(Response::new(302)),
            "/to" => {
                // `/to?<status>&<location>`
                let (status, loc) = query.split_once('&').unwrap();
                redirect_to(ctx, status.parse().unwrap(), loc);
            }
            "/slow" => {
                let d = ctx.detach().unwrap();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(800));
                    d.respond(Response::text(200, "late"));
                });
            }
            "/hello" => ctx.text(200, "hello"),
            _ => ctx.text(404, "no"),
        }
    })
}

fn server() -> (Arc<Engine>, String, Arc<AtomicUsize>) {
    let loops = Arc::new(AtomicUsize::new(0));
    let e = start(serve(app(loops.clone())));
    let base = format!("http://127.0.0.1:{}", e.local_addrs()[0].port());
    (e, base, loops)
}

fn body(r: Result<only_http::client::ClientResponse, ClientError>) -> String {
    String::from_utf8(r.unwrap().body).unwrap()
}

#[test]
fn redirect_chains_follow_relative_locations_and_report_the_final_url() {
    let (e, base, _) = server();
    // Off by default: the 3xx is the answer.
    let plain = Client::new(e.clone());
    let r = plain
        .send(ClientRequest::get(&format!("{base}/chain/a")))
        .wait();
    let r = r.unwrap();
    assert_eq!(r.status, 302);
    assert_eq!(r.headers.get("location"), Some("/chain/b"));
    assert_eq!(r.url, format!("{base}/chain/a"));

    let c = Client::new(e.clone()).with_redirects(RedirectPolicy::limit(5));
    let r = c
        .send(ClientRequest::get(&format!("{base}/chain/a")))
        .wait()
        .unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"end x=1"[..]));
    assert_eq!(r.url, format!("{base}/chain/c?x=1"));
    // Exactly enough hops is fine; one fewer is not.
    let two = Client::new(e.clone()).with_redirects(RedirectPolicy::limit(2));
    assert_eq!(
        two.send(ClientRequest::get(&format!("{base}/chain/a")))
            .wait()
            .unwrap()
            .status,
        200
    );
    let one = Client::new(e.clone()).with_redirects(RedirectPolicy::limit(1));
    let err = one
        .send(ClientRequest::get(&format!("{base}/chain/a")))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::TooManyRedirects), "{err}");
    // A redirect without Location is returned as is.
    let r = c
        .send(ClientRequest::get(&format!("{base}/no-location")))
        .wait()
        .unwrap();
    assert_eq!(r.status, 302);
    // An unusable target fails.
    let err = c
        .send(ClientRequest::get(&format!("{base}/to?302&ftp://x/")))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::InvalidUrl(_)), "{err}");
    stop(&e);
}

#[test]
fn redirect_loops_end_at_the_limit() {
    let (e, base, loops) = server();
    let c = Client::new(e.clone()).with_redirects(RedirectPolicy::limit(3));
    let err = c
        .send(ClientRequest::get(&format!("{base}/loop")))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::TooManyRedirects), "{err}");
    // The first request plus three redirects.
    assert_eq!(loops.load(Ordering::SeqCst), 4);
    stop(&e);
}

#[test]
fn redirect_method_and_body_rules() {
    let (e, base, _) = server();
    let c = Client::new(e.clone()).with_redirects(RedirectPolicy::limit(3));
    let go = |method: only_http::Method, status: u16| {
        let req = ClientRequest::new(method, &format!("{base}/to?{status}&/inspect"))
            .body(b"payload".to_vec())
            .header("Content-Type", "text/plain");
        body(c.send(req).wait())
    };
    use only_http::Method::{Delete, Get, Head, Post, Put};
    // 303: anything but HEAD becomes GET without body.
    assert_eq!(go(Post, 303), "GET 0 ct=false auth=- cookie=-");
    assert_eq!(go(Put, 303), "GET 0 ct=false auth=- cookie=-");
    let r = c
        .send(ClientRequest::new(Head, &format!("{base}/to?303&/inspect")))
        .wait()
        .unwrap();
    assert_eq!((r.status, r.body.len()), (200, 0));
    // 301/302: POST becomes GET, other methods are kept with their body.
    assert_eq!(go(Post, 301), "GET 0 ct=false auth=- cookie=-");
    assert_eq!(go(Post, 302), "GET 0 ct=false auth=- cookie=-");
    assert_eq!(go(Put, 302), "PUT 7 ct=true auth=- cookie=-");
    assert_eq!(go(Delete, 301), "DELETE 7 ct=true auth=- cookie=-");
    // 307/308: method and body kept.
    assert_eq!(go(Post, 307), "POST 7 ct=true auth=- cookie=-");
    assert_eq!(go(Put, 308), "PUT 7 ct=true auth=- cookie=-");
    assert_eq!(go(Get, 307), "GET 7 ct=true auth=- cookie=-");
    stop(&e);
}

#[test]
fn credentials_do_not_follow_a_redirect_to_another_origin() {
    let (a, base_a, _) = server();
    let (b, base_b, _) = server();
    let c = Client::new(a.clone()).with_redirects(RedirectPolicy::limit(3));
    let req = |loc: &str| {
        ClientRequest::get(&format!("{base_a}/to?302&{loc}"))
            .header("Authorization", "Bearer secret")
            .header("Cookie", "sid=1")
            .header("X-Other", "kept")
    };
    // Same origin: kept.
    assert_eq!(
        body(c.send(req("/inspect")).wait()),
        "GET 0 ct=false auth=Bearer secret cookie=sid=1"
    );
    // Another port is another origin: stripped.
    assert_eq!(
        body(c.send(req(&format!("{base_b}/inspect"))).wait()),
        "GET 0 ct=false auth=- cookie=-"
    );
    // ... and stay stripped when the chain comes back to the first origin.
    let back = format!("{base_b}/to?302&{base_a}/inspect");
    assert_eq!(
        body(c.send(req(&back)).wait()),
        "GET 0 ct=false auth=- cookie=-"
    );
    // `localhost` vs `127.0.0.1` differ as origins too.
    let port_a = a.local_addrs()[0].port();
    assert_eq!(
        body(
            c.send(req(&format!("http://localhost:{port_a}/inspect")))
                .wait()
        ),
        "GET 0 ct=false auth=- cookie=-"
    );
    stop(&a);
    stop(&b);
}

#[test]
fn per_request_timeouts() {
    let (e, base, _) = server();
    let c = Client::new(e.clone());
    let t0 = Instant::now();
    let err = c
        .send(ClientRequest::get(&format!("{base}/slow")).timeout(Duration::from_millis(150)))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::Timeout), "{err}");
    assert!(
        t0.elapsed() < Duration::from_millis(700),
        "{:?}",
        t0.elapsed()
    );
    // The client still works afterwards (the timed-out connection was closed, not reused).
    assert_eq!(
        body(c.send(ClientRequest::get(&format!("{base}/hello"))).wait()),
        "hello"
    );
    // A client-wide default, overridden per request.
    let c = Client::new(e.clone()).with_timeout(Duration::from_millis(150));
    let err = c
        .send(ClientRequest::get(&format!("{base}/slow")))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::Timeout), "{err}");
    let r = c
        .send(ClientRequest::get(&format!("{base}/slow")).timeout(Duration::from_secs(5)))
        .wait();
    assert_eq!(body(r), "late");
    // The timeout covers the redirects too.
    let c = c.with_redirects(RedirectPolicy::limit(3));
    let err = c
        .send(ClientRequest::get(&format!("{base}/to?302&/slow")))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::Timeout), "{err}");
    // A peer that accepts and never answers.
    let mute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", mute.local_addr().unwrap());
    let err = c.send(ClientRequest::get(&url)).wait().unwrap_err();
    assert!(matches!(err, ClientError::Timeout), "{err}");
    // Many at once, each failing on its own.
    let futs: Vec<_> = (0..20)
        .map(|_| c.send(ClientRequest::get(&format!("{base}/slow"))))
        .collect();
    for f in futs {
        assert!(matches!(f.wait(), Err(ClientError::Timeout)));
    }
    drop(mute);
    stop(&e);
}

#[test]
fn h2_requests_time_out_and_the_connection_survives() {
    let (e, _, _) = server();
    let addr = e.local_addrs()[0];
    let h2 = H2Client::dial_blocking(&e, addr, None, H2Options::default()).unwrap();
    let base = format!("http://{addr}");
    let err = h2
        .send(ClientRequest::get(&format!("{base}/slow")).timeout(Duration::from_millis(100)))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::Timeout), "{err}");
    let r = h2
        .send(ClientRequest::get(&format!("{base}/hello")))
        .wait()
        .unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
    assert_eq!(r.url, format!("{base}/hello"));
    assert!(h2.is_open());
    stop(&e);
}

#[test]
fn names_resolve_off_the_calling_thread() {
    let (e, _, _) = server();
    let port = e.local_addrs()[0].port();
    let c = Client::new(e.clone());
    // `localhost` goes through the resolver threads; the callback gets the answer.
    let (tx, rx) = std::sync::mpsc::channel();
    c.request(
        ClientRequest::get(&format!("http://localhost:{port}/hello")),
        move |r| {
            let _ = tx.send(r.map(|r| r.status).ok());
        },
    );
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), Some(200));
    let err = c
        .send(ClientRequest::get("http://no-such-host.invalid/"))
        .wait()
        .unwrap_err();
    assert!(matches!(err, ClientError::Io(_)), "{err}");
    stop(&e);
}

#[test]
fn http_through_a_proxy_uses_the_absolute_form() {
    let (e, base, _) = server();
    let p = proxy::start(Some("Basic dXNlcjpwYXNz")); // user:pass
    let c = Client::new(e.clone())
        .with_proxy(Proxy::all(&format!("http://user:pass@{}", p.addr)).unwrap());
    assert_eq!(
        body(c.send(ClientRequest::get(&format!("{base}/hello"))).wait()),
        "hello"
    );
    // Reused through the same proxy connection.
    assert_eq!(
        body(
            c.send(ClientRequest::post(
                &format!("{base}/inspect"),
                b"abc".to_vec()
            ))
            .wait()
        ),
        "POST 3 ct=false auth=- cookie=-"
    );
    let seen = p.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen[0].starts_with(&format!("GET {base}/hello HTTP/1.1\r\n")),
        "{seen:?}"
    );
    assert!(seen[0].contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    // Wrong credentials: the proxy's 407 is the answer for plain http.
    let bad = Client::new(e.clone())
        .with_proxy(Proxy::all(&format!("http://user:nope@{}", p.addr)).unwrap());
    let r = bad
        .send(ClientRequest::get(&format!("{base}/hello")))
        .wait()
        .unwrap();
    assert_eq!(r.status, 407);
    // NO_PROXY: straight to the server.
    let direct = Client::new(e.clone()).with_proxy(
        Proxy::all(&format!("http://{}", p.addr))
            .unwrap()
            .no_proxy("127.0.0.1"),
    );
    let before = p.seen().len();
    assert_eq!(
        body(
            direct
                .send(ClientRequest::get(&format!("{base}/hello")))
                .wait()
        ),
        "hello"
    );
    assert_eq!(p.seen().len(), before);
    stop(&e);
}

fn tls_server() -> (Arc<Engine>, only::tls::ClientConfig) {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = only::tls::ServerConfig::builder(
        vec![only::tls::Certificate::from_der(cert.clone())],
        only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let e = start(Tls::server(scfg, serve(app(Arc::default()))));
    let mut roots = only::tls::RootCerts::empty();
    roots.add(&only::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = only::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    (e, ccfg)
}

#[test]
fn https_through_a_proxy_uses_connect() {
    let (e, ccfg) = tls_server();
    let port = e.local_addrs()[0].port();
    let p = proxy::start(Some("Basic dXNlcjpwYXNz"));
    let c = Client::new(e.clone()).with_tls(ccfg.clone()).with_proxy(
        Proxy::none()
            .https(&format!("http://user:pass@{}", p.addr))
            .unwrap(),
    );
    let url = format!("https://localhost:{port}/hello");
    assert_eq!(body(c.send(ClientRequest::get(&url)).wait()), "hello");
    // Kept alive inside the tunnel: one CONNECT for two requests.
    assert_eq!(body(c.send(ClientRequest::get(&url)).wait()), "hello");
    let seen = p.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].starts_with(&format!(
            "CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n"
        )),
        "{seen:?}"
    );
    assert!(seen[0].contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    // The proxy refuses the tunnel: an error carrying its status.
    let bad = Client::new(e.clone())
        .with_tls(ccfg)
        .with_proxy(Proxy::all(&format!("http://{}", p.addr)).unwrap());
    let err = bad.send(ClientRequest::get(&url)).wait().unwrap_err();
    let ClientError::Io(io) = &err else {
        panic!("{err}")
    };
    assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
    let refused = io
        .get_ref()
        .unwrap()
        .downcast_ref::<ProxyRefused>()
        .unwrap();
    assert_eq!(refused.status(), 407);
    stop(&e);
}

#[test]
fn https_uses_the_system_roots_by_default() {
    // A self-signed server is not trusted by the system's CAs.
    let (e, _) = tls_server();
    let port = e.local_addrs()[0].port();
    let c = Client::new(e.clone());
    let err = c
        .send(ClientRequest::get(&format!(
            "https://localhost:{port}/hello"
        )))
        .wait()
        .unwrap_err();
    assert!(
        matches!(err, ClientError::Closed | ClientError::Io(_)),
        "{err}"
    );
    stop(&e);
}
