//! HTTP client features of ADR-010: redirects (chains, loops, method rules, cross-origin header
//! stripping), per-request timeouts (HTTP/1 and HTTP/2), proxies (absolute form, `CONNECT`,
//! authentication, refusal, `NO_PROXY`), name resolution off the calling thread; ADR-059: the
//! cookie jar across redirect chains, `https://` proxies (TLS to the proxy).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

#[path = "support/proxy.rs"]
mod proxy;
#[path = "support/tls_front.rs"]
mod tls_front;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig, tls::Tls};
use akio_http::{
    Context, Response, Router,
    client::{Client, ClientError, ClientRequest, Proxy, ProxyRefused, RedirectPolicy},
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

fn start(acceptor: impl akio::Acceptor) -> Arc<Engine> {
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
            "/host" => {
                let r = format!(
                    "{} ua={}",
                    ctx.header("host").unwrap_or("-"),
                    ctx.header("user-agent").unwrap_or("-"),
                );
                ctx.text(200, r);
            }
            "/cookie/set" => {
                // `/cookie/set?<location>`: sets cookies, then redirects there.
                let mut r = Response::new(302).header("Location", &query);
                for c in [
                    "a=1; Path=/",
                    "strict=1; SameSite=Strict; Path=/",
                    "lax=1; SameSite=Lax; Path=/",
                    "dom=1; Domain=127.0.0.1; Path=/",
                    "bad=1; Domain=0.0.1; Path=/",
                    "sec=1; Secure; Path=/",
                    "deep=1; Path=/elsewhere",
                ] {
                    r.headers.append("Set-Cookie", c);
                }
                ctx.respond(r);
            }
            "/cookie/clear" => {
                let mut r = Response::text(200, "cleared");
                r.headers.append("Set-Cookie", "a=; Max-Age=0; Path=/");
                ctx.respond(r);
            }
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

fn body(r: Result<akio_http::client::ClientResponse, ClientError>) -> String {
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
    let go = |method: akio_http::Method, status: u16| {
        let req = ClientRequest::new(method, &format!("{base}/to?{status}&/inspect"))
            .body(b"payload".to_vec())
            .header("Content-Type", "text/plain");
        body(c.send(req).wait())
    };
    use akio_http::Method::{Delete, Get, Head, Post, Put};
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

/// A11: a request's own `Host` field is sent in place of the URL's, kept on a redirect to the
/// same origin and dropped on one to another; an empty `User-Agent` sends none.
#[test]
fn a_request_keeps_its_own_host_and_user_agent() {
    let (a, base_a, _) = server();
    let (b, base_b, _) = server();
    let host_a = base_a.trim_start_matches("http://").to_owned();
    let host_b = base_b.trim_start_matches("http://").to_owned();
    let c = Client::new(a.clone()).with_redirects(RedirectPolicy::limit(3));
    let get = |url: &str| ClientRequest::get(url);
    // No `Host` field: the URL's, and the default `User-Agent`.
    assert_eq!(
        body(c.send(get(&format!("{base_a}/host"))).wait()),
        format!("{host_a} ua=akio-http")
    );
    // The request's own, whatever its case; an empty one is not a host.
    let own = get(&format!("{base_a}/host")).header("host", "app.example:8080");
    assert_eq!(body(c.send(own).wait()), "app.example:8080 ua=akio-http");
    let empty = get(&format!("{base_a}/host")).header("Host", "");
    assert_eq!(body(c.send(empty).wait()), format!("{host_a} ua=akio-http"));
    // A `User-Agent` of the request's own, and an empty one, which sends none.
    let ua = get(&format!("{base_a}/host")).header("User-Agent", "curl/8");
    assert_eq!(body(c.send(ua).wait()), format!("{host_a} ua=curl/8"));
    let none = get(&format!("{base_a}/host")).header("User-Agent", "");
    assert_eq!(body(c.send(none).wait()), format!("{host_a} ua=-"));
    // A redirect to the same origin keeps the request's `Host`; one to another drops it.
    let same = get(&format!("{base_a}/to?302&/host")).header("Host", "app.example");
    assert_eq!(body(c.send(same).wait()), "app.example ua=akio-http");
    let other = get(&format!("{base_a}/to?302&{base_b}/host")).header("Host", "app.example");
    assert_eq!(body(c.send(other).wait()), format!("{host_b} ua=akio-http"));
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
fn h2_connect_resolves_and_races_a_name() {
    let (e, _, _) = server();
    let port = e.local_addrs()[0].port();
    // `localhost` may list ::1 first, where nothing listens: the race moves on to 127.0.0.1.
    let (tx, rx) = std::sync::mpsc::channel();
    H2Client::connect(
        &e,
        "localhost",
        port,
        None,
        H2Options::default(),
        move |r| {
            let _ = tx.send(r);
        },
    );
    let h2 = rx.recv_timeout(Duration::from_secs(10)).unwrap().unwrap();
    let r = h2
        .send(ClientRequest::get(&format!(
            "http://localhost:{port}/hello"
        )))
        .wait()
        .unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
    // A name that does not resolve: the error.
    let (tx, rx) = std::sync::mpsc::channel();
    H2Client::connect(
        &e,
        "no-such-host.invalid",
        port,
        None,
        H2Options::default(),
        move |r| {
            let _ = tx.send(r.map(|_| ()));
        },
    );
    assert!(rx.recv_timeout(Duration::from_secs(30)).unwrap().is_err());
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

fn tls_server() -> (Arc<Engine>, akio::tls::ClientConfig) {
    let (e, c, _) = tls_parts();
    (e, c)
}

/// An https server for `localhost`, a client config trusting it, and the server config.
fn tls_parts() -> (
    Arc<Engine>,
    akio::tls::ClientConfig,
    akio::tls::ServerConfig,
) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = ck.0.as_der().to_vec();
    let scfg = akio::tls::ServerConfig::builder(
        vec![akio::tls::Certificate::from_der(cert.clone())],
        akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
    )
    .build()
    .unwrap();
    let e = start(Tls::server(scfg.clone(), serve(app(Arc::default()))));
    let mut roots = akio::tls::RootCerts::empty();
    roots.add(&akio::tls::Certificate::from_der(cert)).unwrap();
    let ccfg = akio::tls::ClientConfig::builder()
        .roots(roots)
        .build()
        .unwrap();
    (e, ccfg, scfg)
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

#[test]
fn cookies_follow_the_jar_rules_across_redirects() {
    use akio_http::cookie::CookieJar;
    let (e, base, _) = server();
    let port = e.local_addrs()[0].port();
    let jar = CookieJar::new();
    let c = Client::new(e.clone())
        .with_redirects(RedirectPolicy::limit(5))
        .with_cookies(jar.clone());
    // Set mid-chain, sent on the next hop of the same chain; `bad` (another domain), `sec`
    // (Secure over http) and `deep` (another path) are not.
    let r = c
        .send(ClientRequest::get(&format!("{base}/cookie/set?/inspect")))
        .wait();
    assert_eq!(
        body(r),
        "GET 0 ct=false auth=- cookie=a=1; strict=1; lax=1; dom=1"
    );
    let names: Vec<String> = jar.cookies().into_iter().map(|c| c.name).collect();
    assert_eq!(names, ["a", "strict", "lax", "dom", "deep"]);
    // A chain that starts on another site (localhost) and lands on 127.0.0.1: no Strict
    // cookies; Lax ones only for a safe method.
    let cross = format!("http://localhost:{port}/to?302&http://127.0.0.1:{port}/inspect");
    assert_eq!(
        body(c.send(ClientRequest::get(&cross)).wait()),
        "GET 0 ct=false auth=- cookie=a=1; lax=1; dom=1"
    );
    let cross_post = format!("http://localhost:{port}/to?307&http://127.0.0.1:{port}/inspect");
    assert_eq!(
        body(
            c.send(ClientRequest::post(&cross_post, b"x".to_vec()))
                .wait()
        ),
        "POST 1 ct=false auth=- cookie=a=1; dom=1"
    );
    // Host-only cookies of 127.0.0.1 do not go to localhost.
    assert_eq!(
        body(
            c.send(ClientRequest::get(&format!(
                "http://localhost:{port}/inspect"
            )))
            .wait()
        ),
        "GET 0 ct=false auth=- cookie=-"
    );
    // A request's own Cookie field comes first, in the same field.
    let r = c
        .send(ClientRequest::get(&format!("{base}/inspect")).header("Cookie", "mine=1"))
        .wait();
    assert_eq!(
        body(r),
        "GET 0 ct=false auth=- cookie=mine=1; a=1; strict=1; lax=1; dom=1"
    );
    // Max-Age=0 deletes.
    assert_eq!(
        body(
            c.send(ClientRequest::get(&format!("{base}/cookie/clear")))
                .wait()
        ),
        "cleared"
    );
    assert_eq!(
        body(
            c.send(ClientRequest::get(&format!("{base}/inspect")))
                .wait()
        ),
        "GET 0 ct=false auth=- cookie=strict=1; lax=1; dom=1"
    );
    // Without a jar nothing is stored or sent.
    let plain = Client::new(e.clone()).with_redirects(RedirectPolicy::limit(5));
    assert!(plain.cookies().is_none());
    assert_eq!(
        body(
            plain
                .send(ClientRequest::get(&format!("{base}/cookie/set?/inspect")))
                .wait()
        ),
        "GET 0 ct=false auth=- cookie=-"
    );
    stop(&e);
}

#[test]
fn through_an_https_proxy() {
    let (e, ccfg, scfg) = tls_parts();
    let tls_port = e.local_addrs()[0].port();
    let (pe, base, _) = server();
    let p = proxy::start(Some("Basic dXNlcjpwYXNz"));
    let (fe, front, opened) = tls_front::start(scfg, p.addr);
    let c = Client::new(e.clone())
        .with_tls(ccfg.clone())
        .with_proxy(Proxy::all(&format!("https://user:pass@localhost:{}", front.port())).unwrap());
    // https://: CONNECT inside TLS to the proxy, TLS to the target inside the tunnel.
    let url = format!("https://localhost:{tls_port}/hello");
    assert_eq!(body(c.send(ClientRequest::get(&url)).wait()), "hello");
    assert_eq!(body(c.send(ClientRequest::get(&url)).wait()), "hello");
    // http://: absolute form over TLS to the proxy.
    let plain = format!("{base}/hello");
    assert_eq!(body(c.send(ClientRequest::get(&plain)).wait()), "hello");
    let seen = p.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(seen[0].starts_with(&format!("CONNECT localhost:{tls_port} HTTP/1.1\r\n")));
    assert!(seen[0].contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    assert!(
        seen[1].starts_with(&format!("GET {plain} HTTP/1.1\r\n")),
        "{seen:?}"
    );
    assert!(seen[1].contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    assert_eq!(opened.load(Ordering::SeqCst), 2);
    // The proxy's certificate is checked against its name.
    let wrong = Client::new(e.clone())
        .with_tls(ccfg)
        .with_proxy(Proxy::all(&format!("https://user:pass@127.0.0.1:{}", front.port())).unwrap());
    assert!(wrong.send(ClientRequest::get(&url)).wait().is_err());
    assert!(wrong.send(ClientRequest::get(&plain)).wait().is_err());
    assert_eq!(p.seen().len(), 2, "nothing reached the proxy");
    stop(&fe);
    stop(&pe);
    stop(&e);
}
