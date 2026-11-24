//! `Files` answering as a gateway's static handler does (ADR-124): index files tried in order,
//! directories redirected to their slash, a file asked for with a slash and what is not a
//! regular file answered 404, 403 for a file that may not be read, Go's content types with a
//! default type or sniffing, answers of the caller's own, listings and redirects under a
//! prefix; and the disk pool's timeout, which answers a request held by a disk that hangs 503.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use akio::{Backend, Config, Engine, Listener, UringConfig};
use akio_http::{
    Context, Response, Router,
    files::{Files, MimeTypes},
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

struct Server {
    engine: Engine,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.engine.shutdown();
        self.engine.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("akio-files-gw-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn start(dir: PathBuf, app: Router) -> Server {
    let engine = Engine::builder()
        .config({
            let mut v = Config::default();
            v.shutdown_timeout = Duration::from_millis(500);
            v
        })
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(backend())
                .threads(2)
                .serve(serve(app)),
        )
        .build()
        .unwrap();
    engine.start().unwrap();
    Server { engine, dir }
}

struct Resp {
    status: u16,
    h: HashMap<String, String>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, n: &str) -> Option<&str> {
        self.h.get(n).map(String::as_str)
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One request on its own connection (`Connection: close`), the whole answer read.
fn request(addr: SocketAddr, method: &str, path: &str) -> Resp {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(
        format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut all = Vec::new();
    s.read_to_end(&mut all).unwrap();
    let end = all.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(all[..end].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let h = lines
        .map(|l| {
            let (k, v) = l.split_once(':').unwrap();
            (k.to_ascii_lowercase(), v.trim().to_owned())
        })
        .collect();
    Resp {
        status,
        h,
        body: all[end + 4..].to_vec(),
    }
}

fn get(addr: SocketAddr, path: &str) -> Resp {
    request(addr, "GET", path)
}

/// fit's short answers: `"404 Not Found\n"`.
fn fit_error(status: u16) -> Response {
    let reason = match status {
        301 => "Moved Permanently",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    Response::with_body(
        status,
        "text/plain; charset=utf-8",
        format!("{status} {reason}\n").into_bytes(),
    )
}

fn write(dir: &Path, rel: &str, data: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

#[test]
fn index_files_redirects_and_trailing_slashes() {
    let dir = scratch("index");
    write(&dir, "a/default.htm", b"second index");
    write(&dir, "b/index.html", b"first index");
    write(&dir, "b/default.htm", b"not this one");
    write(&dir, "c/other.txt", b"no index here");
    write(&dir, "file.txt", b"a file");
    write(&dir, "x:y.txt", b"colon");
    let files = || {
        Files::new(&dir)
            .index_files(&["index.html", "default.htm"])
            .redirect_directories(true)
            .check_interval(Duration::from_secs(60))
            .error_response(fit_error)
    };
    let none = Files::new(&dir).index_files(&[]).error_response(fit_error);
    let app = Router::new()
        .get("/none/*path", none)
        .get("/r/*path", files())
        .fallback(files());
    let s = start(dir, app);
    let addr = s.engine.local_addrs()[0];
    // Twice: from the disk, then from what the cache knows.
    for _ in 0..2 {
        let r = get(addr, "/a/");
        assert_eq!((r.status, r.text().as_str()), (200, "second index"));
        let r = get(addr, "/b/");
        assert_eq!((r.status, r.text().as_str()), (200, "first index"));
        // Without its slash: redirected, the query kept.
        let r = get(addr, "/a?x=1");
        assert_eq!(r.status, 301);
        assert_eq!(r.header("location"), Some("/a/?x=1"));
        assert_eq!(r.text(), "301 Moved Permanently\n");
        // A file asked for as a directory is not there.
        let r = get(addr, "/file.txt/");
        assert_eq!((r.status, r.text().as_str()), (404, "404 Not Found\n"));
        let r = get(addr, "/file.txt");
        assert_eq!((r.status, r.text().as_str()), (200, "a file"));
        // A `:` is a character like others.
        let r = get(addr, "/x:y.txt");
        assert_eq!((r.status, r.text().as_str()), (200, "colon"));
        // No index file and no listing.
        assert_eq!(get(addr, "/c/").status, 404);
    }
    // No index files at all.
    assert_eq!(get(addr, "/none/b/").status, 404);
    assert_eq!(get(addr, "/none/file.txt").status, 200);
    let r = get(addr, "/none/b");
    assert_eq!(r.status, 404, "index_files([]) without redirects: no index");
    // Under a route, the redirect names the whole path.
    let r = get(addr, "/r/a");
    assert_eq!(r.status, 301);
    assert_eq!(r.header("location"), Some("/r/a/"));
    assert_eq!(get(addr, "/r/a/").text(), "second index");
    let r = request(addr, "POST", "/a/");
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some("GET, HEAD"));
    assert_eq!(r.text(), "405 Method Not Allowed\n");
}

#[test]
fn prefixed_listings_and_redirects_name_the_whole_path() {
    let dir = scratch("prefix");
    write(&dir, "sub/one.txt", b"1");
    let files = Arc::new(
        Files::new(&dir)
            .redirect_directories(true)
            .list_directories(100),
    );
    let f2 = files.clone();
    let app = Router::new()
        .get("/assets/*rest", move |ctx: &mut Context| {
            let rest = ctx.path().strip_prefix("/assets").unwrap_or("").to_owned();
            f2.serve_prefixed(ctx, "/assets", &rest);
        })
        .get("/assets", move |ctx: &mut Context| {
            files.serve_prefixed(ctx, "/assets", "");
        });
    let s = start(dir, app);
    let addr = s.engine.local_addrs()[0];
    let r = get(addr, "/assets/sub/");
    assert_eq!(r.status, 200);
    let page = r.text();
    assert!(
        page.contains("<title>Index of /assets/sub/</title>"),
        "{page}"
    );
    assert!(page.contains("href=\"../\""), "{page}");
    assert!(page.contains("one.txt"), "{page}");
    let r = get(addr, "/assets/");
    assert!(r.text().contains("Index of /assets/"), "{}", r.text());
    assert!(r.text().contains("href=\"../\""));
    let r = get(addr, "/assets/sub?q=2");
    assert_eq!(r.status, 301);
    assert_eq!(r.header("location"), Some("/assets/sub/?q=2"));
    // The prefix alone is the root, a directory: served as asked.
    assert_eq!(get(addr, "/assets").status, 200);
}

#[test]
fn content_types_default_type_and_sniffing() {
    let dir = scratch("types");
    write(&dir, "a.xml", b"<a/>");
    write(&dir, "a.avif", b"\0\0");
    write(&dir, "page", b"<!DOCTYPE html><p>hi</p>");
    write(&dir, "blob", b"\x01\x02\x03");
    write(
        &dir,
        "big-page",
        &[b"<html><body>".as_slice(), &[b' '; 4096]].concat(),
    );
    let sniffing = Files::new(&dir)
        .mime_types(Arc::new(MimeTypes::builtin()))
        .sniff(true)
        .max_cached_bytes(1024);
    let defaulted = Files::new(&dir)
        .mime_types(Arc::new(MimeTypes::builtin()))
        .default_type(Some("application/x-default"))
        .sniff(true);
    let app = Router::new().get("/d/*path", defaulted).fallback(sniffing);
    let s = start(dir, app);
    let addr = s.engine.local_addrs()[0];
    let ct = |p: &str| get(addr, p).header("content-type").map(str::to_owned);
    assert_eq!(ct("/a.xml").as_deref(), Some("text/xml; charset=utf-8"));
    assert_eq!(ct("/a.avif").as_deref(), Some("image/avif"));
    assert_eq!(ct("/page").as_deref(), Some("text/html; charset=utf-8"));
    assert_eq!(ct("/blob").as_deref(), Some("application/octet-stream"));
    // Sent from disk (above max_cached_bytes): sniffed from its first bytes too.
    assert_eq!(ct("/big-page").as_deref(), Some("text/html; charset=utf-8"));
    assert_eq!(ct("/d/page").as_deref(), Some("application/x-default"));
    assert_eq!(ct("/d/a.xml").as_deref(), Some("text/xml; charset=utf-8"));
}

#[test]
fn unreadable_files_and_what_is_not_a_regular_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("perm");
    write(&dir, "secret.txt", b"secret");
    let secret = dir.join("secret.txt");
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o000)).unwrap();
    // A FIFO: opening it would wait for a writer.
    let fifo = dir.join("pipe");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .is_ok_and(|s| s.success());
    let app = Router::new().fallback(
        Files::new(&dir)
            .check_interval(Duration::ZERO)
            .error_response(fit_error),
    );
    let s = start(dir, app);
    let addr = s.engine.local_addrs()[0];
    // root reads any file: only a user who may not gets 403.
    if std::fs::read(&secret).is_err() {
        let r = get(addr, "/secret.txt");
        assert_eq!((r.status, r.text().as_str()), (403, "403 Forbidden\n"));
    }
    if made {
        let t = Instant::now();
        for _ in 0..20 {
            assert_eq!(get(addr, "/pipe").status, 404);
        }
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn a_disk_that_hangs_is_answered_503_after_the_timeout() {
    let dir = scratch("timeout");
    write(&dir, "ok.txt", b"fine");
    // `hide` runs on the disk pool for `try_paths` candidates: one that sleeps stands for a
    // disk that hangs.
    let files = Files::new(&dir)
        .try_paths(&["{path}", "/hang"])
        .hide(|p| {
            if p == "/hang" {
                std::thread::sleep(Duration::from_secs(3));
            }
            false
        })
        .disk_timeout(Some(Duration::from_millis(300)))
        .error_response(fit_error);
    let s = start(dir, Router::new().fallback(files));
    let addr = s.engine.local_addrs()[0];
    let t = Instant::now();
    let r = get(addr, "/missing");
    let took = t.elapsed();
    assert_eq!(r.status, 503, "{}", r.text());
    assert_eq!(r.header("retry-after"), Some("1"));
    assert_eq!(r.text(), "503 Service Unavailable\n");
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_millis(2500),
        "{took:?}"
    );
    // A request the pool answers in time is served as ever.
    let r = get(addr, "/ok.txt");
    assert_eq!((r.status, r.text().as_str()), (200, "fine"));
    // Let the sleeping job end before the server goes.
    std::thread::sleep(Duration::from_secs(3));
}
