//! Micro benchmarks of the in-house HTTP codecs against the crates they replaced:
//! the HTTP/1 head parser (`only_ws::http1` vs httparse), HPACK (`only_http::hpack` vs
//! loona-hpack) and the route constraint regexp engine (`only_http::re` vs regex).
//!
//! `cargo run --release --manifest-path tools/codec-bench/Cargo.toml [http1|hpack|regex]`

use std::hint::black_box;
use std::time::Instant;

/// Runs `f` `iters` times (after a warm-up) and returns ns per call (best of 5 rounds).
fn ns(iters: u32, mut f: impl FnMut()) -> f64 {
    for _ in 0..iters / 10 {
        f();
    }
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        best = best.min(t.elapsed().as_nanos() as f64 / f64::from(iters));
    }
    best
}

fn row(what: &str, ours: f64, theirs: f64, name: &str) {
    println!(
        "{what:<44} only {ours:>8.1} ns   {name} {theirs:>8.1} ns   ratio {:>5.2}",
        ours / theirs
    );
}

const SMALL: &[u8] = b"GET /plaintext HTTP/1.1\r\nHost: localhost:8080\r\n\r\n";
const BROWSER: &[u8] = b"GET /api/v1/users/12345/repos?page=2&per_page=50 HTTP/1.1\r\n\
Host: www.example.com\r\n\
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8\r\n\
Accept-Encoding: gzip, deflate, br\r\n\
Referer: https://www.example.com/some/where/else\r\n\
Cookie: session=0123456789abcdef0123456789abcdef; theme=dark; _ga=GA1.2.1234567890.1234567890\r\n\
Connection: keep-alive\r\n\
Cache-Control: max-age=0\r\n\
Upgrade-Insecure-Requests: 1\r\n\
\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
Server: only\r\n\
Date: Sat, 14 Nov 2026 12:00:00 GMT\r\n\
Content-Type: application/json; charset=utf-8\r\n\
Content-Length: 1234\r\n\
Cache-Control: no-cache, no-store, must-revalidate\r\n\
Vary: Accept-Encoding\r\n\
X-Request-Id: 0f8fad5b-d9cb-469f-a165-70867728950e\r\n\
\r\n";

fn http1() {
    use only_ws::http1::{Header, Resume, Status, parse_request, parse_response};
    println!("HTTP/1 heads (whole head in one buffer, 100 header slots)");
    for (what, wire) in [
        ("request, 1 header", SMALL),
        ("request, browser-like, 11 headers", BROWSER),
    ] {
        let ours = ns(2_000_000, || {
            let mut h = [Header::EMPTY; 100];
            let r = parse_request(black_box(wire), &mut h, &mut Resume::default());
            assert!(matches!(r, Ok(Status::Complete(_))));
            black_box(&r);
        });
        let theirs = ns(2_000_000, || {
            let mut h = [httparse::EMPTY_HEADER; 100];
            let mut req = httparse::Request::new(&mut h);
            let r = req.parse(black_box(wire));
            assert!(matches!(r, Ok(httparse::Status::Complete(_))));
            black_box(&req);
        });
        row(what, ours, theirs, "httparse");
    }
    let ours = ns(2_000_000, || {
        let mut h = [Header::EMPTY; 100];
        let r = parse_response(black_box(RESPONSE), &mut h, &mut Resume::default());
        assert!(matches!(r, Ok(Status::Complete(_))));
        black_box(&r);
    });
    let theirs = ns(2_000_000, || {
        let mut h = [httparse::EMPTY_HEADER; 100];
        let mut resp = httparse::Response::new(&mut h);
        let r = resp.parse(black_box(RESPONSE));
        assert!(matches!(r, Ok(httparse::Status::Complete(_))));
        black_box(&resp);
    });
    row("response, 7 headers", ours, theirs, "httparse");
    // A head arriving 16 bytes at a time: resumed parsing vs parsing again from the start.
    let ours = ns(100_000, || {
        let mut resume = Resume::default();
        for end in (16..BROWSER.len()).step_by(16).chain([BROWSER.len()]) {
            let mut h = [Header::EMPTY; 100];
            let r = parse_request(black_box(&BROWSER[..end]), &mut h, &mut resume);
            black_box(&r);
        }
    });
    let theirs = ns(100_000, || {
        for end in (16..BROWSER.len()).step_by(16).chain([BROWSER.len()]) {
            let mut h = [httparse::EMPTY_HEADER; 100];
            let mut req = httparse::Request::new(&mut h);
            let r = req.parse(black_box(&BROWSER[..end]));
            black_box(&r);
        }
    });
    row(
        "browser-like request in 16-byte reads",
        ours,
        theirs,
        "httparse",
    );
}

type Fields = Vec<(&'static [u8], &'static [u8])>;

fn h2_request() -> Fields {
    vec![
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"www.example.com"),
        (b":path", b"/api/v1/users/12345/repos?page=2&per_page=50"),
        (b"user-agent", b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
        (b"accept", b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        (b"accept-language", b"en-US,en;q=0.9,zh-CN;q=0.8"),
        (b"accept-encoding", b"gzip, deflate, br"),
        (b"cookie", b"session=0123456789abcdef0123456789abcdef; theme=dark"),
    ]
}

fn h2_response() -> Fields {
    vec![
        (b":status", b"200"),
        (b"server", b"only"),
        (b"date", b"Sat, 14 Nov 2026 12:00:00 GMT"),
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", b"1234"),
    ]
}

fn hpack() {
    use only_http::hpack::{Decoder, Encoder};
    println!("HPACK");
    // First block on a fresh connection (all literals), then the same block again (indexed).
    for (what, fields, huffman) in [
        ("decode request, first block, Huffman", h2_request(), true),
        ("decode request, first block, raw", h2_request(), false),
        ("decode response, first block, Huffman", h2_response(), true),
    ] {
        let mut e = Encoder::new();
        e.set_huffman(huffman);
        let block = e.encode(fields.iter().copied());
        let ours = ns(200_000, || {
            let mut d = Decoder::new();
            black_box(d.decode(black_box(&block)).unwrap());
        });
        let theirs = ns(200_000, || {
            let mut d = loona_hpack::Decoder::new();
            black_box(d.decode(black_box(&block)).unwrap());
        });
        row(what, ours, theirs, "loona-hpack");
    }
    // Steady state: the fields are in the dynamic table, the block is all indexes.
    let mut e = Encoder::new();
    let first = e.encode(h2_request().iter().copied());
    let again = e.encode(h2_request().iter().copied());
    let mut ours_d = Decoder::new();
    ours_d.decode(&first).unwrap();
    let mut theirs_d = loona_hpack::Decoder::new();
    theirs_d.decode(&first).unwrap();
    let ours = ns(1_000_000, || {
        black_box(ours_d.decode(black_box(&again)).unwrap());
    });
    let theirs = ns(1_000_000, || {
        black_box(theirs_d.decode(black_box(&again)).unwrap());
    });
    row(
        "decode request, indexed (steady state)",
        ours,
        theirs,
        "loona-hpack",
    );
    // Encoding a response on a warm connection (what the server does per request).
    let mut ours_e = Encoder::new();
    let mut theirs_e = loona_hpack::Encoder::new();
    let resp = h2_response();
    ours_e.encode(resp.iter().copied());
    theirs_e.encode(resp.iter().copied());
    let ours = ns(1_000_000, || {
        black_box(ours_e.encode(black_box(&resp).iter().copied()));
    });
    let theirs = ns(1_000_000, || {
        black_box(theirs_e.encode(black_box(&resp).iter().copied()));
    });
    row("encode response, warm table", ours, theirs, "loona-hpack");
    let ours = ns(200_000, || {
        let mut e = Encoder::new();
        black_box(e.encode(black_box(&resp).iter().copied()));
    });
    let theirs = ns(200_000, || {
        let mut e = loona_hpack::Encoder::new();
        black_box(e.encode(black_box(&resp).iter().copied()));
    });
    row(
        "encode response, fresh table (only: Huffman)",
        ours,
        theirs,
        "loona-hpack",
    );
}

fn regexp() {
    println!("Route constraint regexps (whole-segment match)");
    for (pattern, subject) in [
        ("[0-9]+", "1234567"),
        ("\\d{4}-\\d{2}-\\d{2}", "2026-11-14"),
        ("[a-z0-9_-]{3,16}", "only-http_user"),
        ("(?:v[0-9]+|latest)", "latest"),
        ("[0-9]+", "12345x"),
    ] {
        let ours_re = only_http::re::Regex::new(pattern).unwrap();
        let theirs_re = regex::Regex::new(&format!("^(?:{pattern})$")).unwrap();
        assert_eq!(ours_re.is_match(subject), theirs_re.is_match(subject));
        let ours = ns(2_000_000, || {
            black_box(ours_re.is_match(black_box(subject)));
        });
        let theirs = ns(2_000_000, || {
            black_box(theirs_re.is_match(black_box(subject)));
        });
        row(&format!("{pattern} on {subject:?}"), ours, theirs, "regex");
    }
    let ours = ns(20_000, || {
        black_box(only_http::re::Regex::new(black_box("\\d{4}-\\d{2}-\\d{2}")).unwrap());
    });
    let theirs = ns(20_000, || {
        black_box(regex::Regex::new(black_box("^(?:\\d{4}-\\d{2}-\\d{2})$")).unwrap());
    });
    row("compile \\d{4}-\\d{2}-\\d{2}", ours, theirs, "regex");
}

fn main() {
    // Optional filter: `http1`, `hpack`, `regex`.
    let only = std::env::args().nth(1).unwrap_or_default();
    if only.is_empty() || only == "http1" {
        http1();
    }
    if only.is_empty() || only == "hpack" {
        hpack();
    }
    if only.is_empty() || only == "regex" {
        regexp();
    }
}
