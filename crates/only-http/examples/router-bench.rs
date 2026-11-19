//! Router micro benchmark: ns per lookup and heap allocations per lookup on a GitHub-API-style
//! route table, for the current router and for the previous algorithm (kept below as `old`, the
//! segment tree that collected a `Vec<&str>` of segments and `(String, String)` parameters).
//!
//! `cargo run --release -p only-http --example router-bench`
#![allow(missing_docs)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use only_http::{Context, Method, Router};

/// Counts every allocation (and reallocation) made by the process.
struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts calls.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// 52 routes in the style of the GitHub v3 API (the table popularised by Go router benchmarks).
const ROUTES: &[(&str, &str)] = &[
    ("GET", "/authorizations"),
    ("GET", "/authorizations/:id"),
    ("POST", "/authorizations"),
    ("DELETE", "/authorizations/:id"),
    ("GET", "/applications/:client_id/tokens/:access_token"),
    ("DELETE", "/applications/:client_id/tokens"),
    ("GET", "/events"),
    ("GET", "/repos/:owner/:repo/events"),
    ("GET", "/networks/:owner/:repo/events"),
    ("GET", "/orgs/:org/events"),
    ("GET", "/users/:user/received_events"),
    ("GET", "/users/:user/received_events/public"),
    ("GET", "/users/:user/events"),
    ("GET", "/users/:user/events/public"),
    ("GET", "/users/:user/events/orgs/:org"),
    ("GET", "/feeds"),
    ("GET", "/notifications"),
    ("GET", "/repos/:owner/:repo/notifications"),
    ("PUT", "/notifications"),
    ("GET", "/notifications/threads/:id"),
    ("GET", "/notifications/threads/:id/subscription"),
    ("GET", "/repos/:owner/:repo/stargazers"),
    ("GET", "/users/:user/starred"),
    ("GET", "/user/starred"),
    ("GET", "/user/starred/:owner/:repo"),
    ("PUT", "/user/starred/:owner/:repo"),
    ("GET", "/users/:user/gists"),
    ("GET", "/gists"),
    ("GET", "/gists/:id"),
    ("POST", "/gists"),
    ("GET", "/repos/:owner/:repo/git/blobs/:sha"),
    ("POST", "/repos/:owner/:repo/git/blobs"),
    ("GET", "/repos/:owner/:repo/git/commits/:sha"),
    ("GET", "/repos/:owner/:repo/git/refs"),
    ("GET", "/repos/:owner/:repo/git/tags/:sha"),
    ("GET", "/repos/:owner/:repo/git/trees/:sha"),
    ("GET", "/issues"),
    ("GET", "/user/issues"),
    ("GET", "/orgs/:org/issues"),
    ("GET", "/repos/:owner/:repo/issues"),
    ("GET", "/repos/:owner/:repo/issues/:number"),
    ("POST", "/repos/:owner/:repo/issues"),
    ("GET", "/repos/:owner/:repo/assignees"),
    ("GET", "/repos/:owner/:repo/issues/:number/comments"),
    ("GET", "/repos/:owner/:repo/pulls/:number/files"),
    ("GET", "/search/repositories"),
    ("GET", "/search/code"),
    ("GET", "/users/:user"),
    ("GET", "/user"),
    ("GET", "/users"),
    ("GET", "/emojis"),
    ("GET", "/repos/:owner/:repo/contents/*path"),
];

/// Routes with varied regexp constraints, and a request each matches.
const VARIED: &[(&str, &str)] = &[
    (
        "/repos/{owner:[a-z0-9_-]{1,39}}/{repo:[A-Za-z0-9_.-]+}/commits/{sha:[0-9a-f]{7,40}}",
        "/repos/lesser-known_org/only.rs/commits/436b47e7c0ffee",
    ),
    (
        "/reports/{date:\\d{4}-\\d{2}-\\d{2}}",
        "/reports/2026-11-19",
    ),
    ("/users/{id:[0-9]+}", "/users/1234567"),
    ("/users/{name:[a-z][a-z0-9_]{2,15}}", "/users/octocat_42"),
    (
        "/files/{name:[a-z0-9_-]+\\.(?:png|jpe?g|gif)}",
        "/files/holiday-photo.jpeg",
    ),
    ("/v{major:[0-9]+}.{minor:[0-9]+}/status", "/v12.345/status"),
    (
        "/items/{id:[0-9]+}/tags/{tag:\\w+}",
        "/items/42/tags/new_arrival",
    ),
    ("/hex/{v:0x[0-9a-fA-F]+}", "/hex/0xDEADbeef"),
];

/// A concrete request path for a pattern.
fn concrete(pattern: &str) -> String {
    pattern
        .split('/')
        .map(|s| match s.as_bytes().first() {
            Some(b':') => format!("v{}", s.len()),
            Some(b'*') => "src/lib/deep/file.rs".to_owned(),
            _ => s.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn measure(name: &str, iters: u64, f: impl FnMut() -> usize) {
    measure_n(name, iters, ROUTES.len() as u64, f);
}

/// `per` lookups per call of `f`.
fn measure_n(name: &str, iters: u64, per: u64, mut f: impl FnMut() -> usize) {
    // Warm up (regex caches, branch predictors).
    for _ in 0..iters / 10 {
        black_box(f());
    }
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let t = Instant::now();
    let mut found = 0;
    for _ in 0..iters {
        found += f();
    }
    let el = t.elapsed();
    let allocs = ALLOCS.load(Ordering::Relaxed) - a0;
    let lookups = iters * per;
    println!(
        "{name:<28} {:>7.1} ns/lookup  {:>6.2} allocs/lookup  ({found} matches)",
        el.as_nanos() as f64 / lookups as f64,
        allocs as f64 / lookups as f64,
    );
}

fn main() {
    let iters: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    let nop = |_: &mut Context| {};
    let mut router = Router::new();
    let mut old = old::Router::default();
    for (m, p) in ROUTES {
        router = router.route(Method::parse(m), p, nop);
        old.insert(Method::parse(m), p);
    }
    let reqs: Vec<(Method, String)> = ROUTES
        .iter()
        .map(|(m, p)| (Method::parse(m), concrete(p)))
        .collect();
    for (m, p) in &reqs {
        assert!(router.lookup(m, p).is_some(), "{p}");
        assert!(old.lookup(m, p).is_some(), "{p}");
    }
    println!(
        "{} routes, {} lookups per round, {iters} rounds",
        ROUTES.len(),
        reqs.len()
    );
    measure("old (Vec + Strings)", iters, || {
        reqs.iter()
            .filter(|(m, p)| black_box(old.lookup(m, p)).is_some())
            .count()
    });
    measure("new Router::lookup", iters, || {
        reqs.iter()
            .filter(|(m, p)| {
                // Touch a parameter so the work is not optimised away.
                black_box(router.lookup(m, p).map(|r| r.params().count())).is_some()
            })
            .count()
    });

    // Regexp parameters in place of plain ones (the same table with `{id:[0-9]+}`-style
    // segments where the value is numeric).
    let mut re_router = Router::new();
    for (m, p) in ROUTES {
        let p = p
            .replace(":number", "{number:[0-9]+}")
            .replace(":id", "{id:[0-9]+}");
        re_router = re_router.route(Method::parse(m), &p, nop);
    }
    let re_reqs: Vec<(Method, String)> = reqs
        .iter()
        .map(|(m, p)| (m.clone(), p.replace("/v3", "/123").replace("/v7", "/4567")))
        .collect();
    for (m, p) in &re_reqs {
        assert!(re_router.lookup(m, p).is_some(), "{p}");
    }
    measure("new, with regexp params", iters, || {
        re_reqs
            .iter()
            .filter(|(m, p)| {
                black_box(re_router.lookup(m, p).map(|r| r.params().count())).is_some()
            })
            .count()
    });

    // Varied regexp constraints (counted repetition, alternation, classes, partial segments),
    // each request a match that the constraint has to check character by character.
    let mut vre_router = Router::new();
    for (p, _) in VARIED {
        vre_router = vre_router.get(p, nop);
    }
    for (p, req) in VARIED {
        assert!(vre_router.lookup(&Method::Get, req).is_some(), "{p}: {req}");
    }
    measure_n(
        "new, varied regexp params",
        iters,
        VARIED.len() as u64,
        || {
            VARIED
                .iter()
                .filter(|(_, req)| {
                    black_box(
                        vre_router
                            .lookup(&Method::Get, req)
                            .map(|r| r.params().count()),
                    )
                    .is_some()
                })
                .count()
        },
    );

    // Partial segments: `{number}.json`, `{sha}.diff` and `v{id}` in place of plain parameters.
    let mut part_router = Router::new();
    for (m, p) in ROUTES {
        let p = p
            .replace(":number", "{number}.json")
            .replace(":sha", "{sha}.diff")
            .replace(":id", "v{id}");
        part_router = part_router.route(Method::parse(m), &p, nop);
    }
    let part_reqs: Vec<(Method, String)> = ROUTES
        .iter()
        .map(|(m, p)| {
            let p = concrete(
                &p.replace(":number", "N.json")
                    .replace(":sha", "S.diff")
                    .replace(":id", "v7"),
            );
            (Method::parse(m), p)
        })
        .collect();
    for (m, p) in &part_reqs {
        assert!(part_router.lookup(m, p).is_some(), "{p}");
    }
    measure("new, with partial segments", iters, || {
        part_reqs
            .iter()
            .filter(|(m, p)| {
                black_box(part_router.lookup(m, p).map(|r| r.params().count())).is_some()
            })
            .count()
    });
}

/// The previous router's lookup, reproduced for comparison.
mod old {
    use only_http::Method;

    #[derive(Default)]
    struct Node {
        statics: Vec<(String, Node)>,
        param: Option<(String, Box<Node>)>,
        wild: Option<(String, Vec<Method>)>,
        routes: Vec<Method>,
    }

    #[derive(Default)]
    pub(crate) struct Router {
        root: Node,
    }

    impl Router {
        pub(crate) fn insert(&mut self, method: Method, path: &str) {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            let mut node = &mut self.root;
            for seg in &segs {
                if let Some(name) = seg.strip_prefix('*') {
                    node.wild
                        .get_or_insert_with(|| (name.to_owned(), Vec::new()))
                        .1
                        .push(method);
                    return;
                }
                if let Some(name) = seg.strip_prefix(':') {
                    node = &mut node
                        .param
                        .get_or_insert_with(|| (name.to_owned(), Box::default()))
                        .1;
                } else {
                    let at = match node.statics.iter().position(|(s, _)| s == seg) {
                        Some(at) => at,
                        None => {
                            node.statics.push(((*seg).to_owned(), Node::default()));
                            node.statics.len() - 1
                        }
                    };
                    node = &mut node.statics[at].1;
                }
            }
            node.routes.push(method);
        }

        fn find<'a>(
            node: &'a Node,
            segs: &[&str],
            params: &mut Vec<(String, String)>,
        ) -> Option<&'a [Method]> {
            let Some((first, rest)) = segs.split_first() else {
                if !node.routes.is_empty() {
                    return Some(&node.routes);
                }
                return node.wild.as_ref().map(|(name, routes)| {
                    params.push((name.clone(), String::new()));
                    routes.as_slice()
                });
            };
            if let Some((_, child)) = node.statics.iter().find(|(s, _)| s == first) {
                let mark = params.len();
                if let Some(r) = Self::find(child, rest, params) {
                    return Some(r);
                }
                params.truncate(mark);
            }
            if let Some((name, child)) = &node.param {
                let mark = params.len();
                params.push((name.clone(), (*first).to_owned()));
                if let Some(r) = Self::find(child, rest, params) {
                    return Some(r);
                }
                params.truncate(mark);
            }
            node.wild.as_ref().map(|(name, routes)| {
                params.push((name.clone(), segs.join("/")));
                routes.as_slice()
            })
        }

        pub(crate) fn lookup(&self, method: &Method, path: &str) -> Option<Vec<(String, String)>> {
            let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            let mut params = Vec::new();
            let routes = Self::find(&self.root, &segs, &mut params)?;
            routes.iter().any(|m| m == method).then_some(params)
        }
    }
}
