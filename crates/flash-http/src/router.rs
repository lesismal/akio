//! Path routing on a segment tree.
//!
//! Segment kinds, tried in this order at every level (with backtracking, so a dead end in a more
//! specific branch falls back to a less specific one):
//!
//! 1. static: `users`;
//! 2. regexp parameter: `{id:[0-9]+}` (chi style; the expression must match the whole segment
//!    and cannot contain `/`; needs the default `regex` feature);
//! 3. plain parameter: `:id` or `{id}` (one non-empty segment);
//! 4. wildcard: `*rest` or `{*rest}`, last segment only, matching the rest of the path (possibly
//!    empty).
//!
//! Lookup does not allocate: parameters are byte ranges into the request path kept in a small
//! inline buffer, and their names are shared with the tree. Values are percent-decoded once, when
//! a route is dispatched, and only if they contain an escape ([`Context::param`]); the raw text
//! stays available ([`Context::param_raw`]).

use std::sync::Arc;

use crate::{
    context::{BodyMode, Context, Middleware, Service},
    message::{Method, Request, Response, percent_decode},
};

/// Parameter positions kept inline before spilling to the heap.
const INLINE: usize = 6;

/// Byte ranges of parameter values in the request path: a tiny small-vector.
#[derive(Clone, Default, Debug)]
pub(crate) struct Ranges {
    len: usize,
    inline: [(u32, u32); INLINE],
    spill: Vec<(u32, u32)>,
}

impl Ranges {
    fn push(&mut self, start: usize, end: usize) {
        let r = (start as u32, end as u32);
        if self.len < INLINE {
            self.inline[self.len] = r;
        } else {
            self.spill.push(r);
        }
        self.len += 1;
    }

    fn truncate(&mut self, n: usize) {
        if n <= INLINE {
            self.spill.clear();
        } else {
            self.spill.truncate(n - INLINE);
        }
        self.len = self.len.min(n);
    }

    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, i: usize) -> std::ops::Range<usize> {
        let (a, b) = if i < INLINE {
            self.inline[i]
        } else {
            self.spill[i - INLINE]
        };
        a as usize..b as usize
    }
}

/// The parameters of the route a request was dispatched to.
#[derive(Default)]
pub(crate) struct Params {
    names: Option<Arc<[Box<str>]>>,
    ranges: Ranges,
    /// Percent-decoded values, only for the parameters that contain an escape.
    decoded: Vec<(usize, String)>,
}

impl Params {
    fn new(names: Arc<[Box<str>]>, ranges: Ranges, path: &str) -> Params {
        let mut decoded = Vec::new();
        for i in 0..ranges.len() {
            let raw = &path[ranges.get(i)];
            if raw.as_bytes().contains(&b'%') {
                if let Some(d) = percent_decode(raw) {
                    decoded.push((i, d));
                }
            }
        }
        Params {
            names: Some(names),
            ranges,
            decoded,
        }
    }

    /// Moves the parameters to the heap, if there are any.
    pub(crate) fn boxed(self) -> Option<Box<Params>> {
        self.names.is_some().then(|| Box::new(self))
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.names.as_ref()?.iter().position(|n| &**n == name)
    }

    /// The value of `name` as sent, from the request path `path`.
    pub(crate) fn raw<'a>(&self, name: &str, path: &'a str) -> Option<&'a str> {
        let i = self.index(name)?;
        path.get(self.ranges.get(i))
    }

    /// The percent-decoded value of `name` (the raw one when it has no valid escapes).
    pub(crate) fn get<'a>(&'a self, name: &str, path: &'a str) -> Option<&'a str> {
        let i = self.index(name)?;
        match self.decoded.iter().find(|(j, _)| *j == i) {
            Some((_, d)) => Some(d),
            None => path.get(self.ranges.get(i)),
        }
    }
}

#[cfg(feature = "regex")]
struct Matcher(regex::Regex);

#[cfg(feature = "regex")]
impl Matcher {
    fn new(src: &str, path: &str) -> Matcher {
        match regex::Regex::new(&format!("^(?:{src})$")) {
            Ok(re) => Matcher(re),
            Err(e) => panic!("bad parameter regexp in {path}: {e}"),
        }
    }

    fn is_match(&self, seg: &str) -> bool {
        self.0.is_match(seg)
    }
}

#[cfg(not(feature = "regex"))]
struct Matcher;

#[cfg(not(feature = "regex"))]
impl Matcher {
    fn new(_src: &str, path: &str) -> Matcher {
        panic!("regexp route parameters need flash-http's `regex` feature: {path}")
    }

    fn is_match(&self, _seg: &str) -> bool {
        false
    }
}

struct Route {
    method: Method,
    svc: Arc<dyn Service>,
}

/// The routes registered for one path pattern.
struct Leaf {
    routes: Vec<Route>,
    /// Parameter names in path order (the same for every route of the leaf).
    names: Arc<[Box<str>]>,
}

struct RegexChild {
    name: Box<str>,
    src: Box<str>,
    re: Matcher,
    node: Node,
}

#[derive(Default)]
struct Node {
    statics: Vec<(Box<str>, Node)>,
    regexes: Vec<RegexChild>,
    param: Option<(Box<str>, Box<Node>)>,
    /// A trailing wildcard: matches the rest of the path (possibly empty).
    wild: Option<(Box<str>, Leaf)>,
    leaf: Option<Leaf>,
}

/// One segment of a route pattern.
enum Seg<'a> {
    Static(&'a str),
    Param(&'a str),
    Regex(&'a str, &'a str),
    Wild(&'a str),
}

fn parse_seg(seg: &str) -> Seg<'_> {
    if let Some(n) = seg.strip_prefix('*') {
        return Seg::Wild(n);
    }
    if let Some(n) = seg.strip_prefix(':') {
        return Seg::Param(n);
    }
    if let Some(inner) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        return match inner.split_once(':') {
            Some((n, re)) => Seg::Regex(n, re),
            None => match inner.strip_prefix('*') {
                Some(n) => Seg::Wild(n),
                None => Seg::Param(inner),
            },
        };
    }
    Seg::Static(seg)
}

/// The next non-empty segment of `path` at or after byte `pos`, as `(start, end)`.
#[inline]
fn next_seg(path: &str, mut pos: usize) -> Option<(usize, usize)> {
    let b = path.as_bytes();
    while pos < b.len() && b[pos] == b'/' {
        pos += 1;
    }
    if pos >= b.len() {
        return None;
    }
    let end = b[pos..]
        .iter()
        .position(|&c| c == b'/')
        .map_or(b.len(), |n| pos + n);
    Some((pos, end))
}

impl Leaf {
    fn new(names: Vec<Box<str>>) -> Leaf {
        Leaf {
            routes: Vec::new(),
            names: names.into(),
        }
    }

    fn add(&mut self, method: Method, svc: Arc<dyn Service>, path: &str) {
        assert!(
            !self.routes.iter().any(|r| r.method == method),
            "duplicate route {} {path}",
            method.as_str()
        );
        self.routes.push(Route { method, svc });
    }
}

/// Wraps `svc` in `mw`.
struct Layered {
    mw: Arc<dyn Middleware>,
    next: Arc<dyn Service>,
}

impl Service for Layered {
    fn call(&self, ctx: &mut Context) {
        self.mw.handle(ctx, &*self.next);
    }

    fn body_mode(&self, req: &Request) -> BodyMode {
        self.next.body_mode(req)
    }
}

/// The local key under which the router tells the fallback which methods a path allows.
const ALLOW: &str = "flash.allow";

/// Default fallback: 405 with `Allow` when the path exists for other methods, else 404.
struct DefaultFallback;

impl Service for DefaultFallback {
    fn call(&self, ctx: &mut Context) {
        match ctx.local(ALLOW).map(str::to_owned) {
            Some(allow) => {
                ctx.respond(Response::text(405, "Method Not Allowed").header("Allow", allow));
            }
            None => ctx.text(404, "Not Found"),
        }
    }
}

/// Routes requests to [`Service`]s by method and path. A `Router` is itself a [`Service`].
///
/// Patterns are made of `/`-separated segments: `users` (static), `{id:[0-9]+}` (regexp
/// parameter), `:id` or `{id}` (parameter), `*rest` or `{*rest}` (wildcard, last only). At each
/// level static beats regexp beats plain parameter beats wildcard, with backtracking. Routing
/// does not allocate; see [`Context::param`] for how values are decoded.
pub struct Router {
    root: Node,
    /// Every registration, kept so a router can be nested into another.
    registered: Vec<(Method, String, Arc<dyn Service>)>,
    fallback: Arc<dyn Service>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router").finish_non_exhaustive()
    }
}

impl Default for Router {
    fn default() -> Self {
        Router::new()
    }
}

impl Router {
    /// An empty router.
    pub fn new() -> Router {
        Router {
            root: Node::default(),
            registered: Vec::new(),
            fallback: Arc::new(DefaultFallback),
        }
    }

    /// Registers `svc` for `method` and `path`. Segments: `users` (static), `{id:[0-9]+}`
    /// (regexp, whole segment, no `/` inside), `:id` / `{id}` (one segment), `*rest` / `{*rest}`
    /// (everything after, last segment only).
    ///
    /// # Panics
    /// On a duplicate route, a parameter name that conflicts with a sibling, a wildcard that is
    /// not last, or an invalid regexp (or any regexp without the `regex` feature).
    #[must_use]
    pub fn route(mut self, method: Method, path: &str, svc: impl Service) -> Router {
        self.insert(method, path.to_owned(), Arc::new(svc));
        self
    }

    fn insert(&mut self, method: Method, path: String, svc: Arc<dyn Service>) {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut names: Vec<Box<str>> = Vec::new();
        let mut node = &mut self.root;
        for (i, seg) in segs.iter().enumerate() {
            match parse_seg(seg) {
                Seg::Wild(name) => {
                    assert!(
                        i == segs.len() - 1,
                        "wildcard must be the last segment: {path}"
                    );
                    names.push(name.into());
                    let (n, leaf) = node
                        .wild
                        .get_or_insert_with(|| (name.into(), Leaf::new(names)));
                    assert!(&**n == name, "wildcard name conflict in {path}");
                    leaf.add(method.clone(), svc.clone(), &path);
                    self.registered.push((method, path, svc));
                    return;
                }
                Seg::Param(name) => {
                    let (n, child) = node
                        .param
                        .get_or_insert_with(|| (name.into(), Box::default()));
                    assert!(
                        &**n == name,
                        "parameter name conflict in {path}: :{n} vs :{name}"
                    );
                    names.push(name.into());
                    node = child;
                }
                Seg::Regex(name, src) => {
                    let at = match node.regexes.iter().position(|c| &*c.src == src) {
                        Some(at) => {
                            assert!(
                                &*node.regexes[at].name == name,
                                "parameter name conflict in {path}: {{{}:{src}}} vs {{{name}:{src}}}",
                                node.regexes[at].name
                            );
                            at
                        }
                        None => {
                            node.regexes.push(RegexChild {
                                name: name.into(),
                                src: src.into(),
                                re: Matcher::new(src, &path),
                                node: Node::default(),
                            });
                            node.regexes.len() - 1
                        }
                    };
                    names.push(name.into());
                    node = &mut node.regexes[at].node;
                }
                Seg::Static(seg) => {
                    let at = match node.statics.iter().position(|(s, _)| &**s == seg) {
                        Some(at) => at,
                        None => {
                            node.statics.push((seg.into(), Node::default()));
                            node.statics.len() - 1
                        }
                    };
                    node = &mut node.statics[at].1;
                }
            }
        }
        node.leaf
            .get_or_insert_with(|| Leaf::new(names))
            .add(method.clone(), svc.clone(), &path);
        self.registered.push((method, path, svc));
    }

    /// `GET path`.
    #[must_use]
    pub fn get(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Get, path, svc)
    }
    /// `POST path`.
    #[must_use]
    pub fn post(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Post, path, svc)
    }
    /// `PUT path`.
    #[must_use]
    pub fn put(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Put, path, svc)
    }
    /// `DELETE path`.
    #[must_use]
    pub fn delete(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Delete, path, svc)
    }
    /// `PATCH path`.
    #[must_use]
    pub fn patch(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Patch, path, svc)
    }
    /// `OPTIONS path`.
    #[must_use]
    pub fn options(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Options, path, svc)
    }

    /// Replaces the answer for unknown paths and wrong methods. The 405 `Allow` list is in
    /// `ctx.local("flash.allow")` when the path exists.
    #[must_use]
    pub fn fallback(mut self, svc: impl Service) -> Router {
        self.fallback = Arc::new(svc);
        self
    }

    /// Wraps every route registered so far, and the fallback, in `mw` (the last layer added is
    /// the outermost). Routes added later are not wrapped.
    #[must_use]
    pub fn layer(mut self, mw: impl Middleware) -> Router {
        let mw: Arc<dyn Middleware> = Arc::new(mw);
        let wrap = |svc: Arc<dyn Service>| -> Arc<dyn Service> {
            Arc::new(Layered {
                mw: mw.clone(),
                next: svc,
            })
        };
        let old = std::mem::take(&mut self.registered);
        self.root = Node::default();
        for (m, p, svc) in old {
            self.insert(m, p, wrap(svc));
        }
        self.fallback = wrap(self.fallback.clone());
        self
    }

    /// Mounts `other` under `prefix` (`/api` + `/users/:id` = `/api/users/:id`). `other`'s layers
    /// stay in effect for its routes.
    #[must_use]
    pub fn nest(mut self, prefix: &str, other: Router) -> Router {
        let prefix = prefix.trim_end_matches('/');
        for (m, p, svc) in other.registered {
            self.insert(m, format!("{prefix}{p}"), svc);
        }
        self
    }

    /// The leaf matching `path[pos..]` below `node`; parameter ranges are pushed onto `out`
    /// (and popped again on backtracking).
    fn find<'a>(node: &'a Node, path: &str, pos: usize, out: &mut Ranges) -> Option<&'a Leaf> {
        let Some((s, e)) = next_seg(path, pos) else {
            if let Some(l) = &node.leaf {
                return Some(l);
            }
            // `/files` also matches `/files/*rest` with an empty rest.
            return node.wild.as_ref().map(|(_, l)| {
                out.push(path.len(), path.len());
                l
            });
        };
        let seg = &path[s..e];
        if let Some((_, child)) = node.statics.iter().find(|(k, _)| **k == *seg) {
            if let Some(l) = Self::find(child, path, e, out) {
                return Some(l);
            }
        }
        let mark = out.len();
        for c in &node.regexes {
            if c.re.is_match(seg) {
                out.push(s, e);
                if let Some(l) = Self::find(&c.node, path, e, out) {
                    return Some(l);
                }
                out.truncate(mark);
            }
        }
        if let Some((_, child)) = &node.param {
            out.push(s, e);
            if let Some(l) = Self::find(child, path, e, out) {
                return Some(l);
            }
            out.truncate(mark);
        }
        node.wild.as_ref().map(|(_, l)| {
            out.push(s, path.trim_end_matches('/').len());
            l
        })
    }

    fn resolve<'a>(&'a self, path: &str, method: &Method, out: &mut Ranges) -> Resolved<'a> {
        let Some(leaf) = Router::find(&self.root, path, 0, out) else {
            return Resolved::NotFound;
        };
        let routes = &leaf.routes;
        let route = routes.iter().find(|r| &r.method == method).or_else(|| {
            // HEAD is answered by the GET route (the body is dropped when encoding).
            (*method == Method::Head)
                .then(|| routes.iter().find(|r| r.method == Method::Get))
                .flatten()
        });
        match route {
            Some(r) => Resolved::Route(r, &leaf.names),
            None => Resolved::NotAllowed(leaf),
        }
    }

    /// Looks up the route `method path` would be dispatched to, without running anything and
    /// without allocating. `None` when no route matches (a 404 or 405). Parameter values are raw.
    pub fn lookup<'r, 'p>(&'r self, method: &Method, path: &'p str) -> Option<RouteMatch<'r, 'p>> {
        let mut ranges = Ranges::default();
        match self.resolve(path, method, &mut ranges) {
            Resolved::Route(_, names) => Some(RouteMatch {
                names,
                ranges,
                path,
            }),
            _ => None,
        }
    }
}

/// A route found by [`Router::lookup`].
#[derive(Debug)]
pub struct RouteMatch<'r, 'p> {
    names: &'r [Box<str>],
    ranges: Ranges,
    path: &'p str,
}

impl<'r, 'p> RouteMatch<'r, 'p> {
    /// The raw (not percent-decoded) value of parameter `name`.
    pub fn param(&self, name: &str) -> Option<&'p str> {
        let i = self.names.iter().position(|n| &**n == name)?;
        self.path.get(self.ranges.get(i))
    }

    /// Every parameter, in path order, as `(name, raw value)`.
    pub fn params(&self) -> impl Iterator<Item = (&'r str, &'p str)> + '_ {
        let path = self.path;
        self.names
            .iter()
            .enumerate()
            .map(move |(i, n)| (&**n, &path[self.ranges.get(i)]))
    }
}

/// Where a request goes.
enum Resolved<'a> {
    Route(&'a Route, &'a Arc<[Box<str>]>),
    /// The path exists, the method does not.
    NotAllowed(&'a Leaf),
    NotFound,
}

/// The `Allow` header for a path with these routes.
fn allow(leaf: &Leaf) -> String {
    let mut allow: Vec<&str> = leaf.routes.iter().map(|r| r.method.as_str()).collect();
    if leaf.routes.iter().any(|r| r.method == Method::Get) {
        allow.push("HEAD");
    }
    allow.sort_unstable();
    allow.join(", ")
}

impl Service for Router {
    fn call(&self, ctx: &mut Context) {
        let mut ranges = Ranges::default();
        match self.resolve(ctx.path(), ctx.method(), &mut ranges) {
            Resolved::Route(r, names) => {
                let params = Params::new(names.clone(), ranges, ctx.path());
                ctx.set_params(params);
                r.svc.call(ctx);
            }
            Resolved::NotAllowed(leaf) => {
                ctx.set_local(ALLOW, allow(leaf));
                self.fallback.call(ctx);
            }
            Resolved::NotFound => self.fallback.call(ctx),
        }
    }

    fn body_mode(&self, req: &Request) -> BodyMode {
        let mut ranges = Ranges::default();
        match self.resolve(req.path(), &req.method, &mut ranges) {
            Resolved::Route(r, _) => r.svc.body_mode(req),
            _ => self.fallback.body_mode(req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router() -> Router {
        let nop = |_: &mut Context| {};
        Router::new()
            .get("/", nop)
            .get("/users/me", nop)
            .get("/users/:id", nop)
            .post("/users/:id", nop)
            .get("/users/:id/posts/:post", nop)
            .get("/files/*path", nop)
            .get("/a/b/c", nop)
    }

    fn matched(r: &Router, path: &str) -> Option<(usize, Vec<(String, String)>)> {
        let mut ranges = Ranges::default();
        Router::find(&r.root, path, 0, &mut ranges).map(|leaf| {
            let params = leaf
                .names
                .iter()
                .enumerate()
                .map(|(i, n)| (n.to_string(), path[ranges.get(i)].to_owned()))
                .collect();
            (leaf.routes.len(), params)
        })
    }

    fn p(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn static_beats_param_beats_wildcard() {
        let r = router();
        // `/users/me` is the static route (1 method), not `:id` (2 methods).
        assert_eq!(matched(&r, "/users/me"), Some((1, vec![])));
        assert_eq!(matched(&r, "/users/42"), Some((2, p(&[("id", "42")]))));
        assert_eq!(
            matched(&r, "/users/42/posts/7"),
            Some((1, p(&[("id", "42"), ("post", "7")])))
        );
        assert_eq!(
            matched(&r, "/files/a/b/c.txt"),
            Some((1, p(&[("path", "a/b/c.txt")])))
        );
        assert_eq!(
            matched(&r, "/files/a/b/"),
            Some((1, p(&[("path", "a/b")]))),
            "a trailing slash is not part of the wildcard"
        );
        assert_eq!(
            matched(&r, "/files"),
            Some((1, p(&[("path", "")]))),
            "the wildcard may match nothing"
        );
        assert_eq!(matched(&r, "/"), Some((1, vec![])));
        assert_eq!(matched(&r, "/nope"), None);
        assert_eq!(matched(&r, "/users/42/other"), None);
    }

    #[test]
    fn backtracks_from_a_static_dead_end_into_a_param() {
        let nop = |_: &mut Context| {};
        let r = Router::new()
            .get("/x/special/deep", nop)
            .get("/x/:v/shallow", nop);
        // `/x/special/shallow`: the static branch `special` dead-ends, `:v` must still match.
        assert_eq!(
            matched(&r, "/x/special/shallow"),
            Some((1, p(&[("v", "special")])))
        );
    }

    #[cfg(feature = "regex")] // regexp parameters need the `regex` feature
    #[test]
    fn regexp_params_sit_between_static_and_plain() {
        let nop = |_: &mut Context| {};
        let r = Router::new()
            .get("/u/me", nop)
            .get("/u/{id:[0-9]+}", nop)
            .post("/u/{id:[0-9]+}", nop)
            .put("/u/{id:[0-9]+}", nop)
            .get("/u/{hex:0x[0-9a-f]+}/x", nop)
            .get("/u/{name}", nop)
            .get("/u/{name}/x", nop)
            .get("/u/*rest", nop)
            .get("/d/{date:\\d{4}-\\d{2}}", nop);
        assert_eq!(matched(&r, "/u/me"), Some((1, vec![])));
        assert_eq!(matched(&r, "/u/42"), Some((3, p(&[("id", "42")]))));
        assert_eq!(
            matched(&r, "/u/42x"),
            Some((1, p(&[("name", "42x")]))),
            "the regexp must match the whole segment"
        );
        assert_eq!(matched(&r, "/u/0x1f/x"), Some((1, p(&[("hex", "0x1f")]))));
        // The regexp branch dead-ends (no `/u/{id}/x`): backtrack into `{name}`.
        assert_eq!(matched(&r, "/u/42/x"), Some((1, p(&[("name", "42")]))));
        assert_eq!(matched(&r, "/u/a/b/c"), Some((1, p(&[("rest", "a/b/c")]))));
        assert_eq!(
            matched(&r, "/d/2026-11"),
            Some((1, p(&[("date", "2026-11")])))
        );
        assert_eq!(matched(&r, "/d/2026-1"), None);
    }

    #[test]
    fn brace_syntax_for_plain_params_and_wildcards() {
        let nop = |_: &mut Context| {};
        let r = Router::new()
            .get("/a/{x}/b", nop)
            .get("/a/:x/c", nop)
            .get("/w/{*all}", nop);
        assert_eq!(matched(&r, "/a/1/b"), Some((1, p(&[("x", "1")]))));
        assert_eq!(matched(&r, "/a/1/c"), Some((1, p(&[("x", "1")]))));
        assert_eq!(matched(&r, "/w/q/r"), Some((1, p(&[("all", "q/r")]))));
    }

    #[test]
    fn many_params_spill_past_the_inline_buffer() {
        let nop = |_: &mut Context| {};
        let r = Router::new().get("/:a/:b/:c/:d/:e/:f/:g/:h/*i", nop);
        let (_, got) = matched(&r, "/1/2/3/4/5/6/7/8/9/10").unwrap();
        assert_eq!(
            got,
            p(&[
                ("a", "1"),
                ("b", "2"),
                ("c", "3"),
                ("d", "4"),
                ("e", "5"),
                ("f", "6"),
                ("g", "7"),
                ("h", "8"),
                ("i", "9/10")
            ])
        );
        // Backtracking across the spill boundary truncates correctly.
        let r = Router::new()
            .get("/:a/:b/:c/:d/:e/:f/:g/x", nop)
            .get("/:a/:b/:c/:d/:e/:f/*rest", nop);
        let (_, got) = matched(&r, "/1/2/3/4/5/6/7/y").unwrap();
        assert_eq!(got.len(), 7);
        assert_eq!(got[6], ("rest".into(), "7/y".into()));
    }

    #[test]
    fn params_decode_once_and_keep_the_raw_text() {
        let nop = |_: &mut Context| {};
        let r = Router::new().get("/f/:name/*rest", nop);
        let path = "/f/a%20b/c%2Fd/%zz";
        let mut ranges = Ranges::default();
        let leaf = Router::find(&r.root, path, 0, &mut ranges).unwrap();
        let params = Params::new(leaf.names.clone(), ranges, path);
        assert_eq!(params.get("name", path), Some("a b"));
        assert_eq!(params.raw("name", path), Some("a%20b"));
        // A malformed escape leaves the raw text.
        assert_eq!(params.get("rest", path), Some("c%2Fd/%zz"));
        assert_eq!(params.get("nope", path), None);
        let path = "/f/x/y%2Fz";
        let mut ranges = Ranges::default();
        let leaf = Router::find(&r.root, path, 0, &mut ranges).unwrap();
        let params = Params::new(leaf.names.clone(), ranges, path);
        assert_eq!(params.get("rest", path), Some("y/z"));
        assert_eq!(params.raw("rest", path), Some("y%2Fz"));
    }

    #[test]
    fn lookup_reports_matches_without_dispatching() {
        let r = router();
        let m = r.lookup(&Method::Get, "/users/42/posts/7").unwrap();
        assert_eq!(m.param("post"), Some("7"));
        assert_eq!(
            m.params().collect::<Vec<_>>(),
            vec![("id", "42"), ("post", "7")]
        );
        assert!(
            r.lookup(&Method::Head, "/users/me").is_some(),
            "HEAD via GET"
        );
        assert!(r.lookup(&Method::Delete, "/users/1").is_none(), "405");
        assert!(r.lookup(&Method::Get, "/zzz").is_none(), "404");
    }

    #[test]
    fn trailing_and_duplicate_slashes_are_ignored() {
        let r = router();
        assert!(matched(&r, "/users/42/").is_some());
        assert!(matched(&r, "//users//42").is_some());
    }

    #[test]
    #[should_panic(expected = "duplicate route")]
    fn duplicate_routes_panic() {
        let nop = |_: &mut Context| {};
        let _ = Router::new().get("/a", nop).get("/a", nop);
    }

    #[test]
    #[should_panic(expected = "duplicate route")]
    fn duplicate_wildcard_routes_panic() {
        let nop = |_: &mut Context| {};
        let _ = Router::new().get("/a/*x", nop).get("/a/*x", nop);
    }

    #[test]
    #[should_panic(expected = "parameter name conflict")]
    fn conflicting_param_names_panic() {
        let nop = |_: &mut Context| {};
        let _ = Router::new().get("/a/:x", nop).get("/a/:y/b", nop);
    }

    #[cfg(feature = "regex")] // regexp parameters need the `regex` feature
    #[test]
    #[should_panic(expected = "parameter name conflict")]
    fn conflicting_regexp_param_names_panic() {
        let nop = |_: &mut Context| {};
        let _ = Router::new()
            .get("/a/{x:[0-9]+}", nop)
            .get("/a/{y:[0-9]+}/b", nop);
    }

    #[cfg(feature = "regex")] // regexp parameters need the `regex` feature
    #[test]
    #[should_panic(expected = "bad parameter regexp")]
    fn invalid_regexp_panics() {
        let nop = |_: &mut Context| {};
        let _ = Router::new().get("/a/{x:[0-9}", nop);
    }

    #[test]
    #[cfg(not(feature = "regex"))]
    #[should_panic(expected = "need flash-http's `regex` feature")]
    fn regexp_params_without_the_feature_panic() {
        let nop = |_: &mut Context| {};
        let _ = Router::new().get("/a/{x:[0-9]+}", nop);
    }

    #[test]
    fn nesting_prefixes_routes() {
        let nop = |_: &mut Context| {};
        let api = Router::new().get("/users/:id", nop);
        let r = Router::new().nest("/api/v1/", api);
        assert!(matched(&r, "/api/v1/users/9").is_some());
        assert!(matched(&r, "/users/9").is_none());
    }
}
