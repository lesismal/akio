//! Path routing: static segments beat `:param` segments beat a trailing `*wildcard`.

use std::sync::Arc;

use crate::{
    context::{BodyMode, Context, Middleware, Service},
    message::{Method, Request, Response},
};

struct Route {
    method: Method,
    svc: Arc<dyn Service>,
}

#[derive(Default)]
struct Node {
    statics: Vec<(String, Node)>,
    param: Option<(String, Box<Node>)>,
    /// A trailing `*name`: matches the rest of the path (possibly empty).
    wild: Option<(String, Vec<Route>)>,
    routes: Vec<Route>,
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
                ctx.respond(Response::text(405, "Method Not Allowed").header("Allow", allow))
            }
            None => ctx.text(404, "Not Found"),
        }
    }
}

/// Routes requests to [`Service`]s by method and path. A `Router` is itself a [`Service`].
pub struct Router {
    root: Node,
    /// Every registration, kept so a router can be nested into another.
    registered: Vec<(Method, String, Arc<dyn Service>)>,
    fallback: Arc<dyn Service>,
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

    /// Registers `svc` for `method` and `path`. Segments: `users` (static), `:id` (one segment),
    /// `*rest` (everything after, last segment only).
    ///
    /// # Panics
    /// On a duplicate route, a parameter name that conflicts with a sibling, or a wildcard that is
    /// not last.
    pub fn route(mut self, method: Method, path: &str, svc: impl Service) -> Router {
        self.insert(method, path.to_owned(), Arc::new(svc));
        self
    }

    fn insert(&mut self, method: Method, path: String, svc: Arc<dyn Service>) {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut node = &mut self.root;
        for (i, seg) in segs.iter().enumerate() {
            if let Some(name) = seg.strip_prefix('*') {
                assert!(
                    i == segs.len() - 1,
                    "wildcard must be the last segment: {path}"
                );
                let (n, routes) = node
                    .wild
                    .get_or_insert_with(|| (name.to_owned(), Vec::new()));
                assert!(n == name, "wildcard name conflict in {path}");
                assert!(
                    !routes.iter().any(|r| r.method == method),
                    "duplicate route {} {path}",
                    method.as_str()
                );
                routes.push(Route {
                    method: method.clone(),
                    svc: svc.clone(),
                });
                self.registered.push((method, path, svc));
                return;
            }
            if let Some(name) = seg.strip_prefix(':') {
                let (n, child) = node
                    .param
                    .get_or_insert_with(|| (name.to_owned(), Box::default()));
                assert!(
                    n == name,
                    "parameter name conflict in {path}: :{n} vs :{name}"
                );
                node = child;
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
        assert!(
            !node.routes.iter().any(|r| r.method == method),
            "duplicate route {} {path}",
            method.as_str()
        );
        node.routes.push(Route {
            method: method.clone(),
            svc: svc.clone(),
        });
        self.registered.push((method, path, svc));
    }

    /// `GET path`.
    pub fn get(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Get, path, svc)
    }
    /// `POST path`.
    pub fn post(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Post, path, svc)
    }
    /// `PUT path`.
    pub fn put(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Put, path, svc)
    }
    /// `DELETE path`.
    pub fn delete(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Delete, path, svc)
    }
    /// `PATCH path`.
    pub fn patch(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Patch, path, svc)
    }
    /// `OPTIONS path`.
    pub fn options(self, path: &str, svc: impl Service) -> Router {
        self.route(Method::Options, path, svc)
    }

    /// Replaces the answer for unknown paths and wrong methods. The 405 `Allow` list is in
    /// `ctx.local("flash.allow")` when the path exists.
    pub fn fallback(mut self, svc: impl Service) -> Router {
        self.fallback = Arc::new(svc);
        self
    }

    /// Wraps every route registered so far, and the fallback, in `mw` (the last layer added is
    /// the outermost). Routes added later are not wrapped.
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
    pub fn nest(mut self, prefix: &str, other: Router) -> Router {
        let prefix = prefix.trim_end_matches('/');
        for (m, p, svc) in other.registered {
            self.insert(m, format!("{prefix}{p}"), svc);
        }
        self
    }

    fn find<'a>(
        node: &'a Node,
        segs: &[&str],
        params: &mut Vec<(String, String)>,
    ) -> Option<&'a [Route]> {
        let Some((first, rest)) = segs.split_first() else {
            if !node.routes.is_empty() {
                return Some(&node.routes);
            }
            // `/files` also matches `/files/*rest` with an empty rest.
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
}

/// Where a request goes.
enum Resolved<'a> {
    Route(&'a Route, Vec<(String, String)>),
    /// The path exists, the method does not: the allowed methods.
    NotAllowed(String),
    NotFound,
}

impl Router {
    fn resolve<'a>(&'a self, path: &str, method: &Method) -> Resolved<'a> {
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut params = Vec::new();
        let Some(routes) = Router::find(&self.root, &segs, &mut params) else {
            return Resolved::NotFound;
        };
        let route = routes.iter().find(|r| &r.method == method).or_else(|| {
            // HEAD is answered by the GET route (the body is dropped when encoding).
            (*method == Method::Head)
                .then(|| routes.iter().find(|r| r.method == Method::Get))
                .flatten()
        });
        match route {
            Some(r) => Resolved::Route(r, params),
            None => {
                let mut allow: Vec<&str> = routes.iter().map(|r| r.method.as_str()).collect();
                if routes.iter().any(|r| r.method == Method::Get) {
                    allow.push("HEAD");
                }
                allow.sort_unstable();
                Resolved::NotAllowed(allow.join(", "))
            }
        }
    }
}

impl Service for Router {
    fn call(&self, ctx: &mut Context) {
        let path = ctx.path().to_owned();
        match self.resolve(&path, &ctx.method().clone()) {
            Resolved::Route(r, params) => {
                ctx.set_params(params);
                r.svc.call(ctx);
            }
            Resolved::NotAllowed(allow) => {
                ctx.set_local(ALLOW, allow);
                self.fallback.call(ctx);
            }
            Resolved::NotFound => self.fallback.call(ctx),
        }
    }

    fn body_mode(&self, req: &Request) -> BodyMode {
        match self.resolve(req.path(), &req.method) {
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
        let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut params = Vec::new();
        Router::find(&r.root, &segs, &mut params).map(|routes| (routes.len(), params))
    }

    #[test]
    fn static_beats_param_beats_wildcard() {
        let r = router();
        // `/users/me` is the static route (1 method), not `:id` (2 methods).
        assert_eq!(matched(&r, "/users/me"), Some((1, vec![])));
        assert_eq!(
            matched(&r, "/users/42"),
            Some((2, vec![("id".into(), "42".into())]))
        );
        assert_eq!(
            matched(&r, "/users/42/posts/7"),
            Some((
                1,
                vec![("id".into(), "42".into()), ("post".into(), "7".into())]
            ))
        );
        assert_eq!(
            matched(&r, "/files/a/b/c.txt"),
            Some((1, vec![("path".into(), "a/b/c.txt".into())]))
        );
        assert_eq!(
            matched(&r, "/files"),
            Some((1, vec![("path".into(), String::new())])),
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
            Some((1, vec![("v".into(), "special".into())]))
        );
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
    #[should_panic(expected = "parameter name conflict")]
    fn conflicting_param_names_panic() {
        let nop = |_: &mut Context| {};
        let _ = Router::new().get("/a/:x", nop).get("/a/:y/b", nop);
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
