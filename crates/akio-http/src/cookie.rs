//! A cookie jar for the HTTP client (RFC 6265, with the RFC 6265bis rules browsers follow;
//! ADR-059).
//!
//! [`CookieJar`] stores what `Set-Cookie` response fields say and answers which cookies a
//! request carries. [`Client::with_cookies`](crate::client::Client::with_cookies) attaches one
//! to a client: every response (each hop of a redirect chain included) is stored, and every
//! request gets the matching `Cookie` field. Nothing is stored unless a jar is attached.
//!
//! The rules:
//! - **Domain.** Without `Domain` a cookie is host-only (sent back to that exact host). With it,
//!   the request host must be that domain or one of its subdomains, and the cookie goes to all
//!   of them. A `Domain` that is a public suffix is refused unless it is the request host itself
//!   (the cookie is then host-only): single labels (`com`, `localhost`) always count as public
//!   suffixes, and [`CookieJar::public_suffixes`] adds a list such as the Public Suffix List
//!   (none is built in, so `co.uk` passes unless the hook says otherwise). An IP address host
//!   only takes host-only cookies (`Domain` equal to the address, or none).
//! - **Path.** `Path` if it starts with `/`, else the request path up to its last `/`; a request
//!   carries a cookie when its path is the cookie path or below it.
//! - **Secure.** Secure cookies are only set from and sent to `https://`; an `http://` response
//!   cannot overwrite a Secure cookie. `__Secure-` names need `Secure`, `__Host-` names need
//!   `Secure`, no `Domain` and `Path=/`.
//! - **HttpOnly** is stored and reported ([`Cookie::http_only`]); an HTTP client sends such
//!   cookies like any other (the flag hides them from scripts).
//! - **SameSite.** `None` needs `Secure`. A request reached through a redirect chain that left
//!   the site of the first request (the registrable domain: one label more than the public
//!   suffix) does not carry `Strict` cookies, nor `Lax` ones unless its method is safe (`GET`,
//!   `HEAD`, `OPTIONS`, `TRACE`). Cookies without `SameSite` are not restricted.
//! - **Expiry.** `Max-Age` wins over `Expires`; zero or less, or a past date, deletes the
//!   cookie; expiry is capped at 400 days. Without either the cookie lasts as long as the jar.
//!   Dates are parsed with RFC 6265's lenient algorithm.
//!
//! Limits ([`CookieLimits`], RFC 6265 section 6.1 minimums): a name plus value of at most
//! 4096 bytes, 50 cookies per domain and 3000 in all; past them the least recently used go
//! first, expired ones before anything else.
//!
//! ```
//! use akio_http::cookie::CookieJar;
//! let jar = CookieJar::new();
//! jar.store("https://www.example.com/a/b", "sid=1; Path=/; Domain=example.com; Secure");
//! jar.store("https://www.example.com/a/b", "pref=dark");
//! assert_eq!(jar.header("https://api.example.com/").as_deref(), Some("sid=1"));
//! // Longer paths first.
//! assert_eq!(jar.header("https://www.example.com/a/c").as_deref(), Some("pref=dark; sid=1"));
//! assert_eq!(jar.header("http://www.example.com/a/c").as_deref(), Some("pref=dark"));
//! ```

use std::{
    collections::HashMap,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Longest expiry a cookie may ask for (RFC 6265bis: 400 days).
pub const MAX_AGE_CAP: Duration = Duration::from_secs(400 * 24 * 3600);

/// The jar's limits ([`CookieJar::with_limits`]). Start from `CookieLimits::default()` and set
/// the fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CookieLimits {
    /// Largest name plus value; a longer cookie is ignored. Default 4096.
    pub max_cookie_bytes: usize,
    /// Most cookies per domain (host-only or `Domain`). Default 50.
    pub max_per_domain: usize,
    /// Most cookies in the jar. Default 3000.
    pub max_cookies: usize,
}

impl Default for CookieLimits {
    fn default() -> CookieLimits {
        CookieLimits {
            max_cookie_bytes: 4096,
            max_per_domain: 50,
            max_cookies: 3000,
        }
    }
}

/// A cookie's `SameSite` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SameSite {
    /// Not sent once a redirect chain left the first request's site.
    Strict,
    /// As `Strict`, except on requests with a safe method.
    Lax,
    /// No restriction (requires `Secure`).
    None,
}

/// A stored cookie ([`CookieJar::cookies`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cookie {
    /// Name (may be empty: a `Set-Cookie` without `=`).
    pub name: String,
    /// Value.
    pub value: String,
    /// The host (host-only cookies) or the domain it covers, lower case.
    pub domain: String,
    /// Sent to `domain` exactly, not to its subdomains.
    pub host_only: bool,
    /// Path prefix.
    pub path: String,
    /// Only over `https://`.
    pub secure: bool,
    /// `HttpOnly` was given.
    pub http_only: bool,
    /// `SameSite`, if given.
    pub same_site: Option<SameSite>,
    /// When it expires; `None`: lasts as long as the jar.
    pub expires: Option<SystemTime>,
}

#[derive(Clone)]
struct Stored {
    c: Cookie,
    /// Expiry in Unix seconds, or `None`.
    expires: Option<i64>,
    created: u64,
    last_used: u64,
}

type SuffixFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

#[derive(Default)]
struct Store {
    /// By domain.
    cookies: HashMap<String, Vec<Stored>>,
    total: usize,
    /// Creation / use sequence.
    seq: u64,
}

/// The cookie store. Cheap to clone: clones share the cookies.
#[derive(Clone)]
pub struct CookieJar {
    store: Arc<Mutex<Store>>,
    limits: CookieLimits,
    suffix: Option<SuffixFn>,
}

impl Default for CookieJar {
    fn default() -> CookieJar {
        CookieJar::new()
    }
}

impl fmt::Debug for CookieJar {
    // Without the values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieJar")
            .field("cookies", &self.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// The parts of a request URL the jar looks at.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Origin<'a> {
    pub(crate) secure: bool,
    /// Lower case, no brackets.
    pub(crate) host: String,
    /// The path, without query or fragment.
    pub(crate) path: &'a str,
}

pub(crate) fn origin(url: &str) -> Option<Origin<'_>> {
    let (secure, rest) = if let Some(r) = strip_prefix_ci(url, "https://") {
        (true, r)
    } else {
        (false, strip_prefix_ci(url, "http://")?)
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    let path = &rest[end..];
    let path = &path[..path.find(['?', '#']).unwrap_or(path.len())];
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(after) = hostport.strip_prefix('[') {
        after.split_once(']')?.0
    } else {
        hostport.rsplit_once(':').map_or(hostport, |(h, _)| h)
    };
    if host.is_empty() {
        return None;
    }
    Some(Origin {
        secure,
        host: host.trim_end_matches('.').to_ascii_lowercase(),
        path,
    })
}

fn strip_prefix_ci<'a>(s: &'a str, p: &str) -> Option<&'a str> {
    (s.len() >= p.len() && s.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes()))
        .then(|| &s[p.len()..])
}

pub(crate) fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

fn to_system(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
}

/// RFC 6265 section 5.1.3: `host` domain-matches `domain`.
fn domain_match(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
            && host.parse::<IpAddr>().is_err())
}

/// RFC 6265 section 5.1.4: `req` path-matches `cookie`.
fn path_match(req: &str, cookie: &str) -> bool {
    req == cookie
        || (req.starts_with(cookie)
            && (cookie.ends_with('/') || req.as_bytes().get(cookie.len()) == Some(&b'/')))
}

/// RFC 6265 section 5.1.4: the default path of a request path.
fn default_path(path: &str) -> &str {
    if !path.starts_with('/') {
        return "/";
    }
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

fn is_safe_method(m: &str) -> bool {
    matches!(m, "GET" | "HEAD" | "OPTIONS" | "TRACE")
}

impl CookieJar {
    /// An empty jar with the default [`CookieLimits`].
    pub fn new() -> CookieJar {
        CookieJar {
            store: Arc::default(),
            limits: CookieLimits::default(),
            suffix: None,
        }
    }

    /// The same jar (shared cookies) with other limits; they apply as cookies come in.
    #[must_use]
    pub fn with_limits(mut self, limits: CookieLimits) -> CookieJar {
        self.limits = limits;
        self
    }

    /// Adds public suffixes: `is_suffix(domain)` (lower case, no leading dot) says whether
    /// `domain` is one, such as `co.uk` or `github.io` from the Public Suffix List. Single
    /// labels are public suffixes whatever it says. Applies to the cookies set afterwards and
    /// to the site of redirect chains.
    #[must_use]
    pub fn public_suffixes(
        mut self,
        is_suffix: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> CookieJar {
        self.suffix = Some(Arc::new(is_suffix));
        self
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Store> {
        self.store.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn is_public_suffix(&self, domain: &str) -> bool {
        !domain.contains('.') || self.suffix.as_ref().is_some_and(|f| f(domain))
    }

    /// The site of `host`: the host itself for an IP address, else its registrable domain
    /// (the public suffix plus one label; the whole host if it is a public suffix).
    pub fn site(&self, host: &str) -> String {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host.parse::<IpAddr>().is_ok() {
            return host;
        }
        // Longest public suffix first: the leftmost label boundary that starts one.
        let mut prev: Option<usize> = None;
        let mut start = 0;
        loop {
            let suffix = &host[start..];
            if self.is_public_suffix(suffix) {
                return match prev {
                    Some(p) => host[p..].to_owned(),
                    None => host,
                };
            }
            match suffix.find('.') {
                Some(i) => {
                    prev = Some(start);
                    start += i + 1;
                }
                None => return host,
            }
        }
    }

    /// Stores one `Set-Cookie` field value received in the response to a request for `url`.
    /// Whether it was stored (a cookie that expires at once deletes its match and counts as
    /// stored); the rules are in the [module docs](self).
    pub fn store(&self, url: &str, set_cookie: &str) -> bool {
        match origin(url) {
            Some(o) => self.store_from(&o, set_cookie, now_secs()),
            None => false,
        }
    }

    pub(crate) fn store_from(&self, o: &Origin<'_>, line: &str, now: i64) -> bool {
        let Some(p) = parse_set_cookie(line, self.limits.max_cookie_bytes) else {
            return false;
        };
        let host = o.host.as_str();
        let host_is_ip = host.parse::<IpAddr>().is_ok();
        // Domain.
        let (domain, host_only) = match p.domain.as_deref() {
            None | Some("") => (host.to_owned(), true),
            Some(d) => {
                if d.ends_with('.') {
                    return false;
                }
                if host_is_ip || self.is_public_suffix(d) {
                    if d != host {
                        return false;
                    }
                    (host.to_owned(), true)
                } else if domain_match(host, d) {
                    (d.to_owned(), false)
                } else {
                    return false;
                }
            }
        };
        if p.secure && !o.secure {
            return false;
        }
        if p.same_site == Some(SameSite::None) && !p.secure {
            return false;
        }
        let path = match p.path.as_deref() {
            Some(x) if x.starts_with('/') => x.to_owned(),
            _ => default_path(o.path).to_owned(),
        };
        let lname = p.name.to_ascii_lowercase();
        if lname.starts_with("__secure-") && !p.secure {
            return false;
        }
        if lname.starts_with("__host-") && !(p.secure && host_only && path == "/") {
            return false;
        }
        let expires = match (p.max_age, p.expires) {
            (Some(m), _) if m <= 0 => Some(i64::MIN),
            (Some(m), _) => Some(now.saturating_add(m)),
            (None, Some(e)) => Some(e),
            (None, None) => None,
        }
        .map(|e| e.min(now.saturating_add(MAX_AGE_CAP.as_secs() as i64)));
        let mut st = self.lock();
        // An insecure origin leaves Secure cookies alone (RFC 6265bis section 5.7).
        if !o.secure {
            let shadowed = st.cookies.iter().any(|(d, v)| {
                (domain_match(d, &domain) || domain_match(&domain, d))
                    && v.iter().any(|s| {
                        s.c.secure
                            && s.c.name == p.name
                            && path_match(&path, &s.c.path)
                            && !s.expires.is_some_and(|e| e <= now)
                    })
            });
            if shadowed {
                return false;
            }
        }
        st.seq += 1;
        let seq = st.seq;
        let list = st.cookies.entry(domain.clone()).or_default();
        let old = list
            .iter()
            .position(|s| s.c.name == p.name && s.c.path == path && s.c.host_only == host_only);
        let created = match old {
            Some(i) => list.remove(i).created,
            None => seq,
        };
        let removed = usize::from(old.is_some());
        if expires.is_some_and(|e| e <= now) {
            if list.is_empty() {
                st.cookies.remove(&domain);
            }
            st.total -= removed;
            return true;
        }
        list.push(Stored {
            c: Cookie {
                name: p.name,
                value: p.value,
                domain: domain.clone(),
                host_only,
                path,
                secure: p.secure,
                http_only: p.http_only,
                same_site: p.same_site,
                expires: expires.map(to_system),
            },
            expires,
            created,
            last_used: seq,
        });
        st.total = st.total + 1 - removed;
        self.enforce(&mut st, &domain, now);
        true
    }

    /// Drops cookies past the limits: expired ones, then the least recently used.
    fn enforce(&self, st: &mut Store, domain: &str, now: i64) {
        let over_domain = st
            .cookies
            .get(domain)
            .is_some_and(|v| v.len() > self.limits.max_per_domain);
        if over_domain || st.total > self.limits.max_cookies {
            purge_expired(st, now);
        }
        if let Some(v) = st.cookies.get_mut(domain) {
            let mut dropped = 0;
            while v.len() > self.limits.max_per_domain {
                let Some(i) = (0..v.len()).min_by_key(|&i| v[i].last_used) else {
                    break;
                };
                v.remove(i);
                dropped += 1;
            }
            if v.is_empty() {
                st.cookies.remove(domain);
            }
            st.total -= dropped;
        }
        while st.total > self.limits.max_cookies {
            let lru = st
                .cookies
                .iter()
                .flat_map(|(d, v)| v.iter().enumerate().map(move |(i, s)| (s.last_used, d, i)))
                .min()
                .map(|(_, d, i)| (d.clone(), i));
            let Some((d, i)) = lru else { break };
            if let Some(v) = st.cookies.get_mut(&d) {
                v.remove(i);
                if v.is_empty() {
                    st.cookies.remove(&d);
                }
            }
            st.total -= 1;
        }
    }

    /// The `Cookie` field value for a `GET` request to `url` that is not part of a cross-site
    /// redirect chain; `None` when no cookie applies.
    pub fn header(&self, url: &str) -> Option<String> {
        let o = origin(url)?;
        self.header_for(&o, "GET", false, now_secs())
    }

    /// The `Cookie` value for a request: `cross_site` says whether its redirect chain left the
    /// first request's site.
    pub(crate) fn header_for(
        &self,
        o: &Origin<'_>,
        method: &str,
        cross_site: bool,
        now: i64,
    ) -> Option<String> {
        let mut st = self.lock();
        st.seq += 1;
        let seq = st.seq;
        let path = if o.path.is_empty() { "/" } else { o.path };
        let mut hits: Vec<(usize, u64, &mut Stored)> = Vec::new();
        let host = o.host.as_str();
        let mut expired = false;
        for (d, v) in &mut st.cookies {
            if !domain_match(host, d) {
                continue;
            }
            for s in v.iter_mut() {
                if s.expires.is_some_and(|e| e <= now) {
                    expired = true;
                    continue;
                }
                let ok = (!s.c.host_only || host == s.c.domain)
                    && path_match(path, &s.c.path)
                    && (!s.c.secure || o.secure)
                    && match (s.c.same_site, cross_site) {
                        (_, false) | (None | Some(SameSite::None), true) => true,
                        (Some(SameSite::Lax), true) => is_safe_method(method),
                        (Some(SameSite::Strict), true) => false,
                    };
                if ok {
                    hits.push((s.c.path.len(), s.created, s));
                }
            }
        }
        // Longer paths first, then older (RFC 6265 section 5.4).
        hits.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut out = String::new();
        for (_, _, s) in hits {
            s.last_used = seq;
            if !out.is_empty() {
                out.push_str("; ");
            }
            if !s.c.name.is_empty() {
                out.push_str(&s.c.name);
                out.push('=');
            }
            out.push_str(&s.c.value);
        }
        if expired {
            purge_expired(&mut st, now);
        }
        (!out.is_empty()).then_some(out)
    }

    /// Every cookie that has not expired.
    pub fn cookies(&self) -> Vec<Cookie> {
        let now = now_secs();
        let st = self.lock();
        let mut v: Vec<&Stored> = st
            .cookies
            .values()
            .flatten()
            .filter(|s| !s.expires.is_some_and(|e| e <= now))
            .collect();
        v.sort_by_key(|s| s.created);
        v.into_iter().map(|s| s.c.clone()).collect()
    }

    /// How many cookies are stored (expired ones not yet dropped included).
    pub fn len(&self) -> usize {
        self.lock().total
    }

    /// Whether the jar is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes every cookie.
    pub fn clear(&self) {
        let mut st = self.lock();
        st.cookies.clear();
        st.total = 0;
    }
}

fn purge_expired(st: &mut Store, now: i64) {
    let mut dropped = 0;
    st.cookies.retain(|_, v| {
        let n = v.len();
        v.retain(|s| !s.expires.is_some_and(|e| e <= now));
        dropped += n - v.len();
        !v.is_empty()
    });
    st.total -= dropped;
}

/// A parsed `Set-Cookie` value (RFC 6265 section 5.2).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct SetCookie {
    pub(crate) name: String,
    pub(crate) value: String,
    /// Lower case, leading dot removed.
    pub(crate) domain: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) secure: bool,
    pub(crate) http_only: bool,
    pub(crate) same_site: Option<SameSite>,
    /// Seconds.
    pub(crate) max_age: Option<i64>,
    /// Unix seconds.
    pub(crate) expires: Option<i64>,
}

/// Longest attribute value considered (RFC 6265bis: longer ones are ignored).
const MAX_ATTR: usize = 1024;

fn trim_ws(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// Parses a `Set-Cookie` value; `None` when it is to be ignored.
pub(crate) fn parse_set_cookie(line: &str, max_bytes: usize) -> Option<SetCookie> {
    let (pair, attrs) = match line.split_once(';') {
        Some((p, a)) => (p, Some(a)),
        None => (line, None),
    };
    let (name, value) = match pair.split_once('=') {
        Some((n, v)) => (trim_ws(n), trim_ws(v)),
        None => ("", trim_ws(pair)),
    };
    if (name.is_empty() && value.is_empty())
        || name.len() + value.len() > max_bytes
        || name
            .bytes()
            .chain(value.bytes())
            .any(|b| b < 0x20 || b == 0x7f)
    {
        return None;
    }
    let mut c = SetCookie {
        name: name.to_owned(),
        value: value.to_owned(),
        ..SetCookie::default()
    };
    for av in attrs.into_iter().flat_map(|a| a.split(';')) {
        let (k, v) = match av.split_once('=') {
            Some((k, v)) => (trim_ws(k), trim_ws(v)),
            None => (trim_ws(av), ""),
        };
        if v.len() > MAX_ATTR {
            continue;
        }
        match k.to_ascii_lowercase().as_str() {
            "expires" => {
                if let Some(t) = parse_date(v) {
                    c.expires = Some(t);
                }
            }
            "max-age" => {
                let digits = v.strip_prefix('-').unwrap_or(v);
                if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                    let n: i64 = digits.parse().unwrap_or(i64::MAX);
                    c.max_age = Some(if v.starts_with('-') { -n.min(1) } else { n });
                }
            }
            "domain" => {
                if !v.is_empty() {
                    c.domain = Some(v.trim_start_matches('.').to_ascii_lowercase());
                }
            }
            "path" => c.path = Some(v.to_owned()),
            "secure" => c.secure = true,
            "httponly" => c.http_only = true,
            "samesite" => {
                c.same_site = match v.to_ascii_lowercase().as_str() {
                    "strict" => Some(SameSite::Strict),
                    "lax" => Some(SameSite::Lax),
                    "none" => Some(SameSite::None),
                    _ => None,
                };
            }
            _ => {}
        }
    }
    Some(c)
}

fn is_delim(b: u8) -> bool {
    matches!(b, 0x09 | 0x20..=0x2f | 0x3b..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e)
}

/// Leading digits of `t` (between `min` and `max` of them) when what follows is not a digit.
fn digits(t: &[u8], min: usize, max: usize) -> Option<(u32, &[u8])> {
    let n = t.iter().take_while(|b| b.is_ascii_digit()).count();
    if n < min || n > max {
        return None;
    }
    let v = t[..n]
        .iter()
        .fold(0u32, |a, b| a * 10 + u32::from(b - b'0'));
    Some((v, &t[n..]))
}

/// RFC 6265 section 5.1.1: a cookie date, as Unix seconds.
pub(crate) fn parse_date(s: &str) -> Option<i64> {
    let (mut time, mut day, mut month, mut year) = (None, None, None, None);
    for tok in s
        .as_bytes()
        .split(|&b| is_delim(b))
        .filter(|t| !t.is_empty())
    {
        if time.is_none() {
            // hms-time: 1*2DIGIT ":" 1*2DIGIT ":" 1*2DIGIT ( non-digit *OCTET )
            let hms = digits(tok, 1, 2).and_then(|(h, r)| {
                let r = r.strip_prefix(b":")?;
                let (m, r) = digits(r, 1, 2)?;
                let r = r.strip_prefix(b":")?;
                let (sec, _) = digits(r, 1, 2)?;
                Some((h, m, sec))
            });
            if hms.is_some() {
                time = hms;
                continue;
            }
        }
        if day.is_none() {
            if let Some((d, _)) = digits(tok, 1, 2) {
                day = Some(d);
                continue;
            }
        }
        if month.is_none() && tok.len() >= 3 {
            const MONTHS: [&[u8; 3]; 12] = [
                b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct",
                b"nov", b"dec",
            ];
            if let Some(i) = MONTHS
                .iter()
                .position(|m| tok[..3].eq_ignore_ascii_case(&m[..]))
            {
                month = Some(i as u32 + 1);
                continue;
            }
        }
        if year.is_none() {
            if let Some((y, _)) = digits(tok, 2, 4) {
                year = Some(y);
                continue;
            }
        }
    }
    let (h, mi, sec) = time?;
    let (d, mo, mut y) = (day?, month?, year?);
    if (70..=99).contains(&y) {
        y += 1900;
    } else if y <= 69 {
        y += 2000;
    }
    if !(1..=31).contains(&d) || y < 1601 || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if d > dim[mo as usize - 1] {
        return None;
    }
    let days = days_from_civil(i64::from(y), mo, d);
    Some(days * 86400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(sec))
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The fuzz entry (`cookie_parse`): parsing and storing never panic, and a stored cookie is
/// sent back to its own origin.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn fuzz(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_date(s);
    let (url, line) = s
        .split_once('\n')
        .unwrap_or(("https://a.example.com/x/y", s));
    let jar = CookieJar::new().with_limits(CookieLimits {
        max_cookie_bytes: 4096,
        max_per_domain: 3,
        max_cookies: 5,
    });
    let _ = jar.site(url);
    let now = 1_700_000_000;
    for l in line.split('\n') {
        if let Some(o) = origin(url) {
            jar.store_from(&o, l, now);
            let _ = jar.header_for(&o, "POST", true, now);
            let _ = jar.header_for(&o, "GET", false, now);
        }
    }
    assert!(jar.len() <= 5);
    assert!(jar.lock().cookies.values().all(|v| v.len() <= 3));
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z

    fn o(url: &str) -> Origin<'_> {
        origin(url).unwrap()
    }

    fn set(jar: &CookieJar, url: &str, line: &str) -> bool {
        jar.store_from(&o(url), line, NOW)
    }

    fn get(jar: &CookieJar, url: &str) -> Option<String> {
        jar.header_for(&o(url), "GET", false, NOW)
    }

    #[test]
    fn dates() {
        let t = |s| parse_date(s);
        assert_eq!(t("Sun, 06 Nov 1994 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(t("Sunday, 06-Nov-94 08:49:37 GMT"), Some(784_111_777));
        assert_eq!(t("Sun Nov  6 08:49:37 1994"), Some(784_111_777));
        assert_eq!(t("6 nov 1994 8:49:37"), Some(784_111_777));
        assert_eq!(t("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(t("Tue, 29 Feb 2000 00:00:00 GMT"), Some(951_782_400));
        assert_eq!(t("Wed, 09 Jun 2021 10:18:14 GMT"), Some(1_623_233_894));
        assert_eq!(t("Fri, 01 Jan 2038 00:00:00 GMT"), Some(2_145_916_800));
        assert_eq!(
            t("01 Jan 30 00:00:00"),
            Some(1_893_456_000),
            "2-digit year < 70"
        );
        for bad in [
            "Thu, 29 Feb 2001 00:00:00 GMT",
            "Thu, 32 Jan 2001 00:00:00 GMT",
            "Thu, 01 Jan 1600 00:00:00 GMT",
            "Thu, 01 Jan 2001 24:00:00 GMT",
            "Thu, 01 Foo 2001 00:00:00 GMT",
            "Thu, 01 Jan 2001",
            "",
        ] {
            assert_eq!(t(bad), None, "{bad}");
        }
    }

    #[test]
    fn set_cookie_parsing() {
        let p = parse_set_cookie(
            " a = b c ; Path=/x; Domain=.Example.COM; Secure; HttpOnly; SameSite=lax; Max-Age=60; foo",
            4096,
        )
        .unwrap();
        assert_eq!((p.name.as_str(), p.value.as_str()), ("a", "b c"));
        assert_eq!(p.domain.as_deref(), Some("example.com"));
        assert_eq!(p.path.as_deref(), Some("/x"));
        assert!(p.secure && p.http_only);
        assert_eq!((p.same_site, p.max_age), (Some(SameSite::Lax), Some(60)));
        let p = parse_set_cookie("novalue", 4096).unwrap();
        assert_eq!((p.name.as_str(), p.value.as_str()), ("", "novalue"));
        assert!(parse_set_cookie("=", 4096).is_none());
        assert!(parse_set_cookie("a=b\x01", 4096).is_none());
        assert!(parse_set_cookie(&format!("a={}", "x".repeat(4096)), 4096).is_none());
        assert_eq!(
            parse_set_cookie("a=b; Max-Age=-5", 4096).unwrap().max_age,
            Some(-1)
        );
        assert_eq!(
            parse_set_cookie("a=b; Max-Age=5x", 4096).unwrap().max_age,
            None
        );
        assert_eq!(
            parse_set_cookie("a=b; samesite=bogus", 4096)
                .unwrap()
                .same_site,
            None
        );
    }

    #[test]
    fn domain_rules() {
        let jar = CookieJar::new();
        let u = "http://www.example.com/";
        assert!(set(&jar, u, "a=1; Domain=example.com"));
        assert!(set(&jar, u, "b=2"));
        // Not a domain of the host, a sibling, or a public suffix.
        assert!(!set(&jar, u, "c=3; Domain=other.com"));
        assert!(!set(&jar, u, "c=3; Domain=api.example.com"));
        assert!(!set(&jar, u, "c=3; Domain=com"));
        assert!(!set(&jar, u, "c=3; Domain=example.com."));
        assert_eq!(get(&jar, "http://example.com/").as_deref(), Some("a=1"));
        assert_eq!(get(&jar, "http://x.y.example.com/").as_deref(), Some("a=1"));
        assert_eq!(
            get(&jar, "http://www.example.com/").as_deref(),
            Some("a=1; b=2")
        );
        assert_eq!(get(&jar, "http://notexample.com/"), None);
        // Single-label hosts: Domain must be the host itself (then host-only).
        assert!(set(&jar, "http://localhost:8080/", "l=1; Domain=localhost"));
        assert!(!set(&jar, "http://a.localhost/", "l=2; Domain=localhost"));
        assert_eq!(get(&jar, "http://localhost/").as_deref(), Some("l=1"));
        assert_eq!(get(&jar, "http://x.localhost/"), None);
        // IP hosts: host-only only.
        assert!(set(&jar, "http://10.0.0.1/", "i=1; Domain=10.0.0.1"));
        assert!(!set(&jar, "http://10.0.0.1/", "i=2; Domain=0.0.1"));
        assert!(!set(&jar, "http://10.0.0.1/", "i=2; Domain=1"));
        assert!(set(&jar, "http://[::1]:80/", "v6=1"));
        assert_eq!(get(&jar, "http://10.0.0.1/").as_deref(), Some("i=1"));
        assert_eq!(get(&jar, "http://110.0.0.1/"), None);
        assert_eq!(get(&jar, "http://[::1]/").as_deref(), Some("v6=1"));
        // A public suffix list.
        let jar = CookieJar::new().public_suffixes(|d| d == "co.uk" || d == "github.io");
        assert!(!set(&jar, "https://a.b.co.uk/", "x=1; Domain=co.uk"));
        assert!(set(&jar, "https://a.b.co.uk/", "x=1; Domain=b.co.uk"));
        assert!(!set(&jar, "https://me.github.io/", "x=1; Domain=github.io"));
        assert!(set(&jar, "https://github.io/", "y=1; Domain=github.io"));
        assert_eq!(get(&jar, "https://z.b.co.uk/").as_deref(), Some("x=1"));
        assert_eq!(get(&jar, "https://me.github.io/"), None, "host-only");
        assert_eq!(jar.site("a.b.co.uk"), "b.co.uk");
        assert_eq!(jar.site("me.github.io"), "me.github.io");
        assert_eq!(jar.site("co.uk"), "co.uk");
        assert_eq!(CookieJar::new().site("a.b.co.uk"), "co.uk");
        assert_eq!(CookieJar::new().site("[::1]"), "::1");
    }

    #[test]
    fn path_rules() {
        let jar = CookieJar::new();
        assert!(set(&jar, "http://h.test/a/b/c?q=1", "d=1"));
        assert!(set(&jar, "http://h.test/a/b/c", "e=1; Path=/a"));
        assert!(set(&jar, "http://h.test/a/b/c", "f=1; Path=relative"));
        assert!(set(&jar, "http://h.test/", "g=1; Path=/"));
        assert_eq!(
            get(&jar, "http://h.test/a/b/x").as_deref(),
            Some("d=1; f=1; e=1; g=1")
        );
        assert_eq!(get(&jar, "http://h.test/a/bc").as_deref(), Some("e=1; g=1"));
        assert_eq!(get(&jar, "http://h.test/ab").as_deref(), Some("g=1"));
        assert_eq!(get(&jar, "http://h.test").as_deref(), Some("g=1"));
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path("/x"), "/");
        assert_eq!(default_path("/x/"), "/x");
        assert_eq!(default_path(""), "/");
        assert!(path_match("/a/", "/a/"));
        assert!(path_match("/a/b", "/a/"));
        assert!(!path_match("/ab", "/a/"));
    }

    #[test]
    fn secure_and_prefixes() {
        let jar = CookieJar::new();
        assert!(
            !set(&jar, "http://h.test/", "s=1; Secure"),
            "Secure from http"
        );
        assert!(set(&jar, "https://h.test/", "s=1; Secure"));
        assert_eq!(get(&jar, "http://h.test/"), None);
        assert_eq!(get(&jar, "https://h.test/").as_deref(), Some("s=1"));
        // http cannot overwrite (or shadow) it.
        assert!(!set(&jar, "http://h.test/", "s=2"));
        assert!(set(&jar, "http://h.test/", "t=2"));
        assert!(!set(&jar, "https://h.test/", "__Secure-a=1"));
        assert!(set(&jar, "https://h.test/", "__Secure-a=1; Secure"));
        assert!(!set(&jar, "https://h.test/", "__Host-a=1; Secure; Path=/x"));
        assert!(!set(
            &jar,
            "https://www.h.test/",
            "__Host-a=1; Secure; Path=/; Domain=h.test"
        ));
        assert!(set(&jar, "https://h.test/", "__Host-a=1; Secure; Path=/"));
        assert!(!set(&jar, "https://h.test/", "n=1; SameSite=None"));
        assert!(set(&jar, "https://h.test/", "n=1; SameSite=None; Secure"));
        let c = jar.cookies();
        assert!(c.iter().any(|c| c.name == "s" && c.secure && c.host_only));
    }

    #[test]
    fn same_site_on_cross_site_chains() {
        let jar = CookieJar::new();
        let u = "https://b.test/";
        assert!(set(&jar, u, "strict=1; SameSite=Strict"));
        assert!(set(&jar, u, "lax=1; SameSite=Lax"));
        assert!(set(&jar, u, "none=1; SameSite=None; Secure"));
        assert!(set(&jar, u, "plain=1; HttpOnly"));
        let h = |m, cross| jar.header_for(&o(u), m, cross, NOW);
        assert_eq!(
            h("POST", false).as_deref(),
            Some("strict=1; lax=1; none=1; plain=1")
        );
        assert_eq!(h("GET", true).as_deref(), Some("lax=1; none=1; plain=1"));
        assert_eq!(h("POST", true).as_deref(), Some("none=1; plain=1"));
    }

    #[test]
    fn expiry_and_replacement() {
        let jar = CookieJar::new();
        let u = "http://h.test/";
        assert!(set(&jar, u, "a=1; Max-Age=10"));
        assert!(set(&jar, u, "b=1; Expires=Thu, 01 Jan 2099 00:00:00 GMT"));
        assert!(set(
            &jar,
            u,
            "c=1; Expires=Thu, 01 Jan 2099 00:00:00 GMT; Max-Age=0"
        ));
        assert!(set(&jar, u, "d=1; Expires=Thu, 01 Jan 2000 00:00:00 GMT"));
        assert_eq!(get(&jar, u).as_deref(), Some("a=1; b=1"));
        // Capped at 400 days.
        let b = jar
            .lock()
            .cookies
            .values()
            .flatten()
            .find(|s| s.c.name == "b")
            .unwrap()
            .c
            .clone();
        assert_eq!(
            b.expires,
            Some(to_system(NOW + MAX_AGE_CAP.as_secs() as i64))
        );
        // Later than the max age: gone.
        assert_eq!(
            jar.header_for(&o(u), "GET", false, NOW + 11).as_deref(),
            Some("b=1")
        );
        // Replace keeps the order (creation time); Max-Age=0 deletes.
        assert!(set(&jar, u, "e=1"));
        assert!(set(&jar, u, "b=2"));
        assert_eq!(get(&jar, u).as_deref(), Some("b=2; e=1"));
        assert!(set(&jar, u, "b=; Max-Age=0"));
        assert_eq!(get(&jar, u).as_deref(), Some("e=1"));
        assert_eq!(jar.len(), 1);
        jar.clear();
        assert!(jar.is_empty());
    }

    #[test]
    fn limits_evict_least_recently_used() {
        let jar = CookieJar::new().with_limits(CookieLimits {
            max_cookie_bytes: 16,
            max_per_domain: 3,
            max_cookies: 4,
        });
        let u = "http://a.test/";
        for i in 0..3 {
            assert!(set(&jar, u, &format!("c{i}=1")));
        }
        // Using c0 makes c1 the least recently used.
        assert!(jar.header_for(&o(u), "GET", false, NOW).is_some());
        let h = jar.header_for(&o(u), "GET", false, NOW);
        assert_eq!(h.as_deref(), Some("c0=1; c1=1; c2=1"));
        jar.lock()
            .cookies
            .get_mut("a.test")
            .unwrap()
            .iter_mut()
            .find(|s| s.c.name == "c0")
            .unwrap()
            .last_used += 100;
        assert!(set(&jar, u, "c3=1"));
        assert_eq!(get(&jar, u).as_deref(), Some("c0=1; c2=1; c3=1"));
        assert!(set(&jar, "http://b.test/", "x=1"));
        assert!(set(&jar, "http://b.test/", "y=1"));
        assert_eq!(jar.len(), 4);
        assert!(!set(&jar, u, "toolong=0123456789"));
        assert!(jar.lock().cookies.values().all(|v| v.len() <= 3));
    }

    #[test]
    fn urls() {
        let x = o("HTTPS://User@[::1]:8443/p/q?x#y");
        assert_eq!((x.secure, x.host.as_str(), x.path), (true, "::1", "/p/q"));
        let x = o("http://Example.COM.?q");
        assert_eq!(
            (x.secure, x.host.as_str(), x.path),
            (false, "example.com", "")
        );
        assert!(origin("ftp://x/").is_none());
        assert!(origin("http:///").is_none());
    }

    #[test]
    fn fuzz_seeds() {
        fuzz(b"https://a.example.com/x\nsid=1; Domain=example.com; Path=/; Max-Age=9\nb=2");
        fuzz(b"");
        fuzz("\u{0}\n=\n;;;=;Expires=1 1 1 1:1:1".as_bytes());
    }
}
