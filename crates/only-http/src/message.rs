//! Requests, responses, headers.

use std::{net::SocketAddr, sync::Arc, time::SystemTime};

/// An HTTP request method.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// GET
    Get,
    /// HEAD
    Head,
    /// POST
    Post,
    /// PUT
    Put,
    /// DELETE
    Delete,
    /// PATCH
    Patch,
    /// OPTIONS
    Options,
    /// CONNECT
    Connect,
    /// TRACE
    Trace,
    /// Anything else, as sent (case-sensitive).
    Other(String),
}

impl Method {
    /// Parses a method token.
    pub fn parse(s: &str) -> Method {
        match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "PATCH" => Method::Patch,
            "OPTIONS" => Method::Options,
            "CONNECT" => Method::Connect,
            "TRACE" => Method::Trace,
            other => Method::Other(other.to_owned()),
        }
    }

    /// The method as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
            Method::Options => "OPTIONS",
            Method::Connect => "CONNECT",
            Method::Trace => "TRACE",
            Method::Other(s) => s,
        }
    }
}

/// HTTP header fields: ordered, names compared case-insensitively, duplicates allowed.
///
/// All names and values live in one string, so a set of fields costs two allocations however
/// many fields it holds (a parsed request head used to cost two per field).
#[derive(Clone, Default)]
pub struct Headers {
    buf: String,
    /// Per field: name at `buf[.0...1]`, value at `buf[.1...2]`.
    fields: Vec<(usize, usize, usize)>,
}

impl Headers {
    /// An empty set.
    pub fn new() -> Headers {
        Headers::default()
    }

    /// An empty set with room for `fields` fields totalling `bytes` bytes of names and values.
    pub fn with_capacity(fields: usize, bytes: usize) -> Headers {
        Headers {
            buf: String::with_capacity(bytes),
            fields: Vec::with_capacity(fields),
        }
    }

    #[inline]
    fn field(&self, f: &(usize, usize, usize)) -> (&str, &str) {
        (&self.buf[f.0..f.1], &self.buf[f.1..f.2])
    }

    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Every value of `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Whether a comma-separated header (such as `Connection`) lists `token`, ignoring case.
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// Adds a field after the existing ones.
    pub fn append(&mut self, name: impl AsRef<str>, value: impl AsRef<str>) {
        let a = self.buf.len();
        self.buf.push_str(name.as_ref());
        let b = self.buf.len();
        self.buf.push_str(value.as_ref());
        self.fields.push((a, b, self.buf.len()));
    }

    /// Replaces every field called `name` with one.
    pub fn set(&mut self, name: impl AsRef<str>, value: impl AsRef<str>) {
        let name = name.as_ref();
        self.remove(name);
        self.append(name, value);
    }

    /// Removes every field called `name`.
    pub fn remove(&mut self, name: &str) {
        let before = self.fields.len();
        let buf = &self.buf;
        self.fields
            .retain(|f| !buf[f.0..f.1].eq_ignore_ascii_case(name));
        if self.fields.len() == before {
            return;
        }
        // Reclaim the removed bytes once they are most of the buffer.
        let live: usize = self.fields.iter().map(|f| f.2 - f.0).sum();
        if self.buf.len() > 2 * live + 256 {
            let mut c = Headers::with_capacity(self.fields.len(), live);
            for (n, v) in self.iter() {
                c.append(n, v);
            }
            *self = c;
        }
    }

    /// All fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|f| self.field(f))
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether there are no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl PartialEq for Headers {
    fn eq(&self, other: &Headers) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Headers {}

impl std::fmt::Debug for Headers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// HTTP version of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2 (requests that arrived on an h2 stream).
    Http2,
    /// HTTP/3 (requests that arrived on a QUIC stream, see `only-h3`).
    Http3,
}

/// A parsed request, with its body fully received.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Request {
    /// Request method.
    pub method: Method,
    /// The request target exactly as sent (`/a/b?x=1`).
    pub target: String,
    /// Protocol version.
    pub version: Version,
    /// Header fields.
    pub headers: Headers,
    /// Trailer fields of a chunked body.
    pub trailers: Headers,
    /// The body (decoded if it was chunked).
    pub body: Vec<u8>,
    /// The peer's address.
    pub peer: SocketAddr,
}

impl Request {
    /// A request with `method` for `target` (`/a/b?x=1`): HTTP/1.1, no headers, an empty body
    /// and an unspecified peer address. Handy for testing services; set the other fields as
    /// needed.
    pub fn new(method: Method, target: impl Into<String>) -> Request {
        Request {
            method,
            target: target.into(),
            version: Version::Http11,
            headers: Headers::new(),
            trailers: Headers::new(),
            body: Vec::new(),
            peer: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }

    /// The path of the target, without the query.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    /// The query string, without the `?`.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }

    /// The value of query parameter `key` (not percent-decoded).
    pub fn query_param(&self, key: &str) -> Option<&str> {
        self.query()?
            .split('&')
            .filter_map(|kv| kv.split_once('=').or(Some((kv, ""))))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }
}

/// A response to send.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header fields. `Content-Length`, `Date` and `Connection` are added when encoding unless
    /// present.
    pub headers: Headers,
    /// The body.
    pub body: Vec<u8>,
    /// A file to send after the head instead of `body` (sent with `sendfile(2)` on plain TCP).
    pub file: Option<FileBody>,
    /// The body is streamed: no `Content-Length` is added.
    pub(crate) streaming: bool,
    /// Trailer fields sent after the body (HTTP/2; ignored on HTTP/1).
    pub trailers: Option<Headers>,
}

/// A byte range of an open file used as a response body.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FileBody {
    /// The open file.
    pub file: Arc<std::fs::File>,
    /// First byte to send.
    pub offset: u64,
    /// Number of bytes to send.
    pub len: u64,
}

impl FileBody {
    /// `len` bytes of `file` starting at `offset`.
    pub fn new(file: Arc<std::fs::File>, offset: u64, len: u64) -> FileBody {
        FileBody { file, offset, len }
    }
}

impl Response {
    /// An empty response with `status`.
    pub fn new(status: u16) -> Response {
        Response {
            status,
            headers: Headers::new(),
            body: Vec::new(),
            file: None,
            streaming: false,
            trailers: None,
        }
    }

    /// A response whose body is `len` bytes of `file` from `offset`.
    pub fn from_file(status: u16, content_type: &str, file: FileBody) -> Response {
        let mut r = Response::new(status);
        r.headers.set("Content-Type", content_type);
        r.file = Some(file);
        r
    }

    /// Body length, whichever way the body is held.
    pub fn body_len(&self) -> u64 {
        self.file.as_ref().map_or(self.body.len() as u64, |f| f.len)
    }

    /// A `text/plain; charset=utf-8` response.
    pub fn text(status: u16, body: impl Into<String>) -> Response {
        let mut r = Response::new(status);
        r.headers.set("Content-Type", "text/plain; charset=utf-8");
        r.body = body.into().into_bytes();
        r
    }

    /// A response with the given content type and body.
    pub fn with_body(status: u16, content_type: &str, body: Vec<u8>) -> Response {
        let mut r = Response::new(status);
        r.headers.set("Content-Type", content_type);
        r.body = body;
        r
    }

    /// Sets a header, replacing earlier ones of that name.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl AsRef<str>) -> Response {
        self.headers.set(name, value);
        self
    }

    /// Serialises the response. `head_only` omits the body (HEAD) but keeps its length.
    pub(crate) fn encode(
        &self,
        version: Version,
        keep_alive: bool,
        head_only: bool,
        out: &mut Vec<u8>,
    ) {
        out.extend_from_slice(b"HTTP/1.1 ");
        push_uint(out, u64::from(self.status));
        out.push(b' ');
        out.extend_from_slice(reason(self.status).as_bytes());
        out.extend_from_slice(b"\r\n");
        let (mut has_len, mut has_date, mut has_conn) = (false, false, false);
        for (n, v) in self.headers.iter() {
            has_len |= n.eq_ignore_ascii_case("content-length");
            has_date |= n.eq_ignore_ascii_case("date");
            has_conn |= n.eq_ignore_ascii_case("connection");
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            // Header injection guard: a value cannot contain a line break.
            if v.contains(['\r', '\n']) {
                out.extend(v.bytes().filter(|b| *b != b'\r' && *b != b'\n'));
            } else {
                out.extend_from_slice(v.as_bytes());
            }
            out.extend_from_slice(b"\r\n");
        }
        let bodyless = self.status < 200 || self.status == 204 || self.status == 304;
        if !has_len && !bodyless && !self.streaming {
            out.extend_from_slice(b"Content-Length: ");
            push_uint(out, self.body_len());
            out.extend_from_slice(b"\r\n");
        }
        if !has_date {
            out.extend_from_slice(b"Date: ");
            with_http_date(|d| out.extend_from_slice(d.as_bytes()));
            out.extend_from_slice(b"\r\n");
        }
        if !has_conn {
            if !keep_alive {
                out.extend_from_slice(b"Connection: close\r\n");
            } else if version == Version::Http10 {
                out.extend_from_slice(b"Connection: keep-alive\r\n");
            }
        }
        out.extend_from_slice(b"\r\n");
        if !head_only && !bodyless {
            out.extend_from_slice(&self.body);
        }
    }
}

/// The standard reason phrase of a status code.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        417 => "Expectation Failed",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

thread_local! {
    static DATE: std::cell::RefCell<(u64, String)> = const { std::cell::RefCell::new((0, String::new())) };
}

/// The current time as an IMF-fixdate, cached for the current second.
pub fn http_date_now() -> String {
    with_http_date(str::to_owned)
}

/// Calls `f` with the current IMF-fixdate (cached per thread for the current second, so a
/// response costs no formatting and no allocation for it).
pub(crate) fn with_http_date<R>(f: impl FnOnce(&str) -> R) -> R {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    DATE.with(|c| {
        let mut c = c.borrow_mut();
        if c.0 != secs || c.1.is_empty() {
            *c = (secs, format_http_date(secs));
        }
        f(&c.1)
    })
}

/// Appends `n` in decimal.
pub(crate) fn push_uint(out: &mut Vec<u8>, mut n: u64) {
    let mut b = [0u8; 20];
    let mut i = b.len();
    loop {
        i -= 1;
        b[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&b[i..]);
}

/// Formats seconds since the Unix epoch as `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn format_http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_matches_rfc_example() {
        // RFC 7231: Sun, 06 Nov 1994 08:49:37 GMT
        assert_eq!(
            format_http_date(784_111_777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            format_http_date(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
    }

    #[test]
    fn push_uint_and_header_storage() {
        for n in [0u64, 7, 10, 200, 65535, u64::MAX] {
            let mut v = Vec::new();
            push_uint(&mut v, n);
            assert_eq!(v, n.to_string().as_bytes());
        }
        let mut h = Headers::with_capacity(2, 16);
        for i in 0..200 {
            h.set("X-Count", i.to_string()); // repeated set: removed bytes are reclaimed
        }
        h.append("Accept", "*/*");
        assert_eq!(h.get("x-count"), Some("199"));
        assert_eq!(h.len(), 2);
        assert!(h.buf.len() < 1024, "{}", h.buf.len());
        let mut g = Headers::new();
        g.append("x-count", "199");
        assert_ne!(h, g);
        g.append("Accept", "*/*");
        h.remove("Accept");
        g.remove("accept");
        assert_eq!(h.iter().collect::<Vec<_>>(), [("X-Count", "199")]);
        assert_eq!(format!("{h:?}"), r#"[("X-Count", "199")]"#);
    }

    #[test]
    fn headers_are_case_insensitive_and_ordered() {
        let mut h = Headers::new();
        h.append("Accept", "a");
        h.append("accept", "b");
        h.append("Connection", "Keep-Alive, Upgrade");
        assert_eq!(h.get("ACCEPT"), Some("a"));
        assert_eq!(h.get_all("accept").collect::<Vec<_>>(), ["a", "b"]);
        assert!(h.has_token("connection", "upgrade"));
        assert!(!h.has_token("connection", "close"));
        h.set("accept", "c");
        assert_eq!(h.get_all("Accept").collect::<Vec<_>>(), ["c"]);
    }

    #[test]
    fn query_params() {
        let r = Request {
            method: Method::Get,
            target: "/a/b?x=1&y&z=3".into(),
            version: Version::Http11,
            headers: Headers::new(),
            trailers: Headers::new(),
            body: vec![],
            peer: "127.0.0.1:1".parse().unwrap(),
        };
        assert_eq!(r.path(), "/a/b");
        assert_eq!(r.query_param("x"), Some("1"));
        assert_eq!(r.query_param("y"), Some(""));
        assert_eq!(r.query_param("z"), Some("3"));
        assert_eq!(r.query_param("w"), None);
    }

    #[test]
    fn encode_adds_framing_and_strips_line_breaks() {
        let r = Response::text(200, "hi").header("X-A", "a\r\nInjected: 1");
        let mut out = Vec::new();
        r.encode(Version::Http11, true, false, &mut out);
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.contains("X-A: aInjected: 1\r\n"));
        assert!(!s.contains("\r\nInjected"));
        assert!(s.ends_with("\r\n\r\nhi"));
        let mut out = Vec::new();
        r.encode(Version::Http11, false, true, &mut out);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Connection: close\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.ends_with("\r\n\r\n"), "HEAD has no body");
    }
}

/// Decodes `%XX` escapes (and nothing else, so `+` stays `+`). `None` if an escape is malformed
/// or the result is not UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod percent_tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b%2Fc+d").as_deref(), Some("a b/c+d"));
        assert_eq!(percent_decode("%E2%82%AC").as_deref(), Some("€"));
        assert_eq!(percent_decode("100%"), None);
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%ff"), None, "not UTF-8");
    }
}
