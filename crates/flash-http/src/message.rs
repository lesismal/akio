//! Requests, responses, headers.

use std::{net::SocketAddr, sync::Arc, time::SystemTime};

/// An HTTP request method.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// An empty set.
    pub fn new() -> Headers {
        Headers(Vec::new())
    }

    /// The first value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every value of `name`, in order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.0
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether a comma-separated header (such as `Connection`) lists `token`, ignoring case.
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name)
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    /// Adds a field after the existing ones.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.0.push((name.into(), value.into()));
    }

    /// Replaces every field called `name` with one.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        self.remove(&name);
        self.0.push((name, value.into()));
    }

    /// Removes every field called `name`.
    pub fn remove(&mut self, name: &str) {
        self.0.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }

    /// All fields in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no fields.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// HTTP version of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2 (requests that arrived on an h2 stream).
    Http2,
}

/// A parsed request, with its body fully received.
#[derive(Clone, Debug)]
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
pub struct FileBody {
    /// The open file.
    pub file: Arc<std::fs::File>,
    /// First byte to send.
    pub offset: u64,
    /// Number of bytes to send.
    pub len: u64,
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
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Response {
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
        use std::io::Write;
        let _ = write!(out, "HTTP/1.1 {} {}\r\n", self.status, reason(self.status));
        for (n, v) in self.headers.iter() {
            out.extend_from_slice(n.as_bytes());
            out.extend_from_slice(b": ");
            // Header injection guard: a value cannot contain a line break.
            out.extend(v.bytes().filter(|b| *b != b'\r' && *b != b'\n'));
            out.extend_from_slice(b"\r\n");
        }
        let bodyless = self.status < 200 || self.status == 204 || self.status == 304;
        if self.headers.get("Content-Length").is_none() && !bodyless && !self.streaming {
            let _ = write!(out, "Content-Length: {}\r\n", self.body_len());
        }
        if self.headers.get("Date").is_none() {
            out.extend_from_slice(b"Date: ");
            out.extend_from_slice(http_date().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if self.headers.get("Connection").is_none() {
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
pub(crate) fn http_date_now() -> String {
    http_date()
}

fn http_date() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    DATE.with(|c| {
        let mut c = c.borrow_mut();
        if c.0 != secs || c.1.is_empty() {
            *c = (secs, format_http_date(secs));
        }
        c.1.clone()
    })
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
