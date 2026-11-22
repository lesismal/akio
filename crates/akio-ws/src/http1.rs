//! Sans-io HTTP/1.x message head parser (RFC 9110, RFC 9112): request heads, response heads and
//! field blocks (chunked trailers). Zero-copy (names, values, method, target and reason borrow
//! the input), incremental (a [`Resume`] makes a head delivered in many reads cost O(n) in total)
//! and strict:
//!
//! * the method and field names are tokens; the request target is visible ASCII; field values
//!   are `field-vchar` / SP / HTAB / obs-text, with surrounding whitespace removed;
//! * exactly one SP between the request-line (and status-line) elements; the version is exactly
//!   `HTTP/1.0` or `HTTP/1.1` (another well-formed `HTTP/x.y` is [`Error::Version`]);
//! * lines end in CRLF or a bare LF (RFC 9112 §2.2); a bare CR, whitespace before a field's colon
//!   or before the first field, and obsolete line folding are rejected;
//! * empty lines before the start line are skipped (RFC 9112 §2.2);
//! * at most `headers.len()` fields ([`Error::TooManyHeaders`]); callers bound the head size.
//!
//! The first call examines every byte, so garbage is refused at once. Resumed calls look at new
//! bytes only once a line has ended (each line is validated exactly once, then the complete head
//! is parsed in one go); an invalid byte inside an unfinished line is reported when its line ends
//! or the caller's size limit is hit.
//!
//! Scanning goes 8 bytes at a time (SWAR on `u64`, safe code) for request targets and field
//! values, which are most of a head.
//!
//! akio-http (which sits above this crate in the dependency graph) parses its request heads, its
//! client's response heads and chunked trailers with it; akio-ws's client parses the handshake
//! response. `#[doc(hidden)]`: not a public API, it may change in any release.

use std::fmt;

/// A header field: `name` as sent (a token), `value` without surrounding whitespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'b> {
    /// The field name (a token: ASCII, never empty).
    pub name: &'b str,
    /// The field value (may hold obs-text bytes, so not necessarily UTF-8).
    pub value: &'b [u8],
}

impl Header<'_> {
    /// A placeholder to initialize header storage with.
    pub const EMPTY: Header<'static> = Header {
        name: "",
        value: b"",
    };
}

/// Why a head is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A malformed request-line or status-line (method, target, spacing, version, status code).
    StartLine,
    /// A well-formed HTTP version other than 1.0 and 1.1.
    Version,
    /// An empty or invalid field name, or whitespace before the colon or the first field.
    HeaderName,
    /// A control character in a field value.
    HeaderValue,
    /// Obsolete line folding (a field line starting with whitespace).
    ObsFold,
    /// A CR not followed by LF.
    NewLine,
    /// More fields than the storage holds.
    TooManyHeaders,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::StartLine => "malformed start line",
            Error::Version => "unsupported HTTP version",
            Error::HeaderName => "invalid header field name",
            Error::HeaderValue => "invalid header field value",
            Error::ObsFold => "obsolete line folding",
            Error::NewLine => "bare CR",
            Error::TooManyHeaders => "too many header fields",
        })
    }
}

impl std::error::Error for Error {}

/// The result of a parse that may need more bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status<T> {
    /// The head is complete.
    Complete(T),
    /// The input is a valid prefix of a head: more bytes are needed.
    Partial,
}

/// A parsed request head.
#[derive(Debug, PartialEq, Eq)]
pub struct Request<'b, 'h> {
    /// The method token.
    pub method: &'b str,
    /// The request target.
    pub target: &'b str,
    /// The minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub minor: u8,
    /// The header fields, in order.
    pub headers: &'h [Header<'b>],
    /// The length of the head, terminating empty line included.
    pub len: usize,
}

/// A parsed response head.
#[derive(Debug, PartialEq, Eq)]
pub struct Response<'b, 'h> {
    /// The minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub minor: u8,
    /// The status code (three digits).
    pub code: u16,
    /// The reason phrase; empty when absent or when it holds non-ASCII bytes.
    pub reason: &'b str,
    /// The header fields, in order.
    pub headers: &'h [Header<'b>],
    /// The length of the head, terminating empty line included.
    pub len: usize,
}

/// Progress kept between calls on a growing buffer, so that only new bytes are examined until
/// the head is complete. Reset it (or use a new one) for every head; the buffer passed must keep
/// the bytes it held before (it may only grow).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Resume {
    /// Bytes already examined (0: nothing known, parse from scratch).
    seen: usize,
    /// Start of the first field line not validated yet (0: the start line is not complete).
    line: usize,
    /// Fields validated before `line`.
    fields: usize,
}

type Step<T> = Result<Option<T>, Error>;

const fn token_table() -> [bool; 256] {
    let mut t = [false; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        t[i] = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            );
        i += 1;
    }
    t
}

/// `tchar` (RFC 9110 §5.6.2).
static TOKEN: [bool; 256] = token_table();

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

#[inline(always)]
fn word(b: &[u8], i: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(a)
}

/// High bit set in every byte of `w` that is below `n` (exact for the lowest such byte; `n` <= 128).
#[inline(always)]
const fn less(w: u64, n: u8) -> u64 {
    w.wrapping_sub(LO * n as u64) & !w & HI
}

/// High bit set in every byte of `w` equal to `n` (exact for the lowest such byte).
#[inline(always)]
const fn equal(w: u64, n: u8) -> u64 {
    let x = w ^ (LO * n as u64);
    x.wrapping_sub(LO) & !x & HI
}

/// The index of the first byte at or after `i` that is not visible ASCII (0x21..=0x7e), or
/// `b.len()`.
#[inline]
fn scan_target(b: &[u8], mut i: usize) -> usize {
    while i + 8 <= b.len() {
        let w = word(b, i);
        let bad = less(w, 0x21) | (w & HI) | equal(w, 0x7f);
        if bad != 0 {
            return i + (bad.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    while i < b.len() && matches!(b[i], 0x21..=0x7e) {
        i += 1;
    }
    i
}

/// The index of the first byte at or after `i` that may not appear in a field value (a control
/// character other than HTAB, or DEL), or `b.len()`.
#[inline]
fn scan_value(b: &[u8], mut i: usize) -> usize {
    loop {
        while i + 8 <= b.len() {
            let w = word(b, i);
            let bad = less(w, 0x20) | equal(w, 0x7f);
            if bad != 0 {
                i += (bad.trailing_zeros() / 8) as usize;
                break;
            }
            i += 8;
        }
        while i < b.len() {
            match b[i] {
                b'\t' => i += 1,
                0..=0x1f | 0x7f => return i,
                _ => {
                    i += 1;
                    if i + 8 <= b.len() {
                        break; // back to whole words
                    }
                }
            }
        }
        if i >= b.len() {
            return b.len();
        }
    }
}

/// The index of the first LF at or after `i`.
fn find_lf(b: &[u8], mut i: usize) -> Option<usize> {
    while i + 8 <= b.len() {
        let m = equal(word(b, i), b'\n');
        if m != 0 {
            return Some(i + (m.trailing_zeros() / 8) as usize);
        }
        i += 8;
    }
    b[i.min(b.len())..]
        .iter()
        .position(|&c| c == b'\n')
        .map(|k| i + k)
}

#[inline]
fn token(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && TOKEN[b[i] as usize] {
        i += 1;
    }
    i
}

/// ASCII bytes already validated as such.
#[inline]
fn ascii(b: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(b).map_err(|_| Error::StartLine)
}

/// The end of a line at `b[i]` (CRLF or LF): the index after it. `err` if `b[i]` is something
/// else.
#[inline]
fn eol(b: &[u8], i: usize, err: Error) -> Step<usize> {
    match b.get(i) {
        None => Ok(None),
        Some(b'\n') => Ok(Some(i + 1)),
        Some(b'\r') => match b.get(i + 1) {
            None => Ok(None),
            Some(b'\n') => Ok(Some(i + 2)),
            Some(_) => Err(Error::NewLine),
        },
        Some(_) => Err(err),
    }
}

fn skip_empty_lines(b: &[u8]) -> Step<usize> {
    let mut i = 0;
    loop {
        match b.get(i) {
            None => return Ok(None),
            Some(b'\n') => i += 1,
            Some(b'\r') => match b.get(i + 1) {
                None => return Ok(None),
                Some(b'\n') => i += 2,
                Some(_) => return Err(Error::NewLine),
            },
            Some(_) => return Ok(Some(i)),
        }
    }
}

/// `HTTP/1.0` or `HTTP/1.1` at `b[i]`: (minor, index after).
fn version(b: &[u8], i: usize) -> Step<(u8, usize)> {
    const SHAPE: &[u8; 8] = b"HTTP/d.d";
    let fits = |k: usize, c: u8| match SHAPE[k] {
        b'd' => c.is_ascii_digit(),
        s => s == c,
    };
    let rest = &b[i.min(b.len())..];
    if rest.len() < 8 {
        return if rest.iter().enumerate().all(|(k, &c)| fits(k, c)) {
            Ok(None)
        } else {
            Err(Error::StartLine)
        };
    }
    match &rest[..8] {
        b"HTTP/1.1" => Ok(Some((1, i + 8))),
        b"HTTP/1.0" => Ok(Some((0, i + 8))),
        v if v.iter().enumerate().all(|(k, &c)| fits(k, c)) => Err(Error::Version),
        _ => Err(Error::StartLine),
    }
}

/// `method SP request-target SP HTTP-version CRLF`: (method, target, minor, index after).
fn request_line(b: &[u8]) -> Step<(&str, &str, u8, usize)> {
    let Some(m0) = skip_empty_lines(b)? else {
        return Ok(None);
    };
    let m1 = token(b, m0);
    if m1 == b.len() {
        return Ok(None);
    }
    if m1 == m0 || b[m1] != b' ' {
        return Err(Error::StartLine);
    }
    let t0 = m1 + 1;
    let t1 = scan_target(b, t0);
    if t1 == b.len() {
        return Ok(None);
    }
    if t1 == t0 || b[t1] != b' ' {
        return Err(Error::StartLine);
    }
    let Some((minor, v1)) = version(b, t1 + 1)? else {
        return Ok(None);
    };
    let Some(next) = eol(b, v1, Error::StartLine)? else {
        return Ok(None);
    };
    Ok(Some((ascii(&b[m0..m1])?, ascii(&b[t0..t1])?, minor, next)))
}

/// `HTTP-version SP status-code [SP reason-phrase] CRLF`: (minor, code, reason, index after).
fn status_line(b: &[u8]) -> Step<(u8, u16, &str, usize)> {
    let Some(i) = skip_empty_lines(b)? else {
        return Ok(None);
    };
    let Some((minor, mut i)) = version(b, i)? else {
        return Ok(None);
    };
    match b.get(i) {
        None => return Ok(None),
        Some(b' ') => i += 1,
        Some(_) => return Err(Error::StartLine),
    }
    let mut code = 0u16;
    for _ in 0..3 {
        match b.get(i) {
            None => return Ok(None),
            Some(d) if d.is_ascii_digit() => code = code * 10 + u16::from(d - b'0'),
            Some(_) => return Err(Error::StartLine),
        }
        i += 1;
    }
    let (r0, r1) = match b.get(i) {
        None => return Ok(None),
        Some(b' ') => {
            let r1 = scan_value(b, i + 1);
            if r1 == b.len() {
                return Ok(None);
            }
            (i + 1, r1)
        }
        Some(_) => (i, i),
    };
    let Some(next) = eol(b, r1, Error::StartLine)? else {
        return Ok(None);
    };
    let reason = &b[r0..r1];
    let reason = if reason.is_ascii() {
        ascii(reason)?
    } else {
        ""
    };
    Ok(Some((minor, code, reason, next)))
}

enum Fields {
    /// The empty line was reached: (index after it, field count).
    Done(usize, usize),
    /// More bytes needed: (start of the incomplete line, fields before it).
    Partial(usize, usize),
}

/// Field lines from `b[i]` up to the empty line. `count` fields came before; at most `max` in
/// all. With `out` non-empty the fields are stored there (`out.len() >= max`).
fn fields<'b>(
    b: &'b [u8],
    mut i: usize,
    mut count: usize,
    max: usize,
    out: &mut [Header<'b>],
) -> Result<Fields, Error> {
    let store = !out.is_empty();
    loop {
        let line = i;
        match b.get(i) {
            None => return Ok(Fields::Partial(line, count)),
            Some(b'\n') => return Ok(Fields::Done(i + 1, count)),
            Some(b'\r') => {
                return match b.get(i + 1) {
                    None => Ok(Fields::Partial(line, count)),
                    Some(b'\n') => Ok(Fields::Done(i + 2, count)),
                    Some(_) => Err(Error::NewLine),
                };
            }
            Some(b' ' | b'\t') if count > 0 => return Err(Error::ObsFold),
            Some(_) => {}
        }
        let n1 = token(b, i);
        if n1 == b.len() {
            return Ok(Fields::Partial(line, count));
        }
        if n1 == i || b[n1] != b':' {
            return Err(Error::HeaderName);
        }
        let mut v0 = n1 + 1;
        while v0 < b.len() && matches!(b[v0], b' ' | b'\t') {
            v0 += 1;
        }
        let v1 = scan_value(b, v0);
        let Some(next) = eol(b, v1, Error::HeaderValue)? else {
            return Ok(Fields::Partial(line, count));
        };
        if count == max {
            return Err(Error::TooManyHeaders);
        }
        if store {
            let mut e = v1;
            while e > v0 && matches!(b[e - 1], b' ' | b'\t') {
                e -= 1;
            }
            out[count] = Header {
                name: std::str::from_utf8(&b[i..n1]).map_err(|_| Error::HeaderName)?,
                value: &b[v0..e],
            };
        }
        count += 1;
        i = next;
    }
}

impl Resume {
    /// Whether the head is certainly still incomplete, judging only bytes not examined yet.
    /// `Ok(false)`: parse from scratch now.
    fn still_partial(&mut self, b: &[u8], max: usize) -> Result<bool, Error> {
        if self.seen == 0 {
            return Ok(false);
        }
        if self.seen > b.len() {
            *self = Resume::default(); // not the same buffer: start over
            return Ok(false);
        }
        if find_lf(b, self.seen).is_none() {
            self.seen = b.len(); // no new line ended
            return Ok(true);
        }
        if self.line == 0 {
            return Ok(false); // the start line just ended: parse it all
        }
        match fields(b, self.line, self.fields, max, &mut [])? {
            Fields::Done(..) => Ok(false),
            Fields::Partial(line, count) => {
                *self = Resume {
                    seen: b.len(),
                    line,
                    fields: count,
                };
                Ok(true)
            }
        }
    }

    fn partial(&mut self, b: &[u8], line: usize, fields: usize) {
        *self = Resume {
            seen: b.len(),
            line,
            fields,
        };
    }
}

fn reset_on_error<T>(r: Result<T, Error>, resume: &mut Resume) -> Result<T, Error> {
    if r.is_err() {
        *resume = Resume::default();
    }
    r
}

/// Parses a request head from the start of `buf` into `headers` (which bounds the field count).
/// `resume` carries progress between calls on a growing `buf`; pass `&mut Resume::default()` for
/// a one-off parse.
pub fn parse_request<'b, 'h>(
    buf: &'b [u8],
    headers: &'h mut [Header<'b>],
    resume: &mut Resume,
) -> Result<Status<Request<'b, 'h>>, Error> {
    let r = parse_request_inner(buf, headers, resume);
    reset_on_error(r, resume)
}

fn parse_request_inner<'b, 'h>(
    buf: &'b [u8],
    headers: &'h mut [Header<'b>],
    resume: &mut Resume,
) -> Result<Status<Request<'b, 'h>>, Error> {
    if resume.still_partial(buf, headers.len())? {
        return Ok(Status::Partial);
    }
    let Some((method, target, minor, i)) = request_line(buf)? else {
        resume.partial(buf, 0, 0);
        return Ok(Status::Partial);
    };
    let max = headers.len();
    match fields(buf, i, 0, max, headers)? {
        Fields::Done(len, n) => {
            *resume = Resume::default();
            let headers: &'h [Header<'b>] = headers;
            Ok(Status::Complete(Request {
                method,
                target,
                minor,
                headers: &headers[..n],
                len,
            }))
        }
        Fields::Partial(line, count) => {
            resume.partial(buf, line, count);
            Ok(Status::Partial)
        }
    }
}

/// Parses a response head from the start of `buf` into `headers` (which bounds the field count).
/// See [`parse_request`] for `resume`.
pub fn parse_response<'b, 'h>(
    buf: &'b [u8],
    headers: &'h mut [Header<'b>],
    resume: &mut Resume,
) -> Result<Status<Response<'b, 'h>>, Error> {
    let r = parse_response_inner(buf, headers, resume);
    reset_on_error(r, resume)
}

fn parse_response_inner<'b, 'h>(
    buf: &'b [u8],
    headers: &'h mut [Header<'b>],
    resume: &mut Resume,
) -> Result<Status<Response<'b, 'h>>, Error> {
    if resume.still_partial(buf, headers.len())? {
        return Ok(Status::Partial);
    }
    let Some((minor, code, reason, i)) = status_line(buf)? else {
        resume.partial(buf, 0, 0);
        return Ok(Status::Partial);
    };
    let max = headers.len();
    match fields(buf, i, 0, max, headers)? {
        Fields::Done(len, n) => {
            *resume = Resume::default();
            let headers: &'h [Header<'b>] = headers;
            Ok(Status::Complete(Response {
                minor,
                code,
                reason,
                headers: &headers[..n],
                len,
            }))
        }
        Fields::Partial(line, count) => {
            resume.partial(buf, line, count);
            Ok(Status::Partial)
        }
    }
}

/// Parses field lines up to and including the empty line (a trailer section): (length, fields).
pub fn parse_fields<'b, 'h>(
    buf: &'b [u8],
    headers: &'h mut [Header<'b>],
) -> Result<Status<(usize, &'h [Header<'b>])>, Error> {
    let max = headers.len();
    match fields(buf, 0, 0, max, headers)? {
        Fields::Done(len, n) => {
            let headers: &'h [Header<'b>] = headers;
            Ok(Status::Complete((len, &headers[..n])))
        }
        Fields::Partial(..) => Ok(Status::Partial),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Parsed = (String, String, u8, Vec<(String, Vec<u8>)>, usize);

    fn req(b: &[u8]) -> Result<Status<Parsed>, Error> {
        let mut h = [Header::EMPTY; 8];
        Ok(match parse_request(b, &mut h, &mut Resume::default())? {
            Status::Partial => Status::Partial,
            Status::Complete(r) => Status::Complete((
                r.method.to_owned(),
                r.target.to_owned(),
                r.minor,
                r.headers
                    .iter()
                    .map(|h| (h.name.to_owned(), h.value.to_vec()))
                    .collect(),
                r.len,
            )),
        })
    }

    fn err(b: &[u8]) -> Error {
        req(b).expect_err(&String::from_utf8_lossy(b))
    }

    #[test]
    fn request_heads() {
        let wire = b"\r\nPOST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-E:\r\nX-T: \t v  w \t\r\n\r\nbody";
        let Status::Complete((m, t, v, h, n)) = req(wire).unwrap() else {
            panic!()
        };
        assert_eq!((m.as_str(), t.as_str(), v), ("POST", "/a?b=1", 1));
        assert_eq!(
            h,
            vec![
                ("Host".into(), b"x".to_vec()),
                ("X-E".into(), b"".to_vec()),
                ("X-T".into(), b"v  w".to_vec())
            ]
        );
        assert_eq!(&wire[n..], b"body");
        // Bare LF line ends, HTTP/1.0, obs-text in a value.
        let Status::Complete((_, _, v, h, _)) = req(b"GET * HTTP/1.0\nA: \xff\xfe\n\n").unwrap()
        else {
            panic!()
        };
        assert_eq!(v, 0);
        assert_eq!(h[0].1, b"\xff\xfe");
        // Every prefix of a valid head is partial.
        for k in 0..wire.len() - 4 {
            assert_eq!(req(&wire[..k]), Ok(Status::Partial), "prefix {k}");
        }
    }

    #[test]
    fn request_errors() {
        assert_eq!(err(b"GET / HTTP/2.0\r\n\r\n"), Error::Version);
        assert_eq!(err(b"GET / HTTP/1.10\r\n\r\n"), Error::StartLine);
        assert_eq!(err(b"GET / HTTX/1.1\r\n"), Error::StartLine);
        assert_eq!(err(b"GE\x01T / HTTP/1.1\r\n\r\n"), Error::StartLine);
        assert_eq!(
            err(b"GE\x01T"),
            Error::StartLine,
            "garbage is refused early"
        );
        assert_eq!(err(b"GET  / HTTP/1.1\r\n\r\n"), Error::StartLine);
        assert_eq!(err(b"GET /\xff HTTP/1.1\r\n\r\n"), Error::StartLine);
        assert_eq!(err(b"GET / HTTP/1.1 \r\n\r\n"), Error::StartLine);
        assert_eq!(err(b"GET /\r\n\r\n"), Error::StartLine, "HTTP/0.9");
        assert_eq!(err(b" GET / HTTP/1.1\r\n\r\n"), Error::StartLine);
        assert_eq!(err(b"\rGET / HTTP/1.1\r\n\r\n"), Error::NewLine);
        assert_eq!(err(b"GET / HTTP/1.1\rX: y\r\n\r\n"), Error::NewLine);
        assert_eq!(err(b"GET / HTTP/1.1\r\nA : b\r\n\r\n"), Error::HeaderName);
        assert_eq!(err(b"GET / HTTP/1.1\r\n A: b\r\n\r\n"), Error::HeaderName);
        assert_eq!(err(b"GET / HTTP/1.1\r\n: b\r\n\r\n"), Error::HeaderName);
        assert_eq!(
            err(b"GET / HTTP/1.1\r\nA\xc3: b\r\n\r\n"),
            Error::HeaderName
        );
        assert_eq!(err(b"GET / HTTP/1.1\r\nA: b\r\n c\r\n\r\n"), Error::ObsFold);
        assert_eq!(
            err(b"GET / HTTP/1.1\r\nA: b\x00c\r\n\r\n"),
            Error::HeaderValue
        );
        assert_eq!(
            err(b"GET / HTTP/1.1\r\nA: b\x7f\r\n\r\n"),
            Error::HeaderValue
        );
        assert_eq!(err(b"GET / HTTP/1.1\r\nA: b\rc\r\n\r\n"), Error::NewLine);
        assert_eq!(err(b"GET / HTTP/1.1\r\n\r\r\n"), Error::NewLine);
        let mut many = b"GET / HTTP/1.1\r\n".to_vec();
        for _ in 0..9 {
            many.extend_from_slice(b"A: b\r\n");
        }
        assert_eq!(err(&many), Error::TooManyHeaders, "before the head ends");
    }

    #[test]
    fn swar_scans_match_bytewise() {
        let mut v = vec![b'a'; 40];
        for pos in 0..40 {
            for bad in [0u8, b'\r', b'\n', 0x1f, 0x7f, b' ', 0x80, b'\t'] {
                let mut w = v.clone();
                w[pos] = bad;
                let t = w.iter().position(|c| !matches!(c, 0x21..=0x7e));
                assert_eq!(scan_target(&w, 0), t.unwrap_or(w.len()));
                let f = w
                    .iter()
                    .position(|&c| (c < 0x20 && c != b'\t') || c == 0x7f);
                assert_eq!(scan_value(&w, 0), f.unwrap_or(w.len()), "{pos} {bad}");
                assert_eq!(find_lf(&w, 0), w.iter().position(|&c| c == b'\n'));
            }
        }
        v[3] = b'\t';
        v[20] = b'\t';
        v[33] = b'\r';
        assert_eq!(scan_value(&v, 0), 33);
    }

    #[test]
    fn responses_and_trailers() {
        let mut h = [Header::EMPTY; 4];
        let r = parse_response(
            b"HTTP/1.1 404 Not  Found\r\nA: b\r\n\r\n",
            &mut h,
            &mut Resume::default(),
        );
        let Ok(Status::Complete(r)) = r else { panic!() };
        assert_eq!(
            (r.minor, r.code, r.reason, r.headers.len()),
            (1, 404, "Not  Found", 1)
        );
        for (wire, reason) in [
            (&b"HTTP/1.0 200\r\n\r\n"[..], ""),
            (b"HTTP/1.1 200 \r\n\r\n", ""),
            (b"HTTP/1.1 200 \xffk\r\n\r\n", ""),
        ] {
            let Ok(Status::Complete(r)) = parse_response(wire, &mut h, &mut Resume::default())
            else {
                panic!()
            };
            assert_eq!((r.code, r.reason, r.len), (200, reason, wire.len()));
        }
        for bad in [
            &b"HTTP/1.1 20 OK\r\n\r\n"[..],
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1  200 OK\r\n\r\n",
            b"HTTP/1.1 200 O\x01K\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nA: b\r\n\tc\r\n\r\n",
            b"ICY 200 OK\r\n\r\n",
        ] {
            assert!(
                parse_response(bad, &mut h, &mut Resume::default()).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let Ok(Status::Complete((n, f))) = parse_fields(b"X-Sum: 1\r\n\r\nrest", &mut h) else {
            panic!()
        };
        assert_eq!((n, f.len(), f[0].value), (12, 1, &b"1"[..]));
        assert_eq!(
            parse_fields(b"\r\n", &mut h),
            Ok(Status::Complete((2, &[][..])))
        );
    }

    #[test]
    fn resumed_parsing_matches_one_shot() {
        let wire: &[u8] = b"GET /x HTTP/1.1\r\nHost: a\r\nB: c\r\nD: e\r\n\r\nNEXT";
        let mut h = [Header::EMPTY; 8];
        let one = {
            let Ok(Status::Complete(r)) = parse_request(wire, &mut h, &mut Resume::default())
            else {
                panic!()
            };
            (r.target.to_owned(), r.headers.len(), r.len)
        };
        for step in 1..8 {
            let mut resume = Resume::default();
            let mut end = 0;
            let got = loop {
                end = (end + step).min(wire.len());
                let mut h = [Header::EMPTY; 8];
                match parse_request(&wire[..end], &mut h, &mut resume).unwrap() {
                    Status::Partial => assert!(end < wire.len()),
                    Status::Complete(r) => break (r.target.to_owned(), r.headers.len(), r.len),
                }
            };
            assert_eq!(got, one, "step {step}");
            assert_eq!(resume, Resume::default());
        }
        // Errors in later lines are still found when resuming, and the field count carries over.
        let mut resume = Resume::default();
        let mut h = [Header::EMPTY; 2];
        let b = b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n";
        assert_eq!(
            parse_request(&b[..20], &mut h, &mut resume),
            Ok(Status::Partial)
        );
        assert_eq!(parse_request(b, &mut h, &mut resume), Ok(Status::Partial));
        let mut c = b.to_vec();
        c.extend_from_slice(b"C: 3\r\n");
        assert_eq!(
            parse_request(&c, &mut h, &mut resume),
            Err(Error::TooManyHeaders)
        );
        let mut resume = Resume::default();
        assert_eq!(
            parse_request(&b[..20], &mut h, &mut resume),
            Ok(Status::Partial)
        );
        assert_eq!(
            parse_request(b"GET / HTTP/1.1\r\nA: 1\r\n\x01", &mut h, &mut resume),
            Err(Error::HeaderName)
        );
    }
}
