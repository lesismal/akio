//! Sans-io request parsing: the head (via `akio_ws::http1`) and chunked bodies.

use akio_ws::http1::{self, Header, Resume};

use crate::message::{Headers, Method, Spare, Version};

/// A parsed request head.
#[derive(Debug)]
pub(crate) struct Head {
    pub method: Method,
    /// The target in origin form (`/a?b`), `*` (`OPTIONS`) or a `CONNECT`'s authority: a target
    /// in absolute form is given here by its path and query (see [`absolute_form`]).
    pub target: String,
    /// The target as sent when it was in absolute form (`http://a.example/b?c`), else `None`.
    pub absolute: Option<Box<str>>,
    pub version: Version,
    pub headers: Headers,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// Malformed request (400).
    Bad,
    /// More header fields than allowed (431).
    TooManyHeaders,
    /// HTTP version other than 1.0/1.1 (505).
    Version,
}

/// Parses a head from `buf`. `Ok(None)`: incomplete. `Ok(Some((head, n)))`: `n` bytes consumed.
/// `resume` carries the progress over calls on the same growing buffer (see [`Resume`]).
pub(crate) fn parse_head(
    buf: &[u8],
    resume: &mut Resume,
) -> Result<Option<(Head, usize)>, ParseError> {
    // Most heads have a handful of fields: try with room for 32 (filling the storage costs per
    // request), and only parse again with room for the limit when that is not enough. A failed
    // parse resets `resume`, so the second one starts from scratch.
    const FEW_HEADERS: usize = 32;
    const MAX_HEADERS: usize = 100;
    let mut few = [Header::EMPTY; FEW_HEADERS];
    match http1::parse_request(buf, &mut few, resume) {
        Ok(http1::Status::Complete(r)) => return head(r),
        Ok(http1::Status::Partial) => return Ok(None),
        Err(http1::Error::TooManyHeaders) => {}
        Err(e) => return Err(parse_error(e)),
    }
    let mut storage = [Header::EMPTY; MAX_HEADERS];
    match http1::parse_request(buf, &mut storage, resume) {
        Ok(http1::Status::Complete(r)) => head(r),
        Ok(http1::Status::Partial) => Ok(None),
        Err(e) => Err(parse_error(e)),
    }
}

fn parse_error(e: http1::Error) -> ParseError {
    match e {
        http1::Error::TooManyHeaders => ParseError::TooManyHeaders,
        http1::Error::Version => ParseError::Version,
        _ => ParseError::Bad,
    }
}

fn head(req: http1::Request<'_, '_>) -> Result<Option<(Head, usize)>, ParseError> {
    let version = if req.minor == 0 {
        Version::Http10
    } else {
        Version::Http11
    };
    let bytes = req
        .headers
        .iter()
        .map(|h| h.name.len() + h.value.len())
        .sum();
    let mut headers = Headers::spare(Spare::Req, req.headers.len(), bytes);
    for h in req.headers {
        // Header values must be text we can hand out as `&str`.
        let v = std::str::from_utf8(h.value).map_err(|_| ParseError::Bad)?;
        headers.append(h.name, v);
    }
    let method = Method::parse(req.method);
    let (target, absolute) = target(&method, req.target)?;
    Ok(Some((
        Head {
            method,
            target,
            absolute,
            version,
            headers,
        },
        req.len,
    )))
}

/// The request's target and, for one in absolute form, the target as sent (RFC 9112 §3.2): a
/// target in origin form (`/a?b`) is taken as it is, as is `*` for `OPTIONS` and any target of
/// a `CONNECT` (authority form, which the service checks). One in absolute form
/// (`http://a.example/b?c`) is taken as an origin server takes it (§3.2.2): by its path and query
/// (`/b?c`, `/` for an empty path), its authority becoming the request's `Host` (see
/// `Session::on_head`). Any other target, authority form included, is refused (400): routed by
/// a target that is not a path, a request would miss the routes of the path a proxy forwards it
/// to (akit A200).
fn target(method: &Method, target: &str) -> Result<(String, Option<Box<str>>), ParseError> {
    if target.starts_with('/')
        || *method == Method::Connect
        || (target == "*" && *method == Method::Options)
    {
        return Ok((crate::context::new_target(target), None));
    }
    let Some((_, rest)) = absolute_form(target) else {
        return Err(ParseError::Bad);
    };
    let mut t = crate::context::new_target("");
    if !rest.starts_with('/') {
        t.push('/');
    }
    t.push_str(rest);
    Ok((t, Some(target.into())))
}

/// The host and the rest of a request target in absolute form, `scheme "://" authority
/// path-abempty [ "?" query ]` (RFC 9112 §3.2.2, RFC 3986 §3): the host is the authority without
/// its user information (`a.example:8080` of `http://u@a.example:8080/b`), the rest what follows
/// the authority (`/b?c`, `?c` or empty). `None` when `target` is not in absolute form, or its
/// host is empty (RFC 9110 §4.2.1) or has a byte RFC 3986 does not allow in a host and port.
pub(crate) fn absolute_form(target: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = target.split_once("://")?;
    let mut b = scheme.bytes();
    if !b.next()?.is_ascii_alphabetic()
        || !b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, rest) = rest.split_at(end);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // reg-name / IP-literal / IPv4address, then `:` port: unreserved, pct-encoded, sub-delims,
    // `:`, `[` and `]`.
    let host_byte = |c: u8| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'%'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'['
                    | b']'
            )
    };
    if host.is_empty() || !host.bytes().all(host_byte) || host.starts_with(':') {
        return None;
    }
    Some((host, rest))
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChunkError {
    /// Malformed chunk framing.
    Bad,
    /// The decoded body would exceed the limit.
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    /// Reading the hex size.
    Size,
    /// Skipping a chunk extension up to the line end.
    Ext,
    /// Expecting LF after the size line's CR.
    SizeLf,
    /// Chunk data, this many bytes left.
    Data(u64),
    /// Expecting CR after data.
    DataCr,
    /// Expecting LF after data.
    DataLf,
    /// After the zero chunk: trailer lines until an empty line.
    Trailer,
    Done,
}

/// Incremental decoder for `Transfer-Encoding: chunked` bodies.
#[derive(Debug)]
pub(crate) struct ChunkDecoder {
    st: St,
    size: u64,
    digits: u8,
    trailer: Vec<u8>,
}

const MAX_TRAILER_BYTES: usize = 8 << 10;

impl ChunkDecoder {
    pub(crate) fn new() -> ChunkDecoder {
        ChunkDecoder {
            st: St::Size,
            size: 0,
            digits: 0,
            trailer: Vec::new(),
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.st == St::Done
    }

    /// Trailer fields received after the last chunk.
    pub(crate) fn trailers(&self) -> Headers {
        let mut h = Headers::new();
        let mut storage = [Header::EMPTY; 32];
        if let Ok(http1::Status::Complete((_, parsed))) =
            http1::parse_fields(&self.trailer, &mut storage)
        {
            for t in parsed {
                if let Ok(v) = std::str::from_utf8(t.value) {
                    h.append(t.name, v);
                }
            }
        }
        h
    }

    /// Consumes bytes from `input`, appending decoded data to `out` (which may grow to
    /// `max_total` bytes). Returns how many bytes were used; the decoder is [`done`](Self::is_done)
    /// once the terminating empty line has been seen, even if `input` has more (the next request).
    pub(crate) fn feed(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
        max_total: usize,
    ) -> Result<usize, ChunkError> {
        let mut i = 0;
        while i < input.len() && self.st != St::Done {
            let b = input[i];
            match self.st {
                St::Size => {
                    if let Some(d) = (b as char).to_digit(16) {
                        self.digits += 1;
                        if self.digits > 15 {
                            return Err(ChunkError::Bad);
                        }
                        self.size = self.size * 16 + u64::from(d);
                        i += 1;
                    } else if self.digits == 0 {
                        return Err(ChunkError::Bad);
                    } else if b == b';' || b == b' ' || b == b'\t' {
                        self.st = St::Ext;
                        i += 1;
                    } else if b == b'\r' {
                        self.st = St::SizeLf;
                        i += 1;
                    } else {
                        return Err(ChunkError::Bad);
                    }
                }
                St::Ext => {
                    if b == b'\r' {
                        self.st = St::SizeLf;
                    }
                    i += 1;
                }
                St::SizeLf => {
                    if b != b'\n' {
                        return Err(ChunkError::Bad);
                    }
                    i += 1;
                    self.digits = 0;
                    if self.size == 0 {
                        self.st = St::Trailer;
                    } else {
                        self.st = St::Data(self.size);
                    }
                    self.size = 0;
                }
                St::Data(left) => {
                    let n = (input.len() - i).min(left as usize);
                    if out.len() + n > max_total {
                        return Err(ChunkError::TooLarge);
                    }
                    out.extend_from_slice(&input[i..i + n]);
                    i += n;
                    let left = left - n as u64;
                    self.st = if left == 0 {
                        St::DataCr
                    } else {
                        St::Data(left)
                    };
                }
                St::DataCr => {
                    if b != b'\r' {
                        return Err(ChunkError::Bad);
                    }
                    self.st = St::DataLf;
                    i += 1;
                }
                St::DataLf => {
                    if b != b'\n' {
                        return Err(ChunkError::Bad);
                    }
                    self.st = St::Size;
                    i += 1;
                }
                St::Trailer => {
                    self.trailer.push(b);
                    i += 1;
                    if self.trailer.len() > MAX_TRAILER_BYTES {
                        return Err(ChunkError::Bad);
                    }
                    // An empty line (just CRLF at the start, or CRLFCRLF after fields) ends it.
                    if self.trailer == b"\r\n" {
                        self.trailer.clear();
                        self.st = St::Done;
                    } else if self.trailer.ends_with(b"\r\n\r\n") {
                        self.st = St::Done;
                    }
                }
                St::Done => unreachable!(),
            }
        }
        Ok(i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(wire: &[u8], split: usize) -> (Vec<u8>, Headers, usize) {
        let mut d = ChunkDecoder::new();
        let mut out = Vec::new();
        let mut used = 0;
        // Feed in pieces of `split` bytes to prove the decoder is incremental.
        for piece in wire.chunks(split.max(1)) {
            used += d.feed(piece, &mut out, 1 << 20).unwrap();
            if d.is_done() {
                break;
            }
        }
        assert!(d.is_done());
        (out, d.trailers(), used)
    }

    #[test]
    fn decodes_chunks_extensions_and_trailers_at_any_split() {
        let wire = b"5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: 42\r\nX-B: b\r\n\r\nGET /next";
        let body_end = wire.len() - b"GET /next".len();
        for split in 1..=wire.len() {
            let (out, trailers, used) = decode_all(wire, split);
            assert_eq!(out, b"hello world", "split {split}");
            assert_eq!(trailers.get("x-sum"), Some("42"));
            assert_eq!(trailers.get("x-b"), Some("b"));
            // Never reads into the next pipelined request.
            assert!(used <= body_end + (split - 1), "split {split} used {used}");
            if split >= wire.len() {
                assert_eq!(used, body_end);
            }
        }
    }

    #[test]
    fn no_trailers_ends_at_the_empty_line() {
        let (out, trailers, used) = decode_all(b"3\r\nabc\r\n0\r\n\r\nrest", 64);
        assert_eq!(out, b"abc");
        assert!(trailers.is_empty());
        assert_eq!(used, 13);
    }

    #[test]
    fn rejects_bad_framing_and_oversize() {
        let mut out = Vec::new();
        assert_eq!(
            ChunkDecoder::new().feed(b"zz\r\n", &mut out, 100),
            Err(ChunkError::Bad)
        );
        assert_eq!(
            ChunkDecoder::new().feed(b"3\r\nabcX\n", &mut out, 100),
            Err(ChunkError::Bad)
        );
        assert_eq!(
            ChunkDecoder::new().feed(b"10\r\n0123456789abcdef\r\n0\r\n\r\n", &mut Vec::new(), 8),
            Err(ChunkError::TooLarge)
        );
        assert_eq!(
            ChunkDecoder::new().feed(b"fffffffffffffffff\r\n", &mut out, 100),
            Err(ChunkError::Bad),
            "absurd size is refused before it can overflow"
        );
    }

    fn parse_head_once(b: &[u8]) -> Result<Option<(Head, usize)>, ParseError> {
        parse_head(b, &mut Resume::default())
    }

    #[test]
    fn head_parsing() {
        let wire = b"POST /x?y=1 HTTP/1.1\r\nHost: a\r\nContent-Length:  3 \r\n\r\nabc";
        let (h, n) = parse_head(wire, &mut Resume::default()).unwrap().unwrap();
        assert_eq!(h.method, Method::Post);
        assert_eq!(h.target, "/x?y=1");
        assert_eq!(h.version, Version::Http11);
        assert_eq!(h.headers.get("content-length"), Some("3"));
        assert_eq!(&wire[n..], b"abc");
        assert!(parse_head_once(b"GET / HT").unwrap().is_none());
        assert_eq!(
            parse_head_once(b"GET / HTTP/2.0\r\n\r\n").unwrap_err(),
            ParseError::Version
        );
        assert_eq!(
            parse_head_once(b"GE\x01T / HTTP/1.1\r\n\r\n").unwrap_err(),
            ParseError::Bad
        );
        let mut many = String::from("GET / HTTP/1.1\r\n");
        for i in 0..120 {
            many.push_str(&format!("H{i}: v\r\n"));
        }
        many.push_str("\r\n");
        assert_eq!(
            parse_head_once(many.as_bytes()).unwrap_err(),
            ParseError::TooManyHeaders
        );
    }

    /// The parts of a target in absolute form (ADR-177): its host without user information,
    /// and what follows the authority; `None` for any other form, or an empty or invalid host.
    #[test]
    fn absolute_form_parts() {
        for (target, want) in [
            (
                "http://a.example/admin/x?q",
                Some(("a.example", "/admin/x?q")),
            ),
            ("https://u:p@a:8443?q", Some(("a:8443", "?q"))),
            ("HTTP://A", Some(("A", ""))),
            ("h2c+x.y-z://a", Some(("a", ""))),
            ("http://[::1]:80/", Some(("[::1]:80", "/"))),
            ("http://u@v@a/b", Some(("a", "/b"))),
            ("http:///x", None),
            ("http://u@/x", None),
            ("http://:80/x", None),
            ("http://a\"b/", None),
            ("http://a<b/", None),
            ("http:/a/b", None),
            ("/http://a/b", None),
            ("a:443", None),
            ("*", None),
            ("1http://a/b", None),
            ("ht_tp://a/b", None),
            ("://a/b", None),
        ] {
            assert_eq!(absolute_form(target), want, "{target}");
        }
    }

    /// Targets as RFC 9112 §3.2 asks of an origin server (ADR-177): origin form as sent,
    /// absolute form by its path and query with the target kept, `*` for `OPTIONS` alone, any
    /// target for `CONNECT`, and anything else refused.
    #[test]
    fn request_target_forms() {
        let parse = |line: &str| {
            parse_head_once(format!("{line} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes())
                .map(|h| h.map(|(h, _)| (h.target, h.absolute.map(String::from))))
        };
        let ok = |t: &str, raw: Option<&str>| Ok(Some((t.to_owned(), raw.map(str::to_owned))));
        assert_eq!(parse("GET /a?b"), ok("/a?b", None));
        assert_eq!(
            parse("GET http://a.example/admin/x?q"),
            ok("/admin/x?q", Some("http://a.example/admin/x?q"))
        );
        assert_eq!(
            parse("GET http://a.example"),
            ok("/", Some("http://a.example"))
        );
        assert_eq!(
            parse("GET http://a.example?q"),
            ok("/?q", Some("http://a.example?q"))
        );
        assert_eq!(parse("OPTIONS *"), ok("*", None));
        assert_eq!(parse("CONNECT a.example:443"), ok("a.example:443", None));
        for bad in [
            "GET *",
            "GET a.example:443",
            "GET admin/x",
            "GET http:///admin/x",
            "GET http:/admin/x",
            "POST mailto:a@b",
        ] {
            assert_eq!(parse(bad), Err(ParseError::Bad), "{bad}");
        }
    }
}
