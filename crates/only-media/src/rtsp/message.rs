//! The RTSP message layer, sans-IO: [`Parser`] splits what a connection reads into requests,
//! responses and interleaved frames, bounding each header and body; [`Response`] and
//! [`interleaved`] write them; [`Transport`] reads and writes the `Transport` header. A parser
//! made with [`Parser::client`] returns whole responses ([`Reply`]), as an RTSP client needs.

use std::{
    fmt::{self, Write as _},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Default bound of a message head.
pub const MAX_HEAD: usize = 16 << 10;
/// Default bound of a message body.
pub const MAX_BODY: usize = 256 << 10;

/// A protocol violation on an RTSP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtspError {
    /// The head is longer than allowed.
    HeadTooLarge,
    /// The body is longer than allowed.
    BodyTooLarge,
    /// The start line or a header is malformed.
    Malformed,
}

impl fmt::Display for RtspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtspError::HeadTooLarge => f.write_str("RTSP head too large"),
            RtspError::BodyTooLarge => f.write_str("RTSP body too large"),
            RtspError::Malformed => f.write_str("malformed RTSP message"),
        }
    }
}

impl std::error::Error for RtspError {}

/// An RTSP request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Request {
    /// The method (`DESCRIBE`, `SETUP`...).
    pub method: String,
    /// The request URI.
    pub uri: String,
    /// The headers in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Request {
    /// The first header `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `CSeq`.
    pub fn cseq(&self) -> Option<&str> {
        self.header("cseq")
    }
}

/// What the parser found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame {
    /// A request.
    Request(Request),
    /// A response (its status code); the server ignores them. A [`Parser::client`] returns
    /// [`Frame::Reply`] instead.
    Response(u16),
    /// A whole response, from a [`Parser::client`].
    Reply(Reply),
    /// An interleaved binary frame (`$`, channel, length, data).
    Interleaved {
        /// The channel.
        channel: u8,
        /// The data.
        data: Vec<u8>,
    },
}

/// An RTSP response as a client reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reply {
    /// The status code.
    pub status: u16,
    /// The reason phrase.
    pub reason: String,
    /// The headers in order.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Reply {
    /// The first header `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every header `name` (case-insensitive), in order (`WWW-Authenticate` may repeat).
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `CSeq`.
    pub fn cseq(&self) -> Option<&str> {
        self.header("cseq")
    }
}

/// Splits a byte stream into [`Frame`]s.
#[derive(Debug)]
pub struct Parser {
    buf: Vec<u8>,
    max_head: usize,
    max_body: usize,
    replies: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Parser::new(MAX_HEAD, MAX_BODY)
    }
}

impl Parser {
    /// A parser bounding heads to `max_head` and bodies to `max_body` bytes.
    pub fn new(max_head: usize, max_body: usize) -> Parser {
        Parser {
            buf: Vec::new(),
            max_head,
            max_body,
            replies: false,
        }
    }

    /// A parser for a client connection: like [`new`](Self::new), but responses come out
    /// whole, as [`Frame::Reply`] (headers and body), rather than as [`Frame::Response`].
    pub fn client(max_head: usize, max_body: usize) -> Parser {
        Parser {
            replies: true,
            ..Parser::new(max_head, max_body)
        }
    }

    /// Whether part of a message is buffered (its first bytes arrived, not all of it).
    pub(crate) fn pending(&self) -> bool {
        !self.buf.is_empty()
    }

    /// Feeds bytes; appends complete frames to `out`.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Frame>) -> Result<(), RtspError> {
        self.buf.extend_from_slice(data);
        let mut p = 0;
        let res = loop {
            // Tolerate stray line ends between messages.
            while matches!(self.buf.get(p), Some(b'\r' | b'\n')) {
                p += 1;
            }
            match self.next(p) {
                Ok(Some((f, n))) => {
                    out.push(f);
                    p += n;
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        self.buf.drain(..p);
        res
    }

    fn next(&self, p: usize) -> Result<Option<(Frame, usize)>, RtspError> {
        let b = &self.buf[p..];
        if b.is_empty() {
            return Ok(None);
        }
        if b[0] == b'$' {
            if b.len() < 4 {
                return Ok(None);
            }
            let n = usize::from(u16::from_be_bytes([b[2], b[3]]));
            if b.len() < 4 + n {
                return Ok(None);
            }
            return Ok(Some((
                Frame::Interleaved {
                    channel: b[1],
                    data: b[4..4 + n].to_vec(),
                },
                4 + n,
            )));
        }
        let Some(end) = find_head_end(b) else {
            if b.len() > self.max_head {
                return Err(RtspError::HeadTooLarge);
            }
            return Ok(None);
        };
        if end > self.max_head {
            return Err(RtspError::HeadTooLarge);
        }
        let head = std::str::from_utf8(&b[..end]).map_err(|_| RtspError::Malformed)?;
        let mut lines = head.split("\r\n").flat_map(|l| l.split('\n'));
        let start = lines.next().ok_or(RtspError::Malformed)?;
        let mut headers = Vec::new();
        for l in lines {
            if l.is_empty() {
                continue;
            }
            let (n, v) = l.split_once(':').ok_or(RtspError::Malformed)?;
            headers.push((n.trim().to_owned(), v.trim().to_owned()));
        }
        let len = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .map(|(_, v)| v.parse::<usize>().map_err(|_| RtspError::Malformed))
            .transpose()?
            .unwrap_or(0);
        if len > self.max_body {
            return Err(RtspError::BodyTooLarge);
        }
        let body_at = end + head_sep_len(b, end);
        if b.len() < body_at + len {
            return Ok(None);
        }
        let body = b[body_at..body_at + len].to_vec();
        let mut parts = start.split(' ').filter(|s| !s.is_empty());
        let first = parts.next().ok_or(RtspError::Malformed)?;
        let frame = if first.starts_with("RTSP/") {
            let code = parts
                .next()
                .and_then(|c| c.parse().ok())
                .ok_or(RtspError::Malformed)?;
            if self.replies {
                let reason = start.splitn(3, ' ').nth(2).unwrap_or("").trim().to_owned();
                Frame::Reply(Reply {
                    status: code,
                    reason,
                    headers,
                    body,
                })
            } else {
                Frame::Response(code)
            }
        } else {
            let uri = parts.next().ok_or(RtspError::Malformed)?;
            let ver = parts.next().ok_or(RtspError::Malformed)?;
            if !ver.starts_with("RTSP/")
                || !first.bytes().all(|c| c.is_ascii_alphabetic() || c == b'_')
            {
                return Err(RtspError::Malformed);
            }
            Frame::Request(Request {
                method: first.to_ascii_uppercase(),
                uri: uri.to_owned(),
                headers,
                body,
            })
        };
        Ok(Some((frame, body_at + len)))
    }
}

fn find_head_end(b: &[u8]) -> Option<usize> {
    let a = b.windows(4).position(|w| w == b"\r\n\r\n");
    let c = b.windows(2).position(|w| w == b"\n\n");
    match (a, c) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

fn head_sep_len(b: &[u8], end: usize) -> usize {
    if b[end..].starts_with(b"\r\n\r\n") {
        4
    } else {
        2
    }
}

/// An RTSP response being built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// The headers (`CSeq` and `Content-Length` are added when encoding).
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with `status`.
    pub fn new(status: u16) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// Sets the body with its content type.
    #[must_use]
    pub fn body(mut self, content_type: &str, body: Vec<u8>) -> Response {
        self.headers
            .push(("Content-Type".to_owned(), content_type.to_owned()));
        self.body = body;
        self
    }

    /// Encodes the response answering `cseq`.
    pub fn encode(&self, cseq: Option<&str>) -> Vec<u8> {
        let mut s = format!("RTSP/1.0 {} {}\r\n", self.status, reason(self.status));
        if let Some(c) = cseq {
            let _ = write!(s, "CSeq: {c}\r\n");
        }
        for (n, v) in &self.headers {
            let _ = write!(s, "{n}: {}\r\n", v.replace(['\r', '\n'], ""));
        }
        s.push_str("Server: only-media\r\n");
        if !self.body.is_empty() {
            let _ = write!(s, "Content-Length: {}\r\n", self.body.len());
        }
        s.push_str("\r\n");
        let mut out = s.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// The reason phrase of an RTSP status code.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        415 => "Unsupported Media Type",
        453 => "Not Enough Bandwidth",
        454 => "Session Not Found",
        455 => "Method Not Valid in This State",
        459 => "Aggregate Operation Not Allowed",
        461 => "Unsupported Transport",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Appends an interleaved frame (`$`, channel, length, data) to `out`; data longer than
/// 65535 bytes is truncated (RTP packets never are).
pub fn interleaved(channel: u8, data: &[u8], out: &mut Vec<u8>) {
    let n = data.len().min(0xffff);
    out.push(b'$');
    out.push(channel);
    out.extend_from_slice(&(n as u16).to_be_bytes());
    out.extend_from_slice(&data[..n]);
}

/// Where a `Range` header starts (RFC 2326 12.29): an absolute UTC time (`clock=`), or a
/// normal play time (`npt=`, `now` being zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RangeStart {
    Clock(SystemTime),
    Npt(Duration),
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of day `z` since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// The `Range` value of an open range from the UTC time `t`: `clock=YYYYMMDDThhmmss.fffZ-`
/// (RFC 2326 3.7; times before 1970 are written as 1970).
pub(crate) fn clock_range(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (y, mo, da) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!(
        "clock={y:04}{mo:02}{da:02}T{:02}{:02}{:02}.{:03}Z-",
        s / 3600,
        s / 60 % 60,
        s % 60,
        d.subsec_millis()
    )
}

/// Seconds with an optional fraction (`12`, `12.5`).
fn seconds(v: &str) -> Option<Duration> {
    let (w, f) = v.split_once('.').unwrap_or((v, ""));
    if w.is_empty()
        || !w.bytes().all(|b| b.is_ascii_digit())
        || !f.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let w: u64 = w.parse().ok()?;
    let mut nanos = 0u32;
    for (i, b) in f.bytes().take(9).enumerate() {
        nanos += u32::from(b - b'0') * 10u32.pow(8 - i as u32);
    }
    Some(Duration::new(w, nanos))
}

/// Where the `Range` header value `v` starts: `clock=` (`YYYYMMDDThhmmss[.fraction]Z`) or
/// `npt=` (`now`, seconds, or `h:mm:ss`, each with a fraction); `None` for other units or
/// malformed values.
pub(crate) fn range_start(v: &str) -> Option<RangeStart> {
    let (unit, rest) = v.trim().split_once('=')?;
    let start = rest.split(['-', ';']).next()?.trim();
    match unit.trim().to_ascii_lowercase().as_str() {
        "clock" => {
            let t = start.strip_suffix('Z')?;
            let (date, time) = t.split_once('T')?;
            let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
            if date.len() != 8
                || hms.len() != 6
                || !date.bytes().chain(hms.bytes()).all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let n = |s: &str| s.parse::<u32>().ok();
            let (y, mo, d) = (n(&date[..4])?, n(&date[4..6])?, n(&date[6..])?);
            let (h, mi, s) = (n(&hms[..2])?, n(&hms[2..4])?, n(&hms[4..])?);
            if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
                return None;
            }
            let days = days_from_civil(i64::from(y), mo, d);
            let secs = days * 86_400 + i64::from(h * 3600 + mi * 60 + s);
            let frac = if frac.is_empty() {
                Duration::ZERO
            } else {
                seconds(&format!("0.{frac}"))?
            };
            let secs = u64::try_from(secs).ok()?;
            UNIX_EPOCH
                .checked_add(Duration::from_secs(secs) + frac)
                .map(RangeStart::Clock)
        }
        "npt" => {
            if start.eq_ignore_ascii_case("now") {
                return Some(RangeStart::Npt(Duration::ZERO));
            }
            let mut parts = start.rsplitn(3, ':');
            let s = seconds(parts.next()?)?;
            let mut total = s;
            for (k, p) in parts.enumerate() {
                let v: u64 = p.parse().ok()?;
                total += Duration::from_secs(v * if k == 0 { 60 } else { 3600 });
            }
            Some(RangeStart::Npt(total))
        }
        _ => None,
    }
}

/// One transport specification of a `Transport` header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Transport {
    /// `RTP/AVP/TCP`: interleaved on the RTSP connection.
    pub tcp: bool,
    /// `multicast` was asked for.
    pub multicast: bool,
    /// `interleaved=a-b`.
    pub interleaved: Option<(u8, u8)>,
    /// `client_port=a-b`.
    pub client_port: Option<(u16, u16)>,
    /// `server_port=a-b`.
    pub server_port: Option<(u16, u16)>,
    /// `ssrc=`.
    pub ssrc: Option<u32>,
    /// `mode=` (`record` or `play`), lowercased.
    pub mode: Option<String>,
}

fn range<T: std::str::FromStr + Copy>(v: &str) -> Option<(T, T)> {
    match v.split_once('-') {
        Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
        None => {
            let a = v.trim().parse().ok()?;
            Some((a, a))
        }
    }
}

impl Transport {
    /// Parses the specifications of a `Transport` header, in order of preference; those that
    /// are not RTP/AVP are left out.
    pub fn parse_all(v: &str) -> Vec<Transport> {
        v.split(',').filter_map(Transport::parse).collect()
    }

    fn parse(spec: &str) -> Option<Transport> {
        let mut it = spec.split(';');
        let proto = it.next()?.trim().to_ascii_uppercase();
        let tcp = match proto.as_str() {
            "RTP/AVP" | "RTP/AVP/UDP" => false,
            "RTP/AVP/TCP" => true,
            _ => return None,
        };
        let mut t = Transport {
            tcp,
            ..Transport::default()
        };
        for p in it {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            match k.trim().to_ascii_lowercase().as_str() {
                "multicast" => t.multicast = true,
                "interleaved" => t.interleaved = range(v),
                "client_port" => t.client_port = range(v),
                "server_port" => t.server_port = range(v),
                "ssrc" => t.ssrc = u32::from_str_radix(v.trim(), 16).ok(),
                "mode" => t.mode = Some(v.trim().trim_matches('"').to_ascii_lowercase()),
                _ => {}
            }
        }
        Some(t)
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.tcp {
            "RTP/AVP/TCP;unicast"
        } else {
            "RTP/AVP;unicast"
        })?;
        if let Some((a, b)) = self.interleaved {
            write!(f, ";interleaved={a}-{b}")?;
        }
        if let Some((a, b)) = self.client_port {
            write!(f, ";client_port={a}-{b}")?;
        }
        if let Some((a, b)) = self.server_port {
            write!(f, ";server_port={a}-{b}")?;
        }
        if let Some(s) = self.ssrc {
            write!(f, ";ssrc={s:08X}")?;
        }
        if let Some(m) = &self.mode {
            write!(f, ";mode={m}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_interleaved_and_responses() {
        let mut p = Parser::default();
        let mut out = Vec::new();
        let wire = b"OPTIONS rtsp://h/live/s RTSP/1.0\r\nCSeq: 1\r\n\r\n$\x01\x00\x03abcANNOUNCE rtsp://h/x RTSP/1.0\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\nv=0\nRTSP/1.0 200 OK\r\nCSeq: 3\r\n\r\n\r\n";
        for c in wire.chunks(7) {
            p.feed(c, &mut out).unwrap();
        }
        let reqs: Vec<&Frame> = out.iter().collect();
        assert_eq!(reqs.len(), 4);
        match reqs[0] {
            Frame::Request(r) => {
                assert_eq!(r.method, "OPTIONS");
                assert_eq!(r.cseq(), Some("1"));
            }
            _ => panic!(),
        }
        assert_eq!(
            reqs[1],
            &Frame::Interleaved {
                channel: 1,
                data: b"abc".to_vec()
            }
        );
        match reqs[2] {
            Frame::Request(r) => assert_eq!(r.body, b"v=0\n"),
            _ => panic!(),
        }
        assert_eq!(reqs[3], &Frame::Response(200));
        let mut p = Parser::new(32, 8);
        assert_eq!(p.feed(&[b'A'; 40], &mut out), Err(RtspError::HeadTooLarge));
        let mut p = Parser::new(1024, 8);
        assert_eq!(
            p.feed(b"X y RTSP/1.0\r\nContent-Length: 9\r\n\r\n", &mut out),
            Err(RtspError::BodyTooLarge)
        );
        let mut p = Parser::default();
        assert_eq!(p.feed(b"bad\r\n\r\n", &mut out), Err(RtspError::Malformed));
    }

    #[test]
    fn range_times() {
        // RFC 2326 10.15's example, and a fraction.
        let t = UNIX_EPOCH + Duration::from_secs(824_221_925);
        assert_eq!(
            range_start("clock=19960213T143205Z-"),
            Some(RangeStart::Clock(t))
        );
        assert_eq!(clock_range(t), "clock=19960213T143205.000Z-");
        let t2 = t + Duration::from_millis(250);
        assert_eq!(clock_range(t2), "clock=19960213T143205.250Z-");
        assert_eq!(range_start(&clock_range(t2)), Some(RangeStart::Clock(t2)));
        // Round trips over leap years and centuries.
        for secs in [0u64, 951_782_400, 4_107_542_399, 1_798_761_600 + 86_399] {
            let t = UNIX_EPOCH + Duration::from_secs(secs);
            assert_eq!(
                range_start(&clock_range(t)),
                Some(RangeStart::Clock(t)),
                "{secs}"
            );
        }
        assert_eq!(
            clock_range(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "clock=20000229T000000.000Z-"
        );
        assert_eq!(
            range_start("npt=now-"),
            Some(RangeStart::Npt(Duration::ZERO))
        );
        assert_eq!(
            range_start(" NPT = 12.5-20"),
            Some(RangeStart::Npt(Duration::from_millis(12_500)))
        );
        assert_eq!(
            range_start("npt=1:02:03.25-"),
            Some(RangeStart::Npt(Duration::from_millis(3_723_250)))
        );
        for bad in [
            "smpte=0:10:00-",
            "clock=1996021T143205Z-",
            "clock=19961313T143205Z-",
            "clock=19960213T143205-",
            "clock=19960213T143205.xZ-",
            "npt=-5",
            "npt=a:b",
            "clock",
        ] {
            assert_eq!(range_start(bad), None, "{bad}");
        }
    }

    #[test]
    fn transport_header() {
        let ts = Transport::parse_all(
            "RTP/AVP/TCP;unicast;interleaved=0-1;mode=record, RTP/AVP;unicast;client_port=5000-5001, RAW/RAW/UDP",
        );
        assert_eq!(ts.len(), 2);
        assert!(ts[0].tcp);
        assert_eq!(ts[0].interleaved, Some((0, 1)));
        assert_eq!(ts[0].mode.as_deref(), Some("record"));
        assert_eq!(ts[1].client_port, Some((5000, 5001)));
        let mut t = ts[1].clone();
        t.server_port = Some((8000, 8001));
        assert_eq!(
            t.to_string(),
            "RTP/AVP;unicast;client_port=5000-5001;server_port=8000-8001"
        );
        let r = Response::new(200)
            .header("Session", "abc")
            .encode(Some("7"));
        let s = String::from_utf8(r).unwrap();
        assert!(s.starts_with("RTSP/1.0 200 OK\r\nCSeq: 7\r\nSession: abc\r\n"));
        let mut b = Vec::new();
        interleaved(3, &[1, 2], &mut b);
        assert_eq!(b, vec![b'$', 3, 0, 2, 1, 2]);
    }

    #[test]
    fn client_parser_returns_whole_replies() {
        let wire = b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Base: rtsp://h/s/\r\nContent-Length: 4\r\n\r\nv=0\n$\x00\x00\x02hi\r\nRTSP/1.0 401 Unauthorized\r\nCSeq: 3\r\nWWW-Authenticate: Digest realm=\"r\", nonce=\"n\"\r\nWWW-Authenticate: Basic realm=\"r\"\r\n\r\nOPTIONS * RTSP/1.0\r\nCSeq: 9\r\n\r\n";
        for step in [1, 3, 7, wire.len()] {
            let mut p = Parser::client(MAX_HEAD, MAX_BODY);
            let mut out = Vec::new();
            for c in wire.chunks(step) {
                p.feed(c, &mut out).unwrap();
            }
            assert!(!p.pending());
            assert_eq!(out.len(), 4, "chunks of {step}");
            let Frame::Reply(r) = &out[0] else { panic!() };
            assert_eq!((r.status, r.reason.as_str()), (200, "OK"));
            assert_eq!(r.cseq(), Some("2"));
            assert_eq!(r.header("content-base"), Some("rtsp://h/s/"));
            assert_eq!(r.body, b"v=0\n");
            assert_eq!(
                out[1],
                Frame::Interleaved {
                    channel: 0,
                    data: b"hi".to_vec()
                }
            );
            let Frame::Reply(r) = &out[2] else { panic!() };
            assert_eq!(r.status, 401);
            assert_eq!(r.reason, "Unauthorized");
            assert_eq!(r.headers_named("www-authenticate").count(), 2);
            assert!(matches!(&out[3], Frame::Request(q) if q.method == "OPTIONS"));
        }
        // A partial head is pending; past the bound it is an error.
        let mut p = Parser::client(64, 8);
        let mut out = Vec::new();
        p.feed(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n", &mut out).unwrap();
        assert!(out.is_empty() && p.pending());
        assert_eq!(p.feed(&[b'x'; 64], &mut out), Err(RtspError::HeadTooLarge));
        let mut p = Parser::client(1024, 8);
        assert_eq!(
            p.feed(b"RTSP/1.0 200 OK\r\nContent-Length: 9\r\n\r\n", &mut out),
            Err(RtspError::BodyTooLarge)
        );
        let mut p = Parser::client(1024, 8);
        assert_eq!(
            p.feed(b"RTSP/1.0 abc OK\r\n\r\n", &mut out),
            Err(RtspError::Malformed)
        );
        // The server's parser still reports status codes only.
        let mut p = Parser::default();
        p.feed(b"RTSP/1.0 404 Not Found\r\n\r\n", &mut out).unwrap();
        assert_eq!(out.last(), Some(&Frame::Response(404)));
    }
}
