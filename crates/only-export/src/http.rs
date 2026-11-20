//! A minimal blocking HTTP/1.1 client for OTLP/HTTP POSTs, used only on the exporter thread:
//! TCP or TLS (only-tls), keep-alive with one reconnect, timeouts on every step, bounded
//! responses.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

use only_tls::{ClientConfig, stream::Stream};

/// Largest response head and body read (OTLP responses are tiny).
const MAX_HEAD: usize = 16 << 10;
const MAX_BODY: usize = 1 << 20;

/// `http[s]://host:port[/path]`, split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Without a trailing slash (`""` for the root).
    pub(crate) base: String,
    /// `https://`.
    pub(crate) tls: bool,
}

impl Endpoint {
    pub(crate) fn parse(url: &str) -> io::Result<Endpoint> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{m}: {url}"));
        let (rest, tls) = match (url.strip_prefix("http://"), url.strip_prefix("https://")) {
            (Some(r), _) => (r, false),
            (_, Some(r)) => (r, true),
            _ => return Err(bad("expected an http:// or https:// URL")),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
                (h, p.parse::<u16>().map_err(|_| bad("bad port"))?)
            }
            _ => (authority, if tls { 443 } else { 80 }),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(bad("missing host"));
        }
        Ok(Endpoint {
            host: host.to_owned(),
            port,
            base: path.trim_end_matches('/').to_owned(),
            tls,
        })
    }

    /// `scheme://host:port`.
    pub(crate) fn origin(&self) -> String {
        format!(
            "{}://{}",
            if self.tls { "https" } else { "http" },
            self.host_header()
        )
    }

    /// Resolves the host (on the exporter thread).
    pub(crate) fn addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok((self.host.as_str(), self.port).to_socket_addrs()?.collect())
    }

    pub(crate) fn host_header(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A connection: plain TCP or TLS over it.
#[derive(Debug)]
enum Conn {
    Plain(TcpStream),
    Tls(Box<Stream<TcpStream>>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// Connects to the first address of `ep` that answers within `timeout`.
pub(crate) fn connect_tcp(ep: &Endpoint, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for a in ep.addrs()? {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(timeout))?;
                s.set_write_timeout(Some(timeout))?;
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// What a POST got back.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) status: u16,
    /// The connection can be reused.
    pub(crate) keep: bool,
    /// `Retry-After` in seconds (429 / 503).
    pub(crate) retry_after: Option<Duration>,
    pub(crate) body: Vec<u8>,
}

/// A keep-alive connection to one endpoint.
#[derive(Debug)]
pub(crate) struct Client {
    ep: Endpoint,
    timeout: Duration,
    conn: Option<Conn>,
    headers: Vec<(String, String)>,
    /// TLS: the config (ALPN `http/1.1`) and the name to verify.
    tls: Option<(ClientConfig, String)>,
}

impl Client {
    pub(crate) fn new(
        ep: Endpoint,
        timeout: Duration,
        headers: Vec<(String, String)>,
        tls: Option<(ClientConfig, String)>,
    ) -> Client {
        Client {
            ep,
            timeout,
            conn: None,
            headers,
            tls,
        }
    }

    fn connect(&self) -> io::Result<Conn> {
        let tcp = connect_tcp(&self.ep, self.timeout)?;
        match &self.tls {
            None => Ok(Conn::Plain(tcp)),
            Some((cfg, name)) => {
                let mut s = Stream::client(cfg, name, tcp)?;
                s.handshake()?;
                Ok(Conn::Tls(Box::new(s)))
            }
        }
    }

    /// POSTs `body` to `base + path`. Retries once on a fresh connection when a reused one
    /// turns out to be closed.
    pub(crate) fn post(
        &mut self,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> io::Result<Response> {
        let reused = self.conn.is_some();
        match self.try_post(path, content_type, body) {
            Ok(s) => Ok(s),
            Err(_) if reused => {
                self.conn = None;
                self.try_post(path, content_type, body)
            }
            Err(e) => Err(e),
        }
    }

    fn try_post(&mut self, path: &str, content_type: &str, body: &[u8]) -> io::Result<Response> {
        if self.conn.is_none() {
            self.conn = Some(self.connect()?);
        }
        let res = (|| {
            let s = self.conn.as_mut().ok_or(io::ErrorKind::NotConnected)?;
            let mut head = format!(
                "POST {}{} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nUser-Agent: only-export/{}\r\n",
                self.ep.base,
                path,
                self.ep.host_header(),
                content_type,
                body.len(),
                env!("CARGO_PKG_VERSION"),
            );
            for (k, v) in &self.headers {
                head.push_str(k);
                head.push_str(": ");
                head.push_str(v);
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            s.write_all(head.as_bytes())?;
            s.write_all(body)?;
            s.flush()?;
            read_response(s)
        })();
        match res {
            Ok(r) => {
                if !r.keep {
                    self.conn = None;
                }
                Ok(r)
            }
            Err(e) => {
                self.conn = None;
                Err(e)
            }
        }
    }
}

fn invalid(m: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}

/// Reads one response.
pub(crate) fn read_response(s: &mut impl Read) -> io::Result<Response> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(invalid("response head too large"));
        }
        let n = s.read(&mut chunk)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| invalid("bad response head"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(invalid("not an HTTP/1.x response"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| invalid("bad status"))?;
    let mut len: Option<usize> = None;
    let mut chunked = false;
    let mut keep = version == "HTTP/1.1";
    let mut retry_after = None;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            len = Some(v.parse().map_err(|_| invalid("bad content-length"))?);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            chunked = v.to_ascii_lowercase().contains("chunked");
        } else if k.eq_ignore_ascii_case("retry-after") {
            // Seconds only (an HTTP date is ignored: the exporter's own backoff applies).
            retry_after = v
                .parse::<u32>()
                .ok()
                .map(|n| Duration::from_secs(u64::from(n)));
        } else if k.eq_ignore_ascii_case("connection") {
            if v.eq_ignore_ascii_case("close") {
                keep = false;
            } else if v.eq_ignore_ascii_case("keep-alive") {
                keep = true;
            }
        }
    }
    let mut body = buf.split_off(head_end);
    let mut fill = |body: &mut Vec<u8>, want: usize| -> io::Result<()> {
        while body.len() < want {
            if body.len() > MAX_BODY {
                return Err(invalid("response body too large"));
            }
            let n = s.read(&mut chunk)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            body.extend_from_slice(&chunk[..n]);
        }
        Ok(())
    };
    let done = |keep: bool, body: Vec<u8>| Response {
        status,
        keep,
        retry_after,
        body,
    };
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return Ok(done(keep, Vec::new()));
    }
    if chunked {
        // Walk the chunks: size line, data, CRLF ... until the zero chunk and its CRLF.
        let mut pos = 0;
        let mut data = Vec::new();
        loop {
            let line_end = loop {
                if let Some(i) = body[pos..].windows(2).position(|w| w == b"\r\n") {
                    break pos + i;
                }
                let want = body.len() + 1;
                fill(&mut body, want)?;
            };
            let size_str =
                std::str::from_utf8(&body[pos..line_end]).map_err(|_| invalid("bad chunk"))?;
            let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| invalid("bad chunk size"))?;
            if size > MAX_BODY {
                return Err(invalid("response body too large"));
            }
            pos = line_end + 2;
            if size == 0 {
                // Trailers (none expected) end with an empty line.
                loop {
                    if let Some(i) = body[pos..].windows(2).position(|w| w == b"\r\n") {
                        if i == 0 {
                            return Ok(done(keep, data));
                        }
                        pos += i + 2;
                        continue;
                    }
                    let want = body.len() + 1;
                    fill(&mut body, want)?;
                }
            }
            fill(&mut body, pos + size + 2)?;
            if data.len() + size > MAX_BODY {
                return Err(invalid("response body too large"));
            }
            data.extend_from_slice(&body[pos..pos + size]);
            pos += size + 2;
        }
    }
    match len {
        Some(n) => {
            if n > MAX_BODY {
                return Err(invalid("response body too large"));
            }
            fill(&mut body, n)?;
            let exact = body.len() == n;
            body.truncate(n);
            Ok(done(keep && exact, body))
        }
        None => {
            // Delimited by the close.
            loop {
                if body.len() > MAX_BODY {
                    return Err(invalid("response body too large"));
                }
                match s.read(&mut chunk)? {
                    0 => return Ok(done(false, body)),
                    n => body.extend_from_slice(&chunk[..n]),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let e = Endpoint::parse("http://collector:4318").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.base.as_str()),
            ("collector", 4318, "")
        );
        let e = Endpoint::parse("http://[::1]:9/otlp/").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.base.as_str()),
            ("::1", 9, "/otlp")
        );
        assert_eq!(e.host_header(), "[::1]:9");
        assert_eq!(e.origin(), "http://[::1]:9");
        assert_eq!(Endpoint::parse("http://h").unwrap().port, 80);
        let t = Endpoint::parse("https://h").unwrap();
        assert!(t.tls && t.port == 443 && t.origin() == "https://h:443");
        assert!(Endpoint::parse("https://h:1").unwrap().tls);
        assert!(Endpoint::parse("ftp://h").is_err());
        assert!(Endpoint::parse("http://h:x").is_err());
        assert!(Endpoint::parse("http://:1").is_err());
    }

    #[test]
    fn responses() {
        let r = |s: &str| {
            read_response(&mut s.as_bytes()).map(|r| {
                (
                    r.status,
                    r.keep,
                    String::from_utf8(r.body).unwrap(),
                    r.retry_after,
                )
            })
        };
        assert_eq!(
            r("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap(),
            (200, true, "ok".into(), None)
        );
        assert_eq!(
            r("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n1\r\n!\r\n0\r\n\r\n").unwrap(),
            (200, true, "ok!".into(), None)
        );
        assert_eq!(
            r("HTTP/1.1 400 Bad\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap(),
            (400, false, String::new(), None)
        );
        assert_eq!(
            r("HTTP/1.1 503 Busy\r\nRetry-After: 7\r\nContent-Length: 0\r\n\r\n").unwrap(),
            (503, true, String::new(), Some(Duration::from_secs(7)))
        );
        assert_eq!(
            r("HTTP/1.0 200 OK\r\n\r\nbody").unwrap(),
            (200, false, "body".into(), None)
        );
        assert!(r("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok").is_err());
        assert!(r("SSH-2.0\r\n\r\n").is_err());
        assert!(r("HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n").is_err());
    }
}
