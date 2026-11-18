//! A minimal blocking HTTP/1.1 client for OTLP/HTTP POSTs, used only on the exporter thread:
//! plain TCP, keep-alive with one reconnect, timeouts on every step, bounded responses.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    time::Duration,
};

/// Largest response head and body read (OTLP responses are tiny).
const MAX_HEAD: usize = 16 << 10;
const MAX_BODY: usize = 1 << 20;

/// `http://host:port[/path]`, split.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Without a trailing slash (`""` for the root).
    pub(crate) base: String,
}

impl Endpoint {
    pub(crate) fn parse(url: &str) -> io::Result<Endpoint> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, format!("{m}: {url}"));
        let rest = match url.strip_prefix("http://") {
            Some(r) => r,
            None if url.starts_with("https://") => {
                return Err(bad(
                    "https endpoints are not supported (use a local collector or a TLS sidecar)",
                ));
            }
            None => return Err(bad("expected an http:// URL")),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
                (h, p.parse::<u16>().map_err(|_| bad("bad port"))?)
            }
            _ => (authority, 80),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() {
            return Err(bad("missing host"));
        }
        Ok(Endpoint {
            host: host.to_owned(),
            port,
            base: path.trim_end_matches('/').to_owned(),
        })
    }

    fn host_header(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A keep-alive connection to one endpoint.
#[derive(Debug)]
pub(crate) struct Client {
    ep: Endpoint,
    timeout: Duration,
    conn: Option<TcpStream>,
    headers: Vec<(String, String)>,
}

impl Client {
    pub(crate) fn new(ep: Endpoint, timeout: Duration, headers: Vec<(String, String)>) -> Client {
        Client {
            ep,
            timeout,
            conn: None,
            headers,
        }
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let addrs: Vec<SocketAddr> = (self.ep.host.as_str(), self.ep.port)
            .to_socket_addrs()?
            .collect();
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for a in addrs {
            match TcpStream::connect_timeout(&a, self.timeout) {
                Ok(s) => {
                    s.set_read_timeout(Some(self.timeout))?;
                    s.set_write_timeout(Some(self.timeout))?;
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// POSTs `body` to `base + path`; the response status. Retries once on a fresh connection
    /// when a reused one turns out to be closed.
    pub(crate) fn post(&mut self, path: &str, content_type: &str, body: &[u8]) -> io::Result<u16> {
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

    fn try_post(&mut self, path: &str, content_type: &str, body: &[u8]) -> io::Result<u16> {
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
            Ok((status, keep)) => {
                if !keep {
                    self.conn = None;
                }
                Ok(status)
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

/// Reads one response; (status, whether the connection can be reused).
pub(crate) fn read_response(s: &mut impl Read) -> io::Result<(u16, bool)> {
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
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim();
        if k.eq_ignore_ascii_case("content-length") {
            len = Some(v.parse().map_err(|_| invalid("bad content-length"))?);
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            chunked = v.to_ascii_lowercase().contains("chunked");
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
    if status == 204 || status == 304 || (100..200).contains(&status) {
        return Ok((status, keep));
    }
    if chunked {
        // Walk the chunks: size line, data, CRLF ... until the zero chunk and its CRLF.
        let mut pos = 0;
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
                            return Ok((status, keep));
                        }
                        pos += i + 2;
                        continue;
                    }
                    let want = body.len() + 1;
                    fill(&mut body, want)?;
                }
            }
            fill(&mut body, pos + size + 2)?;
            pos += size + 2;
        }
    }
    match len {
        Some(n) => {
            if n > MAX_BODY {
                return Err(invalid("response body too large"));
            }
            fill(&mut body, n)?;
            Ok((status, keep && body.len() == n))
        }
        None => {
            // Delimited by the close.
            loop {
                if body.len() > MAX_BODY {
                    return Err(invalid("response body too large"));
                }
                match s.read(&mut chunk)? {
                    0 => return Ok((status, false)),
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
        assert_eq!(Endpoint::parse("http://h").unwrap().port, 80);
        assert!(Endpoint::parse("https://h:1").is_err());
        assert!(Endpoint::parse("ftp://h").is_err());
        assert!(Endpoint::parse("http://h:x").is_err());
        assert!(Endpoint::parse("http://:1").is_err());
    }

    #[test]
    fn responses() {
        let r = |s: &str| read_response(&mut s.as_bytes());
        assert_eq!(
            r("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap(),
            (200, true)
        );
        assert_eq!(
            r("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n").unwrap(),
            (200, true)
        );
        assert_eq!(
            r("HTTP/1.1 400 Bad\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap(),
            (400, false)
        );
        assert_eq!(r("HTTP/1.0 200 OK\r\n\r\nbody").unwrap(), (200, false));
        assert!(r("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok").is_err());
        assert!(r("SSH-2.0\r\n\r\n").is_err());
        assert!(r("HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n").is_err());
    }
}
