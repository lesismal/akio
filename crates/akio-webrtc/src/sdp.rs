//! A small SDP (RFC 8866) reader and writer: the session part and the media sections as
//! ordered attribute lists. The WebRTC meaning (JSEP, RFC 8829) is in `rtc.rs`.

use std::fmt::Write as _;
use std::net::IpAddr;

/// Inputs bigger than this are refused (an SDP is a few KiB).
const MAX_SDP: usize = 256 * 1024;
/// More media sections than this are refused.
const MAX_MEDIA: usize = 64;

/// One `a=` line: `key` or `key:value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attr {
    pub(crate) key: String,
    pub(crate) value: Option<String>,
}

impl Attr {
    pub(crate) fn flag(key: &str) -> Attr {
        Attr {
            key: key.to_owned(),
            value: None,
        }
    }

    pub(crate) fn kv(key: &str, value: impl Into<String>) -> Attr {
        Attr {
            key: key.to_owned(),
            value: Some(value.into()),
        }
    }
}

/// One `m=` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Media {
    /// `audio`, `video`, `application` ...
    pub(crate) kind: String,
    pub(crate) port: u16,
    pub(crate) proto: String,
    pub(crate) fmts: Vec<String>,
    pub(crate) attrs: Vec<Attr>,
}

impl Media {
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.as_deref().unwrap_or(""))
    }

    pub(crate) fn all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.attrs
            .iter()
            .filter(move |a| a.key == key)
            .map(|a| a.value.as_deref().unwrap_or(""))
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.attrs.iter().any(|a| a.key == key)
    }
}

/// A parsed session description.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Sdp {
    pub(crate) session_id: u64,
    pub(crate) version: u64,
    pub(crate) attrs: Vec<Attr>,
    pub(crate) media: Vec<Media>,
    /// The session's `c=` address, if any (unicast `IN IP4` / `IN IP6`).
    pub(crate) conn: Option<IpAddr>,
    /// Each media section's own `c=` address, by index (missing or `None`: none; written
    /// as `0.0.0.0`).
    pub(crate) media_conn: Vec<Option<IpAddr>>,
}

/// The address of a `c=` value: `IN IP4 <addr>` or `IN IP6 <addr>` (a TTL or count after a
/// `/` is dropped; FQDNs and the unspecified address, which JSEP writes, are not taken).
fn conn_addr(v: &str) -> Option<IpAddr> {
    let mut f = v.split_ascii_whitespace();
    if f.next()? != "IN" {
        return None;
    }
    let fam = f.next()?;
    let a = f.next()?.split('/').next()?;
    let ip: IpAddr = a.parse().ok()?;
    if ip.is_unspecified() {
        return None;
    }
    match (fam, ip) {
        ("IP4", IpAddr::V4(_)) | ("IP6", IpAddr::V6(_)) => Some(ip),
        _ => None,
    }
}

impl Sdp {
    /// Parses `s`; unknown lines are kept or skipped, never fatal. Fails only when there is no
    /// `v=0` or the structure is broken.
    pub(crate) fn parse(s: &str) -> Result<Sdp, String> {
        if s.len() > MAX_SDP {
            return Err("SDP too large".into());
        }
        let mut sdp = Sdp::default();
        let mut seen_v = false;
        for raw in s.lines() {
            let line = raw.trim_end_matches('\r').trim();
            if line.is_empty() {
                continue;
            }
            let Some((t, v)) = line.split_once('=') else {
                return Err(format!("malformed line {line:?}"));
            };
            if t.len() != 1 {
                return Err(format!("malformed line {line:?}"));
            }
            match t {
                "v" => {
                    if v != "0" {
                        return Err("unsupported SDP version".into());
                    }
                    seen_v = true;
                }
                "o" => {
                    let f: Vec<&str> = v.split_whitespace().collect();
                    if f.len() >= 3 {
                        sdp.session_id = f[1].parse().unwrap_or(0);
                        sdp.version = f[2].parse().unwrap_or(0);
                    }
                }
                "m" => {
                    if sdp.media.len() >= MAX_MEDIA {
                        return Err("too many media sections".into());
                    }
                    let mut f = v.split_whitespace();
                    let kind = f.next().ok_or("m= without media")?.to_owned();
                    let port = f
                        .next()
                        .and_then(|p| p.split('/').next())
                        .and_then(|p| p.parse::<u16>().ok())
                        .ok_or("m= without a port")?;
                    let proto = f.next().ok_or("m= without a protocol")?.to_owned();
                    let fmts = f.take(128).map(str::to_owned).collect();
                    sdp.media.push(Media {
                        kind,
                        port,
                        proto,
                        fmts,
                        attrs: Vec::new(),
                    });
                    sdp.media_conn.push(None);
                }
                "c" => {
                    let a = conn_addr(v);
                    match sdp.media_conn.last_mut() {
                        Some(c) => *c = a,
                        None => sdp.conn = a,
                    }
                }
                "a" => {
                    let attr = match v.split_once(':') {
                        Some((k, val)) => Attr::kv(k, val.trim()),
                        None => Attr::flag(v),
                    };
                    match sdp.media.last_mut() {
                        Some(m) => m.attrs.push(attr),
                        None => sdp.attrs.push(attr),
                    }
                }
                _ => {}
            }
            if !seen_v {
                return Err("SDP does not start with v=0".into());
            }
        }
        if !seen_v {
            return Err("empty SDP".into());
        }
        Ok(sdp)
    }

    /// Session-level attribute.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.key == key)
            .map(|a| a.value.as_deref().unwrap_or(""))
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.attrs.iter().any(|a| a.key == key)
    }

    /// A media attribute, else the session one.
    pub(crate) fn media_or_session<'a>(&'a self, m: &'a Media, key: &str) -> Option<&'a str> {
        m.get(key).or_else(|| self.get(key))
    }

    /// The SDP text (CRLF line ends).
    pub(crate) fn write(&self) -> String {
        let mut s = String::with_capacity(2048);
        let ip4 = |a: Option<IpAddr>| match a {
            Some(IpAddr::V6(v)) => format!("IN IP6 {v}"),
            Some(IpAddr::V4(v)) => format!("IN IP4 {v}"),
            None => "IN IP4 0.0.0.0".to_owned(),
        };
        let _ = write!(
            s,
            "v=0\r\no=- {} {} {}\r\ns=-\r\n",
            self.session_id,
            self.version,
            ip4(self.conn)
        );
        if self.conn.is_some() {
            let _ = write!(s, "c={}\r\n", ip4(self.conn));
        }
        s.push_str("t=0 0\r\n");
        for a in &self.attrs {
            write_attr(&mut s, a);
        }
        for (i, m) in self.media.iter().enumerate() {
            let _ = write!(s, "m={} {} {}", m.kind, m.port, m.proto);
            for f in &m.fmts {
                let _ = write!(s, " {f}");
            }
            let c = self.media_conn.get(i).copied().flatten();
            let _ = write!(s, "\r\nc={}\r\n", ip4(c));
            for a in &m.attrs {
                write_attr(&mut s, a);
            }
        }
        s
    }
}

fn write_attr(s: &mut String, a: &Attr) {
    match &a.value {
        Some(v) => {
            let _ = write!(s, "a={}:{v}\r\n", a.key);
        }
        None => {
            let _ = write!(s, "a={}\r\n", a.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write() {
        let text = "v=0\r\no=- 123 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1\r\n\
            m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\na=rtcp-mux\r\n\
            a=rtpmap:111 opus/48000/2\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
            a=mid:1\r\na=sctp-port:5000\r\n";
        let sdp = Sdp::parse(text).unwrap();
        assert_eq!((sdp.session_id, sdp.version), (123, 2));
        assert_eq!(sdp.get("group"), Some("BUNDLE 0 1"));
        assert_eq!(sdp.media.len(), 2);
        assert_eq!(sdp.media[0].fmts, ["111", "0"]);
        assert!(sdp.media[0].has("rtcp-mux"));
        assert_eq!(sdp.media[0].all("rtpmap").count(), 1);
        assert_eq!(sdp.media[1].get("sctp-port"), Some("5000"));
        let again = Sdp::parse(&sdp.write()).unwrap();
        assert_eq!(again, sdp);
        assert!(Sdp::parse("").is_err());
        assert!(Sdp::parse("x").is_err());
        assert!(Sdp::parse("a=b\r\nv=0").is_err());
        assert!(Sdp::parse("v=0\r\nm=audio\r\n").is_err());
    }

    #[test]
    fn connection_lines() {
        let text = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1/127\r\n\
            t=0 0\r\nm=audio 4000 RTP/SAVP 0\r\nm=video 4002 RTP/SAVP 96\r\n\
            c=IN IP6 2001:db8::1\r\nm=audio 4004 RTP/SAVP 0\r\nc=IN IP4 host.example\r\n";
        let sdp = Sdp::parse(text).unwrap();
        assert_eq!(sdp.conn, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(
            sdp.media_conn,
            vec![None, Some("2001:db8::1".parse().unwrap()), None]
        );
        let again = Sdp::parse(&sdp.write()).unwrap();
        assert_eq!((again.conn, again.media_conn), (sdp.conn, sdp.media_conn));
        assert_eq!(conn_addr("IN IP4 ::1"), None);
        assert_eq!(conn_addr("IN IP6 10.0.0.1"), None);
        assert_eq!(conn_addr("ATM NSAP x"), None);
        // Without addresses the lines are what they always were.
        let plain = Sdp::default().write();
        assert!(plain.contains("o=- 0 0 IN IP4 0.0.0.0\r\n") && !plain.contains("c="));
    }
}
