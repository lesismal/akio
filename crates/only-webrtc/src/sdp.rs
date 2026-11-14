//! A small SDP (RFC 8866) reader and writer: the session part and the media sections as
//! ordered attribute lists. The WebRTC meaning (JSEP, RFC 8829) is in `rtc.rs`.

use std::fmt::Write as _;

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
        let _ = write!(
            s,
            "v=0\r\no=- {} {} IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n",
            self.session_id, self.version
        );
        for a in &self.attrs {
            write_attr(&mut s, a);
        }
        for m in &self.media {
            let _ = write!(s, "m={} {} {}", m.kind, m.port, m.proto);
            for f in &m.fmts {
                let _ = write!(s, " {f}");
            }
            s.push_str("\r\nc=IN IP4 0.0.0.0\r\n");
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
}
