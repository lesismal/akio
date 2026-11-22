//! Magnet links (BEP 9): `magnet:?xt=urn:btih:<hash>` with the hash in hex or base32, and
//! `xt=urn:btmh:1220<hash>` for a v2 torrent (BEP 52: a SHA-256 multihash in hex; a hybrid
//! torrent's link carries both), plus `dn` (name), `tr` (trackers), `x.pe` (peers), `ws` (web
//! seeds) and `xl` (length).

use std::fmt;
use std::net::SocketAddr;

use crate::metainfo::{InfoHash, InfoHashV2, hexval};

/// A parsed magnet link.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Magnet {
    /// The hash peers name the torrent by: the v1 info hash, or for a v2-only link (no
    /// `btih`) the truncated v2 hash.
    pub info_hash: InfoHash,
    /// `urn:btmh:`: the v2 info hash.
    pub info_hash_v2: Option<InfoHashV2>,
    /// `dn`: display name.
    pub name: Option<String>,
    /// `tr`: tracker URLs.
    pub trackers: Vec<String>,
    /// `x.pe`: peer addresses.
    pub peers: Vec<SocketAddr>,
    /// `ws`: web seeds.
    pub web_seeds: Vec<String>,
    /// `xl`: exact length.
    pub length: Option<u64>,
}

/// Why a magnet link was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MagnetError(pub &'static str);

impl fmt::Display for MagnetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "magnet: {}", self.0)
    }
}

impl std::error::Error for MagnetError {}

impl Magnet {
    /// A magnet link of `info_hash` alone.
    pub fn new(info_hash: InfoHash) -> Magnet {
        Magnet {
            info_hash,
            info_hash_v2: None,
            name: None,
            trackers: Vec::new(),
            peers: Vec::new(),
            web_seeds: Vec::new(),
            length: None,
        }
    }

    /// Parses a `magnet:?` URI.
    pub fn parse(s: &str) -> Result<Magnet, MagnetError> {
        let q = s
            .strip_prefix("magnet:?")
            .ok_or(MagnetError("not a magnet: URI"))?;
        let mut hash = None;
        let mut m = Magnet::new(InfoHash::default());
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let v = decode_component(v).ok_or(MagnetError("bad percent-encoding"))?;
            // `tr.1=` style numbered keys are accepted as well.
            let k = k.split('.').collect::<Vec<_>>();
            match (k[0], k.get(1).copied()) {
                ("xt", _) => {
                    if let Some(h) = v.strip_prefix("urn:btih:") {
                        hash = Some(parse_btih(h).ok_or(MagnetError("bad btih hash"))?);
                    } else if let Some(h) = v.strip_prefix("urn:btmh:") {
                        // Multihash: 0x12 (SHA2-256), 0x20 (32 bytes), the digest.
                        let d = h
                            .strip_prefix("1220")
                            .and_then(InfoHashV2::from_hex)
                            .ok_or(MagnetError("bad btmh hash"))?;
                        m.info_hash_v2 = Some(d);
                    }
                }
                ("dn", _) => m.name = Some(v),
                ("tr", _) => m.trackers.push(v),
                ("ws", _) => m.web_seeds.push(v),
                ("xl", _) => m.length = v.parse().ok(),
                ("x", Some("pe")) => {
                    if let Ok(a) = v.parse() {
                        m.peers.push(a);
                    }
                }
                _ => {}
            }
        }
        m.info_hash = match (hash, m.info_hash_v2) {
            (Some(h), _) => h,
            (None, Some(v2)) => v2.truncated(),
            (None, None) => return Err(MagnetError("no urn:btih: or urn:btmh: exact topic")),
        };
        Ok(m)
    }

    /// A link of a v2-only torrent (no v1 hash).
    pub fn is_v2_only(&self) -> bool {
        self.info_hash_v2
            .is_some_and(|v2| v2.truncated() == self.info_hash)
    }
}

impl fmt::Display for Magnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "?";
        if !self.is_v2_only() {
            write!(f, "magnet:?xt=urn:btih:{}", self.info_hash.to_hex())?;
            sep = "&";
        } else {
            f.write_str("magnet:")?;
        }
        if let Some(v2) = self.info_hash_v2 {
            write!(f, "{sep}xt=urn:btmh:1220{}", v2.to_hex())?;
        }
        if let Some(n) = &self.name {
            write!(f, "&dn={}", encode_component(n))?;
        }
        if let Some(l) = self.length {
            write!(f, "&xl={l}")?;
        }
        for t in &self.trackers {
            write!(f, "&tr={}", encode_component(t))?;
        }
        for w in &self.web_seeds {
            write!(f, "&ws={}", encode_component(w))?;
        }
        for p in &self.peers {
            write!(f, "&x.pe={}", encode_component(&p.to_string()))?;
        }
        Ok(())
    }
}

fn parse_btih(h: &str) -> Option<InfoHash> {
    match h.len() {
        40 => InfoHash::from_hex(h),
        32 => {
            // RFC 4648 base32, no padding.
            let mut out = [0u8; 20];
            let mut acc: u64 = 0;
            let mut bits = 0;
            let mut i = 0;
            for c in h.bytes() {
                let v = match c.to_ascii_uppercase() {
                    c @ b'A'..=b'Z' => c - b'A',
                    c @ b'2'..=b'7' => c - b'2' + 26,
                    _ => return None,
                };
                acc = (acc << 5) | u64::from(v);
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    out[i] = (acc >> bits) as u8;
                    i += 1;
                }
            }
            Some(InfoHash(out))
        }
        _ => None,
    }
}

fn decode_component(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hi = hexval(*b.get(i + 1)?)?;
                let lo = hexval(*b.get(i + 2)?)?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub(crate) fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(c));
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        let h = InfoHash::of(b"abc");
        let s = format!(
            "magnet:?xt=urn:btih:{}&dn=my+file&tr=http%3A%2F%2Ft%2Fa&x.pe=127.0.0.1:6881&xl=12",
            h.to_hex()
        );
        let m = Magnet::parse(&s).unwrap();
        assert_eq!(m.info_hash, h);
        assert_eq!(m.name.as_deref(), Some("my file"));
        assert_eq!(m.trackers, vec!["http://t/a"]);
        assert_eq!(m.peers, vec!["127.0.0.1:6881".parse().unwrap()]);
        assert_eq!(m.length, Some(12));
        assert_eq!(Magnet::parse(&m.to_string()).unwrap(), m);
    }

    #[test]
    fn base32() {
        // 20 zero bytes, then 0xff..: base32 of the hash below.
        let m = Magnet::parse("magnet:?xt=urn:btih:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB").unwrap();
        let mut want = [0u8; 20];
        want[19] = 1;
        assert_eq!(m.info_hash.0, want);
        assert!(Magnet::parse("magnet:?dn=x").is_err());
        assert!(Magnet::parse("http://x").is_err());
    }

    #[test]
    fn v2_and_hybrid() {
        let v2 = InfoHashV2::of(b"info");
        let s = format!("magnet:?xt=urn:btmh:1220{}&dn=x", v2.to_hex());
        let m = Magnet::parse(&s).unwrap();
        assert!(m.is_v2_only());
        assert_eq!(m.info_hash, v2.truncated());
        assert_eq!(Magnet::parse(&m.to_string()).unwrap(), m);
        let v1 = InfoHash::of(b"info");
        let s = format!(
            "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}",
            v1.to_hex(),
            v2.to_hex()
        );
        let m = Magnet::parse(&s).unwrap();
        assert!(!m.is_v2_only());
        assert_eq!((m.info_hash, m.info_hash_v2), (v1, Some(v2)));
        assert_eq!(Magnet::parse(&m.to_string()).unwrap(), m);
        assert!(Magnet::parse("magnet:?xt=urn:btmh:1114aa").is_err());
    }
}
