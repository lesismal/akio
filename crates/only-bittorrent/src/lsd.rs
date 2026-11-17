//! Local Service Discovery (BEP 14): the `BT-SEARCH` announcement a client multicasts on its
//! local network (239.192.152.143:6771, `[ff15::efc0:988f]:6771`) so that peers of the same
//! torrents find each other without a tracker or the DHT. [`Announce`] is the codec; the
//! [`client`](crate::client) sends and hears announcements ([`ClientConfig::lsd`]).
//!
//! ```
//! use only_bittorrent::lsd::{Announce, MULTICAST_V4};
//! use only_bittorrent::metainfo::InfoHash;
//! let a = Announce::new(6881, vec![InfoHash::of(b"x")]);
//! let wire = a.encode(&MULTICAST_V4.to_string());
//! assert_eq!(Announce::parse(&wire), Some(a));
//! ```
//!
//! [`ClientConfig::lsd`]: crate::client::ClientConfig::lsd

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::metainfo::InfoHash;

/// The IPv4 multicast group and port.
pub const MULTICAST_V4: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 192, 152, 143), 6771));
/// The IPv6 multicast group and port (site-local scope).
pub const MULTICAST_V6: SocketAddr = SocketAddr::V6(SocketAddrV6::new(
    Ipv6Addr::new(0xff15, 0, 0, 0, 0, 0, 0xefc0, 0x988f),
    6771,
    0,
    0,
));
/// Largest announcement [`Announce::parse`] reads (one datagram on any link).
pub const MAX_MESSAGE: usize = 1400;
/// Most info hashes one announcement carries (and [`Announce::parse`] keeps).
pub const MAX_INFO_HASHES: usize = 16;

/// A `BT-SEARCH` announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Announce {
    /// The port the announcing peer accepts connections at.
    pub port: u16,
    /// The torrents it has (at most [`MAX_INFO_HASHES`]).
    pub info_hashes: Vec<InfoHash>,
    /// An opaque value a client recognises its own announcements by.
    pub cookie: Option<String>,
}

impl Announce {
    /// An announcement of `info_hashes` (the first [`MAX_INFO_HASHES`]) at `port`.
    pub fn new(port: u16, mut info_hashes: Vec<InfoHash>) -> Announce {
        info_hashes.truncate(MAX_INFO_HASHES);
        Announce {
            port,
            info_hashes,
            cookie: None,
        }
    }

    /// Encodes it for the group `host` (`239.192.152.143:6771` or `[ff15::efc0:988f]:6771`).
    pub fn encode(&self, host: &str) -> Vec<u8> {
        let mut s = format!(
            "BT-SEARCH * HTTP/1.1\r\nHost: {host}\r\nPort: {}\r\n",
            self.port
        );
        for ih in self.info_hashes.iter().take(MAX_INFO_HASHES) {
            s.push_str("Infohash: ");
            s.push_str(&ih.to_hex());
            s.push_str("\r\n");
        }
        if let Some(c) = &self.cookie {
            s.push_str("cookie: ");
            s.push_str(c);
            s.push_str("\r\n");
        }
        s.push_str("\r\n\r\n");
        s.into_bytes()
    }

    /// Parses an announcement; `None` if it is not one (or is larger than [`MAX_MESSAGE`], has
    /// no valid port or no info hash). Header names are case-insensitive; info hashes past
    /// [`MAX_INFO_HASHES`] and unknown headers are ignored.
    pub fn parse(b: &[u8]) -> Option<Announce> {
        if b.len() > MAX_MESSAGE {
            return None;
        }
        let s = std::str::from_utf8(b).ok()?;
        let mut lines = s.split("\r\n").flat_map(|l| l.split('\n'));
        let first = lines.next()?.trim_end_matches('\r');
        if !first.starts_with("BT-SEARCH * HTTP/1.") {
            return None;
        }
        let mut a = Announce {
            port: 0,
            info_hashes: Vec::new(),
            cookie: None,
        };
        for line in lines {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim();
            if k.eq_ignore_ascii_case("port") {
                a.port = v.parse().ok()?;
            } else if k.eq_ignore_ascii_case("infohash") {
                if a.info_hashes.len() < MAX_INFO_HASHES {
                    if let Some(h) = InfoHash::from_hex(v) {
                        if !a.info_hashes.contains(&h) {
                            a.info_hashes.push(h);
                        }
                    }
                }
            } else if k.eq_ignore_ascii_case("cookie") && v.len() <= 64 {
                a.cookie = Some(v.to_owned());
            }
        }
        (a.port != 0 && !a.info_hashes.is_empty()).then_some(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_limits() {
        let mut a = Announce::new(6881, (0..20u8).map(|i| InfoHash([i; 20])).collect());
        assert_eq!(a.info_hashes.len(), MAX_INFO_HASHES);
        a.cookie = Some("abc".into());
        let b = a.encode("239.192.152.143:6771");
        assert_eq!(Announce::parse(&b), Some(a));
        // libtorrent's form: upper-case hex, other header case, bare LF.
        let lt = format!(
            "BT-SEARCH * HTTP/1.1\nHost: 239.192.152.143:6771\nPort: 7000\nInfohash: {}\ncookie: 1f\n\n\n",
            "AB".repeat(20)
        );
        let p = Announce::parse(lt.as_bytes()).unwrap();
        assert_eq!((p.port, p.info_hashes[0]), (7000, InfoHash([0xab; 20])));
        assert!(Announce::parse(b"BT-SEARCH * HTTP/1.1\r\nPort: 1\r\n\r\n").is_none());
        assert!(Announce::parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(Announce::parse(&vec![b'a'; MAX_MESSAGE + 1]).is_none());
        let bad_port = format!(
            "BT-SEARCH * HTTP/1.1\r\nPort: 70000\r\nInfohash: {}\r\n\r\n",
            "a".repeat(40)
        );
        assert!(Announce::parse(bad_port.as_bytes()).is_none());
    }
}
