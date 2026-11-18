//! The listener side of the handshake: a stateless induction answered with a SYN cookie, and
//! a conclusion that becomes a [`Conn`] once accepted. Also the stream ID syntax.

use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use only_crypto::hash::Sha256;

use super::{
    conn::{Config, Conn, RejectReason, rand_u32, socket_id_of},
    crypto::{Cryptor, KeyMaterial, derive_kek, random},
    packet::*,
};

const COOKIE_BUCKET: u64 = 60;

/// What a caller asks for in its conclusion, for [`Listener`]'s accept decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Request {
    /// The caller's address.
    pub remote: SocketAddr,
    /// The caller's socket ID.
    pub peer_socket_id: u32,
    /// The stream ID it sent (empty when none).
    pub stream_id: String,
    /// Whether it encrypts.
    pub encrypted: bool,
    /// The larger of the latencies it proposed.
    pub latency: Duration,
}

/// The listener half of the handshake (sans-IO).
pub struct Listener {
    secret: [u8; 32],
    keks: HashMap<(String, [u8; 8], usize), Vec<u8>>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl Default for Listener {
    fn default() -> Self {
        Listener::new()
    }
}

/// Whether `b` is a handshake, with the caller's socket ID and whether it is an induction.
pub(crate) fn is_handshake(b: &[u8]) -> Option<(u32, bool)> {
    let h = Header::parse(b)?;
    if !h.ctrl || h.typ != CTRL_HANDSHAKE {
        return None;
    }
    let hs = Handshake::parse(&b[HEADER_SIZE..])?;
    Some((hs.socket_id, hs.typ == HS_INDUCTION))
}

pub(crate) fn peer_ip(a: SocketAddr) -> [u8; 16] {
    let mut ip = [0u8; 16];
    match a {
        SocketAddr::V4(v) => {
            let o = v.ip().octets();
            ip[..4].copy_from_slice(&[o[3], o[2], o[1], o[0]]);
        }
        SocketAddr::V6(v) => {
            let o = v.ip().octets();
            for (i, w) in o.chunks_exact(4).enumerate() {
                ip[i * 4..i * 4 + 4].copy_from_slice(&[w[3], w[2], w[1], w[0]]);
            }
        }
    }
    ip
}

impl Listener {
    /// A listener with a fresh cookie secret.
    pub fn new() -> Listener {
        let mut secret = [0u8; 32];
        random(&mut secret);
        Listener {
            secret,
            keks: HashMap::new(),
        }
    }

    fn cookie(&self, addr: SocketAddr, bucket: u64) -> u32 {
        let mut h = Sha256::new();
        h.update(&self.secret);
        h.update(addr.to_string().as_bytes());
        h.update(&bucket.to_be_bytes());
        let s = h.finalize();
        match u32::from_be_bytes([s[0], s[1], s[2], s[3]]) {
            0 => 1,
            c => c,
        }
    }

    fn bucket() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() / COOKIE_BUCKET)
    }

    fn kek(&mut self, pass: &str, salt: &[u8; 16], len: usize) -> Vec<u8> {
        let mut s8 = [0u8; 8];
        s8.copy_from_slice(&salt[8..]);
        let key = (pass.to_owned(), s8, len);
        if let Some(k) = self.keks.get(&key) {
            return k.clone();
        }
        if self.keks.len() >= 256 {
            self.keks.clear();
        }
        let k = derive_kek(pass, salt, len);
        self.keks.insert(key, k.clone());
        k
    }

    /// Handles a handshake datagram from `from`: answers an induction (into `out`) and turns
    /// an accepted conclusion into a connected [`Conn`] (whose response is in its output).
    /// `accept` decides from the [`Request`], returning the connection's configuration or a
    /// rejection, which is answered too.
    pub fn handle(
        &mut self,
        b: &[u8],
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Vec<u8>>,
        accept: impl FnOnce(&Request) -> Result<Config, RejectReason>,
    ) -> Option<Conn> {
        let h = Header::parse(b)?;
        if !h.ctrl || h.typ != CTRL_HANDSHAKE {
            return None;
        }
        let hs = Handshake::parse(&b[HEADER_SIZE..])?;
        let bucket = Listener::bucket();
        match hs.typ {
            HS_INDUCTION => {
                let resp = Handshake {
                    version: 5,
                    ext_field: SRT_MAGIC,
                    isn: hs.isn,
                    mtu: hs.mtu,
                    flow_window: hs.flow_window,
                    typ: HS_INDUCTION,
                    socket_id: 0,
                    cookie: self.cookie(from, bucket),
                    peer_ip: peer_ip(from),
                    ..Handshake::default()
                };
                let mut v = Vec::new();
                Header {
                    ctrl: true,
                    typ: CTRL_HANDSHAKE,
                    dst: hs.socket_id,
                    ..Header::default()
                }
                .write(&mut v);
                resp.write(&mut v);
                out.push(v);
                None
            }
            HS_CONCLUSION => {
                if hs.cookie != self.cookie(from, bucket)
                    && hs.cookie != self.cookie(from, bucket.wrapping_sub(1))
                {
                    return None;
                }
                self.conclusion(&h, &hs, from, now, out, accept)
            }
            _ => None,
        }
    }

    fn conclusion(
        &mut self,
        h: &Header,
        hs: &Handshake,
        from: SocketAddr,
        now: Instant,
        out: &mut Vec<Vec<u8>>,
        accept: impl FnOnce(&Request) -> Result<Config, RejectReason>,
    ) -> Option<Conn> {
        let reject = |r: RejectReason, out: &mut Vec<Vec<u8>>| {
            let mut resp = hs.clone();
            resp.typ = HS_REJECT_BASE + r.0;
            resp.hs = None;
            resp.km = None;
            resp.stream_id = None;
            let mut v = Vec::new();
            Header {
                ctrl: true,
                typ: CTRL_HANDSHAKE,
                dst: hs.socket_id,
                ..Header::default()
            }
            .write(&mut v);
            resp.write(&mut v);
            out.push(v);
            None
        };
        let Some(ext) = hs.hs.filter(|_| hs.version == 5 && !hs.hs_rsp) else {
            return reject(RejectReason::VERSION, out);
        };
        let req = Request {
            remote: from,
            peer_socket_id: hs.socket_id,
            stream_id: hs.stream_id.clone().unwrap_or_default(),
            encrypted: hs.km.is_some(),
            latency: Duration::from_millis(u64::from(ext.rcv_delay.max(ext.snd_delay))),
        };
        let mut cfg = match accept(&req) {
            Ok(c) => c,
            Err(r) => return reject(r, out),
        };
        cfg.stream_id = String::new();
        if cfg.check().is_err() {
            return reject(RejectReason::SYSTEM, out);
        }
        let mut c = Conn::new(cfg, now);
        c.stream_id = req.stream_id;
        match (&c.cfg.passphrase.clone(), &hs.km) {
            (None, Some(_)) | (Some(_), None) => return reject(RejectReason::UNSECURE, out),
            (Some(pass), Some(km)) => {
                let Ok(km) = KeyMaterial::decode(km, |s, l| self.kek(pass, s, l)) else {
                    return reject(RejectReason::BAD_SECRET, out);
                };
                let Some(crypt) = Cryptor::new(&km) else {
                    return reject(RejectReason::BAD_SECRET, out);
                };
                c.kk = if km.even.is_some() { KK_EVEN } else { KK_ODD };
                c.cfg.pbkeylen = km.key_len;
                c.crypt = Some(crypt);
                c.km = Some(km);
            }
            (None, None) => {}
        }
        c.socket_id = socket_id_of(rand_u32());
        c.peer_id = hs.socket_id;
        c.isn = hs.isn;
        c.snd_base = hs.isn;
        c.snd_next = hs.isn;
        c.rcv_base = hs.isn;
        c.rcv_max = hs.isn;
        c.ack_acked = hs.isn;
        let mine = c.cfg.latency.as_micros() as i64;
        c.rcv_latency = mine.max(i64::from(ext.snd_delay) * 1000);
        c.snd_latency = mine.max(i64::from(ext.rcv_delay) * 1000);
        if hs.flow_window > 0 {
            c.peer_flow_window = hs.flow_window.min(1 << 20) as usize;
        }
        let mut resp = Handshake {
            version: 5,
            ext_field: EXT_FLAG_HSREQ,
            isn: hs.isn,
            mtu: hs.mtu,
            flow_window: c.cfg.flow_window as u32,
            typ: HS_CONCLUSION,
            socket_id: c.socket_id,
            cookie: hs.cookie,
            peer_ip: peer_ip(from),
            hs: Some(HsExt {
                version: SRT_VERSION,
                flags: Conn::srt_flags(),
                rcv_delay: (c.rcv_latency / 1000).min(i64::from(u16::MAX)) as u16,
                snd_delay: (c.snd_latency / 1000).min(i64::from(u16::MAX)) as u16,
            }),
            hs_rsp: true,
            ..Handshake::default()
        };
        if let Some(km) = &hs.km {
            resp.encryption = hs.encryption;
            resp.ext_field |= EXT_FLAG_KMREQ;
            resp.km = Some(km.clone());
            resp.km_rsp = true;
        }
        let mut v = Vec::new();
        Header {
            ctrl: true,
            typ: CTRL_HANDSHAKE,
            dst: hs.socket_id,
            ..Header::default()
        }
        .write(&mut v);
        resp.write(&mut v);
        c.hs_resp = Some(v.clone());
        out.push(v);
        c.connected_at(now, h.ts);
        Some(c)
    }
}

/// What a stream ID asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Mode {
    /// Play (`m=request`, the default).
    #[default]
    Request,
    /// Publish (`m=publish`).
    Publish,
    /// Both ways (`m=bidirectional`).
    Bidirectional,
}

/// A parsed stream ID: plain (`app/stream?query`) or in the access control syntax
/// (`#!::r=app/stream,m=publish,u=user`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamId {
    /// The resource (`r=`), the hub path.
    pub resource: String,
    /// The mode (`m=`).
    pub mode: Mode,
    /// The user (`u=`).
    pub user: String,
    /// The session (`s=`).
    pub session: String,
    /// The query of a plain stream ID.
    pub query: String,
    /// Every `key=value` of the access control syntax.
    pub params: Vec<(String, String)>,
}

impl StreamId {
    /// Parses a stream ID; `None` when it names no resource or is malformed.
    pub fn parse(s: &str) -> Option<StreamId> {
        let mut id = StreamId::default();
        let Some(body) = s.strip_prefix("#!::") else {
            let (r, q) = s.split_once('?').unwrap_or((s, ""));
            id.resource = r.trim_start_matches('/').to_owned();
            id.query = q.to_owned();
            return (!id.resource.is_empty()).then_some(id);
        };
        for kv in body.split(',') {
            let (k, v) = kv.split_once('=')?;
            if k.is_empty() {
                return None;
            }
            match k {
                "r" => id.resource = v.trim_start_matches('/').to_owned(),
                "m" => {
                    id.mode = match v {
                        "request" => Mode::Request,
                        "publish" => Mode::Publish,
                        "bidirectional" => Mode::Bidirectional,
                        _ => return None,
                    }
                }
                "u" => id.user = v.to_owned(),
                "s" => id.session = v.to_owned(),
                _ => {}
            }
            id.params.push((k.to_owned(), v.to_owned()));
        }
        (!id.resource.is_empty()).then_some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_ids() {
        let id = StreamId::parse("#!::r=live/s,m=publish,u=bob,x=1").unwrap();
        assert_eq!(id.resource, "live/s");
        assert_eq!(id.mode, Mode::Publish);
        assert_eq!(id.user, "bob");
        assert_eq!(id.params.len(), 4);
        let p = StreamId::parse("/live/s?token=x").unwrap();
        assert_eq!(
            (p.resource.as_str(), p.query.as_str()),
            ("live/s", "token=x")
        );
        assert_eq!(p.mode, Mode::Request);
        assert!(StreamId::parse("").is_none());
        assert!(StreamId::parse("#!::m=publish").is_none());
        assert!(StreamId::parse("#!::r=a,m=bogus").is_none());
        assert!(StreamId::parse("#!::r=a,junk").is_none());
    }
}
