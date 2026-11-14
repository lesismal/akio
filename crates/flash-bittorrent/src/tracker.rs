//! Trackers: the HTTP (BEP 3, compact peers BEP 23, IPv6 peers BEP 7) and UDP (BEP 15)
//! protocols, announce and scrape, as codecs ([`http`], [`udp`]), a [`TrackerClient`] that
//! speaks both on a flash engine, and a [`TrackerServer`] that serves both from one in-memory
//! swarm store (a flash-http service and a UDP acceptor).

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use flash::Engine;
use flash_core::{Acceptor, Conn, ConnInner, Handler};

use crate::bencode::{self, Value};
use crate::metainfo::{InfoHash, sha1};
use crate::wire::{PeerId, compact_peers, parse_compact_peers};

/// The `event` of an announce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Event {
    /// A regular update.
    #[default]
    None,
    /// The download finished.
    Completed,
    /// The first announce.
    Started,
    /// Leaving the swarm.
    Stopped,
}

impl Event {
    fn http(self) -> Option<&'static str> {
        match self {
            Event::None => None,
            Event::Completed => Some("completed"),
            Event::Started => Some("started"),
            Event::Stopped => Some("stopped"),
        }
    }

    fn udp(self) -> u32 {
        match self {
            Event::None => 0,
            Event::Completed => 1,
            Event::Started => 2,
            Event::Stopped => 3,
        }
    }

    fn from_udp(n: u32) -> Event {
        match n {
            1 => Event::Completed,
            2 => Event::Started,
            3 => Event::Stopped,
            _ => Event::None,
        }
    }

    fn from_http(s: &str) -> Event {
        match s {
            "completed" => Event::Completed,
            "started" => Event::Started,
            "stopped" => Event::Stopped,
            _ => Event::None,
        }
    }
}

/// An announce.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnounceRequest {
    /// The torrent.
    pub info_hash: InfoHash,
    /// Our peer ID.
    pub peer_id: PeerId,
    /// Our listen port.
    pub port: u16,
    /// Bytes uploaded this session.
    pub uploaded: u64,
    /// Bytes downloaded this session.
    pub downloaded: u64,
    /// Bytes still missing.
    pub left: u64,
    /// The event.
    pub event: Event,
    /// Peers wanted (-1: the tracker's default).
    pub num_want: i32,
    /// A random key identifying us across IP changes.
    pub key: u32,
}

impl AnnounceRequest {
    /// A `started` announce of `info_hash` with nothing transferred.
    pub fn new(info_hash: InfoHash, peer_id: PeerId, port: u16, left: u64) -> AnnounceRequest {
        AnnounceRequest {
            info_hash,
            peer_id,
            port,
            uploaded: 0,
            downloaded: 0,
            left,
            event: Event::Started,
            num_want: 50,
            key: 0,
        }
    }
}

/// A tracker's answer to an announce.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnounceResponse {
    /// Seconds until the next announce.
    pub interval: u32,
    /// `min interval`, if given.
    pub min_interval: Option<u32>,
    /// Peers.
    pub peers: Vec<SocketAddr>,
    /// Seeders (`complete`).
    pub seeders: Option<u32>,
    /// Leechers (`incomplete`).
    pub leechers: Option<u32>,
    /// `warning message`.
    pub warning: Option<String>,
}

/// Scrape statistics of one torrent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScrapeStats {
    /// Seeders.
    pub complete: u32,
    /// Completed downloads.
    pub downloaded: u32,
    /// Leechers.
    pub incomplete: u32,
}

/// Why an announce or scrape failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrackerError {
    /// The tracker refused (`failure reason`, or a UDP error message).
    Failure(String),
    /// The answer was malformed.
    Protocol(&'static str),
    /// The URL is not one this client speaks.
    BadUrl(String),
    /// Network failure.
    Io(String),
    /// No answer in time.
    Timeout,
}

impl fmt::Display for TrackerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrackerError::Failure(m) => write!(f, "tracker: failure: {m}"),
            TrackerError::Protocol(m) => write!(f, "tracker: protocol: {m}"),
            TrackerError::BadUrl(u) => write!(f, "tracker: bad url {u}"),
            TrackerError::Io(e) => write!(f, "tracker: io: {e}"),
            TrackerError::Timeout => f.write_str("tracker: timeout"),
        }
    }
}

impl std::error::Error for TrackerError {}

fn percent_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 3);
    for &c in b {
        if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~') {
            s.push(char::from(c));
        } else {
            s.push_str(&format!("%{c:02X}"));
        }
    }
    s
}

fn unpercent(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let h = crate::metainfo::hexval(*b.get(i + 1)?)?;
                let l = crate::metainfo::hexval(*b.get(i + 2)?)?;
                out.push((h << 4) | l);
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
    Some(out)
}

/// The HTTP tracker protocol.
pub mod http {
    use super::*;

    /// The announce URL for `req` at tracker `base` (which may have a query already).
    pub fn announce_url(base: &str, req: &AnnounceRequest) -> String {
        let sep = if base.contains('?') { '&' } else { '?' };
        let mut u = format!(
            "{base}{sep}info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact=1&numwant={}&key={:08x}",
            percent_bytes(&req.info_hash.0),
            percent_bytes(&req.peer_id),
            req.port,
            req.uploaded,
            req.downloaded,
            req.left,
            req.num_want.max(0),
            req.key
        );
        if let Some(e) = req.event.http() {
            u.push_str("&event=");
            u.push_str(e);
        }
        u
    }

    /// The scrape URL of an announce URL (`.../announce` -> `.../scrape`), BEP 48.
    pub fn scrape_url(announce: &str, hashes: &[InfoHash]) -> Option<String> {
        let (path, query) = announce
            .split_once('?')
            .map_or((announce, None), |(p, q)| (p, Some(q)));
        let slash = path.rfind('/')?;
        let last = &path[slash + 1..];
        let rest = last.strip_prefix("announce")?;
        let mut u = format!("{}/scrape{rest}", &path[..slash]);
        let mut sep = '?';
        if let Some(q) = query {
            u.push('?');
            u.push_str(q);
            sep = '&';
        }
        for h in hashes {
            u.push(sep);
            u.push_str("info_hash=");
            u.push_str(&percent_bytes(&h.0));
            sep = '&';
        }
        Some(u)
    }

    /// Parses an announce response body.
    pub fn parse_announce(body: &[u8]) -> Result<AnnounceResponse, TrackerError> {
        let v = bencode::decode(body)
            .map_err(|_| TrackerError::Protocol("response is not bencoded"))?;
        if let Some(f) = v.bytes_at("failure reason") {
            return Err(TrackerError::Failure(
                String::from_utf8_lossy(f).into_owned(),
            ));
        }
        let mut r = AnnounceResponse {
            interval: v
                .int("interval")
                .and_then(|i| u32::try_from(i).ok())
                .ok_or(TrackerError::Protocol("no interval"))?,
            min_interval: v.int("min interval").and_then(|i| u32::try_from(i).ok()),
            seeders: v.int("complete").and_then(|i| u32::try_from(i).ok()),
            leechers: v.int("incomplete").and_then(|i| u32::try_from(i).ok()),
            warning: v.str_at("warning message").map(str::to_owned),
            peers: Vec::new(),
        };
        match v.get("peers") {
            Some(Value::Bytes(b)) => r.peers = parse_compact_peers(b, false),
            Some(Value::List(l)) => {
                for p in l {
                    let ip = p.str_at("ip").and_then(|s| s.parse::<IpAddr>().ok());
                    let port = p.int("port").and_then(|n| u16::try_from(n).ok());
                    if let (Some(ip), Some(port)) = (ip, port) {
                        r.peers.push(SocketAddr::new(ip, port));
                    }
                }
            }
            _ => {}
        }
        if let Some(b) = v.bytes_at("peers6") {
            r.peers.extend(parse_compact_peers(b, true));
        }
        Ok(r)
    }

    /// Parses a scrape response body.
    pub fn parse_scrape(body: &[u8]) -> Result<HashMap<InfoHash, ScrapeStats>, TrackerError> {
        let v = bencode::decode(body)
            .map_err(|_| TrackerError::Protocol("response is not bencoded"))?;
        if let Some(f) = v.bytes_at("failure reason") {
            return Err(TrackerError::Failure(
                String::from_utf8_lossy(f).into_owned(),
            ));
        }
        let files = v
            .get("files")
            .and_then(Value::as_dict)
            .ok_or(TrackerError::Protocol("no files"))?;
        let mut out = HashMap::new();
        for (k, s) in files {
            let Ok(h) = <[u8; 20]>::try_from(k.as_slice()) else {
                continue;
            };
            let n = |key| s.int(key).and_then(|i| u32::try_from(i).ok()).unwrap_or(0);
            out.insert(
                InfoHash(h),
                ScrapeStats {
                    complete: n("complete"),
                    downloaded: n("downloaded"),
                    incomplete: n("incomplete"),
                },
            );
        }
        Ok(out)
    }

    /// Parses the query of an announce (server side): `None` if a required field is missing.
    pub fn parse_announce_query(query: &str) -> Option<(AnnounceRequest, bool)> {
        let mut ih = None;
        let mut pid = None;
        let mut req = AnnounceRequest::new(InfoHash::default(), [0; 20], 0, 0);
        req.event = Event::None;
        let mut compact = false;
        let mut port = None;
        for kv in query.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let raw = unpercent(v)?;
            let txt = String::from_utf8_lossy(&raw);
            match k {
                "info_hash" => ih = <[u8; 20]>::try_from(raw.as_slice()).ok().map(InfoHash),
                "peer_id" => pid = <[u8; 20]>::try_from(raw.as_slice()).ok(),
                "port" => port = txt.parse().ok(),
                "uploaded" => req.uploaded = txt.parse().unwrap_or(0),
                "downloaded" => req.downloaded = txt.parse().unwrap_or(0),
                "left" => req.left = txt.parse().unwrap_or(0),
                "event" => req.event = Event::from_http(&txt),
                "numwant" => req.num_want = txt.parse().unwrap_or(50),
                "compact" => compact = txt == "1",
                _ => {}
            }
        }
        req.info_hash = ih?;
        req.peer_id = pid?;
        req.port = port?;
        Some((req, compact))
    }
}

/// The UDP tracker protocol (BEP 15).
pub mod udp {
    use super::*;

    /// The magic `protocol_id` of a connect request.
    pub const PROTOCOL_ID: u64 = 0x0417_2710_1980;
    /// Action: connect.
    pub const CONNECT: u32 = 0;
    /// Action: announce.
    pub const ANNOUNCE: u32 = 1;
    /// Action: scrape.
    pub const SCRAPE: u32 = 2;
    /// Action: error.
    pub const ERROR: u32 = 3;

    fn u32_at(b: &[u8], i: usize) -> u32 {
        u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
    }

    fn u64_at(b: &[u8], i: usize) -> u64 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i..i + 8]);
        u64::from_be_bytes(w)
    }

    /// A connect request.
    pub fn connect_request(tid: u32) -> Vec<u8> {
        let mut b = Vec::with_capacity(16);
        b.extend_from_slice(&PROTOCOL_ID.to_be_bytes());
        b.extend_from_slice(&CONNECT.to_be_bytes());
        b.extend_from_slice(&tid.to_be_bytes());
        b
    }

    /// An announce request.
    pub fn announce_request(conn_id: u64, tid: u32, r: &AnnounceRequest) -> Vec<u8> {
        let mut b = Vec::with_capacity(98);
        b.extend_from_slice(&conn_id.to_be_bytes());
        b.extend_from_slice(&ANNOUNCE.to_be_bytes());
        b.extend_from_slice(&tid.to_be_bytes());
        b.extend_from_slice(&r.info_hash.0);
        b.extend_from_slice(&r.peer_id);
        b.extend_from_slice(&r.downloaded.to_be_bytes());
        b.extend_from_slice(&r.left.to_be_bytes());
        b.extend_from_slice(&r.uploaded.to_be_bytes());
        b.extend_from_slice(&r.event.udp().to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes()); // ip: the sender's
        b.extend_from_slice(&r.key.to_be_bytes());
        b.extend_from_slice(&r.num_want.to_be_bytes());
        b.extend_from_slice(&r.port.to_be_bytes());
        b
    }

    /// A scrape request.
    pub fn scrape_request(conn_id: u64, tid: u32, hashes: &[InfoHash]) -> Vec<u8> {
        let mut b = Vec::with_capacity(16 + 20 * hashes.len());
        b.extend_from_slice(&conn_id.to_be_bytes());
        b.extend_from_slice(&SCRAPE.to_be_bytes());
        b.extend_from_slice(&tid.to_be_bytes());
        for h in hashes {
            b.extend_from_slice(&h.0);
        }
        b
    }

    /// A reply from a tracker.
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Reply {
        /// To a connect.
        Connect {
            /// Transaction ID.
            tid: u32,
            /// The connection ID to use for a minute.
            conn_id: u64,
        },
        /// To an announce.
        Announce {
            /// Transaction ID.
            tid: u32,
            /// The answer.
            resp: AnnounceResponse,
        },
        /// To a scrape: stats in request order.
        Scrape {
            /// Transaction ID.
            tid: u32,
            /// Per torrent.
            stats: Vec<ScrapeStats>,
        },
        /// An error.
        Error {
            /// Transaction ID.
            tid: u32,
            /// Message.
            message: String,
        },
    }

    /// Parses a tracker's reply; `v6` says whether peers are 18-byte IPv6 entries.
    pub fn parse_reply(b: &[u8], v6: bool) -> Result<Reply, TrackerError> {
        if b.len() < 8 {
            return Err(TrackerError::Protocol("short reply"));
        }
        let (action, tid) = (u32_at(b, 0), u32_at(b, 4));
        match action {
            CONNECT if b.len() >= 16 => Ok(Reply::Connect {
                tid,
                conn_id: u64_at(b, 8),
            }),
            ANNOUNCE if b.len() >= 20 => Ok(Reply::Announce {
                tid,
                resp: AnnounceResponse {
                    interval: u32_at(b, 8),
                    leechers: Some(u32_at(b, 12)),
                    seeders: Some(u32_at(b, 16)),
                    peers: parse_compact_peers(&b[20..], v6),
                    ..AnnounceResponse::default()
                },
            }),
            SCRAPE => Ok(Reply::Scrape {
                tid,
                stats: b[8..]
                    .chunks_exact(12)
                    .map(|c| ScrapeStats {
                        complete: u32_at(c, 0),
                        downloaded: u32_at(c, 4),
                        incomplete: u32_at(c, 8),
                    })
                    .collect(),
            }),
            ERROR => Ok(Reply::Error {
                tid,
                message: String::from_utf8_lossy(&b[8..]).into_owned(),
            }),
            _ => Err(TrackerError::Protocol("unknown action")),
        }
    }

    /// A request to a tracker (server side).
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum Request {
        /// Connect.
        Connect {
            /// Transaction ID.
            tid: u32,
        },
        /// Announce.
        Announce {
            /// Connection ID.
            conn_id: u64,
            /// Transaction ID.
            tid: u32,
            /// The announce.
            req: AnnounceRequest,
        },
        /// Scrape.
        Scrape {
            /// Connection ID.
            conn_id: u64,
            /// Transaction ID.
            tid: u32,
            /// Torrents.
            hashes: Vec<InfoHash>,
        },
    }

    /// Parses a request (server side).
    pub fn parse_request(b: &[u8]) -> Result<Request, TrackerError> {
        if b.len() < 16 {
            return Err(TrackerError::Protocol("short request"));
        }
        let conn_id = u64_at(b, 0);
        let (action, tid) = (u32_at(b, 8), u32_at(b, 12));
        match action {
            CONNECT if conn_id == PROTOCOL_ID => Ok(Request::Connect { tid }),
            ANNOUNCE if b.len() >= 98 => {
                let mut ih = [0u8; 20];
                ih.copy_from_slice(&b[16..36]);
                let mut pid = [0u8; 20];
                pid.copy_from_slice(&b[36..56]);
                let mut req = AnnounceRequest::new(
                    InfoHash(ih),
                    pid,
                    u16::from_be_bytes([b[96], b[97]]),
                    u64_at(b, 64),
                );
                req.downloaded = u64_at(b, 56);
                req.uploaded = u64_at(b, 72);
                req.event = Event::from_udp(u32_at(b, 80));
                req.key = u32_at(b, 88);
                req.num_want = u32_at(b, 92) as i32;
                Ok(Request::Announce { conn_id, tid, req })
            }
            SCRAPE => Ok(Request::Scrape {
                conn_id,
                tid,
                hashes: b[16..]
                    .chunks_exact(20)
                    .take(74)
                    .map(|c| {
                        let mut h = [0u8; 20];
                        h.copy_from_slice(c);
                        InfoHash(h)
                    })
                    .collect(),
            }),
            _ => Err(TrackerError::Protocol("bad request")),
        }
    }
}

type AnnounceDone = Box<dyn FnOnce(Result<AnnounceResponse, TrackerError>) + Send>;
type ScrapeDone = Box<dyn FnOnce(Result<HashMap<InfoHash, ScrapeStats>, TrackerError>) + Send>;

enum Done {
    Announce(AnnounceDone),
    Scrape(ScrapeDone),
}

enum UdpWhat {
    Announce(AnnounceRequest),
    Scrape(Vec<InfoHash>),
}

struct UdpTxn {
    what: UdpWhat,
    v6: bool,
    tid: u32,
    conn: Option<Arc<ConnInner>>,
    packet: Vec<u8>,
    connected: bool,
    deadline: Instant,
    tries: u32,
    done: Option<Done>,
}

struct TrackerInner {
    engine: Arc<Engine>,
    http: flash_http::client::Client,
    txns: Mutex<HashMap<u64, UdpTxn>>,
    next: std::sync::atomic::AtomicU64,
    timeout: Duration,
    retries: u32,
}

/// Announces and scrapes over HTTP(S) (through flash-http's client) and UDP (BEP 15, on
/// sockets of the engine's UDP client threads). Cheap to clone.
#[derive(Clone)]
pub struct TrackerClient {
    inner: Arc<TrackerInner>,
}

impl fmt::Debug for TrackerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackerClient").finish_non_exhaustive()
    }
}

impl TrackerClient {
    /// A client on `engine` (started, with client threads for HTTP and UDP client threads for
    /// UDP trackers). A UDP request is sent again after `timeout`, doubling, `retries` times.
    pub fn new(engine: Arc<Engine>, timeout: Duration, retries: u32) -> TrackerClient {
        let inner = Arc::new(TrackerInner {
            http: flash_http::client::Client::new(engine.clone()),
            engine,
            txns: Mutex::new(HashMap::new()),
            next: std::sync::atomic::AtomicU64::new(1),
            timeout,
            retries,
        });
        let weak = Arc::downgrade(&inner);
        let _ = std::thread::Builder::new()
            .name("flash-bt-tracker".into())
            .spawn(move || retransmit_loop(&weak));
        TrackerClient { inner }
    }

    /// Announces `req` to `url` (`http://`, `https://` or `udp://`); `done` runs once, on an
    /// I/O or timer thread.
    pub fn announce(
        &self,
        url: &str,
        req: &AnnounceRequest,
        done: impl FnOnce(Result<AnnounceResponse, TrackerError>) + Send + 'static,
    ) {
        if url.starts_with("http://") || url.starts_with("https://") {
            let u = http::announce_url(url, req);
            self.inner.http.request(
                flash_http::client::ClientRequest::get(&u),
                move |r| match r {
                    Ok(resp) if resp.status == 200 => done(http::parse_announce(&resp.body)),
                    Ok(resp) => done(Err(TrackerError::Io(format!(
                        "http status {}",
                        resp.status
                    )))),
                    Err(e) => done(Err(TrackerError::Io(e.to_string()))),
                },
            );
        } else if let Some(hp) = url.strip_prefix("udp://") {
            self.udp(
                hp,
                UdpWhat::Announce(req.clone()),
                Done::Announce(Box::new(done)),
            );
        } else {
            done(Err(TrackerError::BadUrl(url.to_owned())));
        }
    }

    /// Scrapes `hashes` at the tracker whose announce URL is `url`.
    pub fn scrape(
        &self,
        url: &str,
        hashes: &[InfoHash],
        done: impl FnOnce(Result<HashMap<InfoHash, ScrapeStats>, TrackerError>) + Send + 'static,
    ) {
        if url.starts_with("http://") || url.starts_with("https://") {
            let Some(u) = http::scrape_url(url, hashes) else {
                return done(Err(TrackerError::BadUrl(url.to_owned())));
            };
            self.inner.http.request(
                flash_http::client::ClientRequest::get(&u),
                move |r| match r {
                    Ok(resp) if resp.status == 200 => done(http::parse_scrape(&resp.body)),
                    Ok(resp) => done(Err(TrackerError::Io(format!(
                        "http status {}",
                        resp.status
                    )))),
                    Err(e) => done(Err(TrackerError::Io(e.to_string()))),
                },
            );
        } else if let Some(hp) = url.strip_prefix("udp://") {
            self.udp(
                hp,
                UdpWhat::Scrape(hashes.to_vec()),
                Done::Scrape(Box::new(done)),
            );
        } else {
            done(Err(TrackerError::BadUrl(url.to_owned())));
        }
    }

    fn udp(&self, hostport: &str, what: UdpWhat, done: Done) {
        let hp = hostport.split('/').next().unwrap_or(hostport);
        let Ok(Some(addr)) = hp.to_socket_addrs().map(|mut a| a.next()) else {
            return fail(done, TrackerError::BadUrl(hostport.to_owned()));
        };
        let id = self
            .inner
            .next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tid = crate::rand_u32();
        let packet = udp::connect_request(tid);
        self.inner
            .txns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                id,
                UdpTxn {
                    what,
                    v6: addr.is_ipv6(),
                    tid,
                    conn: None,
                    packet,
                    connected: false,
                    deadline: Instant::now() + self.inner.timeout,
                    tries: 0,
                    done: Some(done),
                },
            );
        let weak = Arc::downgrade(&self.inner);
        let weak2 = weak.clone();
        self.inner
            .engine
            .dial_udp(addr, UdpAcceptor { inner: weak, id }, move |e| {
                if let Some(inner) = weak2.upgrade() {
                    let t = inner
                        .txns
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .remove(&id);
                    if let Some(mut t) = t {
                        if let Some(d) = t.done.take() {
                            fail(d, TrackerError::Io(e.to_string()));
                        }
                    }
                }
            });
    }
}

fn fail(done: Done, e: TrackerError) {
    match done {
        Done::Announce(d) => d(Err(e)),
        Done::Scrape(d) => d(Err(e)),
    }
}

fn retransmit_loop(weak: &Weak<TrackerInner>) {
    loop {
        std::thread::sleep(Duration::from_millis(100));
        let Some(inner) = weak.upgrade() else { return };
        let now = Instant::now();
        let mut failed = Vec::new();
        {
            let mut txns = inner.txns.lock().unwrap_or_else(|p| p.into_inner());
            let mut gone = Vec::new();
            for (id, t) in txns.iter_mut() {
                if now < t.deadline {
                    continue;
                }
                if t.tries >= inner.retries {
                    gone.push(*id);
                    continue;
                }
                t.tries += 1;
                t.deadline = now + inner.timeout * (1 << t.tries.min(8));
                if let Some(c) = &t.conn {
                    let _ = c.send(&t.packet);
                }
            }
            for id in gone {
                if let Some(mut t) = txns.remove(&id) {
                    if let Some(c) = &t.conn {
                        c.close();
                    }
                    if let Some(d) = t.done.take() {
                        failed.push(d);
                    }
                }
            }
        }
        for d in failed {
            fail(d, TrackerError::Timeout);
        }
    }
}

struct UdpAcceptor {
    inner: Weak<TrackerInner>,
    id: u64,
}

struct UdpHandler {
    inner: Weak<TrackerInner>,
    id: u64,
}

impl Acceptor for UdpAcceptor {
    type Handler = UdpHandler;
    fn on_open(&self, c: &Conn<UdpHandler>) -> UdpHandler {
        if let Some(inner) = self.inner.upgrade() {
            let mut txns = inner.txns.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(t) = txns.get_mut(&self.id) {
                t.conn = Some(c.inner().clone());
                let _ = c.send(&t.packet);
            } else {
                c.close();
            }
        }
        UdpHandler {
            inner: self.inner.clone(),
            id: self.id,
        }
    }
}

impl Handler for UdpHandler {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut txns = inner.txns.lock().unwrap_or_else(|p| p.into_inner());
        let Some(t) = txns.get_mut(&self.id) else {
            return;
        };
        let Ok(reply) = udp::parse_reply(data, t.v6) else {
            return;
        };
        let finish = |txns: &mut HashMap<u64, UdpTxn>, r: Result<Reply2, TrackerError>| {
            let d = txns.remove(&self.id).and_then(|mut t| t.done.take());
            (d, r)
        };
        let (d, r) = match reply {
            udp::Reply::Connect { tid, conn_id } if tid == t.tid && !t.connected => {
                t.connected = true;
                t.tid = crate::rand_u32();
                t.packet = match &t.what {
                    UdpWhat::Announce(req) => udp::announce_request(conn_id, t.tid, req),
                    UdpWhat::Scrape(h) => udp::scrape_request(conn_id, t.tid, h),
                };
                t.tries = 0;
                t.deadline = Instant::now() + inner.timeout;
                let _ = c.send(&t.packet);
                return;
            }
            udp::Reply::Announce { tid, resp } if tid == t.tid && t.connected => {
                finish(&mut txns, Ok(Reply2::Announce(resp)))
            }
            udp::Reply::Scrape { tid, stats } if tid == t.tid && t.connected => {
                let hashes = match &t.what {
                    UdpWhat::Scrape(h) => h.clone(),
                    UdpWhat::Announce(_) => Vec::new(),
                };
                finish(
                    &mut txns,
                    Ok(Reply2::Scrape(hashes.into_iter().zip(stats).collect())),
                )
            }
            udp::Reply::Error { tid, message } if tid == t.tid => {
                finish(&mut txns, Err(TrackerError::Failure(message)))
            }
            _ => return,
        };
        drop(txns);
        c.close();
        match (d, r) {
            (Some(Done::Announce(d)), Ok(Reply2::Announce(a))) => d(Ok(a)),
            (Some(Done::Scrape(d)), Ok(Reply2::Scrape(s))) => d(Ok(s)),
            (Some(d), Err(e)) => fail(d, e),
            (Some(d), Ok(_)) => fail(d, TrackerError::Protocol("unexpected reply")),
            (None, _) => {}
        }
    }

    fn on_close(&mut self, _c: &Conn<Self>, err: Option<flash_core::Error>) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let t = inner
            .txns
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
        if let Some(mut t) = t {
            if let Some(d) = t.done.take() {
                let e = err.map_or_else(|| "closed".to_owned(), |e| e.to_string());
                fail(d, TrackerError::Io(e));
            }
        }
    }
}

enum Reply2 {
    Announce(AnnounceResponse),
    Scrape(HashMap<InfoHash, ScrapeStats>),
}

// ---------------------------------------------------------------------------------------------
// Server

#[derive(Clone, Debug)]
struct PeerEntry {
    addr: SocketAddr,
    seeder: bool,
    seen: Instant,
}

#[derive(Debug, Default)]
struct Swarm {
    peers: HashMap<PeerId, PeerEntry>,
    downloaded: u32,
}

/// Tracker server settings.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct TrackerConfig {
    /// `interval` handed out.
    pub interval: u32,
    /// Peers not heard from for this long are dropped.
    pub peer_ttl: Duration,
    /// Most peers returned per announce.
    pub max_peers: usize,
    /// If set, only these torrents are tracked.
    pub allow: Option<Vec<InfoHash>>,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        TrackerConfig {
            interval: 1800,
            peer_ttl: Duration::from_secs(3600),
            max_peers: 50,
            allow: None,
        }
    }
}

struct ServerInner {
    cfg: TrackerConfig,
    swarms: Mutex<HashMap<InfoHash, Swarm>>,
    secret: [u8; 16],
}

/// A tracker over HTTP and UDP sharing one in-memory store: [`TrackerServer::http`] is a
/// flash-http [`Service`](flash_http::Service) (it answers paths ending in `announce` and
/// `scrape`), [`TrackerServer::udp`] the acceptor of a UDP [`flash::Listener`]. UDP connection
/// IDs are derived from a secret, the minute and the client address, so no state is kept per
/// client. Cheap to clone.
///
/// ```no_run
/// use flash::{Engine, Listener};
/// use flash_bittorrent::tracker::TrackerServer;
/// let t = TrackerServer::new(Default::default());
/// let addr = "127.0.0.1:6969".parse().unwrap();
/// let engine = Engine::builder()
///     .listen(Listener::tcp(addr).serve(flash_http::serve(t.http())))
///     .listen(Listener::udp(addr).serve(t.udp()))
///     .build()
///     .unwrap();
/// engine.run().unwrap();
/// ```
#[derive(Clone)]
pub struct TrackerServer {
    inner: Arc<ServerInner>,
}

impl fmt::Debug for TrackerServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrackerServer").finish_non_exhaustive()
    }
}

/// The flash-http service of a [`TrackerServer`].
#[derive(Clone, Debug)]
pub struct HttpTracker(TrackerServer);

/// The UDP acceptor of a [`TrackerServer`].
#[derive(Clone, Debug)]
pub struct UdpTracker(TrackerServer);

/// Handler of one UDP tracker client.
#[derive(Debug)]
pub struct UdpTrackerConn(TrackerServer);

impl TrackerServer {
    /// A tracker with `cfg`.
    pub fn new(cfg: TrackerConfig) -> TrackerServer {
        let mut secret = [0u8; 16];
        crate::rand_fill(&mut secret);
        TrackerServer {
            inner: Arc::new(ServerInner {
                cfg,
                swarms: Mutex::new(HashMap::new()),
                secret,
            }),
        }
    }

    /// The HTTP side.
    pub fn http(&self) -> HttpTracker {
        HttpTracker(self.clone())
    }

    /// The UDP side.
    pub fn udp(&self) -> UdpTracker {
        UdpTracker(self.clone())
    }

    /// Scrape statistics of `info_hash`.
    pub fn stats(&self, info_hash: &InfoHash) -> ScrapeStats {
        let swarms = self.inner.swarms.lock().unwrap_or_else(|p| p.into_inner());
        swarms
            .get(info_hash)
            .map_or_else(ScrapeStats::default, stats_of)
    }

    /// Handles an announce from `from`: records the peer and returns the answer.
    pub fn announce(
        &self,
        from: IpAddr,
        req: &AnnounceRequest,
    ) -> Result<AnnounceResponse, TrackerError> {
        if let Some(allow) = &self.inner.cfg.allow {
            if !allow.contains(&req.info_hash) {
                return Err(TrackerError::Failure("torrent not tracked".into()));
            }
        }
        let now = Instant::now();
        let mut swarms = self.inner.swarms.lock().unwrap_or_else(|p| p.into_inner());
        let ttl = self.inner.cfg.peer_ttl;
        let s = swarms.entry(req.info_hash).or_default();
        s.peers.retain(|_, p| now.duration_since(p.seen) < ttl);
        let seeder = req.left == 0;
        if req.event == Event::Stopped {
            s.peers.remove(&req.peer_id);
        } else {
            if req.event == Event::Completed {
                s.downloaded += 1;
            }
            s.peers.insert(
                req.peer_id,
                PeerEntry {
                    addr: SocketAddr::new(from, req.port),
                    seeder,
                    seen: now,
                },
            );
        }
        let want = usize::try_from(req.num_want)
            .unwrap_or(self.inner.cfg.max_peers)
            .min(self.inner.cfg.max_peers);
        let peers = s
            .peers
            .iter()
            .filter(|(id, p)| **id != req.peer_id && !(seeder && p.seeder))
            .map(|(_, p)| p.addr)
            .take(want)
            .collect();
        let st = stats_of(s);
        Ok(AnnounceResponse {
            interval: self.inner.cfg.interval,
            min_interval: None,
            peers,
            seeders: Some(st.complete),
            leechers: Some(st.incomplete),
            warning: None,
        })
    }

    fn conn_id(&self, addr: SocketAddr, minute: u64) -> u64 {
        let mut b = self.inner.secret.to_vec();
        b.extend_from_slice(&minute.to_be_bytes());
        b.extend_from_slice(addr.to_string().as_bytes());
        let h = sha1(&b);
        let mut w = [0u8; 8];
        w.copy_from_slice(&h[..8]);
        u64::from_be_bytes(w)
    }

    fn conn_id_valid(&self, addr: SocketAddr, id: u64) -> bool {
        let m = minute();
        id == self.conn_id(addr, m) || id == self.conn_id(addr, m.wrapping_sub(1))
    }

    /// Answers one UDP datagram from `from`; `None` when it gets no answer.
    pub fn handle_udp(&self, from: SocketAddr, data: &[u8]) -> Option<Vec<u8>> {
        let err = |tid: u32, m: &str| {
            let mut b = udp::ERROR.to_be_bytes().to_vec();
            b.extend_from_slice(&tid.to_be_bytes());
            b.extend_from_slice(m.as_bytes());
            b
        };
        match udp::parse_request(data).ok()? {
            udp::Request::Connect { tid } => {
                let mut b = udp::CONNECT.to_be_bytes().to_vec();
                b.extend_from_slice(&tid.to_be_bytes());
                b.extend_from_slice(&self.conn_id(from, minute()).to_be_bytes());
                Some(b)
            }
            udp::Request::Announce { conn_id, tid, req } => {
                if !self.conn_id_valid(from, conn_id) {
                    return Some(err(tid, "bad connection id"));
                }
                match self.announce(from.ip(), &req) {
                    Ok(r) => {
                        let mut b = udp::ANNOUNCE.to_be_bytes().to_vec();
                        b.extend_from_slice(&tid.to_be_bytes());
                        b.extend_from_slice(&r.interval.to_be_bytes());
                        b.extend_from_slice(&r.leechers.unwrap_or(0).to_be_bytes());
                        b.extend_from_slice(&r.seeders.unwrap_or(0).to_be_bytes());
                        b.extend_from_slice(&compact_peers(&r.peers, from.is_ipv6()));
                        Some(b)
                    }
                    Err(e) => Some(err(tid, &e.to_string())),
                }
            }
            udp::Request::Scrape {
                conn_id,
                tid,
                hashes,
            } => {
                if !self.conn_id_valid(from, conn_id) {
                    return Some(err(tid, "bad connection id"));
                }
                let mut b = udp::SCRAPE.to_be_bytes().to_vec();
                b.extend_from_slice(&tid.to_be_bytes());
                for h in hashes {
                    let s = self.stats(&h);
                    b.extend_from_slice(&s.complete.to_be_bytes());
                    b.extend_from_slice(&s.downloaded.to_be_bytes());
                    b.extend_from_slice(&s.incomplete.to_be_bytes());
                }
                Some(b)
            }
        }
    }

    /// Answers an HTTP request target (`/announce?...` or `/scrape?...`) from `from`:
    /// the status and bencoded body.
    pub fn handle_http(&self, from: IpAddr, target: &str) -> (u16, Vec<u8>) {
        let failure = |m: &str| {
            (
                200,
                bencode::encode(&Value::dict().with("failure reason", m)),
            )
        };
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let last = path.rsplit('/').next().unwrap_or("");
        if last.starts_with("announce") {
            let Some((req, compact)) = http::parse_announce_query(query) else {
                return failure("bad announce");
            };
            match self.announce(from, &req) {
                Ok(r) => {
                    let mut d = Value::dict()
                        .with("interval", i64::from(r.interval))
                        .with("complete", i64::from(r.seeders.unwrap_or(0)))
                        .with("incomplete", i64::from(r.leechers.unwrap_or(0)));
                    if compact {
                        d.insert("peers", compact_peers(&r.peers, false));
                        let p6 = compact_peers(&r.peers, true);
                        if !p6.is_empty() {
                            d.insert("peers6", p6);
                        }
                    } else {
                        d.insert(
                            "peers",
                            r.peers
                                .iter()
                                .map(|p| {
                                    Value::dict()
                                        .with("ip", p.ip().to_string())
                                        .with("port", i64::from(p.port()))
                                })
                                .collect::<Vec<_>>(),
                        );
                    }
                    (200, bencode::encode(&d))
                }
                Err(e) => failure(&e.to_string()),
            }
        } else if last.starts_with("scrape") {
            let mut files = Value::dict();
            for kv in query.split('&') {
                if let Some(v) = kv.strip_prefix("info_hash=") {
                    if let Some(h) =
                        unpercent(v).and_then(|b| <[u8; 20]>::try_from(b.as_slice()).ok())
                    {
                        let s = self.stats(&InfoHash(h));
                        if let Value::Dict(d) = &mut files {
                            d.insert(
                                h.to_vec(),
                                Value::dict()
                                    .with("complete", i64::from(s.complete))
                                    .with("downloaded", i64::from(s.downloaded))
                                    .with("incomplete", i64::from(s.incomplete)),
                            );
                        }
                    }
                }
            }
            (200, bencode::encode(&Value::dict().with("files", files)))
        } else {
            (404, b"not found".to_vec())
        }
    }
}

fn stats_of(s: &Swarm) -> ScrapeStats {
    let complete = s.peers.values().filter(|p| p.seeder).count() as u32;
    ScrapeStats {
        complete,
        downloaded: s.downloaded,
        incomplete: s.peers.len() as u32 - complete,
    }
}

fn minute() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() / 60)
}

impl flash_http::Service for HttpTracker {
    fn call(&self, ctx: &mut flash_http::Context) {
        let (status, body) = self.0.handle_http(ctx.peer().ip(), &ctx.req().target);
        ctx.bytes(status, "text/plain", body);
    }
}

impl Acceptor for UdpTracker {
    type Handler = UdpTrackerConn;
    fn on_open(&self, _c: &Conn<UdpTrackerConn>) -> UdpTrackerConn {
        UdpTrackerConn(self.0.clone())
    }
}

impl Handler for UdpTrackerConn {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        if let Some(r) = self.0.handle_udp(c.peer_addr(), data) {
            let _ = c.send(&r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_codec() {
        let req = AnnounceRequest::new(InfoHash([0xAB; 20]), *b"-FL0100-abcdefghijkl", 6881, 100);
        let url = http::announce_url("http://t:1/announce", &req);
        assert!(url.contains("info_hash=%AB%AB"));
        assert!(url.contains("event=started"));
        let q = url.split_once('?').unwrap().1;
        let (back, compact) = http::parse_announce_query(q).unwrap();
        assert!(compact);
        assert_eq!(back.info_hash, req.info_hash);
        assert_eq!(back.peer_id, req.peer_id);
        assert_eq!(back.left, 100);
        assert_eq!(
            http::scrape_url("http://t/x/announce.php?k=1", &[InfoHash([1; 20])]).unwrap(),
            format!("http://t/x/scrape.php?k=1&info_hash={}", "%01".repeat(20))
        );
        assert!(http::scrape_url("http://t/a", &[]).is_none());
        let body =
            b"d8:completei1e10:incompletei2e8:intervali60e5:peers6:\x7f\x00\x00\x01\x1a\xe1e";
        let r = http::parse_announce(body).unwrap();
        assert_eq!(r.interval, 60);
        assert_eq!(r.peers, vec!["127.0.0.1:6881".parse().unwrap()]);
        assert_eq!(
            http::parse_announce(b"d14:failure reason4:nopee").unwrap_err(),
            TrackerError::Failure("nope".into())
        );
        assert!(http::parse_announce(b"d14:failure").is_err());
    }

    #[test]
    fn server_both_protocols() {
        let s = TrackerServer::new(TrackerConfig::default());
        let ih = InfoHash([7; 20]);
        let a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        // HTTP: a seeder, then a leecher sees it.
        let mut seed = AnnounceRequest::new(ih, [1; 20], 6881, 0);
        seed.event = Event::Started;
        let target = http::announce_url("/announce", &seed);
        let (st, body) = s.handle_http(a.ip(), &target);
        assert_eq!(st, 200);
        assert!(http::parse_announce(&body).unwrap().peers.is_empty());
        // UDP: connect, then announce as a leecher.
        let r = s.handle_udp(a, &udp::connect_request(9)).unwrap();
        let udp::Reply::Connect { tid: 9, conn_id } = udp::parse_reply(&r, false).unwrap() else {
            panic!()
        };
        let leech = AnnounceRequest::new(ih, [2; 20], 7000, 10);
        let r = s
            .handle_udp(a, &udp::announce_request(conn_id, 10, &leech))
            .unwrap();
        let udp::Reply::Announce { tid: 10, resp } = udp::parse_reply(&r, false).unwrap() else {
            panic!()
        };
        assert_eq!(resp.peers, vec!["10.0.0.1:6881".parse().unwrap()]);
        assert_eq!((resp.seeders, resp.leechers), (Some(1), Some(1)));
        // A bad connection ID is refused.
        let r = s
            .handle_udp(a, &udp::announce_request(conn_id ^ 1, 11, &leech))
            .unwrap();
        assert!(matches!(
            udp::parse_reply(&r, false).unwrap(),
            udp::Reply::Error { tid: 11, .. }
        ));
        // Scrape, both ways.
        let r = s
            .handle_udp(a, &udp::scrape_request(conn_id, 12, &[ih]))
            .unwrap();
        let udp::Reply::Scrape { stats, .. } = udp::parse_reply(&r, false).unwrap() else {
            panic!()
        };
        assert_eq!(stats[0].complete, 1);
        let (_, body) = s.handle_http(a.ip(), &http::scrape_url("/announce", &[ih]).unwrap());
        assert_eq!(http::parse_scrape(&body).unwrap()[&ih].incomplete, 1);
    }
}
