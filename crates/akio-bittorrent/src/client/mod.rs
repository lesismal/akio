//! A BitTorrent client on one `akio` engine and one port number: TCP for the peer wire protocol
//! and UDP shared by uTP and the DHT ([`UdpPort`]); HTTP and UDP trackers go through a
//! [`TrackerClient`] on the same engine, web seeds (BEP 19) through akio-http's client, and
//! storage reads, writes and hash checks run on a logical pool, never on an I/O thread.
//!
//! - v1, v2 and hybrid torrents (BEP 52): a hybrid torrent is announced, looked up and accepted
//!   under both of its hashes; v2 piece layers missing from a magnet's metadata are fetched from
//!   peers with hash requests, and the client answers hash requests for the layers it has.
//! - IPv6: listening on `[::]:port` serves IPv4 and IPv6 on one dual-stack socket pair; the
//!   DHT then keeps an IPv6 routing table too (BEP 32), and PEX and trackers carry IPv6 peers.
//! - Local Service Discovery (BEP 14, [`ClientConfig::lsd`]) on a thread of its own.
//! - Rate limits ([`RateLimits`]) for the client and per torrent, and seed limits
//!   ([`SeedLimits`]): a torrent that reaches its ratio or seeding time pauses.
//! - Fast resume (ADR-033): with [`ClientConfig::resume_dir`] a torrent's state (pieces had,
//!   v2 piece layers, file sizes and times, peers, totals, limits) is saved on a timer, on pause
//!   and at [`Client::close`], and a torrent added again starts from it without hash-checking
//!   its data; files that changed since are checked again. [`Torrent::resume_data`],
//!   [`AddOptions::resume_data`] and [`Client::add_resume`] move the same data as bytes.
//!
//! ```no_run
//! use akio_bittorrent::client::{AddOptions, Client, ClientConfig};
//! use akio_bittorrent::metainfo::MetaInfo;
//! use std::time::Duration;
//!
//! let mut cfg = ClientConfig::default();
//! cfg.data_dir = "downloads".into();
//! let client = Client::new(cfg).unwrap();
//! let t = client.add_torrent(MetaInfo::load("file.torrent").unwrap(), AddOptions::default()).unwrap();
//! // or: client.add_magnet("magnet:?xt=urn:btih:...", AddOptions::default())
//! assert!(t.wait_complete(Duration::from_secs(600)));
//! println!("{:?}", t.stats());
//! ```

mod lsd;
mod peer;
mod rate;
pub(crate) mod resume;
pub mod storage;
mod torrent;
mod webseed;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_pool::{Pool, PoolConfig};

use crate::dht::{self, DhtEvent, NodeId};
use crate::magnet::Magnet;
use crate::metainfo::{Info, InfoHash, InfoHashV2, MetaInfo, PieceLayers};
use crate::mse::Policy;
use crate::port::UdpPort;
use crate::tracker::{AnnounceRequest, Event, TrackerClient};
use crate::wire::{PeerId, new_peer_id};

pub use resume::ResumeError;
pub use storage::{FileStamp, FileStorage, MemoryStorage, Storage};

use resume::ResumeData;

use torrent::{Cx, NewTorrent, TorrentShared};

/// What a torrent reports through [`ClientConfig::on_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TorrentEvent {
    /// The info dictionary arrived from peers (magnet links).
    MetadataReceived,
    /// The data in storage was checked: `pieces` pieces are had.
    Checked {
        /// Pieces found valid.
        pieces: usize,
    },
    /// A piece was downloaded and passed its hash check.
    PieceVerified(u32),
    /// A downloaded piece failed its hash check (it is downloaded again).
    HashFailed(u32),
    /// Every piece is had: the torrent seeds.
    Completed,
    /// A peer finished its handshake.
    PeerConnected(SocketAddr),
    /// A peer went away.
    PeerDisconnected(SocketAddr),
    /// The torrent was paused or resumed.
    StateChanged(TorrentStatus),
    /// A tracker failed.
    TrackerError {
        /// The tracker.
        url: String,
        /// Why.
        error: String,
    },
    /// Something went wrong (storage, metadata).
    Error(String),
    /// The torrent reached its seed ratio or seeding time ([`SeedLimits`]) and was paused.
    SeedLimitReached,
    /// A web seed failed (it is retried later, backing off).
    WebSeedError {
        /// The web seed.
        url: String,
        /// Why.
        error: String,
    },
    /// Fast-resume data was used: `pieces` pieces are taken as had without a hash check, and
    /// `rechecking` pieces, of files that changed since the save, are checked again. Comes
    /// before [`Checked`](Self::Checked).
    ResumeAccepted {
        /// Pieces trusted.
        pieces: usize,
        /// Pieces checked again.
        rechecking: usize,
    },
    /// Fast-resume data was refused (damaged, another torrent, an unknown version); the
    /// torrent's data is checked in full.
    ResumeRejected(String),
}

/// Upload and download rate limits in bytes per second (`None`: unlimited, the default).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateLimits {
    /// Upload limit.
    pub upload: Option<u64>,
    /// Download limit.
    pub download: Option<u64>,
}

impl RateLimits {
    /// Limits of `upload` and `download` bytes per second.
    pub fn new(upload: Option<u64>, download: Option<u64>) -> RateLimits {
        RateLimits { upload, download }
    }
}

/// When a complete torrent stops seeding (`None`: never, the default). The ratio is bytes
/// uploaded over bytes downloaded in this session (over the torrent's size if nothing was
/// downloaded); seeding time counts from completion (or from the start for a torrent added
/// complete). The torrent is paused and reports [`TorrentEvent::SeedLimitReached`]; resuming it
/// with the limit still reached pauses it again, so raise or clear the limit first.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct SeedLimits {
    /// Stop at this ratio.
    pub ratio: Option<f64>,
    /// Stop after seeding this long.
    pub time: Option<Duration>,
}

impl SeedLimits {
    /// Stop at `ratio` or after `time`, whichever comes first.
    pub fn new(ratio: Option<f64>, time: Option<Duration>) -> SeedLimits {
        SeedLimits { ratio, time }
    }
}

/// Where a torrent is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TorrentStatus {
    /// A magnet link waits for the info dictionary.
    FetchingMetadata,
    /// Storage is being hash-checked.
    Checking,
    /// Pieces are missing.
    Downloading,
    /// Every piece is had.
    Seeding,
    /// Stopped by [`Torrent::pause`].
    Paused,
    /// Storage failed.
    Error,
}

/// A torrent's numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TorrentStats {
    /// Status.
    pub status: TorrentStatus,
    /// Pieces had.
    pub pieces_have: usize,
    /// Pieces in all (0 before the info dictionary).
    pub pieces_total: usize,
    /// Bytes missing.
    pub bytes_left: u64,
    /// The torrent's size.
    pub total_size: u64,
    /// Payload bytes downloaded this session.
    pub downloaded: u64,
    /// Payload bytes uploaded this session.
    pub uploaded: u64,
    /// Connected peers.
    pub peers: usize,
    /// Peer addresses known.
    pub known_peers: usize,
    /// Pieces that failed their check.
    pub hash_fails: u64,
    /// Connected peers that have every piece.
    pub seeders: usize,
    /// Time spent seeding (complete and running), including earlier sessions recorded in
    /// fast-resume data.
    pub seeding_time: Duration,
    /// Web seeds fetching a piece right now.
    pub web_seeds_active: usize,
    /// Pieces read back from storage and hash-checked when the torrent started (all of them
    /// without resume data; only those of changed files with it).
    pub pieces_checked: u64,
    /// Payload bytes uploaded, including earlier sessions recorded in fast-resume data.
    pub total_uploaded: u64,
    /// Payload bytes downloaded, including earlier sessions recorded in fast-resume data.
    pub total_downloaded: u64,
}

/// One connected peer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PeerInfo {
    /// Address.
    pub addr: SocketAddr,
    /// Peer ID.
    pub id: PeerId,
    /// Client name from the extension handshake.
    pub client: Option<String>,
    /// Over uTP (else TCP).
    pub utp: bool,
    /// RC4-encrypted (MSE).
    pub encrypted: bool,
    /// We dialed it.
    pub outgoing: bool,
    /// Pieces it has.
    pub pieces: usize,
    /// Bytes downloaded from it.
    pub downloaded: u64,
    /// Bytes uploaded to it.
    pub uploaded: u64,
    /// We choke it.
    pub am_choking: bool,
    /// It chokes us.
    pub peer_choking: bool,
    /// Its handshake announced v2 support (BEP 52; libtorrent sets it only when it dials).
    pub v2: bool,
}

/// Callback for torrent events: `(info_hash, event)`, called in order after the torrent's
/// lock is released, on whichever thread caused the event.
pub type EventFn = Arc<dyn Fn(InfoHash, &TorrentEvent) + Send + Sync>;

/// Client settings. `#[non_exhaustive]`: start from `ClientConfig::default()`.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Address for TCP and UDP (default `0.0.0.0:6881`; port 0 picks a port free for both).
    /// `[::]:port` listens dual-stack: IPv4 and IPv6 peers, and an IPv6 DHT table (BEP 32).
    pub listen: SocketAddr,
    /// Directory torrents are stored below (default: the working directory).
    pub data_dir: PathBuf,
    /// Peer ID (default: `-ON0100-` and random bytes).
    pub peer_id: Option<PeerId>,
    /// Encryption policy (default [`Policy::Prefer`]).
    pub encryption: Policy,
    /// Dial peers over uTP first (default true); incoming uTP is always accepted.
    pub utp: bool,
    /// Run a DHT node (default true).
    pub dht: bool,
    /// DHT bootstrap nodes (default: none; e.g. `router.bittorrent.com:6881` resolved).
    pub dht_bootstrap: Vec<SocketAddr>,
    /// Peer exchange (default true; never for private torrents).
    pub pex: bool,
    /// Announce to trackers (default true).
    pub trackers: bool,
    /// Upload slots besides the optimistic unchoke (default 4).
    pub upload_slots: usize,
    /// Connections per torrent (default 50).
    pub max_peers_per_torrent: usize,
    /// I/O threads per listener (default 2).
    pub threads: usize,
    /// Disk and hashing threads (default 4).
    pub disk_threads: usize,
    /// Tracker request timeout before the first UDP retransmission (default 5 s).
    pub tracker_timeout: Duration,
    /// Local Service Discovery, BEP 14 (default true; never for private torrents). If port
    /// 6771 or the multicast group cannot be used, the client runs without it.
    pub lsd: bool,
    /// Download from the torrents' web seeds, BEP 19 (default true).
    pub web_seeds: bool,
    /// Rate limits for the whole client (default: none).
    pub rate_limits: RateLimits,
    /// Seed limits torrents start with (default: none; [`AddOptions::seed_limits`] overrides).
    pub seed_limits: SeedLimits,
    /// Directory for fast-resume files, `<info hash hex>.resume` (default: none, nothing is
    /// saved or loaded). Torrents are saved every [`resume_interval`](Self::resume_interval)
    /// when something changed, when paused and at [`Client::close`]; a torrent added again
    /// loads its file. Each save replaces the file atomically.
    pub resume_dir: Option<PathBuf>,
    /// How often changed torrents are saved to [`resume_dir`](Self::resume_dir) (default 30 s).
    pub resume_interval: Duration,
    /// Torrent events.
    pub on_event: Option<EventFn>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("listen", &self.listen)
            .field("data_dir", &self.data_dir)
            .field("encryption", &self.encryption)
            .field("utp", &self.utp)
            .field("dht", &self.dht)
            .field("lsd", &self.lsd)
            .field("rate_limits", &self.rate_limits)
            .field("seed_limits", &self.seed_limits)
            .field("resume_dir", &self.resume_dir)
            .field("resume_interval", &self.resume_interval)
            .finish_non_exhaustive()
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            listen: SocketAddr::from(([0, 0, 0, 0], 6881)),
            data_dir: PathBuf::from("."),
            peer_id: None,
            encryption: Policy::Prefer,
            utp: true,
            dht: true,
            dht_bootstrap: Vec::new(),
            pex: true,
            trackers: true,
            upload_slots: 4,
            max_peers_per_torrent: 50,
            threads: 2,
            disk_threads: 4,
            tracker_timeout: Duration::from_secs(5),
            lsd: true,
            web_seeds: true,
            rate_limits: RateLimits::default(),
            seed_limits: SeedLimits::default(),
            resume_dir: None,
            resume_interval: Duration::from_secs(30),
            on_event: None,
        }
    }
}

/// Options of [`Client::add_torrent`] and [`Client::add_magnet`].
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct AddOptions {
    /// Storage of its own (default: [`FileStorage`] below [`ClientConfig::data_dir`]).
    pub storage: Option<Arc<dyn Storage>>,
    /// Start paused.
    pub paused: bool,
    /// Take every piece as had without checking (a torrent just made from its data).
    pub seed: bool,
    /// Peers to dial.
    pub peers: Vec<SocketAddr>,
    /// Trackers besides the torrent's own.
    pub trackers: Vec<String>,
    /// Web seeds besides the torrent's own (BEP 19).
    pub web_seeds: Vec<String>,
    /// The torrent's own rate limits (default: none; the client's apply as well).
    pub rate_limits: RateLimits,
    /// Seed limits (default: [`ClientConfig::seed_limits`]).
    pub seed_limits: Option<SeedLimits>,
    /// Fast-resume data from [`Torrent::resume_data`] (default: the torrent's file in
    /// [`ClientConfig::resume_dir`], if any). Data of another torrent, or damaged, is refused
    /// with [`TorrentEvent::ResumeRejected`] and the data is checked in full. Its peers,
    /// trackers and web seeds are added; its limits apply unless these options set some; a
    /// torrent saved paused starts paused.
    pub resume_data: Option<Vec<u8>>,
}

impl fmt::Debug for AddOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddOptions")
            .field("paused", &self.paused)
            .field("seed", &self.seed)
            .field("peers", &self.peers)
            .field("trackers", &self.trackers)
            .field("web_seeds", &self.web_seeds)
            .field("rate_limits", &self.rate_limits)
            .field("seed_limits", &self.seed_limits)
            .field("resume_data", &self.resume_data.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

/// Why adding a torrent failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum AddError {
    /// The torrent is already in the client.
    Duplicate(InfoHash),
    /// A malformed magnet link.
    Magnet(crate::magnet::MagnetError),
    /// The client is closed.
    Closed,
    /// [`Client::add_resume`]: the resume data was refused.
    Resume(ResumeError),
}

impl fmt::Display for AddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddError::Duplicate(h) => write!(f, "torrent {h} already added"),
            AddError::Magnet(e) => write!(f, "{e}"),
            AddError::Closed => f.write_str("client closed"),
            AddError::Resume(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AddError {}

pub(crate) struct ClientInner {
    pub(crate) cfg: ClientConfig,
    pub(crate) peer_id: PeerId,
    pub(crate) engine: Arc<Engine>,
    pub(crate) port: UdpPort,
    pub(crate) trackers: TrackerClient,
    pub(crate) pool: Arc<Pool>,
    pub(crate) dht: Option<Mutex<dht::Node>>,
    pub(crate) listen: SocketAddr,
    pub(crate) http: akio_http::client::Client,
    pub(crate) rates: Arc<rate::GlobalRates>,
    torrents: Mutex<HashMap<InfoHash, Arc<TorrentShared>>>,
    /// Other hashes of torrents (a hybrid torrent's truncated v2 hash) to their key.
    aliases: Mutex<HashMap<InfoHash, InfoHash>>,
    req2: Mutex<HashMap<[u8; 20], InfoHash>>,
    lookups: Mutex<HashMap<u64, InfoHash>>,
    pub(crate) closed: AtomicBool,
    /// The maintenance and LSD threads, joined by [`Client::close`].
    maintenance: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl ClientInner {
    /// The torrent of `ih`, by its key or another of its hashes.
    pub(crate) fn torrent(&self, ih: &InfoHash) -> Option<Arc<TorrentShared>> {
        let key = self
            .aliases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(ih)
            .copied()
            .unwrap_or(*ih);
        self.torrents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
            .cloned()
    }

    /// Makes `alias` another name of the torrent keyed `key` (handshakes, MSE, LSD).
    pub(crate) fn add_alias(&self, alias: InfoHash, key: InfoHash) {
        if alias == key {
            return;
        }
        self.aliases
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(alias, key);
        self.req2
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(peer::req2(&alias), key);
    }

    pub(crate) fn lookup_req2(&self, h: &[u8; 20]) -> Option<InfoHash> {
        self.req2
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(h)
            .copied()
    }

    pub(crate) fn dht_ping(&self, addr: SocketAddr) {
        if let Some(d) = &self.dht {
            let out = {
                let mut n = d.lock().unwrap_or_else(|p| p.into_inner());
                n.ping(addr);
                n.take_outgoing()
            };
            for (to, b) in out {
                self.port.send_to(to, b);
            }
        }
    }

    pub(crate) fn all(&self) -> Vec<Arc<TorrentShared>> {
        self.torrents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .cloned()
            .collect()
    }
}

/// A BitTorrent client. Cheap to clone; [`Client::close`] (or dropping the last clone) stops it.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("listen", &self.inner.listen)
            .finish_non_exhaustive()
    }
}

/// A torrent in a [`Client`]. Cheap to clone.
#[derive(Clone)]
pub struct Torrent {
    shared: Arc<TorrentShared>,
}

impl fmt::Debug for Torrent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Torrent({})", self.shared.info_hash)
    }
}

fn free_port(ip: std::net::IpAddr) -> io::Result<u16> {
    for _ in 0..50 {
        let t = TcpListener::bind(SocketAddr::new(ip, 0))?;
        let port = t.local_addr()?.port();
        if UdpSocket::bind(SocketAddr::new(ip, port)).is_ok() {
            return Ok(port);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no port free for both TCP and UDP",
    ))
}

impl Client {
    /// Starts a client: binds TCP and UDP on [`ClientConfig::listen`], starts the engine, the
    /// disk pool, the DHT node and the maintenance thread.
    pub fn new(cfg: ClientConfig) -> io::Result<Client> {
        let mut listen = cfg.listen;
        if listen.port() == 0 {
            listen.set_port(free_port(listen.ip())?);
        }
        let cell: Arc<OnceLock<Weak<ClientInner>>> = Arc::new(OnceLock::new());
        let port = UdpPort::new();
        let threads = cfg.threads.max(1);
        let engine = Arc::new(
            Engine::builder()
                .listen(
                    Listener::tcp(listen)
                        .threads(threads)
                        .serve(peer::TcpAcceptor {
                            client: cell.clone(),
                        }),
                )
                .listen(
                    Listener::udp(listen)
                        .threads(threads)
                        .serve(port.acceptor()),
                )
                .client_threads(threads)
                .build()?,
        );
        engine.start()?;
        let addrs = engine.local_addrs();
        let udp_addr = addrs.get(1).copied().unwrap_or(listen);
        port.attach(&engine, udp_addr);
        let mut pc = PoolConfig::default();
        pc.min_threads = 1;
        pc.max_threads = cfg.disk_threads.max(1);
        let pool = Pool::new(pc);
        let trackers = TrackerClient::new(engine.clone(), cfg.tracker_timeout, 3);
        let dht = cfg.dht.then(|| {
            let mut n = dht::Node::new(NodeId::random());
            n.set_ipv6(listen.is_ipv6());
            Mutex::new(n)
        });
        let http = akio_http::client::Client::new(engine.clone())
            .with_redirects(akio_http::client::RedirectPolicy::limit(5))
            .with_options({
                let mut o = akio_http::client::ClientOptions::default();
                o.max_body_bytes = webseed::MAX_RANGE as usize;
                o.max_idle_per_host = 4;
                o
            });
        let rates = Arc::new(rate::GlobalRates::new(
            cfg.rate_limits.upload,
            cfg.rate_limits.download,
        ));
        let inner = Arc::new(ClientInner {
            peer_id: cfg.peer_id.unwrap_or_else(new_peer_id),
            cfg,
            engine,
            port: port.clone(),
            trackers,
            pool,
            dht,
            http,
            rates,
            listen: SocketAddr::new(
                listen.ip(),
                addrs
                    .first()
                    .map_or_else(|| listen.port(), SocketAddr::port),
            ),
            torrents: Mutex::new(HashMap::new()),
            aliases: Mutex::new(HashMap::new()),
            req2: Mutex::new(HashMap::new()),
            lookups: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
            maintenance: Mutex::new(Vec::new()),
        });
        let _ = cell.set(Arc::downgrade(&inner));
        let w = Arc::downgrade(&inner);
        port.on_accept(move |s| Some(Box::new(peer::UtpPeer::incoming(w.clone(), s.peer_addr()))));
        let w = Arc::downgrade(&inner);
        port.on_datagram(move |from, data| {
            if let Some(c) = w.upgrade() {
                on_dht_datagram(&c, from, data);
            }
        });
        if let Some(d) = &inner.dht {
            if !inner.cfg.dht_bootstrap.is_empty() {
                let out = {
                    let mut n = d.lock().unwrap_or_else(|p| p.into_inner());
                    n.bootstrap(&inner.cfg.dht_bootstrap);
                    n.take_outgoing()
                };
                for (to, b) in out {
                    inner.port.send_to(to, b);
                }
            }
        }
        let w = Arc::downgrade(&inner);
        let h = std::thread::Builder::new()
            .name("akio-bt-client".into())
            .spawn(move || maintenance(&w))?;
        let mut threads = vec![h];
        if inner.cfg.lsd {
            if let Some(socks) = lsd::open(listen.is_ipv6()) {
                let w = Arc::downgrade(&inner);
                if let Ok(h) = std::thread::Builder::new()
                    .name("akio-bt-lsd".into())
                    .spawn(move || lsd::run(&w, socks))
                {
                    threads.push(h);
                }
            }
        }
        *inner.maintenance.lock().unwrap_or_else(|p| p.into_inner()) = threads;
        Ok(Client { inner })
    }

    /// The address peers reach this client at (TCP and UDP share the port).
    pub fn listen_addr(&self) -> SocketAddr {
        self.inner.listen
    }

    /// This client's peer ID.
    pub fn peer_id(&self) -> PeerId {
        self.inner.peer_id
    }

    /// The engine the client runs on.
    pub fn engine(&self) -> &Arc<Engine> {
        &self.inner.engine
    }

    /// Nodes in the DHT routing table (0 without a DHT).
    pub fn dht_nodes(&self) -> usize {
        self.inner.dht.as_ref().map_or(0, |d| {
            d.lock().unwrap_or_else(|p| p.into_inner()).table_len()
        })
    }

    /// IPv6 nodes in the DHT routing table (0 unless listening dual-stack).
    pub fn dht_nodes6(&self) -> usize {
        self.inner.dht.as_ref().map_or(0, |d| {
            d.lock().unwrap_or_else(|p| p.into_inner()).table6_len()
        })
    }

    /// Changes the client-wide rate limits.
    pub fn set_rate_limits(&self, limits: RateLimits) {
        self.inner.rates.set(limits.upload, limits.download);
    }

    /// The client-wide rate limits.
    pub fn rate_limits(&self) -> RateLimits {
        let (upload, download) = self.inner.rates.get();
        RateLimits { upload, download }
    }

    /// Bootstraps the DHT from more nodes.
    pub fn dht_bootstrap(&self, nodes: &[SocketAddr]) {
        if let Some(d) = &self.inner.dht {
            let out = {
                let mut n = d.lock().unwrap_or_else(|p| p.into_inner());
                n.bootstrap(nodes);
                n.take_outgoing()
            };
            for (to, b) in out {
                self.inner.port.send_to(to, b);
            }
        }
    }

    fn add(&self, n: NewTorrent) -> Result<Torrent, AddError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(AddError::Closed);
        }
        let ih = n.info_hash;
        let alias = n.info_hash_v2.map(|v| v.truncated());
        for h in std::iter::once(ih).chain(alias) {
            if self.inner.torrent(&h).is_some() {
                return Err(AddError::Duplicate(h));
            }
        }
        let shared = TorrentShared::new(&self.inner, n);
        self.inner
            .torrents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(ih, shared.clone());
        self.inner
            .req2
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(peer::req2(&ih), ih);
        let hashes = shared.lock().hashes.clone();
        for h in hashes {
            self.inner.add_alias(h, ih);
        }
        let running = shared.lock().running();
        if running {
            announce(&self.inner, &shared, Event::Started, false);
            shared.with(|st, cx| st.connect_more(Instant::now(), cx));
            dht_lookup(&self.inner, &shared);
        }
        Ok(Torrent { shared })
    }

    /// The resume data to start a torrent with: `data`, else its file in the resume directory
    /// under any of `hashes`.
    fn load_resume(
        &self,
        hashes: &[InfoHash],
        data: Option<Vec<u8>>,
    ) -> Option<Result<ResumeData, ResumeError>> {
        if let Some(d) = data {
            return Some(ResumeData::decode(&d));
        }
        let dir = self.inner.cfg.resume_dir.as_ref()?;
        for h in hashes {
            match std::fs::read(resume::path(dir, h)) {
                Ok(b) => return Some(ResumeData::decode(&b)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Some(Err(ResumeError::Malformed(e.to_string()))),
            }
        }
        None
    }

    fn factory(&self) -> torrent::StorageFactory {
        let dir = self.inner.cfg.data_dir.clone();
        Box::new(move |info: &Info| Arc::new(FileStorage::new(&dir, info)) as Arc<dyn Storage>)
    }

    /// Adds a torrent from its metainfo.
    pub fn add_torrent(&self, mi: MetaInfo, opts: AddOptions) -> Result<Torrent, AddError> {
        let mut trackers = mi.trackers();
        trackers.extend(opts.trackers.iter().map(|t| vec![t.clone()]));
        let mut url_list = mi.url_list;
        url_list.extend(opts.web_seeds.iter().cloned());
        let hashes: Vec<InfoHash> = std::iter::once(mi.info_hash)
            .chain(mi.info_hash_v2.map(|h| h.truncated()))
            .collect();
        let resume = self.load_resume(&hashes, opts.resume_data);
        let mut n = NewTorrent {
            info_hash: mi.info_hash,
            info_hash_v2: mi.info_hash_v2,
            name: Some(mi.info.name.clone()),
            info: Some(mi.info),
            layers: mi.piece_layers,
            trackers,
            url_list,
            peers: opts.peers,
            storage: opts.storage,
            storage_factory: self.factory(),
            paused: opts.paused,
            seed: opts.seed,
            rate_limits: opts.rate_limits,
            seed_limits: opts.seed_limits.unwrap_or(self.inner.cfg.seed_limits),
            resume: None,
        };
        merge_resume(
            &mut n,
            resume,
            &opts.rate_limits,
            opts.seed_limits.is_some(),
        );
        self.add(n)
    }

    /// Adds a torrent from a magnet link; its info dictionary comes from peers (BEP 9).
    pub fn add_magnet(&self, magnet: &str, opts: AddOptions) -> Result<Torrent, AddError> {
        let m = Magnet::parse(magnet).map_err(AddError::Magnet)?;
        let mut trackers: Vec<Vec<String>> = m.trackers.iter().map(|t| vec![t.clone()]).collect();
        trackers.extend(opts.trackers.iter().map(|t| vec![t.clone()]));
        let mut peers = m.peers.clone();
        peers.extend(opts.peers);
        let mut url_list = m.web_seeds;
        url_list.extend(opts.web_seeds.iter().cloned());
        let hashes: Vec<InfoHash> = std::iter::once(m.info_hash)
            .chain(m.info_hash_v2.map(|h| h.truncated()))
            .collect();
        let resume = self.load_resume(&hashes, opts.resume_data);
        let mut n = NewTorrent {
            info_hash: m.info_hash,
            info_hash_v2: m.info_hash_v2,
            name: m.name,
            info: None,
            layers: PieceLayers::new(),
            trackers,
            url_list,
            peers,
            storage: opts.storage,
            storage_factory: self.factory(),
            paused: opts.paused,
            seed: opts.seed,
            rate_limits: opts.rate_limits,
            seed_limits: opts.seed_limits.unwrap_or(self.inner.cfg.seed_limits),
            resume: None,
        };
        merge_resume(
            &mut n,
            resume,
            &opts.rate_limits,
            opts.seed_limits.is_some(),
        );
        self.add(n)
    }

    /// Adds a torrent from fast-resume data alone ([`Torrent::resume_data`] or a file of
    /// [`ClientConfig::resume_dir`]): its info dictionary, pieces, trackers, web seeds and peers
    /// come from the data (a torrent saved before its info dictionary arrived continues as a
    /// magnet link would). `opts.resume_data` is ignored.
    pub fn add_resume(&self, data: &[u8], opts: AddOptions) -> Result<Torrent, AddError> {
        let r = ResumeData::decode(data).map_err(AddError::Resume)?;
        let mut n = NewTorrent {
            info_hash: r.info_hash,
            info_hash_v2: r.info_hash_v2,
            name: None,
            info: None,
            layers: PieceLayers::new(),
            trackers: opts.trackers.iter().map(|t| vec![t.clone()]).collect(),
            url_list: opts.web_seeds.clone(),
            peers: opts.peers,
            storage: opts.storage,
            storage_factory: self.factory(),
            paused: opts.paused,
            seed: opts.seed,
            rate_limits: opts.rate_limits,
            seed_limits: opts.seed_limits.unwrap_or(self.inner.cfg.seed_limits),
            resume: None,
        };
        merge_resume(
            &mut n,
            Some(Ok(r)),
            &opts.rate_limits,
            opts.seed_limits.is_some(),
        );
        self.add(n)
    }

    /// The torrent of `info_hash` (any of its hashes: a hybrid torrent's truncated v2 hash
    /// finds it too).
    pub fn torrent(&self, info_hash: &InfoHash) -> Option<Torrent> {
        self.inner
            .torrent(info_hash)
            .map(|shared| Torrent { shared })
    }

    /// Every torrent.
    pub fn torrents(&self) -> Vec<Torrent> {
        self.inner
            .all()
            .into_iter()
            .map(|shared| Torrent { shared })
            .collect()
    }

    /// Removes a torrent (its connections close; its data stays, its resume file is deleted).
    pub fn remove(&self, info_hash: &InfoHash) -> Option<Torrent> {
        let key = self.inner.torrent(info_hash)?.info_hash;
        let t = self
            .inner
            .torrents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key)?;
        t.removed.store(true, Ordering::Relaxed);
        if let Some(dir) = &self.inner.cfg.resume_dir {
            let _g = t.save_lock.lock().unwrap_or_else(|p| p.into_inner());
            let _ = std::fs::remove_file(resume::path(dir, &key));
        }
        let hashes = t.lock().hashes.clone();
        for h in std::iter::once(key).chain(hashes) {
            self.inner
                .req2
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&peer::req2(&h));
            self.inner
                .aliases
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&h);
        }
        t.with(|st, cx| st.pause(cx));
        Some(Torrent { shared: t })
    }

    /// Stops everything: torrents announce `stopped`, connections close, the engine shuts down,
    /// and with [`ClientConfig::resume_dir`] every torrent's resume data is saved once its last
    /// write is done (recording whether it was paused before). Returns once the engine's I/O threads, the disk pool and the maintenance thread have
    /// exited, so no callback of this client (and no [`Storage`] call) runs after it. Calling it
    /// again, or from another thread while it runs, returns at once. Must not be called from
    /// one of the client's own threads (inside a [`Storage`] method, say): it would wait for
    /// itself.
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        let all: Vec<(Arc<TorrentShared>, bool)> = self
            .inner
            .all()
            .into_iter()
            .map(|t| {
                let paused = t.lock().status == TorrentStatus::Paused;
                (t, paused)
            })
            .collect();
        for (t, _) in &all {
            t.with(|st, cx| st.pause(cx));
        }
        // Give `stopped` announces a moment.
        std::thread::sleep(Duration::from_millis(50));
        self.inner.engine.shutdown();
        // Before, the threads were left to exit on their own: `close` returned while they
        // could still run callbacks, and dropping the client detached them (ThreadSanitizer
        // "thread leak", tools/sanitizers/README.md).
        self.inner.engine.wait();
        self.inner.pool.shutdown();
        self.inner.pool.join();
        // Every write is done: the files are as the bitfields say.
        if self.inner.cfg.resume_dir.is_some() {
            for (t, paused) in &all {
                if let Err(e) = save_resume(&self.inner, t, Some(*paused)) {
                    resume_failed(t, &e);
                }
            }
        }
        let threads = std::mem::take(
            &mut *self
                .inner
                .maintenance
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
        );
        for h in threads {
            let _ = h.join();
        }
    }
}

impl Torrent {
    /// The info hash.
    pub fn info_hash(&self) -> InfoHash {
        self.shared.info_hash
    }

    /// The v2 info hash (v2 and hybrid torrents, once known).
    pub fn info_hash_v2(&self) -> Option<InfoHashV2> {
        self.shared.lock().info_hash_v2
    }

    /// The v2 piece layers held (from the .torrent, or fetched from peers for a magnet link).
    pub fn piece_layers(&self) -> PieceLayers {
        self.shared.lock().layers.clone()
    }

    /// Changes this torrent's rate limits (the client's apply as well).
    pub fn set_rate_limits(&self, limits: RateLimits) {
        self.shared.lock().set_rate_limits(limits);
    }

    /// This torrent's rate limits.
    pub fn rate_limits(&self) -> RateLimits {
        self.shared.lock().rate_limits()
    }

    /// Changes this torrent's seed limits.
    pub fn set_seed_limits(&self, limits: SeedLimits) {
        let mut st = self.shared.lock();
        st.seed_limits = limits;
        st.resume_gen += 1;
    }

    /// The torrent's fast-resume data (ADR-033), to store anywhere and give back through
    /// [`AddOptions::resume_data`] or [`Client::add_resume`]; `None` while its data is being
    /// checked. Stamps the files from storage, so it does disk I/O on the calling thread.
    /// Taken while the torrent runs, the data trusts files the torrent may still write to
    /// on their size alone; taken while paused, it holds every file to its size and time.
    pub fn resume_data(&self) -> Option<Vec<u8>> {
        let (mut r, storage, _) = self.shared.lock().resume_snapshot(None)?;
        if r.info.is_some() {
            r.files = storage.and_then(|s| s.file_stamps());
        }
        Some(r.encode())
    }

    /// Saves the resume data to [`ClientConfig::resume_dir`] now (an error without one);
    /// `Ok(false)` while the torrent's data is being checked.
    pub fn save_resume_data(&self) -> io::Result<bool> {
        let c = self
            .shared
            .client
            .upgrade()
            .ok_or_else(|| io::Error::other("client closed"))?;
        save_resume(&c, &self.shared, None)
    }

    /// This torrent's seed limits.
    pub fn seed_limits(&self) -> SeedLimits {
        self.shared.lock().seed_limits
    }

    /// Adds a web seed (BEP 19; at most 16 per torrent, duplicates ignored).
    pub fn add_web_seed(&self, url: &str) {
        self.shared.lock().add_web_seed(url);
    }

    /// The name (from the info dictionary or the magnet link).
    pub fn name(&self) -> Option<String> {
        self.shared.lock().name.clone()
    }

    /// The info dictionary, once known.
    pub fn info(&self) -> Option<Info> {
        self.shared.lock().info.as_deref().cloned()
    }

    /// A .torrent of this torrent, once its info dictionary is known.
    pub fn metainfo(&self) -> Option<MetaInfo> {
        self.shared.lock().metainfo()
    }

    /// Numbers.
    pub fn stats(&self) -> TorrentStats {
        self.shared.lock().stats()
    }

    /// The connected peers.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.shared.lock().peer_infos()
    }

    /// Adds peers and dials them.
    pub fn add_peers(&self, peers: &[SocketAddr]) {
        self.shared.with(|st, cx| st.add_peers(peers, cx));
    }

    /// Pauses: connections close, trackers hear `stopped`.
    pub fn pause(&self) {
        self.shared.with(|st, cx| st.pause(cx));
    }

    /// Resumes after [`pause`](Self::pause).
    pub fn resume(&self) {
        self.shared.with(|st, cx| st.resume(cx));
        if let Some(c) = self.shared.client.upgrade() {
            announce(&c, &self.shared, Event::Started, false);
        }
    }

    /// Whether every piece is had.
    pub fn is_complete(&self) -> bool {
        self.shared.lock().is_complete()
    }

    fn wait(&self, timeout: Duration, f: impl Fn(&torrent::TorrentState) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        let mut st = self.shared.lock();
        loop {
            if f(&st) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let wait = (deadline - now).min(Duration::from_millis(200));
            st = self
                .shared
                .cv
                .wait_timeout(st, wait)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// Waits until every piece is had; `false` on timeout.
    pub fn wait_complete(&self, timeout: Duration) -> bool {
        self.wait(timeout, torrent::TorrentState::is_complete)
    }

    /// Waits for the info dictionary (magnet links); `false` on timeout.
    pub fn wait_metadata(&self, timeout: Duration) -> bool {
        self.wait(timeout, |st| st.info.is_some())
    }
}

/// Announces to every tracker of `t` now (`force`), or to those whose interval passed.
pub(crate) fn announce(
    client: &Arc<ClientInner>,
    t: &Arc<TorrentShared>,
    event: Event,
    force: bool,
) {
    if !client.cfg.trackers {
        return;
    }
    let now = Instant::now();
    let (urls, left, up, down) = {
        let mut st = t.lock();
        // Before the info dictionary the size is unknown; a nonzero `left` keeps trackers from
        // taking a magnet link's download for a seeder (and handing it leechers only).
        let left = if st.info.is_none() {
            16 * 1024
        } else {
            st.bytes_left()
        };
        let (up, down) = (st.uploaded, st.downloaded);
        let mut urls = Vec::new();
        for slot in &mut st.trackers {
            if slot.busy && event != Event::Stopped {
                continue;
            }
            let due = force || slot.next <= now;
            if !due {
                continue;
            }
            let ev = match event {
                Event::None if !slot.started => Event::Started,
                e => e,
            };
            if ev == Event::Stopped && !slot.started {
                continue;
            }
            slot.busy = true;
            if ev == Event::Started {
                slot.started = true;
            }
            if ev == Event::Stopped {
                slot.started = false;
            }
            urls.push((slot.url.clone(), slot.info_hash, ev));
        }
        (urls, left, up, down)
    };
    for (url, ih, ev) in urls {
        let mut req = AnnounceRequest::new(ih, client.peer_id, client.listen.port(), left);
        req.event = ev;
        req.uploaded = up;
        req.downloaded = down;
        req.num_want = if ev == Event::Stopped { 0 } else { 50 };
        req.key = u32::from_le_bytes([
            client.peer_id[16],
            client.peer_id[17],
            client.peer_id[18],
            client.peer_id[19],
        ]);
        let weak = Arc::downgrade(t);
        let u = url.clone();
        client.trackers.announce(&url, &req, move |r| {
            let Some(t) = weak.upgrade() else { return };
            t.with(|st, cx| {
                let now = Instant::now();
                let Some(slot) = st
                    .trackers
                    .iter_mut()
                    .find(|s| s.url == u && s.info_hash == ih)
                else {
                    return;
                };
                slot.busy = false;
                match r {
                    Ok(resp) => {
                        slot.fails = 0;
                        slot.last_error = None;
                        slot.interval =
                            Duration::from_secs(u64::from(resp.interval.clamp(30, 3600)));
                        slot.next = now + slot.interval;
                        slot.peers = resp.peers.len();
                        if ev != Event::Stopped {
                            st.add_peers(&resp.peers, cx);
                        }
                    }
                    Err(e) => {
                        slot.fails += 1;
                        slot.last_error = Some(e.to_string());
                        slot.next = now + Duration::from_secs(15 * u64::from(slot.fails.min(40)));
                        cx.events.push(TorrentEvent::TrackerError {
                            url: u.clone(),
                            error: e.to_string(),
                        });
                    }
                }
            });
        });
    }
}

fn dht_lookup(client: &Arc<ClientInner>, t: &Arc<TorrentShared>) {
    let Some(d) = &client.dht else { return };
    {
        let mut st = t.lock();
        if st.private || !st.running() {
            return;
        }
        st.last_dht = Some(Instant::now());
    }
    let hashes = t.lock().hashes.clone();
    let out = {
        let mut n = d.lock().unwrap_or_else(|p| p.into_inner());
        for h in hashes {
            let id = n.get_peers(h, Some(client.listen.port()));
            client
                .lookups
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(id, t.info_hash);
        }
        n.take_outgoing()
    };
    for (to, b) in out {
        client.port.send_to(to, b);
    }
}

fn dht_flush(client: &Arc<ClientInner>, out: Vec<(SocketAddr, Vec<u8>)>, events: Vec<DhtEvent>) {
    for (to, b) in out {
        client.port.send_to(to, b);
    }
    for e in events {
        match e {
            DhtEvent::Peers { info_hash, peers } => {
                if let Some(t) = client.torrent(&info_hash) {
                    t.with(|st, cx| st.add_peers(&peers, cx));
                }
            }
            DhtEvent::LookupDone { id, .. } => {
                client
                    .lookups
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&id);
            }
            _ => {}
        }
    }
}

fn on_dht_datagram(client: &Arc<ClientInner>, from: SocketAddr, data: &[u8]) {
    let Some(d) = &client.dht else { return };
    if data.first() != Some(&b'd') {
        return;
    }
    let (out, events) = {
        let mut n = d.lock().unwrap_or_else(|p| p.into_inner());
        n.handle(from, data);
        (n.take_outgoing(), n.take_events())
    };
    dht_flush(client, out, events);
}

/// Adds what resume data `r` holds to a torrent being added, or records why it was refused.
fn merge_resume(
    n: &mut NewTorrent,
    r: Option<Result<ResumeData, ResumeError>>,
    rate_limits: &RateLimits,
    seed_limits_set: bool,
) {
    let Some(r) = r else { return };
    let r = r.and_then(|r| r.check(&n.info_hash, n.info.as_ref()).map(|()| r));
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            n.resume = Some(Err(e.to_string()));
            return;
        }
    };
    if n.info.is_none() {
        n.info = r.info.as_deref().cloned();
    }
    if n.info_hash_v2.is_none() {
        n.info_hash_v2 = r.info_hash_v2;
    }
    if n.name.is_none() {
        n.name = r.name.clone();
    }
    for t in &r.trackers {
        if !n.trackers.iter().flatten().any(|u| u == t) {
            n.trackers.push(vec![t.clone()]);
        }
    }
    for u in &r.url_list {
        if !n.url_list.contains(u) {
            n.url_list.push(u.clone());
        }
    }
    for p in &r.peers {
        if !n.peers.contains(p) {
            n.peers.push(*p);
        }
    }
    n.paused |= r.paused;
    if *rate_limits == RateLimits::default() {
        n.rate_limits = r.rate_limits;
    }
    if !seed_limits_set {
        n.seed_limits = r.seed_limits;
    }
    n.resume = Some(Ok(r));
}

/// Writes `t`'s resume data to the resume directory (`paused`: the state to record instead of
/// the current one); `Ok(false)` if there is nothing to save (a check runs, or it was removed).
fn save_resume(client: &ClientInner, t: &TorrentShared, paused: Option<bool>) -> io::Result<bool> {
    let Some(dir) = &client.cfg.resume_dir else {
        return Err(io::Error::other("no resume directory configured"));
    };
    let _g = t.save_lock.lock().unwrap_or_else(|p| p.into_inner());
    if t.removed.load(Ordering::Relaxed) {
        return Ok(false);
    }
    let Some((mut r, storage, generation)) = t.lock().resume_snapshot(paused) else {
        return Ok(false);
    };
    let totals = (r.uploaded, r.downloaded);
    // Stamped after the bitfield was taken: every piece it holds is written already.
    if r.info.is_some() {
        r.files = storage.and_then(|s| s.file_stamps());
    }
    resume::write_atomic(&resume::path(dir, &t.info_hash), &r.encode())?;
    let mut st = t.lock();
    st.saved_gen = st.saved_gen.max(generation);
    st.saved_stats = totals;
    Ok(true)
}

fn resume_failed(t: &Arc<TorrentShared>, e: &io::Error) {
    t.with(|_, cx| {
        cx.events
            .push(TorrentEvent::Error(format!("saving resume data: {e}")));
    });
}

/// Queues a save of `t` on the disk pool when one is due: soon after a pause or a check (once
/// no write is in flight, or after 5 s), or every resume interval if anything changed.
fn maybe_save(client: &Arc<ClientInner>, t: &Arc<TorrentShared>, now: Instant) {
    if client.cfg.resume_dir.is_none() || t.save_queued.load(Ordering::Relaxed) {
        return;
    }
    {
        let mut st = t.lock();
        let soon = st.save_now.is_some_and(|at| {
            !st.writes_in_flight() || now.duration_since(at) >= Duration::from_secs(5)
        });
        let due = now.duration_since(st.last_save) >= client.cfg.resume_interval
            && (st.resume_gen != st.saved_gen || st.totals() != st.saved_stats);
        if !soon && !due {
            return;
        }
        st.save_now = None;
        st.last_save = now;
    }
    t.save_queued.store(true, Ordering::Relaxed);
    let (wc, wt) = (Arc::downgrade(client), Arc::downgrade(t));
    let job = Box::new(move || {
        let (Some(c), Some(t)) = (wc.upgrade(), wt.upgrade()) else {
            return;
        };
        if let Err(e) = save_resume(&c, &t, None) {
            resume_failed(&t, &e);
        }
        t.save_queued.store(false, Ordering::Relaxed);
    });
    if client.pool.try_execute(job).is_err() {
        t.save_queued.store(false, Ordering::Relaxed);
    }
}

fn maintenance(weak: &Weak<ClientInner>) {
    let mut last_dht_tick = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(100));
        let Some(client) = weak.upgrade() else { return };
        if client.closed.load(Ordering::Relaxed) {
            return;
        }
        let now = Instant::now();
        for t in client.all() {
            t.with(|st, cx: &mut Cx| st.tick(now, cx));
            maybe_save(&client, &t, now);
            let (running, last_dht, peers) = {
                let st = t.lock();
                (st.running(), st.last_dht, st.stats().peers)
            };
            if running {
                announce(&client, &t, Event::None, false);
                let every = if peers < 5 {
                    Duration::from_secs(60)
                } else {
                    Duration::from_secs(15 * 60)
                };
                if last_dht.is_none_or(|at| now.duration_since(at) >= every) {
                    dht_lookup(&client, &t);
                }
            }
        }
        if now.duration_since(last_dht_tick) >= Duration::from_secs(1) {
            last_dht_tick = now;
            if let Some(d) = &client.dht {
                let (out, events) = {
                    let mut n = d.lock().unwrap_or_else(|p| p.into_inner());
                    n.tick();
                    (n.take_outgoing(), n.take_events())
                };
                dht_flush(&client, out, events);
            }
        }
    }
}
