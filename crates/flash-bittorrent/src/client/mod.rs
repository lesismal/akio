//! A BitTorrent client on one flash engine and one port number: TCP for the peer wire protocol
//! and UDP shared by uTP and the DHT ([`UdpPort`]); HTTP and UDP trackers go through a
//! [`TrackerClient`] on the same engine, and storage reads, writes and SHA-1 checks run on a
//! logical pool, never on an I/O thread.
//!
//! ```no_run
//! use flash_bittorrent::client::{AddOptions, Client, ClientConfig};
//! use flash_bittorrent::metainfo::MetaInfo;
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

mod peer;
pub mod storage;
mod torrent;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use flash::{Engine, Listener};
use flash_pool::{Pool, PoolConfig};

use crate::dht::{self, DhtEvent, NodeId};
use crate::magnet::Magnet;
use crate::metainfo::{Info, InfoHash, MetaInfo};
use crate::mse::Policy;
use crate::port::UdpPort;
use crate::tracker::{AnnounceRequest, Event, TrackerClient};
use crate::wire::{PeerId, new_peer_id};

pub use storage::{FileStorage, MemoryStorage, Storage};

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
}

/// Callback for torrent events: `(info_hash, event)`, called in order after the torrent's
/// lock is released, on whichever thread caused the event.
pub type EventFn = Arc<dyn Fn(InfoHash, &TorrentEvent) + Send + Sync>;

/// Client settings. `#[non_exhaustive]`: start from `ClientConfig::default()`.
#[derive(Clone)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Address for TCP and UDP (default `0.0.0.0:6881`; port 0 picks a port free for both).
    pub listen: SocketAddr,
    /// Directory torrents are stored below (default: the working directory).
    pub data_dir: PathBuf,
    /// Peer ID (default: `-FL0100-` and random bytes).
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
}

impl fmt::Debug for AddOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddOptions")
            .field("paused", &self.paused)
            .field("seed", &self.seed)
            .field("peers", &self.peers)
            .field("trackers", &self.trackers)
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
}

impl fmt::Display for AddError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddError::Duplicate(h) => write!(f, "torrent {h} already added"),
            AddError::Magnet(e) => write!(f, "{e}"),
            AddError::Closed => f.write_str("client closed"),
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
    torrents: Mutex<HashMap<InfoHash, Arc<TorrentShared>>>,
    req2: Mutex<HashMap<[u8; 20], InfoHash>>,
    lookups: Mutex<HashMap<u64, InfoHash>>,
    closed: AtomicBool,
}

impl ClientInner {
    pub(crate) fn torrent(&self, ih: &InfoHash) -> Option<Arc<TorrentShared>> {
        self.torrents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(ih)
            .cloned()
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

    fn all(&self) -> Vec<Arc<TorrentShared>> {
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
        let dht = cfg
            .dht
            .then(|| Mutex::new(dht::Node::new(NodeId::random())));
        let inner = Arc::new(ClientInner {
            peer_id: cfg.peer_id.unwrap_or_else(new_peer_id),
            cfg,
            engine,
            port: port.clone(),
            trackers,
            pool,
            dht,
            listen: SocketAddr::new(
                listen.ip(),
                addrs
                    .first()
                    .map_or_else(|| listen.port(), SocketAddr::port),
            ),
            torrents: Mutex::new(HashMap::new()),
            req2: Mutex::new(HashMap::new()),
            lookups: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
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
        std::thread::Builder::new()
            .name("flash-bt-client".into())
            .spawn(move || maintenance(&w))?;
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
        if self.inner.torrent(&ih).is_some() {
            return Err(AddError::Duplicate(ih));
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
        let running = shared.lock().running();
        if running {
            announce(&self.inner, &shared, Event::Started, false);
            shared.with(|st, cx| st.connect_more(Instant::now(), cx));
            dht_lookup(&self.inner, &shared);
        }
        Ok(Torrent { shared })
    }

    fn factory(&self) -> torrent::StorageFactory {
        let dir = self.inner.cfg.data_dir.clone();
        Box::new(move |info: &Info| Arc::new(FileStorage::new(&dir, info)) as Arc<dyn Storage>)
    }

    /// Adds a torrent from its metainfo.
    pub fn add_torrent(&self, mi: MetaInfo, opts: AddOptions) -> Result<Torrent, AddError> {
        let mut trackers = mi.trackers();
        trackers.extend(opts.trackers.iter().map(|t| vec![t.clone()]));
        self.add(NewTorrent {
            info_hash: mi.info_hash,
            name: Some(mi.info.name.clone()),
            info: Some(mi.info),
            trackers,
            url_list: mi.url_list,
            peers: opts.peers,
            storage: opts.storage,
            storage_factory: self.factory(),
            paused: opts.paused,
            seed: opts.seed,
        })
    }

    /// Adds a torrent from a magnet link; its info dictionary comes from peers (BEP 9).
    pub fn add_magnet(&self, magnet: &str, opts: AddOptions) -> Result<Torrent, AddError> {
        let m = Magnet::parse(magnet).map_err(AddError::Magnet)?;
        let mut trackers: Vec<Vec<String>> = m.trackers.iter().map(|t| vec![t.clone()]).collect();
        trackers.extend(opts.trackers.iter().map(|t| vec![t.clone()]));
        let mut peers = m.peers.clone();
        peers.extend(opts.peers);
        self.add(NewTorrent {
            info_hash: m.info_hash,
            name: m.name,
            info: None,
            trackers,
            url_list: m.web_seeds,
            peers,
            storage: opts.storage,
            storage_factory: self.factory(),
            paused: opts.paused,
            seed: opts.seed,
        })
    }

    /// The torrent of `info_hash`.
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

    /// Removes a torrent (its connections close; its data stays).
    pub fn remove(&self, info_hash: &InfoHash) -> Option<Torrent> {
        let t = self
            .inner
            .torrents
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(info_hash)?;
        self.inner
            .req2
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&peer::req2(info_hash));
        t.with(|st, cx| st.pause(cx));
        Some(Torrent { shared: t })
    }

    /// Stops everything: torrents announce `stopped`, connections close, the engine shuts down.
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        for t in self.inner.all() {
            t.with(|st, cx| st.pause(cx));
        }
        // Give `stopped` announces a moment.
        std::thread::sleep(Duration::from_millis(50));
        self.inner.engine.shutdown();
        self.inner.pool.shutdown();
    }
}

impl Torrent {
    /// The info hash.
    pub fn info_hash(&self) -> InfoHash {
        self.shared.info_hash
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
            urls.push((slot.url.clone(), ev));
        }
        (urls, left, up, down)
    };
    for (url, ev) in urls {
        let mut req = AnnounceRequest::new(t.info_hash, client.peer_id, client.listen.port(), left);
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
                let Some(slot) = st.trackers.iter_mut().find(|s| s.url == u) else {
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
    let out = {
        let mut n = d.lock().unwrap_or_else(|p| p.into_inner());
        let id = n.get_peers(t.info_hash, Some(client.listen.port()));
        client
            .lookups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, t.info_hash);
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
