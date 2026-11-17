//! One torrent's state and protocol logic: peers, the piece picker (rarest first, pieces in
//! progress first, random first pieces, endgame), request pipelining, choking, metadata
//! exchange, PEX, v2 piece layers (hash requests both ways), web seeds, rate and seed limits,
//! verification and storage through the logical pool.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use only_core::ConnInner;
use only_pool::Pool;

use super::rate::{Bucket, GlobalRates};
use super::storage::Storage;
use super::webseed::{self, Fetch, MAX_WEB_SEEDS};
use super::{
    ClientInner, PeerInfo, RateLimits, SeedLimits, TorrentEvent, TorrentStats, TorrentStatus,
};
use crate::merkle::{self, Hash, MerkleTree};
use crate::metainfo::{Info, InfoHash, InfoHashV2, MetaInfo, PieceLayers, sha1};
use crate::mse::Rc4;
use crate::port::UtpStream;
use crate::wire::{
    BLOCK_SIZE, Bitfield, ExtendedHandshake, Handshake, HashRequest, METADATA_PIECE, Message,
    MetadataMsg, PeerId, Pex, allowed_fast_set,
};

/// Our extended message IDs.
pub(crate) const UT_METADATA: u8 = 1;
pub(crate) const UT_PEX: u8 = 2;
const PIPELINE: usize = 64;
const MAX_SERVING: usize = 512;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SNUB: Duration = Duration::from_secs(60);
const KEEPALIVE: Duration = Duration::from_secs(90);
const PEER_TIMEOUT: Duration = Duration::from_secs(240);
const CHOKE_INTERVAL: Duration = Duration::from_secs(10);
const OPTIMISTIC_INTERVAL: Duration = Duration::from_secs(30);
const PEX_INTERVAL: Duration = Duration::from_secs(60);
const META_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_METADATA: u32 = 16 << 20;
const RANDOM_FIRST: usize = 4;
const ALLOWED_FAST: usize = 10;
/// Piece-layer hashes asked for in one hash request (libtorrent's chunk).
const LAYER_CHUNK: u64 = 512;
const HASH_TIMEOUT: Duration = Duration::from_secs(10);
/// Hash requests in flight to one peer.
const MAX_HASH_ASKED: usize = 4;
/// Block-layer hash requests of one peer being served (each reads a piece).
const MAX_HASH_SERVING: usize = 8;
/// Merkle trees kept to answer hash requests.
const MAX_TREES: usize = 64;
const WEB_SEED_BACKOFF_MAX: Duration = Duration::from_secs(600);

/// Makes a torrent's storage once its info dictionary is known.
pub(crate) type StorageFactory = Box<dyn FnOnce(&Info) -> Arc<dyn Storage> + Send>;

/// How a peer is reached.
#[derive(Clone)]
pub(crate) enum Link {
    Tcp(Arc<ConnInner>),
    Utp(UtpStream),
}

impl Link {
    pub(crate) fn write(&self, data: Vec<u8>) {
        match self {
            Link::Tcp(c) => {
                let _ = c.send_owned(data);
            }
            Link::Utp(s) => {
                let _ = s.write(&data);
            }
        }
    }

    pub(crate) fn close(&self) {
        match self {
            Link::Tcp(c) => c.close_after_send(),
            Link::Utp(s) => s.close(),
        }
    }

    fn is_utp(&self) -> bool {
        matches!(self, Link::Utp(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Req {
    index: u32,
    begin: u32,
    length: u32,
}

pub(crate) struct Peer {
    addr: SocketAddr,
    link: Link,
    enc: Option<Rc4>,
    id: PeerId,
    outgoing: bool,
    encrypted: bool,
    ext: bool,
    fast: bool,
    dht: bool,
    am_choking: bool,
    am_interested: bool,
    peer_choking: bool,
    peer_interested: bool,
    v2: bool,
    hash_asked: usize,
    hash_serving: usize,
    hash_rejects: u32,
    have: Bitfield,
    /// A bitfield, have-all or haves that arrived before the info dictionary.
    early_bits: Option<Vec<u8>>,
    early_all: bool,
    early_haves: Vec<u32>,
    ut_metadata: u8,
    ut_pex: u8,
    metadata_size: Option<u32>,
    listen_port: Option<u16>,
    client_name: Option<String>,
    reqq: usize,
    requests: Vec<(Req, Instant)>,
    serving: HashSet<Req>,
    allowed_fast: HashSet<u32>,
    dl_round: u64,
    ul_round: u64,
    downloaded: u64,
    uploaded: u64,
    last_recv: Instant,
    last_sent: Instant,
    last_piece: Instant,
    pex_sent: HashSet<SocketAddr>,
    last_pex: Instant,
    unchoked_at: Instant,
}

impl Peer {
    fn send(&mut self, m: &Message) {
        let mut b = m.encode();
        if let Some(e) = &mut self.enc {
            e.apply(&mut b);
        }
        self.link.write(b);
        self.last_sent = Instant::now();
    }

    /// The address it accepts connections at.
    fn listen_addr(&self) -> SocketAddr {
        if self.outgoing {
            self.addr
        } else {
            SocketAddr::new(self.addr.ip(), self.listen_port.unwrap_or(0))
        }
    }
}

#[derive(Debug, Default)]
struct PieceDl {
    /// 0 = to request, 1 = requested, 2 = received.
    blocks: Vec<u8>,
    req_count: Vec<u8>,
    buf: Vec<u8>,
    received: usize,
    contributors: HashSet<IpAddr>,
}

#[derive(Debug)]
struct MetaDl {
    size: u32,
    pieces: Vec<Option<Vec<u8>>>,
    asked: HashMap<u32, (u64, Instant)>,
}

/// A piece layer being fetched with hash requests, 512 hashes at a time.
#[derive(Debug)]
struct LayerDl {
    root: Hash,
    file: usize,
    file_len: u64,
    pieces: u64,
    /// The chunks' hashes once proven.
    chunks: Vec<Option<Vec<Hash>>>,
    /// Chunk -> (peer, request, sent).
    asked: HashMap<usize, (u64, HashRequest, Instant)>,
}

#[derive(Debug)]
struct WebSeed {
    url: String,
    piece: Option<u32>,
    fails: u32,
    next_try: Instant,
}

#[derive(Debug, Clone)]
struct Known {
    failures: u32,
    next_try: Instant,
    connected: bool,
    connecting: Option<Instant>,
    plaintext: bool,
    no_utp: bool,
    banned: bool,
}

/// A dial the torrent asks for (done after its lock is released).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Dial {
    pub(crate) addr: SocketAddr,
    pub(crate) utp: bool,
    pub(crate) mse: bool,
}

/// Effects gathered under the torrent's lock, carried out after it is released.
#[derive(Default)]
pub(crate) struct Cx {
    pub(crate) events: Vec<TorrentEvent>,
    pub(crate) dials: Vec<Dial>,
    pub(crate) dht_ping: Vec<SocketAddr>,
    pub(crate) announce: Option<crate::tracker::Event>,
    pub(crate) close: Vec<Link>,
    pub(crate) web: Vec<Fetch>,
    pub(crate) aliases: Vec<InfoHash>,
}

#[derive(Debug, Clone)]
pub(crate) struct TrackerSlot {
    pub(crate) url: String,
    /// The hash announced (a hybrid torrent has a slot per hash).
    pub(crate) info_hash: InfoHash,
    pub(crate) next: Instant,
    pub(crate) interval: Duration,
    pub(crate) fails: u32,
    pub(crate) busy: bool,
    pub(crate) started: bool,
    pub(crate) last_error: Option<String>,
    pub(crate) peers: usize,
}

pub(crate) struct TorrentState {
    pub(crate) me: Weak<TorrentShared>,
    pub(crate) info_hash: InfoHash,
    /// Every hash the torrent goes by: the key first, then a hybrid's truncated v2 hash.
    pub(crate) hashes: Vec<InfoHash>,
    pub(crate) info_hash_v2: Option<InfoHashV2>,
    pub(crate) layers: PieceLayers,
    layer_dl: HashMap<Hash, LayerDl>,
    trees: HashMap<Hash, Arc<MerkleTree>>,
    /// Pieces that cannot be checked yet (a v2 piece layer is missing); empty when none.
    blocked: Bitfield,
    web_seeds: Vec<WebSeed>,
    /// Pieces from web seeds being checked -> the seed.
    ws_verifying: HashMap<u32, String>,
    up: Bucket,
    down: Bucket,
    rates: Arc<GlobalRates>,
    upload_wait: VecDeque<(u64, Req)>,
    pub(crate) seed_limits: SeedLimits,
    seeding_since: Option<Instant>,
    seeding_before: Duration,
    pub(crate) last_lsd: Option<Instant>,
    pub(crate) lsd_now: bool,
    pub(crate) lsd_wanted: bool,
    web_wanted: bool,
    pub(crate) name: Option<String>,
    pub(crate) info: Option<Arc<Info>>,
    pub(crate) private: bool,
    pub(crate) storage: Option<Arc<dyn Storage>>,
    storage_factory: Option<StorageFactory>,
    pub(crate) pool: Arc<Pool>,
    pub(crate) status: TorrentStatus,
    seed_mode: bool,
    have: Bitfield,
    availability: Vec<u16>,
    downloading: HashMap<u32, PieceDl>,
    verifying: HashSet<u32>,
    peers: HashMap<u64, Peer>,
    next_key: u64,
    known: HashMap<SocketAddr, Known>,
    meta: Option<MetaDl>,
    pub(crate) trackers: Vec<TrackerSlot>,
    pub(crate) url_list: Vec<String>,
    pub(crate) downloaded: u64,
    pub(crate) uploaded: u64,
    hash_fails: u64,
    last_choke: Instant,
    last_optimistic: Instant,
    optimistic: Option<u64>,
    pub(crate) completed_in_session: bool,
    pub(crate) last_dht: Option<Instant>,
    pub(crate) our_id: PeerId,
    pub(crate) listen_port: u16,
    pub(crate) max_peers: usize,
    pub(crate) upload_slots: usize,
    pub(crate) use_utp: bool,
    pub(crate) mse: crate::mse::Policy,
    pub(crate) pex: bool,
}

pub(crate) struct TorrentShared {
    pub(crate) info_hash: InfoHash,
    pub(crate) client: Weak<ClientInner>,
    pub(crate) st: Mutex<TorrentState>,
    pub(crate) cv: Condvar,
}

/// Settings a torrent starts with.
pub(crate) struct NewTorrent {
    pub(crate) info_hash: InfoHash,
    pub(crate) info_hash_v2: Option<InfoHashV2>,
    pub(crate) name: Option<String>,
    pub(crate) info: Option<Info>,
    pub(crate) layers: PieceLayers,
    pub(crate) rate_limits: RateLimits,
    pub(crate) seed_limits: SeedLimits,
    pub(crate) trackers: Vec<Vec<String>>,
    pub(crate) url_list: Vec<String>,
    pub(crate) peers: Vec<SocketAddr>,
    pub(crate) storage: Option<Arc<dyn Storage>>,
    pub(crate) storage_factory: StorageFactory,
    pub(crate) paused: bool,
    pub(crate) seed: bool,
}

impl TorrentShared {
    pub(crate) fn new(client: &Arc<ClientInner>, n: NewTorrent) -> Arc<TorrentShared> {
        let cfg = &client.cfg;
        let now = Instant::now();
        let mut hashes = vec![n.info_hash];
        if let Some(v2) = n.info_hash_v2 {
            if v2.truncated() != n.info_hash {
                hashes.push(v2.truncated());
            }
        }
        let slots = |hashes: &[InfoHash]| -> Vec<TrackerSlot> {
            hashes
                .iter()
                .flat_map(|h| {
                    n.trackers.iter().flatten().map(|u| TrackerSlot {
                        url: u.clone(),
                        info_hash: *h,
                        next: now,
                        interval: Duration::from_secs(1800),
                        fails: 0,
                        busy: false,
                        started: false,
                        last_error: None,
                        peers: 0,
                    })
                })
                .collect()
        };
        let trackers = slots(&hashes);
        let mut web_seeds: Vec<WebSeed> = Vec::new();
        for u in &n.url_list {
            if web_seeds.len() < MAX_WEB_SEEDS && !web_seeds.iter().any(|w| w.url == *u) {
                web_seeds.push(WebSeed {
                    url: u.clone(),
                    piece: None,
                    fails: 0,
                    next_try: now,
                });
            }
        }
        let ts = Arc::new_cyclic(|me| TorrentShared {
            info_hash: n.info_hash,
            client: Arc::downgrade(client),
            cv: Condvar::new(),
            st: Mutex::new(TorrentState {
                me: me.clone(),
                info_hash: n.info_hash,
                hashes,
                info_hash_v2: n.info_hash_v2,
                layers: n.layers,
                layer_dl: HashMap::new(),
                trees: HashMap::new(),
                blocked: Bitfield::new(0),
                web_seeds,
                ws_verifying: HashMap::new(),
                up: Bucket::new(n.rate_limits.upload),
                down: Bucket::new(n.rate_limits.download),
                rates: client.rates.clone(),
                upload_wait: VecDeque::new(),
                seed_limits: n.seed_limits,
                seeding_since: None,
                seeding_before: Duration::ZERO,
                last_lsd: None,
                lsd_now: true,
                lsd_wanted: cfg.lsd,
                web_wanted: cfg.web_seeds,
                name: n.name,
                info: None,
                private: false,
                storage: n.storage,
                storage_factory: Some(n.storage_factory),
                pool: client.pool.clone(),
                status: TorrentStatus::FetchingMetadata,
                seed_mode: n.seed,
                have: Bitfield::new(0),
                availability: Vec::new(),
                downloading: HashMap::new(),
                verifying: HashSet::new(),
                peers: HashMap::new(),
                next_key: 1,
                known: HashMap::new(),
                meta: None,
                trackers,
                url_list: n.url_list,
                downloaded: 0,
                uploaded: 0,
                hash_fails: 0,
                last_choke: now,
                last_optimistic: now,
                optimistic: None,
                completed_in_session: false,
                last_dht: None,
                our_id: client.peer_id,
                listen_port: client.listen.port(),
                max_peers: cfg.max_peers_per_torrent,
                upload_slots: cfg.upload_slots,
                use_utp: cfg.utp,
                mse: cfg.encryption,
                pex: cfg.pex,
            }),
        });
        let mut cx = Cx::default();
        {
            let mut st = ts.lock();
            if n.paused {
                st.status = TorrentStatus::Paused;
            }
            if let Some(info) = n.info {
                st.set_info(info, &mut cx);
            }
            let now = Instant::now();
            for p in n.peers {
                st.add_known(p, now);
            }
        }
        ts.finish(cx);
        ts
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, TorrentState> {
        self.st.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Runs `f` under the lock, then carries out its effects.
    pub(crate) fn with<R>(self: &Arc<Self>, f: impl FnOnce(&mut TorrentState, &mut Cx) -> R) -> R {
        let mut cx = Cx::default();
        let r = {
            let mut st = self.lock();
            f(&mut st, &mut cx)
        };
        self.finish(cx);
        r
    }

    pub(crate) fn finish(self: &Arc<Self>, cx: Cx) {
        for l in cx.close {
            l.close();
        }
        if !cx.events.is_empty() {
            self.cv.notify_all();
        }
        let Some(client) = self.client.upgrade() else {
            return;
        };
        for d in cx.dials {
            super::peer::dial(&client, self, d);
        }
        for a in cx.dht_ping {
            client.dht_ping(a);
        }
        for a in cx.aliases {
            client.add_alias(a, self.info_hash);
        }
        for f in cx.web {
            webseed::start(&client, self, f);
        }
        if let Some(e) = cx.announce {
            super::announce(&client, self, e, true);
        }
        if let Some(cb) = &client.cfg.on_event {
            for e in &cx.events {
                cb(self.info_hash, e);
            }
        }
    }
}

fn block_count(len: u32) -> usize {
    len.div_ceil(BLOCK_SIZE) as usize
}

impl TorrentState {
    pub(crate) fn stats(&self) -> TorrentStats {
        let (have, total) = (self.have.count(), self.have.len());
        let left = self.info.as_ref().map_or(0, |i| {
            (0..i.num_pieces())
                .filter(|&p| !self.have.get(p))
                .map(|p| u64::from(i.piece_size(p)))
                .sum()
        });
        TorrentStats {
            status: self.status,
            pieces_have: have,
            pieces_total: total,
            bytes_left: left,
            total_size: self.info.as_ref().map_or(0, |i| i.total_length),
            downloaded: self.downloaded,
            uploaded: self.uploaded,
            peers: self.peers.len(),
            known_peers: self.known.len(),
            hash_fails: self.hash_fails,
            seeders: self
                .peers
                .values()
                .filter(|p| p.have.is_full() && !p.have.is_empty())
                .count(),
            seeding_time: self.seeding_time(Instant::now()),
            web_seeds_active: self.web_seeds.iter().filter(|w| w.piece.is_some()).count(),
        }
    }

    fn seeding_time(&self, now: Instant) -> Duration {
        self.seeding_before
            + self
                .seeding_since
                .map_or(Duration::ZERO, |s| now.duration_since(s))
    }

    pub(crate) fn set_rate_limits(&mut self, l: RateLimits) {
        self.up.set_rate(l.upload);
        self.down.set_rate(l.download);
    }

    pub(crate) fn rate_limits(&self) -> RateLimits {
        RateLimits::new(self.up.rate(), self.down.rate())
    }

    pub(crate) fn add_web_seed(&mut self, url: &str) {
        if self.web_seeds.len() < MAX_WEB_SEEDS && !self.web_seeds.iter().any(|w| w.url == url) {
            self.web_seeds.push(WebSeed {
                url: url.to_owned(),
                piece: None,
                fails: 0,
                next_try: Instant::now(),
            });
            self.url_list.push(url.to_owned());
        }
    }

    fn may_download(&mut self, now: Instant) -> bool {
        self.down.ready(now) && self.rates.down_ready(now)
    }

    fn took_download(&mut self, n: u64) {
        self.down.take(n);
        self.rates.down_take(n);
    }

    fn may_upload(&mut self, now: Instant) -> bool {
        self.up.ready(now) && self.rates.up_ready(now)
    }

    pub(crate) fn peer_infos(&self) -> Vec<PeerInfo> {
        self.peers
            .values()
            .map(|p| PeerInfo {
                addr: p.addr,
                id: p.id,
                client: p.client_name.clone(),
                utp: p.link.is_utp(),
                encrypted: p.encrypted,
                outgoing: p.outgoing,
                pieces: p.have.count(),
                downloaded: p.downloaded,
                uploaded: p.uploaded,
                am_choking: p.am_choking,
                peer_choking: p.peer_choking,
            })
            .collect()
    }

    pub(crate) fn metainfo(&self) -> Option<MetaInfo> {
        let info = self.info.as_ref()?;
        let mut mi = MetaInfo::from_info((**info).clone());
        mi.piece_layers = self.layers.clone();
        let mut urls: Vec<Vec<String>> = Vec::new();
        for t in &self.trackers {
            if !urls.iter().any(|u| u[0] == t.url) {
                urls.push(vec![t.url.clone()]);
            }
        }
        if let Some(first) = urls.first() {
            mi.announce = first.first().cloned();
        }
        if urls.len() > 1 {
            mi.announce_list = urls;
        }
        mi.url_list = self.url_list.clone();
        Some(mi)
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.info.is_some() && self.have.is_full()
    }

    pub(crate) fn bytes_left(&self) -> u64 {
        self.stats().bytes_left
    }

    pub(crate) fn running(&self) -> bool {
        !matches!(self.status, TorrentStatus::Paused | TorrentStatus::Error)
    }

    pub(crate) fn add_known(&mut self, addr: SocketAddr, now: Instant) {
        if addr.port() == 0 || addr.ip().is_unspecified() {
            return;
        }
        if addr.port() == self.listen_port && (addr.ip().is_loopback()) {
            return; // ourselves
        }
        if self.known.len() >= 2000 {
            return;
        }
        self.known.entry(addr).or_insert(Known {
            failures: 0,
            next_try: now,
            connected: false,
            connecting: None,
            plaintext: false,
            no_utp: false,
            banned: false,
        });
    }

    /// Adds peers from any source and dials them right away.
    pub(crate) fn add_peers(&mut self, peers: &[SocketAddr], cx: &mut Cx) {
        let now = Instant::now();
        for &p in peers {
            self.add_known(p, now);
        }
        self.connect_more(now, cx);
    }

    // ---- info and checking -------------------------------------------------------------

    pub(crate) fn set_info(&mut self, info: Info, cx: &mut Cx) {
        if self.info.is_some() {
            return;
        }
        let n = info.num_pieces();
        self.private = info.private;
        if self.name.is_none() {
            self.name = Some(info.name.clone());
        }
        // A magnet link names one hash; the dictionary may carry the other one too.
        if let Some(v2) = info.info_hash_v2() {
            self.info_hash_v2 = Some(v2);
        }
        let more: Vec<InfoHash> = info
            .info_hash_v1()
            .into_iter()
            .chain(info.info_hash_v2().map(|v| v.truncated()))
            .filter(|h| !self.hashes.contains(h))
            .collect();
        for h in more {
            self.hashes.push(h);
            cx.aliases.push(h);
            let urls: Vec<String> = self
                .trackers
                .iter()
                .filter(|t| t.info_hash == self.info_hash)
                .map(|t| t.url.clone())
                .collect();
            let now = Instant::now();
            for url in urls {
                self.trackers.push(TrackerSlot {
                    url,
                    info_hash: h,
                    next: now,
                    interval: Duration::from_secs(1800),
                    fails: 0,
                    busy: false,
                    started: false,
                    last_error: None,
                    peers: 0,
                });
            }
        }
        // Layers that came with a .torrent of a different dictionary do not count.
        let stale: Vec<Hash> = self
            .layers
            .iter()
            .filter(|(r, l)| !info.check_piece_layer(r, l))
            .map(|(r, _)| *r)
            .collect();
        if !stale.is_empty() {
            self.layers = PieceLayers::new();
        }
        if self.storage.is_none() {
            if let Some(f) = self.storage_factory.take() {
                self.storage = Some(f(&info));
            }
        }
        self.have = Bitfield::new(n);
        self.availability = vec![0; n];
        let info = Arc::new(info);
        self.info = Some(info);
        self.meta = None;
        self.update_blocked();
        // Peers that told us their pieces before we knew how many there are.
        let keys: Vec<u64> = self.peers.keys().copied().collect();
        for k in keys {
            let Some(p) = self.peers.get_mut(&k) else {
                continue;
            };
            let mut bf = Bitfield::new(n);
            if p.early_all {
                bf = Bitfield::full(n);
            } else if let Some(b) = p.early_bits.take() {
                bf = Bitfield::from_bytes(&b, n).unwrap_or_else(|| Bitfield::new(n));
            }
            for &i in &p.early_haves {
                bf.set(i as usize, true);
            }
            p.early_haves.clear();
            for i in bf.ones() {
                self.availability[i] += 1;
            }
            p.have = bf;
            // We said have-none (or an empty bitfield) at the handshake; nothing to correct.
            if p.fast && p.addr.is_ipv4() {
                if let IpAddr::V4(ip) = p.addr.ip() {
                    for i in allowed_fast_set(&self.info_hash, ip, n as u32, ALLOWED_FAST) {
                        p.send(&Message::AllowedFast(i));
                    }
                }
            }
        }
        cx.events.push(TorrentEvent::MetadataReceived);
        self.start_check(cx);
    }

    fn start_check(&mut self, cx: &mut Cx) {
        let (Some(info), Some(storage)) = (self.info.clone(), self.storage.clone()) else {
            return;
        };
        if self.seed_mode {
            self.have = Bitfield::full(info.num_pieces());
            self.checked(cx);
            return;
        }
        if !storage.may_have_data() {
            self.checked(cx);
            return;
        }
        if self.status != TorrentStatus::Paused {
            self.status = TorrentStatus::Checking;
        }
        let me = self.me.clone();
        let layers = self.layers.clone();
        let job = Box::new(move || {
            let mut bf = Bitfield::new(info.num_pieces());
            for i in 0..info.num_pieces() {
                let len = info.piece_size(i) as usize;
                if let Ok(d) = storage.read(info.piece_offset(i), len) {
                    if info.verify_piece_with(&layers, i, &d) {
                        bf.set(i, true);
                    }
                }
            }
            if let Some(t) = me.upgrade() {
                t.with(|st, cx| {
                    st.have = bf;
                    st.checked(cx);
                });
            }
        });
        if self.pool.try_execute(job).is_err() {
            self.status = TorrentStatus::Error;
            cx.events
                .push(TorrentEvent::Error("disk pool refused the check".into()));
        }
    }

    fn checked(&mut self, cx: &mut Cx) {
        let complete = self.have.is_full();
        if self.status != TorrentStatus::Paused {
            self.status = if complete {
                TorrentStatus::Seeding
            } else {
                TorrentStatus::Downloading
            };
        }
        cx.events.push(TorrentEvent::Checked {
            pieces: self.have.count(),
        });
        // Tell the peers that connected meanwhile.
        let have: Vec<usize> = self.have.ones().collect();
        let keys: Vec<u64> = self.peers.keys().copied().collect();
        for k in keys {
            if let Some(p) = self.peers.get_mut(&k) {
                for &i in &have {
                    p.send(&Message::Have(i as u32));
                }
            }
            self.update_interest(k);
            self.fill_requests(k);
        }
        if complete {
            self.cv_notify();
        }
        self.connect_more(Instant::now(), cx);
    }

    fn cv_notify(&self) {
        if let Some(t) = self.me.upgrade() {
            t.cv.notify_all();
        }
    }

    // ---- peers --------------------------------------------------------------------------

    /// Registers a handshaken connection; `None` refuses it (a duplicate, ourselves, full).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_peer(
        &mut self,
        link: Link,
        enc: Option<Rc4>,
        hs: &Handshake,
        addr: SocketAddr,
        outgoing: bool,
        encrypted: bool,
        cx: &mut Cx,
    ) -> Option<u64> {
        let now = Instant::now();
        if hs.peer_id == self.our_id {
            if let Some(k) = self.known.get_mut(&addr) {
                k.banned = true;
                k.connecting = None;
            }
            return None;
        }
        // Two connections to one peer (both sides dialed at once): both sides keep the one the
        // lower peer ID started, so they agree on which to drop.
        if let Some((&old, p)) = self.peers.iter().find(|(_, p)| p.id == hs.peer_id) {
            let keep_ours = self.our_id < hs.peer_id;
            if p.outgoing == outgoing || keep_ours != outgoing {
                if let Some(k) = self.known.get_mut(&addr) {
                    k.connecting = None;
                }
                return None;
            }
            self.remove_peer(old, cx);
        }
        if !self.running() || self.peers.len() >= self.max_peers + 5 {
            if let Some(k) = self.known.get_mut(&addr) {
                k.connecting = None;
            }
            return None;
        }
        let key = self.next_key;
        self.next_key += 1;
        let n = self.have.len();
        let mut p = Peer {
            addr,
            link,
            enc,
            id: hs.peer_id,
            outgoing,
            encrypted,
            ext: hs.extended(),
            fast: hs.fast(),
            dht: hs.dht(),
            v2: hs.v2(),
            hash_asked: 0,
            hash_serving: 0,
            hash_rejects: 0,
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            have: Bitfield::new(n),
            early_bits: None,
            early_all: false,
            early_haves: Vec::new(),
            ut_metadata: 0,
            ut_pex: 0,
            metadata_size: None,
            listen_port: None,
            client_name: None,
            reqq: 250,
            requests: Vec::new(),
            serving: HashSet::new(),
            allowed_fast: HashSet::new(),
            dl_round: 0,
            ul_round: 0,
            downloaded: 0,
            uploaded: 0,
            last_recv: now,
            last_sent: now,
            last_piece: now,
            pex_sent: HashSet::new(),
            // The first PEX message goes out at the next tick, then one a minute.
            last_pex: now.checked_sub(PEX_INTERVAL).unwrap_or(now),
            unchoked_at: now,
        };
        if p.ext {
            let mut h = ExtendedHandshake::default();
            h.m.insert("ut_metadata".into(), UT_METADATA);
            if self.pex && !self.private {
                h.m.insert("ut_pex".into(), UT_PEX);
            }
            h.v = Some(concat!("only-bittorrent ", env!("CARGO_PKG_VERSION")).into());
            h.p = Some(self.listen_port);
            h.reqq = Some(MAX_SERVING as u32);
            h.metadata_size = self.info.as_ref().map(|i| i.raw().len() as u32);
            h.yourip = Some(addr.ip());
            p.send(&Message::Extended {
                id: 0,
                payload: h.encode(),
            });
        }
        if self.info.is_some() && self.status != TorrentStatus::Checking {
            if p.fast && self.have.is_full() {
                p.send(&Message::HaveAll);
            } else if p.fast && self.have.count() == 0 {
                p.send(&Message::HaveNone);
            } else {
                p.send(&Message::Bitfield(self.have.as_bytes().to_vec()));
            }
        } else if p.fast {
            p.send(&Message::HaveNone);
        }
        if p.dht {
            if let Some(port) = self.dht_port() {
                p.send(&Message::Port(port));
            }
        }
        if p.fast {
            if let (Some(info), IpAddr::V4(ip)) = (&self.info, addr.ip()) {
                for i in
                    allowed_fast_set(&self.info_hash, ip, info.num_pieces() as u32, ALLOWED_FAST)
                {
                    p.send(&Message::AllowedFast(i));
                }
            }
        }
        self.peers.insert(key, p);
        if outgoing {
            if let Some(k) = self.known.get_mut(&addr) {
                k.connected = true;
                k.connecting = None;
                k.failures = 0;
            }
        }
        cx.events.push(TorrentEvent::PeerConnected(addr));
        Some(key)
    }

    fn dht_port(&self) -> Option<u16> {
        let client = self.me.upgrade()?.client.upgrade()?;
        client.dht.is_some().then_some(client.listen.port())
    }

    pub(crate) fn remove_peer(&mut self, key: u64, cx: &mut Cx) {
        let Some(p) = self.peers.remove(&key) else {
            return;
        };
        for i in p.have.ones() {
            if let Some(a) = self.availability.get_mut(i) {
                *a = a.saturating_sub(1);
            }
        }
        for (r, _) in &p.requests {
            self.release(r);
        }
        if let Some(m) = &mut self.meta {
            m.asked.retain(|_, (k, _)| *k != key);
        }
        for l in self.layer_dl.values_mut() {
            l.asked.retain(|_, (k, ..)| *k != key);
        }
        self.upload_wait.retain(|(k, _)| *k != key);
        if self.optimistic == Some(key) {
            self.optimistic = None;
        }
        if let Some(k) = self.known.get_mut(&p.listen_addr()) {
            k.connected = false;
            k.connecting = None;
            k.next_try = Instant::now() + Duration::from_secs(30);
        }
        cx.close.push(p.link.clone());
        cx.events.push(TorrentEvent::PeerDisconnected(p.addr));
        // Others may take its pieces.
        let keys: Vec<u64> = self.peers.keys().copied().collect();
        for k in keys {
            self.fill_requests(k);
        }
    }

    /// A dial that failed before the handshake: back off, or retry another way.
    pub(crate) fn dial_failed(&mut self, d: Dial, cx: &mut Cx) {
        let now = Instant::now();
        let Some(k) = self.known.get_mut(&d.addr) else {
            return;
        };
        k.connecting = None;
        if d.utp {
            // uTP did not work: TCP next, at once.
            k.no_utp = true;
            k.next_try = now;
        } else if d.mse && self.mse == crate::mse::Policy::Prefer && !k.plaintext {
            k.plaintext = true;
            k.next_try = now;
        } else {
            k.failures += 1;
            k.no_utp = false;
            k.plaintext = false;
            k.next_try = now + Duration::from_secs(15 * u64::from(1 + k.failures.min(20)));
        }
        self.connect_more(now, cx);
    }

    pub(crate) fn connect_more(&mut self, now: Instant, cx: &mut Cx) {
        if !self.running() || self.status == TorrentStatus::Checking {
            return;
        }
        if self.is_complete() && self.status == TorrentStatus::Seeding {
            // Seeders wait to be found, and still dial leechers they learned of.
        }
        let connecting = self
            .known
            .values()
            .filter(|k| k.connecting.is_some())
            .count();
        let mut room = self
            .max_peers
            .saturating_sub(self.peers.len() + connecting)
            .min(8);
        if room == 0 {
            return;
        }
        let connected: HashSet<SocketAddr> = self.peers.values().map(Peer::listen_addr).collect();
        for (addr, k) in &mut self.known {
            if room == 0 {
                break;
            }
            if let Some(at) = k.connecting {
                if now.duration_since(at) > Duration::from_secs(60) {
                    k.connecting = None;
                }
                continue;
            }
            if k.banned || k.connected || connected.contains(addr) || k.next_try > now {
                continue;
            }
            k.connecting = Some(now);
            room -= 1;
            cx.dials.push(Dial {
                addr: *addr,
                utp: self.use_utp && !k.no_utp,
                mse: match self.mse {
                    crate::mse::Policy::Disabled => false,
                    crate::mse::Policy::Require => true,
                    crate::mse::Policy::Prefer => !k.plaintext,
                },
            });
        }
    }

    // ---- interest, choking, requests ----------------------------------------------------

    fn wants_from(&self, p: &Peer) -> bool {
        self.info.is_some()
            && self.status != TorrentStatus::Checking
            && p.have.ones().any(|i| {
                !self.have.get(i) && !self.verifying.contains(&(i as u32)) && !self.blocked.get(i)
            })
    }

    /// Recomputes the pieces a missing piece layer keeps from being checked.
    fn update_blocked(&mut self) {
        let Some(info) = self.info.clone() else {
            return;
        };
        if info.has_v1() || self.layers.is_complete(&info) {
            self.blocked = Bitfield::new(0);
            return;
        }
        let mut b = Bitfield::new(info.num_pieces());
        for f in self.layers.missing(&info) {
            for i in info.file_pieces(f) {
                b.set(i, true);
            }
        }
        self.blocked = b;
    }

    fn web_busy(&self, i: u32) -> bool {
        self.web_seeds.iter().any(|w| w.piece == Some(i))
    }

    fn update_interest(&mut self, key: u64) {
        let Some(p) = self.peers.get(&key) else {
            return;
        };
        let want = self.wants_from(p);
        let Some(p) = self.peers.get_mut(&key) else {
            return;
        };
        if want != p.am_interested {
            p.am_interested = want;
            p.send(if want {
                &Message::Interested
            } else {
                &Message::NotInterested
            });
        }
    }

    fn release(&mut self, r: &Req) {
        if let Some(pd) = self.downloading.get_mut(&r.index) {
            let b = (r.begin / BLOCK_SIZE) as usize;
            if let (Some(st), Some(c)) = (pd.blocks.get_mut(b), pd.req_count.get_mut(b)) {
                *c = c.saturating_sub(1);
                if *st == 1 && *c == 0 {
                    *st = 0;
                }
            }
        }
    }

    fn pick_block(&mut self, key: u64) -> Option<Req> {
        let info = self.info.clone()?;
        let p = self.peers.get(&key)?;
        let choked = p.peer_choking;
        let ok_piece = |i: u32| !choked || p.allowed_fast.contains(&i);
        let mine: HashSet<Req> = p.requests.iter().map(|(r, _)| *r).collect();
        // 1. A piece in progress.
        let mut partial: Vec<u32> = self
            .downloading
            .iter()
            .filter(|(i, pd)| p.have.get(**i as usize) && ok_piece(**i) && pd.blocks.contains(&0))
            .map(|(i, _)| *i)
            .collect();
        partial.sort_unstable_by_key(|i| {
            (self.availability.get(*i as usize).copied().unwrap_or(0), *i)
        });
        if let Some(&i) = partial.first() {
            let pd = self.downloading.get_mut(&i)?;
            let b = pd.blocks.iter().position(|&s| s == 0)?;
            pd.blocks[b] = 1;
            pd.req_count[b] += 1;
            let size = info.piece_size(i as usize);
            let begin = b as u32 * BLOCK_SIZE;
            return Some(Req {
                index: i,
                begin,
                length: BLOCK_SIZE.min(size - begin),
            });
        }
        // 2. A new piece: random among the first few, then rarest first.
        let cands: Vec<u32> = (0..info.num_pieces() as u32)
            .filter(|&i| {
                !self.have.get(i as usize)
                    && p.have.get(i as usize)
                    && !self.downloading.contains_key(&i)
                    && !self.verifying.contains(&i)
                    && !self.blocked.get(i as usize)
                    && ok_piece(i)
                    && !self.web_busy(i)
            })
            .collect();
        if !cands.is_empty() {
            let i = if self.have.count() < RANDOM_FIRST {
                cands[crate::rand_u32() as usize % cands.len()]
            } else {
                let min = cands
                    .iter()
                    .map(|&i| self.availability[i as usize])
                    .min()
                    .unwrap_or(0);
                let rarest: Vec<u32> = cands
                    .into_iter()
                    .filter(|&i| self.availability[i as usize] == min)
                    .collect();
                rarest[crate::rand_u32() as usize % rarest.len()]
            };
            let size = info.piece_size(i as usize);
            let nb = block_count(size);
            let mut pd = PieceDl {
                blocks: vec![0; nb],
                req_count: vec![0; nb],
                buf: vec![0; size as usize],
                ..PieceDl::default()
            };
            pd.blocks[0] = 1;
            pd.req_count[0] = 1;
            self.downloading.insert(i, pd);
            return Some(Req {
                index: i,
                begin: 0,
                length: BLOCK_SIZE.min(size),
            });
        }
        // 3. Endgame: every missing block is requested; ask for one again from this peer.
        let mut best: Option<(u8, Req)> = None;
        for (&i, pd) in &self.downloading {
            if !p.have.get(i as usize) || !ok_piece(i) {
                continue;
            }
            let size = info.piece_size(i as usize);
            for (b, &s) in pd.blocks.iter().enumerate() {
                if s != 1 || pd.req_count[b] >= 2 {
                    continue;
                }
                let begin = b as u32 * BLOCK_SIZE;
                let r = Req {
                    index: i,
                    begin,
                    length: BLOCK_SIZE.min(size - begin),
                };
                if mine.contains(&r) {
                    continue;
                }
                if best.is_none_or(|(c, _)| pd.req_count[b] < c) {
                    best = Some((pd.req_count[b], r));
                }
            }
        }
        let (_, r) = best?;
        let pd = self.downloading.get_mut(&r.index)?;
        pd.req_count[(r.begin / BLOCK_SIZE) as usize] += 1;
        Some(r)
    }

    pub(crate) fn fill_requests(&mut self, key: u64) {
        if self.status == TorrentStatus::Checking || !self.running() || self.info.is_none() {
            return;
        }
        let Some(p) = self.peers.get(&key) else {
            return;
        };
        if !p.am_interested || (p.peer_choking && p.allowed_fast.is_empty()) {
            return;
        }
        let target = p.reqq.clamp(2, PIPELINE);
        if p.requests.len() > target / 2 {
            return; // refill once half the pipeline is answered
        }
        let mut batch = Vec::new();
        let now = Instant::now();
        while self
            .peers
            .get(&key)
            .is_some_and(|p| p.requests.len() + batch.len() < target)
        {
            if !self.may_download(now) {
                break; // the next tick refills
            }
            match self.pick_block(key) {
                Some(r) => {
                    self.took_download(u64::from(r.length));
                    batch.push(r);
                }
                None => break,
            }
        }
        let Some(p) = self.peers.get_mut(&key) else {
            return;
        };
        for r in batch {
            p.send(&Message::Request {
                index: r.index,
                begin: r.begin,
                length: r.length,
            });
            p.requests.push((r, now));
        }
    }

    fn rechoke(&mut self, now: Instant) {
        self.last_choke = now;
        let seeding = self.is_complete();
        let mut cands: Vec<(u64, u64)> = self
            .peers
            .iter()
            .filter(|(_, p)| p.peer_interested)
            .map(|(k, p)| (*k, if seeding { p.ul_round } else { p.dl_round }))
            .collect();
        cands.sort_by_key(|a| std::cmp::Reverse(a.1));
        let mut unchoke: HashSet<u64> = cands
            .iter()
            .take(self.upload_slots)
            .map(|(k, _)| *k)
            .collect();
        if now.duration_since(self.last_optimistic) >= OPTIMISTIC_INTERVAL
            || self.optimistic.is_none()
        {
            self.last_optimistic = now;
            let rest: Vec<u64> = cands
                .iter()
                .map(|(k, _)| *k)
                .filter(|k| !unchoke.contains(k))
                .collect();
            self.optimistic =
                (!rest.is_empty()).then(|| rest[crate::rand_u32() as usize % rest.len()]);
        }
        if let Some(o) = self.optimistic {
            unchoke.insert(o);
        }
        let mut choked = Vec::new();
        for (k, p) in &mut self.peers {
            let choke = !unchoke.contains(k);
            if choke != p.am_choking {
                p.am_choking = choke;
                if choke {
                    choked.push(*k);
                    p.send(&Message::Choke);
                    if p.fast {
                        for r in p.serving.drain().collect::<Vec<_>>() {
                            p.send(&Message::Reject {
                                index: r.index,
                                begin: r.begin,
                                length: r.length,
                            });
                        }
                    } else {
                        p.serving.clear();
                    }
                } else {
                    p.unchoked_at = now;
                    p.send(&Message::Unchoke);
                }
            }
            p.dl_round = 0;
            p.ul_round = 0;
        }
        if !choked.is_empty() && !self.upload_wait.is_empty() {
            self.upload_wait.retain(|(k, _)| !choked.contains(k));
        }
    }

    /// Unchokes an interested peer at once when an upload slot is free.
    fn quick_unchoke(&mut self, key: u64) {
        let unchoked = self.peers.values().filter(|p| !p.am_choking).count();
        if unchoked > self.upload_slots {
            return;
        }
        if let Some(p) = self.peers.get_mut(&key) {
            if p.am_choking && p.peer_interested {
                p.am_choking = false;
                p.unchoked_at = Instant::now();
                p.send(&Message::Unchoke);
            }
        }
    }

    // ---- messages -----------------------------------------------------------------------

    pub(crate) fn on_message(&mut self, key: u64, m: Message, cx: &mut Cx) {
        let n = self.have.len();
        let has_info = self.info.is_some();
        {
            let Some(p) = self.peers.get_mut(&key) else {
                return;
            };
            p.last_recv = Instant::now();
        }
        match m {
            Message::KeepAlive => {}
            Message::Choke => {
                let Some(p) = self.peers.get_mut(&key) else {
                    return;
                };
                p.peer_choking = true;
                if !p.fast {
                    // Without the Fast extension a choke drops every request but allowed-fast ones.
                    let all = std::mem::take(&mut p.requests);
                    let (keep, dropped): (Vec<_>, Vec<_>) = all
                        .into_iter()
                        .partition(|(r, _)| p.allowed_fast.contains(&r.index));
                    p.requests = keep;
                    for (r, _) in dropped {
                        self.release(&r);
                    }
                }
            }
            Message::Unchoke => {
                if let Some(p) = self.peers.get_mut(&key) {
                    p.peer_choking = false;
                }
                self.fill_requests(key);
            }
            Message::Interested => {
                if let Some(p) = self.peers.get_mut(&key) {
                    p.peer_interested = true;
                }
                self.quick_unchoke(key);
            }
            Message::NotInterested => {
                if let Some(p) = self.peers.get_mut(&key) {
                    p.peer_interested = false;
                }
            }
            Message::Have(i) => {
                let Some(p) = self.peers.get_mut(&key) else {
                    return;
                };
                if !has_info {
                    if p.early_haves.len() < 100_000 {
                        p.early_haves.push(i);
                    }
                    return;
                }
                if (i as usize) >= n {
                    cx.close.push(p.link.clone());
                    return;
                }
                if !p.have.get(i as usize) {
                    p.have.set(i as usize, true);
                    self.availability[i as usize] += 1;
                }
                self.update_interest(key);
                self.fill_requests(key);
            }
            Message::Bitfield(b) => {
                let Some(p) = self.peers.get_mut(&key) else {
                    return;
                };
                if !has_info {
                    p.early_bits = Some(b);
                    return;
                }
                let Some(bf) = Bitfield::from_bytes(&b, n) else {
                    cx.close.push(p.link.clone());
                    return;
                };
                for i in p.have.ones().collect::<Vec<_>>() {
                    self.availability[i] = self.availability[i].saturating_sub(1);
                }
                for i in bf.ones() {
                    self.availability[i] += 1;
                }
                if let Some(p) = self.peers.get_mut(&key) {
                    p.have = bf;
                }
                self.update_interest(key);
                self.fill_requests(key);
            }
            Message::HaveAll => {
                let Some(p) = self.peers.get_mut(&key) else {
                    return;
                };
                if !has_info {
                    p.early_all = true;
                    return;
                }
                for i in p.have.ones().collect::<Vec<_>>() {
                    self.availability[i] = self.availability[i].saturating_sub(1);
                }
                for a in &mut self.availability {
                    *a += 1;
                }
                if let Some(p) = self.peers.get_mut(&key) {
                    p.have = Bitfield::full(n);
                }
                self.update_interest(key);
                self.fill_requests(key);
            }
            Message::HaveNone => {}
            Message::Request {
                index,
                begin,
                length,
            } => self.on_request(
                key,
                Req {
                    index,
                    begin,
                    length,
                },
            ),
            Message::Piece { index, begin, data } => self.on_piece(key, index, begin, data, cx),
            Message::Cancel {
                index,
                begin,
                length,
            } => {
                let r = Req {
                    index,
                    begin,
                    length,
                };
                if let Some(p) = self.peers.get_mut(&key) {
                    p.serving.remove(&r);
                }
                if !self.upload_wait.is_empty() {
                    self.upload_wait.retain(|x| *x != (key, r));
                }
            }
            Message::Reject {
                index,
                begin,
                length,
            } => {
                let r = Req {
                    index,
                    begin,
                    length,
                };
                let Some(p) = self.peers.get_mut(&key) else {
                    return;
                };
                let before = p.requests.len();
                p.requests.retain(|(x, _)| *x != r);
                if p.requests.len() != before {
                    self.release(&r);
                }
                if self.peers.get(&key).is_some_and(|p| !p.peer_choking) {
                    self.fill_requests(key);
                }
            }
            Message::AllowedFast(i) => {
                if let Some(p) = self.peers.get_mut(&key) {
                    if (i as usize) < n || !has_info {
                        p.allowed_fast.insert(i);
                    }
                }
                self.fill_requests(key);
            }
            Message::Port(port) => {
                if let Some(p) = self.peers.get(&key) {
                    if port != 0 {
                        cx.dht_ping.push(SocketAddr::new(p.addr.ip(), port));
                    }
                }
            }
            Message::HashRequest(r) => self.on_hash_request(key, r),
            Message::Hashes { req, hashes } => self.on_hashes(key, req, &hashes),
            Message::HashReject(r) => self.on_hash_reject(key, r),
            Message::Suggest(_) | Message::Unknown { .. } => {}
            Message::Extended { id, payload } => self.on_extended(key, id, &payload, cx),
        }
    }

    fn on_request(&mut self, key: u64, r: Req) {
        let Some(info) = self.info.clone() else {
            return;
        };
        if self.storage.is_none() {
            return;
        }
        let Some(p) = self.peers.get_mut(&key) else {
            return;
        };
        let valid = (r.index as usize) < info.num_pieces()
            && r.length > 0
            && r.length <= 128 * 1024
            && u64::from(r.begin) + u64::from(r.length)
                <= u64::from(info.piece_size(r.index as usize))
            && self.have.get(r.index as usize);
        let allowed = !p.am_choking
            || (p.fast && allowed_fast_for(&self.info_hash, p.addr, info.num_pieces(), r.index));
        if !valid || !allowed || p.serving.len() >= MAX_SERVING {
            if p.fast {
                p.send(&Message::Reject {
                    index: r.index,
                    begin: r.begin,
                    length: r.length,
                });
            }
            return;
        }
        if !p.serving.insert(r) {
            return;
        }
        self.upload_wait.push_back((key, r));
        self.pump_uploads();
    }

    /// Starts the reads of queued requests while the upload limits allow.
    fn pump_uploads(&mut self) {
        let (Some(info), Some(storage)) = (self.info.clone(), self.storage.clone()) else {
            return;
        };
        let now = Instant::now();
        while let Some(&(key, r)) = self.upload_wait.front() {
            if !self.may_upload(now) {
                return; // the next tick refills
            }
            self.upload_wait.pop_front();
            if !self.peers.get(&key).is_some_and(|p| p.serving.contains(&r)) {
                continue; // cancelled or choked meanwhile
            }
            self.up.take(u64::from(r.length));
            self.rates.up_take(u64::from(r.length));
            let me = self.me.clone();
            let storage = storage.clone();
            let off = info.piece_offset(r.index as usize) + u64::from(r.begin);
            let job = Box::new(move || {
                let data = storage.read(off, r.length as usize);
                if let Some(t) = me.upgrade() {
                    t.with(|st, _| st.send_block(key, r, data));
                }
            });
            if self.pool.try_execute(job).is_err() {
                if let Some(p) = self.peers.get_mut(&key) {
                    p.serving.remove(&r);
                }
            }
        }
    }

    fn send_block(&mut self, key: u64, r: Req, data: std::io::Result<Vec<u8>>) {
        let Some(p) = self.peers.get_mut(&key) else {
            return;
        };
        if !p.serving.remove(&r) {
            return; // cancelled, or choked meanwhile
        }
        match data {
            Ok(d) => {
                let len = d.len() as u64;
                p.send(&Message::Piece {
                    index: r.index,
                    begin: r.begin,
                    data: d,
                });
                p.uploaded += len;
                p.ul_round += len;
                self.uploaded += len;
            }
            Err(_) => {
                if p.fast {
                    p.send(&Message::Reject {
                        index: r.index,
                        begin: r.begin,
                        length: r.length,
                    });
                }
            }
        }
    }

    fn on_piece(&mut self, key: u64, index: u32, begin: u32, data: Vec<u8>, cx: &mut Cx) {
        let Some(info) = self.info.clone() else {
            return;
        };
        let r = Req {
            index,
            begin,
            length: data.len() as u32,
        };
        let now = Instant::now();
        let ip = {
            let Some(p) = self.peers.get_mut(&key) else {
                return;
            };
            p.requests.retain(|(x, _)| *x != r);
            p.last_piece = now;
            p.downloaded += data.len() as u64;
            p.dl_round += data.len() as u64;
            p.addr.ip()
        };
        self.downloaded += data.len() as u64;
        let Some(pd) = self.downloading.get_mut(&index) else {
            self.fill_requests(key);
            return;
        };
        let b = (begin / BLOCK_SIZE) as usize;
        let size = info.piece_size(index as usize);
        if begin % BLOCK_SIZE != 0
            || b >= pd.blocks.len()
            || u64::from(begin) + data.len() as u64 > u64::from(size)
        {
            self.fill_requests(key);
            return;
        }
        if pd.blocks[b] != 2 {
            pd.buf[begin as usize..begin as usize + data.len()].copy_from_slice(&data);
            pd.blocks[b] = 2;
            pd.received += 1;
            pd.contributors.insert(ip);
            // Endgame: cancel the same block asked of others.
            if pd.req_count[b] > 1 {
                for (k, op) in &mut self.peers {
                    if *k == key {
                        continue;
                    }
                    let before = op.requests.len();
                    op.requests.retain(|(x, _)| *x != r);
                    if op.requests.len() != before {
                        op.send(&Message::Cancel {
                            index,
                            begin,
                            length: r.length,
                        });
                    }
                }
            }
        }
        let done = self
            .downloading
            .get(&index)
            .is_some_and(|pd| pd.received == pd.blocks.len());
        if done {
            if let Some(pd) = self.downloading.remove(&index) {
                self.verify_and_write(index, pd.buf, cx);
            }
        }
        self.fill_requests(key);
    }

    fn verify_and_write(&mut self, index: u32, buf: Vec<u8>, cx: &mut Cx) {
        let (Some(info), Some(storage)) = (self.info.clone(), self.storage.clone()) else {
            return;
        };
        self.verifying.insert(index);
        let me = self.me.clone();
        let layers = self.layers.clone();
        let job = Box::new(move || {
            let ok = info.verify_piece_with(&layers, index as usize, &buf);
            let res = if ok {
                storage
                    .write(info.piece_offset(index as usize), &buf)
                    .map(|()| true)
            } else {
                Ok(false)
            };
            if let Some(t) = me.upgrade() {
                t.with(|st, cx| st.piece_done(index, res, cx));
            }
        });
        if self.pool.try_execute(job).is_err() {
            self.verifying.remove(&index);
            cx.events
                .push(TorrentEvent::Error("disk pool refused a piece".into()));
        }
    }

    fn piece_done(&mut self, index: u32, res: std::io::Result<bool>, cx: &mut Cx) {
        self.verifying.remove(&index);
        if let Some(url) = self.ws_verifying.remove(&index) {
            if matches!(res, Ok(false)) {
                self.web_seed_failed(&url, format!("piece {index} failed its hash check"), cx);
            }
        }
        match res {
            Ok(true) => {
                if self.have.get(index as usize) {
                    return;
                }
                self.have.set(index as usize, true);
                cx.events.push(TorrentEvent::PieceVerified(index));
                let keys: Vec<u64> = self.peers.keys().copied().collect();
                for k in &keys {
                    if let Some(p) = self.peers.get_mut(k) {
                        p.send(&Message::Have(index));
                    }
                }
                for k in keys {
                    self.update_interest(k);
                    self.fill_requests(k);
                }
                if self.have.is_full() {
                    if self.status != TorrentStatus::Paused {
                        self.status = TorrentStatus::Seeding;
                    }
                    self.completed_in_session = true;
                    cx.events.push(TorrentEvent::Completed);
                    cx.announce = Some(crate::tracker::Event::Completed);
                    // Seeders do not keep connections to other seeders.
                    let seeds: Vec<u64> = self
                        .peers
                        .iter()
                        .filter(|(_, p)| p.have.is_full())
                        .map(|(k, _)| *k)
                        .collect();
                    for k in seeds {
                        self.remove_peer(k, cx);
                    }
                    self.cv_notify();
                }
            }
            Ok(false) => {
                self.hash_fails += 1;
                cx.events.push(TorrentEvent::HashFailed(index));
                let keys: Vec<u64> = self.peers.keys().copied().collect();
                for k in keys {
                    self.fill_requests(k);
                }
            }
            Err(e) => {
                cx.events
                    .push(TorrentEvent::Error(format!("writing piece {index}: {e}")));
                self.status = TorrentStatus::Error;
            }
        }
    }

    fn on_extended(&mut self, key: u64, id: u8, payload: &[u8], cx: &mut Cx) {
        match id {
            0 => {
                let Ok(h) = ExtendedHandshake::decode(payload) else {
                    return;
                };
                let Some(p) = self.peers.get_mut(&key) else {
                    return;
                };
                p.ut_metadata = h.m.get("ut_metadata").copied().unwrap_or(0);
                p.ut_pex = h.m.get("ut_pex").copied().unwrap_or(0);
                p.metadata_size = h.metadata_size;
                p.client_name = h.v.clone();
                if let Some(q) = h.reqq {
                    p.reqq = (q as usize).clamp(1, 2000);
                }
                if h.p.is_some_and(|x| x != 0) {
                    p.listen_port = h.p;
                }
                if !p.outgoing {
                    if let Some(port) = p.listen_port {
                        let a = SocketAddr::new(p.addr.ip(), port);
                        let now = Instant::now();
                        self.add_known(a, now);
                        if let Some(k) = self.known.get_mut(&a) {
                            k.connected = true;
                        }
                    }
                }
                if self.info.is_none() {
                    self.request_metadata(cx);
                }
            }
            UT_METADATA => {
                let Ok(m) = MetadataMsg::decode(payload) else {
                    return;
                };
                self.on_metadata(key, m, cx);
            }
            UT_PEX => {
                if self.private || !self.pex {
                    return;
                }
                let Ok(px) = Pex::decode(payload) else { return };
                let added: Vec<SocketAddr> = px.added.into_iter().take(50).collect();
                self.add_peers(&added, cx);
            }
            _ => {}
        }
    }

    fn on_metadata(&mut self, key: u64, m: MetadataMsg, cx: &mut Cx) {
        match m {
            MetadataMsg::Request(piece) => {
                let raw = self.info.as_ref().map(|i| i.raw().to_vec());
                let Some(p) = self.peers.get_mut(&key) else {
                    return;
                };
                if p.ut_metadata == 0 {
                    return;
                }
                let id = p.ut_metadata;
                let reply = match raw {
                    Some(raw) if (piece as usize) * METADATA_PIECE < raw.len() => {
                        let start = piece as usize * METADATA_PIECE;
                        let end = (start + METADATA_PIECE).min(raw.len());
                        MetadataMsg::Data {
                            piece,
                            total_size: raw.len() as u32,
                            data: raw[start..end].to_vec(),
                        }
                    }
                    _ => MetadataMsg::Reject(piece),
                };
                p.send(&Message::Extended {
                    id,
                    payload: reply.encode(),
                });
            }
            MetadataMsg::Data {
                piece,
                total_size,
                data,
            } => {
                let Some(meta) = &mut self.meta else { return };
                if total_size != meta.size || (piece as usize) >= meta.pieces.len() {
                    return;
                }
                let want = if (piece as usize) + 1 == meta.pieces.len() {
                    meta.size as usize - piece as usize * METADATA_PIECE
                } else {
                    METADATA_PIECE
                };
                if data.len() != want {
                    return;
                }
                meta.pieces[piece as usize] = Some(data);
                meta.asked.remove(&piece);
                if meta.pieces.iter().all(Option::is_some) {
                    let raw: Vec<u8> = meta.pieces.iter().flatten().flatten().copied().collect();
                    let ok = match self.info_hash_v2 {
                        // A v2-only link: the dictionary's SHA-256 is the hash.
                        Some(v2) if v2.truncated() == self.info_hash => {
                            merkle::sha256(&raw) == v2.0
                        }
                        _ => sha1(&raw) == self.info_hash.0,
                    };
                    if ok {
                        match Info::parse(&raw) {
                            Ok(info) => {
                                self.set_info(info, cx);
                                let keys: Vec<u64> = self.peers.keys().copied().collect();
                                for k in keys {
                                    self.update_interest(k);
                                }
                            }
                            Err(e) => {
                                cx.events
                                    .push(TorrentEvent::Error(format!("metadata: {e}")));
                                self.meta = None;
                            }
                        }
                    } else {
                        self.meta = None; // start over
                    }
                } else {
                    self.request_metadata(cx);
                }
            }
            MetadataMsg::Reject(piece) => {
                if let Some(meta) = &mut self.meta {
                    meta.asked.remove(&piece);
                }
            }
        }
    }

    fn request_metadata(&mut self, _cx: &mut Cx) {
        if self.info.is_some() {
            return;
        }
        let now = Instant::now();
        if self.meta.is_none() {
            let size = self
                .peers
                .values()
                .filter(|p| p.ut_metadata != 0)
                .find_map(|p| p.metadata_size)
                .filter(|&s| s > 0 && s <= MAX_METADATA);
            let Some(size) = size else { return };
            self.meta = Some(MetaDl {
                size,
                pieces: vec![None; (size as usize).div_ceil(METADATA_PIECE)],
                asked: HashMap::new(),
            });
        }
        let Some(meta) = &mut self.meta else { return };
        meta.asked
            .retain(|_, (_, at)| now.duration_since(*at) < META_TIMEOUT);
        let size = meta.size;
        let mut sources: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, p)| p.ut_metadata != 0 && p.metadata_size == Some(size))
            .map(|(k, _)| *k)
            .collect();
        if sources.is_empty() {
            return;
        }
        sources.sort_unstable();
        let mut si = crate::rand_u32() as usize;
        for piece in 0..meta.pieces.len() as u32 {
            if meta.pieces[piece as usize].is_some() || meta.asked.contains_key(&piece) {
                continue;
            }
            let k = sources[si % sources.len()];
            si += 1;
            if let Some(p) = self.peers.get_mut(&k) {
                let id = p.ut_metadata;
                p.send(&Message::Extended {
                    id,
                    payload: MetadataMsg::Request(piece).encode(),
                });
                meta.asked.insert(piece, (k, now));
            }
        }
    }

    // ---- periodic -------------------------------------------------------------------------

    pub(crate) fn tick(&mut self, now: Instant, cx: &mut Cx) {
        if !self.running() {
            return;
        }
        // Timeouts, keepalives, snubbing.
        let keys: Vec<u64> = self.peers.keys().copied().collect();
        for k in keys {
            let Some(p) = self.peers.get_mut(&k) else {
                continue;
            };
            if now.duration_since(p.last_recv) > PEER_TIMEOUT {
                self.remove_peer(k, cx);
                continue;
            }
            if now.duration_since(p.last_sent) > KEEPALIVE {
                p.send(&Message::KeepAlive);
            }
            let stale: Vec<Req> = p
                .requests
                .iter()
                .filter(|(_, at)| now.duration_since(*at) > REQUEST_TIMEOUT)
                .map(|(r, _)| *r)
                .collect();
            let snubbed = !p.requests.is_empty() && now.duration_since(p.last_piece) > SNUB;
            if !stale.is_empty() || snubbed {
                let all: Vec<Req> = if snubbed {
                    p.requests.drain(..).map(|(r, _)| r).collect()
                } else {
                    p.requests.retain(|(r, _)| !stale.contains(r));
                    stale
                };
                for r in all {
                    self.release(&r);
                }
            }
            self.fill_requests(k);
        }
        if now.duration_since(self.last_choke) >= CHOKE_INTERVAL {
            self.rechoke(now);
        }
        if self.info.is_none() {
            self.request_metadata(cx);
        }
        if self.pex && !self.private {
            self.send_pex(now);
        }
        self.pump_uploads();
        self.request_layers(now);
        self.web_seed_work(now, cx);
        self.check_seed_limits(now, cx);
        if !self.running() {
            return;
        }
        self.connect_more(now, cx);
    }

    fn check_seed_limits(&mut self, now: Instant, cx: &mut Cx) {
        let seeding = self.status == TorrentStatus::Seeding && self.is_complete();
        if !seeding {
            if let Some(s) = self.seeding_since.take() {
                self.seeding_before += now.duration_since(s);
            }
            return;
        }
        self.seeding_since.get_or_insert(now);
        let SeedLimits { ratio, time } = self.seed_limits;
        let total = self.info.as_ref().map_or(0, |i| i.total_length);
        let denom = if self.downloaded > 0 {
            self.downloaded
        } else {
            total
        };
        let ratio_hit =
            ratio.is_some_and(|r| denom > 0 && self.uploaded as f64 / denom as f64 >= r);
        let time_hit = time.is_some_and(|t| self.seeding_time(now) >= t);
        if ratio_hit || time_hit {
            cx.events.push(TorrentEvent::SeedLimitReached);
            self.pause(cx);
        }
    }

    // ---- v2 piece layers ----------------------------------------------------------------

    /// The merkle tree of `file` from its piece layer (cached), to answer hash requests.
    fn tree(&mut self, info: &Info, file: usize) -> Option<Arc<MerkleTree>> {
        let f = info.files.get(file)?;
        let root = f.pieces_root?;
        if let Some(t) = self.trees.get(&root) {
            return Some(t.clone());
        }
        let layer = self.layers.get(&root)?;
        let t = Arc::new(MerkleTree::from_layer(
            layer,
            merkle::piece_height(info.piece_length),
            merkle::root_height(f.length),
        ));
        if self.trees.len() >= MAX_TREES {
            self.trees.clear();
        }
        self.trees.insert(root, t.clone());
        Some(t)
    }

    fn reject_hashes(&mut self, key: u64, r: HashRequest) {
        if let Some(p) = self.peers.get_mut(&key) {
            p.send(&Message::HashReject(r));
        }
    }

    /// Answers a hash request: piece-layer hashes from the layer, block hashes of a piece we
    /// have from storage (on the pool). Anything else is rejected.
    fn on_hash_request(&mut self, key: u64, r: HashRequest) {
        let Some(info) = self.info.clone() else {
            return self.reject_hashes(key, r);
        };
        let Some(file) = info.file_of_root(&r.pieces_root) else {
            return self.reject_hashes(key, r);
        };
        let len = info.files[file].length;
        let rh = merkle::root_height(len);
        let ph = merkle::piece_height(info.piece_length);
        let bpp = merkle::blocks_per_piece(info.piece_length);
        let index = u64::from(r.index);
        if r.base_layer >= rh
            || r.proof_layers >= rh - r.base_layer
            || !merkle::valid_range(rh - r.base_layer, index, r.length)
        {
            return self.reject_hashes(key, r);
        }
        let Some(tree) = self.tree(&info, file) else {
            return self.reject_hashes(key, r);
        };
        if r.base_layer == ph {
            match tree.hashes(index, r.length, r.proof_layers) {
                Some(hashes) => {
                    if let Some(p) = self.peers.get_mut(&key) {
                        p.send(&Message::Hashes { req: r, hashes });
                    }
                }
                None => self.reject_hashes(key, r),
            }
            return;
        }
        let piece = info.file_pieces(file).start as u64 + index / u64::from(bpp);
        let busy = self
            .peers
            .get(&key)
            .is_none_or(|p| p.hash_serving >= MAX_HASH_SERVING);
        if r.base_layer != 0
            || r.length != bpp
            || busy
            || !self.have.get(piece as usize)
            || self.storage.is_none()
        {
            return self.reject_hashes(key, r);
        }
        let Some(storage) = self.storage.clone() else {
            return;
        };
        let Some(uncles) = tree.uncles(0, index, r.length, r.proof_layers) else {
            return self.reject_hashes(key, r);
        };
        // The file's bytes of that piece (its tail is padding in the piece space).
        let pl = u64::from(info.piece_length);
        let local = index / u64::from(bpp);
        let n = (len - local * pl).min(pl) as usize;
        let off = info.files[file].offset + local * pl;
        if let Some(p) = self.peers.get_mut(&key) {
            p.hash_serving += 1;
        }
        let me = self.me.clone();
        let job = Box::new(move || {
            let res = storage.read(off, n).map(|d| {
                let mut h = merkle::block_hashes(&d);
                h.resize(bpp as usize, [0; 32]);
                h.extend(uncles);
                h
            });
            if let Some(t) = me.upgrade() {
                t.with(|st, _| st.send_hashes(key, r, res.ok()));
            }
        });
        if self.pool.try_execute(job).is_err() {
            if let Some(p) = self.peers.get_mut(&key) {
                p.hash_serving -= 1;
            }
            self.reject_hashes(key, r);
        }
    }

    fn send_hashes(&mut self, key: u64, r: HashRequest, hashes: Option<Vec<Hash>>) {
        let Some(p) = self.peers.get_mut(&key) else {
            return;
        };
        p.hash_serving = p.hash_serving.saturating_sub(1);
        p.send(&match hashes {
            Some(hashes) => Message::Hashes { req: r, hashes },
            None => Message::HashReject(r),
        });
    }

    /// A chunk of a piece layer asked of `key`, matching `r`: removes it from the asked set.
    fn take_asked(&mut self, key: u64, r: &HashRequest) -> Option<usize> {
        let dl = self.layer_dl.get_mut(&r.pieces_root)?;
        let c = dl
            .asked
            .iter()
            .find(|(_, (k, q, _))| *k == key && q == r)
            .map(|(c, _)| *c)?;
        dl.asked.remove(&c);
        if let Some(p) = self.peers.get_mut(&key) {
            p.hash_asked = p.hash_asked.saturating_sub(1);
        }
        Some(c)
    }

    fn on_hashes(&mut self, key: u64, r: HashRequest, hashes: &[Hash]) {
        let Some(c) = self.take_asked(key, &r) else {
            return; // not asked for: ignored
        };
        let Some(info) = self.info.clone() else {
            return;
        };
        let Some(dl) = self.layer_dl.get_mut(&r.pieces_root) else {
            return;
        };
        let count = r.length as usize;
        if hashes.len() != count + merkle::uncle_count(r.length, r.proof_layers) {
            return;
        }
        let ph = merkle::piece_height(info.piece_length);
        let rh = merkle::root_height(dl.file_len);
        let (nodes, uncles) = hashes.split_at(count);
        if !merkle::verify_hashes(nodes, ph, u64::from(r.index), uncles, &dl.root, rh) {
            if let Some(p) = self.peers.get_mut(&key) {
                p.hash_rejects += 1;
            }
            return;
        }
        let real = (dl.pieces - u64::from(r.index)).min(count as u64) as usize;
        dl.chunks[c] = Some(nodes[..real].to_vec());
        if dl.chunks.iter().all(Option::is_some) {
            let layer: Vec<Hash> = dl.chunks.iter().flatten().flatten().copied().collect();
            let root = dl.root;
            self.layer_dl.remove(&root);
            if self.layers.insert(&info, root, layer) {
                self.update_blocked();
                let keys: Vec<u64> = self.peers.keys().copied().collect();
                for k in keys {
                    self.update_interest(k);
                    self.fill_requests(k);
                }
            }
        }
        self.request_layers(Instant::now());
    }

    fn on_hash_reject(&mut self, key: u64, r: HashRequest) {
        if self.take_asked(key, &r).is_some() {
            if let Some(p) = self.peers.get_mut(&key) {
                p.hash_rejects += 1;
            }
        }
    }

    /// Asks v2 peers for the piece layers still missing, a chunk of 512 hashes at a time.
    fn request_layers(&mut self, now: Instant) {
        let Some(info) = self.info.clone() else {
            return;
        };
        if !info.has_v2() || self.status == TorrentStatus::Checking {
            return;
        }
        let missing = self.layers.missing(&info);
        if missing.is_empty() {
            self.layer_dl.clear();
            return;
        }
        let pl = u64::from(info.piece_length);
        for f in missing {
            let Some(root) = info.files[f].pieces_root else {
                continue;
            };
            let len = info.files[f].length;
            self.layer_dl.entry(root).or_insert_with(|| {
                let pieces = len.div_ceil(pl);
                LayerDl {
                    root,
                    file: f,
                    file_len: len,
                    pieces,
                    chunks: vec![None; pieces.div_ceil(LAYER_CHUNK) as usize],
                    asked: HashMap::new(),
                }
            });
        }
        // Requests that timed out.
        let mut expired = Vec::new();
        for dl in self.layer_dl.values_mut() {
            dl.asked.retain(|_, (k, _, at)| {
                let keep = now.duration_since(*at) < HASH_TIMEOUT;
                if !keep {
                    expired.push(*k);
                }
                keep
            });
        }
        for k in expired {
            if let Some(p) = self.peers.get_mut(&k) {
                p.hash_asked = p.hash_asked.saturating_sub(1);
                p.hash_rejects += 1;
            }
        }
        let ph = merkle::piece_height(info.piece_length);
        let mut sends: Vec<(u64, HashRequest, Hash, usize)> = Vec::new();
        let mut asked: HashMap<u64, usize> = HashMap::new();
        for dl in self.layer_dl.values() {
            let rh = merkle::root_height(dl.file_len);
            let first = info.file_pieces(dl.file).start;
            for (c, got) in dl.chunks.iter().enumerate() {
                if got.is_some() || dl.asked.contains_key(&c) {
                    continue;
                }
                let index = c as u64 * LAYER_CHUNK;
                let left = dl.pieces - index;
                let count = left.min(LAYER_CHUNK).next_power_of_two() as u32;
                let span = first + index as usize..first + (index + left.min(LAYER_CHUNK)) as usize;
                let mut cands: Vec<u64> = self
                    .peers
                    .iter()
                    .filter(|(k, p)| {
                        p.v2 && p.hash_rejects < 3
                            && p.hash_asked + asked.get(*k).copied().unwrap_or(0) < MAX_HASH_ASKED
                            && span.clone().any(|i| p.have.get(i))
                    })
                    .map(|(k, _)| *k)
                    .collect();
                if cands.is_empty() {
                    continue;
                }
                cands.sort_unstable();
                let k = cands[crate::rand_u32() as usize % cands.len()];
                *asked.entry(k).or_default() += 1;
                let req = HashRequest::new(dl.root, ph, index as u32, count, rh - ph - 1);
                sends.push((k, req, dl.root, c));
            }
        }
        for (k, req, root, c) in sends {
            if let Some(p) = self.peers.get_mut(&k) {
                p.hash_asked += 1;
                p.send(&Message::HashRequest(req));
            }
            if let Some(dl) = self.layer_dl.get_mut(&root) {
                dl.asked.insert(c, (k, req, now));
            }
        }
    }

    // ---- web seeds ----------------------------------------------------------------------

    /// Gives idle web seeds a piece each: one no connected peer has if any, else the first
    /// missing one nobody is fetching.
    fn web_seed_work(&mut self, now: Instant, cx: &mut Cx) {
        if !self.web_wanted
            || self.web_seeds.is_empty()
            || !self.running()
            || self.status != TorrentStatus::Downloading
        {
            return;
        }
        let Some(info) = self.info.clone() else {
            return;
        };
        for w in 0..self.web_seeds.len() {
            if self.web_seeds[w].piece.is_some() || self.web_seeds[w].next_try > now {
                continue;
            }
            if !self.may_download(now) {
                return;
            }
            let free = |st: &Self, i: u32| {
                !st.have.get(i as usize)
                    && !st.downloading.contains_key(&i)
                    && !st.verifying.contains(&i)
                    && !st.blocked.get(i as usize)
                    && !st.web_busy(i)
                    && !st.ws_verifying.contains_key(&i)
            };
            let n = info.num_pieces() as u32;
            let pick = (0..n)
                .find(|&i| free(self, i) && self.availability.get(i as usize) == Some(&0))
                .or_else(|| (0..n).find(|&i| free(self, i)));
            let Some(i) = pick else { return };
            let ws = &mut self.web_seeds[w];
            ws.piece = Some(i);
            let fetch = webseed::plan(&ws.url, &info, i);
            self.took_download(u64::from(info.piece_size(i as usize)));
            cx.web.push(fetch);
        }
    }

    pub(crate) fn web_seed_done(
        &mut self,
        url: &str,
        piece: u32,
        res: Result<Vec<u8>, String>,
        cx: &mut Cx,
    ) {
        let Some(ws) = self.web_seeds.iter_mut().find(|w| w.url == url) else {
            return;
        };
        if ws.piece == Some(piece) {
            ws.piece = None;
        }
        match res {
            Ok(buf) => {
                ws.fails = 0;
                self.downloaded += buf.len() as u64;
                if self.running()
                    && !self.have.get(piece as usize)
                    && !self.verifying.contains(&piece)
                {
                    self.ws_verifying.insert(piece, url.to_owned());
                    self.verify_and_write(piece, buf, cx);
                }
            }
            Err(e) => self.web_seed_failed(url, e, cx),
        }
        self.web_seed_work(Instant::now(), cx);
    }

    fn web_seed_failed(&mut self, url: &str, error: String, cx: &mut Cx) {
        let Some(ws) = self.web_seeds.iter_mut().find(|w| w.url == url) else {
            return;
        };
        ws.fails += 1;
        let backoff = Duration::from_secs(5)
            .saturating_mul(1 << ws.fails.min(8))
            .min(WEB_SEED_BACKOFF_MAX);
        ws.next_try = Instant::now() + backoff;
        cx.events.push(TorrentEvent::WebSeedError {
            url: url.to_owned(),
            error,
        });
    }

    fn send_pex(&mut self, now: Instant) {
        let current: HashSet<SocketAddr> = self
            .peers
            .values()
            .map(Peer::listen_addr)
            .filter(|a| a.port() != 0)
            .collect();
        for p in self.peers.values_mut() {
            if p.ut_pex == 0 || now.duration_since(p.last_pex) < PEX_INTERVAL {
                continue;
            }
            let me = p.listen_addr();
            let added: Vec<SocketAddr> = current
                .iter()
                .filter(|a| **a != me && !p.pex_sent.contains(a))
                .take(50)
                .copied()
                .collect();
            let dropped: Vec<SocketAddr> = p
                .pex_sent
                .iter()
                .filter(|a| !current.contains(a))
                .take(50)
                .copied()
                .collect();
            if added.is_empty() && dropped.is_empty() {
                continue; // nothing to say: the minute starts with the first message
            }
            p.last_pex = now;
            for a in &added {
                p.pex_sent.insert(*a);
            }
            for a in &dropped {
                p.pex_sent.remove(a);
            }
            let id = p.ut_pex;
            p.send(&Message::Extended {
                id,
                payload: Pex { added, dropped }.encode(),
            });
        }
    }

    /// Pauses: drops every connection.
    pub(crate) fn pause(&mut self, cx: &mut Cx) {
        if self.status == TorrentStatus::Paused {
            return;
        }
        if let Some(s) = self.seeding_since.take() {
            self.seeding_before += Instant::now().duration_since(s);
        }
        self.status = TorrentStatus::Paused;
        self.upload_wait.clear();
        let keys: Vec<u64> = self.peers.keys().copied().collect();
        for k in keys {
            self.remove_peer(k, cx);
        }
        for k in self.known.values_mut() {
            k.connecting = None;
        }
        cx.announce = Some(crate::tracker::Event::Stopped);
        cx.events
            .push(TorrentEvent::StateChanged(TorrentStatus::Paused));
    }

    /// Resumes a paused torrent.
    pub(crate) fn resume(&mut self, cx: &mut Cx) {
        if self.status != TorrentStatus::Paused {
            return;
        }
        self.status = if self.info.is_none() {
            TorrentStatus::FetchingMetadata
        } else if self.have.is_full() {
            TorrentStatus::Seeding
        } else {
            TorrentStatus::Downloading
        };
        for t in &mut self.trackers {
            t.next = Instant::now();
            t.started = false;
        }
        for k in self.known.values_mut() {
            k.next_try = Instant::now();
        }
        cx.events.push(TorrentEvent::StateChanged(self.status));
        self.connect_more(Instant::now(), cx);
    }
}

fn allowed_fast_for(ih: &InfoHash, addr: SocketAddr, n: usize, index: u32) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => allowed_fast_set(ih, ip, n as u32, ALLOWED_FAST).contains(&index),
        IpAddr::V6(_) => false,
    }
}
