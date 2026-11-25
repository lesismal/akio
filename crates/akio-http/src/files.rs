//! Static files: path safety, MIME types, conditional requests, ranges, pre-compressed variants,
//! an in-memory cache for small files and `sendfile(2)` for large ones.

use std::{
    collections::HashMap,
    fs,
    hash::{BuildHasher, Hasher},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use akio_core::{Pool, PoolConfig};
use akio_sys::{FsEvent, FsWatcher, WatchId};

use crate::{
    context::{Context, Detached, Service},
    message::{FileBody, Headers, Method, Request, Response, format_http_date, percent_decode},
};

mod mime;
pub use mime::{MimeTypes, SNIFF_LEN, sniff};

/// Serves files below a root directory. Mount it on a wildcard route
/// (`router.get("/static/*path", Files::new("public"))`, parameter name `path`) or use it as the
/// router fallback (then the request path is used).
///
/// * `GET`/`HEAD`, `ETag` + `Last-Modified`; `If-None-Match` / `If-Modified-Since` answer `304`,
///   `If-Match` / `If-Unmodified-Since` answer `412`; `Range` requests (`206`/`416`), honoured
///   only while `If-Range` (an entity tag or a date) still matches.
/// * Several ranges (`bytes=0-9,20-29`) answer `206` with a `multipart/byteranges` body, parts
///   in request order. Overlapping ranges and ranges less than 80 bytes apart are coalesced
///   (RFC 9110 section 14.2); a header with more than 32 ranges, or whose parts would exceed
///   1 MiB, is ignored and the whole file is sent. A multipart body is built in memory.
/// * `index.html` for directories (or the [`index_files`](Files::index_files) given, tried in
///   order); `..` and other escapes are refused. Symlinks are followed. Only regular files are
///   opened: anything else, and a file asked for with a trailing slash, is `404`; a file that
///   may not be read is `403`. With [`redirect_directories`](Files::redirect_directories), a
///   directory asked for without its slash is redirected to it.
/// * The `Content-Type` by extension ([`mime_types`](Files::mime_types)), else
///   [`default_type`](Files::default_type), else [sniffed](Files::sniff) or
///   `application/octet-stream`.
/// * `file.ext.br` / `file.ext.zst` / `file.ext.gz` next to `file.ext` are served to clients
///   that accept them: the one the client's `Accept-Encoding` ranks highest by its q values
///   (`*` standing for codings it does not name, `q=0` refusing one), among equals the first of
///   [`twins`](Files::twins) (`br`, `zstd`, `gzip` by default); whether they exist is cached
///   with the file, so a hit costs no `stat` per variant.
/// * With [`compress`](Files::compress), a file cached in memory is also kept compressed, one
///   copy per coding, made once on the disk pool the first time a client asks for it and
///   served from then on to the clients that accept it.
/// * [`serve`](Files::serve) serves a path the caller names; [`try_paths`](Files::try_paths)
///   tries candidate paths in turn (`try_files`); [`list_directories`](Files::list_directories)
///   lists a directory without an index file.
/// * Files up to [`max_cached_bytes`](Files::max_cached_bytes) are cached in memory and
///   re-checked against the disk at most every [`check_interval`](Files::check_interval);
///   larger ones are sent with `sendfile` from a handle kept open (with its metadata) for up to
///   [`max_open_files`](Files::max_open_files) files, under the same re-check rule, so a hit
///   costs no `stat`/`open`. When the handles are all taken, a new file evicts the least
///   recently used one (CLOCK). An entry is dropped or replaced when its file is deleted, or
///   when its size, modification time or inode change (an atomic rename over it included).
/// * Only a cache hit inside its trust window is answered on the I/O thread. Everything that
///   touches the disk (`stat`, `open`, reading a file into the cache, the parts of a
///   multi-range response from a large file) runs on a small pool of its own (up to 16 threads,
///   4096 queued requests; past that the answer is `503` with `Retry-After: 1`, and so it is
///   past [`disk_timeout`](Files::disk_timeout)), and the response is sent from there.
/// * At most [`max_cache_bytes`](Files::max_cache_bytes) (64 MiB) of files are kept in memory,
///   the entries used least recently evicted first.
/// * With [`watch`](Files::watch) on, the cache follows the disk through change notifications
///   (inotify on Linux, kqueue on macOS) instead of re-checking: an entry is dropped as soon as
///   its file, a compressed twin, or a directory on its path changes, and until then it is
///   served without consulting the disk, however old it is. Entries the notifications cannot
///   vouch for keep the [`check_interval`](Files::check_interval) rule; see
///   [`watch`](Files::watch).
pub struct Files {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    /// [`Files::index_files`]: the files that stand for a directory, tried in order.
    index: Vec<String>,
    /// [`Files::redirect_directories`].
    redirect_dirs: bool,
    /// [`Files::mime_types`]; `None`: [`Files`]' own short table.
    mime_types: Option<Arc<MimeTypes>>,
    /// [`Files::default_type`].
    default_type: Option<Arc<str>>,
    /// [`Files::sniff`].
    sniff: bool,
    /// [`Files::error_response`].
    errors: Option<Errors>,
    /// [`Files::max_cache_bytes`].
    max_cache_bytes: u64,
    /// [`Files::disk_timeout`] and the requests it bounds.
    disk_timeout: Option<Duration>,
    waiting: Arc<Waiting>,
    max_cached: u64,
    check_interval: Duration,
    cache_control: Option<String>,
    max_open: usize,
    /// The cache, sharded by path: a hit takes one shard's read lock.
    shards: Box<[RwLock<HashMap<PathBuf, Entry>>]>,
    /// The entries holding an open file, and those holding bytes in memory, in CLOCK order.
    /// Only cache fills and evictions (on the disk pool) take it, always before a shard lock.
    ring: Mutex<Rings>,
    /// Whether [`Files::watch`] asked for change notifications, and how many watches at most.
    watch_on: bool,
    max_watches: usize,
    /// The change notifications, set up on the first request that reaches the disk (`None`
    /// when they cannot be).
    watch: OnceLock<Option<Arc<Watch>>>,
    /// The compressed twins looked up, as indexes into [`TWINS`], in order of preference among
    /// equal q values; none: no lookups and no `Vary`.
    twins: Vec<usize>,
    /// [`Files::try_paths`]' candidates; none: the path asked for.
    tries: Vec<String>,
    /// [`Files::hide`]'s test.
    hide: Option<Hide>,
    /// What the candidates resolved request paths to (see [`Tried`]).
    tried: RwLock<HashMap<String, Tried>>,
    /// [`Files::compress`]' codings, as indexes into [`TWINS`] in order of preference among
    /// equal q values; none: no copies.
    compress: Vec<usize>,
    /// [`Files::list_directories`]' bound on the entries read; 0: no listings.
    list_max: usize,
}

/// [`Files::hide`]'s test.
type Hide = Arc<dyn Fn(&str) -> bool + Send + Sync + std::panic::RefUnwindSafe>;

/// [`Files::error_response`]'s answers.
type Errors = Arc<dyn Fn(u16) -> Response + Send + Sync + std::panic::RefUnwindSafe>;

/// The default of [`Files::max_cache_bytes`]: 64 MiB.
const DEFAULT_MAX_CACHE_BYTES: u64 = 64 << 20;

/// The file [`Files::try_paths`]' candidates resolved a request path to, and when (in
/// [`clock_ms`] milliseconds): trusted for [`check_interval`](Files::check_interval) while the
/// file's own entry is.
struct Tried {
    file: PathBuf,
    checked: u64,
}

/// The most request paths [`Files::try_paths`] remembers the resolution of; past it the memory
/// starts over.
const MAX_TRIED: usize = 4096;

impl Drop for Inner {
    fn drop(&mut self) {
        // The watcher thread holds only a weak reference: wake it so that it notices and exits.
        if let Some(Some(w)) = self.watch.get() {
            w.sys.wake();
        }
    }
}

const SHARDS: usize = 16;

/// The `.br`, `.zst` and `.gz` twins of a file: `Content-Encoding` token and file extension,
/// in order of preference.
const TWINS: [(&str, &str); 3] = [("br", "br"), ("zstd", "zst"), ("gzip", "gz")];

enum Entry {
    File(Arc<Cached>),
    /// A directory, served as its index file.
    Dir(Arc<DirEntry>),
}

struct DirEntry {
    /// The index file.
    index: Arc<Path>,
    /// When the disk was last consulted, in [`clock_ms`] milliseconds.
    checked: AtomicU64,
    /// Change notifications cover the directory: trusted until they drop the entry.
    watched: AtomicBool,
}

/// Entries of one kind and the CLOCK hand: the next slot considered for eviction. Each slot
/// has the bytes it is charged.
#[derive(Default)]
struct Ring {
    slots: Vec<(PathBuf, Arc<Cached>, u64)>,
    hand: usize,
}

/// The cache's two bounds: the entries holding an open file (at most `max_open`), and those
/// holding bytes in memory (at most `max_cache_bytes` of them, `bytes` in all).
#[derive(Default)]
struct Rings {
    open: Ring,
    mem: Ring,
    bytes: u64,
}

impl Rings {
    /// Drops `path` from both rings (not from the cache's map).
    fn remove(&mut self, path: &Path) {
        if let Some(i) = self.open.position(path) {
            self.open.slots.swap_remove(i);
        }
        if let Some(i) = self.mem.position(path) {
            let (_, _, n) = self.mem.slots.swap_remove(i);
            self.bytes = self.bytes.saturating_sub(n);
        }
    }

    /// Drops every slot whose path satisfies `pred` from both rings.
    fn retain(&mut self, pred: impl Fn(&Path) -> bool) {
        self.open.slots.retain(|(p, ..)| !pred(p));
        let mut freed = 0;
        self.mem.slots.retain(|(p, _, n)| {
            let keep = !pred(p);
            if !keep {
                freed += *n;
            }
            keep
        });
        self.bytes = self.bytes.saturating_sub(freed);
    }
}

impl Ring {
    fn position(&self, path: &Path) -> Option<usize> {
        self.slots.iter().position(|(p, ..)| p == path)
    }

    /// The slot of the entry to evict: the first one from the hand that was not used since the
    /// hand last passed it (each used entry gets its bit cleared and a second chance).
    fn victim(&mut self) -> usize {
        loop {
            if self.hand >= self.slots.len() {
                self.hand = 0;
            }
            if !self.slots[self.hand].1.used.swap(false, Ordering::Relaxed) {
                return self.hand;
            }
            self.hand += 1;
        }
    }
}

impl std::fmt::Debug for Files {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Files").finish_non_exhaustive()
    }
}

/// The content of a cache entry: the bytes of a small file, or an open handle to a large one.
enum Body {
    Mem(Arc<[u8]>),
    File(Arc<fs::File>),
}

impl Clone for Body {
    fn clone(&self) -> Body {
        match self {
            Body::Mem(b) => Body::Mem(b.clone()),
            Body::File(f) => Body::File(f.clone()),
        }
    }
}

struct Cached {
    body: Body,
    len: u64,
    mtime: SystemTime,
    mtime_secs: u64,
    /// Device and inode: a file renamed over the cached one has another.
    id: (u64, u64),
    /// Used since the CLOCK hand last passed (open-file entries).
    used: AtomicBool,
    /// When the disk was last consulted, in [`clock_ms`] milliseconds.
    checked: AtomicU64,
    /// Change notifications cover the file, its twins and its directories: the entry is
    /// trusted until they drop it.
    watched: AtomicBool,
    /// Change notifications can follow this file (on Linux: a regular file with one link; on
    /// macOS: [`guard`](Cached::guard) was taken before the file was read).
    trackable: bool,
    /// The file's own watch (macOS), ended when the last holder drops it.
    guard: Option<Arc<FileWatch>>,
    etag: Box<str>,
    /// The content type (of the original file, for a compressed twin).
    mime: Arc<str>,
    /// The fields every answer about this file carries: `ETag`, `Last-Modified`,
    /// `Accept-Ranges`, `Cache-Control`, `Content-Encoding`, `Vary`; formatted once.
    meta: Headers,
    /// `Content-Type`, then `meta`.
    full: Headers,
    /// The compressed twins (see [`TWINS`]); `None` when there is no such file. Checked with
    /// the entry itself.
    twins: [Option<Arc<Cached>>; 3],
    /// The compressed copies ([`Files::compress`]), by index into [`TWINS`]; empty when the
    /// file gets none.
    packs: Box<[Pack]>,
}

/// A compressed copy of a file kept in memory ([`Files::compress`]).
#[derive(Default)]
struct Pack {
    /// Set once the copy's job ran: the copy, or `None` when it is not worth keeping.
    made: OnceLock<Option<Arc<Cached>>>,
    /// A job is making it (or was refused, and the flag cleared again).
    making: AtomicBool,
}

/// The smallest file [`Files::compress`] compresses: a smaller one goes in one packet with its
/// head either way.
const PACK_MIN_BYTES: u64 = 1400;

impl Cached {
    #[allow(clippy::too_many_arguments)]
    fn new(
        body: Body,
        len: u64,
        mtime: SystemTime,
        id: (u64, u64),
        mime: Arc<str>,
        encoding: Option<&str>,
        cache_control: Option<&str>,
        vary: bool,
        twins: [Option<Arc<Cached>>; 3],
        track: (bool, Option<Arc<FileWatch>>),
        packs: bool,
    ) -> Cached {
        let secs = unix_secs(mtime);
        let etag = match encoding {
            None => format!("\"{len:x}-{secs:x}\""),
            Some(e) => format!("\"{len:x}-{secs:x}-{e}\""),
        };
        let mut meta = Headers::with_capacity(6, 160);
        meta.append("ETag", &etag);
        meta.append("Last-Modified", format_http_date(secs));
        meta.append("Accept-Ranges", "bytes");
        if let Some(cc) = cache_control {
            meta.append("Cache-Control", cc);
        }
        if let Some(e) = encoding {
            meta.append("Content-Encoding", e);
        }
        if vary {
            meta.append("Vary", "Accept-Encoding");
        }
        let mut full = Headers::with_capacity(7, 192);
        full.append("Content-Type", &*mime);
        for (n, v) in meta.iter() {
            full.append(n, v);
        }
        Cached {
            body,
            len,
            mtime,
            mtime_secs: secs,
            id,
            used: AtomicBool::new(false),
            checked: AtomicU64::new(clock_ms()),
            watched: AtomicBool::new(false),
            trackable: track.0,
            guard: track.1,
            etag: etag.into(),
            mime,
            meta,
            full,
            twins,
            packs: if packs {
                std::iter::repeat_with(Pack::default)
                    .take(TWINS.len())
                    .collect()
            } else {
                Box::default()
            },
        }
    }

    /// The bytes this entry (with its compressed twins and copies) holds in memory.
    fn mem_bytes(&self) -> u64 {
        let own = |c: &Cached| match c.body {
            Body::Mem(_) => c.len,
            Body::File(_) => 0,
        };
        let twins: u64 = self.twins.iter().flatten().map(|t| own(t)).sum();
        let packs: u64 = self
            .packs
            .iter()
            .filter_map(|p| p.made.get().cloned().flatten())
            .map(|c| c.len)
            .sum();
        own(self) + twins + packs
    }

    /// Whether `md` still describes the file this entry was read from.
    fn matches(&self, md: &fs::Metadata) -> bool {
        self.len == md.len()
            && self.mtime == md.modified().unwrap_or(SystemTime::UNIX_EPOCH)
            && self.id == (md.dev(), md.ino())
    }
}

/// Milliseconds since the first call: the clock of cache freshness.
fn clock_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    u64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The pool every [`Files`] does its disk work on (and file bodies are encoded on, ADR-124).
pub(crate) fn disk_pool() -> &'static Arc<Pool> {
    static POOL: OnceLock<Arc<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let mut cfg = PoolConfig::default();
        cfg.max_threads = 16;
        cfg.queue_capacity = 4096;
        Pool::new(cfg)
    })
}

fn read_lock<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|p| p.into_inner())
}

fn write_lock<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|p| p.into_inner())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Files {
    /// Serves `root`.
    pub fn new(root: impl Into<PathBuf>) -> Files {
        Files {
            inner: Arc::new(Inner {
                root: root.into(),
                index: vec!["index.html".into()],
                redirect_dirs: false,
                mime_types: None,
                default_type: None,
                sniff: false,
                errors: None,
                max_cache_bytes: DEFAULT_MAX_CACHE_BYTES,
                disk_timeout: None,
                waiting: Arc::default(),
                max_cached: 256 << 10,
                check_interval: Duration::from_secs(5),
                cache_control: None,
                max_open: 64,
                shards: (0..SHARDS).map(|_| RwLock::default()).collect(),
                ring: Mutex::default(),
                watch_on: false,
                max_watches: 1024,
                watch: OnceLock::new(),
                twins: vec![0, 1, 2],
                tries: Vec::new(),
                hide: None,
                tried: RwLock::default(),
                compress: Vec::new(),
                list_max: 0,
            }),
        }
    }

    /// The settings, while the `Files` is being built (nothing else holds it yet).
    fn cfg(&mut self) -> &mut Inner {
        Arc::get_mut(&mut self.inner).expect("Files is configured before it serves")
    }

    /// The file served for a directory (default `index.html`); see
    /// [`index_files`](Files::index_files) for several.
    #[must_use]
    pub fn index(mut self, name: &str) -> Files {
        self.cfg().index = vec![name.to_owned()];
        self
    }

    /// The files that stand for a directory, tried in order: the first that is a regular file
    /// is served (ADR-124). None (`&[]`): a directory has no index file, and is listed (see
    /// [`list_directories`](Files::list_directories)) or answered `404`. Default
    /// `["index.html"]`.
    #[must_use]
    pub fn index_files(mut self, names: &[&str]) -> Files {
        self.cfg().index = names.iter().map(|n| (*n).to_owned()).collect();
        self
    }

    /// Redirects a directory asked for without its trailing slash (ADR-124): `301` with
    /// `Location` the request's path with the slash added (the prefix
    /// [`serve_prefixed`](Files::serve_prefixed) was given included) and its query kept, so
    /// that the index file's relative links resolve against the directory. Default off: the
    /// index file is served at either path. Not with [`try_paths`](Files::try_paths), whose
    /// candidates say whether they name a directory.
    #[must_use]
    pub fn redirect_directories(mut self, on: bool) -> Files {
        self.cfg().redirect_dirs = on;
        self
    }

    /// The content types by file extension (ADR-124), in place of [`Files`]' own short table
    /// (22 extensions): [`MimeTypes::builtin`], [`MimeTypes::system`] (with the system's
    /// `mime.types`), or a table of the caller's own.
    #[must_use]
    pub fn mime_types(mut self, table: Arc<MimeTypes>) -> Files {
        self.cfg().mime_types = Some(table);
        self
    }

    /// The `Content-Type` of a file whose extension gives none, as nginx's `default_type`
    /// (ADR-124); a compressed twin of such a file gets it too. `None` (the default): the type
    /// is [sniffed](Files::sniff) when that is on, else `application/octet-stream`.
    #[must_use]
    pub fn default_type(mut self, content_type: Option<&str>) -> Files {
        self.cfg().default_type = content_type.map(Arc::from);
        self
    }

    /// Without a [`default_type`](Files::default_type), works out the type of a file whose
    /// extension gives none from its first 512 bytes ([`sniff`]), as Go's
    /// `http.DetectContentType` does (ADR-124): read with the file, on the disk pool, and kept
    /// with its entry. A compressed twin of such a file is `application/octet-stream`. Default
    /// off: `application/octet-stream`.
    #[must_use]
    pub fn sniff(mut self, on: bool) -> Files {
        self.cfg().sniff = on;
        self
    }

    /// The answers `Files` makes itself (ADR-124), by status: `301` (a directory redirected,
    /// `Location` added to it), `403` (a file that may not be read), `404`, `405` (`Allow`
    /// added), `500` and `503` (`Retry-After` added). Default: `text/plain` with the reason
    /// phrase (`Not Found`). It runs on the I/O thread and on the disk pool; it must not block.
    #[must_use]
    pub fn error_response(
        mut self,
        f: impl Fn(u16) -> Response + Send + Sync + std::panic::RefUnwindSafe + 'static,
    ) -> Files {
        self.cfg().errors = Some(Arc::new(f));
        self
    }

    /// The most bytes of files kept in memory, compressed twins and copies
    /// ([`compress`](Files::compress)) included (ADR-124; default 64 MiB). Past it, the
    /// entries used least recently (CLOCK) are evicted; a file larger than the bound alone is
    /// read for its request and not kept. 0 keeps nothing in memory.
    #[must_use]
    pub fn max_cache_bytes(mut self, n: u64) -> Files {
        self.cfg().max_cache_bytes = n;
        self
    }

    /// How long a request waits on the disk pool (ADR-124): one not answered from it within
    /// `d`, queued behind others or held by a disk that hangs, is answered `503` with
    /// `Retry-After: 1`, and the pool's work, when it runs or ends later, answers nothing. The
    /// answer comes within an eighth of `d` after it. `None` (the default): no limit.
    #[must_use]
    pub fn disk_timeout(mut self, d: Option<Duration>) -> Files {
        self.cfg().disk_timeout = d.filter(|d| !d.is_zero());
        self
    }

    /// Largest file kept in memory (default 256 KiB; 0 disables the cache).
    #[must_use]
    pub fn max_cached_bytes(mut self, n: u64) -> Files {
        self.cfg().max_cached = n;
        self
    }

    /// How many files larger than [`max_cached_bytes`](Files::max_cached_bytes) keep an open
    /// handle and their metadata cached (default 64; 0 opens such files per request). Each
    /// holds a file descriptor (and one more per compressed twin) until it is evicted (least
    /// recently used first, CLOCK), its file changes or the `Files` is dropped; responses still
    /// being sent keep their own handle.
    #[must_use]
    pub fn max_open_files(mut self, n: usize) -> Files {
        self.cfg().max_open = n;
        self
    }

    /// How long a cached file is trusted before the disk is consulted again (default 5 s).
    #[must_use]
    pub fn check_interval(mut self, d: Duration) -> Files {
        self.cfg().check_interval = d;
        self
    }

    /// Follows changes on disk through notifications (inotify on Linux, kqueue `EVFILT_VNODE`
    /// on macOS; default off). A cached file whose file, compressed twins and directories (from
    /// the root down) are all watched is served without touching the disk until a change
    /// drops it: a write, an attribute change, a rename or deletion of the file, a twin or a
    /// directory, or a lost-event overflow (which drops everything). One thread per `Files`
    /// reads the notifications.
    ///
    /// The notifications cannot vouch for every entry, and those keep the
    /// [`check_interval`](Files::check_interval) rule: on Linux, files that are symlinks or
    /// have more than one hard link (a write through another link is not reported for this
    /// directory); entries read while a change was being reported; entries past
    /// [`max_watches`](Files::max_watches); everything when notifications cannot be set up.
    ///
    /// Do not turn it on for network or FUSE file systems (NFS, SMB, sshfs…): changes made by
    /// other machines produce no notification there, so cached entries would never be renewed.
    #[must_use]
    pub fn watch(mut self, on: bool) -> Files {
        self.cfg().watch_on = on;
        self
    }

    /// The most watches [`watch`](Files::watch) sets up (default 1024): one per directory, and
    /// on macOS also one per cached file and twin (each an `O_EVTONLY` file descriptor). Past
    /// it, new entries keep the [`check_interval`](Files::check_interval) rule. On Linux the
    /// watches also count against `fs.inotify.max_user_watches`.
    #[must_use]
    pub fn max_watches(mut self, n: usize) -> Files {
        self.cfg().max_watches = n;
        self
    }

    /// The compressed twins served, by coding name (`"br"`, `"zstd"`, `"gzip"`), in order of
    /// preference among codings the client accepts with equal q values (default all three, in
    /// that order). Other names, and a name given twice, are left out. None (`&[]`) looks up no
    /// twins and sends no `Vary: Accept-Encoding`.
    #[must_use]
    pub fn twins(mut self, encodings: &[&str]) -> Files {
        let mut order = Vec::new();
        for e in encodings {
            if let Some(i) = TWINS.iter().position(|(name, _)| name == e) {
                if !order.contains(&i) {
                    order.push(i);
                }
            }
        }
        self.cfg().twins = order;
        self
    }

    /// Codings a file cached in memory is also kept compressed with, by name (`"br"`, `"zstd"`,
    /// `"gzip"`), in order of preference among codings the client accepts with equal q values
    /// (ADR-112); other names, and a name given twice, are left out. None (`&[]`, the default)
    /// keeps no copies.
    ///
    /// A copy is made once, on the disk pool, at a level that makes it small (gzip 9, brotli 9,
    /// zstd 19, with windows no larger than the file), the first time a client that prefers
    /// that coding asks for the file; that request and those before the copy is ready get the
    /// file as it is. It is kept with the file's entry, until the file changes. A file of fewer
    /// than 1400 bytes, of a type that does not compress (see
    /// [`compressible`](crate::middleware::compressible)), or that compresses by less than a
    /// twentieth gets none; a ranged request is answered from the file, and a compressed twin
    /// on disk ([`twins`](Files::twins)) goes ahead of a copy. A copy has its own `ETag` (the
    /// file's with `-` and the coding added) and no `Accept-Ranges`; every answer about a file
    /// says `Vary: Accept-Encoding`.
    #[must_use]
    pub fn compress(mut self, encodings: &[&str]) -> Files {
        let mut order = Vec::new();
        for e in encodings {
            if let Some(i) = TWINS.iter().position(|(name, _)| name == e) {
                if !order.contains(&i) {
                    order.push(i);
                }
            }
        }
        self.cfg().compress = order;
        self
    }

    /// Candidate paths tried in turn for each request, as nginx's `try_files`: `{path}` stands
    /// for the path asked for (percent-decoded, with a leading `/`), and a candidate ending in
    /// `/` names a directory, served by its index file (or its listing, see
    /// [`list_directories`](Files::list_directories)). The first that exists is served; when
    /// none does the answer is `404`. A candidate that names a directory without the slash, a
    /// file with one, something other than a regular file or directory, or a path outside the
    /// root (`..`, a NUL, a backslash), or that [`hide`](Files::hide) hides, is passed over.
    /// `["{path}", "{path}/", "/index.html"]` serves a single-page application.
    ///
    /// What the candidates resolved a path to is kept (for up to 4096 paths) and trusted for
    /// [`check_interval`](Files::check_interval), so a request for a path resolved lately is
    /// answered on the I/O thread like any cached file; the rest are resolved on the disk pool.
    #[must_use]
    pub fn try_paths(mut self, candidates: &[&str]) -> Files {
        self.cfg().tries = candidates.iter().map(|c| (*c).to_owned()).collect();
        self
    }

    /// A test of the paths a request names (percent-decoded, with a leading `/`): a path for
    /// which it returns `true` is answered `404`, as a file that is not there, and a
    /// [`try_paths`](Files::try_paths) candidate for which it does is passed over. For
    /// instance, files whose names start with a dot. Runs on the I/O thread for the path asked
    /// for, and on the disk pool for candidates; it must not block.
    #[must_use]
    pub fn hide(
        mut self,
        f: impl Fn(&str) -> bool + Send + Sync + std::panic::RefUnwindSafe + 'static,
    ) -> Files {
        self.cfg().hide = Some(Arc::new(f));
        self
    }

    /// Lists a directory that has no index file, asked for with its trailing slash, rather than
    /// answering `404` (default off: 0). At most `max_entries` entries are read, in the order
    /// the directory gives them, and a listing of a directory with more says so. Names starting
    /// with a dot are left out. The page (`text/html; charset=utf-8`, `Cache-Control:
    /// no-cache`) shows directories first, then files, each group by name, with sizes and
    /// modification times (UTC); links are relative. Listings are read on the disk pool for
    /// every request and are not cached.
    #[must_use]
    pub fn list_directories(mut self, max_entries: usize) -> Files {
        self.cfg().list_max = max_entries;
        self
    }

    /// A `Cache-Control` header for every file response.
    #[must_use]
    pub fn cache_control(mut self, v: &str) -> Files {
        self.cfg().cache_control = Some(v.to_owned());
        self
    }

    /// The path below the root `decoded` (a percent-decoded request path) names, or `None` if
    /// it is unsafe.
    fn relative(decoded: &str) -> Option<PathBuf> {
        let mut rel = PathBuf::new();
        for seg in decoded.split('/').filter(|s| !s.is_empty() && *s != ".") {
            if seg == ".." || seg.contains(['\\', '\0']) {
                return None;
            }
            rel.push(seg);
        }
        Some(rel)
    }

    #[cfg(test)]
    fn mime(path: &Path) -> &'static str {
        Files::short_mime(path).unwrap_or("application/octet-stream")
    }

    /// [`Files`]' own table.
    fn short_mime(path: &Path) -> Option<&'static str> {
        Some(
            match path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref()
            {
                Some("html" | "htm") => "text/html; charset=utf-8",
                Some("css") => "text/css; charset=utf-8",
                Some("js" | "mjs") => "text/javascript; charset=utf-8",
                Some("json") => "application/json",
                Some("txt") => "text/plain; charset=utf-8",
                Some("xml") => "application/xml",
                Some("svg") => "image/svg+xml",
                Some("png") => "image/png",
                Some("jpg" | "jpeg") => "image/jpeg",
                Some("gif") => "image/gif",
                Some("webp") => "image/webp",
                Some("ico") => "image/x-icon",
                Some("woff") => "font/woff",
                Some("woff2") => "font/woff2",
                Some("wasm") => "application/wasm",
                Some("pdf") => "application/pdf",
                Some("mp4") => "video/mp4",
                Some("webm") => "video/webm",
                Some("mp3") => "audio/mpeg",
                _ => return None,
            },
        )
    }
}

impl Inner {
    fn shard(&self, path: &Path) -> &RwLock<HashMap<PathBuf, Entry>> {
        // FNV-1a: cheap, and only spreads paths over the shards (each map hashes again).
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for b in path.as_os_str().as_encoded_bytes() {
            h = (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3);
        }
        &self.shards[(h as usize) % self.shards.len()]
    }

    fn is_fresh(&self, checked: &AtomicU64, watched: &AtomicBool) -> bool {
        if watched.load(Ordering::Relaxed) {
            return true;
        }
        let age = clock_ms().saturating_sub(checked.load(Ordering::Relaxed));
        u128::from(age) < self.check_interval.as_millis()
    }

    /// A cached entry still inside its trust window, without touching the disk (a directory
    /// is followed to its index file).
    /// `dir`: the path was asked for as a directory (with its trailing slash), so a file is not
    /// served for it; and, with [`Files::redirect_directories`], a directory asked for without
    /// it goes to the disk pool, which redirects it.
    fn fresh(&self, path: &Path, dir: bool) -> Option<Arc<Cached>> {
        let index = {
            let g = read_lock(self.shard(path));
            match g.get(path)? {
                Entry::File(c) => {
                    return (!dir && self.is_fresh(&c.checked, &c.watched)).then(|| {
                        c.used.store(true, Ordering::Relaxed);
                        c.clone()
                    });
                }
                Entry::Dir(d) => {
                    if !self.is_fresh(&d.checked, &d.watched) || (!dir && self.redirect_dirs) {
                        return None;
                    }
                    d.index.clone()
                }
            }
        };
        let g = read_lock(self.shard(&index));
        match g.get(&*index)? {
            Entry::File(c) if self.is_fresh(&c.checked, &c.watched) => {
                c.used.store(true, Ordering::Relaxed);
                Some(c.clone())
            }
            _ => None,
        }
    }

    /// Drops the entry of a path that is gone, freeing its open-file slot.
    fn forget(&self, path: &Path) {
        let mut ring = lock(&self.ring);
        ring.remove(path);
        write_lock(self.shard(path)).remove(path);
    }

    /// Drops every entry whose path satisfies `pred`.
    fn forget_where(&self, pred: impl Fn(&Path) -> bool) {
        let mut ring = lock(&self.ring);
        ring.retain(&pred);
        for s in &self.shards {
            write_lock(s).retain(|p, _| !pred(p));
        }
    }

    /// Answers a request from the disk (on the disk pool): `stat`, directory index, (re)loading
    /// the cache entry and its compressed twins. `list_as` is the path a directory without an
    /// index file is listed as, when it may be (see [`Files::list_directories`]).
    fn serve_disk(self: &Arc<Self>, req: &Request, mut path: PathBuf, at: &At) -> Response {
        // Watches go up before the disk is consulted, so a change after it is reported.
        let ticket = self.watch_begin(&path);
        let mut md = match fs::metadata(&path) {
            Ok(md) => md,
            Err(e) => {
                self.forget(&path);
                return self.error(status_of(&e));
            }
        };
        let mut dirs_ok = ticket.as_ref().is_some_and(|t| t.dirs);
        if md.is_dir() {
            if !at.dir && self.redirect_dirs {
                return self.redirect(req, at);
            }
            let dir = path.clone();
            dirs_ok = dirs_ok && ticket.as_ref().is_some_and(|t| t.w.ensure_dir(&dir));
            let found = self.index.iter().find_map(|name| {
                let p = dir.join(name);
                fs::metadata(&p)
                    .ok()
                    .filter(fs::Metadata::is_file)
                    .map(|m| (p, m))
            });
            match found {
                Some((p, m)) => (path, md) = (p, m),
                None => {
                    return match &at.title {
                        Some(title) if self.list_max > 0 => {
                            list_dir(&dir, title, self.list_max, |s| self.error(s))
                        }
                        _ => self.error(404),
                    };
                }
            }
            let entry = Arc::new(DirEntry {
                index: Arc::from(path.as_path()),
                checked: AtomicU64::new(clock_ms()),
                watched: AtomicBool::new(false),
            });
            write_lock(self.shard(&dir)).insert(dir, Entry::Dir(entry.clone()));
            if let Some(t) = &ticket {
                t.finish(&entry.watched, dirs_ok);
            }
        } else if at.dir || !md.is_file() {
            // A file asked for as a directory, or a device, a pipe or a socket: never opened.
            return self.error(404);
        }
        let track = ticket.as_ref().filter(|_| dirs_ok);
        let c = match self.load_tracked(&path, &md, track) {
            Ok(c) => c,
            Err(status) => return self.error(status),
        };
        let served = self.variant(req, &c);
        self.build(req, served, true)
            .unwrap_or_else(|| self.error(500))
    }

    /// The `301` to the directory `at` names, with its slash (see
    /// [`Files::redirect_directories`]).
    fn redirect(&self, req: &Request, at: &At) -> Response {
        let mut target = String::with_capacity(at.location.len() + 2);
        target.push_str(&at.location);
        target.push('/');
        if let Some(q) = req.query() {
            target.push('?');
            target.push_str(q);
        }
        if target.starts_with("//") {
            // A path that would read as a host.
            target = format!("/{}", target.trim_start_matches('/'));
        }
        let mut r = self.error(301);
        r.headers.set("Location", &target);
        r
    }

    /// [`Files::error_response`]'s answer for `status`, or the reason phrase.
    fn error(&self, status: u16) -> Response {
        let mut r = match &self.errors {
            Some(f) => f(status),
            None => Response::text(
                status,
                match status {
                    301 => "Moved Permanently",
                    403 => "Forbidden",
                    404 => "Not Found",
                    405 => "Method Not Allowed",
                    503 => "Service Unavailable",
                    _ => "Internal Server Error",
                },
            ),
        };
        r.status = status;
        match status {
            405 => r.headers.set("Allow", "GET, HEAD"),
            503 => r.headers.set("Retry-After", "1"),
            _ => {}
        }
        r
    }

    /// What [`Files::try_paths`]' candidates resolved `asked` to lately, when that file's entry
    /// is still inside its trust window too.
    fn tried_fresh(&self, asked: &str) -> Option<Arc<Cached>> {
        let file = {
            let g = read_lock(&self.tried);
            let t = g.get(asked)?;
            let age = clock_ms().saturating_sub(t.checked);
            if u128::from(age) >= self.check_interval.as_millis() {
                return None;
            }
            t.file.clone()
        };
        self.fresh(&file, false)
    }

    /// Answers a request with [`Files::try_paths`]' candidates, from the disk (on the disk
    /// pool): the first that names a file, or a directory (with its slash) with an index file
    /// or a listing, is served; 404 when none does.
    fn serve_tries(self: &Arc<Self>, req: &Request, asked: &str) -> Response {
        for t in &self.tries {
            let cand = t.replace("{path}", asked);
            let Some(rel) = Files::relative(&cand) else {
                continue;
            };
            if self.hide.as_ref().is_some_and(|h| h(&cand)) {
                continue;
            }
            let dir = cand.ends_with('/') || rel.as_os_str().is_empty();
            let full = self.root.join(&rel);
            let Ok(md) = fs::metadata(&full) else {
                continue;
            };
            let (file, md) = if md.is_dir() {
                if !dir {
                    continue;
                }
                let found = self.index.iter().find_map(|name| {
                    let p = full.join(name);
                    fs::metadata(&p)
                        .ok()
                        .filter(fs::Metadata::is_file)
                        .map(|m| (p, m))
                });
                match found {
                    Some(f) => f,
                    None if self.list_max > 0 => {
                        // The listing's links are relative to the candidate, cleaned.
                        let mut title = String::from("/");
                        for seg in &rel {
                            title.push_str(&seg.to_string_lossy());
                            title.push('/');
                        }
                        return list_dir(&full, &title, self.list_max, |s| self.error(s));
                    }
                    None => continue,
                }
            } else if dir || !md.is_file() {
                continue;
            } else {
                (full, md)
            };
            let Ok(c) = self.load_tracked(&file, &md, None) else {
                continue;
            };
            {
                let mut g = write_lock(&self.tried);
                if g.len() >= MAX_TRIED && !g.contains_key(asked) {
                    g.clear();
                }
                g.insert(
                    asked.to_owned(),
                    Tried {
                        file,
                        checked: clock_ms(),
                    },
                );
            }
            let served = self.variant(req, &c);
            return self
                .build(req, served, true)
                .unwrap_or_else(|| self.error(500));
        }
        self.error(404)
    }

    /// Whether answers about a file say `Vary: Accept-Encoding`: when twins or copies may
    /// answer in its place.
    fn vary(&self) -> bool {
        !self.twins.is_empty() || !self.compress.is_empty()
    }

    /// Whether a file (not a twin: `encoding` is `None`) whose content is `body` gets
    /// compressed copies: kept in memory, large enough and of a type that compresses.
    fn packable(&self, body: &Body, len: u64, mime: &str, encoding: Option<&str>) -> bool {
        !self.compress.is_empty()
            && encoding.is_none()
            && matches!(body, Body::Mem(_))
            && len >= PACK_MIN_BYTES
            && crate::middleware::compressible(mime)
    }

    /// The type of a file by its extension: from [`Files::mime_types`]'s table, or [`Files`]'
    /// own.
    fn ext_type(&self, path: &Path) -> Option<Arc<str>> {
        match &self.mime_types {
            Some(t) => t.for_path(path),
            None => Files::short_mime(path).map(Arc::from),
        }
    }

    /// The type of the file at `path` when its extension gives none: the
    /// [`default_type`](Files::default_type), else what [`sniff`] makes of `head` (its first
    /// bytes, when sniffing is on and they are at hand), else `application/octet-stream`.
    fn fallback_type(&self, head: Option<&[u8]>) -> Arc<str> {
        if let Some(t) = &self.default_type {
            return t.clone();
        }
        match head.filter(|_| self.sniff) {
            Some(h) => Arc::from(sniff(h)),
            None => Arc::from("application/octet-stream"),
        }
    }

    /// The variant of `c` to send `req`: a compressed twin on disk ([`pick`]), else the
    /// compressed copy the client prefers once it is made, else `c`. Asking for a copy not
    /// made yet starts its job on the disk pool.
    fn variant<'a>(self: &Arc<Self>, req: &Request, c: &'a Arc<Cached>) -> &'a Arc<Cached> {
        let served = pick(c, &req.headers, &self.twins);
        if c.packs.is_empty() || !Arc::ptr_eq(served, c) || req.headers.get("range").is_some() {
            return served;
        }
        let mut best: Option<(usize, f64)> = None;
        for &i in &self.compress {
            let (Some(p), Some((enc, _))) = (c.packs.get(i), TWINS.get(i)) else {
                continue;
            };
            if matches!(p.made.get(), Some(None)) {
                continue; // not worth it
            }
            let q = accept_q(&req.headers, enc);
            if q > 0.0 && best.is_none_or(|(_, b)| q > b) {
                best = Some((i, q));
            }
        }
        let Some((i, _)) = best else { return c };
        let Some(p) = c.packs.get(i) else { return c };
        match p.made.get() {
            Some(Some(copy)) => copy,
            Some(None) => c,
            None => {
                self.make_pack(c, i);
                c
            }
        }
    }

    /// Starts the job that makes `c`'s copy in the `i`-th coding of [`TWINS`], unless one is
    /// under way. A job the pool refuses leaves the copy to a later request.
    fn make_pack(self: &Arc<Self>, c: &Arc<Cached>, i: usize) {
        let Some(p) = c.packs.get(i) else { return };
        if p.making.swap(true, Ordering::AcqRel) {
            return;
        }
        let (inner, file) = (self.clone(), c.clone());
        let job = Box::new(move || {
            let copy = inner.pack(&file, i);
            let bytes = copy.as_ref().map_or(0, |c| c.len);
            if let Some(p) = file.packs.get(i) {
                if p.made.set(copy).is_ok() && bytes > 0 {
                    inner.charge(&file, bytes);
                }
            }
        });
        if disk_pool().try_execute(job).is_err() {
            p.making.store(false, Ordering::Release);
        }
    }

    /// `c`'s copy compressed with the `i`-th coding of [`TWINS`], or `None` when it compresses
    /// by less than a twentieth. Runs on the disk pool.
    fn pack(&self, c: &Cached, i: usize) -> Option<Arc<Cached>> {
        let (Body::Mem(data), Some(&(enc, _))) = (&c.body, TWINS.get(i)) else {
            return None;
        };
        // Windows no larger than the file bound the encoders' memory by it.
        let bits = usize::BITS - (data.len().max(2) - 1).leading_zeros();
        let mut out = Vec::new();
        match enc {
            "gzip" => {
                out = akio_deflate::compress(
                    akio_deflate::Format::Gzip,
                    akio_deflate::Level::new(9),
                    data,
                );
            }
            "br" => akio_brotli::Compressor::new(akio_brotli::Level::new(9))
                .window_bits(bits.clamp(10, 24))
                .compress(data, &mut out, akio_brotli::Flush::Finish),
            _ => akio_zstd::Compressor::new(akio_zstd::Level::new(19))
                .window_log(bits.clamp(10, 23))
                .compress(data, &mut out, akio_zstd::Flush::Finish),
        }
        if out.is_empty() || out.len() > data.len() - data.len() / 20 {
            return None;
        }
        let len = out.len() as u64;
        let mut copy = Cached::new(
            Body::Mem(out.into()),
            len,
            c.mtime,
            c.id,
            c.mime.clone(),
            Some(enc),
            self.cache_control.as_deref(),
            true,
            [None, None, None],
            (false, None),
            false,
        );
        // Another representation of the file: its tag with the coding added, and no ranges,
        // which are answered from the file as it is.
        let tag = format!("{}-{enc}\"", c.etag.trim_end_matches('"'));
        for h in [&mut copy.meta, &mut copy.full] {
            h.set("ETag", &tag);
            h.remove("Accept-Ranges");
        }
        copy.etag = tag.into();
        Some(Arc::new(copy))
    }

    /// A copy of `c`'s (made after `c` was cached) adds `bytes` to what `c` is charged, and
    /// evicts entries used least recently while the cache holds more than its bound.
    fn charge(&self, c: &Arc<Cached>, bytes: u64) {
        let mut ring = lock(&self.ring);
        let Some(i) = ring
            .mem
            .slots
            .iter()
            .position(|(_, e, _)| Arc::ptr_eq(e, c))
        else {
            return; // not cached (any more): the copy goes with the entry
        };
        ring.mem.slots[i].2 += bytes;
        ring.bytes += bytes;
        self.evict_mem(&mut ring, 0);
    }

    /// Evicts the in-memory entries used least recently until the cache holds no more than its
    /// bound with `room` bytes more.
    fn evict_mem(&self, ring: &mut Rings, room: u64) {
        while ring.bytes.saturating_add(room) > self.max_cache_bytes && !ring.mem.slots.is_empty() {
            let v = ring.mem.victim();
            let gone = ring.mem.slots[v].0.clone();
            ring.mem.hand = v + 1;
            ring.remove(&gone);
            write_lock(self.shard(&gone)).remove(&gone);
        }
    }

    /// [`load_tracked`](Inner::load_tracked) without change notifications.
    #[cfg(test)]
    fn load(&self, path: &Path, md: &fs::Metadata) -> Option<Arc<Cached>> {
        self.load_tracked(path, md, None).ok()
    }

    /// The entry of `path` (whose metadata is `md`), reusing what is cached when the file did
    /// not change, and caching it when it is small enough or open handles are cached at all.
    /// With `track` (watches cover every directory on the path), the entry is marked watched
    /// when notifications can vouch for it. Runs on the disk pool.
    fn load_tracked(
        &self,
        path: &Path,
        md: &fs::Metadata,
        track: Option<&Ticket>,
    ) -> Result<Arc<Cached>, u16> {
        let old = match read_lock(self.shard(path)).get(path) {
            Some(Entry::File(c)) => Some(c.clone()),
            _ => None,
        };
        let watch = track.map(|t| &t.w);
        let ext_type = self.ext_type(path);
        // A twin has its original's type, by name; without one, the default or none sniffed.
        let twin_type = ext_type
            .clone()
            .or_else(|| self.default_type.clone())
            .unwrap_or_else(|| Arc::from("application/octet-stream"));
        let twins: [Option<Arc<Cached>>; 3] = std::array::from_fn(|i| {
            if !self.twins.contains(&i) {
                return None;
            }
            let (enc, ext) = TWINS[i];
            let mut p = path.as_os_str().to_owned();
            p.push(".");
            p.push(ext);
            let p = PathBuf::from(p);
            let m = fs::metadata(&p).ok().filter(fs::Metadata::is_file)?;
            match old.as_ref().and_then(|o| o.twins[i].clone()) {
                Some(t) if t.matches(&m) => Some(t),
                _ => self
                    .read(
                        &p,
                        &m,
                        Some(twin_type.clone()),
                        Some(enc),
                        [None, None, None],
                        watch,
                    )
                    .ok(),
            }
        });
        let c = match old {
            Some(o) if o.matches(md) => {
                let same = o.twins.iter().zip(&twins).all(|(a, b)| match (a, b) {
                    (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                    (None, None) => true,
                    _ => false,
                });
                if same {
                    o.checked.store(clock_ms(), Ordering::Relaxed);
                    for t in o.twins.iter().flatten() {
                        t.checked.store(clock_ms(), Ordering::Relaxed);
                    }
                    if let Some(t) = track {
                        t.finish(&o.watched, o.vouched());
                    }
                    return Ok(o);
                }
                // Same file, other twins: keep its content.
                let packs = self.packable(&o.body, o.len, &o.mime, None);
                Arc::new(Cached::new(
                    o.body.clone(),
                    o.len,
                    o.mtime,
                    o.id,
                    o.mime.clone(),
                    None,
                    self.cache_control.as_deref(),
                    self.vary(),
                    twins,
                    (o.trackable, o.guard.clone()),
                    packs,
                ))
            }
            _ => self.read(path, md, ext_type, None, twins, watch)?,
        };
        let open = matches!(c.body, Body::File(_));
        let bytes = c.mem_bytes();
        if (open && self.max_open == 0) || bytes > self.max_cache_bytes {
            // Not cached: opened, or read, for this request only.
            self.forget(path);
            return Ok(c);
        }
        let mut ring = lock(&self.ring);
        ring.remove(path);
        if open {
            if ring.open.slots.len() >= self.max_open {
                // Every slot is taken: the new file replaces the CLOCK victim.
                let v = ring.open.victim();
                let gone = ring.open.slots[v].0.clone();
                ring.open.hand = v + 1;
                ring.remove(&gone);
                write_lock(self.shard(&gone)).remove(&gone);
            }
            ring.open.slots.push((path.to_owned(), c.clone(), 0));
        }
        if bytes > 0 {
            self.evict_mem(&mut ring, bytes);
            ring.bytes += bytes;
            ring.mem.slots.push((path.to_owned(), c.clone(), bytes));
        }
        write_lock(self.shard(path)).insert(path.to_owned(), Entry::File(c.clone()));
        drop(ring);
        if let Some(t) = track {
            t.finish(&c.watched, c.vouched());
        }
        Ok(c)
    }

    /// Reads (small) or opens (large) the file at `path`, described by `md`. With `watch`,
    /// works out whether notifications can follow the file (taking its own watch first, on
    /// macOS).
    /// `mime` is the type the file's name gives (its original's, for a twin); without one the
    /// type is worked out here ([`fallback_type`](Inner::fallback_type)). Errors are the status
    /// to answer: 403 for a file that may not be read, else 404.
    fn read(
        &self,
        path: &Path,
        md: &fs::Metadata,
        mime: Option<Arc<str>>,
        encoding: Option<&str>,
        twins: [Option<Arc<Cached>>; 3],
        watch: Option<&Arc<Watch>>,
    ) -> Result<Arc<Cached>, u16> {
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let id = (md.dev(), md.ino());
        let track = watch.map_or((false, None), |w| Watch::track(w, path, md));
        let (body, len) = if md.len() > self.max_cached {
            let f = fs::File::open(path).map_err(|e| status_of(&e))?;
            // The metadata of the handle itself: the path may have been replaced since `md`.
            let fmd = f.metadata().map_err(|e| status_of(&e))?;
            if fmd.len() != md.len()
                || fmd.modified().ok() != Some(mtime)
                || (fmd.dev(), fmd.ino()) != id
                || !fmd.is_file()
            {
                return Err(404);
            }
            (Body::File(Arc::new(f)), md.len())
        } else {
            let data = fs::read(path).map_err(|e| status_of(&e))?;
            let n = data.len() as u64;
            (Body::Mem(data.into()), n)
        };
        let mime = match mime {
            Some(m) => m,
            None if self.default_type.is_none() && self.sniff => match &body {
                Body::Mem(b) => self.fallback_type(Some(b)),
                Body::File(f) => {
                    let mut head = [0u8; SNIFF_LEN];
                    let n = read_head(f, &mut head);
                    self.fallback_type(head.get(..n))
                }
            },
            None => self.fallback_type(None),
        };
        let packs = self.packable(&body, len, &mime, encoding);
        Ok(Arc::new(Cached::new(
            body,
            len,
            mtime,
            id,
            mime,
            encoding,
            self.cache_control.as_deref(),
            self.vary(),
            twins,
            track,
            packs,
        )))
    }

    /// The change notifications, started on first use (`None` when off, or when they could not
    /// be set up or broke).
    fn watcher(self: &Arc<Self>) -> Option<Arc<Watch>> {
        if !self.watch_on {
            return None;
        }
        let w = self.watch.get_or_init(|| {
            let w = Arc::new(Watch {
                sys: FsWatcher::new().ok()?,
                max: self.max_watches,
                epoch: AtomicU64::new(0),
                broken: AtomicBool::new(false),
                state: Mutex::default(),
            });
            let (inner, w2) = (Arc::downgrade(self), w.clone());
            std::thread::Builder::new()
                .name("akio-files-watch".into())
                .spawn(move || Watch::run(&inner, &w2))
                .ok()?;
            Some(w)
        });
        w.clone().filter(|w| !w.broken.load(Ordering::Relaxed))
    }

    /// Before `path` is looked up on disk: the notification epoch, and watches on every
    /// directory from the root down to the one holding `path`.
    fn watch_begin(self: &Arc<Self>, path: &Path) -> Option<Ticket> {
        let w = self.watcher()?;
        let epoch = w.epoch.load(Ordering::SeqCst);
        let mut chain: Vec<&Path> = path
            .parent()
            .map(|p| {
                p.ancestors()
                    .take_while(|a| a.starts_with(&self.root))
                    .collect()
            })
            .unwrap_or_default();
        chain.reverse();
        let dirs = chain.into_iter().all(|d| w.ensure_dir(d));
        Some(Ticket { w, epoch, dirs })
    }

    /// Applies a batch of change notifications: drops the entries they concern.
    fn apply(&self, w: &Watch, evs: &[FsEvent]) {
        // Bumped before anything is dropped: a load that began before this batch was read
        // cannot mark its entry watched (see `Ticket::finish`).
        w.epoch.fetch_add(1, Ordering::SeqCst);
        let mut files = Vec::new();
        let mut trees = Vec::new();
        let mut children = Vec::new();
        let mut unwatch = Vec::new();
        let mut all = false;
        {
            let mut st = lock(&w.state);
            for ev in evs {
                match ev {
                    FsEvent::Overflow => all = true,
                    FsEvent::Gone { id } => {
                        unwatch.push(*id);
                        for p in st.paths.remove(id).unwrap_or_default() {
                            if st.dirs.get(&p).is_some_and(|d| d.0 == *id) {
                                st.end_tree(&p, &mut unwatch);
                                trees.push(p);
                            } else {
                                files.push(p);
                            }
                        }
                    }
                    FsEvent::Changed { id, name, is_dir } => {
                        let Some(paths) = st.paths.get(id).cloned() else {
                            continue;
                        };
                        for p in paths {
                            if !st.dirs.get(&p).is_some_and(|d| d.0 == *id) {
                                files.push(p); // a file's own watch (macOS)
                            } else if let Some(n) = name {
                                let c = p.join(n);
                                if *is_dir || st.dirs.contains_key(&c) {
                                    // A directory (or a symlink to one) moved, removed or
                                    // replaced: everything below, watches included.
                                    st.end_tree(&c, &mut unwatch);
                                    trees.push(c);
                                } else {
                                    files.push(c);
                                }
                            } else {
                                // macOS: entries of `p` were added, removed or renamed. A
                                // subdirectory replaced through a symlink reports nothing
                                // itself: compare the watched ones with the disk.
                                let moved: Vec<PathBuf> = st
                                    .dirs
                                    .iter()
                                    .filter(|(d, (_, ino))| {
                                        d.parent() == Some(p.as_path())
                                            && fs::metadata(d)
                                                .map_or(true, |m| (m.dev(), m.ino()) != *ino)
                                    })
                                    .map(|(d, _)| d.clone())
                                    .collect();
                                for d in moved {
                                    st.end_tree(&d, &mut unwatch);
                                    trees.push(d);
                                }
                                children.push(p);
                            }
                        }
                    }
                }
            }
        }
        // Outside the watch state lock: dropping an entry may end its file watch, which takes it.
        for id in unwatch {
            w.sys.unwatch(id);
        }
        if all {
            self.forget_where(|_| true);
            return;
        }
        for t in &trees {
            self.forget_where(|p| p.starts_with(t));
        }
        if !children.is_empty() {
            self.forget_where(|p| p.parent().is_some_and(|d| children.iter().any(|c| c == d)));
        }
        for f in &files {
            self.forget(f);
            // A compressed twin is cached with its original.
            let ext = f.extension().and_then(|e| e.to_str());
            if TWINS.iter().any(|(_, x)| Some(*x) == ext) {
                self.forget(&f.with_extension(""));
            }
        }
    }
}

/// Change notifications for one [`Files`]: the watches and the thread reading them.
struct Watch {
    sys: FsWatcher,
    max: usize,
    /// Incremented before each batch of notifications is applied.
    epoch: AtomicU64,
    /// Reading notifications failed: the cache went back to the interval rule.
    broken: AtomicBool,
    state: Mutex<WatchState>,
}

#[derive(Default)]
struct WatchState {
    /// The watched directories: watch, and device and inode when the watch was made.
    dirs: HashMap<PathBuf, (WatchId, (u64, u64))>,
    /// The paths each watch is for (directories; files on macOS). On Linux a directory
    /// reached by two paths has one watch.
    paths: HashMap<WatchId, Vec<PathBuf>>,
    /// The file watches alive (macOS).
    files: usize,
}

impl WatchState {
    /// Forgets the watches of `top` and every directory below it (their paths no longer lead
    /// to what they watch), adding the ids to end to `unwatch`.
    fn end_tree(&mut self, top: &Path, unwatch: &mut Vec<WatchId>) {
        let below: Vec<(PathBuf, WatchId)> = self
            .dirs
            .iter()
            .filter(|(d, _)| d.starts_with(top))
            .map(|(d, (id, _))| (d.clone(), *id))
            .collect();
        for (d, id) in below {
            self.dirs.remove(&d);
            if let Some(ps) = self.paths.get_mut(&id) {
                ps.retain(|p| *p != d);
                if ps.is_empty() {
                    self.paths.remove(&id);
                    unwatch.push(id);
                }
            }
        }
    }
}

impl Watch {
    /// The watcher thread: reads notifications until the [`Files`] is dropped.
    fn run(inner: &Weak<Inner>, w: &Arc<Watch>) {
        let mut evs = Vec::new();
        loop {
            evs.clear();
            let r = w.sys.wait(None, &mut evs);
            let Some(inner) = inner.upgrade() else {
                return;
            };
            if r.is_err() {
                // Nothing can be vouched for any more: back to re-checking everything.
                w.broken.store(true, Ordering::Relaxed);
                w.epoch.fetch_add(1, Ordering::SeqCst);
                inner.forget_where(|_| true);
                return;
            }
            if !evs.is_empty() {
                inner.apply(w, &evs);
            }
        }
    }

    /// Whether `dir` is watched, watching it if there is room.
    fn ensure_dir(&self, dir: &Path) -> bool {
        let mut st = lock(&self.state);
        if st.dirs.contains_key(dir) {
            return true;
        }
        if st.dirs.len() + st.files >= self.max {
            return false;
        }
        let Ok(id) = self.sys.watch_dir(dir) else {
            return false;
        };
        // The directory the watch follows (after it was made: a later replacement is reported).
        let Ok(m) = fs::metadata(dir) else {
            drop(st);
            self.sys.unwatch(id);
            return false;
        };
        st.dirs.insert(dir.to_owned(), (id, (m.dev(), m.ino())));
        st.paths.entry(id).or_default().push(dir.to_owned());
        true
    }

    /// Whether notifications can follow the file at `path` (described by `md`), and its own
    /// watch on macOS, taken before the file is read.
    fn track(w: &Arc<Watch>, path: &Path, md: &fs::Metadata) -> (bool, Option<Arc<FileWatch>>) {
        if FsWatcher::DIR_EVENTS_NAME_ENTRIES {
            // Linux: the directory's watch reports writes made through this path only, and
            // changes to a symlink, not to its target.
            let plain = fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file());
            return (plain && md.nlink() == 1, None);
        }
        let guard = {
            let mut st = lock(&w.state);
            if st.dirs.len() + st.files >= w.max {
                return (false, None);
            }
            let Ok(id) = w.sys.watch_file(path) else {
                return (false, None);
            };
            st.files += 1;
            st.paths.insert(id, vec![path.to_owned()]);
            Arc::new(FileWatch { w: w.clone(), id })
        };
        // The watch follows the file `md` describes only if the path was not replaced since.
        let same = fs::metadata(path).is_ok_and(|m| {
            m.len() == md.len()
                && m.modified().ok() == md.modified().ok()
                && (m.dev(), m.ino()) == (md.dev(), md.ino())
        });
        if same {
            (true, Some(guard))
        } else {
            (false, None)
        }
    }
}

/// A file's own watch (macOS): ended when the last cache entry holding it is dropped.
struct FileWatch {
    w: Arc<Watch>,
    id: WatchId,
}

impl Drop for FileWatch {
    fn drop(&mut self) {
        {
            let mut st = lock(&self.w.state);
            st.files -= 1;
            st.paths.remove(&self.id);
        }
        self.w.sys.unwatch(self.id);
    }
}

/// Taken before a request consults the disk: the notification epoch then, and whether every
/// directory on the path is watched.
struct Ticket {
    w: Arc<Watch>,
    epoch: u64,
    dirs: bool,
}

impl Ticket {
    /// After the entry holding `watched` is in the cache: marks it watched when `ok` and no
    /// notification was applied since the ticket was taken (one may concern what was read, and
    /// was applied before the entry was in place to be dropped).
    fn finish(&self, watched: &AtomicBool, ok: bool) {
        let ok = ok && self.w.epoch.load(Ordering::SeqCst) == self.epoch;
        watched.store(ok, Ordering::Relaxed);
    }
}

impl Cached {
    /// Notifications can follow the file and every compressed twin.
    fn vouched(&self) -> bool {
        self.trackable && self.twins.iter().flatten().all(|t| t.trackable)
    }
}

/// The variant of `c` to send for the request's `Accept-Encoding` fields: the compressed twin
/// on disk the client ranks highest by q value, among equals the first in `order` (indexes into
/// [`TWINS`]); else `c` itself.
fn pick<'a>(c: &'a Arc<Cached>, headers: &Headers, order: &[usize]) -> &'a Arc<Cached> {
    if c.twins.iter().all(Option::is_none) {
        return c;
    }
    let mut best: Option<(&'a Arc<Cached>, f64)> = None;
    for &i in order {
        let (Some(Some(t)), Some((enc, _))) = (c.twins.get(i), TWINS.get(i)) else {
            continue;
        };
        let q = accept_q(headers, enc);
        if q > 0.0 && best.is_none_or(|(_, b)| q > b) {
            best = Some((t, q));
        }
    }
    best.map_or(c, |(t, _)| t)
}

/// The q value the `Accept-Encoding` fields give `coding` (RFC 9110 section 12.5.3): its own,
/// else that of `*`, else 0 (not accepted). Names compare case-insensitively; a q value that
/// does not parse, or lies outside 0 to 1, counts as 1.
fn accept_q(headers: &Headers, coding: &str) -> f64 {
    let (mut own, mut any) = (None, None);
    for field in headers.get_all("accept-encoding") {
        for member in field.split(',') {
            let mut parts = member.split(';');
            let name = parts.next().unwrap_or("").trim();
            let mut q = 1.0;
            for param in parts {
                if let Some((k, v)) = param.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("q") {
                        if let Ok(v) = v.trim().parse::<f64>() {
                            if (0.0..=1.0).contains(&v) {
                                q = v;
                            }
                        }
                    }
                }
            }
            if name.eq_ignore_ascii_case(coding) {
                own = Some(q);
            } else if name == "*" {
                any = Some(q);
            }
        }
    }
    own.or(any).unwrap_or(0.0)
}

/// A listing of the directory `dir`, asked for as `title` (a decoded request path ending in
/// `/`): at most `max` entries read, names starting with a dot left out, directories first,
/// each group by name. Runs on the disk pool.
fn list_dir(dir: &Path, title: &str, max: usize, error: impl Fn(u16) -> Response) -> Response {
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => return error(status_of(&e)),
    };
    // One more than shown tells whether there are more; a huge directory costs no more.
    let mut entries: Vec<(String, bool, Option<fs::Metadata>)> = Vec::new();
    let mut more = false;
    for e in rd {
        let Ok(e) = e else { break };
        if entries.len() == max {
            more = true;
            break;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
        entries.push((name, is_dir, e.metadata().ok()));
    }
    entries.retain(|(name, ..)| !name.starts_with('.'));
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let title = html_escape(&format!("Index of {title}"));
    let mut b = String::with_capacity(256 + entries.len() * 128);
    b.push_str("<!doctype html>\n<meta charset=\"utf-8\">\n<title>");
    b.push_str(&title);
    b.push_str("</title>\n<h1>");
    b.push_str(&title);
    b.push_str("</h1>\n<table>\n");
    if title != "Index of /" {
        b.push_str("<tr><td><a href=\"../\">../</a></td><td></td><td></td></tr>\n");
    }
    for (name, is_dir, md) in &entries {
        let (mut size, mut modified) = (String::new(), String::new());
        if let Some(md) = md {
            modified = format_minute(unix_secs(md.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
            if !is_dir {
                size = md.len().to_string();
            }
        }
        // The href is relative, its one segment escaped, so a name with `?`, `#` or `:` stays
        // a name.
        let mut href = format!("./{}", path_escape(name));
        let mut shown = name.clone();
        if *is_dir {
            href.push('/');
            shown.push('/');
        }
        b.push_str("<tr><td><a href=\"");
        b.push_str(&html_escape(&href));
        b.push_str("\">");
        b.push_str(&html_escape(&shown));
        b.push_str("</a></td><td>");
        b.push_str(&size);
        b.push_str("</td><td>");
        b.push_str(&modified);
        b.push_str("</td></tr>\n");
    }
    b.push_str("</table>\n");
    if more {
        b.push_str(&format!(
            "<p>Only the first {max} entries the directory gave are listed.</p>\n"
        ));
    }
    let mut r = Response::with_body(200, "text/html; charset=utf-8", b.into_bytes());
    r.headers.append("Cache-Control", "no-cache");
    r
}

/// The status a failed look at a file answers: 403 for one that may not be read, else 404.
fn status_of(e: &std::io::Error) -> u16 {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        403
    } else {
        404
    }
}

/// Reads up to `buf.len()` bytes from the start of `f`; how many it read.
fn read_head(f: &fs::File, buf: &mut [u8]) -> usize {
    let mut n = 0;
    while n < buf.len() {
        match f.read_at(&mut buf[n..], n as u64) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    n
}

/// Where a request is in the tree, for the answers that name it.
struct At {
    /// Asked for as a directory: with its trailing slash, or the root.
    dir: bool,
    /// What a listing is titled (the decoded path, prefix included, ending in `/`), when the
    /// directory may be listed: asked for with its slash.
    title: Option<String>,
    /// The request's path as sent (prefix included), without a trailing slash: where
    /// [`Files::redirect_directories`] sends the client, with the slash.
    location: String,
}

/// `&`, `<`, `>`, `"` and `'` as HTML character references.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// One path segment percent-encoded: all but letters, digits and `-._~$&+:=@`.
fn path_escape(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        if c.is_ascii_alphanumeric() || b"-._~$&+:=@".contains(&c) {
            out.push(char::from(c));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(c >> 4)]));
            out.push(char::from(HEX[usize::from(c & 15)]));
        }
    }
    out
}

/// `secs` since the Unix epoch as `YYYY-MM-DD hh:mm`, in UTC.
fn format_minute(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Parses an IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`, the format senders must use) to
/// seconds since the Unix epoch.
fn parse_http_date(s: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut it = s.trim().split(' ');
    it.next()?.strip_suffix(',')?;
    let d: i64 = it.next()?.parse().ok()?;
    let mon = it.next()?;
    let m = MONTHS.iter().position(|&m| m == mon)? as i64 + 1;
    let y: i64 = it.next()?.parse().ok()?;
    let mut hms = it.next()?.split(':').map(|v| v.parse::<i64>().ok());
    let (h, mi, sec) = (hms.next()??, hms.next()??, hms.next()??);
    if it.next() != Some("GMT") || it.next().is_some() || !(1..=31).contains(&d) {
        return None;
    }
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).ok()
}

/// More range specs than this in one header: the header is ignored (a DoS guard, RFC 9110
/// section 14.2 lets a server ignore or reject such requests).
const MAX_RANGES: usize = 32;
/// Ranges closer than this are sent as one part: a part header costs about as much.
const COALESCE_GAP: u64 = 80;
/// Largest multipart body built (in memory); beyond it the whole file is sent instead.
const MAX_MULTIPART_BYTES: u64 = 1 << 20;

/// What a `Range` header asks of a file.
#[derive(Debug, PartialEq, Eq)]
enum Ranges {
    /// No usable header: send the whole file.
    Ignore,
    /// Malformed, or no range overlaps the file: `416`.
    Unsatisfiable,
    /// Inclusive byte ranges, coalesced, in the order the response sends them.
    Some(Vec<(u64, u64)>),
}

/// Parses a `Range` header against a file of `len` bytes (RFC 9110 section 14.1.2). Ranges that
/// start past the end are dropped; overlapping and nearby ranges are coalesced (section 14.2),
/// and the parts keep the order of the first range of each in the header.
fn parse_ranges(h: &str, len: u64) -> Ranges {
    let h = h.trim();
    let Some(spec) = h
        .get(..6)
        .filter(|u| u.eq_ignore_ascii_case("bytes="))
        .map(|_| &h[6..])
    else {
        return Ranges::Ignore; // another unit
    };
    let specs = spec.split(',').map(str::trim).filter(|s| !s.is_empty());
    if specs.clone().nth(MAX_RANGES).is_some() {
        return Ranges::Ignore;
    }
    let digits = |s: &str| -> Option<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    // (start, end, position in the header)
    let mut rs: Vec<(u64, u64, usize)> = Vec::new();
    for (i, r) in specs.enumerate() {
        let Some((a, b)) = r.split_once('-') else {
            return Ranges::Unsatisfiable;
        };
        let (a, b) = (a.trim(), b.trim());
        let (start, end) = if a.is_empty() {
            // Suffix: the last `n` bytes.
            let Some(n) = digits(b) else {
                return Ranges::Unsatisfiable;
            };
            if n == 0 || len == 0 {
                continue;
            }
            (len.saturating_sub(n), len - 1)
        } else {
            let Some(start) = digits(a) else {
                return Ranges::Unsatisfiable;
            };
            let end = if b.is_empty() {
                u64::MAX
            } else {
                match digits(b) {
                    Some(e) if e >= start => e,
                    _ => return Ranges::Unsatisfiable,
                }
            };
            if start >= len {
                continue; // unsatisfiable on its own: dropped
            }
            (start, end.min(len - 1))
        };
        rs.push((start, end, i));
    }
    if rs.is_empty() {
        return Ranges::Unsatisfiable;
    }
    // Coalesce: by start, merging what overlaps or nearly touches; each merged part takes the
    // header position of its earliest member.
    rs.sort_unstable();
    let mut out: Vec<(u64, u64, usize)> = Vec::with_capacity(rs.len());
    for (s, e, i) in rs {
        match out.last_mut() {
            Some(last) if s <= last.1.saturating_add(COALESCE_GAP) => {
                last.1 = last.1.max(e);
                last.2 = last.2.min(i);
            }
            _ => out.push((s, e, i)),
        }
    }
    out.sort_unstable_by_key(|r| r.2);
    Ranges::Some(out.into_iter().map(|(s, e, _)| (s, e)).collect())
}

/// A multipart boundary: 128 random bits (std's per-process random hash keys, advanced per call).
fn boundary() -> String {
    let mut out = String::with_capacity(36);
    out.push_str("akio");
    for i in 0..2u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i);
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// The `multipart/byteranges` body (RFC 9110 section 14.6) for `ranges` of a file of `len`
/// bytes, reading each part with `read(offset, buf)`. Returns the boundary and the body.
fn multipart(
    ranges: &[(u64, u64)],
    len: u64,
    mime: &str,
    mut read: impl FnMut(u64, &mut [u8]) -> std::io::Result<()>,
) -> std::io::Result<(String, Vec<u8>)> {
    let mut parts = Vec::with_capacity(ranges.len());
    for &(a, b) in ranges {
        let mut buf = vec![0; (b - a + 1) as usize];
        read(a, &mut buf)?;
        parts.push(buf);
    }
    // A boundary must not occur in the content; with 128 random bits it practically never does,
    // but the parts are at hand, so make sure.
    let mut bnd = boundary();
    while parts
        .iter()
        .any(|p| p.windows(bnd.len()).any(|w| w == bnd.as_bytes()))
    {
        bnd = boundary();
    }
    let total: usize = parts.iter().map(Vec::len).sum();
    let mut body = Vec::with_capacity(total + ranges.len() * (bnd.len() + mime.len() + 80));
    for (&(a, b), data) in ranges.iter().zip(&parts) {
        if !body.is_empty() {
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(
            format!(
                "--{bnd}\r\nContent-Type: {mime}\r\nContent-Range: bytes {a}-{b}/{len}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
    }
    body.extend_from_slice(format!("\r\n--{bnd}--\r\n").as_bytes());
    Ok((bnd, body))
}

impl Service for Files {
    fn call(&self, ctx: &mut Context) {
        // Mounted under a route, the path below it: redirects and listings name the request's
        // whole path.
        match ctx.param_raw("path") {
            Some(rel) => {
                let mut rel = rel.to_owned();
                let full = ctx.path();
                // The route's wildcard leaves out a trailing slash, which says "a directory".
                if full.ends_with('/') && !rel.ends_with('/') {
                    rel.push('/');
                }
                let prefix = full
                    .strip_suffix(rel.as_str())
                    .unwrap_or("")
                    .trim_end_matches('/')
                    .to_owned();
                self.serve_prefixed(ctx, &prefix, &rel);
            }
            None => {
                let raw = ctx.path().to_owned();
                self.serve(ctx, &raw);
            }
        }
    }

    fn streams_bodies(&self) -> bool {
        false
    }
}

impl Files {
    /// Serves `path`, a request path below the root as sent (percent-encoded), in place of the
    /// route parameter `path` or the request's own path [`Service::call`] takes: for a caller
    /// that routes by a path of its own (a prefix stripped, dot segments removed). It is
    /// percent-decoded and checked as theirs are.
    pub fn serve(&self, ctx: &mut Context, path: &str) {
        self.serve_prefixed(ctx, "", path);
    }

    /// [`serve`](Files::serve) for a caller that took `prefix` off the request's path, and
    /// serves `path`, what is left (ADR-124): the root stands for `prefix`, so a directory's
    /// listing is titled by the whole path (`Index of /assets/sub/`, with a `../` link) and
    /// [`redirect_directories`](Files::redirect_directories) sends the client to the whole
    /// path with its slash. Both are as sent (percent-encoded); only `path` is looked up.
    pub fn serve_prefixed(&self, ctx: &mut Context, prefix: &str, path: &str) {
        let inner = &self.inner;
        let head = *ctx.method() == Method::Head;
        if *ctx.method() != Method::Get && !head {
            return ctx.respond(inner.error(405));
        }
        let Some(decoded) = percent_decode(path) else {
            return ctx.respond(inner.error(404));
        };
        let Some(rel) = Files::relative(&decoded) else {
            return ctx.respond(inner.error(404));
        };
        // The path asked for, with a leading slash: what `hide` and `{path}` see.
        let asked = if decoded.starts_with('/') {
            decoded
        } else {
            format!("/{decoded}")
        };
        if inner.hide.as_ref().is_some_and(|h| h(&asked)) {
            return ctx.respond(inner.error(404));
        }
        // A directory is listed only when asked for with its slash, so that its relative links
        // resolve; a file asked for with one is not there.
        let dir = asked.ends_with('/') || rel.as_os_str().is_empty();
        // Fast path: an entry still inside its trust window needs no syscall at all.
        let known = if inner.tries.is_empty() {
            inner.fresh(&inner.root.join(&rel), dir)
        } else {
            inner.tried_fresh(&asked)
        };
        if let Some(c) = known {
            let served = inner.variant(ctx.req(), &c);
            if let Some(r) = inner.build(ctx.req(), served, false) {
                return ctx.respond(r);
            }
        }
        // Anything else touches the disk: on the disk pool, never on the I/O thread.
        let at = At {
            dir,
            title: (dir && inner.list_max > 0).then(|| {
                let p = percent_decode(prefix).unwrap_or_default();
                format!("{}{asked}", p.trim_end_matches('/'))
            }),
            location: if !dir && inner.redirect_dirs {
                let p = prefix.trim_end_matches('/');
                if path.starts_with('/') {
                    format!("{p}{path}")
                } else {
                    format!("{p}/{path}")
                }
            } else {
                String::new()
            },
        };
        let Some(d) = ctx.detach() else { return };
        let job_inner = inner.clone();
        let cell: Cell = Arc::new(Mutex::new(Some(d)));
        let job_cell = cell.clone();
        let job = Box::new(move || {
            // The request's work, unless the timeout answered it while it waited.
            let Some(req) = lock(&job_cell).as_ref().map(|d| d.req_arc()) else {
                return;
            };
            let inner = job_inner;
            let r = if inner.tries.is_empty() {
                inner.serve_disk(&req, inner.root.join(&rel), &at)
            } else {
                inner.serve_tries(&req, &asked)
            };
            let d = lock(&job_cell).take();
            if let Some(d) = d {
                d.respond(r);
            }
        });
        if disk_pool().try_execute(job).is_err() {
            let d = lock(&cell).take();
            if let Some(d) = d {
                d.respond(inner.error(503));
            }
        } else if let Some(t) = inner.disk_timeout {
            Waiting::join(&inner.waiting, cell, t, inner.clone());
        }
    }
}

/// A request on its way through the disk pool: its pool work and [`Files::disk_timeout`] each
/// take it to answer, whichever comes first.
type Cell = Arc<Mutex<Option<Detached>>>;

/// The requests [`Files::disk_timeout`] bounds, in the order they were queued (their deadlines'
/// order too: the timeout is the same for all). A sweep every eighth of the timeout, scheduled
/// only while requests wait, answers those past it 503 and drops those answered.
#[derive(Default)]
struct Waiting {
    state: Mutex<WaitState>,
}

#[derive(Default)]
struct WaitState {
    queue: std::collections::VecDeque<(Instant, Cell)>,
    /// A sweep is scheduled.
    sweeping: bool,
}

/// When the waiting list holds this many, it drops the requests already answered: those still
/// waiting are at most the pool's queue and threads, fewer than this.
const MAX_WAITING: usize = 8192;

impl Waiting {
    fn join(w: &Arc<Waiting>, cell: Cell, timeout: Duration, inner: Arc<Inner>) {
        let mut st = lock(&w.state);
        if st.queue.len() >= MAX_WAITING {
            st.queue.retain(|(_, c)| lock(c).is_some());
        }
        st.queue.push_back((Instant::now() + timeout, cell));
        if !st.sweeping {
            st.sweeping = true;
            Waiting::schedule(w.clone(), timeout, inner);
        }
    }

    fn schedule(w: Arc<Waiting>, timeout: Duration, inner: Arc<Inner>) {
        let every = (timeout / 8).max(Duration::from_millis(1));
        crate::timer::after(every, move || w.sweep(timeout, inner));
    }

    /// Answers the requests past their deadline 503, drops the answered ones at the front, and
    /// schedules the next sweep while any wait. Runs on the timer thread: quick.
    fn sweep(self: Arc<Self>, timeout: Duration, inner: Arc<Inner>) {
        let now = Instant::now();
        let mut late = Vec::new();
        {
            let mut st = lock(&self.state);
            while let Some((deadline, cell)) = st.queue.front() {
                let answered = lock(cell).is_none();
                if !answered && *deadline > now {
                    break;
                }
                if !answered {
                    late.push(cell.clone());
                }
                st.queue.pop_front();
            }
            if st.queue.is_empty() {
                st.sweeping = false;
            } else {
                Waiting::schedule(self.clone(), timeout, inner.clone());
            }
        }
        for cell in late {
            let d = lock(&cell).take();
            if let Some(d) = d {
                d.respond(inner.error(503));
            }
        }
    }
}

impl Inner {
    /// The response to `req` from entry `c` (the file, or a compressed twin of it). `None` when it needs the disk and `disk` is false (the parts of a
    /// multi-range response from an open file).
    fn build(&self, req: &Request, c: &Arc<Cached>, disk: bool) -> Option<Response> {
        let head = req.method == Method::Head;
        let etag = &*c.etag;
        let header = |n: &str| req.headers.get(n);
        // Conditional requests.
        // RFC 9110 section 13.2.2 order: If-Match / If-Unmodified-Since, then If-None-Match /
        // If-Modified-Since, then If-Range.
        let precondition_failed = match header("if-match") {
            Some(v) => !v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t == etag // strong comparison
            }),
            None => header("if-unmodified-since")
                .and_then(parse_http_date)
                .is_some_and(|d| c.mtime_secs > d),
        };
        if precondition_failed {
            let mut r = Response::new(412);
            r.headers.append("ETag", etag);
            return Some(r);
        }
        let not_modified = match header("if-none-match") {
            Some(v) => v.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t.trim_start_matches("W/") == etag
            }),
            None => header("if-modified-since")
                .and_then(parse_http_date)
                .is_some_and(|d| c.mtime_secs <= d),
        };
        if not_modified {
            let mut r = Response::new(304);
            r.headers = c.meta.clone();
            return Some(r);
        }
        // `If-Range`: the range applies only while the client's copy is current (a strong entity
        // tag, or exactly the modification date); otherwise the whole file is sent.
        let range_ok = header("if-range").is_none_or(|v| {
            let v = v.trim();
            if v.starts_with('"') || v.starts_with("W/") {
                v == etag
            } else {
                parse_http_date(v) == Some(c.mtime_secs)
            }
        });
        let len = c.len;
        // Ranges (GET only).
        let ranges = match header("range") {
            Some(h) if !head && range_ok => parse_ranges(h, len),
            _ => Ranges::Ignore,
        };
        let ranges = match ranges {
            Ranges::Unsatisfiable => {
                let mut r = Response::new(416);
                r.headers.append("Content-Range", format!("bytes */{len}"));
                return Some(r);
            }
            Ranges::Some(rs)
                if rs.len() > 1
                    && rs.iter().map(|(a, b)| b - a + 1).sum::<u64>() > MAX_MULTIPART_BYTES =>
            {
                Vec::new() // too large to assemble: the whole file
            }
            Ranges::Some(rs) => rs,
            Ranges::Ignore => Vec::new(),
        };
        let mut resp = if ranges.len() > 1 {
            if matches!(c.body, Body::File(_)) && !disk {
                return None;
            }
            let read = |off: u64, buf: &mut [u8]| -> std::io::Result<()> {
                match &c.body {
                    Body::Mem(b) => {
                        buf.copy_from_slice(&b[off as usize..off as usize + buf.len()]);
                        Ok(())
                    }
                    Body::File(f) => f.read_exact_at(buf, off),
                }
            };
            let Ok((bnd, body)) = multipart(&ranges, len, &c.mime, read) else {
                // The file shrank under us: the client retries.
                return Some(Response::text(500, "Internal Server Error"));
            };
            let mut r = Response::new(206);
            r.headers = Headers::with_capacity(8, 256);
            r.headers.append(
                "Content-Type",
                format!("multipart/byteranges; boundary={bnd}"),
            );
            for (n, v) in c.meta.iter() {
                r.headers.append(n, v);
            }
            r.body = body;
            r
        } else {
            let (status, offset, count) = match ranges.first() {
                Some(&(a, b)) => (206, a, b - a + 1),
                None => (200, 0, len),
            };
            let mut r = Response::new(status);
            r.headers = c.full.clone();
            if status == 206 {
                r.headers.append(
                    "Content-Range",
                    format!("bytes {offset}-{}/{len}", offset + count - 1),
                );
            }
            match &c.body {
                // HEAD sends no body: nothing to copy.
                Body::Mem(_) if head => {}
                Body::Mem(bytes) => {
                    r.body = bytes[offset as usize..(offset + count) as usize].to_vec();
                }
                Body::File(f) => {
                    r.file = Some(FileBody {
                        file: f.clone(),
                        offset,
                        len: count,
                    });
                }
            }
            r
        };
        // HEAD announces the length of the full representation.
        if head {
            let mut b = Vec::with_capacity(20);
            crate::message::push_uint(&mut b, len);
            resp.headers
                .append("Content-Length", std::str::from_utf8(&b).unwrap_or("0"));
        }
        Some(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_q_values() {
        let q = |fields: &[&str], coding: &str| {
            let mut h = Headers::new();
            for f in fields {
                h.append("Accept-Encoding", f);
            }
            accept_q(&h, coding)
        };
        assert!((q(&["gzip"], "gzip") - 1.0).abs() < 1e-9);
        assert!((q(&["GZIP;q=0.3"], "gzip") - 0.3).abs() < 1e-9);
        assert!((q(&["br", "gzip ; q=0.5"], "gzip") - 0.5).abs() < 1e-9);
        assert!((q(&["*;q=0.2"], "zstd") - 0.2).abs() < 1e-9);
        assert!(q(&["*;q=0.2, zstd;q=0"], "zstd").abs() < 1e-9);
        assert!(q(&["deflate"], "gzip").abs() < 1e-9);
        assert!(q(&[], "gzip").abs() < 1e-9);
        assert!((q(&["gzip;q=nope"], "gzip") - 1.0).abs() < 1e-9);
        assert!((q(&["gzip;q=2"], "gzip") - 1.0).abs() < 1e-9);
        assert!((q(&["gzip;level=3;q=0.7"], "gzip") - 0.7).abs() < 1e-9);
    }

    #[test]
    fn listing_escapes_and_dates() {
        assert_eq!(path_escape("a&b<c>.txt"), "a&b%3Cc%3E.txt");
        assert_eq!(path_escape("q?x #y/z;w,v"), "q%3Fx%20%23y%2Fz%3Bw%2Cv");
        assert_eq!(path_escape("ok-_.~$+:=@9"), "ok-_.~$+:=@9");
        assert_eq!(path_escape("é"), "%C3%A9");
        assert_eq!(
            html_escape(r#"<a href="x">&'</a>"#),
            "&lt;a href=&#34;x&#34;&gt;&amp;&#39;&lt;/a&gt;"
        );
        assert_eq!(format_minute(0), "1970-01-01 00:00");
        assert_eq!(format_minute(784_111_777), "1994-11-06 08:49");
        assert_eq!(format_minute(951_782_400), "2000-02-29 00:00");
        assert_eq!(format_minute(4_102_444_799), "2099-12-31 23:59");
    }

    #[test]
    fn http_dates_round_trip() {
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        for secs in [0, 951_782_400, 1_700_000_000, 4_102_444_800] {
            assert_eq!(parse_http_date(&format_http_date(secs)), Some(secs));
        }
        assert_eq!(parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 UTC"), None);
        assert_eq!(parse_http_date("garbage"), None);
    }

    fn some(v: &[(u64, u64)]) -> Ranges {
        Ranges::Some(v.to_vec())
    }

    #[test]
    fn single_range_parsing() {
        assert_eq!(parse_ranges("bytes=0-4", 10), some(&[(0, 4)]));
        assert_eq!(parse_ranges("bytes=5-", 10), some(&[(5, 9)]));
        assert_eq!(parse_ranges("bytes=-3", 10), some(&[(7, 9)]));
        assert_eq!(parse_ranges("bytes=-30", 10), some(&[(0, 9)]));
        assert_eq!(
            parse_ranges("bytes=2-99", 10),
            some(&[(2, 9)]),
            "end is clamped"
        );
        assert_eq!(
            parse_ranges("BYTES = 1-2", 10),
            Ranges::Ignore,
            "no space in the unit"
        );
        assert_eq!(
            parse_ranges("Bytes=1-2", 10),
            some(&[(1, 2)]),
            "unit is case-insensitive"
        );
        assert_eq!(parse_ranges("bytes=10-12", 10), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=5-2", 10), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=-0", 10), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=0-0", 0), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("bytes=-5", 0), Ranges::Unsatisfiable);
        assert_eq!(parse_ranges("items=0-1", 10), Ranges::Ignore);
        assert_eq!(parse_ranges("bytes=", 10), Ranges::Unsatisfiable);
        for bad in [
            "bytes=a-1",
            "bytes=1-b",
            "bytes=+1-2",
            "bytes=1",
            "bytes=--1",
            "bytes=1-2-3",
        ] {
            assert_eq!(parse_ranges(bad, 10), Ranges::Unsatisfiable, "{bad}");
        }
        assert_eq!(
            parse_ranges("bytes=0-99999999999999999999", 10),
            Ranges::Unsatisfiable,
            "overflow"
        );
    }

    #[test]
    fn multi_range_parsing_and_coalescing() {
        let len = 1000;
        assert_eq!(
            parse_ranges("bytes=0-9,200-209", len),
            some(&[(0, 9), (200, 209)])
        );
        // Request order is kept for parts that are not merged.
        assert_eq!(
            parse_ranges("bytes=500-509, 0-9 ,-10", len),
            some(&[(500, 509), (0, 9), (990, 999)])
        );
        // Overlapping, adjacent and nearby (< 80 bytes apart) ranges merge; the merged part sits
        // where its first member was asked for.
        assert_eq!(
            parse_ranges("bytes=500-599,0-9,550-650,5-20", len),
            some(&[(500, 650), (0, 20)])
        );
        assert_eq!(parse_ranges("bytes=0-9,10-19", len), some(&[(0, 19)]));
        assert_eq!(parse_ranges("bytes=0-9,89-99", len), some(&[(0, 99)]));
        assert_eq!(
            parse_ranges("bytes=0-9,91-99", len),
            some(&[(0, 9), (91, 99)])
        );
        assert_eq!(parse_ranges("bytes=0-,5-10", len), some(&[(0, 999)]));
        // The same range many times is one part.
        let many = vec!["0-0"; 20].join(",");
        assert_eq!(parse_ranges(&format!("bytes={many}"), len), some(&[(0, 0)]));
        // Unsatisfiable members are dropped; if none is left, 416.
        assert_eq!(parse_ranges("bytes=2000-3000,0-1", len), some(&[(0, 1)]));
        assert_eq!(
            parse_ranges("bytes=2000-3000,1000-", len),
            Ranges::Unsatisfiable
        );
        // One malformed member spoils the header.
        assert_eq!(parse_ranges("bytes=0-1,x-2", len), Ranges::Unsatisfiable);
        // Empty list elements are allowed.
        assert_eq!(parse_ranges("bytes=0-1,,", len), some(&[(0, 1)]));
        // Too many ranges: the header is ignored (DoS guard).
        let r: Vec<String> = (0..=MAX_RANGES)
            .map(|i| format!("{}-{}", i * 100, i * 100))
            .collect();
        assert_eq!(
            parse_ranges(&format!("bytes={}", r.join(",")), 100_000),
            Ranges::Ignore
        );
        let r = &r[..MAX_RANGES];
        let Ranges::Some(got) = parse_ranges(&format!("bytes={}", r.join(",")), 100_000) else {
            panic!("32 ranges are served");
        };
        assert_eq!(got.len(), MAX_RANGES);
    }

    #[test]
    fn multipart_bodies() {
        let file: Vec<u8> = (0..100u8).collect();
        let (bnd, body) = multipart(&[(0, 2), (10, 11)], 100, "text/plain", |off, buf| {
            buf.copy_from_slice(&file[off as usize..off as usize + buf.len()]);
            Ok(())
        })
        .unwrap();
        assert!(bnd.len() >= 32 && bnd.bytes().all(|b| b.is_ascii_alphanumeric()));
        let mut want = Vec::new();
        want.extend_from_slice(
            format!("--{bnd}\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-2/100\r\n\r\n")
                .as_bytes(),
        );
        want.extend_from_slice(&[0, 1, 2]);
        want.extend_from_slice(
            format!(
                "\r\n--{bnd}\r\nContent-Type: text/plain\r\nContent-Range: bytes 10-11/100\r\n\r\n"
            )
            .as_bytes(),
        );
        want.extend_from_slice(&[10, 11]);
        want.extend_from_slice(format!("\r\n--{bnd}--\r\n").as_bytes());
        assert_eq!(body, want);
        assert_ne!(boundary(), boundary());
        // A read error (the file shrank) is reported.
        assert!(
            multipart(&[(0, 1), (5, 6)], 10, "x/y", |_, _| Err(
                std::io::ErrorKind::UnexpectedEof.into()
            ))
            .is_err()
        );
    }

    /// A scratch directory under the system temp dir.
    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("akio-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// The cache invariants: the open ring lists exactly the open-file entries, at most `max`;
    /// the memory ring lists exactly the entries holding bytes, charged what they hold, within
    /// the bound.
    fn check_ring(f: &Files, max: usize) {
        let ring = lock(&f.inner.ring);
        assert!(
            ring.open.slots.len() <= max,
            "{} open files > {max}",
            ring.open.slots.len()
        );
        let (mut files, mut mems, mut bytes) = (0, 0, 0);
        for s in &f.inner.shards {
            for (p, e) in read_lock(s).iter() {
                if let Entry::File(c) = e {
                    if matches!(c.body, Body::File(_)) {
                        files += 1;
                        let i = ring
                            .open
                            .position(p)
                            .expect("an open file outside the ring");
                        assert!(Arc::ptr_eq(&ring.open.slots[i].1, c), "a stale ring entry");
                    }
                    if c.mem_bytes() > 0 {
                        mems += 1;
                        let i = ring.mem.position(p).expect("bytes outside the ring");
                        assert!(Arc::ptr_eq(&ring.mem.slots[i].1, c), "a stale ring entry");
                        assert_eq!(ring.mem.slots[i].2, c.mem_bytes(), "charged otherwise");
                        bytes += c.mem_bytes();
                    }
                }
            }
        }
        assert_eq!(files, ring.open.slots.len());
        assert_eq!(mems, ring.mem.slots.len());
        assert_eq!(bytes, ring.bytes);
        assert!(ring.bytes <= f.inner.max_cache_bytes);
        for r in [&ring.open, &ring.mem] {
            let mut sorted: Vec<&PathBuf> = r.slots.iter().map(|(p, ..)| p).collect();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), r.slots.len(), "a path twice in the ring");
        }
    }

    fn open_cached(f: &Files, p: &Path) -> Arc<Cached> {
        f.inner.load(p, &fs::metadata(p).unwrap()).unwrap()
    }

    fn cached_entry(f: &Files, p: &Path) -> Option<Arc<Cached>> {
        match read_lock(f.inner.shard(p)).get(p) {
            Some(Entry::File(c)) => Some(c.clone()),
            _ => None,
        }
    }

    #[test]
    fn open_file_cache_evicts_under_churn_and_keeps_hot_files() {
        let dir = scratch("churn");
        let paths: Vec<PathBuf> = (0..40)
            .map(|i| {
                let p = dir.join(format!("f{i}.bin"));
                fs::write(&p, vec![i as u8; 100 + i]).unwrap();
                p
            })
            .collect();
        let f = Files::new(&dir).max_cached_bytes(10).max_open_files(4);
        let hot = &paths[0];
        open_cached(&f, hot);
        // A pseudo-random walk over the cold files, with the hot one used in between.
        let mut x = 7u64;
        for _ in 0..500 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let p = &paths[1 + (x >> 33) as usize % (paths.len() - 1)];
            let c = open_cached(&f, p);
            assert_eq!(c.len, fs::metadata(p).unwrap().len());
            check_ring(&f, 4);
            let c = f
                .inner
                .fresh(hot, false)
                .unwrap_or_else(|| open_cached(&f, hot));
            assert_eq!(c.len, 100);
        }
        assert!(cached_entry(&f, hot).is_some(), "the hot file was evicted");
        // A file that turns small leaves the ring; one that is deleted leaves the cache.
        fs::write(&paths[0], b"tiny").unwrap();
        open_cached(&f, hot);
        check_ring(&f, 4);
        assert!(matches!(cached_entry(&f, hot).unwrap().body, Body::Mem(_)));
        assert_eq!(lock(&f.inner.ring).open.slots.len(), 3);
        let victim = lock(&f.inner.ring).open.slots[0].0.clone();
        f.inner.forget(&victim);
        check_ring(&f, 4);
        assert_eq!(lock(&f.inner.ring).open.slots.len(), 2);
        assert!(cached_entry(&f, &victim).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_cache_is_bounded_and_keeps_hot_files() {
        let dir = scratch("membound");
        let paths: Vec<PathBuf> = (0..40)
            .map(|i| {
                let p = dir.join(format!("f{i}.txt"));
                fs::write(&p, vec![b'a' + (i % 26) as u8; 1000 + i]).unwrap();
                p
            })
            .collect();
        // Room for about five files.
        let f = Files::new(&dir).max_cache_bytes(5_200);
        let hot = &paths[0];
        open_cached(&f, hot);
        let mut x = 11u64;
        for _ in 0..500 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let p = &paths[1 + (x >> 33) as usize % (paths.len() - 1)];
            let c = open_cached(&f, p);
            assert_eq!(c.len, fs::metadata(p).unwrap().len());
            check_ring(&f, 64);
            let c = f
                .inner
                .fresh(hot, false)
                .unwrap_or_else(|| open_cached(&f, hot));
            assert_eq!(c.len, 1000);
        }
        assert!(cached_entry(&f, hot).is_some(), "the hot file was evicted");
        let ring = lock(&f.inner.ring);
        assert!(ring.mem.slots.len() >= 4, "{}", ring.mem.slots.len());
        drop(ring);
        // A file larger than the bound alone is served, never kept.
        let huge = dir.join("huge.txt");
        fs::write(&huge, vec![b'x'; 6_000]).unwrap();
        assert_eq!(open_cached(&f, &huge).len, 6_000);
        assert!(cached_entry(&f, &huge).is_none());
        check_ring(&f, 64);
        // 0 keeps nothing.
        let none = Files::new(&dir).max_cache_bytes(0);
        open_cached(&none, hot);
        assert!(cached_entry(&none, hot).is_none());
        check_ring(&none, 64);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn compressed_copies_count_in_the_memory_bound() {
        let dir = scratch("packbound");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        fs::write(&a, "hello compressible world ".repeat(400)).unwrap();
        fs::write(&b, "another compressible text ".repeat(400)).unwrap();
        // How large a's copy is.
        let probe = Files::new(&dir).compress(&["gzip"]);
        let pa = open_cached(&probe, &a);
        probe.inner.make_pack(&pa, 2);
        wait_until("the probe's copy", || pa.packs[2].made.get().is_some());
        let copy = pa.mem_bytes() - pa.len;
        assert!(copy > 0);
        // Room for a and b, not for a's copy too.
        let bound = 10_000 + 10_400 + copy - 1;
        let f = Files::new(&dir).compress(&["gzip"]).max_cache_bytes(bound);
        let ca = open_cached(&f, &a);
        let cb = open_cached(&f, &b);
        check_ring(&f, 64);
        assert!(cached_entry(&f, &a).is_some() && cached_entry(&f, &b).is_some());
        f.inner.make_pack(&ca, 2);
        wait_until("a's copy", || ca.packs[2].made.get().is_some());
        // Charged once the copy is made: something goes.
        wait_until("an eviction", || {
            cached_entry(&f, &a).is_none() || cached_entry(&f, &b).is_none()
        });
        check_ring(&f, 64);
        assert!(lock(&f.inner.ring).bytes <= bound);
        drop((ca, cb));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_file_cache_notices_a_file_renamed_over_the_cached_one() {
        let dir = scratch("rename");
        let p = dir.join("a.bin");
        fs::write(&p, vec![1u8; 1000]).unwrap();
        let f = Files::new(&dir).max_cached_bytes(10);
        let before = open_cached(&f, &p);
        // Same size and modification time, another inode.
        let tmp = dir.join("a.bin.tmp");
        fs::write(&tmp, vec![2u8; 1000]).unwrap();
        let t = fs::metadata(&p).unwrap().modified().unwrap();
        fs::File::options()
            .write(true)
            .open(&tmp)
            .unwrap()
            .set_modified(t)
            .unwrap();
        fs::rename(&tmp, &p).unwrap();
        let after = open_cached(&f, &p);
        assert_ne!(before.id, after.id);
        let Body::File(h) = &after.body else {
            panic!("an open file")
        };
        let mut b = [0u8; 1];
        h.read_exact_at(&mut b, 0).unwrap();
        assert_eq!(b[0], 2, "served from the old inode");
        check_ring(&f, 64);
        assert_eq!(lock(&f.inner.ring).open.slots.len(), 1, "replaced in place");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn twins_are_cached_with_the_file_including_their_absence() {
        let dir = scratch("twins");
        let p = dir.join("app.js");
        fs::write(&p, b"console.log(1)").unwrap();
        fs::write(dir.join("app.js.gz"), b"gz-bytes").unwrap();
        let f = Files::new(&dir);
        let c = open_cached(&f, &p);
        assert!(c.twins[0].is_none(), "no .br");
        assert!(c.twins[1].is_none(), "no .zst");
        let gz = c.twins[2].as_ref().expect("the .gz twin");
        assert_eq!(&*gz.mime, "text/javascript; charset=utf-8");
        assert_eq!(gz.meta.get("content-encoding"), Some("gzip"));
        assert!(gz.etag.ends_with("-gzip\""));
        let enc = |c: &Arc<Cached>, accept: &str| {
            let mut h = Headers::new();
            h.append("Accept-Encoding", accept);
            pick(c, &h, &[0, 1, 2])
                .meta
                .get("content-encoding")
                .map(str::to_owned)
        };
        assert_eq!(enc(&c, "gzip, br").as_deref(), Some("gzip"));
        assert_eq!(enc(&c, "identity"), None);
        // Unchanged on disk: the same entries are kept.
        let again = open_cached(&f, &p);
        assert!(Arc::ptr_eq(&c, &again));
        // A new twin appears: the entry is renewed with it, the content is shared.
        fs::write(dir.join("app.js.br"), b"br-bytes").unwrap();
        let renewed = open_cached(&f, &p);
        assert!(!Arc::ptr_eq(&c, &renewed));
        assert_eq!(enc(&renewed, "gzip, br").as_deref(), Some("br"));
        fs::write(dir.join("app.js.zst"), b"zstd-bytes").unwrap();
        let renewed = open_cached(&f, &p);
        assert_eq!(enc(&renewed, "gzip, zstd").as_deref(), Some("zstd"));
        assert_eq!(enc(&renewed, "gzip, zstd, br").as_deref(), Some("br"));
        assert_eq!(enc(&renewed, "gzip").as_deref(), Some("gzip"));
        let _ = fs::remove_dir_all(&dir);
    }

    fn get(f: &Files, p: &Path) -> Response {
        f.inner.serve_disk(
            &Request::new(Method::Get, "/"),
            p.to_owned(),
            &At {
                dir: false,
                title: None,
                location: String::new(),
            },
        )
    }

    /// Waits up to 5 s for `cond`.
    fn wait_until(what: &str, cond: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Requests `p` until its entry is watched: notifications still in flight from an earlier
    /// change keep a request from vouching for what it read.
    fn watched_soon(f: &Files, p: &Path) -> Arc<Cached> {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            get(f, p);
            if let Some(c) = f.inner.fresh(p, false) {
                return c;
            }
            assert!(Instant::now() < end, "{} never became watched", p.display());
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Without watching, a zero interval means nothing is fresh.
    #[test]
    fn unwatched_entries_follow_the_interval() {
        let dir = scratch("nowatch");
        let p = dir.join("x.txt");
        fs::write(&p, "one").unwrap();
        let f = Files::new(&dir).check_interval(Duration::ZERO);
        assert_eq!(get(&f, &p).body, b"one");
        assert!(f.inner.fresh(&p, false).is_none());
        assert!(
            f.inner.watch.get().is_none(),
            "no watcher without watch(true)"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn watched_entries_live_until_a_change() {
        let dir = scratch("watch");
        let sub = dir.join("a").join("b");
        fs::create_dir_all(&sub).unwrap();
        let p = sub.join("x.txt");
        fs::write(&p, "one").unwrap();
        // A zero interval: only a watched entry is ever fresh.
        let f = Files::new(&dir).watch(true).check_interval(Duration::ZERO);
        assert_eq!(get(&f, &p).body, b"one");
        let c = f.inner.fresh(&p, false).expect("a watched entry is fresh");
        assert!(c.watched.load(Ordering::Relaxed));
        drop(c);

        // A write drops it; the next request reads the new content and watches again.
        fs::write(&p, "two").unwrap();
        wait_until("a write to drop the entry", || {
            f.inner.fresh(&p, false).is_none()
        });
        assert_eq!(get(&f, &p).body, b"two");
        watched_soon(&f, &p);

        // A new compressed twin drops the original.
        fs::write(sub.join("x.txt.gz"), b"\x1f\x8b").unwrap();
        wait_until("a new twin to drop the entry", || {
            f.inner.fresh(&p, false).is_none()
        });
        let c = watched_soon(&f, &p);
        assert!(c.twins[2].is_some());
        drop(c);
        // A change to the twin drops the original too.
        fs::write(sub.join("x.txt.gz"), b"\x1f\x8b\x08").unwrap();
        wait_until("a twin write to drop the entry", || {
            f.inner.fresh(&p, false).is_none()
        });
        watched_soon(&f, &p);

        // Renaming a directory on the path drops everything below it and its watches.
        fs::rename(dir.join("a"), dir.join("a2")).unwrap();
        wait_until("a renamed directory to drop the entry", || {
            f.inner.fresh(&p, false).is_none()
        });
        assert_eq!(get(&f, &p).status, 404);
        fs::create_dir_all(&sub).unwrap();
        fs::write(&p, "three").unwrap();
        assert_eq!(get(&f, &p).body, b"three");
        // The re-created directories are watched anew.
        watched_soon(&f, &p);
        fs::write(&p, "four").unwrap();
        wait_until("a write in the new directory", || {
            f.inner.fresh(&p, false).is_none()
        });

        // A directory served as its index file.
        let a = dir.join("a");
        fs::write(a.join("index.html"), "idx").unwrap();
        assert_eq!(get(&f, &a).body, b"idx");
        watched_soon(&f, &a);
        fs::remove_file(a.join("index.html")).unwrap();
        wait_until("a removed index to drop the directory", || {
            f.inner.fresh(&a, false).is_none()
        });
        assert_eq!(get(&f, &a).status, 404);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn watch_limits_overflow_and_in_flight_changes_fall_back() {
        let dir = scratch("watchlimits");
        fs::create_dir_all(dir.join("d")).unwrap();
        let top = dir.join("top.txt");
        let deep = dir.join("d").join("deep.txt");
        fs::write(&top, "t").unwrap();
        fs::write(&deep, "d").unwrap();

        // Room for one watch: the root, not `d`.
        let f = Files::new(&dir)
            .watch(true)
            .max_watches(1)
            .check_interval(Duration::ZERO);
        get(&f, &top);
        get(&f, &deep);
        if FsWatcher::DIR_EVENTS_NAME_ENTRIES {
            assert!(f.inner.fresh(&top, false).is_some());
        }
        assert!(
            f.inner.fresh(&deep, false).is_none(),
            "past max_watches: the interval rule"
        );

        // An overflow drops everything.
        let f = Files::new(&dir).watch(true).check_interval(Duration::ZERO);
        get(&f, &top);
        get(&f, &deep);
        assert!(f.inner.fresh(&top, false).is_some() && f.inner.fresh(&deep, false).is_some());
        let w = f.inner.watcher().unwrap();
        f.inner.apply(&w, &[FsEvent::Overflow]);
        assert!(f.inner.fresh(&top, false).is_none() && f.inner.fresh(&deep, false).is_none());

        // A notification applied while a request read the disk: not marked watched.
        let t = f.inner.watch_begin(&top).unwrap();
        f.inner.apply(&w, &[]);
        let md = fs::metadata(&top).unwrap();
        let c = f.inner.load_tracked(&top, &md, Some(&t)).unwrap();
        assert!(!c.watched.load(Ordering::Relaxed));
        drop((c, t));
        // The next request vouches for it again.
        get(&f, &top);
        assert!(f.inner.fresh(&top, false).is_some());

        // Dropping the Files ends the thread and every watch.
        drop(f);
        wait_until("the watcher thread to exit", || Arc::strong_count(&w) == 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Linux: a write through another hard link is not reported for this directory, so such
    /// files keep the interval rule (macOS watches the file itself).
    #[cfg(target_os = "linux")]
    #[test]
    fn linked_files_are_not_vouched_for_on_linux() {
        let dir = scratch("watchlinks");
        let p = dir.join("x.txt");
        fs::write(&p, "x").unwrap();
        fs::hard_link(&p, dir.join("y.txt")).unwrap();
        std::os::unix::fs::symlink(&p, dir.join("z.txt")).unwrap();
        let f = Files::new(&dir).watch(true).check_interval(Duration::ZERO);
        get(&f, &p);
        get(&f, &dir.join("z.txt"));
        assert!(f.inner.fresh(&p, false).is_none());
        assert!(f.inner.fresh(&dir.join("z.txt"), false).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mime_types() {
        assert_eq!(
            Files::mime(Path::new("a/b.HTML")),
            "text/html; charset=utf-8"
        );
        assert_eq!(Files::mime(Path::new("x.wasm")), "application/wasm");
        assert_eq!(Files::mime(Path::new("noext")), "application/octet-stream");
    }
}
