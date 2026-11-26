//! Every place in the libraries that hands work to a logical pool, and the lane it takes
//! (docs/rules.md, rule 2).
//!
//! A pool has two lanes. New work (`try_execute`, `try_execute_batch`, and the wrappers over
//! them: `Conn::spawn_blocking`, `Conn::execute`, `ConnInner::execute`, `Executor::execute`,
//! `detach_to_pool`, ...) is admitted while the queue has room and refused past it: that is where
//! an overloaded process turns work away, and the caller answers for it (a 503, a
//! `RESOURCE_EXHAUSTED`, a dropped datagram). The next step of work admitted already (the next
//! piece of a response under way, the next message of an open call, a piece downloaded whole)
//! goes through `resume` (`Pool::resume`, `ConnInner::resume`, `Executor::resume`, ...), which a
//! full queue does not refuse. A refused submission is never tried again from a timer.
//!
//! [`pool_submissions_are_registered`] scans `crates/*/src/**/*.rs` (test-only code, comments
//! and string literals left out) for calls named like a submission (`SUBMIT_CALLS`, called as
//! `x.name(` or `X::name(`) and checks them against [`SITES`]:
//!
//! - every call found is listed, as often as it occurs in its function;
//! - every listed call is still there (keep the list honest: drop or move an entry with its
//!   code);
//! - a call listed in the `Resume` lane calls `resume`, one in the `New` lane does not;
//! - no timer call (`after(`, `after_send(`, `sleep(`, `schedule(`, `Timer::at(`) follows a
//!   submission in the same function: that is where a refused submission would be tried again.
//!   A timer about time (a timeout armed once the work is queued) goes in a function of its own.
//!
//! # Registering a new site
//!
//! When the test names an unlisted call, add an entry to [`SITES`] with:
//!
//! - `file`: the path from the workspace root, as the message prints it;
//! - `func`: the enclosing function, `Type::method` or `function`, as the message prints it
//!   (closures count as their function);
//! - `call`: the receiver and method with no spaces, as the message prints it;
//! - `lane`: [`Lane::New`] when the call admits new work and may be refused; [`Lane::Resume`]
//!   when it is the next step of work admitted already (then it must call `resume`, and its
//!   owner must keep one such step queued or running at a time); [`Lane::User`] when it is a
//!   public wrapper that forwards its own caller's choice of lane; [`Lane::NotPool`] for a call
//!   that only shares the name (a TLS handshake's `resume`);
//! - `refused`: what happens when the pool refuses it (for `User`, what the wrapper hands back;
//!   for `NotPool`, what the call is).
//!
//! Work that only needs to reach a connection's loop uses `run_on_loop`, which is no pool
//! submission and needs no entry.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// The lane a submission takes (see the module docs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lane {
    /// New work: may be refused by a full pool; the caller answers for it.
    New,
    /// The next step of work admitted already: `resume`, never refused for a full queue.
    Resume,
    /// A public wrapper that forwards its caller's choice of lane.
    User,
    /// Named like a submission, but submits to no pool.
    NotPool,
}

/// One submission in the libraries.
struct Site {
    /// From the workspace root.
    file: &'static str,
    /// `Type::method` or `function`.
    func: &'static str,
    /// Receiver and method, no spaces.
    call: &'static str,
    lane: Lane,
    /// What happens when the pool refuses it.
    refused: &'static str,
}

const fn site(
    file: &'static str,
    func: &'static str,
    call: &'static str,
    lane: Lane,
    refused: &'static str,
) -> Site {
    Site {
        file,
        func,
        call,
        lane,
        refused,
    }
}

use Lane::{New, NotPool, Resume, User};

/// Every call in the libraries named like a pool submission.
#[rustfmt::skip]
const SITES: &[Site] = &[
    // akio-core: the connection's pool handles.
    site("crates/akio-core/src/conn.rs", "ConnInner::execute", "pool.try_execute", User,
        "hands the job back (Err(job)), unrun: the caller answers for it"),
    site("crates/akio-core/src/conn.rs", "ConnInner::execute_batch", "pool.try_execute_batch", User,
        "leaves what the pool cannot take in `jobs`, unrun, for the caller"),
    site("crates/akio-core/src/conn.rs", "ConnInner::resume", "pool.resume", User,
        "hands the job back only when the pool is shut down, the engine has none or the connection is closed"),
    site("crates/akio-core/src/conn.rs", "Conn::spawn_blocking", "pool.try_execute", User,
        "Error::Overloaded to the caller; work and completion dropped unrun"),
    site("crates/akio-core/src/conn.rs", "Conn::execute", "self.inner.execute", User,
        "Error::Overloaded to the caller; work dropped unrun"),
    // akio-quic: a QUIC connection's pool handles, through its UDP socket.
    site("crates/akio-quic/src/lib.rs", "Connection::spawn_blocking", "sock.spawn_blocking", User,
        "Error::Overloaded (Closed when the socket is gone) to the caller"),
    site("crates/akio-quic/src/lib.rs", "Connection::execute", "sock.inner().execute", User,
        "hands the job back, unrun, to the caller"),
    site("crates/akio-quic/src/lib.rs", "Connection::resume", "sock.inner().resume", User,
        "hands the job back only when the socket or the pool is gone"),
    site("crates/akio-quic/src/proto/conn/mod.rs", "Connection::resume_tls", "self.tls.resume", NotPool,
        "the TLS handshake going on after an asynchronous step"),
    // akio-http: the executor, requests on the pool, files.
    site("crates/akio-http/src/pool.rs", "Executor::execute", "self.try_execute", User,
        "Error::Overloaded to the caller; work dropped unrun"),
    site("crates/akio-http/src/pool.rs", "Executor::resume", "c.resume", User,
        "hands the job back only when the pool is shut down or the connection is gone"),
    site("crates/akio-http/src/pool.rs", "Executor::resume", "s.get().resume", User,
        "hands the job back as the transport's ConnSink::resume does"),
    site("crates/akio-http/src/pool.rs", "Executor::try_execute", "c.execute", User,
        "hands the job back to `queue` / `Gather`, which answer 503"),
    site("crates/akio-http/src/pool.rs", "Executor::try_execute", "s.get().execute", User,
        "hands the job back to `queue` / `Gather`, which answer 503"),
    site("crates/akio-http/src/pool.rs", "Executor::try_execute_batch", "c.execute_batch", User,
        "leaves the refused jobs in `jobs` for Gather::drop (503)"),
    site("crates/akio-http/src/pool.rs", "Executor::try_execute_batch", "self.try_execute", User,
        "leaves the refused jobs in `jobs` for Gather::drop (503)"),
    site("crates/akio-http/src/pool.rs", "Gather::drop", "exec.try_execute_batch", New,
        "each refused request runs here with REFUSED set and is answered 503 (Retry-After: 1)"),
    site("crates/akio-http/src/pool.rs", "queue", "exec.try_execute", New,
        "the job runs here with REFUSED set: the request is answered 503 (call_on_pool, detach_to_pool, suspend_to_pool)"),
    site("crates/akio-http/src/pool.rs", "queue_suspended", "s.resume", NotPool,
        "Suspended::resume: hands a suspended request back to its connection"),
    site("crates/akio-http/src/transport.rs", "ConnSink::resume", "self.execute", User,
        "the trait's default, for a transport with no lane for resumed work: what its execute does (H3Out overrides it with Pool::resume)"),
    site("crates/akio-http/src/context.rs", "FilePump::submit", "crate::files::disk_pool().resume", Resume,
        "refused only by a pool shut down: the pump is dropped and its stream, unfinished, closes the connection"),
    site("crates/akio-http/src/files.rs", "Files::serve_prefixed", "disk_pool().try_execute", New,
        "the request is answered 503"),
    site("crates/akio-http/src/files.rs", "Inner::make_pack", "disk_pool().try_execute", New,
        "no compressed copy yet: `making` is cleared and a later request starts it"),
    // akio-h3.
    site("crates/akio-h3/src/lib.rs", "H3Out::execute", "self.c.execute", User,
        "hands the job back (dispatch_conn_on_pool answers 503)"),
    site("crates/akio-h3/src/lib.rs", "H3Out::resume", "self.c.resume", User,
        "hands the job back only when the socket or the pool is gone"),
    site("crates/akio-h3/src/lib.rs", "read_on_pool", "c.resume", Resume,
        "refused only when the socket or the pool is gone: the stream is reset (H3_INTERNAL_ERROR)"),
    // akio-grpc: a call whose handler runs on the pool.
    site("crates/akio-grpc/src/lib.rs", "OnPool::start", "self.exec.execute", New,
        "opening the call: it ends with RESOURCE_EXHAUSTED (server busy)"),
    site("crates/akio-grpc/src/lib.rs", "OnPool::start", "self.exec.resume", Resume,
        "the next message of an open call; refused only by a pool shut down: UNAVAILABLE"),
    // akio-arpc.
    site("crates/akio-arpc/src/lib.rs", "Peer::on_message", "conn.execute", New,
        "the job runs here with REFUSED set and answers SERVER_BUSY"),
    // akio-bittorrent: the disk pool.
    site("crates/akio-bittorrent/src/client/torrent.rs", "TorrentState::start_check", "self.pool.try_execute", New,
        "the torrent goes to Error (\"disk pool refused the check\")"),
    site("crates/akio-bittorrent/src/client/torrent.rs", "TorrentState::start_read", "self.pool.try_execute", New,
        "the peer's block request is dropped (no longer served); the peer asks again or times it out"),
    site("crates/akio-bittorrent/src/client/torrent.rs", "TorrentState::on_hash_request", "self.pool.try_execute", New,
        "the peer's hash request is rejected (HashReject)"),
    site("crates/akio-bittorrent/src/client/torrent.rs", "TorrentState::verify_and_write", "self.pool.resume", Resume,
        "a piece downloaded whole; refused only by a pool shut down: dropped with an Error event"),
    site("crates/akio-bittorrent/src/client/mod.rs", "maybe_save", "client.pool.try_execute", New,
        "the save is skipped; the next resume interval saves (periodic work, not a retry)"),
    site("crates/akio-bittorrent/src/client/mod.rs", "Torrent::resume", "st.resume", NotPool,
        "resumes a paused torrent"),
    // akio-socks: name resolution and GSS-API steps, which may block.
    site("crates/akio-socks/src/client.rs", "Control::advance", "c.spawn_blocking", New,
        "the GSS-API step fails the client handshake (the connection closes)"),
    site("crates/akio-socks/src/lib.rs", "SocksSession::connect", "c.spawn_blocking", New,
        "the CONNECT is answered with a general failure (Failure::Busy)"),
    site("crates/akio-socks/src/lib.rs", "SocksSession::gss_step", "c.spawn_blocking", New,
        "the session closes"),
    site("crates/akio-socks/src/udp.rs", "Assoc::relay_to", "c.spawn_blocking", New,
        "the datagram is dropped, as UDP may"),
    // Named `resume`, no pool: handshakes and encoders going on.
    site("crates/akio-tls/src/proto/conn.rs", "Machine::resume", "s.resume", NotPool,
        "the TLS server handshake going on after an asynchronous step"),
    site("crates/akio-tls/src/proto/conn.rs", "Connection::resume_now", "self.m.resume", NotPool,
        "the TLS handshake going on after an asynchronous step"),
    site("crates/akio-tls/src/quic.rs", "QuicTls::resume_now", "self.m.resume", NotPool,
        "the QUIC TLS handshake going on after an asynchronous step"),
    site("crates/akio-brotli/src/cstream.rs", "Compressor::meta_block", "Encoder::resume", NotPool,
        "an encoder going on from its saved state"),
    site("crates/akio-brotli/src/cstream.rs", "Compressor::meta_block", "Encoder::resume", NotPool,
        "an encoder going on from its saved state"),
    site("crates/akio-zstd/src/cstream.rs", "Compressor::block", "Encoder::resume", NotPool,
        "an encoder going on from its saved state"),
    site("crates/akio-zstd/src/cstream.rs", "Compressor::block", "Encoder::resume", NotPool,
        "an encoder going on from its saved state"),
];

/// Method and function names that hand work to a pool.
const SUBMIT_CALLS: &[&str] = &[
    "try_execute",
    "try_execute_batch",
    "execute_batch",
    "execute",
    "spawn_blocking",
    "resume",
    "detach_to_pool",
];

/// Calls that schedule something for later or wait: after a submission in the same function,
/// they are where a refused submission would be tried again from a timer.
const TIMER_CALLS: &[&str] = &["after(", "after_send(", "sleep(", "schedule(", "Timer::at("];

/// A submission found in the sources.
#[derive(Debug, Clone)]
struct Found {
    file: String,
    func: String,
    call: String,
    line: usize,
    /// A timer call after it in the same function: (line, the call).
    timer_after: Option<(usize, String)>,
}

impl Found {
    fn key(&self) -> (String, String, String) {
        (self.file.clone(), self.func.clone(), self.call.clone())
    }
}

/// The workspace root: two levels above this crate.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

#[test]
fn pool_submissions_are_registered() {
    let found = scan_workspace(&workspace());
    assert!(
        found.len() >= 20,
        "the scan found only {} submissions: is it looking in crates/*/src?",
        found.len()
    );
    let errors = check(&found, SITES);
    assert!(
        errors.is_empty(),
        "pool submissions (see the top of crates/akio/tests/pool_submissions.rs for how to \
         register one):\n\n{}",
        errors.join("\n\n")
    );
}

/// Checks `found` against `sites`; one message per problem.
fn check(found: &[Found], sites: &[Site]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut by_key: BTreeMap<(String, String, String), Vec<&Found>> = BTreeMap::new();
    for f in found {
        by_key.entry(f.key()).or_default().push(f);
    }
    let mut listed: BTreeMap<(String, String, String), Vec<&Site>> = BTreeMap::new();
    for s in sites {
        listed
            .entry((s.file.into(), s.func.into(), s.call.into()))
            .or_default()
            .push(s);
        if s.refused.trim().is_empty() {
            errors.push(format!(
                "{} `{}` `{}`: say what happens when the pool refuses it (`refused`)",
                s.file, s.func, s.call
            ));
        }
        let name = s.call.rsplit(['.', ':']).next().unwrap_or("");
        match s.lane {
            Resume if name != "resume" => errors.push(format!(
                "{} `{}` `{}` is listed as the next step of admitted work (Lane::Resume) but calls \
                 `{name}`, the lane for new work, which a full pool refuses: call `resume` \
                 (`Pool::resume`, `ConnInner::resume`, `Executor::resume`, ...) and keep one \
                 such step queued or running at a time, or list it as Lane::New with what \
                 happens on refusal",
                s.file, s.func, s.call
            )),
            New if name == "resume" => errors.push(format!(
                "{} `{}` `{}` is listed as new work (Lane::New) but calls `resume`, which a full \
                 pool never refuses: new work goes through `try_execute` / `execute`, or list it \
                 as Lane::Resume if it is the next step of work admitted already",
                s.file, s.func, s.call
            )),
            _ => {}
        }
    }
    for (key, fs) in &by_key {
        let n = listed.get(key).map_or(0, Vec::len);
        let (file, func, call) = key;
        let lines: Vec<String> = fs.iter().map(|f| f.line.to_string()).collect();
        if n < fs.len() {
            errors.push(format!(
                "{file}:{} `{func}` calls `{call}`, named like a pool submission, {} time(s), \
                 but SITES lists it {n} time(s). Decide its lane and list it (once per call):\n    \
                 site(\"{file}\", \"{func}\", \"{call}\", New | Resume | User | NotPool, \"what \
                 happens when the pool refuses it\"),",
                lines.join(","),
                fs.len()
            ));
        }
    }
    for (key, ss) in &listed {
        let n = by_key.get(key).map_or(0, Vec::len);
        let (file, func, call) = key;
        if n < ss.len() {
            errors.push(format!(
                "{file} `{func}` `{call}` is listed {} time(s) in SITES but found {n} time(s): \
                 the code moved, was renamed or removed; update or drop the entry",
                ss.len()
            ));
        }
    }
    for f in found {
        let lane = listed
            .get(&f.key())
            .and_then(|ss| ss.first())
            .map(|s| s.lane);
        if lane == Some(NotPool) {
            continue;
        }
        if let Some((line, timer)) = &f.timer_after {
            errors.push(format!(
                "{}:{line}: `{timer}` follows the pool submission `{}` (line {}) in `{}`: a \
                 refused submission is never tried again from a timer (rules.md rule 2). New \
                 work answers for the refusal (503, RESOURCE_EXHAUSTED, an error); the next step \
                 of admitted work uses `resume`, which a full queue does not refuse. A timer \
                 about time (a timeout armed once the work is queued) goes in a function of its \
                 own",
                f.file, f.call, f.line, f.func
            ));
        }
    }
    errors
}

// ---- The scanner -------------------------------------------------------------------------

/// Scans the library sources of the workspace at `root`.
fn scan_workspace(root: &Path) -> Vec<Found> {
    let mut files = Vec::new();
    let crates = root.join("crates");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&crates)
        .expect("crates/")
        .map(|e| e.expect("crates/ entry").path().join("src"))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for d in dirs {
        rust_files(&d, &mut files);
    }
    files.sort();
    let mut skip = BTreeSet::new();
    let mut children: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    let mut scanned = Vec::new();
    for path in &files {
        let src = fs::read_to_string(path).expect("source file");
        let rel = path
            .strip_prefix(root)
            .expect("under the root")
            .to_string_lossy()
            .replace('\\', "/");
        let s = scan_source(&rel, &src);
        for (m, test_only) in s.mods {
            let p = mod_path(path, &m);
            if test_only {
                skip.insert(p.clone());
            }
            children.entry(path.clone()).or_default().push(p);
        }
        scanned.push((path.clone(), s.found));
    }
    // A test-only module's own modules are test-only too.
    let mut todo: Vec<PathBuf> = skip.iter().cloned().collect();
    while let Some(p) = todo.pop() {
        for c in children.get(&p).into_iter().flatten() {
            if skip.insert(c.clone()) {
                todo.push(c.clone());
            }
        }
    }
    scanned
        .into_iter()
        .filter(|(p, _)| !skip.contains(p))
        .flat_map(|(_, f)| f)
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).expect("source dir") {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// A `mod` declared without a body: its name or `#[path]`.
#[derive(Debug, PartialEq)]
enum ModDecl {
    Name(String),
    Path(String),
}

/// The file of module `m` declared in `file`.
fn mod_path(file: &Path, m: &ModDecl) -> PathBuf {
    let dir = file.parent().expect("file in a dir");
    match m {
        ModDecl::Path(p) => dir.join(p),
        ModDecl::Name(n) => {
            let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let base = if matches!(stem, "lib" | "main" | "mod") {
                dir.to_path_buf()
            } else {
                dir.join(stem)
            };
            let flat = base.join(format!("{n}.rs"));
            if flat.exists() {
                flat
            } else {
                base.join(n).join("mod.rs")
            }
        }
    }
}

/// What one file holds.
struct Scanned {
    found: Vec<Found>,
    /// Its `mod x;` declarations, and whether each is test-only.
    mods: Vec<(ModDecl, bool)>,
}

/// Scans one file: `rel` is its path from the workspace root.
fn scan_source(rel: &str, src: &str) -> Scanned {
    let mut code = sanitize(src);
    let mut mods = Vec::new();
    mask_test_code(src, &mut code, &mut mods);
    for (m, _) in declared_mods(src, &code) {
        mods.push((m, false));
    }
    let b = code.as_bytes();
    let (fns, types) = scopes(b);
    let mut found = Vec::new();
    for (pos, name) in submit_calls(b) {
        let line = line_of(b, pos);
        let call = format!("{}{}", receiver(b, pos), &code[pos..pos + name.len()]);
        let call: String = call.chars().filter(|c| !c.is_whitespace()).collect();
        let f = fns
            .iter()
            .filter(|s| s.start < pos && pos < s.end)
            .max_by_key(|s| s.start);
        let (func, timer_after) = match f {
            None => ("-".to_owned(), None),
            Some(f) => {
                let ty = types
                    .iter()
                    .filter(|t| t.start < f.start && f.start < t.end)
                    .max_by_key(|t| t.start);
                let func = match ty {
                    Some(t) => format!("{}::{}", t.name, f.name),
                    None => f.name.clone(),
                };
                // From the end of the call's arguments: the job itself may wait or arm a timer.
                let args = pos
                    + name.len()
                    + b[pos + name.len()..]
                        .iter()
                        .position(|&c| c == b'(')
                        .unwrap_or(0);
                let after = close_of(b, args).map_or(args, |e| e + 1).min(f.end);
                let timer =
                    timer_call(&code[after..f.end]).map(|(o, t)| (line_of(b, after + o), t));
                (func, timer)
            }
        };
        found.push(Found {
            file: rel.to_owned(),
            func,
            call,
            line,
            timer_after,
        });
    }
    Scanned { found, mods }
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn line_of(b: &[u8], pos: usize) -> usize {
    1 + b[..pos].iter().filter(|&&c| c == b'\n').count()
}

/// `src` with comments and the contents of string and character literals blanked (spaces, the
/// newlines kept), so byte offsets and lines stay those of `src`.
fn sanitize(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let prev_ident = i > 0 && is_ident(b[i - 1]);
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            let end = b[i..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(b.len(), |n| i + n);
            blank(&mut out, i, end);
            i = end;
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let (mut depth, mut j) = (1, i + 2);
            while j < b.len() && depth > 0 {
                if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                    depth += 1;
                    j += 2;
                } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if (c == b'r' || (c == b'b' && b.get(i + 1) == Some(&b'r'))) && !prev_ident {
            // A raw string: r"..", r#".."#, br"..".
            let mut j = if c == b'b' { i + 2 } else { i + 1 };
            let hashes = b[j..].iter().take_while(|&&c| c == b'#').count();
            j += hashes;
            if b.get(j) == Some(&b'"') {
                let close: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                let body = j + 1;
                let end = b[body..]
                    .windows(close.len())
                    .position(|w| w == close.as_slice())
                    .map_or(b.len(), |n| body + n);
                blank(&mut out, body, end);
                i = (end + close.len()).min(b.len());
            } else {
                i += 1;
            }
        } else if c == b'"' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = j.min(b.len());
            blank(&mut out, i + 1, end);
            i = end + 1;
        } else if c == b'\'' {
            // A character literal, or a lifetime / label (left alone).
            if b.get(i + 1) == Some(&b'\\') {
                let mut j = i + 2;
                while j < b.len() && b[j] != b'\'' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                let end = j.min(b.len());
                blank(&mut out, i + 1, end);
                i = end + 1;
            } else {
                // One character (maybe several bytes), then a quote.
                let ch = src[i + 1..].chars().next().map_or(0, char::len_utf8);
                if ch > 0 && b.get(i + 1 + ch) == Some(&b'\'') {
                    blank(&mut out, i + 1, i + 1 + ch);
                    i += 2 + ch;
                } else {
                    i += 1;
                }
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking keeps UTF-8")
}

/// Blanks in `code` the items and statements under a `#[cfg(..)]` that names `test` (and not
/// `not(test)`), and records the `mod x;` among them in `mods` as test-only.
fn mask_test_code(src: &str, code: &mut String, mods: &mut Vec<(ModDecl, bool)>) {
    // `#![cfg(test)]`: the whole file.
    if let Some(n) = code.find("#![cfg(") {
        let attr_end = close_of(code.as_bytes(), n + 2).unwrap_or(code.len() - 1);
        let attr = &code[n..=attr_end];
        if words(attr).any(|w| w == "test") && !attr.contains("not(test") {
            *code = code.replace(|c: char| c != '\n', " ");
            return;
        }
    }
    let mut from = 0;
    while let Some(n) = code[from..].find("#[cfg(") {
        let at = from + n;
        let b = code.as_bytes();
        let Some(attr_end) = close_of(b, at + 1) else {
            break;
        };
        let attr = &code[at..=attr_end];
        let names_test = words(attr).any(|w| w == "test") && !attr.contains("not(test");
        if !names_test {
            from = attr_end + 1;
            continue;
        }
        // Further attributes, then the item: up to a `;` or through a `{..}` block.
        let mut i = attr_end + 1;
        let mut path = None;
        loop {
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if b.get(i) == Some(&b'#') && b.get(i + 1) == Some(&b'[') {
                let Some(e) = close_of(b, i + 1) else { break };
                let a = &src[i..=e];
                if code[i..=e].starts_with("#[path") {
                    path = a.split('"').nth(1).map(str::to_owned);
                }
                i = e + 1;
            } else {
                break;
            }
        }
        let item_start = i;
        let mut depth = 0i32;
        let mut end = b.len();
        while i < b.len() {
            match b[i] {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b';' if depth == 0 => {
                    end = i + 1;
                    break;
                }
                b'{' if depth == 0 => {
                    end = close_of(b, i).map_or(b.len(), |e| e + 1);
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        let item: Vec<&str> = words(&code[item_start..end]).collect();
        if code[item_start..end].trim_end().ends_with(';') {
            if let Some(k) = item.iter().position(|w| *w == "mod") {
                if let Some(name) = item.get(k + 1) {
                    mods.push((
                        match path.take() {
                            Some(p) => ModDecl::Path(p),
                            None => ModDecl::Name((*name).to_owned()),
                        },
                        true,
                    ));
                }
            }
        }
        let mut bytes = std::mem::take(code).into_bytes();
        for c in &mut bytes[at..end] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
        *code = String::from_utf8(bytes).expect("blanking keeps UTF-8");
        from = end;
    }
}

/// The `mod x;` declarations left in `code` (after [`mask_test_code`]), with a `#[path]` just
/// before one taken from `src`.
fn declared_mods(src: &str, code: &str) -> Vec<(ModDecl, bool)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    for (pos, w) in word_positions(code) {
        if w != "mod" {
            continue;
        }
        let rest = &code[pos + 3..];
        let name: String = rest
            .trim_start()
            .bytes()
            .take_while(|&c| is_ident(c))
            .map(char::from)
            .collect();
        let after = rest.trim_start()[name.len()..].trim_start();
        if name.is_empty() || !after.starts_with(';') {
            continue;
        }
        // Attributes since the previous item.
        let start = b[..pos]
            .iter()
            .rposition(|&c| c == b';' || c == b'}' || c == b'{')
            .map_or(0, |p| p + 1);
        let path = src[start..pos]
            .find("#[path")
            .and_then(|p| src[start + p..pos].split('"').nth(1))
            .map(str::to_owned);
        out.push((
            match path {
                Some(p) => ModDecl::Path(p),
                None => ModDecl::Name(name),
            },
            false,
        ));
    }
    out
}

fn words(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
}

/// Each identifier-like word of `s` and its offset.
fn word_positions(s: &str) -> Vec<(usize, &str)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if is_ident(b[i]) && (i == 0 || !is_ident(b[i - 1])) {
            let mut j = i;
            while j < b.len() && is_ident(b[j]) {
                j += 1;
            }
            out.push((i, &s[i..j]));
            i = j;
        } else {
            i += 1;
        }
    }
    out
}

/// The offset of the bracket closing the one at `open` (`(`, `[` or `{`).
fn close_of(b: &[u8], open: usize) -> Option<usize> {
    let (o, c) = match b.get(open)? {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        b'{' => (b'{', b'}'),
        _ => return None,
    };
    let mut depth = 0usize;
    for (i, &x) in b.iter().enumerate().skip(open) {
        if x == o {
            depth += 1;
        } else if x == c {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// The offset of the bracket opening the one closing at `close`.
fn open_of(b: &[u8], close: usize) -> Option<usize> {
    let (o, c) = match b.get(close)? {
        b')' => (b'(', b')'),
        b']' => (b'[', b']'),
        _ => return None,
    };
    let mut depth = 0usize;
    for i in (0..=close).rev() {
        if b[i] == c {
            depth += 1;
        } else if b[i] == o {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// A function body or an `impl` / `trait` block: its name and the offsets of its braces.
#[derive(Debug)]
struct Scope {
    name: String,
    start: usize,
    end: usize,
}

/// The function bodies and the `impl` / `trait` blocks of `b`.
fn scopes(b: &[u8]) -> (Vec<Scope>, Vec<Scope>) {
    let code = std::str::from_utf8(b).expect("UTF-8");
    let (mut fns, mut types) = (Vec::new(), Vec::new());
    for (pos, w) in word_positions(code) {
        let kw_end = pos + w.len();
        match w {
            "fn" | "trait" => {
                let rest = &code[kw_end..];
                let name: String = rest
                    .trim_start()
                    .bytes()
                    .take_while(|&c| is_ident(c))
                    .map(char::from)
                    .collect();
                if name.is_empty() {
                    continue; // a `fn(..)` type
                }
                if let Some((start, end)) = body(b, kw_end) {
                    let s = Scope { name, start, end };
                    if w == "fn" {
                        fns.push(s);
                    } else {
                        types.push(s);
                    }
                }
            }
            "impl" if item_position(b, pos) => {
                if let Some((start, end)) = body(b, kw_end) {
                    let name = impl_type(&code[kw_end..start]);
                    types.push(Scope { name, start, end });
                }
            }
            _ => {}
        }
    }
    (fns, types)
}

/// Whether the word at `pos` starts an item (not `impl Trait` in a type).
fn item_position(b: &[u8], pos: usize) -> bool {
    let mut i = pos;
    while i > 0 && b[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i == 0 || matches!(b[i - 1], b';' | b'{' | b'}' | b']') {
        return true;
    }
    let mut j = i;
    while j > 0 && is_ident(b[j - 1]) {
        j -= 1;
    }
    matches!(&b[j..i], b"unsafe" | b"default")
}

/// The braces of the block that follows a header starting at `from`, or `None` when the
/// header ends with `;` (no body).
fn body(b: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut depth = 0i32;
    for i in from..b.len() {
        match b[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b';' if depth == 0 => return None,
            b'{' if depth == 0 => return Some((i, close_of(b, i)?)),
            _ => {}
        }
    }
    None
}

/// The type an `impl` header (what follows `impl`, up to its `{`) is for.
fn impl_type(h: &str) -> String {
    let mut h = h.trim();
    if h.starts_with('<') {
        // Generic parameters: up to the matching `>`, `->` aside.
        let b = h.as_bytes();
        let mut depth = 0i32;
        let mut end = 0;
        for i in 0..b.len() {
            match b[i] {
                b'<' => depth += 1,
                b'>' if i == 0 || b[i - 1] != b'-' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        h = h[end..].trim();
    }
    // `Trait for Type`: the type, at depth 0 of `<..>`.
    let b = h.as_bytes();
    let mut depth = 0i32;
    let mut target = h;
    for (i, _) in h.char_indices() {
        match b[i] {
            b'<' => depth += 1,
            b'>' if i == 0 || b[i - 1] != b'-' => depth -= 1,
            _ => {}
        }
        if depth == 0
            && h[i..].starts_with("for")
            && (i == 0 || !is_ident(b[i - 1]))
            && !b.get(i + 3).copied().is_some_and(is_ident)
        {
            target = &h[i + 3..];
        }
    }
    let target = target.split(" where").next().unwrap_or("").trim();
    let target = target
        .trim_start_matches('&')
        .trim_start_matches("mut ")
        .trim_start_matches("dyn ")
        .trim();
    let path: String = target
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == ':')
        .collect();
    path.rsplit("::").next().unwrap_or("").to_owned()
}

/// Each call named like a submission (`.name(`, `::name(`, `.name::<..>(`): the offset of its
/// name, and the name.
fn submit_calls(b: &[u8]) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for i in 1..b.len() {
        if is_ident(b[i - 1]) || !is_ident(b[i]) {
            continue;
        }
        let path = b[i - 1] == b'.' || (i >= 2 && &b[i - 2..i] == b"::");
        if !path {
            continue;
        }
        for &name in SUBMIT_CALLS {
            let n = name.as_bytes();
            if !b[i..].starts_with(n) || b.get(i + n.len()).copied().is_some_and(is_ident) {
                continue;
            }
            let mut j = i + n.len();
            if b[j..].starts_with(b"::<") {
                let mut depth = 0;
                while j < b.len() {
                    match b[j] {
                        b'<' => depth += 1,
                        b'>' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
            }
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if b.get(j) == Some(&b'(') {
                out.push((i, name));
            }
        }
    }
    out
}

/// The receiver or path before the call whose name starts at `name_at`, with the `.` or `::`
/// that joins them: `self.exec.`, `crate::files::disk_pool().`, `Pool::`.
fn receiver(b: &[u8], name_at: usize) -> String {
    let mut i = name_at;
    loop {
        // `i` is just after a `.` or `::` (or at the name); step over it.
        if i >= 1 && b[i - 1] == b'.' {
            i -= 1;
        } else if i >= 2 && &b[i - 2..i] == b"::" {
            i -= 2;
        } else {
            break;
        }
        while i > 0 && b[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        while i > 0 && b[i - 1] == b'?' {
            i -= 1;
        }
        while i > 0 && matches!(b[i - 1], b')' | b']') {
            match open_of(b, i - 1) {
                Some(o) => i = o,
                None => break,
            }
        }
        let end = i;
        while i > 0 && is_ident(b[i - 1]) {
            i -= 1;
        }
        if i == end && !matches!(b.get(end), Some(b'(' | b'[')) {
            break;
        }
        while i > 0 && b[i - 1].is_ascii_whitespace() {
            // A chain broken over lines continues only with a `.` or `::` before.
            let mut k = i - 1;
            while k > 0 && b[k].is_ascii_whitespace() {
                k -= 1;
            }
            if b[k] == b'.' || (k >= 1 && &b[k - 1..=k] == b"::") {
                i = k + 1;
            } else {
                break;
            }
        }
    }
    String::from_utf8_lossy(&b[i..name_at]).into_owned()
}

/// The first timer call in `text`: its offset and which.
fn timer_call(text: &str) -> Option<(usize, String)> {
    let b = text.as_bytes();
    TIMER_CALLS
        .iter()
        .flat_map(|t| {
            text.match_indices(t)
                .filter(|(o, _)| *o == 0 || !is_ident(b[o - 1]))
                .map(|(o, t)| (o, t.trim_end_matches('(').to_owned()))
                .collect::<Vec<_>>()
        })
        .min_by_key(|(o, _)| *o)
}

// ---- The scanner's own tests ---------------------------------------------------------------

fn scan(src: &str) -> Vec<Found> {
    scan_source("crates/x/src/lib.rs", src).found
}

#[test]
fn comments_strings_and_chars_are_blanked() {
    let src = "let a = \"x.execute(job)\"; // y.execute(job)\n\
               /* z.resume(j) /* nested */ */ let c = '\"'; let l: &'a str = r#\"q.resume(\"#;\n\
               let e = '\\''; f.execute(job);";
    let code = sanitize(src);
    assert_eq!(code.len(), src.len());
    assert_eq!(code.lines().count(), src.lines().count());
    let found: Vec<_> = submit_calls(code.as_bytes())
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert_eq!(found, ["execute"], "only the call in code: {code}");
    assert!(
        code.contains("&'a str"),
        "a lifetime is not a character literal"
    );
}

#[test]
fn test_code_is_left_out() {
    let src = r#"
fn real(p: &Pool) { let _ = p.try_execute(job); }
#[cfg(test)]
mod tests {
    fn t(p: &Pool) { p.try_execute(job).unwrap(); }
}
#[cfg(test)]
#[path = "quic_tests.rs"]
mod qt;
#[cfg(any(test, feature = "fuzzing"))]
pub mod fuzzing;
#[cfg(not(test))]
fn kept(p: &Pool) { let _ = p.resume(job); }
fn stmt(p: &Pool) {
    #[cfg(test)]
    COUNT.fetch_add(1, Relaxed);
    #[cfg(test)]
    { let _ = p.try_execute(job); }
}
mod plain;
"#;
    let s = scan_source("crates/x/src/lib.rs", src);
    let calls: Vec<_> = s
        .found
        .iter()
        .map(|f| (f.func.as_str(), f.call.as_str()))
        .collect();
    assert_eq!(calls, [("real", "p.try_execute"), ("kept", "p.resume")]);
    assert_eq!(
        s.mods,
        [
            (ModDecl::Path("quic_tests.rs".into()), true),
            (ModDecl::Name("fuzzing".into()), true),
            (ModDecl::Name("plain".into()), false),
        ]
    );
}

#[test]
fn functions_and_receivers_are_named() {
    let src = r"
impl<H: Handler> Conn<H> {
    pub fn execute(&self, work: impl FnOnce() + Send + 'static) -> Result<()> {
        self.inner
            .execute(Box::new(work))
            .map_err(|_| Error::Overloaded)
    }
}
impl ConnSink for H3Out {
    fn resume(&self, job: Job) -> Result<(), Job> { self.c.resume(job) }
}
trait Sink {
    fn go(&self);
    fn resume(&self, job: Job) -> Result<(), Job> { self.execute(job) }
}
fn free() {
    let _ = crate::files::disk_pool().resume(Box::new(move || self.run()));
    match s.get()?.execute(job) { _ => {} }
    let _ = Pool::try_execute(&p, job);
    let _ = c.spawn_blocking::<u8, _, _>(w, d);
}
";
    let calls: Vec<_> = scan(src)
        .into_iter()
        .map(|f| format!("{} {}", f.func, f.call))
        .collect();
    assert_eq!(
        calls,
        [
            "Conn::execute self.inner.execute",
            "H3Out::resume self.c.resume",
            "Sink::resume self.execute",
            "free crate::files::disk_pool().resume",
            "free s.get()?.execute",
            "free Pool::try_execute",
            "free c.spawn_blocking",
        ]
    );
}

/// `FilePump::submit` and HTTP/3's `read_on_pool` as they were before `Pool::resume`: a full
/// pool was asked again every 5 ms from a timer. The check finds both retries.
#[test]
fn a_refusal_retried_from_a_timer_is_found() {
    let src = r"
impl FilePump {
    fn submit(self) {
        let cell = Arc::new(Mutex::new(Some(self)));
        let job = Box::new(move || {});
        if crate::files::disk_pool().try_execute(job).is_err() {
            let p = cell.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(mut p) = p {
                p.refused += 1;
                if p.refused <= PUMP_RETRIES {
                    crate::timer::after(PUMP_RETRY, move || p.submit());
                }
            }
        }
    }
}
fn read_on_pool(r: FileRead, refused: u32) {
    let queued = c.spawn_blocking(move || {});
    let Err(e) = queued else { return };
    match e {
        akio_quic::Error::Overloaded if refused < READ_RETRIES => {
            akio_http::transport::after(READ_RETRY, move || read_on_pool(r, refused + 1));
        }
        _ => {}
    }
}
fn backoff(p: &Pool) {
    while p.try_execute(job()).is_err() {
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn timeout_first(p: &Pool) {
    let t = timer::after(d, || {});
    let _ = p.try_execute(job);
}
";
    let found = scan(src);
    let timers: Vec<_> = found
        .iter()
        .map(|f| {
            (
                f.func.as_str(),
                f.timer_after.as_ref().map(|t| t.1.as_str()),
            )
        })
        .collect();
    assert_eq!(
        timers,
        [
            ("FilePump::submit", Some("after")),
            ("read_on_pool", Some("after")),
            ("backoff", Some("sleep")),
            ("timeout_first", None),
        ]
    );
    let sites = [
        site(
            "crates/x/src/lib.rs",
            "FilePump::submit",
            "crate::files::disk_pool().try_execute",
            Resume,
            "x",
        ),
        site(
            "crates/x/src/lib.rs",
            "read_on_pool",
            "c.spawn_blocking",
            New,
            "x",
        ),
        site("crates/x/src/lib.rs", "backoff", "p.try_execute", New, "x"),
        site(
            "crates/x/src/lib.rs",
            "timeout_first",
            "p.try_execute",
            New,
            "x",
        ),
        site("crates/x/src/lib.rs", "gone", "p.try_execute", New, "x"),
    ];
    let errors = check(&found, &sites);
    let has = |what: &str| errors.iter().filter(|e| e.contains(what)).count();
    assert_eq!(
        has("Lane::Resume) but calls `try_execute`"),
        1,
        "{errors:#?}"
    );
    assert_eq!(has("never tried again from a timer"), 3, "{errors:#?}");
    assert_eq!(
        has("`gone` `p.try_execute` is listed 1 time(s)"),
        1,
        "{errors:#?}"
    );
    assert_eq!(errors.len(), 5, "{errors:#?}");
    // An unlisted call is named with the entry to add.
    let errors = check(&found[..1], &[]);
    assert_eq!(errors.len(), 2, "{errors:#?}");
    assert!(errors[0].contains(
        "site(\"crates/x/src/lib.rs\", \"FilePump::submit\", \"crate::files::disk_pool().try_execute\""
    ));
}
