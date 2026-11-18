//! Fast resume (ADR-033) on loopback with files on disk: a client restarted after `close`, or
//! after being killed mid-download, finishes without hash-checking the pieces it had; files
//! changed since the save are checked again; damaged resume data is refused; v1, v2 and hybrid
//! torrents; v2 piece layers fetched for a magnet link survive a restart.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use only_bittorrent::client::{
    AddOptions, Client, ClientConfig, MemoryStorage, RateLimits, SeedLimits, Torrent, TorrentEvent,
    TorrentStatus,
};
use only_bittorrent::metainfo::{Builder, Info, InfoHash, MetaInfo, TorrentVersion};

const VERSIONS: [TorrentVersion; 3] = [
    TorrentVersion::V1,
    TorrentVersion::V2,
    TorrentVersion::Hybrid,
];

fn data(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn files() -> Vec<(Vec<String>, Vec<u8>)> {
    vec![
        (vec!["a.bin".to_owned()], data(900_000, 3)),
        (vec!["b.bin".to_owned()], data(500_000, 5)),
        (vec!["c.txt".to_owned()], data(20_000, 7)),
    ]
}

fn torrent(v: TorrentVersion) -> (MetaInfo, Vec<u8>) {
    let f = files();
    let mi = Builder::new("rt")
        .piece_length(32 * 1024)
        .version(v)
        .build_files(&f)
        .unwrap();
    let mi = MetaInfo::parse(&mi.to_bytes()).unwrap();
    let mut out = vec![0u8; mi.info.total_length as usize];
    for fe in mi.info.files.iter().filter(|f| !f.padding) {
        let (_, d) = f.iter().find(|(p, _)| *p == fe.path).unwrap();
        out[fe.offset as usize..fe.offset as usize + d.len()].copy_from_slice(d);
    }
    (mi, out)
}

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let mut b = [0u8; 4];
        let t = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        b.copy_from_slice(&(t as u32).to_le_bytes());
        let p = std::env::temp_dir().join(format!(
            "only-bt-resume-{tag}-{}-{}",
            std::process::id(),
            u32::from_le_bytes(b)
        ));
        std::fs::create_dir_all(&p).unwrap();
        Dir(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Events = Arc<Mutex<Vec<TorrentEvent>>>;

fn cfg(dir: &Path, resume: bool) -> (ClientConfig, Events) {
    let mut c = ClientConfig::default();
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.dht = false;
    c.lsd = false;
    c.trackers = false;
    c.data_dir = dir.join("data");
    if resume {
        c.resume_dir = Some(dir.join("resume"));
    }
    let ev: Events = Arc::default();
    let e = ev.clone();
    c.on_event = Some(Arc::new(move |_, x: &TorrentEvent| {
        e.lock().unwrap().push(x.clone());
    }));
    (c, ev)
}

fn seeder(mi: &MetaInfo, payload: &[u8]) -> Client {
    let mut c = ClientConfig::default();
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.dht = false;
    c.lsd = false;
    c.trackers = false;
    let client = Client::new(c).unwrap();
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::with_data(payload.to_vec())));
    let t = client.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(10)), "seeder check");
    client
}

fn resume_file(dir: &Path, ih: &InfoHash) -> PathBuf {
    dir.join("resume").join(format!("{}.resume", ih.to_hex()))
}

/// The bytes on disk, as the piece space (zeros for padding).
fn on_disk(dir: &Path, info: &Info) -> Vec<u8> {
    let mut out = vec![0u8; info.total_length as usize];
    for f in info.files.iter().filter(|f| !f.padding) {
        let mut p = dir.join("data").join(&info.name);
        p.extend(&f.path);
        let d = std::fs::read(&p).unwrap_or_default();
        let n = d.len().min(f.length as usize);
        out[f.offset as usize..f.offset as usize + n].copy_from_slice(&d[..n]);
    }
    out
}

fn wait_for(t: &Torrent, what: &str, f: impl Fn(&Torrent) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !f(t) {
        assert!(Instant::now() < deadline, "{what}: {:?}", t.stats());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn accepted(ev: &Events) -> Option<(usize, usize)> {
    ev.lock().unwrap().iter().find_map(|e| match e {
        TorrentEvent::ResumeAccepted { pieces, rechecking } => Some((*pieces, *rechecking)),
        _ => None,
    })
}

/// Waits for the start-up check to be reported (events come after waiters wake).
fn wait_checked(ev: &Events) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ev
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, TorrentEvent::Checked { .. }))
    {
        assert!(Instant::now() < deadline, "no check");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Downloads `mi` to `dir` and closes the client (saving resume data).
fn download_and_close(dir: &Path, mi: &MetaInfo, seed: &Client) -> (u64, u64) {
    let (c, _) = cfg(dir, true);
    let client = Client::new(c).unwrap();
    let mut o = AddOptions::default();
    o.peers = vec![seed.listen_addr()];
    let t = client.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(30)), "{:?}", t.stats());
    let s = t.stats();
    assert_eq!(s.pieces_checked, 0, "nothing on disk to check");
    client.close();
    assert!(resume_file(dir, &mi.info_hash).exists());
    (s.downloaded, s.uploaded)
}

#[test]
fn restart_after_close_without_rehash() {
    for v in VERSIONS {
        let (mi, payload) = torrent(v);
        let n = mi.info.num_pieces();
        let seed = seeder(&mi, &payload);
        let dir = Dir::new("close");
        let (downloaded, _) = download_and_close(&dir.0, &mi, &seed);
        seed.close();
        // No peer at all: everything comes from disk and the resume file.
        let (c, ev) = cfg(&dir.0, true);
        let client = Client::new(c).unwrap();
        let t = client
            .add_torrent(mi.clone(), AddOptions::default())
            .unwrap();
        assert!(t.wait_complete(Duration::from_secs(10)), "{v:?}");
        wait_checked(&ev);
        let s = t.stats();
        assert_eq!(s.status, TorrentStatus::Seeding);
        assert_eq!(s.pieces_checked, 0, "{v:?}: no piece hashed again");
        assert_eq!(accepted(&ev), Some((n, 0)), "{v:?}");
        assert_eq!(s.total_downloaded, downloaded, "{v:?}: totals carried over");
        assert_eq!(s.downloaded, 0);
        assert!(on_disk(&dir.0, &mi.info) == payload);
        client.close();
        // Without resume data the same data is checked in full.
        let (c, ev) = cfg(&dir.0, false);
        let client = Client::new(c).unwrap();
        let t = client.add_torrent(mi, AddOptions::default()).unwrap();
        assert!(t.wait_complete(Duration::from_secs(10)), "{v:?}");
        wait_checked(&ev);
        assert_eq!(t.stats().pieces_checked, n as u64);
        assert_eq!(accepted(&ev), None);
        client.close();
    }
}

#[test]
fn changed_file_is_rechecked() {
    for v in VERSIONS {
        let (mi, payload) = torrent(v);
        let n = mi.info.num_pieces();
        let seed = seeder(&mi, &payload);
        let dir = Dir::new("changed");
        download_and_close(&dir.0, &mi, &seed);
        // Change one byte of b.bin (same size) and its time.
        let b = mi
            .info
            .files
            .iter()
            .position(|f| f.path == ["b.bin"])
            .unwrap();
        let fe = &mi.info.files[b];
        let path = dir.0.join("data").join("rt").join("b.bin");
        let mut d = std::fs::read(&path).unwrap();
        d[1000] ^= 0xff;
        std::fs::write(&path, &d).unwrap();
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(SystemTime::now() + Duration::from_secs(5))
            .unwrap();
        drop(f);
        let range = mi.info.file_pieces(b);
        let bad = ((fe.offset + 1000) / u64::from(mi.info.piece_length)) as usize;

        let (c, ev) = cfg(&dir.0, true);
        let client = Client::new(c).unwrap();
        let t = client
            .add_torrent(mi.clone(), AddOptions::default())
            .unwrap();
        wait_checked(&ev);
        let s = t.stats();
        assert_eq!(accepted(&ev), Some((n - range.len(), range.len())), "{v:?}");
        assert_eq!(s.pieces_checked, range.len() as u64, "{v:?}");
        // The seeder (a peer the resume data remembers) brings back the damaged piece, and
        // only that one.
        assert!(t.wait_complete(Duration::from_secs(30)), "{v:?}");
        let s = t.stats();
        let verified = || -> Vec<u32> {
            ev.lock()
                .unwrap()
                .iter()
                .filter_map(|e| match e {
                    TorrentEvent::PieceVerified(i) => Some(*i),
                    _ => None,
                })
                .collect()
        };
        // Events reach the callback after waiters wake.
        let deadline = Instant::now() + Duration::from_secs(10);
        while verified().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(verified(), vec![bad as u32], "{v:?}");
        assert_eq!(s.pieces_checked, range.len() as u64, "{v:?}");
        assert!(on_disk(&dir.0, &mi.info) == payload, "{v:?}");
        client.close();
        seed.close();
    }
}

#[test]
fn damaged_or_foreign_resume_data_is_refused() {
    let (mi, payload) = torrent(TorrentVersion::V1);
    let n = mi.info.num_pieces();
    let seed = seeder(&mi, &payload);
    let dir = Dir::new("damaged");
    download_and_close(&dir.0, &mi, &seed);
    seed.close();
    let file = resume_file(&dir.0, &mi.info_hash);
    let good = std::fs::read(&file).unwrap();
    let mut flipped = good.clone();
    let at = flipped.len() / 3;
    flipped[at] ^= 0x20;
    let (other, _) = torrent(TorrentVersion::Hybrid);
    let other_dir = Dir::new("other");
    let other_seed = seeder(&other, &torrent(TorrentVersion::Hybrid).1);
    download_and_close(&other_dir.0, &other, &other_seed);
    other_seed.close();
    let foreign = std::fs::read(resume_file(&other_dir.0, &other.info_hash)).unwrap();
    for (name, bytes) in [
        ("truncated", good[..good.len() - 7].to_vec()),
        ("flipped", flipped),
        ("empty", Vec::new()),
        ("foreign", foreign),
    ] {
        std::fs::write(&file, &bytes).unwrap();
        let (c, ev) = cfg(&dir.0, true);
        let client = Client::new(c).unwrap();
        let t = client
            .add_torrent(mi.clone(), AddOptions::default())
            .unwrap();
        assert!(t.wait_complete(Duration::from_secs(10)), "{name}");
        assert!(
            ev.lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, TorrentEvent::ResumeRejected(_))),
            "{name}"
        );
        assert_eq!(accepted(&ev), None, "{name}");
        assert_eq!(t.stats().pieces_checked, n as u64, "{name}: full check");
        client.close();
    }
    // `add_resume` refuses damaged data outright.
    let (c, _) = cfg(&dir.0, false);
    let client = Client::new(c).unwrap();
    assert!(
        client
            .add_resume(&good[..10], AddOptions::default())
            .is_err()
    );
    client.close();
}

#[test]
fn export_import_keeps_state() {
    let (mi, payload) = torrent(TorrentVersion::Hybrid);
    let seed = seeder(&mi, &payload);
    let dir = Dir::new("export");
    let (c, _) = cfg(&dir.0, false);
    let client = Client::new(c).unwrap();
    let mut o = AddOptions::default();
    o.peers = vec![seed.listen_addr()];
    let t = client.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(30)));
    t.set_seed_limits(SeedLimits::new(Some(4.0), None));
    t.set_rate_limits(RateLimits::new(Some(1 << 20), None));
    t.add_web_seed("http://127.0.0.1:1/ws/");
    t.pause();
    wait_for(&t, "paused", |t| t.stats().status == TorrentStatus::Paused);
    let bytes = t.resume_data().unwrap();
    let downloaded = t.stats().downloaded;
    client.close();
    seed.close();

    let (c, ev) = cfg(&dir.0, false);
    let client = Client::new(c).unwrap();
    let t = client.add_resume(&bytes, AddOptions::default()).unwrap();
    assert_eq!(t.info_hash(), mi.info_hash);
    assert_eq!(t.info_hash_v2(), mi.info_hash_v2);
    wait_checked(&ev);
    let s = t.stats();
    assert_eq!(s.pieces_have, mi.info.num_pieces());
    assert_eq!(
        s.status,
        TorrentStatus::Paused,
        "saved paused, starts paused"
    );
    assert_eq!(s.pieces_checked, 0);
    assert_eq!(s.total_downloaded, downloaded);
    assert_eq!(accepted(&ev), Some((mi.info.num_pieces(), 0)));
    assert_eq!(t.seed_limits(), SeedLimits::new(Some(4.0), None));
    assert_eq!(t.rate_limits(), RateLimits::new(Some(1 << 20), None));
    assert!(
        t.metainfo()
            .unwrap()
            .url_list
            .contains(&"http://127.0.0.1:1/ws/".to_owned())
    );
    assert_eq!(t.info().unwrap().raw(), mi.info.raw());
    t.resume();
    wait_for(&t, "seeding", |t| {
        t.stats().status == TorrentStatus::Seeding
    });
    client.close();
}

#[test]
fn v2_magnet_layers_survive_restart() {
    let (mi, payload) = torrent(TorrentVersion::V2);
    let seed = seeder(&mi, &payload);
    let dir = Dir::new("magnet");
    let (c, _) = cfg(&dir.0, true);
    let client = Client::new(c).unwrap();
    let mut m = mi.magnet();
    m.peers.push(seed.listen_addr());
    let t = client
        .add_magnet(&m.to_string(), AddOptions::default())
        .unwrap();
    assert!(t.wait_complete(Duration::from_secs(30)), "{:?}", t.stats());
    assert_eq!(t.piece_layers(), mi.piece_layers);
    client.close();
    seed.close();
    let bytes = std::fs::read(resume_file(&dir.0, &mi.info_hash)).unwrap();

    // The magnet link again, no peers: metadata and layers come from the resume file.
    let (c, ev) = cfg(&dir.0, true);
    let client = Client::new(c).unwrap();
    let t = client
        .add_magnet(&mi.magnet().to_string(), AddOptions::default())
        .unwrap();
    assert!(t.wait_complete(Duration::from_secs(10)), "{:?}", t.stats());
    wait_checked(&ev);
    assert_eq!(t.piece_layers(), mi.piece_layers);
    assert_eq!(t.stats().pieces_checked, 0);
    assert_eq!(accepted(&ev), Some((mi.info.num_pieces(), 0)));
    client.close();
    // And from the bytes alone.
    let (c, _) = cfg(&dir.0, false);
    let client = Client::new(c).unwrap();
    let t = client.add_resume(&bytes, AddOptions::default()).unwrap();
    assert!(t.wait_complete(Duration::from_secs(10)));
    assert_eq!(t.piece_layers(), mi.piece_layers);
    assert_eq!(t.stats().pieces_checked, 0);
    client.close();
}

// ---- killed mid-download ------------------------------------------------------------------

const CHILD_ENV: &str = "ONLY_BT_RESUME_CHILD";

/// The child process of `killed_mid_download_resumes_without_rehash`: downloads slowly,
/// saving resume data every 200 ms, until killed. A no-op as an ordinary test.
#[test]
fn resume_kill_child() {
    let Ok(dir) = std::env::var(CHILD_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let mi = MetaInfo::load(dir.join("t.torrent")).unwrap();
    let peer = std::fs::read_to_string(dir.join("peer")).unwrap();
    let (mut c, _) = cfg(&dir, true);
    c.resume_interval = Duration::from_millis(200);
    let client = Client::new(c).unwrap();
    let mut o = AddOptions::default();
    o.peers = vec![peer.trim().parse().unwrap()];
    o.rate_limits = RateLimits::new(None, Some(300 * 1024));
    let _t = client.add_torrent(mi, o).unwrap();
    std::thread::sleep(Duration::from_secs(60));
    std::process::exit(3); // never finishes normally
}

#[test]
fn killed_mid_download_resumes_without_rehash() {
    for v in VERSIONS {
        let (mi, payload) = torrent(v);
        let n = mi.info.num_pieces();
        let seed = seeder(&mi, &payload);
        let dir = Dir::new("kill");
        std::fs::write(dir.0.join("t.torrent"), mi.to_bytes()).unwrap();
        std::fs::write(dir.0.join("peer"), seed.listen_addr().to_string()).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "resume_kill_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, &dir.0)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Let it save a few times with part of the data, then kill it (SIGKILL: no close).
        let file = resume_file(&dir.0, &mi.info_hash);
        let deadline = Instant::now() + Duration::from_secs(30);
        while !file.exists() {
            assert!(Instant::now() < deadline, "{v:?}: no resume file");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(1800));
        child.kill().unwrap();
        child.wait().unwrap();

        let (c, ev) = cfg(&dir.0, true);
        let client = Client::new(c).unwrap();
        let t = client
            .add_torrent(mi.clone(), AddOptions::default())
            .unwrap();
        // The child's rate limit came with its resume data.
        t.set_rate_limits(RateLimits::default());
        wait_checked(&ev);
        let (had, rechecking) = accepted(&ev).expect("resume data accepted");
        assert!(had > 0 && had < n, "{v:?}: killed mid-download ({had}/{n})");
        assert_eq!(rechecking, 0, "{v:?}");
        assert_eq!(t.stats().pieces_checked, 0, "{v:?}: no piece hashed again");
        // The seeder is among the peers the resume data remembers.
        assert!(t.wait_complete(Duration::from_secs(30)), "{v:?}");
        let s = t.stats();
        assert_eq!(s.pieces_checked, 0, "{v:?}");
        assert_eq!(s.hash_fails, 0, "{v:?}");
        assert!(on_disk(&dir.0, &mi.info) == payload, "{v:?}: data intact");
        client.close();
        seed.close();
    }
}
