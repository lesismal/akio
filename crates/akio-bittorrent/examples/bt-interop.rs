//! The `akio` side of `tools/interop/bittorrent/run.sh`: make torrents, run a tracker, seed and
//! leech against other clients (aria2, libtorrent).
//!
//! ```text
//! bt-interop make <file-or-dir> <out.torrent> <tracker-url|-> [piece-length] [v1|v2|hybrid]
//!            [--web-seed url]...                   (prints the info hash)
//! bt-interop magnet <torrent>                       (prints its magnet link: btih and/or btmh)
//! bt-interop tracker <addr>
//! bt-interop seed <torrent> <data-dir> <listen> [options]
//! bt-interop leech <torrent|magnet> <data-dir> <listen> [options]
//! bt-interop dht <listen> [--bootstrap addr]...      (a DHT node that stays up)
//! options: --peer addr  --mse prefer|require|off  --no-utp  --no-dht  --bootstrap addr
//!          --timeout secs  --expect-utp  --expect-tcp  --expect-encrypted  --lsd
//!          --web-seed url  --up-limit bytes/s  --down-limit bytes/s
//! ```

use std::net::{SocketAddr, ToSocketAddrs};
use std::process::exit;
use std::sync::Arc;
use std::time::{Duration, Instant};

use akio::{Engine, Listener};
use akio_bittorrent::client::{AddOptions, Client, ClientConfig, RateLimits, TorrentEvent};
use akio_bittorrent::metainfo::{Builder, MetaInfo, TorrentVersion};
use akio_bittorrent::mse::Policy;
use akio_bittorrent::tracker::{TrackerConfig, TrackerServer};

fn die(m: impl std::fmt::Display) -> ! {
    eprintln!("bt-interop: {m}");
    exit(1)
}

fn addr(s: &str) -> SocketAddr {
    s.to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .unwrap_or_else(|| die(format!("bad address {s}")))
}

#[derive(Default)]
struct Opts {
    peers: Vec<SocketAddr>,
    bootstrap: Vec<SocketAddr>,
    mse: Option<Policy>,
    no_utp: bool,
    no_dht: bool,
    timeout: u64,
    expect_utp: bool,
    expect_tcp: bool,
    expect_encrypted: bool,
    lsd: bool,
    web_seeds: Vec<String>,
    up_limit: Option<u64>,
    down_limit: Option<u64>,
}

fn opts(args: &[String]) -> Opts {
    let mut o = Opts {
        timeout: 120,
        ..Opts::default()
    };
    let mut i = 0;
    while i < args.len() {
        let v = || {
            args.get(i + 1)
                .cloned()
                .unwrap_or_else(|| die("missing option value"))
        };
        match args[i].as_str() {
            "--peer" => {
                o.peers.push(addr(&v()));
                i += 1;
            }
            "--bootstrap" => {
                o.bootstrap.push(addr(&v()));
                i += 1;
            }
            "--mse" => {
                o.mse = Some(match v().as_str() {
                    "prefer" => Policy::Prefer,
                    "require" => Policy::Require,
                    "off" => Policy::Disabled,
                    x => die(format!("bad --mse {x}")),
                });
                i += 1;
            }
            "--timeout" => {
                o.timeout = v().parse().unwrap_or_else(|_| die("bad --timeout"));
                i += 1;
            }
            "--web-seed" => {
                o.web_seeds.push(v());
                i += 1;
            }
            "--up-limit" => {
                o.up_limit = Some(v().parse().unwrap_or_else(|_| die("bad --up-limit")));
                i += 1;
            }
            "--down-limit" => {
                o.down_limit = Some(v().parse().unwrap_or_else(|_| die("bad --down-limit")));
                i += 1;
            }
            "--lsd" => o.lsd = true,
            "--no-utp" => o.no_utp = true,
            "--no-dht" => o.no_dht = true,
            "--expect-utp" => o.expect_utp = true,
            "--expect-tcp" => o.expect_tcp = true,
            "--expect-encrypted" => o.expect_encrypted = true,
            x => die(format!("unknown option {x}")),
        }
        i += 1;
    }
    o
}

fn client(dir: &str, listen: &str, o: &Opts) -> Client {
    let mut c = ClientConfig::default();
    c.listen = addr(listen);
    c.data_dir = dir.into();
    c.encryption = o.mse.unwrap_or(Policy::Prefer);
    c.utp = !o.no_utp;
    c.dht = !o.no_dht;
    c.dht_bootstrap = o.bootstrap.clone();
    c.lsd = o.lsd;
    c.rate_limits = RateLimits::new(o.up_limit, o.down_limit);
    c.on_event = Some(Arc::new(|ih, e| match e {
        TorrentEvent::PieceVerified(_) => {}
        TorrentEvent::PeerConnected(_) => {
            // Recorded here: a leecher drops a seeder once complete, which may come before
            // the main loop looks at the peers.
            if let Some(t) = CLIENT.get().and_then(|c| c.torrent(&ih)) {
                let mut seen = SEEN.lock().unwrap_or_else(|p| p.into_inner());
                for p in t.peers() {
                    if !seen.iter().any(|(a, ..)| *a == p.addr) {
                        eprintln!(
                            "peer {} client {:?} utp {} encrypted {}",
                            p.addr, p.client, p.utp, p.encrypted
                        );
                        seen.push((p.addr, p.utp, p.encrypted));
                    }
                }
            }
        }
        e => eprintln!("[{}] {e:?}", &ih.to_hex()[..8]),
    }));
    let c = Client::new(c).unwrap_or_else(|e| die(e));
    let _ = CLIENT.set(c.clone());
    c
}

type Seen = Vec<(SocketAddr, bool, bool)>;
static CLIENT: std::sync::OnceLock<Client> = std::sync::OnceLock::new();
static SEEN: std::sync::Mutex<Seen> = std::sync::Mutex::new(Vec::new());

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map_or("", String::as_str);
    let arg = |i: usize| {
        args.get(i)
            .cloned()
            .unwrap_or_else(|| die("missing argument (see the source for usage)"))
    };
    match cmd {
        "make" => {
            let tracker = arg(4);
            let path = arg(2);
            let name = std::path::Path::new(&path)
                .file_name()
                .map_or_else(|| die("bad path"), |n| n.to_string_lossy().into_owned());
            let mut b = Builder::new(name).piece_length(
                args.get(5)
                    .map_or(256 * 1024, |p| p.parse().unwrap_or(262_144)),
            );
            if tracker != "-" {
                b = b.tracker(tracker);
            }
            let mut i = 6;
            while i < args.len() {
                match args[i].as_str() {
                    "v1" => b = b.version(TorrentVersion::V1),
                    "v2" => b = b.version(TorrentVersion::V2),
                    "hybrid" => b = b.version(TorrentVersion::Hybrid),
                    "--web-seed" => {
                        b = b.web_seed(arg(i + 1));
                        i += 1;
                    }
                    x => die(format!("bad make option {x}")),
                }
                i += 1;
            }
            let mi = b.build_path(&path).unwrap_or_else(|e| die(e));
            std::fs::write(arg(3), mi.to_bytes()).unwrap_or_else(|e| die(e));
            println!("{}", mi.info_hash);
        }
        "magnet" => {
            let mi = MetaInfo::load(arg(2)).unwrap_or_else(|e| die(e));
            println!("{}", mi.magnet());
        }
        "tracker" => {
            let a = addr(&arg(2));
            let t = TrackerServer::new(TrackerConfig::default());
            let engine = Engine::builder()
                .listen(
                    Listener::tcp(a)
                        .threads(1)
                        .serve(akio_http::serve(t.http())),
                )
                .listen(Listener::udp(a).threads(1).serve(t.udp()))
                .build()
                .unwrap_or_else(|e| die(e));
            eprintln!("tracker on {a} (http and udp)");
            engine.run().unwrap_or_else(|e| die(e));
        }
        "dht" => {
            let o = opts(&args[3..]);
            let c = client(".", &arg(2), &o);
            loop {
                std::thread::sleep(Duration::from_secs(5));
                eprintln!("dht nodes: {}", c.dht_nodes());
            }
        }
        "seed" | "leech" => {
            let src = arg(2);
            let o = opts(&args[5..]);
            let c = client(&arg(3), &arg(4), &o);
            let mut add = AddOptions::default();
            add.peers = o.peers.clone();
            add.web_seeds = o.web_seeds.clone();
            let t = if src.starts_with("magnet:") {
                c.add_magnet(&src, add)
            } else {
                c.add_torrent(MetaInfo::load(&src).unwrap_or_else(|e| die(e)), add)
            }
            .unwrap_or_else(|e| die(e));
            eprintln!(
                "{} {} on {} as {}",
                cmd,
                t.info_hash(),
                c.listen_addr(),
                String::from_utf8_lossy(&c.peer_id())
            );
            if cmd == "seed" {
                if !t.wait_complete(Duration::from_secs(o.timeout)) {
                    die(format!("seed data incomplete: {:?}", t.stats()));
                }
                eprintln!("seeding");
                loop {
                    std::thread::sleep(Duration::from_secs(2));
                    let s = t.stats();
                    eprintln!(
                        "uploaded {} to {} peers {:?}",
                        s.uploaded,
                        s.peers,
                        t.peers()
                            .iter()
                            .map(|p| (p.addr, p.utp, p.encrypted))
                            .collect::<Vec<_>>()
                    );
                }
            }
            let start = Instant::now();
            while !t.is_complete() {
                if start.elapsed() > Duration::from_secs(o.timeout) {
                    die(format!("timed out: {:?}", t.stats()));
                }
                std::thread::sleep(Duration::from_millis(20));
                let ms = start.elapsed().as_millis();
                if ms % 5000 < 20 {
                    eprintln!("status {:?}", t.stats());
                    for p in t.peers() {
                        eprintln!("  {p:?}");
                    }
                }
            }
            let seen = SEEN.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let s = t.stats();
            let secs = start.elapsed().as_secs_f64();
            println!(
                "complete: {} bytes in {:.2}s ({:.1} MiB/s), peers seen {:?}",
                s.total_size,
                secs,
                s.total_size as f64 / secs / 1048576.0,
                seen
            );
            if o.expect_utp && !seen.iter().any(|(_, u, _)| *u) {
                die("no uTP peer");
            }
            if o.expect_tcp && !seen.iter().any(|(_, u, _)| !*u) {
                die("no TCP peer");
            }
            if o.expect_encrypted && !seen.iter().any(|(_, _, e)| *e) {
                die("no encrypted peer");
            }
            c.close();
        }
        _ => die("usage: bt-interop make|tracker|seed|leech|dht ... (see the source)"),
    }
}
