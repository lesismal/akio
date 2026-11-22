//! Cross-process BPF steering and listener migration (ADR-063), end to end with real worker
//! processes: this binary re-executes itself as the workers (`harness = false`), each an echo
//! server that answers which worker it is.
//!
//! Privileged on Linux (`CAP_BPF`, bpffs at /sys/fs/bpf): without privileges the steering
//! tests check the fallback instead, unless `AKIO_TEST_EXPECT_EBPF=1`, which turns that into a
//! failure. `AKIO_TEST_BACKEND=uring` runs the workers on io_uring.
//!
//! `cargo test -p akio-prefork --test bpf [-- <name filter>]`
#![allow(missing_docs)]

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("\nrunning 0 tests (Linux only)\n\ntest result: ok.");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::main();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io::{self, Read, Write},
        net::{SocketAddr, TcpStream},
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use akio::{
        AccelStatus, Backend, Config, Conn, Engine, Handler, UringConfig, ebpf::HashKey,
        ebpf::Steering, fn_acceptor,
    };
    use akio_prefork::{BpfSteering, ListenMode, Prefork, Status, Supervisor, Worker};

    const WORKERS: usize = 3;
    const THREADS: usize = 2;
    /// Client threads of `killed_worker_queue`, each with at most one connection open.
    const CLIENTS: usize = 8;

    fn expect_ebpf() -> bool {
        std::env::var("AKIO_TEST_EXPECT_EBPF").is_ok_and(|v| v == "1")
    }

    // ---- the worker ---------------------------------------------------------------------------

    fn backend() -> Backend {
        match std::env::var("AKIO_TEST_BACKEND").as_deref() {
            Ok("uring") => Backend::IoUring({
                let mut v = UringConfig::default();
                v.strict = true;
                v
            }),
            _ => Backend::Epoll,
        }
    }

    /// Reads an 8-byte id and answers `id, worker index, generation, steering state`, then
    /// closes.
    struct Echo {
        reply: [u8; 8],
        got: Vec<u8>,
    }

    impl Handler for Echo {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            self.got.extend_from_slice(data);
            if self.got.len() >= 8 {
                let mut out = self.got[..8].to_vec();
                out.extend_from_slice(&self.reply);
                let _ = c.send(&out);
                c.close();
            }
        }
    }

    fn worker(w: Worker) -> io::Result<()> {
        let accepted = Arc::new(AtomicU64::new(0));
        let mut cfg = Config::default();
        cfg.shutdown_timeout = Duration::from_secs(10);
        let state = Arc::new(AtomicU64::new(0));
        let (a, st) = (accepted.clone(), state.clone());
        let (index, generation) = (w.index() as u32, w.generation() as u16);
        let engine =
            Engine::builder()
                .config(cfg)
                .listen(w.listener(0)?.backend(backend()).serve(fn_acceptor(
                    move |_c: &Conn<Echo>| {
                        a.fetch_add(1, Ordering::Relaxed);
                        let mut reply = [0u8; 8];
                        reply[..4].copy_from_slice(&index.to_be_bytes());
                        reply[4..6].copy_from_slice(&generation.to_be_bytes());
                        reply[6] = st.load(Ordering::Relaxed) as u8;
                        Echo {
                            reply,
                            got: Vec::new(),
                        }
                    },
                )))
                .build()?;
        // b'S' shared steering attached, b'D' degraded, b'O' none.
        state.store(
            u64::from(match engine.accel_status().first() {
                Some(AccelStatus::Steering(i)) if i.shared => b'S',
                Some(AccelStatus::Degraded(_)) => b'D',
                _ => b'O',
            }),
            Ordering::Relaxed,
        );
        let r = w.serve(&engine);
        if let Ok(path) = std::env::var("AKIO_TEST_COUNT_FILE") {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            // One write(2) per line: workers exit (and append) concurrently.
            let line = format!(
                "{} {} {} {}\n",
                std::process::id(),
                w.index(),
                w.generation(),
                accepted.load(Ordering::Relaxed)
            );
            f.write_all(line.as_bytes())?;
        }
        r
    }

    // ---- helpers ------------------------------------------------------------------------------

    struct Reply {
        index: usize,
        generation: u16,
        state: u8,
        peer: SocketAddr,
    }

    /// One exchange on a fresh connection from `from` (port 0: any).
    fn ask(addr: SocketAddr, from: Option<SocketAddr>, id: u64) -> io::Result<Reply> {
        let mut s = match from {
            Some(f) => {
                let s = akio_sys::connect_nonblocking_from(f, addr)?;
                s.set_nonblocking(false)?;
                s
            }
            None => TcpStream::connect_timeout(&addr, Duration::from_secs(5))?,
        };
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let peer = s.local_addr()?;
        s.write_all(&id.to_be_bytes())?;
        let mut b = [0u8; 16];
        s.read_exact(&mut b)?;
        if b[..8] != id.to_be_bytes() {
            return Err(io::Error::other("echo mismatch"));
        }
        Ok(Reply {
            index: u32::from_be_bytes([b[8], b[9], b[10], b[11]]) as usize,
            generation: u16::from_be_bytes([b[12], b[13]]),
            state: b[14],
            peer,
        })
    }

    fn pin_base(name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/sys/fs/bpf/akio-prefork-test-{}-{name}",
            std::process::id()
        ))
    }

    fn prefork(steering: Steering, name: &str) -> Prefork {
        let mut b = BpfSteering::new(steering, THREADS);
        b.dir = pin_base(name);
        Prefork::new()
            .workers(WORKERS)
            .listen("127.0.0.1:0".parse().unwrap())
            .mode(ListenMode::ReusePort)
            .bpf_steering(b)
            .shutdown_timeout(Duration::from_secs(15))
            .ready_timeout(Duration::from_secs(20))
            .restart_backoff(Duration::from_millis(50), Duration::from_secs(1))
    }

    fn wait_until(sup: &Supervisor, secs: u64, what: &str, ok: impl Fn(&Status) -> bool) -> Status {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let st = sup.status();
            if ok(&st) {
                return st;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}: {st:?}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn settled(st: &Status) -> bool {
        st.serving().len() == WORKERS && st.workers.len() == WORKERS
    }

    /// Whether shared steering is in place for listener 0; panics under `AKIO_TEST_EXPECT_EBPF=1`
    /// when it is not.
    fn steering_active(sup: &Supervisor) -> bool {
        let on = sup.bpf_steering(0).is_some();
        assert!(
            on || !expect_ebpf(),
            "shared BPF steering unavailable with AKIO_TEST_EXPECT_EBPF=1"
        );
        on
    }

    /// `TcpExtTCPMigrateReqSuccess` / `Failure` of this network namespace.
    fn migrate_counters() -> (u64, u64) {
        let s = std::fs::read_to_string("/proc/net/netstat").unwrap_or_default();
        let mut lines = s.lines();
        while let (Some(h), Some(v)) = (lines.next(), lines.next()) {
            if !h.starts_with("TcpExt:") {
                continue;
            }
            let keys: Vec<&str> = h.split_whitespace().collect();
            let vals: Vec<&str> = v.split_whitespace().collect();
            let get = |k: &str| {
                keys.iter()
                    .position(|x| *x == k)
                    .and_then(|i| vals.get(i)?.parse().ok())
                    .unwrap_or(0)
            };
            return (get("TCPMigrateReqSuccess"), get("TCPMigrateReqFailure"));
        }
        (0, 0)
    }

    // ---- tests --------------------------------------------------------------------------------

    /// Hash steering by source address over every worker's sockets: the worker that answers
    /// is the one `expected_index` names, also after a worker crashed and its replacement took
    /// its slots over.
    fn steering_follows_the_shared_table() {
        let steering = Steering::Hash(HashKey::SrcIp);
        let sup = prefork(steering, "spread").spawn().unwrap();
        let addr = sup.addrs()[0];
        let st = wait_until(&sup, 20, "workers", settled);
        let active = steering_active(&sup);
        let check = |round: &str| {
            let mut seen = [0usize; WORKERS];
            for k in 1..=60u8 {
                let from: SocketAddr = format!("127.0.0.{k}:0").parse().unwrap();
                let r = ask(addr, Some(from), u64::from(k)).unwrap();
                if active {
                    assert_eq!(
                        r.state, b'S',
                        "worker {} not on the shared program",
                        r.index
                    );
                    let want =
                        akio::ebpf::expected_index(steering, WORKERS * THREADS, r.peer, addr)
                            .unwrap()
                            / THREADS;
                    assert_eq!(r.index, want, "{round}: peer {}", r.peer);
                } else {
                    assert_ne!(r.state, b'S');
                }
                seen[r.index] += 1;
            }
            println!("    {round}: answers per worker {seen:?}");
            assert!(seen.iter().all(|&c| c > 0), "{round}: {seen:?}");
        };
        check("start");
        // Kill worker 1; its replacement joins the same slots.
        let victim = st.serving().iter().find(|w| w.index == 1).unwrap().pid;
        akio_sys::process::kill(victim, 9).unwrap();
        wait_until(&sup, 20, "the restart", |st| {
            st.restarts == 1 && settled(st)
        });
        check("after a restart");
        if active {
            let dir = sup.bpf_steering(0).unwrap().dir().to_path_buf();
            assert!(dir.join("prog").exists());
            sup.shutdown();
            sup.wait().unwrap();
            assert!(!dir.exists(), "pins left in {}", dir.display());
            assert!(!pin_base("spread").exists());
        }
    }

    /// Reloads under continuous connection churn: every connection is answered, and the
    /// workers' accept counts add up to the clients' successful exchanges.
    fn reload_loses_nothing(steering: Steering, name: &str, reloads: u16) {
        let count_file =
            std::env::temp_dir().join(format!("akio-prefork-bpf-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&count_file);
        let sup = prefork(steering, name)
            .env("AKIO_TEST_COUNT_FILE", &count_file)
            .spawn()
            .unwrap();
        let addr = sup.addrs()[0];
        wait_until(&sup, 20, "workers", settled);
        let active = steering_active(&sup);
        let migrating = active && sup.bpf_steering(0).unwrap().migrates();
        let before = migrate_counters();
        let stop = Arc::new(AtomicBool::new(false));
        let ok = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let next = Arc::new(AtomicU64::new(1));
        let clients: Vec<_> = (0..8)
            .map(|_| {
                let (stop, ok, failed, next) =
                    (stop.clone(), ok.clone(), failed.clone(), next.clone());
                thread::spawn(move || {
                    let mut generations = std::collections::HashSet::new();
                    while !stop.load(Ordering::Relaxed) {
                        let id = next.fetch_add(1, Ordering::Relaxed);
                        match ask(addr, None, id) {
                            Ok(r) => {
                                generations.insert(r.generation);
                                ok.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                eprintln!("    exchange {id} failed: {e}");
                                failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    generations
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(300));
        for g in 1..=reloads {
            sup.reload();
            wait_until(&sup, 30, "the reload", |st| {
                st.generation == u64::from(g) && settled(st)
            });
            thread::sleep(Duration::from_millis(200));
        }
        stop.store(true, Ordering::Relaxed);
        let mut generations = std::collections::HashSet::new();
        for c in clients {
            generations.extend(c.join().unwrap());
        }
        sup.shutdown();
        sup.wait().unwrap();
        let after = migrate_counters();
        let counts = std::fs::read_to_string(&count_file).unwrap_or_default();
        let _ = std::fs::remove_file(&count_file);
        let served: u64 = counts
            .lines()
            .filter_map(|l| l.split_whitespace().nth(3)?.parse::<u64>().ok())
            .sum();
        let (ok, failed) = (ok.load(Ordering::Relaxed), failed.load(Ordering::Relaxed));
        println!(
            "    {name}: steering {active} (migration {migrating}), {reloads} reloads, {ok} \
             exchanges, {failed} failed, workers accepted {served} ({} exits), generations \
             seen {generations:?}, TCPMigrateReq success +{} failure +{}",
            counts.lines().count(),
            after.0 - before.0,
            after.1 - before.1,
        );
        assert_eq!(
            counts.lines().count(),
            WORKERS * (usize::from(reloads) + 1),
            "every worker reported: {counts}"
        );
        assert!(generations.len() > usize::from(reloads), "{generations:?}");
        if migrating || (!active && kernel_migrates()) {
            assert_eq!(failed, 0, "connections lost during reloads");
            assert_eq!(served, ok as u64, "accept counts do not add up");
        } else {
            // Without migration a reload may reset what the old sockets queued: reported, and
            // still every accepted connection was answered.
            assert!(served >= ok as u64, "accepted {served} < answered {ok}");
        }
    }

    fn kernel_migrates() -> bool {
        std::fs::read_to_string("/proc/sys/net/ipv4/tcp_migrate_req").is_ok_and(|v| v.trim() == "1")
    }

    /// A worker that stops accepting (SIGSTOP) while clients keep connecting, then dies
    /// (SIGKILL): the connections queued on its sockets migrate to the other workers with the
    /// shared program, and are reset without it (the control run, when the sysctl is off).
    fn killed_worker_queue(with_bpf: bool) -> (usize, usize, (u64, u64)) {
        let p = if with_bpf {
            prefork(Steering::Cpu, "stall")
        } else {
            Prefork::new()
                .workers(WORKERS)
                .listen("127.0.0.1:0".parse().unwrap())
                .mode(ListenMode::ReusePort)
                .shutdown_timeout(Duration::from_secs(15))
                .restart_backoff(Duration::from_millis(50), Duration::from_secs(1))
        };
        let sup = p.spawn().unwrap();
        let addr = sup.addrs()[0];
        let st = wait_until(&sup, 20, "workers", settled);
        if with_bpf && !steering_active(&sup) {
            sup.shutdown();
            sup.wait().unwrap();
            return (0, 0, (0, 0));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let ok = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicUsize::new(0));
        let clients: Vec<_> = (0..CLIENTS as u64)
            .map(|t| {
                let (stop, ok, failed) = (stop.clone(), ok.clone(), failed.clone());
                thread::spawn(move || {
                    let mut id = t << 32;
                    while !stop.load(Ordering::Relaxed) {
                        id += 1;
                        match ask(addr, None, id) {
                            Ok(_) => ok.fetch_add(1, Ordering::Relaxed),
                            Err(_) => failed.fetch_add(1, Ordering::Relaxed),
                        };
                    }
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(300));
        let victim = st.serving().iter().find(|w| w.index == 1).unwrap().pid;
        let before = migrate_counters();
        akio_sys::process::kill(victim, 19).unwrap(); // SIGSTOP
        thread::sleep(Duration::from_millis(300));
        akio_sys::process::kill(victim, 9).unwrap();
        wait_until(&sup, 20, "the restart", |st| {
            st.restarts == 1 && settled(st)
        });
        thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::Relaxed);
        for c in clients {
            c.join().unwrap();
        }
        let after = migrate_counters();
        sup.shutdown();
        sup.wait().unwrap();
        (
            ok.load(Ordering::Relaxed),
            failed.load(Ordering::Relaxed),
            (after.0 - before.0, after.1 - before.1),
        )
    }

    fn killed_worker_queue_migrates() {
        let (ok, failed, (mig, mig_failed)) = killed_worker_queue(true);
        println!(
            "    shared program: {ok} answered, {failed} failed, TCPMigrateReq success +{mig} \
             failure +{mig_failed}"
        );
        if ok == 0 {
            return; // not privileged (and not expected to be)
        }
        // Each client waits on at most one connection, and within the 300 ms stop every client
        // ends up waiting on the stopped worker: the connections queued on its sockets migrate,
        // those it had already accepted when it stopped die with it. How many it had accepted
        // depends on scheduling (0-4 of 8 on a loaded gpu51, with failed + migrated about 9-11),
        // so the bound is one per client: losing all of them would mean nothing was saved.
        assert!(mig >= 1, "nothing migrated");
        assert!(failed < CLIENTS, "{failed} exchanges failed");
        if !kernel_migrates() {
            let (ok, failed, (mig, _)) = killed_worker_queue(false);
            println!(
                "    control (kernel hashing, tcp_migrate_req=0): {ok} answered, {failed} \
                 failed, TCPMigrateReq success +{mig}"
            );
            assert!(
                failed >= 1,
                "the control run lost nothing: is migration on?"
            );
        }
    }

    /// Without bpffs (a directory elsewhere) the supervisor logs and the workers run without
    /// the shared program; strict mode fails the spawn instead.
    fn falls_back_without_bpffs() {
        let mut b = BpfSteering::new(Steering::Cpu, THREADS);
        b.dir = std::env::temp_dir().join(format!("akio-prefork-not-bpffs-{}", std::process::id()));
        let p = Prefork::new()
            .workers(2)
            .listen("127.0.0.1:0".parse().unwrap())
            .mode(ListenMode::ReusePort)
            .shutdown_timeout(Duration::from_secs(10));
        let sup = p.clone().bpf_steering(b.clone()).spawn().unwrap();
        assert!(sup.bpf_steering(0).is_none());
        let addr = sup.addrs()[0];
        wait_until(&sup, 20, "workers", |st| st.serving().len() == 2);
        for id in 0..20 {
            let r = ask(addr, None, id).unwrap();
            assert_eq!(r.state, b'O', "a worker attached a program");
        }
        sup.shutdown();
        sup.wait().unwrap();
        b.strict = true;
        let e = p.bpf_steering(b.clone()).spawn().unwrap_err();
        println!("    strict: {e}");
        let _ = std::fs::remove_dir_all(&b.dir);
    }

    type Test = Box<dyn Fn()>;

    pub(super) fn main() {
        if akio_prefork::is_worker() {
            if let Err(e) = Prefork::new().run(worker) {
                eprintln!("worker failed: {e}");
                std::process::exit(1);
            }
            return;
        }
        let filter: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let tests: Vec<(&str, Test)> = vec![
            (
                "steering_follows_the_shared_table",
                Box::new(steering_follows_the_shared_table),
            ),
            (
                "reload_loses_nothing_cpu",
                Box::new(|| reload_loses_nothing(Steering::Cpu, "cpu", 3)),
            ),
            (
                "reload_loses_nothing_hash",
                Box::new(|| reload_loses_nothing(Steering::Hash(HashKey::SrcIpPort), "hash", 3)),
            ),
            (
                "killed_worker_queue_migrates",
                Box::new(killed_worker_queue_migrates),
            ),
            (
                "falls_back_without_bpffs",
                Box::new(falls_back_without_bpffs),
            ),
        ];
        let selected: Vec<_> = tests
            .iter()
            .filter(|(name, _)| {
                filter.is_empty() || filter.iter().any(|f| name.contains(f.as_str()))
            })
            .collect();
        println!("\nrunning {} tests", selected.len());
        let mut failed = Vec::new();
        for (name, test) in selected {
            let t0 = Instant::now();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
            let verdict = if r.is_ok() { "ok" } else { "FAILED" };
            println!("test {name} ... {verdict} ({:.2?})", t0.elapsed());
            if r.is_err() {
                failed.push(*name);
            }
        }
        if failed.is_empty() {
            println!("\ntest result: ok.");
        } else {
            println!("\ntest result: FAILED. {failed:?}");
            std::process::exit(101);
        }
    }
}
