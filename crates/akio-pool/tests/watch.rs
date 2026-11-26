//! The pressure watcher (`akio-pool-watch`): started by a pool passing half of its queue, gone
//! once every watched pool has stayed calm. The watcher is one per process, so these tests run
//! one at a time (`SERIAL`), each starting with no watcher running, and wait with bounded loops
//! instead of counting on exact timing.

use std::{
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, mpsc},
    thread,
    time::{Duration, Instant},
};

use akio_pool::{Job, Pool, PoolConfig, blocking, watch_list_has, watcher_running};

static SERIAL: Mutex<()> = Mutex::new(());

/// Takes the test lock and waits for any watcher of an earlier test to be gone.
fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    logs();
    wait_until("no watcher left from an earlier test", || {
        !watcher_running()
    });
    g
}

fn wait_until(what: &str, mut c: impl FnMut() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < Duration::from_secs(15), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// The `akio-pool` records logged so far: (level, message).
struct Capture(Mutex<Vec<(akio_log::Level, String)>>);

impl akio_log::Logger for Capture {
    fn log(&self, r: &akio_log::Record<'_>) {
        if r.target() == "akio-pool" {
            let mut l = self.0.lock().unwrap_or_else(|p| p.into_inner());
            l.push((r.level(), r.args().to_string()));
        }
    }
}

fn logs() -> &'static Capture {
    static LOGS: OnceLock<&'static Capture> = OnceLock::new();
    LOGS.get_or_init(|| {
        let c: &'static Capture = Box::leak(Box::new(Capture(Mutex::new(Vec::new()))));
        akio_log::set_logger(c).expect("the only logger of this binary");
        akio_log::set_max_level(akio_log::LevelFilter::Info);
        c
    })
}

/// Logged lines of pool `name` containing `text`.
fn logged(name: &str, text: &str) -> Vec<(akio_log::Level, String)> {
    let prefix = format!("pool {name}:");
    logs()
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter(|(_, m)| m.starts_with(&prefix) && m.contains(text))
        .cloned()
        .collect()
}

fn cfg(name: &str, max: usize, cap: usize) -> PoolConfig {
    let mut c = PoolConfig::default();
    c.max_threads = max;
    c.max_blocked_threads = max;
    c.queue_capacity = cap;
    c.keep_alive = Duration::from_millis(100);
    c.name = name.to_owned();
    c
}

type Gate = Arc<(Mutex<bool>, Condvar)>;

fn gate() -> Gate {
    Arc::new((Mutex::new(false), Condvar::new()))
}

/// A job that waits for the gate (10 s at most).
fn gate_job(g: &Gate) -> Job {
    let g = g.clone();
    Box::new(move || {
        let (m, cv) = &*g;
        let m = m.lock().unwrap_or_else(|p| p.into_inner());
        drop(cv.wait_timeout_while(m, Duration::from_secs(10), |o| !*o));
    })
}

fn open(g: &Gate) {
    *g.0.lock().unwrap_or_else(|p| p.into_inner()) = true;
    g.1.notify_all();
}

/// Occupies the pool's only thread with a gated job and queues `n` more gated jobs.
fn fill(p: &Pool, g: &Gate, n: usize) {
    p.try_execute(gate_job(g)).expect("room");
    wait_until("the gate job runs", || {
        let s = p.stats();
        s.threads == 1 && s.queued == 0
    });
    for _ in 0..n {
        p.try_execute(gate_job(g)).expect("room");
    }
}

fn shut(p: &Pool) {
    p.shutdown();
    p.join();
}

#[test]
fn a_pool_at_half_its_queue_starts_no_watcher() {
    let _g = serial();
    let p = Pool::new(cfg("calm", 1, 10));
    let g = gate();
    // The running job plus 5 queued: half the queue, not past it.
    fill(&p, &g, 5);
    thread::sleep(Duration::from_millis(250));
    assert!(!p.stats().watched);
    assert!(
        !watcher_running(),
        "no watcher thread while no pool is past half"
    );
    assert!(!watch_list_has(&p));
    open(&g);
    wait_until("the jobs ran", || p.stats().completed == 6);
    assert!(!watcher_running());
    assert_eq!(p.stats().warnings, [0; 4]);
    shut(&p);
}

#[test]
fn pressure_starts_the_watcher_and_calm_stops_it_each_episode() {
    let _g = serial();
    let p = Pool::new(cfg("episodes", 1, 10));
    for episode in 1..=2u64 {
        let g = gate();
        fill(&p, &g, 6);
        assert!(p.stats().watched, "6 of 10 is past half");
        wait_until("the watcher runs", watcher_running);
        assert!(watch_list_has(&p));
        wait_until("50% counted", || p.stats().warnings[0] == episode);
        for _ in 0..2 {
            p.try_execute(gate_job(&g)).expect("room");
        }
        wait_until("75% counted", || p.stats().warnings[1] == episode);
        for _ in 0..2 {
            p.try_execute(gate_job(&g)).expect("room");
        }
        wait_until("100% counted", || p.stats().warnings[3] == episode);
        open(&g);
        wait_until("the pool leaves the list", || !watch_list_has(&p));
        wait_until("the watcher exits", || !watcher_running());
        let s = p.stats();
        assert!(!s.watched);
        assert_eq!(
            s.warnings,
            [episode, episode, 0, episode],
            "90% was jumped over"
        );
        assert_eq!(logged("episodes", "pressure over").len() as u64, episode);
    }
    // The first episode's lines were logged; the second's came within 10 s, so were held back.
    let full = logged("episodes", "queue full");
    assert_eq!(full.len(), 1);
    assert_eq!(full[0].0, akio_log::Level::Error);
    let past = logged("episodes", "queue past");
    assert_eq!(past.len(), 2, "50% and 75% once each: {past:?}");
    assert!(past.iter().all(|(l, _)| *l == akio_log::Level::Warn));
    shut(&p);
}

/// A refusal between two samples counts as a full queue though the backlog never shows it:
/// with no room at all (capacity 0), every submission is refused and nothing ever waits.
#[test]
fn a_refusal_between_samples_counts_as_full() {
    let _g = serial();
    let p = Pool::new(cfg("refusal", 1, 0));
    assert!(p.try_execute(Box::new(|| {})).is_err());
    assert!(p.stats().watched);
    wait_until("100% counted", || p.stats().warnings[3] == 1);
    wait_until("the watcher exits", || !watcher_running());
    let s = p.stats();
    assert_eq!((s.warnings, s.watched, s.queued), ([0, 0, 0, 1], false, 0));
    let over = logged("refusal", "pressure over");
    assert_eq!(over.len(), 1);
    assert!(over[0].1.contains("1 refused"), "{over:?}");
    shut(&p);
}

/// Work held up by the stand-in limit (`max_blocked_threads`) counts as 100% too, and gets a
/// line of its own.
#[test]
fn the_stand_in_limit_counts_as_full() {
    let _g = serial();
    let mut c = cfg("ceiling", 1, 16);
    c.max_blocked_threads = 0;
    let p = Pool::new(c);
    let (tx, rx) = mpsc::channel();
    let q = p.clone();
    p.try_execute(Box::new(move || {
        let (sub_tx, sub_rx) = mpsc::channel::<()>();
        let _ = q.try_execute(Box::new(move || {
            let _ = sub_tx.send(());
        }));
        // Nothing stands in for this thread: the sub-task waits.
        let _ = tx.send(blocking(|| sub_rx.recv_timeout(Duration::from_millis(300))));
    }))
    .expect("room");
    let got = rx.recv_timeout(Duration::from_secs(10)).expect("job ran");
    assert!(got.is_err());
    assert!(p.stats().blocked_at_ceiling >= 1);
    wait_until("100% counted", || p.stats().warnings[3] == 1);
    wait_until("the watcher exits", || !watcher_running());
    assert_eq!(logged("ceiling", "max_blocked_threads").len(), 1);
    shut(&p);
}

/// A pool dropped while watched leaves the list, and the watcher exits; no summary is logged
/// for it.
#[test]
fn a_pool_dropped_while_watched_is_removed() {
    let _g = serial();
    let p = Pool::new(cfg("dropped", 1, 0));
    // Refused: watched, and no thread holds the pool.
    assert!(p.try_execute(Box::new(|| {})).is_err());
    assert!(watch_list_has(&p));
    let weak = Arc::downgrade(&p);
    drop(p);
    // The watcher may hold it for the length of a sample.
    wait_until("the pool is gone", || weak.strong_count() == 0);
    wait_until("the watcher exits", || !watcher_running());
    assert!(logged("dropped", "pressure over").is_empty());
}

/// Many submitters cross the line again and again, around the time the watcher lets the pool
/// go: whenever the pool is over the line, it ends up in the list with a watcher running (no
/// registration is lost between the watcher's leaving and a submitter's crossing).
#[test]
fn no_registration_is_lost_while_the_watcher_leaves() {
    let _g = serial();
    let p = Pool::new(cfg("race", 1, 100));
    for round in 0..6u64 {
        let g = gate();
        // Over the line, then calm: the watcher leaves about 1 s after the calm begins.
        fill(&p, &g, 60);
        wait_until("watched", || watch_list_has(&p));
        open(&g);
        wait_until("drained", || p.stats().queued == 0);
        thread::sleep(Duration::from_millis(900 + round * 50));
        // Four submitters push the pool past half at once, as the watcher may be leaving.
        let g = gate();
        p.try_execute(gate_job(&g)).expect("room");
        let pushers: Vec<_> = (0..4)
            .map(|_| {
                let (p, g) = (p.clone(), g.clone());
                thread::spawn(move || {
                    for _ in 0..15 {
                        p.try_execute(gate_job(&g)).expect("room");
                    }
                })
            })
            .collect();
        for h in pushers {
            h.join().expect("pusher");
        }
        wait_until("over the line, the pool is watched", || {
            p.stats().watched && watch_list_has(&p) && watcher_running()
        });
        open(&g);
        wait_until("drained", || p.stats().queued == 0);
    }
    wait_until("the watcher exits", || !watcher_running());
    assert!(!p.stats().watched);
    shut(&p);
}
