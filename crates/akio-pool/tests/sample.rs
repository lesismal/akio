//! Sampling by hand ([`akio_pool::sample`], [`Pool::sample`]), with automatic sampling switched
//! off by the first test (it is on by default) so that the watcher counts nothing.

use std::{
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio_pool::{
    DEFAULT_SAMPLE_INTERVAL, Job, Pool, PoolConfig, auto_sample, sample, sample_interval,
    set_auto_sample, watch_list_has, watcher_running,
};

fn wait_until(what: &str, mut c: impl FnMut() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < Duration::from_secs(15), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn cfg(name: &str, cap: usize) -> PoolConfig {
    let mut c = PoolConfig::default();
    c.max_threads = 1;
    c.queue_capacity = cap;
    c.name = name.to_owned();
    c
}

type Gate = Arc<(Mutex<bool>, Condvar)>;

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

/// On by default, every 500 ms. Switched off, a full pool, refusing work, is not watched and
/// starts no watcher; nothing is counted until a sample by hand looks, which counts each rise
/// once.
#[test]
fn switched_off_a_sample_by_hand_counts_the_rises() {
    assert!(auto_sample(), "automatic sampling is on by default");
    assert_eq!(sample_interval(), DEFAULT_SAMPLE_INTERVAL);
    assert_eq!(DEFAULT_SAMPLE_INTERVAL, Duration::from_millis(500));
    set_auto_sample(false);
    let p = Pool::new(cfg("by-hand", 10));
    let g: Gate = Arc::new((Mutex::new(false), Condvar::new()));
    p.try_execute(gate_job(&g)).expect("room");
    wait_until("the gate job runs", || p.stats().queued == 0);
    for _ in 0..10 {
        p.try_execute(gate_job(&g)).expect("room");
    }
    assert!(p.try_execute(Box::new(|| {})).is_err());
    let s = p.stats();
    assert!(!s.watched && !watch_list_has(&p) && !watcher_running());
    assert_eq!((s.warnings, s.max_queued, s.rejected), ([0; 4], 10, 1));
    assert_eq!(p.sample().warnings, [0, 0, 0, 1], "full: 100% at once");
    assert_eq!(
        p.sample().warnings,
        [0, 0, 0, 1],
        "the same queue again: nothing new"
    );
    assert!(
        !p.stats().watched && !watcher_running(),
        "a sample by hand watches nothing"
    );
    open(&g);
    wait_until("drained", || p.stats().completed == 11);
    // Down to empty, then 6 of 10: a new rise to 50%.
    p.sample();
    let g: Gate = Arc::new((Mutex::new(false), Condvar::new()));
    p.try_execute(gate_job(&g)).expect("room");
    wait_until("the gate job runs", || p.stats().queued == 0);
    for _ in 0..6 {
        p.try_execute(gate_job(&g)).expect("room");
    }
    assert_eq!(p.sample().warnings, [1, 0, 0, 1]);
    open(&g);
    p.shutdown();
    p.join();
}

/// `sample` reports every pool alive and not shut down, in the order created, and leaves out
/// those shut down or dropped.
#[test]
fn sample_reports_the_live_pools() {
    let a = Pool::new(cfg("sample-a", 7));
    let b = Pool::new(cfg("sample-b", 9));
    assert!(b.id() > a.id());
    let ids = |s: &[akio_pool::PoolSample]| s.iter().map(|p| p.id).collect::<Vec<_>>();
    let all = sample();
    let mine: Vec<_> = all
        .iter()
        .filter(|s| s.id == a.id() || s.id == b.id())
        .collect();
    assert_eq!(mine.len(), 2, "{all:?}");
    assert_eq!(
        (mine[0].name.as_str(), mine[0].queue_capacity),
        ("sample-a", 7)
    );
    assert_eq!(
        (mine[1].name.as_str(), mine[1].max_threads),
        ("sample-b", 1)
    );
    b.shutdown();
    b.join();
    assert!(!ids(&sample()).contains(&b.id()), "shut down: left out");
    let id = a.id();
    drop(a);
    assert!(!ids(&sample()).contains(&id), "dropped: left out");
}
