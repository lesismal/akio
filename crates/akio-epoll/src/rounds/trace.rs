//! Diagnostics of rounds scheduling (ADR-102), on with `AKIO_ROUNDS_TRACE=1`: once a second,
//! stderr gets how long connections waited in the worker queues and how long pollers took to
//! hand out a batch of events. Off, it costs one relaxed load per round.

use std::{
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

static ON: AtomicBool = AtomicBool::new(false);
static INIT: OnceLock<Instant> = OnceLock::new();

pub(crate) struct Counters {
    pub(crate) rounds: AtomicU64,
    pub(crate) queue_gt100us: AtomicU64,
    pub(crate) queue_gt1ms: AtomicU64,
    pub(crate) queue_gt3ms: AtomicU64,
    pub(crate) queue_max_us: AtomicU64,
    pub(crate) polls: AtomicU64,
    pub(crate) poll_gt1ms: AtomicU64,
    pub(crate) poll_max_us: AtomicU64,
    pub(crate) wait_gt3ms_with_events: AtomicU64,
}

pub(crate) static C: Counters = Counters {
    rounds: AtomicU64::new(0),
    queue_gt100us: AtomicU64::new(0),
    queue_gt1ms: AtomicU64::new(0),
    queue_gt3ms: AtomicU64::new(0),
    queue_max_us: AtomicU64::new(0),
    polls: AtomicU64::new(0),
    poll_gt1ms: AtomicU64::new(0),
    poll_max_us: AtomicU64::new(0),
    wait_gt3ms_with_events: AtomicU64::new(0),
};

/// Whether tracing is on (decided once; starts the reporter thread).
pub(crate) fn on() -> bool {
    INIT.get_or_init(|| {
        if std::env::var("AKIO_ROUNDS_TRACE").as_deref() == Ok("1") {
            ON.store(true, Ordering::Relaxed);
            let _ = std::thread::Builder::new()
                .name("akio-rounds-trace".into())
                .spawn(report);
        }
        Instant::now()
    });
    ON.load(Ordering::Relaxed)
}

/// Nanoseconds since tracing was set up (0 when off).
#[inline]
pub(crate) fn now_ns() -> u64 {
    if !ON.load(Ordering::Relaxed) {
        return 0;
    }
    INIT.get().map_or(0, |t| t.elapsed().as_nanos() as u64)
}

pub(crate) fn queued(ns: u64) {
    let us = ns / 1000;
    C.rounds.fetch_add(1, Ordering::Relaxed);
    if us > 100 {
        C.queue_gt100us.fetch_add(1, Ordering::Relaxed);
    }
    if us > 1000 {
        C.queue_gt1ms.fetch_add(1, Ordering::Relaxed);
    }
    if us > 3000 {
        C.queue_gt3ms.fetch_add(1, Ordering::Relaxed);
    }
    C.queue_max_us.fetch_max(us, Ordering::Relaxed);
}

pub(crate) fn polled(busy: Duration, waited: Duration, events: usize) {
    let us = busy.as_micros() as u64;
    C.polls.fetch_add(1, Ordering::Relaxed);
    if us > 1000 {
        C.poll_gt1ms.fetch_add(1, Ordering::Relaxed);
    }
    C.poll_max_us.fetch_max(us, Ordering::Relaxed);
    if waited > Duration::from_millis(3) && events > 1 {
        C.wait_gt3ms_with_events.fetch_add(1, Ordering::Relaxed);
    }
}

fn report() {
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let t = |a: &AtomicU64| a.swap(0, Ordering::Relaxed);
        eprintln!(
            "rounds-trace rounds={} q>100us={} q>1ms={} q>3ms={} qmax={}us polls={} poll>1ms={} pollmax={}us longwait+events={}",
            t(&C.rounds),
            t(&C.queue_gt100us),
            t(&C.queue_gt1ms),
            t(&C.queue_gt3ms),
            t(&C.queue_max_us),
            t(&C.polls),
            t(&C.poll_gt1ms),
            t(&C.poll_max_us),
            t(&C.wait_gt3ms_with_events),
        );
    }
}
