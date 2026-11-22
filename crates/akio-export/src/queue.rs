//! The bounded, sharded queue that finished spans and log records wait in until the exporter
//! thread sends them. Pushing is one short lock on the calling thread's shard, never a wait for
//! the exporter; past the bound items are dropped and counted.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc,
};

use crate::Cmd;

const SHARDS: usize = 8;

fn shard() -> usize {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local! {
        static IDX: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
    }
    IDX.with(|c| {
        let mut i = c.get();
        if i == usize::MAX {
            i = NEXT.fetch_add(1, Ordering::Relaxed) % SHARDS;
            c.set(i);
        }
        i
    })
}

pub(crate) struct Queue<T> {
    shards: [Mutex<Vec<T>>; SHARDS],
    /// Most items queued at once.
    max: usize,
    batch: usize,
    /// Wakes the exporter thread when a batch is full.
    wake: Mutex<Option<mpsc::SyncSender<Cmd>>>,
    /// What to wake it with.
    cmd: fn() -> Cmd,
    pub(crate) open: AtomicBool,
    pub(crate) queued: AtomicUsize,
    pub(crate) dropped: AtomicU64,
    pub(crate) exported: AtomicU64,
    /// Items the collector refused (OTLP partial success).
    pub(crate) rejected: AtomicU64,
    /// Items in the batch waiting to be retried.
    pub(crate) pending: AtomicUsize,
}

impl<T> Queue<T> {
    pub(crate) fn new(
        max: usize,
        batch: usize,
        wake: mpsc::SyncSender<Cmd>,
        cmd: fn() -> Cmd,
    ) -> Queue<T> {
        Queue {
            shards: std::array::from_fn(|_| Mutex::new(Vec::new())),
            max,
            batch,
            wake: Mutex::new(Some(wake)),
            cmd,
            open: AtomicBool::new(true),
            queued: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
            exported: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            pending: AtomicUsize::new(0),
        }
    }

    /// Queues `item`, or drops and counts it when the queue is full or closed.
    pub(crate) fn push(&self, item: T) {
        if !self.open.load(Ordering::Relaxed) {
            return;
        }
        // The bound is on the total; the shards only spread the locks over threads.
        let n = self.queued.fetch_add(1, Ordering::Relaxed);
        if n >= self.max {
            self.queued.fetch_sub(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.shards[shard()]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(item);
        if (n + 1) % self.batch == 0 {
            if let Some(w) = &*self.wake.lock().unwrap_or_else(|p| p.into_inner()) {
                let _ = w.try_send((self.cmd)());
            }
        }
    }

    /// Takes at most `max` items.
    pub(crate) fn drain(&self, max: usize) -> Vec<T> {
        let mut out = Vec::new();
        for s in &self.shards {
            if out.len() >= max {
                break;
            }
            let mut g = s.lock().unwrap_or_else(|p| p.into_inner());
            let take = g.len().min(max - out.len());
            out.extend(g.drain(..take));
        }
        self.queued.fetch_sub(out.len(), Ordering::Relaxed);
        out
    }

    pub(crate) fn len(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    /// Stops queueing (items pushed later are ignored) and forgets the exporter thread.
    pub(crate) fn close(&self) {
        self.open.store(false, Ordering::Relaxed);
        *self.wake.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}
