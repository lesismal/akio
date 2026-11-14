#![forbid(unsafe_code)]
//! Size-class buffer pool and shared read-only buffers.
//!
//! * [`get`] / [`put`] use a small **thread-local** cache of `Vec<u8>`s grouped by size class, so
//!   the hot path takes no lock. Buffers freed on another thread simply join that thread's cache
//!   (bounded), which is fine for the producer/consumer split of send queues.
//! * [`SharedBuf`] is a cheaply clonable, immutable buffer for broadcast (`send_shared`).
//!
//! Guide: [Architecture: memory and buffers](https://lesismal.github.io/flash/en/architecture.html#5-memory-and-buffers)
//! (中文: [架构：内存与缓冲区](https://lesismal.github.io/flash/zh-CN/architecture.html)).
#![warn(clippy::unwrap_used)]

use std::{cell::RefCell, ops::Deref, sync::Arc};

/// Capacities handed out by the pool, ascending.
pub const CLASSES: [usize; 5] = [512, 4 << 10, 16 << 10, 64 << 10, 256 << 10];
const MAX_CACHED_PER_CLASS: usize = 64;

struct Pool {
    free: [Vec<Vec<u8>>; CLASSES.len()],
}

thread_local! {
    static POOL: RefCell<Pool> = const { RefCell::new(Pool { free: [const { Vec::new() }; CLASSES.len()] }) };
}

fn class_for_len(n: usize) -> Option<usize> {
    CLASSES.iter().position(|&c| n <= c)
}

/// An empty `Vec<u8>` with capacity of at least `min_cap`. Requests above the largest class are
/// allocated exactly and are not pooled.
pub fn get(min_cap: usize) -> Vec<u8> {
    match class_for_len(min_cap) {
        Some(i) => POOL
            .try_with(|p| p.borrow_mut().free[i].pop())
            .ok()
            .flatten()
            .unwrap_or_else(|| Vec::with_capacity(CLASSES[i])),
        None => Vec::with_capacity(min_cap),
    }
}

/// Returns a buffer to the thread's cache if it is exactly a class size; otherwise drops it.
pub fn put(mut v: Vec<u8>) {
    if let Some(i) = CLASSES.iter().position(|&c| c == v.capacity()) {
        v.clear();
        let _ = POOL.try_with(|p| {
            let mut p = p.borrow_mut();
            if p.free[i].len() < MAX_CACHED_PER_CLASS {
                p.free[i].push(v);
            }
        });
    }
}

/// An immutable, reference-counted byte buffer. Cloning is an atomic increment.
#[derive(Clone, Debug, Default)]
pub struct SharedBuf(Arc<[u8]>);

impl SharedBuf {
    /// Copies `data` into a new shared buffer.
    pub fn copy_from(data: &[u8]) -> Self {
        SharedBuf(Arc::from(data))
    }
}

impl From<Vec<u8>> for SharedBuf {
    fn from(v: Vec<u8>) -> Self {
        SharedBuf(Arc::from(v))
    }
}

impl Deref for SharedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedBuf {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_rounds_up_to_class_and_reuses() {
        let a = get(100);
        assert_eq!(a.capacity(), 512);
        let ptr = a.as_ptr();
        put(a);
        let b = get(300);
        assert_eq!(b.as_ptr(), ptr, "buffer was recycled");
        assert!(b.is_empty());
    }

    #[test]
    fn oversized_and_foreign_buffers_are_not_pooled() {
        let big = get(1 << 20);
        assert_eq!(big.capacity(), 1 << 20);
        put(big); // dropped
        put(Vec::with_capacity(777)); // dropped
        assert_eq!(get(1 << 20).capacity(), 1 << 20);
    }

    #[test]
    fn cache_is_bounded() {
        for _ in 0..(MAX_CACHED_PER_CLASS + 10) {
            put(Vec::with_capacity(512));
        }
        let n = POOL.with(|p| p.borrow().free[0].len());
        assert_eq!(n, MAX_CACHED_PER_CLASS);
    }

    #[test]
    fn shared_buf_clones_share_storage() {
        let a = SharedBuf::from(vec![1, 2, 3]);
        let b = a.clone();
        assert_eq!(&*a, &*b);
        assert_eq!(a.as_ptr(), b.as_ptr());
    }
}
