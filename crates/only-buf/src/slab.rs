//! Receive slabs: one heap allocation viewed through disjoint, owned handles, so that a datagram
//! received into it can be handed to a protocol layer (and decrypted in place there) without a
//! copy, while the rest of the slab keeps receiving (ADR-024).
//!
//! * [`ChunkMut`]: exclusive read-write access to a byte range of a slab. [`split_to`] cuts it in
//!   two disjoint ones; [`freeze`] turns it into a shared [`Chunk`].
//! * [`Chunk`]: shared read-only access to a byte range; cloning is a reference-count increment.
//! * [`SlabPool`]: hands out whole slabs as a [`ChunkMut`] and reuses a slab once every handle
//!   on it has dropped (on any thread).
//!
//! Soundness rests on one invariant: **the ranges of the live `ChunkMut`s of a slab are
//! disjoint from each other and from the ranges of its live `Chunk`s.** A `ChunkMut` is only
//! created over a whole slab nobody else references ([`SlabPool::take`], checked with
//! `Arc::get_mut`), or by splitting an existing `ChunkMut` (which gives up the part it hands
//! out); a `Chunk` only by freezing a `ChunkMut` (which gives up its range for good). Memory is
//! accessed only through the raw pointer the slab was allocated with, never through a
//! reference to the whole slab, so handles on disjoint ranges never alias.
//!
//! `#[doc(hidden)]`: backend-facing (only-sys, only-epoll, only-core, only-quic); outside the
//! stability promise.
//!
//! [`split_to`]: ChunkMut::split_to
//! [`freeze`]: ChunkMut::freeze
#![allow(unsafe_code)]

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

#[cfg(loom)]
use loom::sync::{
    Arc,
    atomic::{Ordering, fence},
};
#[cfg(not(loom))]
use std::sync::{
    Arc,
    atomic::{Ordering, fence},
};

/// The allocation behind a slab. Freed when the last handle drops.
struct Mem {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: `Mem` owns its allocation (a leaked `Box<[u8]>`), like a `Box`, so moving it to
// another thread is fine. Sharing it (`&Mem` on several threads) is fine because `Mem` itself
// gives no access to the bytes: every access goes through a `ChunkMut` (exclusive over its
// range) or a `Chunk` (read-only over a range no `ChunkMut` covers), per the module invariant.
unsafe impl Send for Mem {}
// SAFETY: see `Send` above.
unsafe impl Sync for Mem {}

impl Mem {
    fn new(len: usize) -> Mem {
        assert!(
            u32::try_from(len).is_ok(),
            "only-buf: slab larger than 4 GiB"
        );
        let b: Box<[u8]> = vec![0u8; len].into_boxed_slice();
        let raw: *mut [u8] = Box::into_raw(b);
        Mem {
            // `Box::into_raw` never returns null.
            ptr: NonNull::new(raw.cast::<u8>()).unwrap_or(NonNull::dangling()),
            len,
        }
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        let raw = std::ptr::slice_from_raw_parts_mut(self.ptr.as_ptr(), self.len);
        // SAFETY: `ptr`/`len` came from `Box::into_raw` of a `Box<[u8]>` of exactly `len` bytes
        // (`Mem::new`), and this is the last reference (`Mem` is only held in an `Arc`, and
        // `drop` runs once).
        drop(unsafe { Box::from_raw(raw) });
    }
}

/// Exclusive read-write access to a range of a slab (see the [module docs](self)).
pub struct ChunkMut {
    mem: Arc<Mem>,
    start: u32,
    end: u32,
}

/// Shared read-only access to a range of a slab; `clone` is a reference-count increment.
#[derive(Clone)]
pub struct Chunk {
    mem: Arc<Mem>,
    start: u32,
    end: u32,
}

impl ChunkMut {
    /// A new slab of `len` zeroed bytes, not pooled.
    ///
    /// # Panics
    ///
    /// If `len` exceeds `u32::MAX`.
    pub fn new(len: usize) -> ChunkMut {
        let mem = Arc::new(Mem::new(len));
        ChunkMut {
            mem,
            start: 0,
            end: len as u32,
        }
    }

    /// Length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    /// Whether the range is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// The start of the range, for handing to the kernel (`recvmsg` iovecs). Writing through it
    /// is allowed within `len()` bytes while `self` is borrowed mutably.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        // SAFETY: `start <= end <= mem.len`, so the offset stays inside the allocation.
        unsafe { self.mem.ptr.as_ptr().add(self.start as usize) }
    }

    /// Splits off `[0, at)` and returns it; `self` keeps `[at, len)`.
    ///
    /// # Panics
    ///
    /// If `at > len()`.
    #[must_use = "the split-off part is lost otherwise"]
    pub fn split_to(&mut self, at: usize) -> ChunkMut {
        assert!(at <= self.len(), "ChunkMut::split_to out of bounds");
        let mid = self.start + at as u32;
        let head = ChunkMut {
            mem: self.mem.clone(),
            start: self.start,
            end: mid,
        };
        self.start = mid;
        head
    }

    /// Shortens the range to `len` bytes (the tail is given up: nothing will use it again until
    /// the slab is reused). No effect if `len >= self.len()`.
    pub fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.end = self.start + len as u32;
        }
    }

    /// Gives up write access: a shared, read-only view of the same range.
    pub fn freeze(self) -> Chunk {
        Chunk {
            mem: self.mem,
            start: self.start,
            end: self.end,
        }
    }
}

impl Deref for ChunkMut {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        // SAFETY: the range lies inside the allocation (`start <= end <= mem.len`), its bytes
        // are initialised (zeroed at allocation), and no other live handle may write it (module
        // invariant); the borrow of `self` keeps `self` from writing while this lives.
        unsafe {
            std::slice::from_raw_parts(self.mem.ptr.as_ptr().add(self.start as usize), self.len())
        }
    }
}

impl DerefMut for ChunkMut {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `deref`; besides, no other live handle reads or writes the range (module
        // invariant) and the mutable borrow of `self` makes this the only access through `self`.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.mem.ptr.as_ptr().add(self.start as usize),
                self.len(),
            )
        }
    }
}

impl Chunk {
    /// Length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        (self.end - self.start) as usize
    }

    /// Whether the range is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

impl Deref for Chunk {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        // SAFETY: the range lies inside the allocation and is initialised; it was frozen from a
        // `ChunkMut`, so no `ChunkMut` covers it any more and nothing writes it until the slab is
        // reused, which needs every handle (this one included) to have dropped.
        unsafe {
            std::slice::from_raw_parts(self.mem.ptr.as_ptr().add(self.start as usize), self.len())
        }
    }
}

impl AsRef<[u8]> for ChunkMut {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl fmt::Debug for ChunkMut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkMut")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Slabs of one size, reused once every handle on them has dropped.
///
/// Not thread-safe by itself (one per receive loop); handles taken from it may move to and drop
/// on any thread.
pub struct SlabPool {
    slab: usize,
    max: usize,
    /// The pool's own reference to each slab it made; a slab is free when this is the only one.
    slabs: Vec<Arc<Mem>>,
    /// Where the next scan for a free slab starts.
    next: usize,
}

/// Slabs looked at for a free one before allocating.
const TRIES: usize = 8;

impl SlabPool {
    /// Slabs of `slab` bytes; at most `max` are kept for reuse (others are dropped after use).
    ///
    /// # Panics
    ///
    /// If `slab` exceeds `u32::MAX`.
    pub fn new(slab: usize, max: usize) -> SlabPool {
        assert!(
            u32::try_from(slab).is_ok(),
            "only-buf: slab larger than 4 GiB"
        );
        SlabPool {
            slab,
            max,
            slabs: Vec::new(),
            next: 0,
        }
    }

    /// Size of each slab in bytes.
    pub fn slab_size(&self) -> usize {
        self.slab
    }

    /// Slabs currently kept (free or in use).
    pub fn kept(&self) -> usize {
        self.slabs.len()
    }

    /// Gives up `slot`, what is left of a slab a receiver was filling, and makes it a whole slab
    /// again: `slot`'s own when nothing else references it any more (the common case: the
    /// datagrams cut from it were handled and dropped), so a receiver keeps writing into memory
    /// that is still in cache; else a slab from [`take`](Self::take).
    pub fn renew(&mut self, slot: &mut ChunkMut) {
        if slot.mem.len == self.slab {
            // The references that may legitimately remain: `slot`'s, and the pool's own if the
            // slab is one it keeps.
            let pooled = self.slabs.iter().any(|s| Arc::ptr_eq(s, &slot.mem));
            let alone = if pooled { 2 } else { 1 };
            // No other handle exists, and none can appear: handles are only made from existing
            // ones (`split_to`, `freeze`, `Chunk::clone`) or by the pool, and we hold both. The
            // fence pairs with the `Release` decrement of each dropped handle (as in
            // `Arc::drop`), so their accesses happen before the slab is written again.
            if Arc::strong_count(&slot.mem) == alone {
                fence(Ordering::Acquire);
                slot.start = 0;
                slot.end = self.slab as u32;
                return;
            }
        }
        *slot = self.take();
    }

    fn whole(&self, i: usize) -> ChunkMut {
        ChunkMut {
            mem: self.slabs[i].clone(),
            start: 0,
            end: self.slab as u32,
        }
    }

    /// A whole slab, exclusively: a free one when there is one, else a new one.
    pub fn take(&mut self) -> ChunkMut {
        let n = self.slabs.len();
        for _ in 0..TRIES.min(n) {
            let i = self.next % n;
            self.next = self.next.wrapping_add(1);
            // `get_mut` succeeds only if no handle besides the pool's exists (and synchronises
            // with the drops of those that did, on any thread).
            if Arc::get_mut(&mut self.slabs[i]).is_some() {
                return self.whole(i);
            }
        }
        let c = ChunkMut::new(self.slab);
        if n < self.max {
            self.slabs.push(c.mem.clone());
        }
        c
    }
}

impl fmt::Debug for SlabPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlabPool")
            .field("slab", &self.slab)
            .field("kept", &self.slabs.len())
            .finish_non_exhaustive()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn split_freeze_and_disjoint_writes() {
        let mut free = ChunkMut::new(64);
        free[..5].copy_from_slice(b"hello");
        let mut a = free.split_to(5);
        assert_eq!(&a[..], b"hello");
        assert_eq!(free.len(), 59);
        free[..5].copy_from_slice(b"world");
        a[0] = b'H';
        let b = free.split_to(5);
        let fa = a.freeze();
        let fa2 = fa.clone();
        assert_eq!(&fa2[..], b"Hello");
        assert_eq!(fa.as_ptr(), fa2.as_ptr());
        assert_eq!(&b[..], b"world");
        free.truncate(3);
        assert_eq!(free.len(), 3);
        free.truncate(10);
        assert_eq!(free.len(), 3);
        assert!(free.split_to(0).is_empty());
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn split_past_end_panics() {
        let mut c = ChunkMut::new(4);
        let _ = c.split_to(5);
    }

    #[test]
    fn pool_reuses_only_free_slabs() {
        let mut pool = SlabPool::new(32, 4);
        let mut a = pool.take();
        let p = a.as_mut_ptr();
        let kept = a.split_to(4).freeze();
        drop(a);
        // `kept` still points into the first slab: a new one is made.
        let mut b = pool.take();
        assert_ne!(b.as_mut_ptr(), p);
        drop(b);
        drop(kept);
        // Both are free now; the scan finds one of them.
        let mut c = pool.take();
        let q = c.as_mut_ptr();
        assert_eq!(c.len(), 32);
        assert!(q == p || pool.kept() == 2);
        assert_eq!(pool.kept(), 2);
        c[..].fill(7);
    }

    #[test]
    fn renew_reuses_the_same_slab_once_free() {
        let mut pool = SlabPool::new(64, 2);
        let mut slot = pool.take();
        let p = slot.as_mut_ptr();
        let held = slot.split_to(40).freeze();
        // A datagram cut from it is still held: another slab.
        pool.renew(&mut slot);
        assert_ne!(slot.as_mut_ptr(), p);
        assert_eq!(slot.len(), 64);
        drop(held);
        // Everything cut from this one dropped: it starts over in place.
        let q = slot.as_mut_ptr();
        let _ = slot.split_to(60);
        pool.renew(&mut slot);
        assert_eq!(slot.as_mut_ptr(), q);
        assert_eq!(slot.len(), 64);
        // Unpooled slabs (the pool keeps none) are reused too when free.
        let mut tiny = SlabPool::new(16, 0);
        let mut t = tiny.take();
        let tp = t.as_mut_ptr();
        let _ = t.split_to(10);
        tiny.renew(&mut t);
        assert_eq!(t.as_mut_ptr(), tp);
        assert_eq!(t.len(), 16);
        // A foreign-sized chunk is never adopted.
        let mut f = ChunkMut::new(8);
        pool.renew(&mut f);
        assert_eq!(f.len(), 64);
        f.fill(1);
    }

    #[test]
    fn renew_after_a_remote_drop() {
        let mut pool = SlabPool::new(128, 1);
        let mut slot = pool.take();
        let p = slot.as_mut_ptr();
        for round in 0..8u8 {
            let mut part = slot.split_to(64);
            let t = std::thread::spawn(move || {
                part.fill(round);
                part.freeze()
            });
            let back = t.join().expect("thread");
            assert!(back.iter().all(|&b| b == round));
            drop(back);
            pool.renew(&mut slot);
            assert_eq!(slot.as_mut_ptr(), p);
            slot.fill(0xaa);
        }
    }

    #[test]
    fn pool_is_bounded() {
        let mut pool = SlabPool::new(8, 2);
        let held: Vec<ChunkMut> = (0..5).map(|_| pool.take()).collect();
        assert_eq!(pool.kept(), 2);
        drop(held);
        let _ = pool.take();
        assert_eq!(pool.kept(), 2);
    }

    #[test]
    fn handles_drop_on_other_threads() {
        let mut pool = SlabPool::new(256, 2);
        for round in 0..4u8 {
            let mut free = pool.take();
            free[..16].fill(round);
            let mine = free.split_to(16).freeze();
            let mut theirs = free.split_to(16);
            let t = std::thread::spawn(move || {
                theirs.fill(round.wrapping_add(1));
                let seen = mine.iter().all(|&b| b == round);
                (seen, theirs.freeze())
            });
            let (ok, back) = t.join().expect("thread");
            assert!(ok);
            assert!(back.iter().all(|&b| b == round.wrapping_add(1)));
            // `free` (the tail) is still writable while the other parts live elsewhere.
            free.fill(0xee);
        }
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::*;

    /// A part handed to another thread is written and dropped there while the owner keeps
    /// asking the pool for slabs: the slab is reused only after that drop, and the reuse sees
    /// the other thread's writes as finished (Arc's release/acquire).
    #[test]
    fn loom_reuse_after_remote_drop() {
        loom::model(|| {
            let mut pool = SlabPool::new(16, 1);
            let mut free = pool.take();
            let mut part = free.split_to(8);
            drop(free);
            let t = loom::thread::spawn(move || {
                part[0] = 1;
                drop(part);
            });
            let mut again = pool.take();
            again[0] = 2;
            t.join().expect("thread");
            assert_eq!(pool.kept(), 1);
        });
    }

    /// The same with `renew`: the slot starts over in its own slab only once the part handed
    /// to the other thread has dropped.
    #[test]
    fn loom_renew_after_remote_drop() {
        loom::model(|| {
            let mut pool = SlabPool::new(16, 1);
            let mut slot = pool.take();
            let mut part = slot.split_to(8);
            let t = loom::thread::spawn(move || {
                part[0] = 1;
                drop(part);
            });
            pool.renew(&mut slot);
            slot[0] = 2;
            t.join().expect("thread");
        });
    }
}
