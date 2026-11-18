//! A decompression bomb under a counting allocator: 817 bytes that would expand to 1 GiB are
//! refused with `TooLarge`, and no allocation is ever larger than the limit.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use only_brotli::{Error, decompress};

/// Tracks the live heap bytes, their peak and the largest single allocation.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

fn grew(n: usize) {
    let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
    LARGEST.fetch_max(n, Ordering::Relaxed);
}

// SAFETY: forwards to the system allocator unchanged; only counts bytes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        // Counted as a new block alive next to the old one until the copy is done.
        grew(n);
        // SAFETY: same contract as the caller's.
        let r = unsafe { System.realloc(p, l, n) };
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        r
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    n: usize,
}

impl Bits {
    fn put(&mut self, n: u32, v: u64) -> &mut Self {
        for i in 0..n {
            if self.n % 8 == 0 {
                self.out.push(0);
            }
            let last = self.out.len() - 1;
            self.out[last] |= (((v >> i) & 1) as u8) << (self.n % 8);
            self.n += 1;
        }
        self
    }
}

#[test]
fn bomb_stays_within_the_limit() {
    // WBITS 16, then 64 meta-blocks of 2^24 bytes: one literal 'z', then a copy of
    // 2^24 - 1 bytes from distance 1, every prefix code with a single symbol.
    let mut b = Bits::default();
    b.put(1, 0);
    for _ in 0..64 {
        b.put(1, 0).put(2, 2).put(24, (1 << 24) - 1).put(1, 0); // MLEN 2^24, compressed
        b.put(3, 0).put(6, 0).put(2, 0).put(1, 0).put(1, 0);
        b.put(2, 1).put(2, 0).put(8, u64::from(b'z')); // literal code
        b.put(2, 1).put(2, 0).put(10, 399); // insert 1, copy code 23
        b.put(2, 1).put(2, 0).put(6, 16); // distance symbol 16
        b.put(24, (1 << 24) - 1 - 2118).put(1, 0);
    }
    b.put(2, 0b11);
    let z = std::mem::take(&mut b.out);
    assert!(z.len() < 1000, "{}", z.len());

    let limit = 64 << 20;
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
    let t = std::time::Instant::now();
    assert_eq!(decompress(&z, limit), Err(Error::TooLarge));
    assert!(t.elapsed() < std::time::Duration::from_secs(5));
    let largest = LARGEST.load(Ordering::Relaxed);
    let peak = PEAK.load(Ordering::Relaxed) - base;
    assert!(largest <= limit, "largest allocation {largest}");
    // The output grows geometrically: at most the last two buffers are alive at once.
    assert!(peak <= limit + limit / 2 + (1 << 20), "peak {peak}");
}
