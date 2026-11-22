//! Fixed costs of the streaming encoder (ADR-074, section 4 and the 2026-11-22 update): what a
//! flushed write of a small event costs, what setting up a stream costs, the memory a stream
//! holds, and bulk HTML written in flushed 16 KiB pieces.
//!
//!     cargo run --release -p only-brotli --example stream-cost [QUALITY [WINDOW_BITS]]
//!
//! Defaults: quality 4, window bits 18 (only-http's `StreamCompress` defaults). Prints one line
//! per measurement; `STREAM_COST_SECS` sets the time per measurement (default 1).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use only_brotli::{Compressor, Flush, Level, decompress};

/// Counts the bytes allocated and live, for the memory a stream holds.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n, Ordering::Relaxed);
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// One server-sent event, about 100 bytes of JSON (as only-http's `stream-bench`).
fn event(i: usize) -> Vec<u8> {
    format!(
        "event: tick\nid: {i}\ndata: {{\"seq\":{i},\"price\":{}.{:02},\"symbol\":\"SYM{}\",\"note\":\"steady\"}}\n\n",
        100 + i % 37,
        i % 100,
        i % 13
    )
    .into_bytes()
}

/// 16 KiB of generated HTML rows, different for each `i` (as only-http's `stream-bench`).
fn rows(i: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 << 10);
    let mut n = i * 1000;
    while out.len() < (16 << 10) - 80 {
        out.extend_from_slice(
            format!(
                "<tr><td>{n}</td><td>item-{}</td><td class=\"p\">{}.{:02}</td></tr>\n",
                n % 97,
                n % 1000,
                n % 100
            )
            .as_bytes(),
        );
        n += 1;
    }
    out
}

fn main() {
    let args: Vec<u32> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let q = args.first().copied().unwrap_or(4);
    let wb = args.get(1).copied().unwrap_or(18);
    let secs: f64 = std::env::var("STREAM_COST_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1.0);
    let budget = Duration::from_secs_f64(secs);
    // `STREAM_COST_ONLY=event` (setup, sse16, memory, html) runs one measurement (to profile).
    let only = std::env::var("STREAM_COST_ONLY").unwrap_or_default();
    let run = |what: &str| only.is_empty() || only == what;
    let new = || Compressor::new(Level::new(q)).window_bits(wb);
    let events: Vec<Vec<u8>> = (0..4096).map(event).collect();
    let ev_bytes: usize = events.iter().map(Vec::len).sum::<usize>() / events.len();

    // Per event: one stream, a flushed write per event (after a warm-up past the first ones).
    let mut out = Vec::new();
    if run("event") {
        let mut c = new();
        let mut wire = Vec::new();
        for e in &events[..256] {
            out.clear();
            c.compress(e, &mut out, Flush::Flush);
            wire.extend_from_slice(&out);
        }
        let (mut n, mut bytes) = (0usize, 0usize);
        let allocs = ALLOCS.load(Ordering::Relaxed);
        let t = Instant::now();
        while t.elapsed() < budget {
            for e in &events {
                out.clear();
                c.compress(e, &mut out, Flush::Flush);
                bytes += out.len();
            }
            n += events.len();
        }
        let per_event = t.elapsed().as_secs_f64() / n as f64;
        let allocs = ALLOCS.load(Ordering::Relaxed) - allocs;
        println!(
            "q{q} w{wb} event: {:.3} us per flushed {ev_bytes}-byte event, {:.1} bytes out, {:.1} allocations",
            per_event * 1e6,
            bytes as f64 / n as f64,
            allocs as f64 / n as f64
        );
        // The stream decodes (a sanity check of what was measured).
        out.clear();
        c.compress(&[], &mut out, Flush::Finish);
        wire.extend_from_slice(&out);
        assert!(decompress(&wire, 1 << 30).is_ok());
    }

    // Setup: a new stream, one flushed event, the end (as a 1-event response).
    if run("setup") {
        let mut n = 0usize;
        let t = Instant::now();
        while t.elapsed() < budget {
            for e in &events[..64] {
                let mut c = new();
                out.clear();
                c.compress(e, &mut out, Flush::Flush);
                c.compress(&[], &mut out, Flush::Finish);
            }
            n += 64;
        }
        let per_stream = t.elapsed().as_secs_f64() / n as f64;
        println!(
            "q{q} w{wb} setup: {:.2} us per stream of one event and the end",
            per_stream * 1e6
        );
    }

    // A 16-event response, as stream-bench's /sse.
    if run("sse16") {
        let mut n = 0usize;
        let t = Instant::now();
        while t.elapsed() < budget {
            let mut c = new();
            out.clear();
            for e in &events[n % 256..n % 256 + 16] {
                c.compress(e, &mut out, Flush::Flush);
            }
            c.compress(&[], &mut out, Flush::Finish);
            n += 1;
        }
        let per_resp = t.elapsed().as_secs_f64() / n as f64;
        let resp_len = out.len();
        let want: Vec<u8> = events[(n - 1) % 256..(n - 1) % 256 + 16].concat();
        assert_eq!(decompress(&out, 1 << 20).unwrap(), want);
        println!(
            "q{q} w{wb} sse16: {:.2} us per 16-event response, {resp_len} bytes",
            per_resp * 1e6
        );
    }

    // Memory per stream: allocated bytes after 3 events and after 30,000 (past the window).
    for k in [3usize, 30_000] {
        if !run("memory") {
            break;
        }
        let before = LIVE.load(Ordering::Relaxed);
        let mut c = new();
        let mut out = Vec::new();
        for i in 0..k {
            out.clear();
            c.compress(&event(i), &mut out, Flush::Flush);
        }
        drop(out);
        let held = LIVE.load(Ordering::Relaxed) - before;
        println!(
            "q{q} w{wb} memory: {} KiB after {k} events",
            held.div_ceil(1024)
        );
        drop(c);
    }

    let pages: Vec<Vec<u8>> = (0..64).map(rows).collect();
    // A response of 16 flushed writes of 16 KiB of HTML, each on a new stream (as
    // stream-bench's /bulk).
    if run("bulk16") {
        let (mut n, mut outb) = (0usize, 0usize);
        let t = Instant::now();
        while t.elapsed() < budget {
            let mut c = new();
            out.clear();
            for p in &pages[n % 48..n % 48 + 16] {
                c.compress(p, &mut out, Flush::Flush);
            }
            c.compress(&[], &mut out, Flush::Finish);
            outb += out.len();
            n += 1;
        }
        let per = t.elapsed().as_secs_f64() / n as f64;
        println!(
            "q{q} w{wb} bulk16: {:.1} us per response of 16 flushed 16 KiB writes, {} bytes",
            per * 1e6,
            outb / n
        );
    }

    // Bulk: 16 KiB of HTML per flushed write, one long stream.
    if !run("html") {
        return;
    }
    let mut c = new();
    let (mut n, mut inb, mut outb) = (0usize, 0usize, 0usize);
    let t = Instant::now();
    while t.elapsed() < budget {
        let p = &pages[n % pages.len()];
        out.clear();
        c.compress(p, &mut out, Flush::Flush);
        inb += p.len();
        outb += out.len();
        n += 1;
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "q{q} w{wb} html: {:.1} MB/s in 16 KiB flushed writes, {:.4} out/in",
        inb as f64 / s / 1e6,
        outb as f64 / inb as f64
    );
}
