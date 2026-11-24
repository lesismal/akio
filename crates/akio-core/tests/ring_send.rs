//! The send-queue side of io_uring ring sends (ADR-106), driven without a ring: the test plays
//! the kernel, reading the bytes a flush describes through the addresses it hands out and writing
//! them to the socket itself, then reports the result with `ring_sent`. Runs on every platform
//! (ring mode is only a flag of the queue).
#![allow(missing_docs)]

use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use akio_core::{Config, ConnInner, LoopLink, RingSend, RingSent, Task};

#[derive(Default)]
struct Link {
    wakes: AtomicUsize,
}

impl LoopLink for Link {
    fn wake_conn(&self, _id: u64) {
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
    fn close_conn(&self, _id: u64, _err: Option<io::Error>) {}
    fn post_task(&self, _id: u64, _task: Task) {}
}

/// A ring-mode connection on a nonblocking socket, its link, and the peer (nonblocking too).
fn conn(ring: bool) -> (Arc<ConnInner>, Arc<Link>, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (s, _) = l.accept().unwrap();
    s.set_nonblocking(true).unwrap();
    peer.set_nonblocking(true).unwrap();
    let a = s.local_addr().unwrap();
    let link = Arc::new(Link::default());
    let c = ConnInner::new(1, s, a, a, link.clone(), Arc::new(Config::default()));
    c.set_ring_sends(ring);
    (c, link, peer)
}

/// The bytes `rs` describes, copied out.
fn described(rs: &RingSend) -> Vec<u8> {
    let mut v = Vec::new();
    for &(addr, len) in rs.parts() {
        // SAFETY: the connection keeps the described bytes alive and unchanged until the send
        // is reported (`ring_sent` / `ring_release`), which every test does only after this.
        v.extend_from_slice(unsafe { std::slice::from_raw_parts(addr as *const u8, len) });
    }
    v
}

/// Plays the kernel: writes the first `max` described bytes to `c`'s socket (the test's peer
/// reads them) and returns the count, as a send completion would.
fn kernel_send(c: &ConnInner, rs: &RingSend, max: usize) -> i32 {
    let bytes = described(rs);
    let n = bytes.len().min(max);
    let mut s = c.stream();
    s.write_all(&bytes[..n]).unwrap();
    n as i32
}

/// Reports a completion; whether the queue drained.
fn drained(c: &ConnInner, res: i32, rs: &mut RingSend) -> bool {
    matches!(c.ring_sent(res, rs).unwrap(), RingSent::Drained { .. })
}

/// Everything readable on `peer` right now.
fn read_now(peer: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match peer.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => panic!("read: {e}"),
        }
    }
    out
}

/// Reads until `n` bytes arrived (they were written to a local socket already).
fn read_n(peer: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < n {
        out.extend(read_now(peer));
    }
    out
}

#[cfg(target_os = "linux")]
const EAGAIN: i32 = 11;
#[cfg(not(target_os = "linux"))]
const EAGAIN: i32 = 35;
#[cfg(target_os = "linux")]
const ECONNRESET: i32 = 104;
#[cfg(not(target_os = "linux"))]
const ECONNRESET: i32 = 54;

#[test]
fn a_flush_describes_the_queue_instead_of_writing_it() {
    let (c, _link, mut peer) = conn(true);
    c.set_corked(true);
    c.send(b"hello ").unwrap();
    c.send_owned(b"owned ".to_vec()).unwrap();
    c.send_shared(akio_buf::SharedBuf::from(b"shared".to_vec()))
        .unwrap();
    let mut rs = RingSend::default();
    let q = c.uncork_flush_ring(&mut rs).unwrap();
    assert_eq!(q, 18, "the bytes stay queued while in flight");
    // The small owned buffer was copied into the tail (`RING_COALESCE`); the shared one is not.
    assert_eq!(rs.parts().len(), 2);
    assert_eq!(described(&rs), b"hello owned shared");
    assert!(
        read_now(&mut peer).is_empty(),
        "nothing written by the flush"
    );
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    assert!(drained(&c, n, &mut rs), "queue empty after the whole send");
    assert!(rs.parts().is_empty());
    assert_eq!(c.queued_bytes(), 0);
    assert_eq!(read_n(&mut peer, 18), b"hello owned shared");
    assert_eq!(c.debug_state().0, 18, "bytes counted as sent");
}

#[test]
fn sends_during_a_send_in_flight_queue_behind_it() {
    let (c, link, mut peer) = conn(true);
    c.set_corked(true);
    c.send(b"first;").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    let first = described(&rs);
    // Not corked any more: without a send in flight this would be written right away.
    c.send(b"second;").unwrap();
    c.send_owned(b"third;".to_vec()).unwrap();
    c.flush().unwrap();
    assert!(
        read_now(&mut peer).is_empty(),
        "nothing overtakes the send in flight"
    );
    assert_eq!(described(&rs), first, "the send in flight is unchanged");
    assert_eq!(c.queued_bytes(), 19);
    let woken = link.wakes.load(Ordering::SeqCst);
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    assert!(!drained(&c, n, &mut rs), "the rest goes as the next send");
    assert_eq!(described(&rs), b"second;third;");
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    assert!(drained(&c, n, &mut rs));
    assert_eq!(read_n(&mut peer, 19), b"first;second;third;");
    assert!(link.wakes.load(Ordering::SeqCst) >= woken);
}

#[test]
fn a_short_send_resumes_where_it_stopped() {
    let (c, _link, mut peer) = conn(true);
    let body: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    c.set_corked(true);
    c.send(b"head:").unwrap();
    c.send_owned(body.clone()).unwrap();
    c.send(b":tail").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    let mut want = b"head:".to_vec();
    want.extend_from_slice(&body);
    want.extend_from_slice(b":tail");
    let mut got = Vec::new();
    // Completions of 3, then 7 777, then the rest: each next send starts at the first byte
    // not sent.
    for max in [3, 7_777, usize::MAX] {
        let n = kernel_send(&c, &rs, max);
        rs.clear();
        let empty = drained(&c, n, &mut rs);
        got.extend(read_n(&mut peer, n as usize));
        if empty {
            break;
        }
    }
    assert_eq!(got.len(), want.len());
    assert!(got == want, "bytes differ after short sends");
    assert_eq!(c.queued_bytes(), 0);
}

#[test]
fn a_send_not_yet_submitted_takes_what_was_queued_after_it() {
    let (c, _link, mut peer) = conn(true);
    c.set_corked(true);
    c.send(b"abc").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    let addr = rs.parts()[0].0;
    // Another callback of the same batch answers too (corked, as the loop does).
    c.set_corked(true);
    c.send(b"def").unwrap();
    c.send_owned(b"ghi".to_vec()).unwrap();
    c.uncork_flush_ring(&mut rs).unwrap();
    assert_eq!(
        described(&rs),
        b"abc",
        "a send in flight is not described twice"
    );
    assert_eq!(c.ring_redescribe(&mut rs), 9);
    assert_eq!(rs.parts()[0].0, addr, "appended in place, not moved");
    assert_eq!(described(&rs), b"abcdefghi");
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    assert!(drained(&c, n, &mut rs));
    assert_eq!(read_n(&mut peer, 9), b"abcdefghi");
}

#[test]
fn a_close_keeps_the_bytes_in_flight_until_released() {
    let (c, _link, _peer) = conn(true);
    let body = vec![7u8; 300_000];
    c.set_corked(true);
    c.send_owned(body.clone()).unwrap();
    c.send(b"more").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    c.mark_closed();
    assert_eq!(
        c.queued_bytes(),
        0,
        "a closed connection counts nothing as queued"
    );
    // The kernel may still be reading: the memory is the same and unchanged.
    let got = described(&rs);
    assert_eq!(&got[..body.len()], &body[..]);
    assert_eq!(&got[body.len()..], b"more");
    assert!(c.send(b"late").is_err());
    // The completion of a closed connection's send frees the chunks and asks for nothing more.
    let mut next = RingSend::default();
    assert!(drained(&c, -ECONNRESET, &mut next));
    assert!(next.parts().is_empty());
    c.ring_release(); // idempotent
}

#[test]
fn a_send_described_but_never_submitted_is_released_with_the_close() {
    let (c, _link, _peer) = conn(true);
    c.set_corked(true);
    c.send(b"never sent").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    c.mark_closed();
    c.ring_release();
    assert_eq!(c.ring_redescribe(&mut rs), 0, "nothing in flight any more");
}

#[test]
fn eagain_waits_and_errors_fail() {
    let (c, _link, mut peer) = conn(true);
    c.set_corked(true);
    c.send(b"x".repeat(10).as_slice()).unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    rs.clear();
    // Nothing sent, socket full: no next send; the loop waits for writability.
    assert!(!drained(&c, -EAGAIN, &mut rs));
    assert!(rs.parts().is_empty());
    assert_eq!(c.queued_bytes(), 10);
    // Writable again: the same bytes are described again.
    assert!(!c.flush_queue_ring(&mut rs).unwrap());
    assert_eq!(described(&rs), b"xxxxxxxxxx");
    rs.clear();
    let e = c.ring_sent(-ECONNRESET, &mut rs).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
    assert!(read_now(&mut peer).is_empty());
}

#[test]
fn a_zero_byte_completion_is_an_error() {
    let (c, _link, _peer) = conn(true);
    c.set_corked(true);
    c.send(b"abc").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    rs.clear();
    let e = c.ring_sent(0, &mut rs).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::WriteZero);
}

#[cfg(unix)]
#[test]
fn a_file_goes_out_with_sendfile_between_ring_sends() {
    let (c, _link, mut peer) = conn(true);
    let path = std::env::temp_dir().join(format!("akio-ring-send-{}", std::process::id()));
    std::fs::write(&path, b"FILE").unwrap();
    let file = Arc::new(std::fs::File::open(&path).unwrap());
    std::fs::remove_file(&path).unwrap();
    c.set_corked(true);
    c.send(b"a:").unwrap();
    c.send_file(file, 0, 4).unwrap();
    c.send(b":b").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    assert_eq!(described(&rs), b"a:", "a send stops in front of the file");
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    // The completion runs the file with sendfile, then describes what follows it.
    assert!(!drained(&c, n, &mut rs));
    assert_eq!(described(&rs), b":b");
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    assert!(drained(&c, n, &mut rs));
    assert_eq!(read_n(&mut peer, 8), b"a:FILE:b");
}

#[test]
fn without_ring_mode_a_ring_flush_writes_as_before() {
    let (c, _link, mut peer) = conn(false);
    c.set_corked(true);
    c.send(b"plain").unwrap();
    let mut rs = RingSend::default();
    assert_eq!(c.uncork_flush_ring(&mut rs).unwrap(), 0);
    assert!(rs.parts().is_empty());
    assert_eq!(read_n(&mut peer, 5), b"plain");
}

#[test]
fn small_owned_buffers_share_the_tail_and_large_ones_stay_whole() {
    let (c, _link, mut peer) = conn(true);
    c.set_corked(true);
    for i in 0..16u8 {
        c.send_owned(vec![b'a' + i; 130]).unwrap();
    }
    let big = vec![b'Z'; 5000];
    c.send_owned(big.clone()).unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    assert_eq!(
        rs.parts().len(),
        2,
        "16 small answers in one 4 KiB tail, the large one whole"
    );
    let mut want = Vec::new();
    for i in 0..16u8 {
        want.extend_from_slice(&[b'a' + i; 130]);
    }
    want.extend_from_slice(&big);
    assert!(described(&rs) == want);
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    assert!(drained(&c, n, &mut rs));
    assert!(read_n(&mut peer, want.len()) == want);
}

#[test]
fn the_completion_that_drains_reports_close_after_send() {
    let (c, _link, mut peer) = conn(true);
    c.set_corked(true);
    c.send(b"bye").unwrap();
    let mut rs = RingSend::default();
    c.uncork_flush_ring(&mut rs).unwrap();
    c.close_after_send();
    let n = kernel_send(&c, &rs, usize::MAX);
    rs.clear();
    assert_eq!(
        c.ring_sent(n, &mut rs).unwrap(),
        RingSent::Drained { close: true }
    );
    assert_eq!(read_n(&mut peer, 3), b"bye");
}
