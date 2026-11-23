use std::{
    any::Any,
    collections::VecDeque,
    io::{self, IoSlice, Write},
    marker::PhantomData,
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::{Arc, OnceLock},
};

use akio_buf::SharedBuf;

use crate::{
    Config, Error, Handler, LoopStats, Pool, Result,
    sync::{AtomicBool, AtomicU8, AtomicU32, Mutex, MutexGuard, Ordering},
};

const OPEN: u8 = 0;
const CLOSING: u8 = 1;
const CLOSED: u8 = 2;

/// `ConnInner::offload`: nothing to do.
const OFFLOAD_NONE: u8 = 0;
/// `ConnInner::offload` bit: the transport wants [`Transport::offload`] calls.
#[cfg(target_os = "linux")]
const OFFLOAD_PENDING: u8 = 1;
/// `ConnInner::offload` bit: the read direction is in the kernel.
const OFFLOAD_RX: u8 = 2;
/// `ConnInner::offload` bit: the send direction is in the kernel and the transport wants the
/// read direction too, once the backend can stop its reads (`offload_rx_now`).
#[cfg(target_os = "linux")]
const OFFLOAD_RX_WAIT: u8 = 4;
/// The smallest read buffer that takes a whole kernel TLS control record (16 KiB of content;
/// the kernel delivers one record per read).
#[cfg(target_os = "linux")]
const KERNEL_RX_MIN_BUF: usize = 16 << 10;

/// How a connection reaches its owning I/O loop. Implemented by backends.
///
/// Implementations must make `wake_conn` / `close_conn` cheap, callable from any thread
/// (including the loop's own, from inside callbacks) and never call user code.
#[doc(hidden)]
pub trait LoopLink: Send + Sync {
    /// Ask the loop to re-evaluate connection `id`: flush queued output, apply read/write
    /// interest, and close it if `close_after_send` has drained.
    fn wake_conn(&self, id: u64);
    /// Ask the loop to close connection `id` (running `on_close` with `err`).
    fn close_conn(&self, id: u64, err: Option<io::Error>);
    /// Runs `task` on connection `id`'s handler, on its owning I/O thread (dropped if the
    /// connection is gone). Used for `spawn_blocking` completions.
    fn post_task(&self, id: u64, task: Task);
    /// The logical pool, if the engine has one.
    fn pool(&self) -> Option<&Pool> {
        None
    }
    /// Counters of the owning I/O thread, if the backend keeps them.
    fn stats(&self) -> Option<Arc<LoopStats>> {
        None
    }
}

/// A type-erased completion for a connection's handler (see [`LoopLink::post_task`]).
#[doc(hidden)]
pub type Task = Box<dyn Any + Send>;

/// What a [`Task`] holds for handler type `H`.
pub(crate) type Completion<H> = Box<dyn FnOnce(&mut H, &Conn<H>) + Send>;

/// A datagram's IP header fields in one word: the traffic class byte (DSCP and ECN) in the low
/// byte, the TTL / hop limit in the high one (0: the socket's); 0 sends no control message.
const fn ip_fields(tos: u8, ttl: u8) -> u16 {
    tos as u16 | (ttl as u16) << 8
}

enum Bytes {
    Owned(Vec<u8>),
    Shared(SharedBuf),
    /// UDP: consecutive datagrams of `.1` bytes each (the last may be shorter), see
    /// [`Conn::send_segments`], sent with the IP header fields `.2` (see [`ip_fields`]).
    Segmented(Vec<u8>, usize, u16),
    /// `len` bytes of `file` from `start`, sent with `sendfile(2)` (never copied into memory).
    #[cfg(unix)]
    File {
        file: Arc<std::fs::File>,
        start: u64,
        len: u64,
    },
    /// An operation on the socket, run in order (kernel TLS, see [`SocketOp`]). Carries no
    /// bytes; a write never reaches past it.
    #[cfg(target_os = "linux")]
    Op(Box<dyn SocketOp>),
}

struct Chunk {
    bytes: Bytes,
    off: usize,
}

impl Chunk {
    fn rest(&self) -> &[u8] {
        match &self.bytes {
            Bytes::Owned(v) => &v[self.off..],
            Bytes::Shared(s) => &s[self.off..],
            Bytes::Segmented(v, ..) => &v[self.off..],
            #[cfg(unix)]
            Bytes::File { .. } => &[],
            #[cfg(target_os = "linux")]
            Bytes::Op(_) => &[],
        }
    }

    /// An operation chunk ([`Bytes::Op`]): writes stop in front of it.
    #[inline]
    fn is_op(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.bytes, Bytes::Op(_))
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Bytes still to send (file bytes included).
    fn remaining(&self) -> usize {
        match &self.bytes {
            #[cfg(unix)]
            Bytes::File { len, .. } => (*len as usize) - self.off,
            _ => self.rest().len(),
        }
    }

    fn is_file(&self) -> bool {
        #[cfg(unix)]
        {
            matches!(self.bytes, Bytes::File { .. })
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// A queue whose first element is held inline, so the common case (one item in flight at a
/// time: one coalesced response in the send queue, one reserved response slot) never allocates a
/// `VecDeque`, and an idle connection keeps no queue allocation (they used to stay at their
/// first growth, a few hundred bytes per connection).
struct InlineDeque<T> {
    head: Option<T>,
    /// Elements after `head`; empty whenever `head` is `None`.
    rest: VecDeque<T>,
}

impl<T> Default for InlineDeque<T> {
    fn default() -> Self {
        InlineDeque {
            head: None,
            rest: VecDeque::new(),
        }
    }
}

impl<T> InlineDeque<T> {
    #[inline]
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    #[inline]
    fn len(&self) -> usize {
        usize::from(self.head.is_some()) + self.rest.len()
    }

    #[inline]
    fn front(&self) -> Option<&T> {
        self.head.as_ref()
    }

    #[inline]
    fn front_mut(&mut self) -> Option<&mut T> {
        self.head.as_mut()
    }

    #[inline]
    fn back_mut(&mut self) -> Option<&mut T> {
        match self.rest.back_mut() {
            Some(c) => Some(c),
            None => self.head.as_mut(),
        }
    }

    #[inline]
    fn push_back(&mut self, c: T) {
        if self.head.is_none() {
            self.head = Some(c);
        } else {
            self.rest.push_back(c);
        }
    }

    #[inline]
    fn pop_front(&mut self) -> Option<T> {
        let h = self.head.take();
        self.head = self.rest.pop_front();
        h
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.head.iter().chain(self.rest.iter())
    }

    /// The `i`-th element.
    #[inline]
    fn get_mut(&mut self, i: usize) -> Option<&mut T> {
        match i {
            0 => self.head.as_mut(),
            _ => self.rest.get_mut(i - 1),
        }
    }

    /// Removes and returns every element; the overflow allocation is released.
    fn take_all(&mut self) -> impl Iterator<Item = T> {
        self.head
            .take()
            .into_iter()
            .chain(std::mem::take(&mut self.rest))
    }
}

/// A byte-stream transformation layered under a connection, such as TLS (see `akio-tls`).
///
/// Everything the application `send`s is passed through [`seal`](Transport::seal) before it
/// reaches the socket, and everything read from the socket through [`recv`](Transport::recv)
/// before it reaches `on_data`. All calls happen under the connection's write lock, in wire
/// order, and must not block or call back into the connection.
pub trait Transport: Send + 'static {
    /// Consumes bytes read from the peer. Appends decoded application bytes to `plain` and any
    /// bytes that must go to the peer (handshake records, alerts) to `out`. On error, what was
    /// appended to `out` is still sent before the connection closes.
    fn recv(&mut self, cipher: &[u8], plain: &mut Vec<u8>, out: &mut Vec<u8>) -> io::Result<()>;
    /// Encodes application bytes for the wire, appending to `out`. May append nothing while the
    /// transport is not ready yet (it must keep the bytes and emit them from a later call).
    fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> io::Result<()>;
    /// The application is done sending: append the closing record(s), if any, to `out`.
    fn shutdown(&mut self, out: &mut Vec<u8>);
    /// For downcasting to the concrete transport.
    fn as_any(&mut self) -> &mut dyn Any;
    /// Short name for the connection table (`"tls"`, ...).
    fn name(&self) -> &'static str {
        "custom"
    }
    /// Whether the transport is still negotiating (a failure now counts as a failed handshake).
    fn handshaking(&self) -> bool {
        false
    }
    /// How long the handshake may take: a connection whose transport is still
    /// [`handshaking`](Transport::handshaking) this long after it opened is closed with
    /// `ErrorKind::TimedOut` (and counted as a failed handshake) by the engine's TCP backends.
    /// `None` (the default): no limit.
    fn handshake_timeout(&self) -> Option<std::time::Duration> {
        None
    }
    /// Receives the connection's [`TransportWaker`] once, when the transport is installed.
    /// A transport that waits for something outside the byte stream (a remote lookup during a
    /// handshake) keeps it and calls [`TransportWaker::wake`] when that completes. The
    /// default ignores it.
    fn set_waker(&mut self, waker: TransportWaker) {
        let _ = waker;
    }

    /// Whether the transport could still move (more of) its work into the kernel with
    /// [`offload`](Self::offload) (Linux; kernel TLS). Read when the transport is installed and
    /// after every `offload` call; once `false` the engine stops asking. Default: `false`.
    #[cfg(target_os = "linux")]
    fn wants_offload(&self) -> bool {
        false
    }

    /// Offers the connection's TCP socket `fd` (local address `local`) for the kernel to take
    /// over the transport's work (Linux; kernel TLS). Called on the owning I/O thread, between
    /// reads, with nothing queued for writing, while [`wants_offload`](Self::wants_offload)
    /// says so. `rx_ok`: the backend can switch the read direction now (no read is in flight
    /// that could hold bytes the transport has not seen); without it only the send direction
    /// may move. Returns the directions in the kernel so far (cumulative): from then on the
    /// engine writes application bytes to the socket as they are (`tx`, see
    /// [`kernel_send`](Self::kernel_send)) and hands what it reads to `on_data` as it is
    /// (`rx`, see [`kernel_record`](Self::kernel_record)). An error closes the connection.
    #[cfg(target_os = "linux")]
    fn offload(
        &mut self,
        fd: std::os::fd::RawFd,
        local: SocketAddr,
        rx_ok: bool,
    ) -> io::Result<Offloaded> {
        let _ = (fd, local, rx_ok);
        Ok(Offloaded::default())
    }

    /// The send direction is in the kernel: `len` application bytes are about to be written to
    /// the socket as they are. The transport may push operations that must run before them (a
    /// TLS 1.3 key update) to `ops`. Default: nothing.
    #[cfg(target_os = "linux")]
    fn kernel_send(&mut self, len: usize, ops: &mut Vec<Box<dyn SocketOp>>) -> io::Result<()> {
        let _ = (len, ops);
        Ok(())
    }

    /// The send direction is in the kernel: moves the operations that `recv`, `shutdown` or
    /// `kernel_record` produced into `ops`, in order (with the send direction in the kernel
    /// they append nothing to `out`). Default: nothing.
    #[cfg(target_os = "linux")]
    fn take_ops(&mut self, ops: &mut Vec<Box<dyn SocketOp>>) {
        let _ = ops;
    }

    /// The receive direction is in the kernel: a record that is not application data arrived
    /// (TLS: content type `typ`, decrypted `content`; an alert, a post-handshake message).
    /// `Ok(false)`: the peer closed its side (close_notify). An error closes the connection
    /// after what [`take_ops`](Self::take_ops) then returns (an alert) is sent.
    #[cfg(target_os = "linux")]
    fn kernel_record(&mut self, typ: u8, content: &[u8]) -> io::Result<bool> {
        let _ = (typ, content);
        Err(io::ErrorKind::InvalidData.into())
    }
}

/// The directions of a [`Transport`] that the kernel has taken over (Linux; kernel TLS).
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Offloaded {
    /// What the application sends goes to the socket unencoded; the kernel encodes it.
    pub tx: bool,
    /// What the socket delivers is already decoded.
    pub rx: bool,
}

#[cfg(target_os = "linux")]
impl Offloaded {
    /// `tx` and `rx` as given.
    pub fn new(tx: bool, rx: bool) -> Offloaded {
        Offloaded { tx, rx }
    }
}

/// An operation on a connection's socket that must happen in order with its queued output,
/// produced by a [`Transport`] whose send direction is in the kernel (Linux; kernel TLS: a
/// control record, new send keys).
#[cfg(target_os = "linux")]
pub trait SocketOp: Send + 'static {
    /// Runs on the socket `fd` (non-blocking). `Ok(true)`: done. `Ok(false)`: the socket is
    /// full; run again once it is writable. An error closes the connection.
    fn run(&mut self, fd: std::os::fd::RawFd) -> io::Result<bool>;
}

/// What [`ConnInner::kernel_read_record`] read (Linux).
#[cfg(target_os = "linux")]
#[doc(hidden)]
#[derive(Debug)]
pub enum KernelRead {
    /// `n` bytes of application data (0: end of stream, or the peer's close_notify).
    Data(usize),
    /// A control record, handled by the transport.
    Control,
}

/// Lets a [`Transport`] that is waiting for something other than the peer's bytes resume:
/// [`wake`](Self::wake) (from any thread) makes the connection's owning I/O thread call
/// [`Transport::recv`] with no input, then hand any decoded bytes to `on_data` and flush what
/// the transport produced, as for bytes read from the socket. Cheap to clone; holds no strong
/// reference to the connection.
#[derive(Clone)]
pub struct TransportWaker {
    inner: std::sync::Weak<ConnInner>,
}

impl std::fmt::Debug for TransportWaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportWaker").finish_non_exhaustive()
    }
}

impl TransportWaker {
    pub(crate) fn new(inner: &Arc<ConnInner>) -> TransportWaker {
        TransportWaker {
            inner: Arc::downgrade(inner),
        }
    }

    /// A waker attached to no connection: [`wake`](Self::wake) does nothing (tests, and
    /// transports driven outside an engine).
    pub fn noop() -> TransportWaker {
        TransportWaker {
            inner: std::sync::Weak::new(),
        }
    }

    /// Schedules the transport poll on the connection's I/O thread. Does nothing once the
    /// connection is closed or gone.
    pub fn wake(&self) {
        if let Some(i) = self.inner.upgrade() {
            if i.is_open() {
                i.link.post_task(i.id, Box::new(TransportPoll));
            }
        }
    }
}

/// The [`Task`] a [`TransportWaker`] posts.
pub(crate) struct TransportPoll;

#[derive(Default)]
struct WriteState {
    /// UDP: every chunk is one datagram; never coalesced, never partially written.
    datagram: bool,
    transport: Option<Box<dyn Transport>>,
    /// The transport's send direction is in the kernel ([`Transport::offload`]): application
    /// bytes go to the socket as they are.
    #[cfg(target_os = "linux")]
    kernel_tx: bool,
    queue: InlineDeque<Chunk>,
    queued: usize,
    /// Bytes of queued file chunks: they use no memory, so they are not in `queued`.
    file_bytes: u64,
    corked: bool,
    close_after_send: bool,
    /// Called once the queue is empty again (see [`Conn::on_drain`]).
    drain: Option<Box<dyn FnOnce() + Send>>,
    /// Bytes written to the socket so far.
    sent: u64,
    /// Counters of the owning I/O thread.
    stats: Option<Arc<LoopStats>>,
}

impl WriteState {
    /// `n` bytes reached the socket in one write.
    #[inline]
    fn wrote(&mut self, n: usize) {
        self.sent += n as u64;
        if let Some(s) = &self.stats {
            s.bytes_out.add(n as u64);
            s.writes.add(1);
            if self.datagram {
                s.datagrams_out.add(1);
            }
        }
    }

    #[inline]
    fn add_queued(&mut self, n: usize) {
        self.queued += n;
        if let Some(s) = &self.stats {
            s.queued_bytes.add(n as u64);
        }
    }

    #[inline]
    fn sub_queued(&mut self, n: usize) {
        self.queued -= n;
        if let Some(s) = &self.stats {
            s.queued_bytes.sub(n as u64);
        }
    }

    fn push_copy(&mut self, data: &[u8]) {
        self.add_queued(data.len());
        // Coalesce small writes into the tail buffer: fewer iovecs per writev.
        if self.datagram {
            // Datagram boundaries must survive.
        } else if let Some(Chunk {
            bytes: Bytes::Owned(v),
            ..
        }) = self.queue.back_mut()
        {
            if v.capacity() - v.len() >= data.len() {
                v.extend_from_slice(data);
                return;
            }
        }
        // A datagram buffer is never appended to: allocate it exactly, not a whole size class.
        let mut v = if self.datagram {
            Vec::with_capacity(data.len())
        } else {
            akio_buf::get(data.len())
        };
        v.extend_from_slice(data);
        self.queue.push_back(Chunk {
            bytes: Bytes::Owned(v),
            off: 0,
        });
    }

    fn consume(&mut self, mut n: usize) {
        while n > 0 {
            let front = self.queue.front_mut().expect("consumed more than queued");
            let left = front.remaining();
            let step = n.min(left);
            let file = front.is_file();
            if n < left {
                front.off += n;
            }
            if file {
                self.file_bytes -= step as u64;
            } else {
                self.sub_queued(step);
            }
            if n < left {
                return;
            }
            n -= left;
            if let Some(Chunk {
                bytes: Bytes::Owned(v) | Bytes::Segmented(v, ..),
                ..
            }) = self.queue.pop_front()
            {
                akio_buf::put(v);
            }
        }
    }

    /// UDP: the datagrams queued, in order, with their IP header fields (see [`ip_fields`]).
    fn datagrams_ip(&self) -> impl Iterator<Item = (&[u8], u16)> {
        self.queue.iter().flat_map(|c| {
            let rest = c.rest();
            let (seg, ip) = match c.bytes {
                Bytes::Segmented(_, seg, ip) => (seg, ip),
                _ => (rest.len().max(1), 0),
            };
            rest.chunks(seg).map(move |d| (d, ip))
        })
    }

    /// UDP: drops the first `k` queued datagrams (sent or refused).
    #[cfg(not(target_os = "linux"))] // Linux goes through `send_datagrams`
    fn consume_datagrams(&mut self, k: usize) {
        for _ in 0..k {
            let Some(front) = self.queue.front_mut() else {
                return;
            };
            let left = front.rest().len();
            let step = match front.bytes {
                Bytes::Segmented(_, seg, _) => seg.min(left),
                _ => left,
            };
            self.consume(step);
        }
    }

    /// UDP: the first `k` queued datagrams reached the socket: counts and drops them.
    fn sent_datagrams(&mut self, k: usize) {
        for _ in 0..k {
            let Some(front) = self.queue.front() else {
                return;
            };
            let left = front.rest().len();
            let step = match front.bytes {
                Bytes::Segmented(_, seg, _) => seg.min(left),
                _ => left,
            };
            self.wrote(step);
            self.consume(step);
        }
    }

    fn clear(&mut self) {
        for c in self.queue.take_all() {
            if let Bytes::Owned(v) | Bytes::Segmented(v, ..) = c.bytes {
                akio_buf::put(v);
            }
        }
        self.sub_queued(self.queued);
        self.file_bytes = 0;
    }
}

/// One connection's datagram queue taking part in [`send_datagrams`].
#[cfg(target_os = "linux")]
struct DgramItem<'a, 'g> {
    inner: &'a ConnInner,
    w: &'g mut WriteState,
    /// What [`ConnInner::flush_queue`] would return; set by `send_datagrams`.
    res: Option<io::Result<bool>>,
}

/// `send_datagrams`' per-thread state: the `sendmmsg` batch and, per message, (item,
/// datagrams in it); kept so a flush allocates nothing.
#[cfg(target_os = "linux")]
struct SendScratch {
    batch: akio_sys::SendBatch,
    map: Vec<(usize, usize)>,
}

#[cfg(target_os = "linux")]
thread_local! {
    static SEND_BATCH: std::cell::RefCell<SendScratch> = std::cell::RefCell::new(SendScratch {
        batch: akio_sys::SendBatch::new(),
        map: Vec::with_capacity(akio_sys::SEND_BATCH),
    });
}

/// Sends the datagrams queued in `items` (which share one socket) with `sendmmsg`, merging runs
/// of equal-size datagrams to one peer into a single GSO message when the kernel supports it.
/// Datagrams the network refuses are dropped, as in the one-at-a-time path. Sets every item's
/// `res`.
#[cfg(target_os = "linux")]
fn send_datagrams(items: &mut [DgramItem<'_, '_>]) {
    use akio_sys::{MAX_GSO_BYTES, MAX_GSO_SEGMENTS};
    const EIO: i32 = 5;
    const EINVAL: i32 = 22;

    /// Drops the datagrams of the first `done` messages from their queues.
    fn apply(items: &mut [DgramItem<'_, '_>], map: &[(usize, usize)]) {
        for &(k, cnt) in map {
            items[k].w.sent_datagrams(cnt);
        }
    }

    let Some(first) = items.first() else {
        return;
    };
    let fd = first.inner.udp_target().1;
    SEND_BATCH.with(|sc| {
        let mut sc = sc.borrow_mut();
        let SendScratch { batch: sb, map } = &mut *sc;
        loop {
            // The datagrams of the message being filled (on the stack: no allocation per flush).
            let mut parts: [&[u8]; MAX_GSO_SEGMENTS] = [&[]; MAX_GSO_SEGMENTS];
            let mut np = 0;
            let gso = akio_sys::gso_enabled();
            map.clear();
            let mut b = sb.batch();
            'fill: for (k, it) in items.iter().enumerate() {
                if it.res.is_some() {
                    continue;
                }
                let dest = it.inner.udp_target().0;
                let v6 = it.inner.local.is_ipv6();
                let (mut seg, mut total, mut ip) = (0, 0, 0);
                let mut iter = it.w.datagrams_ip().peekable();
                while let Some((d, e)) = iter.next() {
                    if np == 0 {
                        (seg, total, ip) = (d.len(), 0, e);
                    }
                    parts[np] = d;
                    np += 1;
                    total += d.len();
                    // Only the last datagram of a GSO message may be shorter than the others.
                    let joins = gso
                        && d.len() == seg
                        && np < MAX_GSO_SEGMENTS
                        && iter.peek().is_some_and(|&(n, e)| {
                            e == ip && n.len() <= seg && total + n.len() <= MAX_GSO_BYTES
                        });
                    if joins {
                        continue;
                    }
                    let g = if np > 1 { seg } else { 0 };
                    let (tos, ttl) = (ip as u8, (ip >> 8) as u8);
                    let pushed = b.push_ip(dest, &parts[..np], g, tos, ttl, v6);
                    let cnt = np;
                    np = 0;
                    if !pushed {
                        break 'fill;
                    }
                    map.push((k, cnt));
                }
            }
            if map.is_empty() {
                break;
            }
            // Messages from the front that were sent or dropped.
            let mut done = 0;
            // The socket is full: stop here.
            let mut full = false;
            let mut failed: Option<(usize, io::Error)> = None;
            while done < map.len() {
                match b.send(fd, done) {
                    Ok(0) => {
                        full = true;
                        break;
                    }
                    Ok(n) => done += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        full = true;
                        break;
                    }
                    Err(e) if b.is_gso(done) && matches!(e.raw_os_error(), Some(EIO | EINVAL)) => {
                        // The kernel or the device cannot segment: never try again.
                        akio_sys::disable_gso();
                        break;
                    }
                    Err(e) => {
                        let k = map[done].0;
                        if items[k].inner.fatal_datagram_error(&e) {
                            failed = Some((k, e));
                            break;
                        }
                        // Refused (too big, unreachable): drop it and go on.
                        done += 1;
                    }
                }
            }
            // `b` (borrowing the queues) is done with; drop what went out.
            apply(items, &map[..done]);
            if let Some((k, e)) = failed {
                items[k].res = Some(Err(e));
            }
            if full {
                break;
            }
        }
        for it in items.iter_mut() {
            if it.res.is_none() {
                it.res = Some(Ok(it.w.queue.is_empty()));
            }
        }
    });
}

/// One piece of a response written in order (see [`ResponseSlot::fill_parts`]).
#[derive(Debug)]
#[non_exhaustive]
pub enum Part {
    /// Bytes to send.
    Bytes(Vec<u8>),
    /// `len` bytes of a file from `offset`, sent with `sendfile(2)` where the transport allows.
    #[cfg(unix)]
    File {
        /// The open file.
        file: Arc<std::fs::File>,
        /// First byte to send.
        offset: u64,
        /// Number of bytes to send.
        len: u64,
    },
}

/// A response position that is open for writing: head-of-line responses are streamed.
struct Stream {
    /// Output held back until every earlier response has been written.
    pending: Vec<u8>,
    live: bool,
    finished: bool,
    close: bool,
}

enum Entry {
    Empty,
    /// Complete; the flag closes the connection once it and everything before is out.
    Ready(Vec<Part>, bool),
    Stream(Stream),
}

/// Responses reserved in request order, possibly filled out of order (see [`ResponseSlot`]).
#[derive(Default)]
struct Ordered {
    /// Sequence number of `entries[0]`.
    head: u64,
    next: u64,
    entries: InlineDeque<Entry>,
    /// Bytes held in memory behind the first position: complete responses waiting for it, and
    /// what streams that are not first in line wrote so far.
    held: usize,
    /// Reads are paused by the limits (mirrors `ConnInner::ordered_hold`, which the loop
    /// reads; this copy is only touched under the lock, so the per-response check needs no
    /// atomic).
    paused: bool,
}

/// `Config::max_pending_responses` as a count (0 would pause before every response: it means 1).
fn pending_limit(cfg: &Config) -> usize {
    cfg.max_pending_responses.map_or(usize::MAX, |l| l.max(1))
}

/// Bytes a response of `parts` holds in memory (files are read when sent).
fn parts_len(parts: &[Part]) -> usize {
    parts
        .iter()
        .map(|p| match p {
            Part::Bytes(b) => b.len(),
            #[cfg(unix)]
            Part::File { .. } => 0,
        })
        .sum()
}

/// The socket under a connection: its own TCP stream, or a peer on a shared UDP socket.
enum Sock {
    Tcp(TcpStream),
    Udp {
        sock: Arc<UdpSocket>,
        peer: SocketAddr,
        /// The socket is `connect`ed to `peer` (a dialed client): use `send`, not `send_to`
        /// (BSD rejects `sendto` on a connected socket).
        connected: bool,
    },
    /// No kernel socket: a userspace network stack (`akio-dpdk`) owns the wire. Writes are
    /// never attempted from `send`; everything is queued and the owning loop moves it into the
    /// stack with [`ConnInner::drain_output`]. `datagram`: UDP semantics (one chunk, one datagram).
    Virtual {
        datagram: bool,
    },
}

/// Type-erased shared connection state: socket, lifecycle, send queue and its lock (ADR-002).
///
/// Public only so that backend crates can drive it; applications use [`Conn`].
#[doc(hidden)]
pub struct ConnInner {
    id: u64,
    state: AtomicU8,
    hold: AtomicBool,
    /// Reads paused because too many ordered responses are pending (see
    /// `Config::max_pending_responses`); separate from `hold`, which is the application's.
    ordered_hold: AtomicBool,
    /// The loop corked the connection around a callback ([`set_corked`](Self::set_corked)):
    /// an atomic, so corking costs no lock. Read together with `WriteState::corked` (the
    /// application's [`cork`](Self::cork)) under the write lock; cleared under it too.
    loop_cork: AtomicBool,
    /// A drain waiter was moved to `drained`: lets [`run_drained`](Self::run_drained) skip its
    /// lock in the usual case of none.
    drain_pending: AtomicBool,
    /// `Config::max_pending_responses`, resolved once (`usize::MAX`: none).
    pending_limit: usize,
    /// Exempt from the write backpressure (see [`set_relayed`](Self::set_relayed)).
    relayed: AtomicBool,
    /// UDP: the traffic class byte (DSCP and ECN) of the datagram being delivered (set by the
    /// loop).
    rx_tos: AtomicU8,
    /// UDP: the TTL / hop limit of the datagram being delivered (0: not reported).
    rx_ttl: AtomicU8,
    /// UDP: the index of the interface the datagram being delivered arrived on (0: not
    /// reported).
    rx_interface: AtomicU32,
    /// Kernel offload of the transport (Linux, [`Transport::offload`]): `OFFLOAD_NONE`,
    /// `OFFLOAD_PENDING` (ask after reads and flushes) and `OFFLOAD_RX` (bit: the read
    /// direction is in the kernel). Read without the lock by the loop's hot paths.
    offload: AtomicU8,
    /// The backend allows the read direction to move into the kernel (no read can be in
    /// flight between its reads; see [`set_rx_offload_ok`](Self::set_rx_offload_ok)).
    rx_offload_ok: AtomicBool,
    write: Mutex<WriteState>,
    /// A drain waiter whose condition was met while the write lock was held; run right after.
    drained: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Allocated by the first `reserve_response` (HTTP), so plain TCP connections, idle ones
    /// above all, do not carry it.
    ordered: Mutex<Option<Box<Ordered>>>,
    sock: Sock,
    link: Arc<dyn LoopLink>,
    cfg: Arc<Config>,
    local: SocketAddr,
    peer: SocketAddr,
    /// Set once by the layer that read the connection's first bytes (a PROXY header, ADR-095);
    /// read without a lock.
    attachment: OnceLock<Arc<dyn Any + Send + Sync>>,
}

#[doc(hidden)]
impl ConnInner {
    pub fn new(
        id: u64,
        stream: TcpStream,
        local: SocketAddr,
        peer: SocketAddr,
        link: Arc<dyn LoopLink>,
        cfg: Arc<Config>,
    ) -> Arc<ConnInner> {
        Arc::new(ConnInner {
            id,
            state: AtomicU8::new(OPEN),
            hold: AtomicBool::new(false),
            ordered_hold: AtomicBool::new(false),
            loop_cork: AtomicBool::new(false),
            drain_pending: AtomicBool::new(false),
            pending_limit: pending_limit(&cfg),
            relayed: AtomicBool::new(false),
            rx_tos: AtomicU8::new(0),
            rx_ttl: AtomicU8::new(0),
            rx_interface: AtomicU32::new(0),
            offload: AtomicU8::new(OFFLOAD_NONE),
            rx_offload_ok: AtomicBool::new(false),
            write: Mutex::new(WriteState {
                stats: link.stats(),
                ..WriteState::default()
            }),
            drained: Mutex::new(None),
            ordered: Mutex::new(None),
            sock: Sock::Tcp(stream),
            link,
            cfg,
            local,
            peer,
            attachment: OnceLock::new(),
        })
    }

    /// A "connection" to `peer` over the UDP socket `sock` shared with other peers. Each `send`
    /// is one datagram to `peer`; reads are delivered by the backend as whole datagrams.
    pub fn new_udp(
        id: u64,
        sock: Arc<UdpSocket>,
        connected: bool,
        local: SocketAddr,
        peer: SocketAddr,
        link: Arc<dyn LoopLink>,
        cfg: Arc<Config>,
    ) -> Arc<ConnInner> {
        Arc::new(ConnInner {
            id,
            state: AtomicU8::new(OPEN),
            hold: AtomicBool::new(false),
            ordered_hold: AtomicBool::new(false),
            loop_cork: AtomicBool::new(false),
            drain_pending: AtomicBool::new(false),
            pending_limit: pending_limit(&cfg),
            relayed: AtomicBool::new(false),
            rx_tos: AtomicU8::new(0),
            rx_ttl: AtomicU8::new(0),
            rx_interface: AtomicU32::new(0),
            offload: AtomicU8::new(OFFLOAD_NONE),
            rx_offload_ok: AtomicBool::new(false),
            write: Mutex::new(WriteState {
                datagram: true,
                stats: link.stats(),
                ..WriteState::default()
            }),
            drained: Mutex::new(None),
            ordered: Mutex::new(None),
            sock: Sock::Udp {
                sock,
                peer,
                connected,
            },
            link,
            cfg,
            local,
            peer,
            attachment: OnceLock::new(),
        })
    }

    /// A connection of a userspace network stack: there is no kernel socket. `send` only queues
    /// (and wakes the loop); the loop hands the queued bytes to its stack with
    /// [`drain_output`](Self::drain_output). `datagram`: every chunk is one datagram (UDP).
    pub fn new_virtual(
        id: u64,
        datagram: bool,
        local: SocketAddr,
        peer: SocketAddr,
        link: Arc<dyn LoopLink>,
        cfg: Arc<Config>,
    ) -> Arc<ConnInner> {
        Arc::new(ConnInner {
            id,
            state: AtomicU8::new(OPEN),
            hold: AtomicBool::new(false),
            ordered_hold: AtomicBool::new(false),
            loop_cork: AtomicBool::new(false),
            drain_pending: AtomicBool::new(false),
            pending_limit: pending_limit(&cfg),
            relayed: AtomicBool::new(false),
            rx_tos: AtomicU8::new(0),
            rx_ttl: AtomicU8::new(0),
            rx_interface: AtomicU32::new(0),
            offload: AtomicU8::new(OFFLOAD_NONE),
            rx_offload_ok: AtomicBool::new(false),
            write: Mutex::new(WriteState {
                datagram,
                stats: link.stats(),
                ..WriteState::default()
            }),
            drained: Mutex::new(None),
            ordered: Mutex::new(None),
            sock: Sock::Virtual { datagram },
            link,
            cfg,
            local,
            peer,
            attachment: OnceLock::new(),
        })
    }

    /// Loop side, userspace stacks ([`new_virtual`](Self::new_virtual)): hands queued output to
    /// `sink` in order. For a datagram connection every call is one whole datagram and any
    /// non-zero return consumes it (a stack that cannot ever send it drops it, as UDP does);
    /// for a stream, `sink` returns how many bytes it took. A return of 0 means "full, try
    /// later" and stops. `Ok(true)` once the queue is empty.
    pub fn drain_output(&self, sink: &mut dyn FnMut(&[u8]) -> usize) -> io::Result<bool> {
        self.drain_output_ecn(&mut |d, _| sink(d))
    }

    /// [`drain_output`](Self::drain_output), with each datagram's ECN codepoint (0 = not
    /// ECN-capable; always 0 for a stream).
    pub fn drain_output_ecn(&self, sink: &mut dyn FnMut(&[u8], u8) -> usize) -> io::Result<bool> {
        let mut w = self.lock();
        let r = Self::drain_virtual(&mut w, sink);
        if matches!(r, Ok(true)) {
            self.stash_drain(&mut w);
        }
        drop(w);
        self.run_drained();
        r
    }

    /// File chunks are read here, on the owning loop, 16 KiB per step (a userspace stack has no
    /// `sendfile`): a page-cache miss waits for the disk on that loop.
    fn drain_virtual(
        w: &mut WriteState,
        sink: &mut dyn FnMut(&[u8], u8) -> usize,
    ) -> io::Result<bool> {
        if w.datagram {
            loop {
                let Some((d, ip)) = w.datagrams_ip().next() else {
                    return Ok(true);
                };
                // Userspace stacks take the ECN codepoint only.
                if sink(d, ip as u8 & 3) == 0 {
                    return Ok(false);
                }
                w.sent_datagrams(1);
            }
        }
        while let Some(front) = w.queue.front() {
            #[cfg(unix)]
            if let Bytes::File { file, start, len } = &front.bytes {
                use std::os::unix::fs::FileExt;
                let (pos, left) = (start + front.off as u64, (*len as usize) - front.off);
                let mut buf = vec![0u8; left.min(16 << 10)];
                let n = file.read_at(&mut buf, pos)?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into()); // file shrank
                }
                let took = sink(&buf[..n], 0);
                if took == 0 {
                    return Ok(false);
                }
                w.wrote(took);
                w.consume(took);
                continue;
            }
            let took = sink(front.rest(), 0);
            if took == 0 {
                return Ok(false);
            }
            w.wrote(took);
            w.consume(took);
        }
        Ok(true)
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// The TCP stream. Only call on connections created with [`ConnInner::new`].
    pub fn stream(&self) -> &TcpStream {
        match &self.sock {
            Sock::Tcp(s) => s,
            Sock::Udp { .. } | Sock::Virtual { .. } => {
                unreachable!("stream() on a connection without a TCP socket")
            }
        }
    }

    /// The TCP stream, or `None` for a UDP connection.
    pub fn tcp_stream(&self) -> Option<&TcpStream> {
        match &self.sock {
            Sock::Tcp(s) => Some(s),
            Sock::Udp { .. } | Sock::Virtual { .. } => None,
        }
    }

    fn tcp(&self) -> &TcpStream {
        self.stream()
    }

    /// Writes `data` to the socket (for UDP: as one datagram to the peer).
    fn raw_write(&self, data: &[u8]) -> io::Result<usize> {
        match &self.sock {
            Sock::Tcp(s) => (&*s).write(data),
            Sock::Udp {
                sock,
                peer,
                connected,
            } => {
                if *connected {
                    sock.send(data)
                } else {
                    sock.send_to(data, peer)
                }
            }
            // The loop moves the bytes into the userspace stack (`drain_output`).
            Sock::Virtual { .. } => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// A UDP datagram with IP header fields `ip` (see [`ip_fields`]: one `sendmsg` with
    /// `IP_TOS` / `IPV6_TCLASS` and `IPV6_HOPLIMIT` control messages).
    #[cfg(target_os = "macos")]
    fn raw_write_ip(&self, data: &[u8], ip: u16) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        match &self.sock {
            Sock::Udp {
                sock,
                peer,
                connected,
            } => akio_sys::send_to_ip(
                sock.as_raw_fd(),
                data,
                (!connected).then_some(peer),
                ip as u8,
                (ip >> 8) as u8,
                self.local.is_ipv6(),
            ),
            _ => self.raw_write(data),
        }
    }

    /// One send is one datagram (UDP, or a userspace stack's UDP).
    fn is_datagram_sock(&self) -> bool {
        matches!(
            self.sock,
            Sock::Udp { .. } | Sock::Virtual { datagram: true }
        )
    }

    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPEN
    }

    /// Reads are paused: by the application ([`hold_reads`](Self::hold_reads)) or because too
    /// many ordered responses are pending (`Config::max_pending_responses`).
    pub fn read_held(&self) -> bool {
        self.hold.load(Ordering::Acquire) || self.ordered_hold.load(Ordering::Acquire)
    }

    /// Marks the connection as one end of a relay: what it reads is sent on *another*
    /// connection, which paces it with [`hold_reads`](Self::hold_reads) and
    /// [`on_drain`](Self::on_drain). Its reads then no longer pause because its own output is
    /// queued (`Config::write_high_watermark`): that output is the other side's data, and a
    /// peer that only reads once it can write (an echo server, say) would never take it while
    /// we stop reading — both sides would wait for each other forever.
    ///
    /// Takes effect at once: the I/O thread re-checks the connection when the setting changes.
    pub fn set_relayed(&self, relayed: bool) {
        if self.relayed.swap(relayed, Ordering::AcqRel) != relayed {
            self.link.wake_conn(self.id);
        }
    }

    /// Loop side, UDP: the ECN codepoint of the datagram about to be delivered (no DSCP).
    pub fn set_rx_ecn(&self, codepoint: u8) {
        self.rx_tos.store(codepoint & 3, Ordering::Relaxed);
    }

    /// Loop side, UDP: the traffic class byte (DSCP and ECN) of the datagram about to be
    /// delivered.
    pub fn set_rx_tos(&self, tos: u8) {
        self.rx_tos.store(tos, Ordering::Relaxed);
    }

    /// Loop side, UDP: the TTL / hop limit of the datagram about to be delivered (0 when not
    /// reported).
    pub fn set_rx_ttl(&self, ttl: u8) {
        self.rx_ttl.store(ttl, Ordering::Relaxed);
    }

    /// UDP: the TTL / hop limit of the datagram being delivered (0 when unknown).
    pub fn rx_ttl(&self) -> u8 {
        self.rx_ttl.load(Ordering::Relaxed)
    }

    /// Loop side, UDP: the index of the interface the datagram about to be delivered arrived
    /// on (0 when not reported).
    pub fn set_rx_interface(&self, interface: u32) {
        self.rx_interface.store(interface, Ordering::Relaxed);
    }

    /// UDP: the index of the interface the datagram being delivered arrived on (0 when
    /// unknown).
    pub fn rx_interface(&self) -> u32 {
        self.rx_interface.load(Ordering::Relaxed)
    }

    /// UDP on a kernel socket: asks for the TTL / hop limit of every datagram the socket
    /// receives ([`rx_ttl`](Self::rx_ttl)); the socket is shared by every peer of a listener or
    /// bound socket. Whether it was enabled.
    pub fn enable_rx_ttl(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Sock::Udp { sock, .. } = &self.sock {
            return akio_sys::enable_recv_ttl(std::os::fd::AsRawFd::as_raw_fd(&**sock));
        }
        false
    }

    /// UDP: the ECN codepoint of the datagram being delivered (0 when unknown).
    pub fn rx_ecn(&self) -> u8 {
        self.rx_tos.load(Ordering::Relaxed) & 3
    }

    /// UDP: the traffic class byte of the datagram being delivered (0 when unknown).
    pub fn rx_tos(&self) -> u8 {
        self.rx_tos.load(Ordering::Relaxed)
    }

    /// Whether reads pause at `Config::write_high_watermark` of queued output (not for a relay,
    /// see [`set_relayed`](Self::set_relayed)).
    pub fn write_backpressure(&self) -> bool {
        !self.relayed.load(Ordering::Acquire)
    }

    pub fn queued_bytes(&self) -> usize {
        let w = self.lock();
        w.queued + w.file_bytes as usize
    }

    /// True once `close_after_send` was requested.
    pub fn close_after_send_requested(&self) -> bool {
        self.lock().close_after_send
    }

    /// Loop side: coalesce writes (`true`) or stop coalescing (`false`, call [`flush_queue`]).
    /// Takes no lock: a sender reads the flag under the write lock, and a loop that corks
    /// always ends with [`uncork_flush`](Self::uncork_flush) (or `flush_queue`), which takes it.
    pub fn set_corked(&self, corked: bool) {
        self.loop_cork.store(corked, Ordering::Relaxed);
        if !corked {
            // The application's cork ends with the loop's, as it always did.
            self.lock().corked = false;
        }
    }

    /// Whether sends are being coalesced (call with the write lock held).
    #[inline]
    fn corked(&self, w: &WriteState) -> bool {
        w.corked || self.loop_cork.load(Ordering::Relaxed)
    }

    /// Loop side: end of a callback. Uncorks and writes what the callback queued. Returns the
    /// bytes still queued (what [`queued_bytes`](Self::queued_bytes) would say), so the loop
    /// needs no second lock to check its backpressure; `Err` if the socket failed.
    pub fn uncork_flush(&self) -> io::Result<usize> {
        let mut w = self.lock();
        w.corked = false;
        self.loop_cork.store(false, Ordering::Relaxed);
        #[allow(unused_mut)]
        let mut r = self.write_locked(&mut w);
        #[cfg(target_os = "linux")]
        if matches!(r, Ok(true)) && self.offload.load(Ordering::Relaxed) & OFFLOAD_PENDING != 0 {
            r = self.try_offload(&mut w).map(|()| w.queue.is_empty());
        }
        let q = w.queued + w.file_bytes as usize;
        drop(w);
        self.run_drained();
        r.map(|_| q)
    }

    /// Loop side: writes as much queued data as the socket takes. `Ok(true)` when empty.
    pub fn flush_queue(&self) -> io::Result<bool> {
        let mut w = self.lock();
        #[allow(unused_mut)]
        let mut r = self.write_locked(&mut w);
        #[cfg(target_os = "linux")]
        if matches!(r, Ok(true)) && self.offload.load(Ordering::Relaxed) & OFFLOAD_PENDING != 0 {
            r = self.try_offload(&mut w).map(|()| w.queue.is_empty());
        }
        drop(w);
        self.run_drained();
        r
    }

    /// Loop side, with nothing queued: offers the socket to the transport
    /// ([`Transport::offload`]) and records what moved into the kernel.
    #[cfg(target_os = "linux")]
    fn try_offload(&self, w: &mut WriteState) -> io::Result<()> {
        let rx_ok = self.rx_offload_ok.load(Ordering::Relaxed);
        self.offload_locked(w, rx_ok)
    }

    /// [`try_offload`](Self::try_offload) and [`offload_rx_now`](Self::offload_rx_now):
    /// calls the transport and records the outcome in `offload`. A transport that moved its
    /// send direction and still wants the receive direction, which `rx_ok` does not allow now,
    /// waits for the backend (`OFFLOAD_RX_WAIT`) instead of being asked after every flush.
    #[cfg(target_os = "linux")]
    fn offload_locked(&self, w: &mut WriteState, rx_ok: bool) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let cur = self.offload.load(Ordering::Relaxed);
        let stop = cur & OFFLOAD_RX;
        let fd = match &self.sock {
            Sock::Tcp(s) if self.is_open() && !w.close_after_send => s.as_raw_fd(),
            _ => {
                self.offload.store(stop, Ordering::Relaxed);
                return Ok(());
            }
        };
        let Some(t) = w.transport.as_mut() else {
            self.offload.store(stop, Ordering::Relaxed);
            return Ok(());
        };
        let rx_ok = rx_ok && self.cfg.telemetry.live().read_buffer() >= KERNEL_RX_MIN_BUF;
        let dirs = t.offload(fd, self.local, rx_ok);
        let wants = t.wants_offload();
        let mut ops = Vec::new();
        t.take_ops(&mut ops);
        let dirs = match dirs {
            Ok(d) => d,
            Err(e) => {
                self.offload.store(stop, Ordering::Relaxed);
                return Err(e);
            }
        };
        w.kernel_tx = dirs.tx;
        let mut v = OFFLOAD_NONE;
        if wants && dirs.tx && !dirs.rx && !rx_ok {
            v |= OFFLOAD_RX_WAIT;
        } else if wants {
            v |= OFFLOAD_PENDING;
        }
        if dirs.rx {
            v |= OFFLOAD_RX;
        }
        self.offload.store(v, Ordering::Release);
        self.queue_ops(w, ops);
        Ok(())
    }

    /// Whether the transport's send direction is in the kernel and its receive direction
    /// waits for the backend to call [`offload_rx_now`](Self::offload_rx_now) (a backend
    /// whose reads can be in flight between its flushes: io_uring). Loop side, lock-free.
    #[cfg(target_os = "linux")]
    pub fn offload_rx_waiting(&self) -> bool {
        self.offload.load(Ordering::Relaxed) & OFFLOAD_RX_WAIT != 0
    }

    /// Loop side, with no read in flight and nothing read that the transport has not seen:
    /// lets the transport move its receive direction into the kernel. Returns whether it is
    /// still waiting (a partial record is buffered: try again after more reads).
    #[cfg(target_os = "linux")]
    pub fn offload_rx_now(&self) -> io::Result<bool> {
        if !self.offload_rx_waiting() {
            return Ok(false);
        }
        let mut w = self.lock();
        let r = self.offload_locked(&mut w, true);
        let wake = !w.queue.is_empty() && !self.corked(&w);
        drop(w);
        if wake {
            self.link.wake_conn(self.id);
        }
        r?;
        // Still wanting the receive direction: the transport stays asked after flushes.
        let v = self.offload.load(Ordering::Relaxed);
        if v & OFFLOAD_PENDING != 0 {
            self.offload
                .store((v & !OFFLOAD_PENDING) | OFFLOAD_RX_WAIT, Ordering::Relaxed);
            return Ok(true);
        }
        Ok(false)
    }

    /// The backend gives up moving the receive direction (it could not stop its reads at a
    /// record boundary): the connection stays as it is.
    #[cfg(target_os = "linux")]
    pub fn offload_rx_give_up(&self) {
        let v = self.offload.load(Ordering::Relaxed);
        self.offload.store(v & OFFLOAD_RX, Ordering::Relaxed);
    }

    /// Queues socket operations of the transport after what is queued. Returns whether the
    /// loop must be woken to run them.
    #[cfg(target_os = "linux")]
    fn queue_ops(&self, w: &mut WriteState, ops: Vec<Box<dyn SocketOp>>) -> bool {
        if ops.is_empty() {
            return false;
        }
        let was_empty = w.queue.is_empty();
        for op in ops {
            w.queue.push_back(Chunk {
                bytes: Bytes::Op(op),
                off: 0,
            });
        }
        was_empty && !self.corked(w)
    }

    /// Backend side, once at registration: whether the read direction of this connection may
    /// move into the kernel (the backend reads only between the loop's flushes, so no read can
    /// hold bytes the transport has not seen when [`Transport::offload`] runs).
    pub fn set_rx_offload_ok(&self, ok: bool) {
        self.rx_offload_ok.store(ok, Ordering::Relaxed);
    }

    /// Whether the transport's read direction is in the kernel: bytes read are already decoded
    /// (Linux; kernel TLS). Always `false` elsewhere.
    #[inline]
    pub fn kernel_rx(&self) -> bool {
        self.offload.load(Ordering::Acquire) & OFFLOAD_RX != 0
    }

    /// Loop side, with the read direction in the kernel: a read failed with `EIO`, which means a
    /// control record is next. Reads it with its content type into `buf` (16 KiB at least) and
    /// hands it to the transport ([`Transport::kernel_record`]); application data that came
    /// instead is returned for `on_data`.
    #[cfg(target_os = "linux")]
    pub fn kernel_read_record(&self, buf: &mut [u8]) -> io::Result<KernelRead> {
        use std::os::fd::AsRawFd;
        const APPLICATION_DATA: u8 = 23;
        let Sock::Tcp(s) = &self.sock else {
            return Err(io::ErrorKind::Unsupported.into());
        };
        // A control record must fit whole (`try_offload` keeps the read direction in user
        // space when the loop's read buffer is smaller).
        if buf.len() < KERNEL_RX_MIN_BUF {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let (typ, n) = loop {
            match akio_sys::ktls::ktls_recv(s.as_raw_fd(), buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                r => break r?,
            }
        };
        if n == 0 || typ == APPLICATION_DATA {
            return Ok(KernelRead::Data(n));
        }
        let mut w = self.lock();
        let Some(t) = w.transport.as_mut() else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        let r = t.kernel_record(typ, &buf[..n]);
        let mut ops = Vec::new();
        t.take_ops(&mut ops);
        let wake = self.queue_ops(&mut w, ops);
        drop(w);
        if wake {
            self.link.wake_conn(self.id);
        }
        match r {
            Ok(true) => Ok(KernelRead::Control),
            Ok(false) => Ok(KernelRead::Data(0)), // close_notify: the end of the stream
            Err(e) => Err(e),
        }
    }

    /// Calls `f` once everything queued has been written (right away if nothing is queued),
    /// or when the connection closes. Replaces an earlier waiter. For flow control between
    /// connections: pause reading one side until the other has drained.
    pub fn on_drain(&self, f: Box<dyn FnOnce() + Send>) {
        let mut w = self.lock();
        if w.queue.is_empty() || !self.is_open() {
            drop(w);
            return f();
        }
        w.drain = Some(f);
    }

    /// Loop side: the connection is gone; drop queued output.
    pub fn mark_closed(&self) {
        self.state.store(CLOSED, Ordering::Release);
        let waiter = {
            let mut w = self.lock();
            w.clear();
            w.drain.take()
        };
        if let Some(f) = waiter {
            f();
        }
    }

    fn lock(&self) -> MutexGuard<'_, WriteState> {
        // A poisoned lock only means a user callback panicked elsewhere; the queue is still
        // consistent because it is never mutated across a callback.
        self.write.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Writes queued chunks until the queue is empty or the socket is full. When it empties, a
    /// drain waiter is moved aside; callers run it with [`run_drained`](Self::run_drained) once
    /// the write lock is released.
    fn write_locked(&self, w: &mut WriteState) -> io::Result<bool> {
        let r = self.write_queue(w);
        if matches!(r, Ok(true)) {
            self.stash_drain(w);
        }
        r
    }

    /// The queue drained: moves the drain waiter, if any, aside for
    /// [`run_drained`](Self::run_drained) (call with the write lock held).
    #[inline]
    fn stash_drain(&self, w: &mut WriteState) {
        if let Some(f) = w.drain.take() {
            *self.drained.lock().unwrap_or_else(|p| p.into_inner()) = Some(f);
            self.drain_pending.store(true, Ordering::Release);
        }
    }

    fn run_drained(&self) {
        // Every path that stashes a waiter calls this afterwards, so a flag still clear here
        // means there is nothing to run (the usual case: no lock taken).
        if !self.drain_pending.load(Ordering::Acquire)
            || !self.drain_pending.swap(false, Ordering::AcqRel)
        {
            return;
        }
        let f = self
            .drained
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(f) = f {
            f();
        }
    }

    /// Writes queued chunks with `writev` until the queue is empty or the socket is full.
    fn write_queue(&self, w: &mut WriteState) -> io::Result<bool> {
        const MAX_IOV: usize = 16;
        if matches!(self.sock, Sock::Virtual { .. }) {
            // Only the owning loop writes (`drain_output`).
            return Ok(w.queue.is_empty());
        }
        if w.datagram {
            #[cfg(target_os = "linux")]
            {
                let mut items = [DgramItem {
                    inner: self,
                    w,
                    res: None,
                }];
                send_datagrams(&mut items);
                return items[0].res.take().expect("result set");
            }
            #[cfg(not(target_os = "linux"))]
            loop {
                let Some((d, ip)) = w.datagrams_ip().next() else {
                    return Ok(true);
                };
                #[cfg(target_os = "macos")]
                let r = if ip == 0 {
                    self.raw_write(d)
                } else {
                    self.raw_write_ip(d, ip)
                };
                #[cfg(not(target_os = "macos"))]
                let r = {
                    let _ = ip;
                    self.raw_write(d)
                };
                match r {
                    Ok(_) => {
                        w.sent_datagrams(1);
                        continue;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if self.fatal_datagram_error(&e) => return Err(e),
                    // A datagram the network refuses (too big, unreachable) is dropped, as UDP
                    // does; it must not wedge the datagrams behind it.
                    Err(_) => {}
                }
                w.consume_datagrams(1);
            }
        }
        while !w.queue.is_empty() {
            #[cfg(target_os = "linux")]
            if let Some(Chunk {
                bytes: Bytes::Op(op),
                ..
            }) = w.queue.front_mut()
            {
                use std::os::fd::AsRawFd;
                match op.run(self.tcp().as_raw_fd()) {
                    Ok(true) => {
                        w.queue.pop_front();
                        continue;
                    }
                    Ok(false) => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            #[cfg(unix)]
            if let Some(Chunk {
                bytes: Bytes::File { file, start, len },
                off,
            }) = w.queue.front()
            {
                use std::os::fd::AsRawFd;
                let out = self.tcp().as_raw_fd();
                let (pos, left) = (start + *off as u64, (*len as usize) - *off);
                match akio_sys::sendfile(out, file.as_raw_fd(), pos, left) {
                    Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()), // file shrank
                    Ok(n) => {
                        w.wrote(n);
                        w.consume(n);
                        continue;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            let n = {
                let mut iov: [IoSlice<'_>; MAX_IOV] = [IoSlice::new(&[]); MAX_IOV];
                let mut k = 0;
                for (slot, c) in iov.iter_mut().zip(w.queue.iter()) {
                    if c.is_file() || c.is_op() {
                        // The file goes out with sendfile, the operation runs, once the bytes
                        // before them did.
                        break;
                    }
                    *slot = IoSlice::new(c.rest());
                    k += 1;
                }
                match self.tcp().write_vectored(&iov[..k]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => {
                        // The slices borrow `w.queue`; account after they are gone.
                        n
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            };
            w.wrote(n);
            w.consume(n);
        }
        Ok(true)
    }

    /// A dialed peer that answered with ICMP "port unreachable" is gone; any other refused
    /// datagram is only dropped.
    fn fatal_datagram_error(&self, e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::ConnectionRefused
            && matches!(
                self.sock,
                Sock::Udp {
                    connected: true,
                    ..
                }
            )
    }

    /// UDP: where datagrams go (`None` on a connected socket) and the socket's fd.
    #[cfg(target_os = "linux")]
    fn udp_target(&self) -> (Option<&SocketAddr>, std::os::fd::RawFd) {
        use std::os::fd::AsRawFd;
        match &self.sock {
            Sock::Udp {
                sock,
                peer,
                connected,
            } => ((!connected).then_some(peer), sock.as_raw_fd()),
            Sock::Tcp(_) | Sock::Virtual { .. } => {
                unreachable!("datagram queue on a connection without a UDP socket")
            }
        }
    }

    /// Queues `data` as consecutive datagrams of `seg` bytes (see [`Conn::send_segments`]).
    pub fn send_segments(&self, data: Vec<u8>, seg: usize) -> Result<()> {
        self.send_segments_ecn(data, seg, 0)
    }

    /// [`send_segments`](Self::send_segments) with ECN codepoint `ecn` on every datagram (its
    /// low two bits, RFC 3168; 0 = not ECN-capable). `seg` 0 sends `data` as one datagram. The
    /// codepoint is set on kernel UDP sockets on Linux and macOS (unless `AKIO_UDP_ECN=0`) and
    /// on a userspace stack's UDP (akio-dpdk), else dropped.
    pub fn send_segments_ecn(&self, data: Vec<u8>, seg: usize, ecn: u8) -> Result<()> {
        self.send_segments_tos(data, seg, ecn & 3)
    }

    /// [`send_segments_ecn`](Self::send_segments_ecn) with the whole traffic class byte `tos`
    /// (DSCP in the upper six bits, ECN in the low two). Userspace stacks get its ECN bits only.
    pub fn send_segments_tos(&self, data: Vec<u8>, seg: usize, tos: u8) -> Result<()> {
        self.send_segments_ip(data, seg, tos, 0)
    }

    /// [`send_segments_tos`](Self::send_segments_tos) with the TTL / hop limit `ttl` (0: the
    /// socket's). Kernel sockets on Linux, and IPv6 ones on macOS, set it; elsewhere it is
    /// dropped.
    pub fn send_segments_ip(&self, data: Vec<u8>, seg: usize, tos: u8, ttl: u8) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut w = self.lock();
        let ip = ip_fields(tos, ttl);
        let (seg, fields) = if ip != 0 && w.datagram && self.is_datagram_sock() {
            // A datagram with a codepoint is queued as one segment of its own length.
            let seg = if seg == 0 {
                data.len()
            } else {
                seg.min(data.len())
            };
            (seg, ip)
        } else {
            (seg, 0)
        };
        if !w.datagram || w.transport.is_some() || seg == 0 || (seg >= data.len() && fields == 0) {
            drop(w);
            if seg == 0 || !self.is_datagram_sock() {
                return self.send_owned(data);
            }
            for d in data.chunks(seg) {
                self.send(d)?;
            }
            return Ok(());
        }
        self.check_sendable(&w, data.len())?;
        let was_empty = w.queue.is_empty();
        w.add_queued(data.len());
        w.queue.push_back(Chunk {
            bytes: Bytes::Segmented(data, seg, fields),
            off: 0,
        });
        if self.corked(&w) {
            return Ok(());
        }
        let r = self.write_locked(&mut w);
        let blocked = !w.queue.is_empty();
        drop(w);
        self.run_drained();
        match r {
            Err(e) => Err(self.fail(e)),
            Ok(_) => {
                if blocked && was_empty {
                    self.link.wake_conn(self.id);
                }
                Ok(())
            }
        }
    }

    /// Loop side, UDP: uncorks every connection in `conns` and flushes their queued datagrams
    /// together, with as few `sendmmsg` calls as possible (they must share one socket). `out`
    /// receives one result per connection, as [`flush_queue`](Self::flush_queue) would return.
    pub fn flush_datagram_peers<C: std::ops::Deref<Target = ConnInner>>(
        conns: &[C],
        out: &mut Vec<io::Result<bool>>,
    ) {
        out.clear();
        #[cfg(target_os = "linux")]
        if let [c] = conns {
            // One connection (a client socket, a quiet server loop): no lists to build.
            let mut g = c.lock();
            g.corked = false;
            c.loop_cork.store(false, Ordering::Relaxed);
            let mut items = [DgramItem {
                inner: c,
                w: &mut g,
                res: None,
            }];
            send_datagrams(&mut items);
            let r = items[0].res.take().unwrap_or(Ok(true));
            if matches!(r, Ok(true)) {
                c.stash_drain(&mut g);
            }
            out.push(r);
            drop(g);
            c.run_drained();
            return;
        }
        #[cfg(target_os = "linux")]
        {
            // Only this (loop) thread ever holds more than one connection's write lock, so taking
            // them all at once cannot deadlock.
            let mut guards: Vec<MutexGuard<'_, WriteState>> =
                conns.iter().map(|c| c.lock()).collect();
            let mut items: Vec<DgramItem<'_, '_>> = conns
                .iter()
                .zip(guards.iter_mut())
                .map(|(c, g)| {
                    g.corked = false;
                    c.loop_cork.store(false, Ordering::Relaxed);
                    DgramItem {
                        inner: c,
                        w: g,
                        res: None,
                    }
                })
                .collect();
            send_datagrams(&mut items);
            for it in &mut items {
                let r = it.res.take().unwrap_or(Ok(true));
                if matches!(r, Ok(true)) {
                    it.inner.stash_drain(it.w);
                }
                out.push(r);
            }
            drop(items);
            drop(guards);
            for c in conns {
                c.run_drained();
            }
        }
        #[cfg(not(target_os = "linux"))]
        for c in conns {
            c.set_corked(false);
            out.push(c.flush_queue());
        }
    }

    fn check_sendable(&self, w: &WriteState, extra: usize) -> Result<()> {
        if !self.is_open() || w.close_after_send {
            return Err(Error::Closed);
        }
        if w.queued + extra > self.cfg.telemetry.live().max_queued_bytes() {
            if let Some(s) = &w.stats {
                s.overloaded.add(1);
            }
            return Err(Error::Overloaded);
        }
        Ok(())
    }

    /// A write failed on a non-loop path: schedule the close and report it.
    fn fail(&self, e: io::Error) -> Error {
        if let Sock::Udp { connected, .. } = self.sock {
            // A refused datagram does not end a UDP "connection"; a dialed one learns from an ICMP
            // "port unreachable" that nobody is there, and that ends it.
            if !(connected && e.kind() == io::ErrorKind::ConnectionRefused) {
                return Error::Io(e);
            }
        }
        if self
            .state
            .compare_exchange(OPEN, CLOSING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.link.close_conn(self.id, Some(e));
        }
        Error::Closed
    }

    pub fn send(&self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut w = self.lock();
        self.check_sendable(&w, data.len())?;
        let sealed = match self.seal(&mut w, data) {
            Ok(s) => s,
            Err(e) => {
                drop(w);
                return Err(self.fail(e));
            }
        };
        let mut data = sealed.as_deref().unwrap_or(data);
        if data.is_empty() {
            return Ok(()); // the transport is holding the bytes until it is ready
        }
        let was_empty = w.queue.is_empty();
        let corked = self.corked(&w);
        // Fast path: nothing queued and not corked -> write straight to the socket.
        if was_empty && !corked {
            loop {
                match self.raw_write(data) {
                    Ok(n) if n == data.len() => {
                        w.wrote(n);
                        return Ok(());
                    }
                    Ok(n) => {
                        w.wrote(n);
                        data = &data[n..];
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        drop(w);
                        return Err(self.fail(e));
                    }
                }
            }
        }
        w.push_copy(data);
        let need_wake = was_empty && !corked;
        drop(w);
        if need_wake {
            self.link.wake_conn(self.id);
        }
        Ok(())
    }

    pub fn send_owned(&self, data: Vec<u8>) -> Result<()> {
        // A direct write is attempted first; only the unwritten tail is queued (copy-free for the
        // whole buffer when it does not fit and the queue is empty).
        if data.is_empty() {
            return Ok(());
        }
        let mut w = self.lock();
        self.check_sendable(&w, data.len())?;
        let data = match self.seal(&mut w, &data) {
            Ok(Some(sealed)) => {
                // The plaintext is done with: a pooled buffer goes back to the pool.
                akio_buf::put(data);
                sealed
            }
            Ok(None) => data,
            Err(e) => {
                drop(w);
                return Err(self.fail(e));
            }
        };
        if data.is_empty() {
            return Ok(());
        }
        let was_empty = w.queue.is_empty();
        let corked = self.corked(&w);
        let mut off = 0;
        if was_empty && !corked {
            loop {
                match self.raw_write(&data[off..]) {
                    Ok(n) => {
                        w.wrote(n);
                        off += n;
                        if off == data.len() {
                            drop(w);
                            akio_buf::put(data); // pooled buffers go back, as when queued
                            return Ok(());
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        drop(w);
                        return Err(self.fail(e));
                    }
                }
            }
        }
        w.add_queued(data.len() - off);
        w.queue.push_back(Chunk {
            bytes: Bytes::Owned(data),
            off,
        });
        let need_wake = was_empty && !corked;
        drop(w);
        if need_wake {
            self.link.wake_conn(self.id);
        }
        Ok(())
    }

    pub fn send_shared(&self, data: SharedBuf) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut w = self.lock();
        self.check_sendable(&w, data.len())?;
        let bytes = match self.seal(&mut w, &data) {
            Ok(Some(sealed)) if sealed.is_empty() => return Ok(()),
            Ok(Some(sealed)) => Bytes::Owned(sealed),
            Ok(None) => Bytes::Shared(data),
            Err(e) => {
                drop(w);
                return Err(self.fail(e));
            }
        };
        let was_empty = w.queue.is_empty();
        let n = match &bytes {
            Bytes::Owned(v) | Bytes::Segmented(v, ..) => v.len(),
            Bytes::Shared(s) => s.len(),
            #[cfg(unix)]
            Bytes::File { .. } => 0,
            #[cfg(target_os = "linux")]
            Bytes::Op(_) => 0,
        };
        w.add_queued(n);
        w.queue.push_back(Chunk { bytes, off: 0 });
        let corked = self.corked(&w);
        let need_wake = was_empty && !corked;
        if !corked {
            // Try to push it out right away.
            if let Err(e) = self.write_locked(&mut w) {
                drop(w);
                return Err(self.fail(e));
            }
        }
        drop(w);
        self.run_drained();
        if need_wake {
            self.link.wake_conn(self.id);
        }
        Ok(())
    }

    pub fn cork(&self) {
        self.lock().corked = true;
    }

    pub fn flush(&self) -> Result<()> {
        let mut w = self.lock();
        w.corked = false;
        self.loop_cork.store(false, Ordering::Relaxed);
        match self.write_locked(&mut w) {
            Ok(true) => {
                drop(w);
                self.run_drained();
                Ok(())
            }
            Ok(false) => {
                drop(w);
                self.link.wake_conn(self.id);
                Ok(())
            }
            Err(e) => {
                drop(w);
                Err(self.fail(e))
            }
        }
    }

    pub fn close(&self) {
        if self
            .state
            .compare_exchange(OPEN, CLOSING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.link.close_conn(self.id, None);
        }
    }

    pub fn close_after_send(&self) {
        let mut w = self.lock();
        if w.close_after_send {
            return;
        }
        w.close_after_send = true;
        if let Some(t) = w.transport.as_mut() {
            let mut out = Vec::new();
            t.shutdown(&mut out);
            self.queue_raw(&mut w, out);
            #[cfg(target_os = "linux")]
            if w.kernel_tx {
                self.take_transport_ops(&mut w);
            }
        }
        drop(w);
        self.link.wake_conn(self.id);
    }

    /// Loop side: the peer finished sending (EOF). Close once everything queued *and* every
    /// response reserved before now has been written: the close takes the next response
    /// position, so pipelined requests still being answered (on the pool, say) are not cut off.
    pub fn close_after_responses(&self) {
        let seq = self.reserve();
        self.fill_parts(seq, Vec::new(), true);
    }

    pub fn hold_reads(&self, hold: bool) {
        if self.hold.swap(hold, Ordering::AcqRel) != hold {
            self.link.wake_conn(self.id);
        }
    }

    /// Runs `job` on the engine's logical pool, with no completion back on the I/O thread
    /// (what `job` sends goes out from the pool thread; responses keep their order through
    /// [`reserve`](Self::reserve)d positions). `Err(job)` hands it back, unrun, when the pool's
    /// queue is full, the engine has no pool, or the connection is closed.
    pub fn execute(&self, job: akio_pool::Job) -> std::result::Result<(), akio_pool::Job> {
        if !self.is_open() {
            return Err(job);
        }
        match self.link.pool() {
            Some(pool) => pool.try_execute(job).map_err(|r| r.0),
            None => Err(job),
        }
    }

    /// Reserves the next response position. Call in request order (on the I/O thread).
    pub fn reserve(&self) -> u64 {
        let mut g = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        let o: &mut Ordered = g.get_or_insert_with(Box::default);
        o.entries.push_back(Entry::Empty);
        o.next += 1;
        self.ordered_limit(o);
        o.next - 1
    }

    /// Fills reserved position `seq`; everything now contiguous from the front is sent in order.
    pub fn fill(&self, seq: u64, data: Vec<u8>, close_after: bool) {
        let mut g = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        let o: &mut Ordered = g.get_or_insert_with(Box::default);
        if seq == o.head {
            // First in line (the usual case): send now, without building a part list.
            o.entries.pop_front();
            o.head += 1;
            let r = self.send_owned(data);
            self.ordered_sent(r);
            if close_after {
                self.close_after_send();
            }
            if o.entries.is_empty() && !o.paused {
                return; // nothing waits behind it
            }
        } else {
            let i = (seq - o.head) as usize;
            o.held += data.len();
            *o.entries.get_mut(i).expect("reserved") =
                Entry::Ready(vec![Part::Bytes(data)], close_after);
            self.check_held(o);
        }
        self.advance(o);
    }

    /// Like [`fill`](Self::fill) with several parts, some of which may be files.
    pub fn fill_parts(&self, seq: u64, parts: Vec<Part>, close_after: bool) {
        let mut g = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        let o: &mut Ordered = g.get_or_insert_with(Box::default);
        let i = (seq - o.head) as usize;
        // Counted even when first in line: `advance` takes it off as it sends the parts.
        o.held += parts_len(&parts);
        *o.entries.get_mut(i).expect("reserved") = Entry::Ready(parts, close_after);
        if i > 0 {
            self.check_held(o);
        }
        self.advance(o);
    }

    /// Opens position `seq` for streaming with `head` as its first bytes.
    pub fn stream_open(&self, seq: u64, head: Vec<u8>) {
        let mut g = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        let o: &mut Ordered = g.get_or_insert_with(Box::default);
        let i = (seq - o.head) as usize;
        o.held += head.len();
        *o.entries.get_mut(i).expect("reserved") = Entry::Stream(Stream {
            pending: head,
            live: false,
            finished: false,
            close: false,
        });
        self.advance(o);
    }

    /// Writes to a streaming position. Written straight to the socket when it is first in line,
    /// held in memory (up to `max_queued_bytes`) until earlier responses are out otherwise.
    pub fn stream_write(&self, seq: u64, data: Vec<u8>) -> Result<()> {
        let mut g = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        let o: &mut Ordered = g.get_or_insert_with(Box::default);
        let i = (seq - o.head) as usize;
        let max = self.cfg.telemetry.live().max_queued_bytes();
        match o.entries.get_mut(i) {
            Some(Entry::Stream(s)) if !s.finished => {
                if i == 0 && s.live {
                    return self.send_owned(data);
                }
                if s.pending.len() + data.len() > max {
                    return Err(Error::Overloaded);
                }
                s.pending.extend_from_slice(&data);
                o.held += data.len();
                self.ordered_limit(o);
                Ok(())
            }
            _ => Err(Error::Closed),
        }
    }

    /// Ends a streaming position; later responses may go out.
    pub fn stream_finish(&self, seq: u64, close_after: bool) {
        let mut g = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        let o: &mut Ordered = g.get_or_insert_with(Box::default);
        let i = (seq - o.head) as usize;
        if let Some(Entry::Stream(s)) = o.entries.get_mut(i) {
            s.finished = true;
            s.close = close_after;
        }
        self.advance(o);
    }

    /// Sends everything that is now first in line. The lock is held across the sends: threads
    /// finishing neighbouring positions must not interleave their writes.
    fn advance(&self, o: &mut Ordered) {
        loop {
            match o.entries.front_mut() {
                Some(Entry::Ready(..)) => {
                    let Some(Entry::Ready(parts, close_after)) = o.entries.pop_front() else {
                        unreachable!()
                    };
                    o.head += 1;
                    o.held -= parts_len(&parts);
                    for p in parts {
                        let r = self.send_part(p);
                        self.ordered_sent(r);
                    }
                    if close_after {
                        self.close_after_send();
                    }
                }
                Some(Entry::Stream(s)) => {
                    if !s.live {
                        s.live = true;
                        o.held -= s.pending.len();
                        if !s.pending.is_empty() {
                            let d = std::mem::take(&mut s.pending);
                            let r = self.send_owned(d);
                            self.ordered_sent(r);
                        }
                    }
                    if !s.finished {
                        break; // later responses wait for this stream to end
                    }
                    let close = s.close;
                    o.entries.pop_front();
                    o.head += 1;
                    if close {
                        self.close_after_send();
                    }
                }
                _ => break,
            }
        }
        self.ordered_limit(o);
    }

    /// Responses held back behind an unfinished one count toward `max_queued_bytes` together
    /// with the send queue: past it the connection ends (as a response over it would), so a
    /// burst of large responses behind a slow one cannot hold unbounded memory.
    fn check_held(&self, o: &Ordered) {
        let max = self.cfg.telemetry.live().max_queued_bytes();
        if o.held > max || o.held + self.queued_bytes() > max {
            self.ordered_sent(Err(Error::Overloaded));
        }
    }

    /// Pauses reads while too many ordered responses are pending, or too many bytes are held
    /// back behind the first one; resumes them (with hysteresis) once enough went out
    /// (`Config::max_pending_responses`, `write_high_watermark`).
    #[inline]
    fn ordered_limit(&self, o: &mut Ordered) {
        // The usual case: one response at a time, filled right away.
        if !o.paused && o.held == 0 && o.entries.len() < self.pending_limit {
            return;
        }
        self.ordered_limit_slow(o);
    }

    #[cold]
    #[inline(never)]
    fn ordered_limit_slow(&self, o: &mut Ordered) {
        let n = o.entries.len();
        let high = self.cfg.telemetry.live().write_high_watermark();
        if !o.paused {
            if n >= self.pending_limit || o.held >= high {
                o.paused = true;
                self.ordered_hold.store(true, Ordering::Release);
                if let Some(s) = self.lock().stats.as_ref() {
                    s.backpressure.add(1);
                }
                self.link.wake_conn(self.id);
            }
        } else if (self.pending_limit == usize::MAX || n <= self.pending_limit / 2)
            && o.held <= high / 4
        {
            o.paused = false;
            self.ordered_hold.store(false, Ordering::Release);
            self.link.wake_conn(self.id);
        }
    }

    /// Reserved responses not yet written, and the bytes held in memory behind the first of
    /// them (for tests and the connection table).
    pub fn pending_responses(&self) -> (usize, usize) {
        let g = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        g.as_ref().map_or((0, 0), |o| (o.entries.len(), o.held))
    }

    /// A response in the ordered stream could not be queued (over `max_queued_bytes`): it
    /// cannot be dropped without corrupting or stalling the stream, so the connection ends.
    fn ordered_sent(&self, r: Result<()>) {
        if let Err(Error::Overloaded) = r {
            if self
                .state
                .compare_exchange(OPEN, CLOSING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let e = io::Error::other("ordered response over max_queued_bytes");
                self.link.close_conn(self.id, Some(e));
            }
        }
    }

    fn send_part(&self, p: Part) -> Result<()> {
        match p {
            Part::Bytes(b) => self.send_owned(b),
            #[cfg(unix)]
            Part::File { file, offset, len } => self.send_file(file, offset, len),
        }
    }

    /// Queues `len` bytes of `file` from `offset` to be sent with `sendfile(2)` (read through
    /// memory when the connection has a transport such as TLS). Not for UDP.
    ///
    /// Without a transport nothing is read here: the kernel copies the file as the socket
    /// drains (`sendfile` on a page-cache miss waits for the disk on the writing thread, as
    /// any `sendfile` server does). With a transport the file is read here, on the calling
    /// thread, in 64 KiB blocks, and all of it is queued at once: it must fit under
    /// `max_queued_bytes` (`Overloaded` otherwise, checked before anything is read), and a
    /// large file read from a slow disk should be sent from the pool (`spawn_blocking`, or a
    /// detached [`ResponseSlot`]) rather than from an I/O thread.
    #[cfg(unix)]
    pub fn send_file(&self, file: Arc<std::fs::File>, offset: u64, len: u64) -> Result<()> {
        use std::os::unix::fs::FileExt;
        if len == 0 {
            return Ok(());
        }
        if self.is_datagram_sock() {
            return Err(Error::Io(io::ErrorKind::Unsupported.into()));
        }
        if self.needs_seal() {
            // All of it is queued in memory: refuse up front what cannot fit, rather than read
            // up to `max_queued_bytes` of it from disk and fail halfway.
            let max = self.cfg.telemetry.live().max_queued_bytes() as u64;
            if len.saturating_add(self.queued_bytes() as u64) > max {
                if let Some(s) = &self.lock().stats {
                    s.overloaded.add(1);
                }
                return Err(Error::Overloaded);
            }
            // Records must be sealed: pass the file through memory in blocks.
            let (mut pos, mut left) = (offset, len);
            while left > 0 {
                let mut buf = vec![0u8; left.min(64 << 10) as usize];
                let n = file.read_at(&mut buf, pos).map_err(Error::Io)?;
                if n == 0 {
                    return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                buf.truncate(n);
                self.send_owned(buf)?;
                pos += n as u64;
                left -= n as u64;
            }
            return Ok(());
        }
        let mut w = self.lock();
        self.check_sendable(&w, 0)?;
        #[cfg(target_os = "linux")]
        if w.kernel_tx {
            // Kernel TLS: the kernel seals what `sendfile` takes from the page cache.
            let n = usize::try_from(len).unwrap_or(usize::MAX);
            if let Err(e) = self.kernel_presend(&mut w, n) {
                drop(w);
                return Err(self.fail(e));
            }
        }
        let was_empty = w.queue.is_empty();
        w.file_bytes += len;
        w.queue.push_back(Chunk {
            bytes: Bytes::File {
                file,
                start: offset,
                len,
            },
            off: 0,
        });
        let corked = self.corked(&w);
        if !corked {
            if let Err(e) = self.write_locked(&mut w) {
                drop(w);
                return Err(self.fail(e));
            }
        }
        let need_wake = was_empty && !corked;
        drop(w);
        self.run_drained();
        if need_wake {
            self.link.wake_conn(self.id);
        }
        Ok(())
    }

    /// Installs the transport layer. Call once, before any data flows.
    pub fn set_transport(&self, t: Box<dyn Transport>) {
        #[cfg(target_os = "linux")]
        if t.wants_offload() && matches!(self.sock, Sock::Tcp(_)) {
            self.offload.store(OFFLOAD_PENDING, Ordering::Relaxed);
        }
        self.lock().transport = Some(t);
    }

    /// The handshake deadline of the transport, if one is installed, still negotiating and
    /// has a [`handshake_timeout`](Transport::handshake_timeout). Loop side, once at open.
    pub fn handshake_timeout(&self) -> Option<std::time::Duration> {
        let w = self.lock();
        let t = w.transport.as_ref()?;
        if t.handshaking() {
            t.handshake_timeout()
        } else {
            None
        }
    }

    /// Whether the installed transport is still negotiating (`false` without one).
    pub fn transport_handshaking(&self) -> bool {
        self.lock()
            .transport
            .as_ref()
            .is_some_and(|t| t.handshaking())
    }

    /// Whether a transport layer is installed.
    pub fn has_transport(&self) -> bool {
        self.lock().transport.is_some()
    }

    /// Runs `f` on the transport under the write lock.
    pub fn with_transport<R>(&self, f: impl FnOnce(&mut dyn Transport) -> R) -> Option<R> {
        let mut w = self.lock();
        w.transport.as_mut().map(|t| f(&mut **t))
    }

    /// Loop side: feeds bytes read from the socket through the transport. Decoded bytes are
    /// appended to `plain`; output for the peer is queued (and flushed by the loop).
    pub fn transport_recv(&self, cipher: &[u8], plain: &mut Vec<u8>) -> io::Result<()> {
        let mut w = self.lock();
        let Some(t) = w.transport.as_mut() else {
            plain.extend_from_slice(cipher);
            return Ok(());
        };
        let mut out = Vec::new();
        let r = t.recv(cipher, plain, &mut out);
        #[allow(unused_mut)]
        let mut wake = self.queue_raw(&mut w, out);
        #[cfg(target_os = "linux")]
        if w.kernel_tx {
            wake |= self.take_transport_ops(&mut w);
        }
        drop(w);
        if wake {
            self.link.wake_conn(self.id);
        }
        r
    }

    /// Queues what the transport produced for its send direction in the kernel. Returns
    /// whether the loop must be woken.
    #[cfg(target_os = "linux")]
    fn take_transport_ops(&self, w: &mut WriteState) -> bool {
        let mut ops = Vec::new();
        if let Some(t) = w.transport.as_mut() {
            t.take_ops(&mut ops);
        }
        self.queue_ops(w, ops)
    }

    /// Queues bytes that are already encoded for the wire. Returns whether the loop must be
    /// woken to flush them.
    fn queue_raw(&self, w: &mut WriteState, out: Vec<u8>) -> bool {
        if out.is_empty() {
            return false;
        }
        let was_empty = w.queue.is_empty();
        w.add_queued(out.len());
        w.queue.push_back(Chunk {
            bytes: Bytes::Owned(out),
            off: 0,
        });
        was_empty && !self.corked(w)
    }

    /// Encodes `data` through the transport if there is one.
    fn seal(&self, w: &mut WriteState, data: &[u8]) -> io::Result<Option<Vec<u8>>> {
        #[cfg(target_os = "linux")]
        if w.kernel_tx {
            self.kernel_presend(w, data.len())?;
            return Ok(None);
        }
        match w.transport.as_mut() {
            None => Ok(None),
            Some(t) => {
                let mut out = Vec::with_capacity(data.len() + 64);
                t.seal(data, &mut out)?;
                Ok(Some(out))
            }
        }
    }

    /// The send direction is in the kernel: `len` bytes are about to go to the socket as they
    /// are. Runs (or queues, and wakes the loop for) what the transport needs done first.
    #[cfg(target_os = "linux")]
    fn kernel_presend(&self, w: &mut WriteState, len: usize) -> io::Result<()> {
        let Some(t) = w.transport.as_mut() else {
            return Ok(());
        };
        let mut ops = Vec::new();
        t.kernel_send(len, &mut ops)?;
        if ops.is_empty() {
            return Ok(());
        }
        if self.queue_ops(w, ops) {
            // Not corked: run them now, so the data can usually still go straight out.
            if !self.write_locked(w)? {
                self.link.wake_conn(self.id);
            }
        }
        Ok(())
    }

    /// Whether application bytes must pass through the transport before the socket.
    fn needs_seal(&self) -> bool {
        let w = self.lock();
        #[cfg(target_os = "linux")]
        if w.kernel_tx {
            return false;
        }
        w.transport.is_some()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// For the connection table: bytes written, bytes queued, transport name, UDP or not.
    pub fn debug_state(&self) -> (u64, usize, Option<&'static str>, bool) {
        let w = self.lock();
        (
            w.sent,
            w.queued + w.file_bytes as usize,
            w.transport.as_ref().map(|t| t.name()),
            w.datagram,
        )
    }

    /// The transport failed: counts it as a failed handshake or a transport error.
    pub fn note_transport_error(&self) {
        let w = self.lock();
        if let Some(s) = &w.stats {
            if w.transport.as_ref().is_some_and(|t| t.handshaking()) {
                s.handshake_failures.add(1);
            } else {
                s.transport_errors.add(1);
            }
        }
    }

    /// The engine's telemetry hub.
    pub fn telemetry(&self) -> &Arc<crate::Telemetry> {
        &self.cfg.telemetry
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Attaches `value` to the connection, once: a second call returns its value back. For a
    /// layer that learned something before the handler ran (the PROXY protocol's addresses).
    pub fn attach(
        &self,
        value: Arc<dyn Any + Send + Sync>,
    ) -> std::result::Result<(), Arc<dyn Any + Send + Sync>> {
        self.attachment.set(value)
    }

    /// The value [`attach`](Self::attach)ed to the connection, if it is a `T`.
    pub fn attachment<T: Any>(&self) -> Option<&T> {
        self.attachment.get()?.downcast_ref::<T>()
    }
}

/// A cloneable, thread-safe handle to a connection (ADR-002).
///
/// `Conn<H>` is `Send + Sync + Clone` for **any** `H` (the type parameter only types the
/// completion callbacks of [`Conn::spawn_blocking`]). Using a handle after the connection closed
/// returns [`Error::Closed`]; it never panics or touches a recycled fd. The socket's file
/// descriptor is released when the connection is closed *and* every handle has been dropped.
pub struct Conn<H> {
    pub(crate) inner: Arc<ConnInner>,
    // `fn() -> H` keeps the handle Send + Sync regardless of H.
    _h: PhantomData<fn() -> H>,
}

impl<H> std::fmt::Debug for Conn<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("id", &self.inner.id)
            .field("peer", &self.inner.peer)
            .field("open", &self.inner.is_open())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ConnInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnInner")
            .field("id", &self.id)
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl<H> Clone for Conn<H> {
    fn clone(&self) -> Self {
        Conn {
            inner: self.inner.clone(),
            _h: PhantomData,
        }
    }
}

impl<H> Conn<H> {
    pub(crate) fn new(inner: Arc<ConnInner>) -> Self {
        Conn {
            inner,
            _h: PhantomData,
        }
    }

    /// Process-unique connection id.
    pub fn id(&self) -> u64 {
        self.inner.id()
    }

    /// What a listener-side layer attached to this connection before its handler ran, if it is
    /// a `T` (for instance `akio_mux::proxy::ProxyHeader`; ADR-095). At most one value is
    /// attached per connection.
    pub fn attachment<T: Any>(&self) -> Option<&T> {
        self.inner.attachment::<T>()
    }

    /// Whether the connection is still open for sending.
    pub fn is_open(&self) -> bool {
        self.inner.is_open()
    }

    /// Bytes accepted by `send*` but not yet written to the socket.
    pub fn queued_bytes(&self) -> usize {
        self.inner.queued_bytes()
    }

    /// Local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    /// Peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr()
    }

    /// Writes `data` now if the socket takes it, queues the rest (copying). Never blocks.
    /// Fails with `Closed` after close, `Overloaded` beyond `Config::max_queued_bytes`.
    pub fn send(&self, data: &[u8]) -> Result<()> {
        self.inner.send(data)
    }

    /// Like [`send`](Self::send) but takes ownership, avoiding a copy of what must be queued.
    pub fn send_owned(&self, data: Vec<u8>) -> Result<()> {
        self.inner.send_owned(data)
    }

    /// Like [`send`](Self::send) with a reference-counted buffer, for broadcast.
    pub fn send_shared(&self, data: SharedBuf) -> Result<()> {
        self.inner.send_shared(data)
    }

    /// UDP: sends `data` as consecutive datagrams of `segment_size` bytes each (the last may be
    /// shorter), in one go: with UDP GSO (one syscall, segmented by the kernel or the NIC) where
    /// Linux supports it, else in a `sendmmsg` batch, else one by one. This is what QUIC stacks
    /// produce when asked for several datagrams at once (quinn-proto's `Transmit::segment_size`).
    /// On a TCP connection it is [`send_owned`](Self::send_owned).
    pub fn send_segments(&self, data: Vec<u8>, segment_size: usize) -> Result<()> {
        self.inner.send_segments(data, segment_size)
    }

    /// UDP (internal, outside the stability promise): [`send_segments`](Self::send_segments)
    /// with ECN codepoint `ecn` on every datagram (RFC 3168: 2 = ECT(0), 1 = ECT(1), 3 = CE,
    /// 0 = not ECN-capable); `segment_size` 0 sends `data` as one datagram. The codepoint is set
    /// on Linux and macOS kernel sockets (unless `AKIO_UDP_ECN=0`) and on akio-dpdk's UDP;
    /// elsewhere datagrams go out unmarked.
    #[doc(hidden)]
    pub fn send_segments_ecn(&self, data: Vec<u8>, segment_size: usize, ecn: u8) -> Result<()> {
        self.inner.send_segments_ecn(data, segment_size, ecn)
    }

    /// UDP (internal, outside the stability promise): [`send_segments_ecn`] with the whole
    /// traffic class byte `tos` (IPv4 TOS / IPv6 traffic class: DSCP in the upper six bits, ECN
    /// in the low two; 0 = unmarked). Set on Linux and macOS kernel sockets (unless
    /// `AKIO_UDP_ECN=0`); akio-dpdk's UDP takes the ECN bits only.
    ///
    /// [`send_segments_ecn`]: Self::send_segments_ecn
    #[doc(hidden)]
    pub fn send_segments_tos(&self, data: Vec<u8>, segment_size: usize, tos: u8) -> Result<()> {
        self.inner.send_segments_tos(data, segment_size, tos)
    }

    /// UDP (internal, outside the stability promise): [`send_segments_tos`] with the TTL
    /// (IPv4) or hop limit (IPv6) `ttl` on every datagram (0: the socket's), in an `IP_TTL` /
    /// `IPV6_HOPLIMIT` control message. Linux kernel sockets set it, macOS ones on IPv6 only
    /// (XNU ignores `IP_TTL` on send); elsewhere it is dropped.
    ///
    /// [`send_segments_tos`]: Self::send_segments_tos
    #[doc(hidden)]
    pub fn send_segments_ip(
        &self,
        data: Vec<u8>,
        segment_size: usize,
        tos: u8,
        ttl: u8,
    ) -> Result<()> {
        self.inner.send_segments_ip(data, segment_size, tos, ttl)
    }

    /// UDP (internal, outside the stability promise): inside `on_data`, the ECN codepoint the
    /// datagram arrived with (0 when not ECN-capable or not reported by the platform).
    #[doc(hidden)]
    pub fn rx_ecn(&self) -> u8 {
        self.inner.rx_ecn()
    }

    /// UDP (internal, outside the stability promise): inside `on_data`, the whole traffic class
    /// byte the datagram arrived with (DSCP and ECN; 0 when not reported: kernel sockets on
    /// Linux and macOS report it, akio-dpdk's UDP the ECN bits only).
    #[doc(hidden)]
    pub fn rx_tos(&self) -> u8 {
        self.inner.rx_tos()
    }

    /// UDP (internal, outside the stability promise): inside `on_data`, the TTL (IPv4) or hop
    /// limit (IPv6) the datagram arrived with; 0 unless asked for with
    /// [`enable_rx_ttl`](Self::enable_rx_ttl) (kernel sockets on Linux and macOS).
    #[doc(hidden)]
    pub fn rx_ttl(&self) -> u8 {
        self.inner.rx_ttl()
    }

    /// UDP: inside `on_data` (or `on_data_owned`), the index of the interface the datagram
    /// arrived on, as [`akio_sys::interfaces`] lists them (the scope id an IPv6 link-local
    /// address carries). 0 unless the socket asked for it
    /// ([`UdpBinding::set_recv_interface`](crate::UdpBinding::set_recv_interface), kernel
    /// sockets on Linux and macOS), and for TCP. Per datagram: one peer's datagrams may arrive
    /// on different interfaces.
    pub fn rx_interface(&self) -> u32 {
        self.inner.rx_interface()
    }

    /// UDP (internal, outside the stability promise): asks the kernel for the TTL / hop limit
    /// of every datagram this connection's socket receives, read with
    /// [`rx_ttl`](Self::rx_ttl). The socket is shared with every other peer of the listener or
    /// bound socket, which then get it too. Whether it was enabled (not on akio-dpdk, nor
    /// outside Linux and macOS).
    #[doc(hidden)]
    pub fn enable_rx_ttl(&self) -> bool {
        self.inner.enable_rx_ttl()
    }

    /// Coalesces writes until [`flush`](Self::flush). Inside `on_data` this is already the
    /// default: everything sent during a callback leaves in one `writev` when it returns.
    pub fn cork(&self) {
        self.inner.cork();
    }

    /// Ends corking and writes queued output.
    pub fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    /// Closes the connection, discarding unsent data. `on_close` runs on the I/O thread.
    pub fn close(&self) {
        self.inner.close();
    }

    /// Closes once everything queued has been written; further sends fail with `Closed`.
    pub fn close_after_send(&self) {
        self.inner.close_after_send();
    }

    /// Pauses (`true`) or resumes (`false`) reading from the peer.
    pub fn hold_reads(&self, hold: bool) {
        self.inner.hold_reads(hold);
    }

    /// Marks (`true`) or unmarks (`false`) this connection as one end of a relay, where what it
    /// reads is written to *another* connection that you pace with
    /// [`hold_reads`](Self::hold_reads) and [`on_drain`](Self::on_drain).
    ///
    /// By default the engine stops reading a connection while its own output queue is at or
    /// above `Config::write_high_watermark`. In a two-way relay that queue holds the *other*
    /// side's data, and a peer that only reads once it can write (an echo server, a proxy
    /// target that talks first) then never drains it while we stop reading: both sides wait
    /// for each other forever. A relayed connection skips that pause; your own
    /// `hold_reads` / `on_drain` pacing bounds memory instead, and `Config::max_queued_bytes`
    /// still applies. Mark both ends of a relay. Takes effect at once.
    pub fn set_relayed(&self, relayed: bool) {
        self.inner.set_relayed(relayed);
    }

    /// Calls `f` once everything queued on this connection has been written (right away if
    /// nothing is), or when it closes. Typical use, relaying between two connections: when the
    /// outgoing side's queue grows, `hold_reads(true)` on the incoming side and resume it from
    /// `on_drain` of the outgoing one.
    pub fn on_drain(&self, f: impl FnOnce() + Send + 'static) {
        self.inner.on_drain(Box::new(f));
    }

    /// The type-erased connection state, for protocol crates that outlive the handler type
    /// (a WebSocket session keeps sending after the HTTP handler it started from is gone).
    #[doc(hidden)]
    pub fn inner(&self) -> &Arc<ConnInner> {
        &self.inner
    }

    /// Runs `f` on the connection's [`Transport`] (e.g. to read TLS details), if it has one.
    pub fn with_transport<R>(&self, f: impl FnOnce(&mut dyn Transport) -> R) -> Option<R> {
        self.inner.with_transport(f)
    }
}

impl<H: Handler> Conn<H> {
    /// Runs `work` on the logical pool, then runs `done` **on this connection's owning I/O
    /// thread** with exclusive access to the handler. If the connection closed meanwhile, `done`
    /// is skipped; so it is if `work` panics. Returns [`Error::Overloaded`] when the pool's queue
    /// is full and [`Error::Closed`] when the connection or the pool is closed.
    pub fn spawn_blocking<R, W, D>(&self, work: W, done: D) -> Result<()>
    where
        R: Send + 'static,
        W: FnOnce() -> R + Send + 'static,
        D: FnOnce(&mut H, &Conn<H>, R) + Send + 'static,
    {
        if !self.inner.is_open() {
            return Err(Error::Closed);
        }
        let Some(pool) = self.inner.link.pool() else {
            return Err(Error::Closed);
        };
        let inner = self.inner.clone();
        let job = Box::new(move || {
            let r = work();
            let f: Completion<H> = Box::new(move |h, c| done(h, c, r));
            let task: Task = Box::new(f);
            inner.link.post_task(inner.id, task);
        });
        pool.try_execute(job).map_err(|_| Error::Overloaded)
    }

    /// Runs `work` on the logical pool with no completion: for work that answers by itself
    /// (through [`send`](Self::send) or a [`ResponseSlot`], both usable from any thread).
    /// [`spawn_blocking`](Self::spawn_blocking) is the form whose result comes back to the
    /// handler. Fails with [`Error::Overloaded`] when the pool's queue is full and
    /// [`Error::Closed`] when the connection is gone; `work` is dropped unrun then.
    pub fn execute(&self, work: impl FnOnce() + Send + 'static) -> Result<()> {
        if !self.inner.is_open() || self.inner.link.pool().is_none() {
            return Err(Error::Closed);
        }
        self.inner
            .execute(Box::new(work))
            .map_err(|_| Error::Overloaded)
    }

    /// Reserves the next response position on this connection. Responses are written in
    /// reservation order no matter in which order the slots are filled, which keeps pipelined
    /// protocols correct when requests finish out of order on the pool. Reserve on the I/O
    /// thread (in `on_data`), move the slot into the work closure, and [`fill`](ResponseSlot::fill)
    /// it there. Dropping an unfilled slot closes the connection (the stream would otherwise
    /// stall behind the missing response).
    pub fn reserve_response(&self) -> Result<ResponseSlot> {
        if !self.inner.is_open() {
            return Err(Error::Closed);
        }
        Ok(ResponseSlot {
            seq: self.inner.reserve(),
            inner: Some(self.inner.clone()),
        })
    }
}

/// A reserved, ordered response position; see [`Conn::reserve_response`].
#[derive(Debug)]
#[must_use = "a reserved response position must be filled"]
pub struct ResponseSlot {
    seq: u64,
    inner: Option<Arc<ConnInner>>,
}

impl ResponseSlot {
    /// The connection this position is on (`None` once filled).
    #[doc(hidden)]
    pub fn conn(&self) -> Option<&Arc<ConnInner>> {
        self.inner.as_ref()
    }

    /// Supplies the response bytes. Safe to call from any thread.
    pub fn fill(mut self, data: Vec<u8>) {
        if let Some(inner) = self.inner.take() {
            inner.fill(self.seq, data, false);
        }
    }

    /// Like [`fill`](Self::fill), and the connection is closed once these bytes (and every
    /// earlier response) have been written. For `Connection: close` style endings.
    pub fn fill_close(mut self, data: Vec<u8>) {
        if let Some(inner) = self.inner.take() {
            inner.fill(self.seq, data, true);
        }
    }

    /// Supplies the response as several parts (bytes and files), optionally closing after them.
    pub fn fill_parts(mut self, parts: Vec<Part>, close_after: bool) {
        if let Some(inner) = self.inner.take() {
            inner.fill_parts(self.seq, parts, close_after);
        }
    }

    /// Starts a streamed response: `head` goes out when this position is first in line, then
    /// [`ResponseStream::write`] appends as the body is produced.
    pub fn stream(mut self, head: Vec<u8>) -> ResponseStream {
        let inner = self.inner.take().expect("slot not yet used");
        inner.stream_open(self.seq, head);
        ResponseStream {
            inner: Some(inner),
            seq: self.seq,
        }
    }
}

/// A response being written piece by piece; see [`ResponseSlot::stream`]. Dropping it without
/// [`finish`](Self::finish) closes the connection (the framing cannot be completed).
#[derive(Debug)]
pub struct ResponseStream {
    inner: Option<Arc<ConnInner>>,
    seq: u64,
}

impl ResponseStream {
    /// Appends bytes. Fails with `Overloaded` when too much is held back or queued, and `Closed`
    /// when the connection is gone: stop producing then.
    pub fn write(&self, data: Vec<u8>) -> Result<()> {
        match &self.inner {
            Some(i) => i.stream_write(self.seq, data),
            None => Err(Error::Closed),
        }
    }

    /// Bytes accepted but not yet written to the socket, for pacing the producer.
    pub fn queued_bytes(&self) -> usize {
        self.inner.as_ref().map_or(0, |i| i.queued_bytes())
    }

    /// Ends the response; later pipelined responses may go out.
    pub fn finish(mut self, close_after: bool) {
        if let Some(i) = self.inner.take() {
            i.stream_finish(self.seq, close_after);
        }
    }
}

impl Drop for ResponseStream {
    fn drop(&mut self) {
        if let Some(i) = self.inner.take() {
            i.stream_finish(self.seq, true);
        }
    }
}

impl Drop for ResponseSlot {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.close();
        }
    }
}

/// Loom models of the send / close / cork protocols. Run with
/// `RUSTFLAGS="--cfg loom" cargo test -p akio-core --lib --release -- loom`.
#[cfg(all(test, loom))]
mod loom_tests {
    use std::{
        io::Read,
        net::{TcpListener, TcpStream},
        sync::atomic::{AtomicUsize, Ordering as StdOrd},
    };

    use loom::thread;

    use super::*;

    /// Records what the connection asks of its loop.
    #[derive(Default)]
    struct FakeLink {
        wakes: AtomicUsize,
        closes: AtomicUsize,
    }

    impl LoopLink for FakeLink {
        fn wake_conn(&self, _id: u64) {
            self.wakes.fetch_add(1, StdOrd::SeqCst);
        }
        fn close_conn(&self, _id: u64, _err: Option<io::Error>) {
            self.closes.fetch_add(1, StdOrd::SeqCst);
        }
        fn post_task(&self, _id: u64, _task: Task) {}
    }

    /// A connected nonblocking socket plus its (undrained) peer.
    fn socket_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        (s, c)
    }

    fn conn(stream: TcpStream, link: Arc<FakeLink>) -> Arc<ConnInner> {
        let a = stream.local_addr().unwrap();
        ConnInner::new(1, stream, a, a, link, Arc::new(Config::default()))
    }

    /// Whatever interleaving of a corking loop and a sender, every accepted byte is written once
    /// the loop uncorks: no lost data, no lost wakeup.
    #[test]
    fn loom_cork_vs_send_loses_nothing() {
        let (s, peer) = socket_pair();
        peer.set_nonblocking(true).unwrap();
        loom::model(move || {
            let link = Arc::new(FakeLink::default());
            let c = conn(s.try_clone().unwrap(), link.clone());
            let sender = {
                let c = c.clone();
                thread::spawn(move || c.send(b"abc").unwrap())
            };
            c.set_corked(true);
            c.uncork_flush().unwrap();
            sender.join().unwrap();
            // Nothing may remain queued: either the sender wrote directly or uncork flushed it,
            // or (sender ran after uncork) it wrote directly because the queue was empty.
            assert_eq!(c.queued_bytes(), 0);
            let mut sink = [0u8; 16];
            let mut got = 0;
            while let Ok(n) = (&peer).read(&mut sink) {
                if n == 0 {
                    break;
                }
                got += n;
            }
            assert_eq!(got % 3, 0);
        });
    }

    /// If a send is queued behind the cork and the loop never uncorks, the sender must have
    /// requested no wakeup (the loop owns the flush); once uncorked data goes out.
    #[test]
    fn loom_send_queued_while_corked_then_flushed() {
        let (s, _peer) = socket_pair();
        loom::model(move || {
            let link = Arc::new(FakeLink::default());
            let c = conn(s.try_clone().unwrap(), link.clone());
            c.set_corked(true);
            let t = {
                let c = c.clone();
                thread::spawn(move || c.send(b"xy").unwrap())
            };
            t.join().unwrap();
            assert_eq!(c.queued_bytes(), 2);
            assert_eq!(link.wakes.load(StdOrd::SeqCst), 0);
            c.uncork_flush().unwrap();
            assert_eq!(c.queued_bytes(), 0);
        });
    }

    /// Concurrent `close` calls schedule exactly one loop close; later sends fail.
    #[test]
    fn loom_close_is_scheduled_once() {
        let (s, _peer) = socket_pair();
        loom::model(move || {
            let link = Arc::new(FakeLink::default());
            let c = conn(s.try_clone().unwrap(), link.clone());
            let ts: Vec<_> = (0..2)
                .map(|_| {
                    let c = c.clone();
                    thread::spawn(move || c.close())
                })
                .collect();
            for t in ts {
                t.join().unwrap();
            }
            assert_eq!(link.closes.load(StdOrd::SeqCst), 1);
            assert!(!c.is_open());
            assert!(matches!(c.send(b"x"), Err(Error::Closed)));
        });
    }

    /// `send` racing `close` + the loop's `mark_closed`: never panics, and after `mark_closed`
    /// nothing stays queued and sends fail.
    #[test]
    fn loom_send_vs_close_and_mark_closed() {
        let (s, _peer) = socket_pair();
        loom::model(move || {
            let link = Arc::new(FakeLink::default());
            let c = conn(s.try_clone().unwrap(), link.clone());
            c.set_corked(true); // force the queued path to race with clear()
            let sender = {
                let c = c.clone();
                thread::spawn(move || {
                    let _ = c.send(b"data");
                })
            };
            c.close();
            c.mark_closed();
            sender.join().unwrap();
            // A send that won the lock before mark_closed is cleared by it; one after is rejected.
            assert!(matches!(c.send(b"z"), Err(Error::Closed)));
            assert_eq!(c.queued_bytes(), 0, "data queued after mark_closed");
        });
    }

    /// A drain waiter registered while a send races the loop's uncork runs exactly once (the
    /// `drain_pending` flag never loses or repeats it).
    #[test]
    fn loom_drain_waiter_runs_once() {
        let (s, _peer) = socket_pair();
        loom::model(move || {
            let link = Arc::new(FakeLink::default());
            let c = conn(s.try_clone().unwrap(), link.clone());
            c.set_corked(true);
            let ran = Arc::new(AtomicUsize::new(0));
            let sender = {
                let c = c.clone();
                thread::spawn(move || c.send(b"ab").unwrap())
            };
            let r = ran.clone();
            c.on_drain(Box::new(move || {
                r.fetch_add(1, StdOrd::SeqCst);
            }));
            sender.join().unwrap();
            assert_eq!(c.uncork_flush().unwrap(), 0);
            assert_eq!(ran.load(StdOrd::SeqCst), 1);
        });
    }

    /// Ordered responses: reads pause at `max_pending_responses` on the loop and resume when
    /// another thread's fill brings them down, whichever fill comes first.
    #[test]
    fn loom_ordered_pause_resumes() {
        let (s, _peer) = socket_pair();
        loom::model(move || {
            let link = Arc::new(FakeLink::default());
            let a = s.local_addr().unwrap();
            let mut cfg = Config::default();
            cfg.max_pending_responses = Some(2);
            let c = ConnInner::new(1, s.try_clone().unwrap(), a, a, link.clone(), Arc::new(cfg));
            let first = c.reserve();
            let second = c.reserve();
            assert!(c.read_held(), "paused at the limit");
            let t = {
                let c = c.clone();
                thread::spawn(move || c.fill(first, b"1".to_vec(), false))
            };
            c.fill(second, b"2".to_vec(), false);
            t.join().unwrap();
            assert!(!c.read_held(), "resumed once written");
            assert_eq!(c.pending_responses(), (0, 0));
        });
    }

    /// `close_after_send` racing `send`: the loop is always asked to re-evaluate afterwards.
    #[test]
    fn loom_close_after_send_requests_wakeup() {
        let (s, _peer) = socket_pair();
        loom::model(move || {
            let link = Arc::new(FakeLink::default());
            let c = conn(s.try_clone().unwrap(), link.clone());
            let t = {
                let c = c.clone();
                thread::spawn(move || {
                    let _ = c.send(b"hi");
                })
            };
            c.close_after_send();
            t.join().unwrap();
            assert!(c.close_after_send_requested());
            assert!(link.wakes.load(StdOrd::SeqCst) >= 1);
            assert!(matches!(c.send(b"x"), Err(Error::Closed)));
        });
    }
}
