//! Connectionless UDP (ADR-065): one [`DatagramsHandler`] per I/O thread of a UDP listener
//! instead of one connection per peer.
//!
//! The handler gets every receive batch (one `recvmmsg` on Linux, up to 32 `recv_from` calls
//! elsewhere) as a [`Datagrams`] list of `(peer, bytes)`, and queues replies (to any address) on
//! [`Replies`]; they leave together when the callback returns: one `sendmmsg` per 64 messages on
//! Linux, runs of equal-size datagrams to one address merged into one UDP GSO message. Nothing is
//! kept per peer: no table, no idle timer, no `on_open` / `on_close`, so memory does not depend
//! on how many addresses send. Other threads send with a [`DatagramSender`].
//!
//! [`DatagramPort`] is the backend-facing driver: the epoll/kqueue UDP loops and the io_uring
//! loops own one per socket and call it on readiness, so the batching exists once.

use std::{
    io,
    net::{SocketAddr, UdpSocket},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use crate::{Config, LoopStats, telemetry::log_or_stderr};

/// Datagrams taken from the socket per receive batch (one `recvmmsg`).
const BATCH: usize = 32;
/// Receive batches per readiness event before the loop looks at its other work.
const MAX_BATCHES_PER_EVENT: usize = 8;
/// What one queued reply costs against the queue limit on top of its bytes (its address and
/// bookkeeping), so that empty datagrams are bounded too.
const MSG_OVERHEAD: usize = 64;
/// Largest UDP payload (IPv6 jumbograms aside).
const MAX_DATAGRAM: usize = 65_535;
/// An emptied reply queue whose buffer grew past this gives the memory back.
const KEEP_CAPACITY: usize = 1 << 20;

static NEXT_PORT_ID: AtomicU64 = AtomicU64::new(1 << 48);

/// A connectionless UDP service (ADR-065): served with `akio::Listener::serve_datagrams`, one
/// value per I/O thread of the listener, created by the factory given there.
///
/// Where the per-peer [`Handler`](crate::Handler) of a UDP listener gets a [`Conn`](crate::Conn)
/// per source address (with its own state, idle timeout and peer limit), a `DatagramsHandler`
/// sees the raw stream of datagrams: what DNS, syslog or StatsD servers need, which answer each
/// datagram on its own and would only pay for a peer table. Callbacks run inline on the I/O
/// thread and must not block (`docs/rules.md`); hand slow work to your own threads and answer
/// from there with a [`DatagramSender`].
///
/// A panic in a callback is caught and logged; the listener keeps serving with the same handler.
pub trait DatagramsHandler: Send + 'static {
    /// One receive batch, in arrival order. `batch` borrows the receive buffers and is only
    /// valid during the call. What is queued on `out` is sent when the call returns, together
    /// (`sendmmsg` and UDP GSO on Linux).
    fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies);

    /// The engine is shutting down; datagrams queued on `out` are still sent (the engine waits
    /// up to `Config::shutdown_timeout` for socket space). Called once per handler.
    fn on_shutdown(&mut self, _out: &mut Replies) {}
}

/// One received datagram's position in the receive buffers.
#[derive(Clone, Copy)]
struct Entry {
    peer: SocketAddr,
    /// `recvmmsg` slot (Linux; unused elsewhere).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    slot: u32,
    off: u32,
    len: u32,
}

/// Where the bytes of a batch live: the `recvmmsg` slots (Linux), else one buffer.
#[cfg(target_os = "linux")]
type Src<'a> = &'a akio_sys::RecvBatch;
#[cfg(not(target_os = "linux"))]
type Src<'a> = &'a [u8];

/// The datagrams of one receive batch ([`DatagramsHandler::on_datagrams`]): `(peer, bytes)`
/// pairs in arrival order, borrowed from the receive buffers. Coalesced GRO receives are split
/// back into their datagrams. Datagrams longer than `Config::read_buffer` are truncated.
#[derive(Clone, Copy)]
pub struct Datagrams<'a> {
    entries: &'a [Entry],
    src: Src<'a>,
}

impl std::fmt::Debug for Datagrams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Datagrams")
            .field("len", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Datagrams<'a> {
    /// Number of datagrams.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// No datagram (never the case in `on_datagrams`).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Datagram `i`: its sender and bytes.
    pub fn get(&self, i: usize) -> Option<(SocketAddr, &'a [u8])> {
        let e = self.entries.get(i)?;
        let (off, len) = (e.off as usize, e.len as usize);
        #[cfg(target_os = "linux")]
        let data: &'a [u8] = self.src.data(e.slot as usize)?.0;
        #[cfg(not(target_os = "linux"))]
        let data: &'a [u8] = self.src;
        Some((e.peer, data.get(off..off + len)?))
    }

    /// The datagrams in arrival order.
    pub fn iter(&self) -> DatagramsIter<'a> {
        DatagramsIter { d: *self, i: 0 }
    }
}

impl ExactSizeIterator for DatagramsIter<'_> {}

impl<'a> IntoIterator for &Datagrams<'a> {
    type Item = (SocketAddr, &'a [u8]);
    type IntoIter = DatagramsIter<'a>;
    fn into_iter(self) -> DatagramsIter<'a> {
        self.iter()
    }
}

/// Iterator over a [`Datagrams`] batch.
#[derive(Clone, Debug)]
pub struct DatagramsIter<'a> {
    d: Datagrams<'a>,
    i: usize,
}

impl<'a> Iterator for DatagramsIter<'a> {
    type Item = (SocketAddr, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        while self.i < self.d.len() {
            let i = self.i;
            self.i += 1;
            if let Some(x) = self.d.get(i) {
                return Some(x);
            }
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.d.len() - self.i;
        (left, Some(left))
    }
}

/// Sends datagrams from a datagram listener's socket, from any thread (`Send + Sync`, cheap to
/// clone). Get one from the handler factory of `akio::Listener::serve_datagrams`, from
/// [`Replies::sender`] or from `akio::Engine::datagram_sender`.
///
/// Every [`send_to`](Self::send_to) is one `sendto` on the calling thread, nothing is queued:
/// when the socket's send buffer is full the datagram is dropped with
/// `ErrorKind::WouldBlock` (UDP semantics; protocols on top retransmit). Inside
/// `on_datagrams`, [`Replies::send_to`] is cheaper: its datagrams leave in one `sendmmsg`.
#[derive(Clone)]
pub struct DatagramSender {
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    stats: Arc<LoopStats>,
}

impl std::fmt::Debug for DatagramSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramSender")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl DatagramSender {
    /// The listener's bound address (port 0 resolved).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Sends one datagram to `addr` right away, from the calling thread (see the type docs).
    pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        loop {
            match self.sock.send_to(data, addr) {
                Ok(n) => {
                    // Counted from any thread: atomic adds (the I/O thread's own use `add_local`).
                    self.stats.writes.add(1);
                    self.stats.datagrams_out.add(1);
                    self.stats.bytes_out.add(n as u64);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Msg {
    addr: SocketAddr,
    off: usize,
    len: usize,
}

/// Datagrams to send at the end of a receive batch ([`DatagramsHandler::on_datagrams`]).
///
/// [`send_to`](Self::send_to) copies the datagram into a buffer owned by the I/O thread; when the
/// callback returns everything goes out with as few syscalls as the platform allows (Linux:
/// `sendmmsg`, with runs of equal-size datagrams to one address merged into one UDP GSO
/// message; elsewhere one `sendto` each). Datagrams the socket has no room for wait, and the
/// listener's thread stops reading until they are out (backpressure). The queue holds at most
/// `Config::max_queued_bytes` (each datagram counts its bytes plus 64); past that `send_to`
/// first sends what is queued and refuses the datagram if that did not make room.
pub struct Replies {
    sender: DatagramSender,
    buf: Vec<u8>,
    msgs: Vec<Msg>,
    /// `msgs[..head]` are sent (or dropped).
    head: usize,
    cap: usize,
    /// The socket was full: the rest waits for it to become writable.
    blocked: bool,
    #[cfg(target_os = "linux")]
    sb: akio_sys::SendBatch,
}

impl std::fmt::Debug for Replies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replies")
            .field("queued", &(self.msgs.len() - self.head))
            .finish_non_exhaustive()
    }
}

impl Replies {
    fn new(sender: DatagramSender, cap: usize) -> Replies {
        Replies {
            sender,
            buf: Vec::new(),
            msgs: Vec::new(),
            head: 0,
            cap: cap.max(MAX_DATAGRAM + MSG_OVERHEAD),
            blocked: false,
            #[cfg(target_os = "linux")]
            sb: akio_sys::SendBatch::new(),
        }
    }

    /// Bytes counted against the queue limit.
    fn queued(&self) -> usize {
        let first = self.msgs.get(self.head).map_or(self.buf.len(), |m| m.off);
        (self.buf.len() - first) + (self.msgs.len() - self.head) * MSG_OVERHEAD
    }

    /// Queues one datagram to `addr`, sent when the callback returns. Errors:
    /// `InvalidInput` for more than 65,535 bytes; `WouldBlock` when the queue is full and the
    /// socket has no room for what is queued (the datagram is dropped).
    pub fn send_to(&mut self, data: &[u8], addr: SocketAddr) -> io::Result<()> {
        if data.len() > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram longer than 65,535 bytes",
            ));
        }
        let cost = data.len() + MSG_OVERHEAD;
        if self.queued() + cost > self.cap {
            if !self.blocked {
                self.flush();
            }
            if self.queued() + cost > self.cap {
                self.sender.stats.overloaded.add_local(1);
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "datagram queue full (max_queued_bytes)",
                ));
            }
        }
        let off = self.buf.len();
        self.buf.extend_from_slice(data);
        self.msgs.push(Msg {
            addr,
            off,
            len: data.len(),
        });
        Ok(())
    }

    /// Datagrams queued and not sent yet.
    pub fn len(&self) -> usize {
        self.msgs.len() - self.head
    }

    /// Nothing queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A handle that sends from this socket from any thread (for work handed off the I/O
    /// thread).
    pub fn sender(&self) -> &DatagramSender {
        &self.sender
    }

    /// Drops what was sent from the front of the queue, keeping the rest.
    fn compact(&mut self) {
        if self.head == self.msgs.len() {
            self.buf.clear();
            self.msgs.clear();
            self.head = 0;
            self.blocked = false;
            if self.buf.capacity() > KEEP_CAPACITY {
                self.buf = Vec::new();
            }
            if self.msgs.capacity() > KEEP_CAPACITY / MSG_OVERHEAD {
                self.msgs = Vec::new();
            }
        } else if self.head > 0 {
            let base = self.msgs[self.head].off;
            self.buf.drain(..base);
            self.msgs.drain(..self.head);
            for m in &mut self.msgs {
                m.off -= base;
            }
            self.head = 0;
        }
    }

    #[cfg(test)]
    fn on_writable_for_test(&mut self) {
        self.blocked = false;
        self.flush();
    }

    /// Sends what is queued until the socket is full.
    #[cfg(target_os = "linux")]
    fn flush(&mut self) {
        use akio_sys::{MAX_GSO_BYTES, MAX_GSO_SEGMENTS, SEND_BATCH};
        use std::os::fd::AsRawFd;
        const EIO: i32 = 5;
        const EINVAL: i32 = 22;
        if self.head == self.msgs.len() {
            return self.compact();
        }
        let fd = self.sender.sock.as_raw_fd();
        let (mut calls, mut sent, mut bytes) = (0u64, 0u64, 0u64);
        let Replies {
            buf,
            msgs,
            head,
            blocked,
            sb,
            ..
        } = self;
        'outer: while *head < msgs.len() {
            let gso = akio_sys::gso_enabled();
            // Per message pushed: datagrams in it and their bytes.
            let mut counts = [(0usize, 0usize); SEND_BATCH];
            let mut k = 0;
            let mut b = sb.batch();
            let mut i = *head;
            while i < msgs.len() && k < SEND_BATCH {
                let first = msgs[i];
                let seg = first.len;
                let (mut j, mut total) = (i + 1, seg);
                if gso && seg > 0 {
                    // Equal-size datagrams to one address; only the last may be shorter.
                    while j < msgs.len() && j - i < MAX_GSO_SEGMENTS {
                        let m = msgs[j];
                        // An empty datagram has no bytes to segment: never part of a run.
                        if m.addr != first.addr
                            || m.len == 0
                            || m.len > seg
                            || total + m.len > MAX_GSO_BYTES
                        {
                            break;
                        }
                        total += m.len;
                        j += 1;
                        if m.len < seg {
                            break;
                        }
                    }
                }
                // Queued in order, so a run is one contiguous range of the buffer.
                let data = &buf[first.off..first.off + total];
                let g = if j - i > 1 { seg } else { 0 };
                if !b.push(Some(&first.addr), std::slice::from_ref(&data), g) {
                    break;
                }
                counts[k] = (j - i, total);
                k += 1;
                i = j;
            }
            let mut done = 0;
            let mut stop = false;
            while done < k {
                match b.send(fd, done) {
                    Ok(0) => {
                        *blocked = true;
                        stop = true;
                        break;
                    }
                    Ok(n) => {
                        calls += 1;
                        for &(c, t) in &counts[done..done + n] {
                            sent += c as u64;
                            bytes += t as u64;
                        }
                        done += n;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        *blocked = true;
                        stop = true;
                        break;
                    }
                    Err(e) if b.is_gso(done) && matches!(e.raw_os_error(), Some(EIO | EINVAL)) => {
                        // The kernel or the device cannot segment: never try again.
                        akio_sys::disable_gso();
                        break;
                    }
                    // Refused (too big, unreachable, wrong family): dropped, as UDP does.
                    Err(_) => done += 1,
                }
            }
            *head += counts[..done].iter().map(|&(c, _)| c).sum::<usize>();
            if stop {
                break 'outer;
            }
        }
        let st = &self.sender.stats;
        st.writes.add_local(calls);
        st.datagrams_out.add_local(sent);
        st.bytes_out.add_local(bytes);
        self.compact();
    }

    /// Sends what is queued until the socket is full.
    #[cfg(not(target_os = "linux"))]
    fn flush(&mut self) {
        let (mut sent, mut bytes) = (0u64, 0u64);
        while self.head < self.msgs.len() {
            let m = self.msgs[self.head];
            match self
                .sender
                .sock
                .send_to(&self.buf[m.off..m.off + m.len], m.addr)
            {
                Ok(n) => {
                    sent += 1;
                    bytes += n as u64;
                    self.head += 1;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.blocked = true;
                    break;
                }
                // Refused (too big, unreachable, wrong family): dropped, as UDP does.
                Err(_) => self.head += 1,
            }
        }
        let st = &self.sender.stats;
        st.writes.add_local(sent);
        st.datagrams_out.add_local(sent);
        st.bytes_out.add_local(bytes);
        self.compact();
    }
}

/// Creates the [`DatagramsHandler`] of each I/O thread of a datagram listener. Backend-facing.
#[doc(hidden)]
pub type DatagramsFactory = Arc<dyn Fn(&DatagramSender) -> Box<dyn DatagramsHandler> + Send + Sync>;

/// Erases a handler factory's type. Backend-facing.
#[doc(hidden)]
pub fn datagrams_factory<H, F>(f: F) -> DatagramsFactory
where
    H: DatagramsHandler,
    F: Fn(&DatagramSender) -> H + Send + Sync + 'static,
{
    Arc::new(move |tx: &DatagramSender| Box::new(f(tx)) as Box<dyn DatagramsHandler>)
}

/// GRO (`Config::udp_gro`) coalesces up to 64 KiB into one receive: only when a slot holds that.
#[cfg(target_os = "linux")]
fn gro_ok(cfg: &Config) -> bool {
    cfg.udp_gro && cfg.read_buffer >= 65535 && akio_sys::gro_available()
}

/// Receive slot size for a read buffer of `rb` bytes.
fn slot_size(cfg: &Config, rb: usize) -> usize {
    #[cfg(target_os = "linux")]
    if gro_ok(cfg) {
        return rb.max(65535);
    }
    let _ = cfg;
    rb.max(1)
}

/// The receive side: `recvmmsg` slots on Linux, one buffer `recv_from` fills elsewhere.
#[cfg(target_os = "linux")]
type RxBuf = akio_sys::RecvBatch;
#[cfg(not(target_os = "linux"))]
type RxBuf = Vec<u8>;

fn new_rx(cfg: &Config, rb: usize) -> RxBuf {
    #[cfg(target_os = "linux")]
    {
        akio_sys::RecvBatch::with_gro(BATCH, rb, gro_ok(cfg))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        // Datagrams pack one after the other; a batch ends when less than a slot is left.
        vec![0; rb.saturating_mul(2)]
    }
}

/// One datagram socket served by a [`DatagramsHandler`]: the receive batch, the handler and its
/// reply queue. Owned by an I/O thread, which calls [`on_readable`](Self::on_readable) /
/// [`on_writable`](Self::on_writable) on readiness and polls the socket for reading while
/// [`wants_read`](Self::wants_read) and for writing while [`wants_write`](Self::wants_write).
/// Backend-facing.
#[doc(hidden)]
pub struct DatagramPort {
    id: u64,
    handler: Box<dyn DatagramsHandler>,
    out: Replies,
    cfg: Arc<Config>,
    rx: RxBuf,
    entries: Vec<Entry>,
    rb: usize,
    shut: bool,
}

impl std::fmt::Debug for DatagramPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramPort")
            .field("local", &self.out.sender.local)
            .finish_non_exhaustive()
    }
}

impl DatagramPort {
    /// Serves the bound socket `sock` (made non-blocking) with a handler from `factory`,
    /// counting into `stats` (the owning loop's counters).
    pub fn new(
        sock: UdpSocket,
        factory: &DatagramsFactory,
        stats: Arc<LoopStats>,
        cfg: Arc<Config>,
    ) -> io::Result<DatagramPort> {
        sock.set_nonblocking(true)?;
        let local = sock.local_addr()?;
        #[cfg(target_os = "linux")]
        if gro_ok(&cfg) {
            use std::os::fd::AsRawFd;
            akio_sys::enable_gro(sock.as_raw_fd());
        }
        let sender = DatagramSender {
            sock: Arc::new(sock),
            local,
            stats,
        };
        let handler = catch_unwind(AssertUnwindSafe(|| factory(&sender)))
            .map_err(|_| io::Error::other("datagrams handler factory panicked"))?;
        let rb = slot_size(&cfg, cfg.telemetry.live().read_buffer());
        Ok(DatagramPort {
            id: NEXT_PORT_ID.fetch_add(1, Ordering::Relaxed),
            handler,
            out: Replies::new(sender.clone(), cfg.max_queued_bytes),
            rx: new_rx(&cfg, rb),
            cfg,
            entries: Vec::with_capacity(BATCH),
            rb,
            shut: false,
        })
    }

    /// The socket's descriptor.
    #[cfg(unix)]
    pub fn fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.out.sender.sock.as_raw_fd()
    }

    /// A sender on this socket.
    pub fn sender(&self) -> DatagramSender {
        self.out.sender.clone()
    }

    /// Poll for reading: not after shutdown, nor while replies wait for socket space.
    pub fn wants_read(&self) -> bool {
        !self.shut && !self.out.blocked
    }

    /// Poll for writing: replies wait for socket space.
    pub fn wants_write(&self) -> bool {
        self.out.blocked
    }

    /// The socket is writable: sends what waits.
    pub fn on_writable(&mut self) {
        self.out.flush();
    }

    /// Live settings changed: the receive buffers take the new `read_buffer` (between batches).
    pub fn on_reload(&mut self) {
        let rb = slot_size(&self.cfg, self.cfg.telemetry.live().read_buffer());
        if rb != self.rb {
            self.rb = rb;
            self.rx = new_rx(&self.cfg, rb);
        }
    }

    /// Shutdown: `on_shutdown`, then what it queued is sent; reading stops.
    pub fn shutdown(&mut self) {
        if self.shut {
            return;
        }
        self.shut = true;
        let t0 = self.cfg.telemetry.timing();
        let (h, out) = (&mut *self.handler, &mut self.out);
        if catch_unwind(AssertUnwindSafe(|| h.on_shutdown(out))).is_err() {
            self.panicked("on_shutdown");
        }
        self.cfg
            .telemetry
            .callback_done(&self.out.sender.stats, "on_shutdown", self.id, t0);
        self.out.flush();
    }

    fn panicked(&self, what: &str) {
        log_or_stderr(
            akio_log::Level::Error,
            format_args!(
                "datagrams handler of {} panicked in {what}; serving on",
                self.out.sender.local
            ),
        );
    }

    /// Runs the handler on the batch in `entries`, then sends its replies.
    fn dispatch(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let st = &self.out.sender.stats;
        for e in &self.entries {
            st.datagram_in(e.len as usize);
        }
        let t0 = self.cfg.telemetry.timing_enabled().then(Instant::now);
        let batch = Datagrams {
            entries: &self.entries,
            src: &self.rx,
        };
        let (h, out) = (&mut *self.handler, &mut self.out);
        let r = catch_unwind(AssertUnwindSafe(|| h.on_datagrams(&batch, out)));
        let st = &self.out.sender.stats;
        match t0 {
            Some(t0) => {
                self.cfg
                    .telemetry
                    .callback_done_at(st, "on_datagrams", self.id, t0);
            }
            None => st.callbacks.add_local(1),
        }
        if r.is_err() {
            self.panicked("on_datagrams");
        }
        self.entries.clear();
        self.out.flush();
    }

    /// The socket is readable: receive batches go to the handler (up to eight per call, the
    /// replies of each sent before the next is read), until the socket is empty or the replies
    /// fill it.
    pub fn on_readable(&mut self) {
        let fd = self.fd();
        for _ in 0..MAX_BATCHES_PER_EVENT {
            if !self.wants_read() {
                return;
            }
            let Some(full) = self.receive(fd) else {
                return;
            };
            self.dispatch();
            if !full {
                return;
            }
        }
    }

    /// One receive batch into `entries`. `Some(true)`: the batch was full (more may wait);
    /// `None`: nothing was read.
    #[cfg(target_os = "linux")]
    fn receive(&mut self, fd: std::os::fd::RawFd) -> Option<bool> {
        let rx = &mut self.rx;
        let n = loop {
            match rx.recv(fd) {
                Ok(0) => return None,
                Ok(n) => break n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    akio_log::debug!(target: "akio", "recvmmsg: {e}");
                    return None;
                }
            }
        };
        for i in 0..n {
            let (Some(peer), Some((d, seg))) = (rx.addr(i), rx.data(i)) else {
                continue;
            };
            if seg > 0 && seg < d.len() {
                // GRO coalesced several datagrams of this peer: restore the boundaries.
                let mut off = 0;
                while off < d.len() {
                    let len = seg.min(d.len() - off);
                    self.entries.push(Entry {
                        peer,
                        slot: i as u32,
                        off: off as u32,
                        len: len as u32,
                    });
                    off += len;
                }
            } else {
                self.entries.push(Entry {
                    peer,
                    slot: i as u32,
                    off: 0,
                    len: d.len() as u32,
                });
            }
        }
        Some(n == BATCH)
    }

    /// One receive batch into `entries` (up to [`BATCH`] `recv_from` calls).
    #[cfg(not(target_os = "linux"))]
    fn receive(&mut self, _fd: i32) -> Option<bool> {
        let buf = &mut self.rx;
        let sock = &self.out.sender.sock;
        let mut off = 0;
        while self.entries.len() < BATCH && buf.len() - off >= self.rb {
            match sock.recv_from(&mut buf[off..off + self.rb]) {
                Ok((n, peer)) => {
                    self.entries.push(Entry {
                        peer,
                        slot: 0,
                        off: off as u32,
                        len: n as u32,
                    });
                    off += n;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    akio_log::debug!(target: "akio", "recv_from: {e}");
                    break;
                }
            }
        }
        if self.entries.is_empty() {
            None
        } else {
            Some(self.entries.len() == BATCH || buf.len() - off < self.rb)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LoopMeta;

    fn replies(cap: usize) -> (Replies, UdpSocket) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let local = sock.local_addr().unwrap();
        let stats = Arc::new(LoopStats::new(LoopMeta::new("test", None, 0)));
        let tx = DatagramSender {
            sock: Arc::new(sock),
            local,
            stats,
        };
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        (Replies::new(tx, cap), rx)
    }

    #[test]
    fn queue_limit_below_at_and_above() {
        let (mut r, rx) = replies(0);
        let to = rx.local_addr().unwrap();
        // The smallest limit still takes one datagram of any size.
        assert_eq!(r.cap, MAX_DATAGRAM + MSG_OVERHEAD);
        // The socket "is full": nothing can be sent, so the limit is what refuses.
        r.blocked = true;
        let n = 1000 - MSG_OVERHEAD;
        let fits = r.cap / 1000;
        for _ in 0..fits {
            r.send_to(&vec![1; n], to).unwrap();
        }
        assert_eq!(r.len(), fits);
        let left = r.cap - r.queued();
        assert!(left < 1000);
        // Exactly the room left: accepted; one byte more: refused.
        let e = r
            .send_to(&vec![2; left - MSG_OVERHEAD + 1], to)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        r.send_to(&vec![2; left - MSG_OVERHEAD], to).unwrap();
        assert_eq!(r.queued(), r.cap);
        assert_eq!(r.sender.stats.overloaded.get(), 1);
        assert_eq!(
            r.send_to(b"", to).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // Writable again: everything goes, in order, and the queue is empty.
        r.on_writable_for_test();
        assert!(r.is_empty() && !r.blocked);
        let mut b = vec![0; 70_000];
        for _ in 0..fits {
            assert_eq!(rx.recv(&mut b).unwrap(), n);
        }
        assert_eq!(rx.recv(&mut b).unwrap(), left - MSG_OVERHEAD);
        let st = r.sender.stats.snapshot();
        assert_eq!(st.datagrams_out, fits as u64 + 1);
    }

    #[test]
    fn too_long_is_invalid() {
        let (mut r, rx) = replies(1 << 20);
        let to = rx.local_addr().unwrap();
        let e = r.send_to(&vec![0; MAX_DATAGRAM + 1], to).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        assert!(r.is_empty());
    }

    #[test]
    fn runs_to_one_address_stay_in_order() {
        let (mut r, rx) = replies(1 << 20);
        let to = rx.local_addr().unwrap();
        // Equal sizes, a shorter last one, then a longer one: GSO runs break where they must.
        let sizes = [100, 100, 100, 40, 100, 300, 300, 0, 7];
        for (i, &n) in sizes.iter().enumerate() {
            r.send_to(&vec![i as u8; n], to).unwrap();
        }
        r.flush();
        assert!(r.is_empty());
        let mut b = vec![0; 70_000];
        for (i, &n) in sizes.iter().enumerate() {
            let k = rx.recv(&mut b).unwrap();
            assert_eq!(k, n, "datagram {i}");
            assert!(b[..k].iter().all(|&x| x == i as u8));
        }
    }
}
