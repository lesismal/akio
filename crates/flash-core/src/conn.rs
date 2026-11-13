use std::{
    collections::VecDeque,
    io::{self, IoSlice, Write},
    marker::PhantomData,
    net::{SocketAddr, TcpStream, UdpSocket},
    sync::Arc,
};

use flash_buf::SharedBuf;

use crate::{
    Config, Error, Handler, Pool, Result,
    sync::{AtomicBool, AtomicU8, Mutex, MutexGuard, Ordering},
};

const OPEN: u8 = 0;
const CLOSING: u8 = 1;
const CLOSED: u8 = 2;

/// How a connection reaches its owning I/O loop. Implemented by backends.
///
/// Implementations must make `wake_conn` / `close_conn` cheap, callable from any thread
/// (including the loop's own, from inside callbacks) and never call user code.
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
}

/// A type-erased completion for a connection's handler (see [`LoopLink::post_task`]).
pub type Task = Box<dyn std::any::Any + Send>;

/// What a [`Task`] holds for handler type `H`.
pub(crate) type Completion<H> = Box<dyn FnOnce(&mut H, &Conn<H>) + Send>;

enum Bytes {
    Owned(Vec<u8>),
    Shared(SharedBuf),
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
        }
    }
}

/// A byte-stream transformation layered under a connection, such as TLS (see `flash-tls`).
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
    fn as_any(&mut self) -> &mut dyn std::any::Any;
}

#[derive(Default)]
struct WriteState {
    /// UDP: every chunk is one datagram; never coalesced, never partially written.
    datagram: bool,
    transport: Option<Box<dyn Transport>>,
    queue: VecDeque<Chunk>,
    queued: usize,
    corked: bool,
    close_after_send: bool,
}

impl WriteState {
    fn push_copy(&mut self, data: &[u8]) {
        self.queued += data.len();
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
        let mut v = flash_buf::get(data.len());
        v.extend_from_slice(data);
        self.queue.push_back(Chunk {
            bytes: Bytes::Owned(v),
            off: 0,
        });
    }

    fn consume(&mut self, mut n: usize) {
        self.queued -= n;
        while n > 0 {
            let front = self.queue.front_mut().expect("consumed more than queued");
            let left = front.rest().len();
            if n < left {
                front.off += n;
                return;
            }
            n -= left;
            if let Some(Chunk {
                bytes: Bytes::Owned(v),
                ..
            }) = self.queue.pop_front()
            {
                flash_buf::put(v);
            }
        }
    }

    fn clear(&mut self) {
        for c in self.queue.drain(..) {
            if let Bytes::Owned(v) = c.bytes {
                flash_buf::put(v);
            }
        }
        self.queued = 0;
    }
}

/// Responses reserved in request order, possibly filled out of order (see [`ResponseSlot`]).
#[derive(Default)]
struct Ordered {
    /// Sequence number of `ready[0]`.
    head: u64,
    next: u64,
    ready: VecDeque<Option<Vec<u8>>>,
}

/// The socket under a connection: its own TCP stream, or a peer on a shared UDP socket.
enum Sock {
    Tcp(TcpStream),
    Udp {
        sock: Arc<UdpSocket>,
        peer: SocketAddr,
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
    write: Mutex<WriteState>,
    ordered: Mutex<Ordered>,
    sock: Sock,
    link: Arc<dyn LoopLink>,
    cfg: Arc<Config>,
    local: SocketAddr,
    peer: SocketAddr,
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
            write: Mutex::new(WriteState::default()),
            ordered: Mutex::new(Ordered::default()),
            sock: Sock::Tcp(stream),
            link,
            cfg,
            local,
            peer,
        })
    }

    /// A "connection" to `peer` over the UDP socket `sock` shared with other peers. Each `send`
    /// is one datagram to `peer`; reads are delivered by the backend as whole datagrams.
    pub fn new_udp(
        id: u64,
        sock: Arc<UdpSocket>,
        local: SocketAddr,
        peer: SocketAddr,
        link: Arc<dyn LoopLink>,
        cfg: Arc<Config>,
    ) -> Arc<ConnInner> {
        Arc::new(ConnInner {
            id,
            state: AtomicU8::new(OPEN),
            hold: AtomicBool::new(false),
            write: Mutex::new(WriteState {
                datagram: true,
                ..WriteState::default()
            }),
            ordered: Mutex::new(Ordered::default()),
            sock: Sock::Udp { sock, peer },
            link,
            cfg,
            local,
            peer,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// The TCP stream. Only call on connections created with [`ConnInner::new`].
    pub fn stream(&self) -> &TcpStream {
        match &self.sock {
            Sock::Tcp(s) => s,
            Sock::Udp { .. } => unreachable!("stream() on a UDP connection"),
        }
    }

    fn tcp(&self) -> &TcpStream {
        self.stream()
    }

    /// Writes `data` to the socket (for UDP: as one datagram to the peer).
    fn raw_write(&self, data: &[u8]) -> io::Result<usize> {
        match &self.sock {
            Sock::Tcp(s) => (&*s).write(data),
            Sock::Udp { sock, peer } => sock.send_to(data, peer),
        }
    }

    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPEN
    }

    pub fn read_held(&self) -> bool {
        self.hold.load(Ordering::Acquire)
    }

    pub fn queued_bytes(&self) -> usize {
        self.lock().queued
    }

    /// True once `close_after_send` was requested.
    pub fn close_after_send_requested(&self) -> bool {
        self.lock().close_after_send
    }

    /// Loop side: coalesce writes (`true`) or stop coalescing (`false`, call [`flush_queue`]).
    pub fn set_corked(&self, corked: bool) {
        self.lock().corked = corked;
    }

    /// Loop side: end of a callback. Uncorks and writes what the callback queued.
    /// Returns `Err` if the socket failed.
    pub fn uncork_flush(&self) -> io::Result<()> {
        let mut w = self.lock();
        w.corked = false;
        self.write_locked(&mut w).map(drop)
    }

    /// Loop side: writes as much queued data as the socket takes. `Ok(true)` when empty.
    pub fn flush_queue(&self) -> io::Result<bool> {
        let mut w = self.lock();
        self.write_locked(&mut w)
    }

    /// Loop side: the connection is gone; drop queued output.
    pub fn mark_closed(&self) {
        self.state.store(CLOSED, Ordering::Release);
        self.lock().clear();
    }

    fn lock(&self) -> MutexGuard<'_, WriteState> {
        // A poisoned lock only means a user callback panicked elsewhere; the queue is still
        // consistent because it is never mutated across a callback.
        self.write.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Writes queued chunks with `writev` until the queue is empty or the socket is full.
    fn write_locked(&self, w: &mut WriteState) -> io::Result<bool> {
        const MAX_IOV: usize = 16;
        if w.datagram {
            while let Some(c) = w.queue.front() {
                match self.raw_write(c.rest()) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    // A datagram the network refuses (too big, unreachable) is dropped, as UDP
                    // does; it must not wedge the datagrams behind it.
                    Err(_) => {}
                }
                let n = c.rest().len();
                w.consume(n);
            }
            return Ok(true);
        }
        while !w.queue.is_empty() {
            let n = {
                let mut iov: [IoSlice<'_>; MAX_IOV] = [IoSlice::new(&[]); MAX_IOV];
                let mut k = 0;
                for (slot, c) in iov.iter_mut().zip(w.queue.iter()) {
                    *slot = IoSlice::new(c.rest());
                    k += 1;
                }
                match self.tcp().write_vectored(&iov[..k]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            };
            w.consume(n);
        }
        Ok(true)
    }

    fn check_sendable(&self, w: &WriteState, extra: usize) -> Result<()> {
        if !self.is_open() || w.close_after_send {
            return Err(Error::Closed);
        }
        if w.queued + extra > self.cfg.max_queued_bytes {
            return Err(Error::Overloaded);
        }
        Ok(())
    }

    /// A write failed on a non-loop path: schedule the close and report it.
    fn fail(&self, e: io::Error) -> Error {
        if matches!(self.sock, Sock::Udp { .. }) {
            // A refused datagram does not end a UDP "connection".
            return Error::Io(e);
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
        // Fast path: nothing queued and not corked -> write straight to the socket.
        if was_empty && !w.corked {
            loop {
                match self.raw_write(data) {
                    Ok(n) if n == data.len() => return Ok(()),
                    Ok(n) => data = &data[n..],
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
        let need_wake = was_empty && !w.corked;
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
            Ok(Some(sealed)) => sealed,
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
        let mut off = 0;
        if was_empty && !w.corked {
            loop {
                match self.raw_write(&data[off..]) {
                    Ok(n) => {
                        off += n;
                        if off == data.len() {
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
        w.queued += data.len() - off;
        w.queue.push_back(Chunk {
            bytes: Bytes::Owned(data),
            off,
        });
        let need_wake = was_empty && !w.corked;
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
        w.queued += match &bytes {
            Bytes::Owned(v) => v.len(),
            Bytes::Shared(s) => s.len(),
        };
        w.queue.push_back(Chunk { bytes, off: 0 });
        let need_wake = was_empty && !w.corked;
        if !w.corked {
            // Try to push it out right away.
            if let Err(e) = self.write_locked(&mut w) {
                drop(w);
                return Err(self.fail(e));
            }
        }
        drop(w);
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
        match self.write_locked(&mut w) {
            Ok(true) => Ok(()),
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
        }
        drop(w);
        self.link.wake_conn(self.id);
    }

    pub fn hold_reads(&self, hold: bool) {
        if self.hold.swap(hold, Ordering::AcqRel) != hold {
            self.link.wake_conn(self.id);
        }
    }

    /// Reserves the next response position. Call in request order (on the I/O thread).
    pub fn reserve(&self) -> u64 {
        let mut o = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        o.ready.push_back(None);
        o.next += 1;
        o.next - 1
    }

    /// Fills reserved position `seq`; everything now contiguous from the front is sent in order.
    pub fn fill(&self, seq: u64, data: Vec<u8>) {
        let mut o = self.ordered.lock().unwrap_or_else(|p| p.into_inner());
        let i = (seq - o.head) as usize;
        o.ready[i] = Some(data);
        // The lock is held across the sends: two threads finishing neighbouring slots must not
        // interleave their writes.
        while let Some(Some(_)) = o.ready.front() {
            if let Some(Some(d)) = o.ready.pop_front() {
                o.head += 1;
                let _ = self.send_owned(d);
            }
        }
    }

    /// Installs the transport layer. Call once, before any data flows.
    pub fn set_transport(&self, t: Box<dyn Transport>) {
        self.lock().transport = Some(t);
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
        let wake = self.queue_raw(&mut w, out);
        drop(w);
        if wake {
            self.link.wake_conn(self.id);
        }
        r
    }

    /// Queues bytes that are already encoded for the wire. Returns whether the loop must be
    /// woken to flush them.
    fn queue_raw(&self, w: &mut WriteState, out: Vec<u8>) -> bool {
        if out.is_empty() {
            return false;
        }
        let was_empty = w.queue.is_empty();
        w.queued += out.len();
        w.queue.push_back(Chunk {
            bytes: Bytes::Owned(out),
            off: 0,
        });
        was_empty && !w.corked
    }

    /// Encodes `data` through the transport if there is one.
    fn seal(&self, w: &mut WriteState, data: &[u8]) -> io::Result<Option<Vec<u8>>> {
        match w.transport.as_mut() {
            None => Ok(None),
            Some(t) => {
                let mut out = Vec::with_capacity(data.len() + 64);
                t.seal(data, &mut out)?;
                Ok(Some(out))
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
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

    /// Coalesces writes until [`flush`](Self::flush). Inside `on_data` this is already the
    /// default: everything sent during a callback leaves in one `writev` when it returns.
    pub fn cork(&self) {
        self.inner.cork()
    }

    /// Ends corking and writes queued output.
    pub fn flush(&self) -> Result<()> {
        self.inner.flush()
    }

    /// Closes the connection, discarding unsent data. `on_close` runs on the I/O thread.
    pub fn close(&self) {
        self.inner.close()
    }

    /// Closes once everything queued has been written; further sends fail with `Closed`.
    pub fn close_after_send(&self) {
        self.inner.close_after_send()
    }

    /// Pauses (`true`) or resumes (`false`) reading from the peer.
    pub fn hold_reads(&self, hold: bool) {
        self.inner.hold_reads(hold)
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
pub struct ResponseSlot {
    seq: u64,
    inner: Option<Arc<ConnInner>>,
}

impl ResponseSlot {
    /// Supplies the response bytes. Safe to call from any thread.
    pub fn fill(mut self, data: Vec<u8>) {
        if let Some(inner) = self.inner.take() {
            inner.fill(self.seq, data);
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
/// `RUSTFLAGS="--cfg loom" cargo test -p flash-core --lib --release -- loom`.
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
