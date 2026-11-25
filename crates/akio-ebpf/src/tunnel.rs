//! A spliced tunnel between two `akio` connections ([`Tunnel`], [`Relay::tunnel`]): the splice
//! with what a proxy needs to run it once its bytes no longer reach the handlers.
//!
//! [`Relay::tunnel`]: crate::Relay::tunnel

use std::{
    io,
    sync::{
        Arc, Condvar, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio_core::ConnInner;

use crate::relay::{ByteCounts, Splice, inner_byte_counts};

/// One side of a [`Tunnel`]: `a` or `b` of [`Relay::tunnel`](crate::Relay::tunnel).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TunnelSide {
    /// The first connection.
    A,
    /// The second connection, the one `first` was written to.
    B,
}

impl TunnelSide {
    fn index(self) -> usize {
        match self {
            TunnelSide::A => 0,
            TunnelSide::B => 1,
        }
    }
}

/// Two `akio` connections spliced by the kernel ([`Relay::tunnel`](crate::Relay::tunnel)), with
/// their counters as the splice began. A spliced connection's bytes never reach its handler, so
/// a proxy follows the tunnel by the sockets' counters:
///
/// - **idle timeout**: [`moved`](Self::moved) (or [`activity`](Self::activity)), read by the
///   proxy's sweep, says whether either socket received anything since the last read;
/// - **close**: when one side ends (its handler's `on_close`),
///   [`close_after_forward`](Self::close_after_forward) closes the other once everything the
///   ended side received has reached the other's send queue (closing a socket drops what the
///   kernel's relay still holds for it), or once that makes no progress for a stall timeout;
/// - **late payload**: a handler that still receives payload while the tunnel is spliced calls
///   [`late_payload`](Self::late_payload) and drops it.
///
/// The tunnel keeps the connections weakly: it does not keep them alive, and dropping it leaves
/// the splice in place (it ends when either socket closes). Every method returns at once; the
/// waits of `close_after_forward` run on a process-wide thread of `akio-ebpf`
/// (`akio-ebpf-drain`), which polls the waiting sides' counters every millisecond while there
/// are any.
#[derive(Debug)]
pub struct Tunnel {
    splice: Splice,
    conns: [Weak<ConnInner>; 2],
    base: [ByteCounts; 2],
    /// Bytes both sockets have received, as [`moved`](Self::moved) last read them.
    activity: AtomicU64,
    /// A drain was started towards that side.
    draining: [AtomicBool; 2],
}

impl Tunnel {
    pub(crate) fn new(splice: Splice, a: &Arc<ConnInner>, b: &Arc<ConnInner>) -> Tunnel {
        // A splice of two connections always has its base (`Relay::splice_inner_first`).
        let base = splice.base().unwrap_or_default();
        Tunnel {
            splice,
            conns: [Arc::downgrade(a), Arc::downgrade(b)],
            activity: AtomicU64::new(base[0].received.wrapping_add(base[1].received)),
            base,
            draining: [AtomicBool::new(false), AtomicBool::new(false)],
        }
    }

    /// The splice (its socket cookies).
    pub fn splice(&self) -> &Splice {
        &self.splice
    }

    /// The counters of `[a, b]` as the kernel began relaying ([`Splice::base`]).
    pub fn base(&self) -> [ByteCounts; 2] {
        self.base
    }

    /// The counters of `side`'s socket now, `None` once its connection is gone or they cannot
    /// be read.
    pub fn counts(&self, side: TunnelSide) -> Option<ByteCounts> {
        self.conn(side).and_then(|c| inner_byte_counts(&c).ok())
    }

    /// Bytes `from` has received since the splice that the kernel relays to the other side
    /// (everything past what userspace had read), `None` once `from` is gone.
    pub fn relayed_from(&self, from: TunnelSide) -> Option<u64> {
        let b = self.base[from.index()];
        self.counts(from)
            .map(|c| c.received.saturating_sub(b.consumed()))
    }

    /// The sum of the bytes both sockets have received, read now (a side that is gone counts
    /// 0): it changes while the tunnel moves data. Two `getsockopt`s and two `ioctl`s a socket.
    pub fn activity(&self) -> u64 {
        let rx = |s| self.counts(s).map_or(0, |c| c.received);
        rx(TunnelSide::A).wrapping_add(rx(TunnelSide::B))
    }

    /// Whether either socket received anything since the last call (or the splice): for the
    /// tunnel's idle timeout. False once either side closed.
    pub fn moved(&self) -> bool {
        let (Some(a), Some(b)) = (self.conn(TunnelSide::A), self.conn(TunnelSide::B)) else {
            return false;
        };
        if !a.is_open() || !b.is_open() {
            return false;
        }
        let (Ok(x), Ok(y)) = (inner_byte_counts(&a), inner_byte_counts(&b)) else {
            return false;
        };
        let now = x.received.wrapping_add(y.received);
        self.activity.swap(now, Ordering::Relaxed) != now
    }

    /// `from` ended (call it from its handler's `on_close`): the other side is closed (after
    /// what the engine still has queued for it, `close_after_send`) once everything `from`
    /// received has been written to its send queue by the kernel's relay, or closed at once
    /// (`close`) when its counter makes no progress for `stall`. Returns at once; later calls
    /// for the same side do nothing.
    pub fn close_after_forward(&self, from: TunnelSide, stall: Duration) {
        let to_side = match from {
            TunnelSide::A => TunnelSide::B,
            TunnelSide::B => TunnelSide::A,
        };
        if self.draining[to_side.index()].swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(to) = self.conn(to_side) else {
            return;
        };
        let Some(relayed) = self.relayed_from(from) else {
            return to.close_after_send();
        };
        let target = self.base[to_side.index()].written.saturating_add(relayed);
        let d = Drain {
            to,
            target,
            last: 0,
            since: Instant::now(),
            stall,
        };
        match drainer() {
            Some(dr) => dr.add(d),
            None => d.to.close_after_send(),
        }
    }

    /// A handler of either side received payload while the tunnel is spliced: it must be
    /// dropped. While both sides are open it can only be a read that completed before the
    /// splice took over (io_uring), which the kernel's newer bytes may have overtaken: both
    /// sides are closed rather than the stream reordered. Once one side closed, the kernel
    /// hands the other's data to userspace, where it has nowhere to go.
    pub fn late_payload(&self) {
        let (a, b) = (self.conn(TunnelSide::A), self.conn(TunnelSide::B));
        if let (Some(a), Some(b)) = (a, b) {
            if a.is_open() && b.is_open() {
                a.close();
                b.close();
            }
        }
    }

    /// Ends the splice ([`Splice::unsplice`]): later data goes to userspace again.
    pub fn unsplice(self) -> io::Result<()> {
        self.splice.unsplice()
    }

    fn conn(&self, side: TunnelSide) -> Option<Arc<ConnInner>> {
        self.conns[side.index()].upgrade()
    }
}

/// A side waiting for the kernel's relay to reach its send queue before it is closed.
struct Drain {
    to: Arc<ConnInner>,
    /// Its `written` counter once everything is forwarded.
    target: u64,
    last: u64,
    since: Instant,
    stall: Duration,
}

impl Drain {
    /// `true` when done (closed).
    fn poll(&mut self) -> bool {
        if !self.to.is_open() {
            return true;
        }
        let written = match inner_byte_counts(&self.to) {
            Ok(b) => b.written,
            Err(_) => {
                self.to.close_after_send();
                return true;
            }
        };
        if written >= self.target {
            self.to.close_after_send();
            return true;
        }
        if written != self.last {
            self.last = written;
            self.since = Instant::now();
        } else if self.since.elapsed() >= self.stall {
            self.to.close();
            return true;
        }
        false
    }
}

struct Drainer {
    list: Mutex<Vec<Drain>>,
    wake: Condvar,
}

impl Drainer {
    fn add(&self, d: Drain) {
        self.list.lock().unwrap_or_else(|p| p.into_inner()).push(d);
        self.wake.notify_one();
    }
}

/// How often the drain thread reads the waiting sides' counters.
const DRAIN_POLL: Duration = Duration::from_millis(1);

/// The process's drain thread, started on first use; `None` if it cannot be started (then
/// sides are closed after the engine's queue, as without a splice). It polls the waiting
/// sides without holding the list's lock, so an I/O thread adding one never waits on a poll.
fn drainer() -> Option<&'static Drainer> {
    static D: OnceLock<Option<&'static Drainer>> = OnceLock::new();
    *D.get_or_init(|| {
        let d: &'static Drainer = Box::leak(Box::new(Drainer {
            list: Mutex::new(Vec::new()),
            wake: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("akio-ebpf-drain".into())
            .spawn(move || {
                loop {
                    let mut batch = {
                        let mut g = d.list.lock().unwrap_or_else(|p| p.into_inner());
                        while g.is_empty() {
                            g = d.wake.wait(g).unwrap_or_else(|p| p.into_inner());
                        }
                        std::mem::take(&mut *g)
                    };
                    batch.retain_mut(|x| !x.poll());
                    if !batch.is_empty() {
                        d.list
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .append(&mut batch);
                    }
                    std::thread::sleep(DRAIN_POLL);
                }
            })
            .ok()
            .map(|_| d)
    })
}
