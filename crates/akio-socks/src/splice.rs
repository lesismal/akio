//! The kernel fast path of `CONNECT` tunnels ([`ProxyConfig::sockmap`](crate::ProxyConfig)):
//! once the upstream is connected, and before the client is told so, the two sockets are
//! spliced with the sockmap relay and the bytes stop passing through userspace.
//!
//! Splicing is refused (and the tunnel relays in userspace as before) when the client sent data
//! behind its request that userspace already holds, for TLS connections, and wherever the relay
//! is unavailable. Bytes waiting in the sockets' receive queues (a server that greets first) are
//! relayed by the kernel after the reply, in order. Should userspace still read payload from a
//! spliced tunnel while both ends are open (an io_uring read that completed before the splice
//! took over), the tunnel is closed rather than risk reordering. A spliced tunnel's progress is read from the sockets'
//! TCP counters: for the idle timeout, and on close, where the other side is only closed once
//! everything the closing side sent has reached its send queue (closing a socket drops what the
//! kernel's relay still holds for it).

use std::{
    io::Write,
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use akio::ebpf::{Relay, byte_counts};
use akio_core::ConnInner;

/// Tunnels spliced since the process started.
static SPLICED: AtomicU64 = AtomicU64::new(0);

/// Number of tunnels the sockmap fast path has spliced in this process (tests, metrics).
#[doc(hidden)]
pub fn spliced_tunnels() -> u64 {
    SPLICED.load(Ordering::Relaxed)
}

/// Byte counters of both sockets when they were spliced.
#[derive(Clone, Copy, Debug)]
struct Base {
    client_rx: u64,
    /// Includes the reply userspace writes right after splicing.
    client_tx: u64,
    up_rx: u64,
    up_tx: u64,
}

/// The fast path of one tunnel.
pub(crate) struct SpliceCtl {
    relay: Relay,
    /// The client sent bytes the userspace relay holds: never splice.
    early: AtomicBool,
    base: OnceLock<Base>,
}

impl SpliceCtl {
    pub(crate) fn new(relay: Option<&Relay>) -> Option<Arc<SpliceCtl>> {
        relay.map(|r| {
            Arc::new(SpliceCtl {
                relay: r.clone(),
                early: AtomicBool::new(false),
                base: OnceLock::new(),
            })
        })
    }

    /// Userspace holds client bytes for the upstream (call with the upstream slot locked, so
    /// that the upstream's thread sees it before deciding).
    pub(crate) fn mark_early(&self) {
        self.early.store(true, Ordering::Release);
    }

    pub(crate) fn is_spliced(&self) -> bool {
        self.base.get().is_some()
    }

    /// Splices `client` and `up` on the upstream's I/O thread, writing the success `reply`
    /// to the client directly once both are spliced and before any byte is relayed (the client
    /// is waiting for it with its reads held). Returns how much of `reply` was written: all of
    /// it when the tunnel is spliced; otherwise the caller sends the rest and relays in
    /// userspace.
    pub(crate) fn try_splice(&self, client: &ConnInner, up: &ConnInner, reply: &[u8]) -> usize {
        if self.early.load(Ordering::Acquire) {
            return 0;
        }
        let (Some(cs), Some(us)) = (client.tcp_stream(), up.tcp_stream()) else {
            return 0;
        };
        let (Ok(c), Ok(u)) = (byte_counts(cs), byte_counts(us)) else {
            return 0;
        };
        let mut written = 0;
        let r = self.relay.splice_inner_with(client, up, || {
            written = (&*cs).write(reply)?;
            if written == reply.len() {
                Ok(())
            } else {
                Err(std::io::ErrorKind::WriteZero.into())
            }
        });
        if r.is_err() {
            return written;
        }
        let _ = self.base.set(Base {
            client_rx: c.received,
            client_tx: c.written + reply.len() as u64,
            up_rx: u.received,
            up_tx: u.written,
        });
        SPLICED.fetch_add(1, Ordering::Relaxed);
        reply.len()
    }

    /// Bytes received on both sockets: changes while the tunnel moves data.
    pub(crate) fn activity(client: &ConnInner, up: &ConnInner) -> u64 {
        let rx = |c: &ConnInner| {
            c.tcp_stream()
                .and_then(|s| byte_counts(s).ok())
                .map_or(0, |b| b.received)
        };
        rx(client).wrapping_add(rx(up))
    }

    /// `from` closed (`from_client`: it is the client): closes `to` once everything `from`
    /// received since splicing has been written to `to`, or when that stops progressing for
    /// `stall`.
    pub(crate) fn close_after_forward(
        &self,
        from: &ConnInner,
        from_client: bool,
        to: Arc<ConnInner>,
        stall: Duration,
    ) {
        let Some(b) = self.base.get() else {
            return to.close_after_send();
        };
        let Some(rx) = from.tcp_stream().and_then(|s| byte_counts(s).ok()) else {
            return to.close_after_send();
        };
        let (rx0, tx0) = if from_client {
            (b.client_rx, b.up_tx)
        } else {
            (b.up_rx, b.client_tx)
        };
        let target = tx0 + rx.received.saturating_sub(rx0);
        drainer().add(Drain {
            to,
            target,
            last: 0,
            since: Instant::now(),
            stall,
        });
    }
}

/// A side waiting for the kernel's relay backlog to reach its send queue before it is closed.
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
        let written = match self.to.tcp_stream().map(byte_counts) {
            Some(Ok(b)) => b.written,
            _ => {
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

/// The process's drainer thread: polls waiting sides every millisecond while there are any.
fn drainer() -> &'static Drainer {
    static D: OnceLock<&'static Drainer> = OnceLock::new();
    D.get_or_init(|| {
        let d: &'static Drainer = Box::leak(Box::new(Drainer {
            list: Mutex::new(Vec::new()),
            wake: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("akio-socks-splice".into())
            .spawn(move || {
                loop {
                    {
                        let mut g = d.list.lock().unwrap_or_else(|p| p.into_inner());
                        while g.is_empty() {
                            g = d.wake.wait(g).unwrap_or_else(|p| p.into_inner());
                        }
                        g.retain_mut(|x| !x.poll());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .expect("akio-socks splice thread");
        d
    })
}
