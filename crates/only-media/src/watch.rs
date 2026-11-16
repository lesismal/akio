//! Connection deadlines for the TCP media servers (RTMP, RTSP): a handshake (or first request)
//! deadline, an idle deadline on received bytes, and a deadline for a message once its first
//! bytes arrived (a peer trickling a byte at a time must not keep a half-received request
//! alive). The I/O thread only stores timestamps; checks run on the media timer thread, a few
//! times per deadline, and close the connection when one passed.

use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use only_core::ConnInner;

/// Deadlines of one connection; `Duration::ZERO` disables one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Deadlines {
    /// From accept until [`Watch::ready`].
    pub handshake: Duration,
    /// Without received bytes (while not [`Watch::set_exempt`]).
    pub idle: Duration,
    /// From the first byte of a message until it is complete ([`Watch::set_partial`]).
    pub message: Duration,
}

/// Shared between the connection's handler and the timer thread.
#[derive(Debug)]
pub(crate) struct Watch {
    start: Instant,
    /// Milliseconds since `start` of the last read.
    last: AtomicU64,
    /// Milliseconds since `start` (+1) when the pending partial message began; 0: none.
    partial: AtomicU64,
    ready: AtomicBool,
    exempt: AtomicBool,
}

impl Watch {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Bytes arrived.
    pub(crate) fn touch(&self) {
        self.last.store(self.now_ms(), Ordering::Relaxed);
    }

    /// The handshake is done (the handshake deadline no longer applies).
    pub(crate) fn ready(&self) {
        self.ready.store(true, Ordering::Relaxed);
    }

    /// Whether a partial message is held (its deadline starts with the first such call).
    pub(crate) fn set_partial(&self, pending: bool) {
        if !pending {
            self.partial.store(0, Ordering::Relaxed);
        } else if self.partial.load(Ordering::Relaxed) == 0 {
            self.partial.store(self.now_ms() + 1, Ordering::Relaxed);
        }
    }

    /// Exempts the connection from the idle deadline (a player that legitimately sends
    /// nothing; stalled players are bounded by the engine's write timeout).
    pub(crate) fn set_exempt(&self, exempt: bool) {
        self.exempt.store(exempt, Ordering::Relaxed);
        if !exempt {
            self.touch();
        }
    }

    /// Whether a deadline passed.
    fn expired(&self, d: &Deadlines) -> bool {
        let now = self.now_ms();
        let ms = |t: Duration| t.as_millis() as u64;
        if !self.ready.load(Ordering::Relaxed) && !d.handshake.is_zero() && now >= ms(d.handshake) {
            return true;
        }
        let p = self.partial.load(Ordering::Relaxed);
        if p != 0 && !d.message.is_zero() && now + 1 >= p + ms(d.message) {
            return true;
        }
        let last = self.last.load(Ordering::Relaxed);
        !self.exempt.load(Ordering::Relaxed) && !d.idle.is_zero() && now >= last + ms(d.idle)
    }
}

/// Starts watching `conn` with `d`; the returned handle is updated by the connection's handler.
pub(crate) fn watch(conn: &Arc<ConnInner>, d: Deadlines) -> Arc<Watch> {
    let w = Arc::new(Watch {
        start: Instant::now(),
        last: AtomicU64::new(0),
        partial: AtomicU64::new(0),
        ready: AtomicBool::new(false),
        exempt: AtomicBool::new(false),
    });
    if !(d.handshake.is_zero() && d.idle.is_zero() && d.message.is_zero()) {
        arm(Arc::downgrade(conn), Arc::downgrade(&w), d);
    }
    w
}

/// The check period: a quarter of the shortest active deadline (deadlines fire up to 25 %
/// late), at least 10 ms.
fn period(w: &Watch, d: &Deadlines) -> Duration {
    let mut p = d.idle;
    for t in [
        d.message,
        if w.ready.load(Ordering::Relaxed) {
            Duration::ZERO
        } else {
            d.handshake
        },
    ] {
        if !t.is_zero() && (p.is_zero() || t < p) {
            p = t;
        }
    }
    (p / 4).max(Duration::from_millis(10))
}

fn arm(conn: Weak<ConnInner>, w: Weak<Watch>, d: Deadlines) {
    let Some(ws) = w.upgrade() else { return };
    let every = period(&ws, &d);
    drop(ws);
    crate::timer::after(every, move || {
        let (Some(c), Some(ws)) = (conn.upgrade(), w.upgrade()) else {
            return;
        };
        if !c.is_open() {
            return;
        }
        if ws.expired(&d) {
            c.close();
            return;
        }
        drop((c, ws));
        arm(conn, w, d);
    });
}
