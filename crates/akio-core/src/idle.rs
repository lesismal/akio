//! A connection's own idle timeout (ADR-155, akit A78): what the backends' idle timers follow
//! for a connection that set one with [`Conn::set_idle_timeout`](crate::Conn::set_idle_timeout)
//! or [`Conn::set_idle_counts_writes`](crate::Conn::set_idle_counts_writes). Backend-facing.
//!
//! A connection that never sets one has [`IdleRule::ENGINE`], which behaves exactly as the
//! engine's idle timer always did: the loops read the connection's settings only when the
//! connection asks them to ([`LoopLink::retime_conn`](crate::LoopLink::retime_conn)), so the
//! I/O path pays nothing for the feature.

use crate::ConnInner;

/// `ConnInner::idle_ms`: the engine's idle timeout applies.
pub(crate) const IDLE_ENGINE: u64 = u64::MAX;
/// The longest timeout kept (about 142 000 years): tick arithmetic never overflows.
pub(crate) const IDLE_MAX: u64 = 1 << 52;
/// `IdleRule::own` bit: outbound data counts as activity.
const WRITES: u64 = 1 << 63;

/// How one connection's idle timer runs, as its loop keeps it. Backend-facing.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdleRule {
    /// `IDLE_ENGINE`, 0 (no idle timeout) or milliseconds, with the `WRITES` bit.
    own: u64,
    /// With `WRITES`: the bytes the connection had sent at the last check.
    mark: u64,
}

impl Default for IdleRule {
    fn default() -> IdleRule {
        IdleRule::ENGINE
    }
}

/// What an idle check found ([`IdleRule::check`]).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdleCheck {
    /// No idle timeout applies: the timer is dropped.
    Off,
    /// Idle for the whole timeout: close the connection.
    Expired,
    /// Check again at this tick.
    At(u64),
}

/// How often a connection counting its writes is checked: an eighth of its timeout, so one
/// that only sends is closed at most that much after the timeout.
fn step(timeout: u64) -> u64 {
    (timeout / 8).max(1)
}

impl IdleRule {
    /// The engine's idle timeout, counting inbound data only (every connection's start).
    pub const ENGINE: IdleRule = IdleRule {
        own: IDLE_ENGINE & !WRITES,
        mark: 0,
    };

    /// The connection's settings, read by its loop after
    /// [`retime_conn`](crate::LoopLink::retime_conn). Counting writes starts from the bytes
    /// sent so far.
    pub fn of(inner: &ConnInner) -> IdleRule {
        let (ms, writes) = inner.idle_setting();
        let own = match ms {
            IDLE_ENGINE => IDLE_ENGINE & !WRITES,
            ms => ms.min(IDLE_MAX),
        };
        IdleRule {
            own: if writes { own | WRITES } else { own },
            mark: if writes { inner.bytes_sent() } else { 0 },
        }
    }

    /// The engine's rule (no setting of the connection's own).
    pub fn is_engine(&self) -> bool {
        *self == IdleRule::ENGINE
    }

    fn writes(&self) -> bool {
        self.own & WRITES != 0
    }

    /// The timeout in milliseconds, given the engine's (`engine`, 0: none); 0 for none.
    pub fn timeout(&self, engine: u64) -> u64 {
        match self.own & !WRITES {
            ms if ms == IDLE_ENGINE & !WRITES => engine,
            ms => ms,
        }
    }

    /// When to check first, (re)arming at `now` a connection last active at `last`; `None`:
    /// no timer.
    pub fn first_check(&self, engine: u64, last: u64, now: u64) -> Option<u64> {
        let t = self.timeout(engine);
        if t == 0 {
            return None;
        }
        let at = last.saturating_add(t);
        Some(if self.writes() {
            at.min(now.saturating_add(step(t)))
        } else {
            at
        })
    }

    /// A check is due at `now` for a connection last active at `*last`. Counting writes, data
    /// sent since the last check moves `*last` to `now` (never earlier than the truth: a
    /// connection is never closed early).
    pub fn check(&mut self, engine: u64, last: &mut u64, now: u64, inner: &ConnInner) -> IdleCheck {
        let t = self.timeout(engine);
        if t == 0 {
            return IdleCheck::Off;
        }
        let writes = self.writes();
        if writes {
            let sent = inner.bytes_sent();
            if sent != self.mark {
                self.mark = sent;
                *last = (*last).max(now);
            }
        }
        let at = last.saturating_add(t);
        if at <= now {
            IdleCheck::Expired
        } else if writes {
            IdleCheck::At(at.min(now.saturating_add(step(t))))
        } else {
            IdleCheck::At(at)
        }
    }
}
