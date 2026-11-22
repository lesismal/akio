//! Client pools: several connections to one server, with calls spread over those that are up.

use std::{
    cell::Cell,
    io,
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use akio::Engine;

use crate::{
    CallFuture, CallResult, Peer, PeerInner, Routes, Values, deadline::Timer, now_ms, start_dial,
};

/// How a [`Pool`] picks the connection of a call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Balance {
    /// Each connection in turn (as Go's `ClientPool.Next`), skipping those that are down.
    #[default]
    RoundRobin,
    /// The connection with the fewest calls waiting for their answer; ties go in turn.
    LeastPending,
}

/// Builds a [`Pool`]; see [`Pool::builder`].
#[derive(Clone, Debug)]
pub struct PoolBuilder {
    size: usize,
    balance: Balance,
    heartbeat: Option<Duration>,
    reconnect: Duration,
    connect_timeout: Duration,
}

impl PoolBuilder {
    /// Number of connections (default 4, at least 1).
    #[must_use]
    pub fn size(mut self, n: usize) -> PoolBuilder {
        self.size = n.max(1);
        self
    }

    /// How calls pick their connection (default [`Balance::RoundRobin`]).
    #[must_use]
    pub fn balance(mut self, b: Balance) -> PoolBuilder {
        self.balance = b;
        self
    }

    /// Pings each connection every `interval` and closes it (it then reconnects) when a ping
    /// got no answer (nothing at all received) within an interval, so a connection to a peer that went silent is
    /// replaced instead of collecting calls that time out. Default 15 s; `None` turns it off.
    #[must_use]
    pub fn heartbeat(mut self, interval: Option<Duration>) -> PoolBuilder {
        self.heartbeat = interval.filter(|d| !d.is_zero());
        self
    }

    /// Wait between reconnection attempts of a lost connection (default 1 s).
    #[must_use]
    pub fn reconnect_interval(mut self, d: Duration) -> PoolBuilder {
        self.reconnect = d.max(Duration::from_millis(1));
        self
    }

    /// How long [`dial`](Self::dial) waits for every connection to come up (default 10 s).
    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> PoolBuilder {
        self.connect_timeout = d;
        self
    }

    /// Connects every connection of the pool to `addr`, with `routes` (shared, as a Go
    /// `ClientPool` shares one handler). Blocks until all are up; if one fails or the
    /// timeout passes, those connected are closed and the error is returned. Connections
    /// lost later reconnect on their own until [`Pool::close`].
    pub fn dial(
        self,
        engine: &Arc<Engine>,
        addr: SocketAddr,
        routes: Arc<Routes>,
    ) -> io::Result<Pool> {
        let pending: Vec<_> = (0..self.size)
            .map(|_| start_dial(engine, addr, routes.clone(), self.reconnect, self.heartbeat))
            .collect();
        let until = Instant::now() + self.connect_timeout;
        let mut peers = Vec::with_capacity(self.size);
        let mut err = None;
        for rx in pending {
            let left = until.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left) {
                Ok(Ok(p)) => peers.push(p),
                Ok(Err(e)) => err = err.or(Some(e)),
                Err(_) => {
                    err = err.or_else(|| {
                        Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "arpc pool dial timed out",
                        ))
                    });
                }
            }
        }
        if let Some(e) = err {
            for p in &peers {
                p.close();
            }
            return Err(e);
        }
        if let Some(every) = self.heartbeat {
            for p in &peers {
                schedule_heartbeat(Arc::downgrade(&p.0), every);
            }
        }
        Ok(Pool {
            peers: peers.into(),
            balance: self.balance,
        })
    }
}

/// Pings the connection every `every` and closes it once a ping got nothing back within an
/// interval; stops with the peer.
fn schedule_heartbeat(weak: Weak<PeerInner>, every: Duration) {
    Timer::at(Instant::now() + every, move || {
        let Some(inner) = weak.upgrade() else {
            return;
        };
        if inner.stopped.load(Ordering::Acquire) {
            return;
        }
        let peer = Peer(inner);
        if peer.0.connected.load(Ordering::Acquire) {
            // Judged by the last ping, not the clock, so a late timer is not taken for silence:
            // closed only when a ping got nothing back for a whole interval.
            let now = now_ms();
            let ping = peer.0.last_ping.load(Ordering::Relaxed);
            let rx = peer.0.last_rx.load(Ordering::Relaxed);
            if ping != 0 && rx < ping && u128::from(now - ping) >= every.as_millis() {
                if let Some(c) = peer.conn() {
                    c.close();
                }
            } else {
                peer.0.last_ping.store(now.max(1), Ordering::Relaxed);
                peer.ping();
            }
        }
        schedule_heartbeat(weak, every);
    });
}

/// Several client connections to one server (Go: `ClientPool`). Calls go to a connection that
/// is up, picked by the pool's [`Balance`]; lost connections reconnect on their own, and each
/// keeps its own bound on pending calls ([`Routes::max_pending_calls`]) and its calls their
/// deadlines ([`Routes::call_timeout`]). Cheap to clone.
#[derive(Clone, Debug)]
pub struct Pool {
    peers: Arc<[Peer]>,
    balance: Balance,
}

thread_local! {
    /// Where this thread's next pick starts: per thread, so picking shares no counter.
    static CURSOR: Cell<usize> = Cell::new({
        static SEED: AtomicUsize = AtomicUsize::new(0);
        SEED.fetch_add(0x9e37_79b9, Ordering::Relaxed)
    });
}

impl Pool {
    /// A builder: 4 connections, round robin, a 15 s heartbeat, reconnecting every second.
    pub fn builder() -> PoolBuilder {
        PoolBuilder {
            size: 4,
            balance: Balance::RoundRobin,
            heartbeat: Some(Duration::from_secs(15)),
            reconnect: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// The connections.
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    /// Connections that are up.
    pub fn connected(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| p.0.connected.load(Ordering::Acquire))
            .count()
    }

    /// The connection the next call goes to: one that is up, picked by the pool's
    /// [`Balance`], or, when none is, any (whose calls then fail with
    /// [`CallError::Closed`](crate::CallError::Closed) at once).
    pub fn peer(&self) -> &Peer {
        let n = self.peers.len();
        let start = CURSOR.with(|c| {
            let v = c.get();
            c.set(v.wrapping_add(1));
            v
        });
        let up = |p: &Peer| p.0.connected.load(Ordering::Acquire);
        let mut best: Option<(&Peer, usize)> = None;
        for i in 0..n {
            let p = &self.peers[start.wrapping_add(i) % n];
            if !up(p) {
                continue;
            }
            match self.balance {
                Balance::RoundRobin => return p,
                Balance::LeastPending => {
                    let load = p.pending_calls();
                    if load == 0 {
                        return p;
                    }
                    if best.is_none_or(|(_, b)| load < b) {
                        best = Some((p, load));
                    }
                }
            }
        }
        best.map_or(&self.peers[start % n], |(p, _)| p)
    }

    /// [`Peer::call`] on a picked connection.
    pub fn call(&self, method: &str, payload: &[u8], timeout: Option<Duration>) -> CallFuture {
        self.peer().call(method, payload, timeout)
    }

    /// [`Peer::call_with`] on a picked connection.
    pub fn call_with(
        &self,
        method: &str,
        payload: &[u8],
        timeout: Option<Duration>,
        values: &Values,
    ) -> CallFuture {
        self.peer().call_with(method, payload, timeout, values)
    }

    /// [`Peer::call_async`] on a picked connection.
    pub fn call_async(
        &self,
        method: &str,
        payload: &[u8],
        timeout: Option<Duration>,
        done: impl FnOnce(CallResult) + Send + 'static,
    ) {
        self.peer().call_async(method, payload, timeout, done);
    }

    /// [`Peer::notify`] on a picked connection.
    pub fn notify(&self, method: &str, payload: &[u8]) -> bool {
        self.peer().notify(method, payload)
    }

    /// Closes every connection (they stop reconnecting).
    pub fn close(&self) {
        for p in self.peers.iter() {
            p.close();
        }
    }
}
