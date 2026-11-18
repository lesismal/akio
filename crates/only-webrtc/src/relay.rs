//! TURN allocations of an [`Endpoint`](crate::Endpoint): relayed candidates shared by its peers.
//!
//! One [`Relay`] drives one [`only_turn::client::Client`] over the endpoint's UDP socket: the
//! server's datagrams are read off the socket before peer routing, relayed data comes out
//! as if it had arrived on the relayed address, and whatever a peer sends from the relayed
//! address goes to the client (channels, permissions and refreshes are its business). Its
//! timers run on the shared WebRTC timer thread.

use std::net::SocketAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use only_turn::client::{Client, ClientConfig, ClientEvent, ClientState};

use crate::{Hub, lock, timer};

/// What the waiter of an allocation gets: (relayed, mapped) or why it failed.
pub(crate) type Allocated = Result<(SocketAddr, Option<SocketAddr>), String>;

struct State {
    client: Client,
    armed: Option<Instant>,
    waiter: Option<mpsc::Sender<Allocated>>,
}

pub(crate) struct Relay {
    pub(crate) server: SocketAddr,
    /// Set once allocated: transmits from this address go through the relay.
    pub(crate) relayed: OnceLock<SocketAddr>,
    state: Mutex<State>,
    hub: Weak<Hub>,
    me: Weak<Relay>,
}

impl Relay {
    pub(crate) fn new(
        hub: &Arc<Hub>,
        cfg: ClientConfig,
        waiter: mpsc::Sender<Allocated>,
    ) -> Arc<Relay> {
        Arc::new_cyclic(|me| Relay {
            server: cfg.server,
            relayed: OnceLock::new(),
            state: Mutex::new(State {
                client: Client::new(cfg, Instant::now()),
                armed: None,
                waiter: Some(waiter),
            }),
            hub: Arc::downgrade(hub),
            me: me.clone(),
        })
    }

    /// Whether the allocation is gone (failed or closed).
    pub(crate) fn is_dead(&self) -> bool {
        matches!(
            lock(&self.state).client.state(),
            ClientState::Failed | ClientState::Closed
        )
    }

    /// A datagram from the server: relayed data comes back as (peer, relayed address, data).
    pub(crate) fn input(&self, data: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
        let mut st = lock(&self.state);
        let now = Instant::now();
        let r = st
            .client
            .handle_input(now, data)
            .map(|(p, d)| (p, d.to_vec()));
        self.after(&mut st);
        let relayed = st.client.relayed_addr()?;
        r.map(|(p, d)| (p, relayed, d))
    }

    /// Sends `data` to `peer` through the relay.
    pub(crate) fn send(&self, peer: SocketAddr, data: &[u8]) {
        let mut st = lock(&self.state);
        let _ = st.client.send_to(Instant::now(), peer, data);
        self.after(&mut st);
    }

    /// Sends what is due (the first Allocate) and arms the timer.
    pub(crate) fn send_nothing(&self) {
        let mut st = lock(&self.state);
        self.after(&mut st);
    }

    /// Deletes the allocation (best effort: the request goes out once, the answer is not
    /// awaited).
    pub(crate) fn close(&self) {
        let mut st = lock(&self.state);
        st.client.close(Instant::now());
        self.after(&mut st);
    }

    /// Sends what the client produced, reports its events and arms its timer.
    fn after(&self, st: &mut State) {
        let hub = self.hub.upgrade();
        let binding = hub.as_ref().and_then(|h| h.binding());
        while let Some(m) = st.client.poll_transmit() {
            if let Some(b) = binding {
                let _ = b.send_to(&m, self.server);
            }
        }
        while let Some(e) = st.client.poll_event() {
            match e {
                ClientEvent::Allocated {
                    relayed, mapped, ..
                } => {
                    let _ = self.relayed.set(relayed);
                    if let Some(w) = st.waiter.take() {
                        let _ = w.send(Ok((relayed, mapped)));
                    }
                }
                ClientEvent::Failed(e) => {
                    only_log::debug!(target: "only_webrtc", "turn {}: {e}", self.server);
                    if let Some(w) = st.waiter.take() {
                        let _ = w.send(Err(e.to_string()));
                    }
                }
                ClientEvent::PeerFailed(p, e) => {
                    only_log::debug!(target: "only_webrtc", "turn {}: peer {p}: {e}", self.server);
                }
                _ => {}
            }
        }
        if let Some(t) = st.client.poll_timeout() {
            if st.armed.is_none_or(|a| t < a) {
                st.armed = Some(t);
                let target: Weak<dyn timer::Due> = self.me.clone();
                timer::timer().schedule(t, target);
            }
        }
    }
}

impl timer::Due for Relay {
    fn fire(&self, at: Instant) {
        let mut st = lock(&self.state);
        if st.armed != Some(at) {
            return;
        }
        st.armed = None;
        st.client.handle_timeout(Instant::now());
        self.after(&mut st);
    }
}
