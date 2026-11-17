//! ICE-TCP (RFC 6544) for an [`Endpoint`](crate::Endpoint): a passive TCP candidate on a
//! listening socket of its own.
//!
//! A dedicated thread accepts connections (blocking `accept`, never an I/O thread) and hands
//! them to the engine ([`only::Engine::adopt_tcp`]). Each connection carries RFC 4571 frames;
//! its first frame must be a connectivity check naming one of the endpoint's peers by ufrag,
//! within [`FIRST_CHECK_TIMEOUT`], and from then on its frames go to that peer as datagrams
//! from the connection's remote address to the candidate's address. What the peer sends from
//! the candidate's address to that remote address goes back framed on the connection.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use only::{Acceptor, Conn, Engine, Handler};
use only_ice::tcp::{FrameReader, frame};
use only_turn::stun;

use crate::{Hub, lock, timer};

/// Connections accepted at once (more are refused at accept).
pub(crate) const MAX_CONNS: usize = 256;
/// A connection whose first check has not arrived this long after it was accepted is closed.
pub(crate) const FIRST_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
/// Datagrams for a connection with more than this queued are dropped (they keep datagram
/// semantics: DTLS, SCTP and RTP recover).
const MAX_QUEUED: usize = 1 << 20;

/// Connections by remote address, and the peer each was identified as.
type Conns = HashMap<SocketAddr, (Conn<IceTcp>, Option<u64>)>;

/// The TCP side of an endpoint.
pub(crate) struct TcpSide {
    /// The candidate's address (what peers send from and what arrives "on").
    pub(crate) local: SocketAddr,
    /// The address the listener is bound to (to wake its thread on close).
    bound: SocketAddr,
    conns: Mutex<Conns>,
    stop: AtomicBool,
}

impl TcpSide {
    /// Starts listening on `listener`; `local` is the address advertised in the candidate.
    pub(crate) fn start(
        hub: &Arc<Hub>,
        engine: &Arc<Engine>,
        listener: TcpListener,
        local: SocketAddr,
    ) -> io::Result<Arc<TcpSide>> {
        let bound = listener.local_addr()?;
        let side = Arc::new(TcpSide {
            local,
            bound,
            conns: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
        });
        let (hub, engine, me) = (
            Arc::downgrade(hub),
            Arc::downgrade(engine),
            Arc::downgrade(&side),
        );
        std::thread::Builder::new()
            .name("only-webrtc-ice-tcp".into())
            .spawn(move || accept_loop(&listener, &hub, &engine, &me))?;
        Ok(side)
    }

    /// Sends a datagram to the connection from `dest`.
    pub(crate) fn send(&self, dest: SocketAddr, data: &[u8]) {
        let c = lock(&self.conns).get(&dest).map(|(c, _)| c.clone());
        let (Some(c), Some(f)) = (c, frame(data)) else {
            return;
        };
        if c.queued_bytes() > MAX_QUEUED {
            return;
        }
        let _ = c.send_owned(f);
    }

    /// Closes the connections of peer `id`.
    pub(crate) fn close_peer(&self, id: u64) {
        let conns: Vec<Conn<IceTcp>> = lock(&self.conns)
            .values()
            .filter(|(_, p)| *p == Some(id))
            .map(|(c, _)| c.clone())
            .collect();
        for c in conns {
            c.close();
        }
    }

    /// Stops accepting and closes every connection.
    pub(crate) fn close(&self) {
        self.stop.store(true, Ordering::Release);
        let mut wake = self.bound;
        if wake.ip().is_unspecified() {
            wake.set_ip(if wake.is_ipv4() {
                std::net::Ipv4Addr::LOCALHOST.into()
            } else {
                std::net::Ipv6Addr::LOCALHOST.into()
            });
        }
        let _ = TcpStream::connect_timeout(&wake, Duration::from_millis(200));
        let conns: Vec<Conn<IceTcp>> = lock(&self.conns).values().map(|(c, _)| c.clone()).collect();
        for c in conns {
            c.close();
        }
    }
}

fn accept_loop(
    listener: &TcpListener,
    hub: &Weak<Hub>,
    engine: &Weak<Engine>,
    side: &Weak<TcpSide>,
) {
    loop {
        let Ok((s, _)) = listener.accept() else {
            std::thread::sleep(Duration::from_millis(50)); // EMFILE and the like
            continue;
        };
        let (Some(side), Some(engine)) = (side.upgrade(), engine.upgrade()) else {
            return;
        };
        if side.stop.load(Ordering::Acquire) {
            return;
        }
        if lock(&side.conns).len() >= MAX_CONNS {
            continue; // dropped: refused
        }
        let _ = s.set_nodelay(true);
        engine.adopt_tcp(
            s,
            TcpAcceptor {
                hub: hub.clone(),
                side: Arc::downgrade(&side),
            },
            |_| {},
        );
    }
}

struct TcpAcceptor {
    hub: Weak<Hub>,
    side: Weak<TcpSide>,
}

impl Acceptor for TcpAcceptor {
    type Handler = IceTcp;
    fn on_open(&self, c: &Conn<IceTcp>) -> IceTcp {
        let guard = Arc::new(Guard {
            side: self.side.clone(),
            conn: c.clone(),
        });
        if let Some(side) = self.side.upgrade() {
            let old = lock(&side.conns).insert(c.peer_addr(), (c.clone(), None));
            if let Some((old, _)) = old {
                old.close();
            }
            let target: Weak<dyn timer::Due> = Arc::downgrade(&guard) as Weak<dyn timer::Due>;
            timer::timer().schedule(Instant::now() + FIRST_CHECK_TIMEOUT, target);
        } else {
            c.close();
        }
        IceTcp {
            hub: self.hub.clone(),
            side: self.side.clone(),
            reader: FrameReader::new(),
            peer: None,
            _guard: guard,
        }
    }
}

/// Closes a connection that was not identified in time.
struct Guard {
    side: Weak<TcpSide>,
    conn: Conn<IceTcp>,
}

impl timer::Due for Guard {
    fn fire(&self, _at: Instant) {
        let Some(side) = self.side.upgrade() else {
            return;
        };
        let unknown = lock(&side.conns)
            .get(&self.conn.peer_addr())
            .is_some_and(|(c, p)| c.id() == self.conn.id() && p.is_none());
        if unknown {
            self.conn.close();
        }
    }
}

/// One ICE-TCP connection of an [`Endpoint`](crate::Endpoint).
pub(crate) struct IceTcp {
    hub: Weak<Hub>,
    side: Weak<TcpSide>,
    reader: FrameReader,
    peer: Option<u64>,
    _guard: Arc<Guard>,
}

impl std::fmt::Debug for IceTcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceTcp")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// The peer a connection's first frame names (a Binding request with our ufrag first).
fn identify(hub: &Hub, data: &[u8]) -> Option<u64> {
    if !stun::is_stun(data) {
        return None;
    }
    let m = stun::Message::parse(data).ok()?;
    if m.method() != stun::Method::BINDING || m.class() != stun::Class::Request {
        return None;
    }
    let u = m.get_str(stun::attr::USERNAME)?;
    hub.peer_by_ufrag(u.split(':').next().unwrap_or(""))
}

impl Handler for IceTcp {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (Some(hub), Some(side)) = (self.hub.upgrade(), self.side.upgrade()) else {
            c.close();
            return;
        };
        let source = c.peer_addr();
        let peer = &mut self.peer;
        let mut close = false;
        self.reader.push(data, |f| {
            let id = match *peer {
                Some(id) => id,
                None => match identify(&hub, f) {
                    Some(id) => {
                        *peer = Some(id);
                        if let Some(e) = lock(&side.conns).get_mut(&source) {
                            e.1 = Some(id);
                        }
                        id
                    }
                    None => {
                        close = true;
                        return false;
                    }
                },
            };
            if !hub.input_peer(id, source, side.local, f) {
                close = true;
                return false;
            }
            true
        });
        if close {
            c.close();
        }
    }

    fn on_close(&mut self, c: &Conn<Self>, _err: Option<only::Error>) {
        if let Some(side) = self.side.upgrade() {
            let mut conns = lock(&side.conns);
            if conns
                .get(&c.peer_addr())
                .is_some_and(|(x, _)| x.id() == c.id())
            {
                conns.remove(&c.peer_addr());
            }
        }
    }
}
