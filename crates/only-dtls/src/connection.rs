//! [`Connection`]: the public sans-io connection, running the DTLS 1.2 or the DTLS 1.3 state
//! machine and switching to DTLS 1.2 when the peer turns out to speak only that.

use std::sync::Arc;
use std::time::Instant;

use crate::conn::{Conn12, Event, HandshakeInfo, Role};
use crate::conn13::Conn13;
use crate::{Config, Error, Session, Version};

/// A DTLS connection: a sans-io state machine. Feed it datagrams
/// ([`handle_datagram`](Connection::handle_datagram)) and timer expiries
/// ([`handle_timeout`](Connection::handle_timeout) at [`poll_timeout`](Connection::poll_timeout));
/// send what [`poll_transmit`](Connection::poll_transmit) returns and act on
/// [`poll_event`](Connection::poll_event).
///
/// The versions come from [`Config::with_versions`]: with DTLS 1.3 enabled the connection
/// starts as DTLS 1.3 (a client's ClientHello also offers DTLS 1.2 when that is enabled too)
/// and continues as DTLS 1.2 when the peer only speaks DTLS 1.2.
#[derive(Debug)]
pub struct Connection {
    inner: Inner,
}

#[derive(Debug)]
enum Inner {
    V12(Box<Conn12>),
    V13(Box<Conn13>),
}

impl Connection {
    /// A client connection; its first flight (the ClientHello) is ready in
    /// [`poll_transmit`](Connection::poll_transmit).
    pub fn client(config: Arc<Config>, now: Instant) -> Result<Connection, Error> {
        Connection::start_client(config, now, None)
    }

    /// A client connection that offers to resume `session` (from
    /// [`Event::NewSession`]); the server may decline and run a full handshake. A DTLS 1.2
    /// session is offered in a DTLS 1.2 ClientHello, a DTLS 1.3 one as a PSK.
    pub fn client_resume(
        config: Arc<Config>,
        now: Instant,
        session: &Session,
    ) -> Result<Connection, Error> {
        Connection::start_client(config, now, Some(session.clone()))
    }

    fn start_client(
        config: Arc<Config>,
        now: Instant,
        session: Option<Session>,
    ) -> Result<Connection, Error> {
        check_versions(&config)?;
        let v13 = config.versions.contains(&Version::Dtls13);
        let v12 = config.versions.contains(&Version::Dtls12);
        let session_v12 = session
            .as_ref()
            .is_some_and(|s| s.version() == Version::Dtls12);
        let inner = if v13 && !(session_v12 && v12) {
            Inner::V13(Box::new(Conn13::client(config, now, session)?))
        } else {
            Inner::V12(Box::new(Conn12::client(config, now, session)?))
        };
        Ok(Connection { inner })
    }

    /// A server connection for the peer at `peer` (any stable encoding of its transport
    /// address; it is bound into HelloVerifyRequest / HelloRetryRequest cookies). It waits for
    /// a ClientHello.
    pub fn server(config: Arc<Config>, now: Instant, peer: &[u8]) -> Result<Connection, Error> {
        check_versions(&config)?;
        let inner = if config.versions.contains(&Version::Dtls13) {
            Inner::V13(Box::new(Conn13::new(config, Role::Server, now, peer)?))
        } else {
            Inner::V12(Box::new(Conn12::new(config, Role::Server, now, peer)?))
        };
        Ok(Connection { inner })
    }

    /// A connection for `role` (WebRTC decides the role from `a=setup`).
    pub fn new(
        config: Arc<Config>,
        role: Role,
        now: Instant,
        peer: &[u8],
    ) -> Result<Connection, Error> {
        match role {
            Role::Client => Connection::client(config, now),
            Role::Server => Connection::server(config, now, peer),
        }
    }

    /// This endpoint's role.
    #[must_use]
    pub fn role(&self) -> Role {
        match &self.inner {
            Inner::V12(c) => c.role(),
            Inner::V13(c) => c.role(),
        }
    }

    /// The protocol version: DTLS 1.3 until a DTLS 1.2 peer shows up when both are enabled;
    /// final once connected.
    #[must_use]
    pub fn version(&self) -> Version {
        match &self.inner {
            Inner::V12(_) => Version::Dtls12,
            Inner::V13(_) => Version::Dtls13,
        }
    }

    /// Whether the handshake completed and the connection is open.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        match &self.inner {
            Inner::V12(c) => c.is_connected(),
            Inner::V13(c) => c.is_connected(),
        }
    }

    /// Whether the connection is closed or failed (nothing more will be sent or received).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        match &self.inner {
            Inner::V12(c) => c.is_closed(),
            Inner::V13(c) => c.is_closed(),
        }
    }

    /// What the handshake established, once connected.
    #[must_use]
    pub fn handshake_info(&self) -> Option<&HandshakeInfo> {
        match &self.inner {
            Inner::V12(c) => c.handshake_info(),
            Inner::V13(c) => c.handshake_info(),
        }
    }

    /// The connection ID this endpoint asked the peer to use (route datagrams carrying it
    /// here); `None` without [`Config::with_connection_id`] or when the peer did not negotiate
    /// CIDs.
    #[must_use]
    pub fn local_connection_id(&self) -> Option<&[u8]> {
        match &self.inner {
            Inner::V12(c) => c.local_cid(),
            Inner::V13(c) => c.local_cid(),
        }
    }

    /// The next datagram to send.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        match &mut self.inner {
            Inner::V12(c) => c.poll_transmit(),
            Inner::V13(c) => c.poll_transmit(),
        }
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<Event> {
        match &mut self.inner {
            Inner::V12(c) => c.poll_event(),
            Inner::V13(c) => c.poll_event(),
        }
    }

    /// When [`handle_timeout`](Connection::handle_timeout) must be called next
    /// (retransmission, delayed ACK or handshake deadline); `None` when nothing is pending.
    /// DTLS 1.3 connections can have timers after the handshake (the final flight until it is
    /// acknowledged, NewSessionTicket and KeyUpdate).
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        match &self.inner {
            Inner::V12(c) => c.poll_timeout(),
            Inner::V13(c) => c.poll_timeout(),
        }
    }

    /// Advances the timers: retransmits the current flight with exponential backoff
    /// (RFC 6347 §4.2.4, RFC 9147 §5.8; DTLS 1.3 resends only what was not acknowledged),
    /// sends delayed ACKs and fails the handshake with [`Error::Timeout`] at its deadline.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<(), Error> {
        match &mut self.inner {
            Inner::V12(c) => c.handle_timeout(now),
            Inner::V13(c) => c.handle_timeout(now),
        }
    }

    /// Processes one received datagram. A fatal error sends the matching alert (in
    /// [`poll_transmit`](Connection::poll_transmit)) and closes the connection. Records that do
    /// not authenticate, replays and stray retransmissions are dropped silently.
    pub fn handle_datagram(&mut self, now: Instant, datagram: &[u8]) -> Result<(), Error> {
        match &mut self.inner {
            Inner::V12(c) => c.handle_datagram(now, datagram),
            Inner::V13(c) => {
                c.handle_datagram(now, datagram)?;
                if !c.wants_downgrade() {
                    return Ok(());
                }
                // The peer speaks only DTLS 1.2: continue with what was sent and received so
                // far, and feed the datagram that showed it again.
                let mut c12 = Conn12::from_handoff(c.take_handoff(), now)?;
                let r = c12.handle_datagram(now, datagram);
                self.inner = Inner::V12(Box::new(c12));
                r
            }
        }
    }

    /// Sends one record of application data (at most 16384 bytes; it goes out as one
    /// datagram).
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        match &mut self.inner {
            Inner::V12(c) => c.send_application_data(data),
            Inner::V13(c) => c.send_application_data(data),
        }
    }

    /// DTLS 1.3: updates the sending keys with a KeyUpdate (RFC 9147 §8), asking the peer to
    /// update its own when `request_peer`; the new keys are used once the peer acknowledged
    /// it. Connections also update on their own before a key reaches its usage limit. Fails
    /// with [`Error::Config`] on a DTLS 1.2 connection.
    pub fn update_keys(&mut self, request_peer: bool) -> Result<(), Error> {
        match &mut self.inner {
            Inner::V12(_) => Err(Error::Config("KeyUpdate needs DTLS 1.3")),
            Inner::V13(c) => c.update_keys(request_peer),
        }
    }

    /// Keying material from the exporter (`label`, optional `context`): RFC 5705 in DTLS 1.2,
    /// RFC 8446 §7.5 in DTLS 1.3 (where no context and an empty one are the same), e.g.
    /// `EXTRACTOR-dtls_srtp` for DTLS-SRTP. Only after the handshake completed.
    pub fn export_keying_material(
        &self,
        label: &str,
        context: Option<&[u8]>,
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        match &self.inner {
            Inner::V12(c) => c.export_keying_material(label, context, len),
            Inner::V13(c) => c.export_keying_material(label, context, len),
        }
    }

    /// Sends close_notify and closes the connection.
    pub fn close(&mut self) {
        match &mut self.inner {
            Inner::V12(c) => c.close(),
            Inner::V13(c) => c.close(),
        }
    }
}

fn check_versions(config: &Config) -> Result<(), Error> {
    if config.versions.is_empty() {
        return Err(Error::Config("no protocol versions"));
    }
    Ok(())
}
