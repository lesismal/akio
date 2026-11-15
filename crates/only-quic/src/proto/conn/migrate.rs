//! Client-initiated (active) migration, RFC 9000 sections 9.2 to 9.6: probing a new path (a
//! new local socket, or the server's preferred address) with PATH_CHALLENGE under a connection
//! ID not used before, moving to it once the server answers, and staying on the old path when
//! it does not.

use std::net::SocketAddr;
use std::time::Instant;

use super::super::crypto::TAG_LEN;
use super::super::frame::ty;
use super::super::packet::{MIN_INITIAL_SIZE, PacketBuilder, pn_len};
use super::super::recovery::Rtt;
use super::*;

/// Why a migration cannot start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MigrateError {
    /// Only a client migrates.
    NotClient,
    /// The connection is closed.
    Closed,
    /// A migration is already under way.
    InProgress,
    /// The server disabled active migration (disable_active_migration).
    Disabled,
}

impl std::fmt::Display for MigrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MigrateError::NotClient => "only a client can migrate",
            MigrateError::Closed => "connection closed",
            MigrateError::InProgress => "a migration is already in progress",
            MigrateError::Disabled => "the server disabled active migration",
        })
    }
}

/// A path being probed before the connection moves to it.
#[derive(Clone, Debug)]
pub(crate) struct Probe {
    /// The server address on the new path (the current one, or the preferred address).
    pub remote: SocketAddr,
    /// The remote connection ID reserved for it, once one is available.
    pub cid_seq: Option<u64>,
    challenge: [u8; 8],
    /// A PATH_CHALLENGE is due.
    send: bool,
    started: Option<Instant>,
    /// When the challenge is sent again.
    resend: Option<Instant>,
}

impl Connection {
    /// The server's preferred address in the family of the current path, if it offered one
    /// and the connection does not use it yet.
    pub fn preferred_address(&self) -> Option<SocketAddr> {
        let pa = self.peer.preferred_address.as_ref()?;
        let a = match self.path.remote {
            SocketAddr::V4(_) => pa.v4.map(SocketAddr::V4),
            SocketAddr::V6(_) => pa.v6.map(SocketAddr::V6),
        }?;
        (a != self.path.remote && !self.on_preferred).then_some(a)
    }

    /// Starts moving this client connection to a new path: to the server's preferred address
    /// if it offered one not used yet, else to the same server address from a new local socket.
    /// Returns the server address of the new path; the I/O layer sends the transmits marked
    /// `probe` over the new socket until [`EndpointEvent::Migrated`] (switch to it) or
    /// [`EndpointEvent::MigrationFailed`] (close it). The probe starts once the handshake is
    /// confirmed and the server provided a spare connection ID.
    pub fn migrate(&mut self, now: Instant) -> Result<SocketAddr, MigrateError> {
        if self.side != Side::Client {
            return Err(MigrateError::NotClient);
        }
        if self.is_closed() {
            return Err(MigrateError::Closed);
        }
        if self.probe.is_some() {
            return Err(MigrateError::InProgress);
        }
        let preferred = self.preferred_address();
        // disable_active_migration does not cover the preferred address (RFC 9000 18.2).
        if preferred.is_none() && self.params_done && self.peer.disable_active_migration {
            return Err(MigrateError::Disabled);
        }
        let mut challenge = [0u8; 8];
        self.rng.fill(&mut challenge);
        let remote = preferred.unwrap_or(self.path.remote);
        self.probe = Some(Probe {
            remote,
            cid_seq: None,
            challenge,
            send: false,
            started: None,
            resend: None,
        });
        self.try_start_probe(now);
        Ok(remote)
    }

    /// Starts the requested probe once the handshake is confirmed and a connection ID not
    /// used before is available (for the preferred address: the one it came with).
    pub(super) fn try_start_probe(&mut self, now: Instant) {
        if !self.confirmed {
            return;
        }
        let Some((remote, started)) = self.probe.as_ref().map(|p| (p.remote, p.cid_seq.is_some()))
        else {
            return;
        };
        if started {
            return;
        }
        let preferred = self.preferred_address();
        let seq = if preferred == Some(remote) {
            self.remote_cids.contains_key(&1).then_some(1)
        } else {
            self.remote_cids
                .range(self.remote_seq + 1..)
                .map(|(s, _)| *s)
                .find(|&s| s != 1 || self.peer.preferred_address.is_none())
        };
        let Some(seq) = seq.filter(|&s| s != self.remote_seq) else {
            return;
        };
        let pto = self.rtt.pto_base();
        if let Some(p) = self.probe.as_mut() {
            p.cid_seq = Some(seq);
            p.send = true;
            p.started = Some(now);
            p.resend = Some(now + pto * 2);
        }
    }

    /// The probe's PATH_CHALLENGE, alone in a 1200-byte datagram on the new path.
    pub(super) fn write_probe(&mut self, now: Instant) -> Option<Transmit> {
        let p = self.probe.as_ref()?;
        if !p.send {
            return None;
        }
        let (remote, challenge) = (p.remote, p.challenge);
        let dcid = self.remote_cids.get(&p.cid_seq?)?.cid;
        let k = self.one_rtt.as_ref()?;
        let sp = &self.spaces[2];
        let pn = sp.next_pn;
        let pnl = pn_len(pn, sp.largest_acked);
        let mut buf = Vec::with_capacity(MIN_INITIAL_SIZE);
        let b = PacketBuilder::short(&mut buf, &dcid, k.phase, pn, pnl);
        buf.push(ty::PATH_CHALLENGE as u8);
        buf.extend_from_slice(&challenge);
        buf.resize(MIN_INITIAL_SIZE - TAG_LEN, 0);
        b.finish(&mut buf, &k.local, &k.local_hp);
        let size = buf.len() as u16;
        let dlv = self.dlv;
        let sp = &mut self.spaces[2];
        sp.next_pn += 1;
        sp.sent.insert(
            pn,
            Sent {
                time: now,
                size,
                ack_eliciting: true,
                in_flight: false,
                mtu_probe: false,
                ecn: false,
                delivered: dlv.delivered,
                delivered_age: age_us(now, dlv.delivered_time),
                first_sent_age: age_us(now, dlv.first_sent),
                app_limited: true,
                frames: Vec::new(),
            },
        );
        if let Some(p) = self.probe.as_mut() {
            p.send = false;
        }
        self.stats.sent_packets += 1;
        self.stats.udp_tx.datagrams += 1;
        self.stats.udp_tx.bytes += buf.len() as u64;
        self.stats.udp_tx.ios += 1;
        Some(Transmit {
            dest: remote,
            segment_size: None,
            data: buf,
            ecn: 0,
            probe: true,
        })
    }

    /// A PATH_RESPONSE: if it answers the probe, the connection moves to the new path.
    pub(super) fn on_probe_response(&mut self, now: Instant, data: [u8; 8]) -> bool {
        let Some(p) = self.probe.as_ref() else {
            return false;
        };
        if p.challenge != data || p.cid_seq.is_none() {
            return false;
        }
        let Some(p) = self.probe.take() else {
            return false;
        };
        let Some(seq) = p.cid_seq else {
            return false;
        };
        // The connection ID of the old path is not used again.
        let old = self.remote_seq;
        self.remote_seq = seq;
        if self.remote_cids.remove(&old).is_some() {
            self.pending.retire_cids.push(old);
        }
        if self.preferred_address() == Some(p.remote) {
            self.on_preferred = true;
        }
        let remote_changed = p.remote != self.path.remote;
        self.path = Path::new(p.remote, true);
        self.prev_path = None;
        // A new path: its congestion state and ECN validation start over (RFC 9000 9.4), and
        // so does its RTT estimate when the server address changed.
        self.cc.reset();
        if remote_changed {
            self.rtt = Rtt::new(self.cfg.transport.initial_rtt);
        }
        self.ecn.new_path(self.cfg.ecn());
        self.pacer = Pacer::new();
        if self.mtu_upper > self.mtu {
            self.mtu_probe = Some((self.next_probe_size(), 0));
        }
        self.reset_idle(now);
        self.ep_events
            .push_back(EndpointEvent::Migrated { remote: p.remote });
        true
    }

    /// The probe's timer: resend the challenge, or give up after three probe timeouts.
    pub(super) fn on_probe_timer(&mut self, now: Instant) {
        let pto = self.rtt.pto_base();
        let Some(p) = self.probe.as_mut() else {
            return;
        };
        let (Some(started), Some(resend)) = (p.started, p.resend) else {
            return;
        };
        if now < resend {
            return;
        }
        if now < started + pto * 3 * 3 {
            p.send = true;
            p.resend = Some(now + pto * 2);
            return;
        }
        let seq = p.cid_seq;
        self.probe = None;
        // The connection ID was used on that path: retire it.
        if let Some(s) = seq {
            if self.remote_cids.remove(&s).is_some() {
                self.pending.retire_cids.push(s);
            }
        }
        self.ep_events.push_back(EndpointEvent::MigrationFailed);
    }

    /// When the probe needs attention.
    pub(super) fn probe_timeout(&self) -> Option<Instant> {
        self.probe.as_ref().and_then(|p| p.resend)
    }

    /// Whether `from` is the server address of the path being probed.
    pub(super) fn probing_from(&self, from: SocketAddr) -> bool {
        self.probe.as_ref().is_some_and(|p| p.remote == from)
    }
}
