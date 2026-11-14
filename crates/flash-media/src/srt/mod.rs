//! SRT, the Secure Reliable Transport (draft-sharabayko-srt-01), in live mode: MPEG-TS over
//! UDP with losses repaired by retransmission within a fixed latency, as encoders, ffmpeg and
//! OBS speak it.
//!
//! [`Conn`] is the protocol without I/O: feed it datagrams ([`Conn::handle`]) and the time
//! ([`Conn::handle_timeout`] at [`Conn::next_timeout`]), drain [`Conn::take_output`] and
//! [`Conn::poll_event`]. It does:
//!
//! * the version 5 handshake as a caller ([`Conn::caller`]: induction, then conclusion with the
//!   listener's SYN cookie) and, with [`Listener`], as a listener that keeps no state for a
//!   caller until its conclusion proves with the cookie that it owns its address; the
//!   HSREQ/HSRSP extension (TSBPD, too-late drop, periodic NAK, retransmission flag) with the
//!   larger of both latencies; the stream ID extension; rejection codes both ways
//!   ([`RejectReason`]);
//! * acknowledgements (a full ACK every 10 ms, a light ACK every 64 packets, ACKACK and the RTT
//!   measured from them), loss reports (a NAK as soon as a gap appears, again every
//!   `(RTT + 4 * RTTVar) / 2`), retransmission bounded by the send buffer and the peer's flow
//!   window, giving up on packets older than the latency allows (DROPREQ);
//! * timestamp-based packet delivery (TSBPD): each payload is delivered at the sender's
//!   timestamp plus the latency on a time base that follows the least delay seen and a drifting
//!   sender clock; packets still missing when a later one is due are dropped as too late;
//! * keepalives, SHUTDOWN and a peer idle timeout;
//! * encryption: AES-CTR with 128-, 192- or 256-bit keys, wrapped (RFC 3394) with a key that
//!   PBKDF2-HMAC-SHA1 derives from the passphrase; the caller's KMREQ in the conclusion, the
//!   listener's KMRSP, and key refreshes (KMREQ control packets) from the peer.
//!
//! [`SrtServer`] runs on a flash UDP listener (one handler per peer address): the stream ID
//! names the stream, plainly (`app/stream?query`) or in the access control syntax
//! (`#!::r=app/stream,m=publish,u=user`); [`SrtConfig::on_connect`] authorizes. A publisher
//! (`m=publish`) reserves its path during the handshake ([`Hub::reserve`](crate::hub::Hub::reserve),
//! so a second one is rejected with 1409) and is demuxed into the hub; a player (`m=request`,
//! the default) receives the hub stream as MPEG-TS, 7 transport packets per SRT packet,
//! dropped while the peer acknowledges too little. [`dial`], [`push`] and [`pull`] are the
//! caller side.
//!
//! Left out: rendezvous mode, file mode and its congestion control, AES-GCM, packet filters
//! (FEC), socket groups, the HSv4 handshake of SRT before 1.3, and starting a key refresh.

mod conn;
mod crypto;
mod listener;
pub(crate) mod packet;
mod server;

pub use conn::{
    Config, Conn, DEFAULT_LATENCY, Event, MAX_PAYLOAD_SIZE, RejectReason, SrtError, State, Stats,
    TS_PAYLOAD_SIZE,
};
pub use listener::{Listener, Mode, Request, StreamId};
pub use server::{
    ConnectHook, DEFAULT_MAX_SEND_BACKLOG, SrtConfig, SrtHandler, SrtPeer, SrtServer, SrtSession,
    dial, pull, push,
};

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        time::{Duration, Instant},
    };

    use super::*;

    /// A caller and a listener wired back to back through a lossy, delaying link, driven by a
    /// simulated clock.
    struct Sim {
        now: Instant,
        caller: Conn,
        listener: Listener,
        server: Option<Conn>,
        /// (deliver at, to server?, datagram)
        wire: Vec<(Instant, bool, Vec<u8>)>,
        sent: u64,
        seed: u64,
        loss_every: u64,
        delay: Duration,
        got: Vec<Vec<u8>>,
        caller_events: Vec<Event>,
        server_events: Vec<Event>,
        rejected: Option<RejectReason>,
    }

    const ADDR: &str = "10.0.0.1:5000";

    impl Sim {
        fn new(caller_cfg: Config, loss_every: u64) -> Sim {
            let now = Instant::now();
            let caller = Conn::caller(caller_cfg, now).unwrap();
            Sim {
                now,
                caller,
                listener: Listener::new(),
                server: None,
                wire: Vec::new(),
                sent: 0,
                seed: 7,
                loss_every,
                delay: Duration::from_millis(5),
                got: Vec::new(),
                caller_events: Vec::new(),
                server_events: Vec::new(),
                rejected: None,
            }
        }

        fn rng(&mut self) -> u64 {
            self.seed = self
                .seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.seed >> 33
        }

        fn send(&mut self, to_server: bool, d: Vec<u8>) {
            // Drop every `loss_every`th first transmission of a data packet but the last ones
            // (a lost tail has no later packet to reveal it), and a pseudo-random quarter of
            // the retransmissions, so that some losses need a second NAK.
            let data = d[0] & 0x80 == 0;
            if data && self.loss_every > 0 {
                let rexmit = d[4] & 0x04 != 0;
                self.sent += 1;
                if !rexmit && self.sent % self.loss_every == 0 && self.sent < 480 {
                    return;
                }
                if rexmit && self.rng() % 4 == 0 {
                    return;
                }
            }
            self.wire.push((self.now + self.delay, to_server, d));
        }

        fn collect(&mut self, server_cfg: &Config) {
            for d in self.caller.take_output() {
                self.send(true, d);
            }
            while let Some(e) = self.caller.poll_event() {
                self.caller_events.push(e);
            }
            if let Some(s) = self.server.as_mut() {
                let out = s.take_output();
                let mut evs = Vec::new();
                while let Some(e) = s.poll_event() {
                    evs.push(e);
                }
                for d in out {
                    self.send(false, d);
                }
                for e in evs {
                    if let Event::Data(d) = &e {
                        self.got.push(d.clone());
                    }
                    self.server_events.push(e);
                }
            }
            let _ = server_cfg;
        }

        fn step(&mut self, dt: Duration, server_cfg: &Config) {
            self.now += dt;
            let now = self.now;
            let due: Vec<_> = {
                let (due, rest): (Vec<_>, Vec<_>) =
                    self.wire.drain(..).partition(|(at, _, _)| *at <= now);
                self.wire = rest;
                due
            };
            for (_, to_server, d) in due {
                if to_server {
                    if let Some(s) = self.server.as_mut() {
                        s.handle(&d, now);
                    } else {
                        let mut out = Vec::new();
                        let addr: SocketAddr = ADDR.parse().unwrap();
                        let cfg = server_cfg.clone();
                        let mut rej = None;
                        let c = self.listener.handle(&d, addr, now, &mut out, |req| {
                            if req.stream_id == "forbidden" {
                                rej = Some(RejectReason::FORBIDDEN);
                                return Err(RejectReason::FORBIDDEN);
                            }
                            Ok(cfg)
                        });
                        if rej.is_some() {
                            self.rejected = rej;
                        }
                        for o in out {
                            self.send(false, o);
                        }
                        self.server = c;
                    }
                } else {
                    self.caller.handle(&d, now);
                }
            }
            self.caller.handle_timeout(now);
            if let Some(s) = self.server.as_mut() {
                s.handle_timeout(now);
            }
            self.collect(server_cfg);
        }
    }

    /// The latency is generous for lossy runs: the RTT estimate starts at 100 ms +- 50 ms (as
    /// libsrt's), so a loss whose retransmission is lost too waits ~150 ms for its second NAK
    /// until the estimate converges.
    fn run(passphrase: Option<&str>, server_pass: Option<&str>, loss_every: u64) -> Sim {
        let latency = if loss_every > 0 { 500 } else { 200 };
        let mut cc = Config::default().stream_id("#!::r=live/s,m=publish");
        cc.passphrase = passphrase.map(str::to_owned);
        let mut sc = Config::default().latency(Duration::from_millis(latency));
        sc.passphrase = server_pass.map(str::to_owned);
        let mut sim = Sim::new(cc, loss_every);
        sim.collect(&sc);
        for _ in 0..50 {
            sim.step(Duration::from_millis(2), &sc);
        }
        if sim.caller.state() != State::Connected {
            return sim;
        }
        for i in 0..500u32 {
            let mut p = vec![0u8; 1316];
            p[..4].copy_from_slice(&i.to_be_bytes());
            sim.caller.write(&p, sim.now).unwrap();
            sim.collect(&sc);
            sim.step(Duration::from_millis(2), &sc);
        }
        for _ in 0..400 {
            sim.step(Duration::from_millis(5), &sc);
        }
        sim
    }

    fn check_all_in_order(sim: &Sim) {
        assert_eq!(
            sim.got.len(),
            500,
            "stats {:?}",
            sim.server.as_ref().map(Conn::stats)
        );
        for (i, p) in sim.got.iter().enumerate() {
            assert_eq!(u32::from_be_bytes([p[0], p[1], p[2], p[3]]), i as u32);
            assert!(p[4..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn handshake_and_clean_transfer() {
        let sim = run(None, None, 0);
        let s = sim.server.as_ref().unwrap();
        assert_eq!(s.stream_id(), "#!::r=live/s,m=publish");
        // The larger latency wins on both sides.
        assert_eq!(s.latency(), Duration::from_millis(200));
        assert_eq!(sim.caller.latency(), Duration::from_millis(200));
        check_all_in_order(&sim);
        assert!(sim.caller_events.contains(&Event::Connected));
        assert_eq!(sim.caller.stats().packets_retrans, 0);
    }

    #[test]
    fn losses_are_repaired() {
        let sim = run(None, None, 7);
        check_all_in_order(&sim);
        let st = sim.server.as_ref().unwrap().stats();
        assert!(st.packets_lost > 40, "{st:?}");
        assert!(
            st.naks_sent > st.packets_lost,
            "some losses needed a second NAK"
        );
        assert_eq!(st.packets_recv_drop, 0);
        assert!(st.naks_sent > 0);
        assert!(sim.caller.stats().packets_retrans >= st.packets_lost);
    }

    #[test]
    fn encrypted_transfer_with_loss() {
        let sim = run(Some("0123456789abc"), Some("0123456789abc"), 11);
        assert!(sim.server.as_ref().unwrap().encrypted());
        check_all_in_order(&sim);
        assert_eq!(sim.server.as_ref().unwrap().stats().packets_undecrypt, 0);
    }

    #[test]
    fn rejections() {
        let sim = run(Some("0123456789abc"), Some("another passphrase"), 0);
        assert!(sim.server.is_none());
        assert!(
            sim.caller_events
                .contains(&Event::Closed(Some(SrtError::Rejected(
                    RejectReason::BAD_SECRET
                ))))
        );
        let sim = run(Some("0123456789abc"), None, 0);
        assert!(
            sim.caller_events
                .contains(&Event::Closed(Some(SrtError::Rejected(
                    RejectReason::UNSECURE
                ))))
        );
        let mut sim = Sim::new(Config::default().stream_id("forbidden"), 0);
        let sc = Config::default();
        sim.collect(&sc);
        for _ in 0..20 {
            sim.step(Duration::from_millis(2), &sc);
        }
        assert_eq!(sim.rejected, Some(RejectReason::FORBIDDEN));
        assert!(
            sim.caller_events
                .contains(&Event::Closed(Some(SrtError::Rejected(
                    RejectReason::FORBIDDEN
                ))))
        );
        assert!(Conn::caller(Config::default().passphrase("short"), Instant::now()).is_err());
    }

    #[test]
    fn shutdown_and_idle() {
        let mut sim = run(None, None, 0);
        let sc = Config::default();
        sim.caller.close(sim.now);
        sim.collect(&sc);
        sim.step(Duration::from_millis(10), &sc);
        assert!(
            sim.server_events
                .contains(&Event::Closed(Some(SrtError::PeerClosed)))
        );
        // A caller that never hears back times out.
        let mut lone = Conn::caller(Config::default(), Instant::now()).unwrap();
        let t = Instant::now() + Duration::from_secs(4);
        lone.handle_timeout(t);
        assert_eq!(
            lone.poll_event(),
            Some(Event::Closed(Some(SrtError::HandshakeTimeout)))
        );
        assert_eq!(lone.write(b"x", t), Err(SrtError::Closed));
    }
}
