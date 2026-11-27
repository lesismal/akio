//! What an SFU needs of a peer (ADR-187): received RTP written to another peer as it is
//! ([`Rtc::write_rtp`]), with the sent stream's SSRC and payload type and sequence numbers and
//! timestamps renumbered continuously across the sources written; a cap on what the remote
//! sends told as REMB; and ICE consent failure after a timeout of its own.

use super::*;

/// The SFU state of one peer.
#[derive(Debug, Default)]
pub(super) struct PeerFwd {
    /// The cap told the remote senders as REMB (bits per second).
    remb_cap: Option<u64>,
    /// When ICE reports `Failed` (consent lost since `Disconnected`).
    pub(super) fail_at: Option<Instant>,
}

/// Packets of the current source forwarded at most this far behind its newest (older ones
/// are dropped: their sequence numbers would be far behind the receiver's window).
pub(super) const MAX_LATE: u64 = 0x4000;

/// How forwarded packets are renumbered on one sent stream: the sequence numbers of a source
/// keep their gaps and order (shifted by an offset), and a new source (another SSRC written)
/// continues after the last number sent, its timestamps after the last one by the time
/// between them.
#[derive(Debug, Default)]
pub(super) struct Renumber {
    /// The SSRC of the source being forwarded.
    src: Option<u32>,
    /// Sent (extended) sequence number = received + `seq_off`, mod 2^64.
    seq_off: u64,
    /// Received sequence numbers below this belong to an earlier numbering: dropped.
    floor: u64,
    /// The newest received sequence number forwarded.
    high: u64,
    /// Sent timestamp = received + `ts_off`.
    ts_off: u32,
    /// The newest packet sent: its timestamp and when it arrived.
    last: Option<(u32, Instant)>,
}

impl Renumber {
    /// The sequence number and timestamp a packet of source `ssrc` (extended sequence number
    /// `seq`, timestamp `ts`, arrived at `received`) goes out with on a stream whose next
    /// sequence number is `next` and clock `clock`; `None` to drop it.
    pub(super) fn map(
        &mut self,
        ssrc: u32,
        seq: u64,
        ts: u32,
        received: Instant,
        next: u16,
        clock: u32,
    ) -> Option<(u16, u32)> {
        if self.src != Some(ssrc) {
            // A new source: right after what the stream sent.
            self.src = Some(ssrc);
            self.seq_off = u64::from(next).wrapping_sub(seq);
            self.floor = seq;
            self.high = seq;
            let out = match self.last {
                Some((last_ts, at)) => {
                    let ticks = received.saturating_duration_since(at).as_nanos()
                        * u128::from(clock)
                        / 1_000_000_000;
                    last_ts.wrapping_add(u32::try_from(ticks).unwrap_or(u32::MAX).max(1))
                }
                None => ts,
            };
            self.ts_off = out.wrapping_sub(ts);
        } else if seq < self.floor || self.high.saturating_sub(seq) > MAX_LATE {
            return None;
        } else if seq > self.high {
            // Numbers the stream took meanwhile (samples written, padding): shift past them.
            let expect = self.high.wrapping_add(self.seq_off).wrapping_add(1) as u16;
            let taken = next.wrapping_sub(expect);
            if taken != 0 && taken < 0x8000 {
                self.seq_off = self.seq_off.wrapping_add(u64::from(taken));
                self.floor = seq;
            }
            self.high = seq;
        }
        let out_ts = ts.wrapping_add(self.ts_off);
        if seq == self.high {
            self.last = Some((out_ts, received));
        }
        Some((seq.wrapping_add(self.seq_off) as u16, out_ts))
    }
}

/// The header extensions of a received packet an application sees in RTP mode
/// ([`RtpPacket::extensions`]): all but the MID and RIDs.
pub(super) fn forwarded_ext(e: &ExtensionValues) -> ExtensionValues {
    ExtensionValues {
        audio_level: e.audio_level,
        video_orientation: e.video_orientation,
        transmission_offset: e.transmission_offset,
        playout_delay: e.playout_delay,
        abs_send_time: e.abs_send_time,
        transport_cc: e.transport_cc,
        ..ExtensionValues::default()
    }
}

impl Rtc {
    /// Sends `pkt` (received from another peer in RTP mode) on `mid` (simulcast encoding `rid`
    /// of a simulcast line, the first without one): with this stream's SSRC, the payload type
    /// negotiated here for its codec, renumbered ([`Renumber`]), its audio level, video
    /// orientation, transmission offset and playout delay under this line's extension ids,
    /// this side's MID, RID and send-time extensions. It joins the stream's retransmission
    /// history (NACKs are answered from it, with RTX where negotiated). `Ok(false)`: no such
    /// sending line or encoding.
    pub(crate) fn write_rtp(
        &mut self,
        now: Instant,
        mid: Mid,
        rid: Option<&str>,
        pkt: &RtpPacket,
    ) -> Result<bool, RtcErr> {
        if let Some(k) = self.tp_redirect(mid) {
            return self.with_tp(k, |s| s.write_rtp(now, mid, rid, pkt));
        }
        let Some(idx) = self.media.iter().position(|l| l.mid == mid) else {
            return Ok(false);
        };
        let line = &mut self.media[idx];
        if line.stopped || !(line.dir.sends() || !line.negotiated && line.want.sends()) {
            return Ok(false);
        }
        let enc = match (line.sim.is_empty(), rid) {
            (true, None) => None,
            (true, Some(_)) => return Ok(false),
            (false, None) => Some(0),
            (false, Some(r)) => match line.sim.iter().position(|e| e.rid == r) {
                Some(i) => Some(i),
                None => return Ok(false),
            },
        };
        let Some(codec) = pkt
            .codec
            .and_then(|c| line.codecs.iter().find(|p| p.codec == c))
            .cloned()
        else {
            return Err(err(format!("{:?} not negotiated on {mid}", pkt.codec)));
        };
        if enc.is_some_and(|i| !line.sim[i].active) {
            return Ok(true); // not accepted by the answer: dropped
        }
        if !(self.srtp_tx.is_some() && self.ice.send_pair().is_some()) {
            return Ok(true); // not connected yet: dropped
        }
        let has_mid = line.ext.id_of(Extension::Mid).is_some();
        let has_rid = line.ext.id_of(Extension::RtpStreamId).is_some();
        let twcc_id = line.ext.id_of(Extension::TransportCc);
        let ast_id = line.ext.id_of(Extension::AbsSendTime);
        let class = if line.kind == MediaKind::Audio {
            pacing::Class::Audio
        } else {
            pacing::Class::Media
        };
        line.last_pt = Some(codec.pt);
        let MediaLine {
            ext: map,
            send,
            sim,
            fwd,
            ..
        } = line;
        let (send, fwd, rid) = match enc {
            Some(i) => {
                let e = &mut sim[i];
                (&mut e.send, &mut e.fwd, Some(e.rid.as_str()))
            }
            None => (send, fwd, None),
        };
        let Some((seq, ts)) = fwd.map(
            pkt.ssrc,
            pkt.seq_no,
            pkt.rtp_time,
            pkt.received,
            send.next_seq(),
            codec.clock,
        ) else {
            return Ok(true);
        };
        let mut ext = forwarded_ext(&pkt.extensions);
        // Send-time extensions are placeholders, filled as the packet leaves.
        ext.abs_send_time = ast_id.map(|_| 0);
        ext.transport_cc = twcc_id.map(|_| 0);
        if has_mid {
            ext.mid = Some(mid.as_str().to_owned());
        }
        if has_rid {
            ext.rid = rid.map(str::to_owned);
        }
        let raw = send.write_with_seq(now, seq, codec.pt, pkt.marker, ts, &pkt.payload, &ext, map);
        let q = pacing::Queued {
            raw,
            twcc: twcc_id,
            ast: ast_id,
            fec: false,
            at: now,
            tp: 0,
        };
        self.send_rtp(now, class, q);
        if self.next_rtcp.is_none() {
            self.next_rtcp = Some(now + Duration::from_millis(100));
        }
        self.send_probes(now);
        Ok(true)
    }

    /// Caps what the remote sends at `cap` bits per second, told as REMB once a second with
    /// the reports and once now (`None`: no more REMBs).
    pub(crate) fn set_receive_bitrate_cap(&mut self, cap: Option<u64>) {
        self.fwd.remb_cap = cap;
        if let Some(remb) = self.remb() {
            let ssrc = self.remb_sender();
            self.send_rtcp(&[
                Rtcp::ReceiverReport {
                    ssrc,
                    reports: Vec::new(),
                },
                remb,
            ]);
        }
    }

    fn remb_sender(&self) -> u32 {
        self.media.first().map_or(1, |l| l.send.ssrc())
    }

    /// The REMB of the cap about every media stream received (signalled ones before any
    /// arrived), or `None` without a cap or a stream.
    fn remb(&self) -> Option<Rtcp> {
        let cap = self.fwd.remb_cap?;
        let mut ssrcs: Vec<u32> = self
            .recv
            .keys()
            .copied()
            .filter(|s| self.routes.get(s).is_none_or(|r| r.repairs.is_none()))
            .collect();
        if ssrcs.is_empty() {
            for l in self.media.iter().filter(|l| !l.stopped) {
                ssrcs.extend(
                    l.remote_ssrcs
                        .iter()
                        .filter(|s| !l.remote_rtx.contains_key(s) && !l.remote_fec.contains_key(s)),
                );
            }
        }
        if ssrcs.is_empty() {
            return None;
        }
        ssrcs.sort_unstable();
        ssrcs.dedup();
        ssrcs.truncate(255);
        Some(Rtcp::Remb {
            sender_ssrc: self.remb_sender(),
            bitrate: cap,
            ssrcs,
        })
    }

    /// The periodic REMB joins the first compound of the reports.
    pub(super) fn add_remb(&self, compounds: &mut Vec<Vec<Rtcp>>) {
        let Some(remb) = self.remb() else { return };
        match compounds.first_mut() {
            Some(c) => c.push(remb),
            None => compounds.push(vec![
                Rtcp::ReceiverReport {
                    ssrc: self.remb_sender(),
                    reports: Vec::new(),
                },
                remb,
            ]),
        }
    }

    /// The ICE state became `s`: consent lost starts the wait for `Failed`, consent back
    /// ends it.
    pub(super) fn consent_state(&mut self, now: Instant, s: IceConnectionState) {
        match s {
            IceConnectionState::Disconnected => {
                if let Some((d, f)) = self.cfg.ice_timeouts {
                    if let Some(more) = f.checked_sub(d).filter(|m| !m.is_zero()) {
                        self.fwd.fail_at = Some(now + more);
                    }
                }
            }
            IceConnectionState::Failed => {}
            _ => self.fwd.fail_at = None,
        }
    }

    /// Reports `Failed` once consent stayed lost for the failed timeout.
    pub(super) fn consent_failed(&mut self, now: Instant) {
        if self.fwd.fail_at.is_some_and(|t| t <= now) {
            self.fwd.fail_at = None;
            self.ice_state = IceConnectionState::Failed;
            self.events
                .push_back(RtcEvent::IceState(IceConnectionState::Failed));
        }
    }

    /// Whether loss of consent is followed by `Failed` (then the peer closes at `Failed`, not
    /// at `Disconnected`).
    pub(crate) fn fails_after_disconnect(&self) -> bool {
        self.cfg.ice_timeouts.is_some_and(|(d, f)| f > d)
    }
}
