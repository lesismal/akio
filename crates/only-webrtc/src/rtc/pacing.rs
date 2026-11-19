//! Bandwidth probing on the send path (ADR-050): the estimator's probe clusters go out as RTX
//! copies of recent media (or padding), paced by its probe timeout; a new ICE pair restarts
//! the estimate.

use super::*;

/// Probe packets sent per call (a 15 ms cluster at 20 Mbps is about 30 packets).
const MAX_PROBES_PER_CALL: usize = 64;

impl Rtc {
    /// Sends the probe packets due at `now`, on the stream that sent the most media among
    /// the lines with congestion control feedback. Nothing before media was sent; clusters
    /// that cannot be sent (no path, no such stream) are dropped, so the probe timeout never
    /// stays due.
    pub(super) fn send_probes(&mut self, now: Instant) {
        let Some(bwe) = self.bwe.as_mut() else {
            return;
        };
        let (true, Some((src, dest))) = (self.srtp_tx.is_some(), self.ice.send_pair()) else {
            bwe.cancel_probes();
            return;
        };
        let ccfb = self.ccfb;
        let pick = self
            .media
            .iter()
            .enumerate()
            .filter(|(_, l)| !l.stopped && (ccfb || l.ext.id_of(Extension::TransportCc).is_some()))
            .flat_map(|(i, l)| {
                let sim = l.sim.iter().enumerate();
                std::iter::once((i, None, l.send.octets_sent()))
                    .chain(sim.map(move |(j, e)| (i, Some(j), e.send.octets_sent())))
            })
            .filter(|c| c.2 > 0)
            .max_by_key(|c| c.2);
        let Some((li, enc, _)) = pick else {
            bwe.cancel_probes();
            return;
        };
        let line = &mut self.media[li];
        let rtx_pt = match line.last_pt {
            Some(p) if line.fec_pts.red == Some(p) => line.fec_pts.red_rtx,
            p => p.and_then(|p| line.codec(p)).and_then(|c| c.rtx),
        };
        let has_twcc = line.ext.id_of(Extension::TransportCc).is_some();
        let has_rrid = line.ext.id_of(Extension::RepairedRtpStreamId).is_some();
        let has_ast = line.ext.id_of(Extension::AbsSendTime).is_some();
        let MediaLine {
            ext: map,
            send,
            sim,
            ..
        } = line;
        let stream = match enc {
            Some(j) => &mut sim[j].send,
            None => send,
        };
        let on_rtx = rtx_pt.is_some() && stream.rtx_ssrc().is_some();
        for _ in 0..MAX_PROBES_PER_CALL {
            let Some(p) = bwe.poll_probe(now) else {
                break;
            };
            let twcc = &mut self.twcc_tx;
            let mut tw = None;
            let Some(raw) = stream.padding(now, p.size, rtx_pt, map, |e| {
                e.transport_cc = has_twcc.then(|| twcc.next_seq());
                tw = e.transport_cc;
                if has_ast {
                    e.abs_send_time = Some(abs_send_time_now());
                }
                // An RTX stream names the encoding it repairs (RFC 8852).
                if on_rtx {
                    let rid = e.rid.take();
                    if has_rrid {
                        e.rrid = rid;
                    }
                }
            }) else {
                bwe.cancel_probes();
                break;
            };
            match tw {
                Some(s) => twcc.on_sent_probe(s, now, raw.len(), p.cluster),
                None if raw.len() >= 12 => {
                    let seq = u16::from_be_bytes([raw[2], raw[3]]);
                    let ssrc = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
                    self.ccfb_tx
                        .on_sent_probe(ssrc, seq, now, raw.len(), p.cluster);
                }
                None => {}
            }
            bwe.on_probe_sent(now, p.cluster, raw.len());
            let Some(tx) = self.srtp_tx.as_mut() else {
                break;
            };
            if let Ok(o) = tx.protect_rtp(&raw) {
                self.stats.bytes_sent += o.len() as u64;
                self.stats.packets_sent += 1;
                self.transmits.push_back((src, dest, o));
            }
        }
    }

    /// ICE selected `(local, remote)`: a change of path restarts the estimate and probing.
    pub(super) fn on_selected_pair(&mut self, now: Instant, local: SocketAddr, remote: SocketAddr) {
        let changed = self.probe_pair.is_some_and(|p| p != (local, remote));
        self.probe_pair = Some((local, remote));
        if changed {
            if let Some(b) = self.bwe.as_mut() {
                b.on_network_change(now);
            }
            self.bwe_event();
        }
    }
}
