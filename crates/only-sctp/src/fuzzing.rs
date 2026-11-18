//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::time::{Duration, Instant};

use crate::{Association, ChannelOptions, Config, Reliability, Scheduler};

/// `sctp_packet`: arbitrary bytes as SCTP packets into a fresh association, one waiting for
/// its COOKIE ECHO, and two established pairs with open channels, one using I-DATA /
/// I-FORWARD-TSN (RFC 8260, round-robin scheduler) and one DATA / FORWARD TSN. Zero
/// checksums (RFC 9653) are accepted, so the CRC check does not hide the parsers; the
/// seeds include HEARTBEATs, a peer restart and RE-CONFIG requests of every kind. The input is
/// used whole and also split on `0xff 0xfe` markers into several packets, each also with its
/// CRC-32C fixed up so that the chunk parsers are reached. Never panics.
pub fn packet(data: &[u8]) {
    let packets: Vec<Vec<u8>> = split(data)
        .into_iter()
        .flat_map(|p| [p.to_vec(), fix_crc(p)])
        .collect();
    let now = Instant::now();

    let mut fresh = Association::new(Config::new(false), now);
    feed(&mut fresh, now, &packets);

    let mut waiting = Association::new(Config::new(true), now);
    waiting.connect(now);
    feed(&mut waiting, now, &packets);

    for interleave in [true, false] {
        let (mut a, mut b) = pair_with(now, interleave);
        feed(&mut a, now, &packets);
        feed(&mut b, now, &packets);
        pump(&mut a, &mut b, now);
    }
}

fn split(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        if data[i] == 0xff && data[i + 1] == 0xfe {
            out.push(&data[start..i]);
            start = i + 2;
            i += 2;
        } else {
            i += 1;
        }
    }
    out.push(&data[start..]);
    out
}

/// Recomputes the checksum so that random bytes get past the CRC check.
fn fix_crc(p: &[u8]) -> Vec<u8> {
    let mut v = p.to_vec();
    if v.len() >= 12 {
        v[8..12].fill(0);
        let c = only_crypto::crc::crc32c(&v);
        v[8..12].copy_from_slice(&c.to_le_bytes());
    }
    v
}

fn feed(a: &mut Association, now: Instant, packets: &[Vec<u8>]) {
    let mut t = now;
    for p in packets {
        a.handle_packet(t, p);
        while a.poll_transmit(t).is_some() {}
        while a.poll_event().is_some() {}
        t += Duration::from_millis(50);
        a.handle_timeout(t);
    }
    let _ = a.poll_timeout();
}

fn pump(a: &mut Association, b: &mut Association, now: Instant) {
    for _ in 0..20 {
        let mut idle = true;
        while let Some(p) = a.poll_transmit(now) {
            b.handle_packet(now, &p);
            idle = false;
        }
        while let Some(p) = b.poll_transmit(now) {
            a.handle_packet(now, &p);
            idle = false;
        }
        if idle {
            break;
        }
    }
}

fn config(client: bool, interleave: bool) -> Config {
    let c = Config::new(client).with_message_interleaving(interleave);
    if interleave {
        c.with_scheduler(Scheduler::RoundRobin)
    } else {
        c
    }
}

/// An established pair (fixed tags and TSNs so that corpus packets match) with a reliable,
/// an unordered partially reliable and a negotiated channel and some traffic.
pub(crate) fn pair_with(now: Instant, interleave: bool) -> (Association, Association) {
    let mut a = Association::with_ids(config(true, interleave), 0x0a0a_0a0a, 1000, [1; 32]);
    let mut b = Association::with_ids(config(false, interleave), 0x0b0b_0b0b, 5000, [2; 32]);
    a.connect(now);
    let c0 = a.open_channel(now, ChannelOptions::new("r")).ok();
    let c1 = a
        .open_channel(
            now,
            ChannelOptions::new("u")
                .with_ordered(false)
                .with_reliability(Reliability::MaxRetransmits(0)),
        )
        .ok();
    let _ = a.open_channel(now, ChannelOptions::new("n").with_negotiated(9));
    let _ = b.open_channel(now, ChannelOptions::new("n").with_negotiated(9));
    pump(&mut a, &mut b, now);
    for (i, c) in [c0, c1].into_iter().flatten().enumerate() {
        let _ = a.send(now, c, &vec![b'x'; 10 + 2000 * i], i == 1);
        let _ = a.send(now, c, b"", false);
    }
    let _ = b.send(now, 9, b"neg", true);
    pump(&mut a, &mut b, now);
    while a.poll_event().is_some() {}
    while b.poll_event().is_some() {}
    (a, b)
}

/// The established pair's `b` gets a packet from `a` (tag and ports of the pair).
#[cfg(test)]
fn to_b(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut w = crate::packet::PacketWriter::new(
        crate::packet::Header {
            src_port: 5000,
            dst_port: 5000,
            vtag: 0x0b0b_0b0b,
        },
        1200,
    );
    for c in chunks {
        w.push_raw(c);
    }
    w.finish()
}

/// RE-CONFIG requests of every kind from `a` to `b`, starting at request sequence number
/// `seq` (a's initial TSN for a fresh pair).
#[cfg(test)]
fn reconfig_requests(seq: u32) -> Vec<Vec<u8>> {
    use crate::packet::{PARAM_ADD_OUTGOING, ReconfigParam};
    [
        vec![ReconfigParam::IncomingReset {
            req_seq: seq,
            streams: vec![0, 4],
        }],
        vec![ReconfigParam::SsnTsnReset { req_seq: seq + 1 }],
        vec![ReconfigParam::IncomingReset {
            req_seq: seq + 2,
            streams: vec![],
        }],
        vec![ReconfigParam::OtherRequest {
            typ: PARAM_ADD_OUTGOING,
            req_seq: seq + 3,
        }],
    ]
    .iter()
    .map(|p| to_b(&[ReconfigParam::encode_chunk(p)]))
    .collect()
}

#[cfg(test)]
fn pump_recording(a: &mut Association, b: &mut Association, now: Instant, out: &mut Vec<Vec<u8>>) {
    for _ in 0..20 {
        let mut idle = true;
        while let Some(p) = a.poll_transmit(now) {
            b.handle_packet(now, &p);
            out.push(p);
            idle = false;
        }
        while let Some(p) = b.poll_transmit(now) {
            a.handle_packet(now, &p);
            out.push(p);
            idle = false;
        }
        if idle {
            break;
        }
    }
}

#[cfg(test)]
fn pair_recording(
    now: Instant,
    interleave: bool,
    out: &mut Vec<Vec<u8>>,
) -> (Association, Association) {
    let mut a = Association::with_ids(config(true, interleave), 0x0a0a_0a0a, 1000, [1; 32]);
    let mut b = Association::with_ids(config(false, interleave), 0x0b0b_0b0b, 5000, [2; 32]);
    a.connect(now);
    let c0 = a.open_channel(now, ChannelOptions::new("r")).ok();
    let c1 = a
        .open_channel(
            now,
            ChannelOptions::new("u")
                .with_ordered(false)
                .with_reliability(Reliability::MaxRetransmits(0)),
        )
        .ok();
    pump_recording(&mut a, &mut b, now, out);
    for (i, c) in [c0, c1].into_iter().flatten().enumerate() {
        let _ = a.send(now, c, &vec![b'x'; 10 + 2000 * i], i == 1);
        let _ = a.send(now, c, b"", false);
    }
    // Lose this round of data so that the partially reliable message is abandoned and a
    // FORWARD TSN / I-FORWARD-TSN follows (the reliable one is retransmitted).
    while let Some(p) = a.poll_transmit(now) {
        out.push(p);
    }
    pump_recording(&mut a, &mut b, now, out);
    let later = now + Duration::from_secs(2);
    a.handle_timeout(later);
    pump_recording(&mut a, &mut b, later, out);
    (a, b)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::packet::{self, ReconfigParam};
    use crate::{Association, ChannelOptions, Event};

    /// The RE-CONFIG parameters in the packets `x` sends.
    fn reconfig_out(x: &mut Association, now: Instant) -> Vec<ReconfigParam> {
        let mut v = Vec::new();
        while let Some(p) = x.poll_transmit(now) {
            if let Some((_, chunks)) = packet::parse_packet(&p, true) {
                for c in chunks.iter().filter(|c| c.typ == packet::CT_RECONFIG) {
                    v.extend(ReconfigParam::parse_all(c.value));
                }
            }
        }
        v
    }

    fn events(x: &mut Association) -> Vec<Event> {
        std::iter::from_fn(|| x.poll_event()).collect()
    }

    /// RFC 6525 §5.2.3: an Incoming SSN Reset Request is answered with our own Outgoing SSN
    /// Reset Request (its response sequence number naming the request); the channel closes
    /// once the peer resets its side too. A retransmission resends that request.
    #[test]
    fn incoming_reset_request() {
        for interleave in [false, true] {
            let now = Instant::now();
            let (mut a, mut b) = super::pair_with(now, interleave);
            assert!(b.channel(0).is_some());
            let req = super::to_b(&[ReconfigParam::encode_chunk(&[
                ReconfigParam::IncomingReset {
                    req_seq: 1000,
                    streams: vec![0, 40],
                },
            ])]);
            b.handle_packet(now, &req);
            let out = reconfig_out(&mut b, now);
            let Some(ReconfigParam::OutgoingReset {
                resp_seq, streams, ..
            }) = out.first()
            else {
                panic!("{interleave}: {out:?}");
            };
            assert_eq!(*resp_seq, 1000);
            let mut st = streams.clone();
            st.sort_unstable();
            assert_eq!(st, vec![0, 40]);
            // Retransmitted: the same Outgoing request again, no explicit response.
            b.handle_packet(now, &req);
            let again = reconfig_out(&mut b, now);
            assert!(
                matches!(
                    again.as_slice(),
                    [ReconfigParam::OutgoingReset { resp_seq: 1000, .. }]
                ),
                "{again:?}"
            );
            // Delivered to a: it resets its incoming side, answers, and resets its outgoing
            // side in turn; both close the channel.
            b.handle_packet(now, &req);
            // The request above stood for a's request 1000: a's own next one is 1001.
            a.skip_request_seq_for_test();
            super::pump(&mut b, &mut a, now);
            super::pump(&mut a, &mut b, now + Duration::from_secs(1));
            assert!(events(&mut a).contains(&Event::ChannelClose { stream: 0 }));
            assert!(events(&mut b).contains(&Event::ChannelClose { stream: 0 }));
            assert!(a.channel(0).is_none() && b.channel(0).is_none());
            // A stream without a channel is reset too (its sequence numbers start over).
            let only0 = super::to_b(&[ReconfigParam::encode_chunk(&[
                ReconfigParam::IncomingReset {
                    req_seq: 1002,
                    streams: vec![0],
                },
            ])]);
            b.handle_packet(now, &only0);
            let out = reconfig_out(&mut b, now);
            assert!(
                matches!(
                    out.as_slice(),
                    [ReconfigParam::OutgoingReset { resp_seq: 1002, streams, .. }] if streams == &[0]
                ),
                "{out:?}"
            );
        }
    }

    /// RFC 6525 §5.2.4: an SSN/TSN Reset Request is "in progress" while our data is in
    /// flight, then performed: the response carries our next TSN and the peer's (its
    /// smallest unacknowledged TSN + 2^31), data at the peer's new TSN with SSN 0 is taken,
    /// and our own SSNs restart at 0.
    #[test]
    fn ssn_tsn_reset_request() {
        let now = Instant::now();
        let (_, mut b) = super::pair_with(now, false);
        b.send(now, 9, b"in flight", true).unwrap();
        let sent: Vec<Vec<u8>> = std::iter::from_fn(|| b.poll_transmit(now)).collect();
        assert!(!sent.is_empty());
        let req = |seq| {
            super::to_b(&[ReconfigParam::encode_chunk(&[ReconfigParam::SsnTsnReset {
                req_seq: seq,
            }])])
        };
        b.handle_packet(now, &req(1000));
        let out = reconfig_out(&mut b, now);
        assert!(
            out.contains(&ReconfigParam::Response {
                resp_seq: 1000,
                result: packet::RESULT_IN_PROGRESS,
                tsns: None,
            }),
            "{out:?}"
        );
        // a acknowledges b's data (cumulative TSN: b's initial TSN 5000 plus what it sent).
        let next = b.next_tsn_for_test();
        let sack = packet::Sack {
            cum_tsn: next.wrapping_sub(1),
            a_rwnd: 1 << 20,
            gaps: vec![],
            dups: vec![],
        };
        b.handle_packet(now, &super::to_b(&[sack.encode()]));
        let cum = b.cum_tsn_for_test();
        b.handle_packet(now, &req(1000));
        let out = reconfig_out(&mut b, now);
        let receiver_next = cum.wrapping_add(1).wrapping_add(1 << 31);
        let want = ReconfigParam::Response {
            resp_seq: 1000,
            result: packet::RESULT_PERFORMED,
            tsns: Some((next, receiver_next)),
        };
        assert!(out.contains(&want), "{out:?}");
        // A retransmission gets the same answer.
        b.handle_packet(now, &req(1000));
        assert_eq!(reconfig_out(&mut b, now), vec![want]);
        // a's data now starts at receiver_next with SSN 0.
        let mut w = packet::PacketWriter::new(
            packet::Header {
                src_port: 5000,
                dst_port: 5000,
                vtag: 0x0b0b_0b0b,
            },
            1200,
        );
        w.push_data(&packet::Data {
            flags: packet::FLAG_BEGIN | packet::FLAG_END,
            tsn: receiver_next,
            stream: 9,
            ssn: 0,
            ppid: crate::assoc::PPID_BINARY,
            payload: b"after reset",
        });
        let _ = events(&mut b);
        b.handle_packet(now, &w.finish());
        assert!(events(&mut b).contains(&Event::ChannelData {
            stream: 9,
            data: b"after reset".to_vec(),
            binary: true,
        }));
        assert_eq!(b.cum_tsn_for_test(), receiver_next);
        // Our next message on stream 9 goes out with SSN 0.
        b.send(now, 9, b"x", true).unwrap();
        let p = b.poll_transmit(now).unwrap();
        let (_, chunks) = packet::parse_packet(&p, true).unwrap();
        let d = chunks.iter().find(|c| c.typ == packet::CT_DATA).unwrap();
        let d = packet::Data::parse(d.flags, d.value).unwrap();
        assert_eq!((d.tsn, d.stream, d.ssn), (next, 9, 0));
    }

    /// A peer restart while we are shutting down is not taken (RFC 9260 §5.2.4 case A).
    #[test]
    fn restart_while_shutting_down() {
        let now = Instant::now();
        let (mut a, mut b) = super::pair_with(now, true);
        b.send(now, 9, b"unacked", true).unwrap();
        b.shutdown(now);
        let mut a2 = Association::with_ids(super::config(true, true), 0x0c0c_0c0c, 9000, [3; 32]);
        a2.connect(now);
        super::pump(&mut a2, &mut b, now);
        assert!(b.is_closed());
        assert!(!events(&mut b).contains(&Event::Restarted));
        let _ = a.open_channel(now, ChannelOptions::new("x"));
    }

    /// Real packets of sessions with DATA and with I-DATA: handshake, DCEP, data of every
    /// kind, SACKs, FORWARD TSN / I-FORWARD-TSN, RE-CONFIG and shutdown, recorded in both
    /// directions.
    fn seeds() -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        for interleave in [false, true] {
            let (mut a, mut b) = super::pair_recording(now, interleave, &mut out);
            assert_eq!(a.message_interleaving(), interleave);
            a.close_channel(now, 0);
            super::pump_recording(&mut a, &mut b, now, &mut out);
            a.shutdown(now);
            super::pump_recording(&mut a, &mut b, now, &mut out);
        }
        for interleave in [false, true] {
            // HEARTBEAT / HEARTBEAT ACK after an idle minute.
            let (mut a, mut b) = super::pair_with(now, interleave);
            let later = now + Duration::from_secs(60);
            a.handle_timeout(later);
            b.handle_timeout(later);
            super::pump_recording(&mut a, &mut b, later, &mut out);
            // RE-CONFIG requests to b, and what b answers.
            for p in super::reconfig_requests(1000) {
                b.handle_packet(later, &p);
                out.push(p);
                super::pump_recording(&mut a, &mut b, later, &mut out);
            }
            // A peer restart: a new `a` (other tag, TSN and key) handshakes with b.
            let mut a2 =
                Association::with_ids(super::config(true, interleave), 0x0c0c_0c0c, 9000, [3; 32]);
            a2.connect(later);
            super::pump_recording(&mut a2, &mut b, later, &mut out);
            assert!(std::iter::from_fn(|| b.poll_event()).any(|e| e == Event::Restarted));
        }
        out.sort();
        out.dedup();
        out
    }

    fn chunk_types(p: &[u8]) -> Vec<u8> {
        packet::parse_packet(p, true)
            .map(|(_, c)| c.iter().map(|c| c.typ).collect())
            .unwrap_or_default()
    }

    #[test]
    fn seeds_cover_idata() {
        let types: Vec<u8> = seeds().iter().flat_map(|p| chunk_types(p)).collect();
        for t in [0, 64, 192, 194] {
            assert!(types.contains(&t), "chunk type {t} missing from the seeds");
        }
    }

    /// RFC 8260 §2.2.3: DATA on an association that negotiated I-DATA, or I-DATA on one that
    /// did not, is a protocol violation: ABORT.
    #[test]
    fn data_kind_mismatch_aborts() {
        for interleave in [true, false] {
            let now = Instant::now();
            let (_, mut b) = super::pair_with(now, interleave);
            assert_eq!(b.message_interleaving(), interleave);
            let typ = if interleave { 0 } else { 64 };
            let mut p = vec![0x13, 0x88, 0x13, 0x88, 0x0b, 0x0b, 0x0b, 0x0b, 0, 0, 0, 0];
            p.extend_from_slice(&[typ, 3, 0, 24]);
            p.extend_from_slice(&1010u32.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, b'a', b'b', b'c', b'd']);
            b.handle_packet(now, &super::fix_crc(&p));
            assert!(b.is_closed(), "{interleave}");
            let sent: Vec<u8> = std::iter::from_fn(|| b.poll_transmit(now))
                .flat_map(|p| chunk_types(&p))
                .collect();
            assert!(sent.contains(&6), "{interleave}: {sent:?}");
        }
    }

    #[test]
    fn replay_corpus() {
        let n = only_core::fuzzing::replay(env!("CARGO_MANIFEST_DIR"), "sctp_packet", |d| {
            super::packet(d);
        });
        assert!(n > 0, "fuzz/corpus/sctp_packet is empty");
    }

    #[test]
    fn seeds_do_not_panic() {
        for s in seeds() {
            super::packet(&s);
        }
    }

    /// Regenerates the seed corpus:
    /// `cargo test -p only-sctp --features fuzzing -- --ignored generate_corpus`.
    #[test]
    #[ignore = "writes fuzz/corpus"]
    fn generate_corpus() {
        only_core::fuzzing::write_target_seeds(env!("CARGO_MANIFEST_DIR"), "sctp_packet", &seeds());
    }
}
