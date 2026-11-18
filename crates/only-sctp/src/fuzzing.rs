//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::time::{Duration, Instant};

use crate::{Association, ChannelOptions, Config, Reliability, Scheduler};

/// `sctp_packet`: arbitrary bytes as SCTP packets into a fresh association, one waiting for
/// its COOKIE ECHO, and two established pairs with open channels, one using I-DATA /
/// I-FORWARD-TSN (RFC 8260, round-robin scheduler) and one DATA / FORWARD TSN. The input is
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
    use std::time::Instant;

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
        out.sort();
        out.dedup();
        out
    }

    fn chunk_types(p: &[u8]) -> Vec<u8> {
        crate::packet::parse_packet(p)
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
