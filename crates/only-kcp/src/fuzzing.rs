//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.
//!
//! Datagram inputs are a sequence of packets, each prefixed by its length (`u16`, little
//! endian); see [`packets`].

use std::sync::OnceLock;

use crate::crypt::Crypt;
use crate::fec;
use crate::frame::{self, Framer};
use crate::kcp::Kcp;

/// Splits `data` into length-prefixed packets (a truncated last one is taken as it is).
pub fn packets(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let n = usize::from(u16::from_le_bytes([data[0], data[1]])).min(data.len() - 2);
        out.push(&data[2..2 + n]);
        data = &data[2 + n..];
    }
    out
}

/// Prefixes each packet with its length (the inverse of [`packets`]).
pub fn join(pkts: &[Vec<u8>]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in pkts {
        v.extend_from_slice(&(p.len() as u16).to_le_bytes());
        v.extend_from_slice(p);
    }
    v
}

/// The fixed-key crypt of each kind kcptun offers (index `i % 6`), built once.
pub fn crypt(i: u8) -> Option<&'static Crypt> {
    const KINDS: [&str; 6] = ["none", "xor", "aes", "aes-128", "aes-192", "aes-128-gcm"];
    static ALL: OnceLock<Vec<Crypt>> = OnceLock::new();
    let all = ALL.get_or_init(|| {
        KINDS
            .iter()
            .map(|k| Crypt::new(k, &[0x42; 32]).expect("crypt"))
            .collect()
    });
    let i = usize::from(i) % 7;
    all.get(i) // 6: no crypt at all
}

fn conv_of(p: &[u8]) -> u32 {
    p.get(..4)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Feeds `pkts` to `k`, interleaved with what a session does between datagrams: reading
/// messages, flushing (acks, retransmissions, window probes) and sending.
fn drive(k: &mut Kcp, pkts: &[&[u8]], cfg: u8) {
    let mut now: u32 = 0;
    let mut sink = |_: &[u8]| {};
    for (i, p) in pkts.iter().enumerate() {
        let _ = k.input(p, now);
        while k.recv().is_some() {}
        if cfg & 4 != 0 && i % 3 == 0 {
            let _ = k.send(&p[..p.len().min(3000)]);
        }
        now = now.wrapping_add(u32::from(cfg >> 3) * 40 + 7);
        k.flush(now, &mut sink);
        let _ = k.next_flush(now);
        let _ = k.peek_size();
    }
}

/// `kcp_input`: the KCP state machine fed arbitrary packets (the conversation id is taken from
/// the first one). `data[0]`: bit 0 stream mode, bit 1 nodelay, bit 2 also send, high bits the
/// clock step.
pub fn kcp_input(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let pkts = packets(rest);
    let mut k = Kcp::new(pkts.first().map_or(0, |p| conv_of(p)));
    k.set_stream(cfg & 1 != 0);
    if cfg & 2 != 0 {
        k.nodelay(1, 10, 2, true);
    }
    drive(&mut k, &pkts, cfg);
}

/// `kcp_fec`: the FEC decoder with `data[0]`/`data[1]` data/parity shards (as a session builds
/// it), fed arbitrary shards; recovered packets must carry a sane size prefix.
pub fn kcp_fec(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let (d, p) = (usize::from(data[0] % 16) + 1, usize::from(data[1] % 8) + 1);
    let Some(mut dec) = fec::Decoder::new(d, p) else {
        return;
    };
    for pkt in packets(&data[2..]) {
        if pkt.len() < fec::HEADER_PLUS2 {
            continue; // the framer never passes shorter shards
        }
        for r in dec.decode(pkt) {
            assert!(r.len() >= 2);
        }
    }
}

/// `kcp_crypt`: opening datagrams with each crypt (`data[0]` picks it), and the round trip
/// `open(seal(x)) == x` on the same bytes.
pub fn kcp_crypt(data: &[u8]) {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let Some(c) = crypt(which) else {
        return;
    };
    let _ = c.open(rest.to_vec());
    let mut b = vec![0u8; c.header()];
    b.extend_from_slice(rest);
    let sealed = c.seal(b);
    assert_eq!(
        c.open(sealed).as_deref(),
        Some(rest),
        "seal/open round trip"
    );
}

/// `kcp_frame`: a session's whole datagram path: decrypt (`data[0]` picks the crypt), peek,
/// FEC framing (`data[1]` sets the shard counts, 0 for none) and KCP input.
pub fn kcp_frame(data: &[u8]) {
    if data.len() < 2 {
        return;
    }
    let c = crypt(data[0]);
    let (d, p) = (usize::from(data[1] & 15), usize::from(data[1] >> 4));
    let Some(mut fr) = Framer::new(d, p) else {
        return;
    };
    let mut k: Option<Kcp> = None;
    let mut now = 0u32;
    for pkt in packets(&data[2..]) {
        let Some(o) = frame::open(c, pkt) else {
            continue;
        };
        if k.is_none() {
            let Some((conv, _, _)) = frame::peek(&o) else {
                continue;
            };
            k = Some(Kcp::new(conv));
        }
        let kcp = k.as_mut().expect("set");
        fr.decode(&o, &mut |p| {
            let _ = kcp.input(p, now);
        });
        while kcp.recv().is_some() {}
        now = now.wrapping_add(10);
        kcp.flush(now, &mut |_| {});
    }
}

#[cfg(test)]
pub(crate) mod seeds {
    use super::*;

    /// Real packets: a sender's segments (data, then acks and window probes from the receiver).
    fn conversation(stream: bool) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let (mut a, mut b) = (Kcp::new(7), Kcp::new(7));
        a.set_stream(stream);
        b.set_stream(stream);
        let (mut ab, mut ba) = (Vec::new(), Vec::new());
        a.send(b"hello").unwrap();
        a.send(&[9u8; 3000]).unwrap();
        a.flush(0, &mut |p| ab.push(p.to_vec()));
        for p in &ab {
            let _ = b.input(p, 5);
        }
        while b.recv().is_some() {}
        b.send(b"reply").unwrap();
        b.flush(10, &mut |p| ba.push(p.to_vec()));
        (ab, ba)
    }

    pub(crate) fn kcp_input() -> Vec<Vec<u8>> {
        let (ab, ba) = conversation(false);
        let (sab, _) = conversation(true);
        let mut rev = ab.clone();
        rev.reverse();
        vec![
            [&[0u8][..], &join(&ab)].concat(),
            [&[2u8 | 4 | 0x18][..], &join(&rev)].concat(),
            [&[1u8][..], &join(&sab)].concat(),
            // The receiver's acks, as the sender sees them.
            [&[0u8][..], &join(&[ab.clone(), ba].concat())].concat(),
        ]
    }

    /// Datagrams from a framer with FEC through crypt `c`.
    fn framed(c: u8, d: usize, p: usize) -> Vec<Vec<u8>> {
        let mut fr = Framer::new(d, p).unwrap();
        let (ab, _) = conversation(false);
        let mut out = Vec::new();
        for pk in ab.iter().cycle().take(d * 2) {
            fr.encode(crypt(c), pk, 0, &mut |x| out.push(x));
        }
        out
    }

    pub(crate) fn kcp_frame() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for c in 0..7u8 {
            let mut dg = framed(c, 3, 2);
            dg.remove(1); // a loss for the FEC to repair
            v.push([&[c, 3 | (2 << 4)][..], &join(&dg)].concat());
        }
        v.push([&[6u8, 0][..], &join(&conversation(false).0)].concat());
        v
    }

    pub(crate) fn kcp_fec() -> Vec<Vec<u8>> {
        let mut dg = framed(6, 4, 2);
        dg.remove(0);
        vec![[&[3u8, 1][..], &join(&dg)].concat()]
    }

    pub(crate) fn kcp_crypt() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for c in 0..6u8 {
            let k = crypt(c).unwrap();
            let mut b = vec![0u8; k.header()];
            b.extend_from_slice(b"\x07\x00\x00\x00\x51 a kcp packet");
            v.push([&[c][..], &k.seal(b)].concat());
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        let n = replay(DIR, "kcp_input", kcp_input)
            + replay(DIR, "kcp_fec", kcp_fec)
            + replay(DIR, "kcp_crypt", kcp_crypt)
            + replay(DIR, "kcp_frame", kcp_frame);
        assert!(n > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in &seeds::kcp_input() {
            kcp_input(s);
        }
        for s in &seeds::kcp_fec() {
            kcp_fec(s);
        }
        for s in &seeds::kcp_crypt() {
            kcp_crypt(s);
        }
        for s in &seeds::kcp_frame() {
            kcp_frame(s);
        }
    }

    /// Regenerates the seed files: `cargo test -p only-kcp --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "kcp_input", &seeds::kcp_input());
        write_target_seeds(DIR, "kcp_fec", &seeds::kcp_fec());
        write_target_seeds(DIR, "kcp_crypt", &seeds::kcp_crypt());
        write_target_seeds(DIR, "kcp_frame", &seeds::kcp_frame());
    }
}
