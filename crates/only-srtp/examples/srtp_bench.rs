//! SRTP protect / unprotect cost per packet, per profile and payload size (one SSRC, packets
//! in order, batches of 1024). Prints ns per packet and MB/s of RTP; used for before/after
//! comparisons of the SRTP data path.
//!
//!   cargo run --release -p only-srtp --example srtp_bench [packets per case, default 200000]
//!       [filter: only cases whose name contains it]

use std::hint::black_box;
use std::time::{Duration, Instant};

use only_srtp::{Context, Profile};

const BATCH: usize = 1024;

fn rtp(seq: u16, payload: usize, ext: bool) -> Vec<u8> {
    let mut p = vec![0x80, 96];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 3000).to_be_bytes());
    p.extend_from_slice(&0x1234_5678u32.to_be_bytes());
    if ext {
        // A CSRC and a one-byte extension (audio level, transport-wide sequence number, MID).
        p[0] |= 0x11;
        p.extend_from_slice(&0xc0ff_ee00u32.to_be_bytes());
        p.extend_from_slice(&[
            0xbe, 0xde, 0, 3, 0x10, 0x80, 0x21, 0, 7, 0x30, b'0', 0, 0, 0, 0, 0,
        ]);
    }
    p.resize(p.len() + payload, 0x5a);
    p
}

/// Best of 5 runs: (protect ns/packet, unprotect ns/packet).
fn run(mk: &dyn Fn() -> Context, payload: usize, ext: bool, n: usize) -> (f64, f64) {
    let mut best = (f64::MAX, f64::MAX);
    for _ in 0..5 {
        let (mut tx, mut rx) = (mk(), mk());
        let (mut tp, mut tu) = (Duration::ZERO, Duration::ZERO);
        let mut seq = 0u16;
        let plain: Vec<Vec<u8>> = (0..BATCH).map(|i| rtp(i as u16, payload, ext)).collect();
        let mut done = 0;
        while done < n {
            let mut batch = plain.clone();
            for p in &mut batch {
                p[2..4].copy_from_slice(&seq.to_be_bytes());
                seq = seq.wrapping_add(1);
            }
            let t = Instant::now();
            let sealed: Vec<Vec<u8>> = batch
                .iter()
                .map(|p| tx.protect_rtp(p).expect("protect"))
                .collect();
            tp += t.elapsed();
            let t = Instant::now();
            for s in &sealed {
                black_box(rx.unprotect_rtp(s).expect("unprotect"));
            }
            tu += t.elapsed();
            done += BATCH;
        }
        let per = |d: Duration| d.as_nanos() as f64 / done as f64;
        best = (best.0.min(per(tp)), best.1.min(per(tu)));
    }
    best
}

fn report(name: &str, payload: usize, size: usize, (p, u): (f64, f64)) {
    let mbs = |ns: f64| size as f64 / ns * 1e3;
    println!(
        "{name:<34} {payload:>5} B  protect {p:>7.1} ns {:>7.0} MB/s  unprotect {u:>7.1} ns {:>7.0} MB/s",
        mbs(p),
        mbs(u)
    );
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(200_000);
    let filter = std::env::args().nth(2).unwrap_or_default();
    let profiles = [
        Profile::AeadAes128Gcm,
        Profile::AeadAes256Gcm,
        Profile::Aes128CmHmacSha1_80,
        Profile::Aes128CmHmacSha1_32,
    ];
    for profile in profiles {
        let key = vec![7u8; profile.key_len()];
        let salt = vec![9u8; profile.salt_len()];
        for payload in [160, 1200] {
            for ext in [false, true] {
                let mk = || Context::new(profile, &key, &salt).expect("context");
                let name = format!("{}{}", profile.name(), if ext { " +ext" } else { "" });
                if !format!("{name} {payload}").contains(&filter) {
                    continue;
                }
                report(
                    &name,
                    payload,
                    rtp(0, payload, ext).len(),
                    run(&mk, payload, ext, n),
                );
            }
        }
    }
    // NEW-API-BEGIN (stripped for runs against releases without these features)
    // AES-f8 and SEED (ADR-052): f8 chains its blocks; SEED is bitsliced, sixteen blocks at a
    // time (CCM's CBC-MAC one at a time).
    for profile in [
        Profile::AesF8HmacSha1_80,
        Profile::SeedCtrHmacSha1_80,
        Profile::SeedGcm96,
        Profile::SeedCcm80,
    ] {
        let key = vec![7u8; profile.key_len()];
        let salt = vec![9u8; profile.salt_len()];
        for payload in [160, 1200] {
            let mk = || Context::new(profile, &key, &salt).expect("context");
            let name = profile.name();
            if !format!("{name} {payload}").contains(&filter) {
                continue;
            }
            let n = if profile == Profile::SeedCcm80 {
                n / 8
            } else {
                n / 2
            };
            report(
                name,
                payload,
                rtp(0, payload, false).len(),
                run(&mk, payload, false, n.max(BATCH)),
            );
        }
    }
    if !filter.is_empty() {
        return;
    }
    for profile in [
        Profile::AeadAes128Gcm,
        Profile::Aes128CmHmacSha1_80,
        Profile::Aes256CmHmacSha1_80,
        Profile::NullHmacSha1_80,
    ] {
        let key = vec![7u8; profile.key_len()];
        let salt = vec![9u8; profile.salt_len()];
        let size = rtp(0, 1200, true).len();
        type Make<'a> = Box<dyn Fn() -> Context + 'a>;
        let variants: [(&str, Make<'_>); 4] = [
            (
                "plain",
                Box::new(|| Context::new(profile, &key, &salt).expect("context")),
            ),
            (
                "mki",
                Box::new(|| {
                    Context::new_with_mki(profile, &[1, 2, 3, 4], &key, &salt).expect("mki")
                }),
            ),
            (
                "cryptex",
                Box::new(|| {
                    Context::new(profile, &key, &salt)
                        .expect("context")
                        .with_cryptex(true)
                }),
            ),
            (
                "rfc6904",
                Box::new(|| {
                    Context::new(profile, &key, &salt)
                        .expect("context")
                        .with_encrypted_header_extensions(&[1, 2, 3])
                }),
            ),
        ];
        for (what, mk) in &variants {
            let name = format!("{} {what}", profile.name());
            report(&name, 1200, size, run(mk.as_ref(), 1200, true, n));
        }
    }
    // Allocation-free variants with reused buffers.
    for profile in [Profile::AeadAes128Gcm, Profile::Aes128CmHmacSha1_80] {
        let key = vec![7u8; profile.key_len()];
        let salt = vec![9u8; profile.salt_len()];
        let (mut tx, mut rx) = (
            Context::new(profile, &key, &salt).expect("context"),
            Context::new(profile, &key, &salt).expect("context"),
        );
        let mut p = rtp(0, 1200, false);
        let (mut a, mut b) = (Vec::with_capacity(1400), Vec::with_capacity(1400));
        let t = Instant::now();
        for i in 0..n {
            p[2..4].copy_from_slice(&(i as u16).to_be_bytes());
            tx.protect_rtp_into(&p, &mut a).expect("protect");
            rx.unprotect_rtp_into(&a, &mut b).expect("unprotect");
        }
        let ns = t.elapsed().as_nanos() as f64 / n as f64;
        println!(
            "{:<34}  1200 B  protect+unprotect into reused buffers {ns:>7.1} ns",
            profile.name()
        );
    }
    // NEW-API-END
}
