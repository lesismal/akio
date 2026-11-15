//! ChaCha20-Poly1305 throughput by message size, `only-crypto` against ring (a dev-dependency):
//!
//! ```text
//! cargo run --release -p only-crypto --example chacha-sizes [MS]
//! ```
//!
//! Seal and open of 64 B, 1 KiB, 1400 B (a QUIC packet), 16 KiB (a full TLS record) and 64 KiB
//! with 13 bytes of AAD: the default key (the widest path this CPU has: ChaCha20 on AVX-512 and
//! Poly1305 on AVX-512 IFMA on x86_64), the AVX2 path (`avx2`: eight-block ChaCha20, scalar
//! Poly1305), the portable code and ring. Open copies the sealed message into the working buffer
//! first on every side. Then the two halves alone at 16 KiB: the ChaCha20 stream and Poly1305.
//! Each case runs for `MS` milliseconds (default 300); MB/s of message bytes.

use std::hint::black_box;
use std::time::{Duration, Instant};

use only_crypto::chacha::{ChaCha20, ChaCha20Poly1305, Poly1305};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

fn rate(ms: u64, bytes: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..16 {
        f();
    }
    let start = Instant::now();
    let mut n = 0u64;
    while start.elapsed() < Duration::from_millis(ms) {
        for _ in 0..16 {
            f();
        }
        n += 16;
    }
    (n as f64 * bytes as f64) / start.elapsed().as_secs_f64() / 1e6
}

fn main() {
    let ms = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(300u64);
    println!(
        "only-crypto hardware paths: [{}]",
        only_crypto::hardware_features()
    );
    let nonce = [1u8; 12];
    let aad = [0x17u8; 13];
    let key = [7u8; 32];
    let ours = [
        ("only", ChaCha20Poly1305::new(&key)),
        ("avx2", ChaCha20Poly1305::new_avx2(&key)),
        ("portable", ChaCha20Poly1305::new_portable(&key)),
    ];
    let ring = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).expect("key"));
    // `PROFILE_LEN=n`: seal n-byte messages with one key only (`PROFILE_KEY`: 0 the default,
    // 1 AVX2, 2 portable), for a profiler.
    if let Some(len) = std::env::var("PROFILE_LEN")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        let i: usize = std::env::var("PROFILE_KEY")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut buf = vec![0x5au8; len];
        let r = rate(ms, len, || {
            black_box(
                ours[i]
                    .1
                    .encrypt_in_place_detached(&nonce, &aad, black_box(&mut buf)),
            );
        });
        println!("  seal {len:>6} B  {} {r:.0} MB/s", ours[i].0);
        return;
    }
    for len in [64usize, 1024, 1400, 16 * 1024, 64 * 1024] {
        let mut buf = vec![0x5au8; len];
        let mut line = format!("  seal {len:>6} B ");
        let mut first = 0.0;
        for (name, k) in &ours {
            let r = rate(ms, len, || {
                black_box(k.encrypt_in_place_detached(&nonce, &aad, black_box(&mut buf)));
            });
            if first == 0.0 {
                first = r;
            }
            line += &format!(" {name} {r:>7.0}");
        }
        let r = rate(ms, len, || {
            let tag = ring
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    black_box(&mut buf),
                )
                .expect("seal");
            black_box(tag.as_ref());
        });
        println!("{line}  ring {r:>7.0} MB/s  only/ring {:.2}", first / r);

        let mut sealed = vec![0xa5u8; len];
        let tag = ours[0]
            .1
            .encrypt_in_place_detached(&nonce, &aad, &mut sealed);
        let mut work = sealed.clone();
        let mut line = format!("  open {len:>6} B ");
        let mut first = 0.0;
        for (name, k) in &ours {
            let r = rate(ms, len, || {
                work.copy_from_slice(&sealed);
                k.decrypt_in_place_detached(&nonce, &aad, black_box(&mut work), &tag)
                    .expect("open");
            });
            if first == 0.0 {
                first = r;
            }
            line += &format!(" {name} {r:>7.0}");
        }
        let mut rsealed = sealed.clone();
        rsealed.extend_from_slice(&tag);
        let mut rwork = rsealed.clone();
        let r = rate(ms, len, || {
            rwork.copy_from_slice(&rsealed);
            black_box(
                ring.open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    black_box(&mut rwork),
                )
                .expect("open"),
            );
        });
        println!("{line}  ring {r:>7.0} MB/s  only/ring {:.2}", first / r);
    }
    let mut big = vec![0x3cu8; 16 * 1024];
    let c = rate(ms, big.len(), || {
        ChaCha20::new(&key, &nonce, 1).apply_keystream(black_box(&mut big));
    });
    let p = rate(ms, big.len(), || {
        black_box(Poly1305::mac(&key, black_box(&big)));
    });
    println!("  16 KiB alone: ChaCha20 {c:.0} MB/s  Poly1305 {p:.0} MB/s");
}
