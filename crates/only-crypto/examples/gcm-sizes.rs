//! AES-GCM throughput by message size, `only-crypto` against ring (a dev-dependency):
//!
//! ```text
//! cargo run --release -p only-crypto --example gcm-sizes [MS]
//! ```
//!
//! For AES-128 and AES-256, seal and open of 64 B, 1 KiB, 1400 B (a QUIC packet), 16 KiB (a
//! full TLS record) and 64 KiB, with 13 bytes of AAD (a TLS 1.3 record header is 5): the default
//! key (the widest kernel this CPU has: VAES + VPCLMULQDQ + AVX-512 on x86_64), the VAES-AVX2
//! kernel of CPUs without AVX-512 (`avx2`, forced), the 128-bit AES-NI + PCLMULQDQ kernel
//! (`narrow`) and ring. Open copies the sealed message into the working buffer first on every
//! side (a successful open leaves plaintext behind). Each case runs for `MS` milliseconds
//! (default 300); MB/s of message bytes.

use std::hint::black_box;
use std::time::{Duration, Instant};

use only_crypto::aes::Aes;
use only_crypto::gcm::AesGcm;
use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

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
    for (klen, alg) in [(16, &AES_128_GCM), (32, &AES_256_GCM)] {
        let key = vec![7u8; klen];
        let wide = AesGcm::new(&key).expect("key");
        let avx2 = AesGcm::with_cipher_avx2(Aes::new(&key).expect("key"));
        let narrow = AesGcm::with_cipher_narrow(Aes::new(&key).expect("key"));
        let ring = LessSafeKey::new(UnboundKey::new(alg, &key).expect("key"));
        println!(
            "AES-{}-GCM (kernels: only {}, avx2 {}, narrow {})",
            klen * 8,
            wide.kernel(),
            avx2.kernel(),
            narrow.kernel()
        );
        for len in [64usize, 1024, 1400, 16 * 1024, 64 * 1024] {
            let mut buf = vec![0x5au8; len];
            let mut rbuf = buf.clone();
            let w = rate(ms, len, || {
                black_box(wide.encrypt_in_place_detached(&nonce, &aad, black_box(&mut buf)));
            });
            let a = rate(ms, len, || {
                black_box(avx2.encrypt_in_place_detached(&nonce, &aad, black_box(&mut buf)));
            });
            let n = rate(ms, len, || {
                black_box(narrow.encrypt_in_place_detached(&nonce, &aad, black_box(&mut buf)));
            });
            let r = rate(ms, len, || {
                let tag = ring
                    .seal_in_place_separate_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(&aad),
                        black_box(&mut rbuf),
                    )
                    .expect("seal");
                black_box(tag.as_ref());
            });
            println!(
                "  seal {len:>6} B  only {w:>8.0}  avx2 {a:>8.0}  narrow {n:>8.0}  ring {r:>8.0} MB/s  only/ring {:.2}  avx2/narrow {:.2}",
                w / r,
                a / n
            );

            let pt = vec![0xa5u8; len];
            let mut sealed = pt.clone();
            let tag = wide.encrypt_in_place_detached(&nonce, &aad, &mut sealed);
            let mut rsealed = pt;
            let rtag = ring
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut rsealed,
                )
                .expect("seal");
            rsealed.extend_from_slice(rtag.as_ref());
            let mut work = sealed.clone();
            let mut rwork = rsealed.clone();
            let w = rate(ms, len, || {
                work.copy_from_slice(&sealed);
                wide.decrypt_in_place_detached(&nonce, &aad, black_box(&mut work), &tag)
                    .expect("open");
            });
            let a = rate(ms, len, || {
                work.copy_from_slice(&sealed);
                avx2.decrypt_in_place_detached(&nonce, &aad, black_box(&mut work), &tag)
                    .expect("open");
            });
            let n = rate(ms, len, || {
                work.copy_from_slice(&sealed);
                narrow
                    .decrypt_in_place_detached(&nonce, &aad, black_box(&mut work), &tag)
                    .expect("open");
            });
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
            println!(
                "  open {len:>6} B  only {w:>8.0}  avx2 {a:>8.0}  narrow {n:>8.0}  ring {r:>8.0} MB/s  only/ring {:.2}  avx2/narrow {:.2}",
                w / r,
                a / n
            );
        }
    }
}
