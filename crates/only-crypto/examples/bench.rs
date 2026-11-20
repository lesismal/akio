//! Throughput of `only-crypto` next to the crates it replaced (dev-dependencies):
//!
//! ```text
//! cargo run --release -p only-crypto --example bench
//! ```
//!
//! Both sides detect CPU features at run time (SHA-NI / ARMv8 SHA, AES-NI / ARMv8 AES,
//! PCLMULQDQ / PMULL, CRC32 instructions, AVX2; the `aes` crate uses ARMv8 AES only with
//! `--cfg aes_armv8`). The "portable" rows force `only-crypto`'s constant-time software AES and
//! GHASH; `ONLY_CRYPTO_PORTABLE=1` forces the portable code everywhere.

use std::hint::black_box;
use std::time::{Duration, Instant};

/// Runs `f` (which processes `bytes` bytes) for about 300 ms and returns MB/s.
fn rate(bytes: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    let mut n = 0u64;
    while start.elapsed() < Duration::from_millis(300) {
        for _ in 0..16 {
            f();
        }
        n += 16;
    }
    (n as f64 * bytes as f64) / start.elapsed().as_secs_f64() / 1e6
}

fn row(name: &str, bytes: usize, ours: f64, theirs: f64) {
    println!(
        "{name:<34} {bytes:>6} B  only-crypto {ours:>9.1} MB/s   old {theirs:>9.1} MB/s   ratio {:>5.2}",
        ours / theirs
    );
}

fn row1(name: &str, bytes: usize, ours: f64) {
    println!("{name:<34} {bytes:>6} B  only-crypto {ours:>9.1} MB/s");
}

fn main() {
    use aes::cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
    use aes_gcm::aead::AeadInPlace;
    use hmac::Mac;
    use sha2::Digest;

    println!(
        "only-crypto hardware paths: [{}]",
        only_crypto::hardware_features()
    );
    let big = vec![0x5au8; 16 * 1024];
    let pkt = vec![0xa5u8; 1400];
    let stun = vec![0x11u8; 100];
    let piece = vec![0x3cu8; 256 * 1024];

    row(
        "SHA-1",
        big.len(),
        rate(big.len(), || {
            black_box(only_crypto::hash::Sha1::digest(black_box(&big)));
        }),
        rate(big.len(), || {
            black_box(sha1::Sha1::digest(black_box(&big)));
        }),
    );
    row(
        "SHA-256",
        big.len(),
        rate(big.len(), || {
            black_box(only_crypto::hash::Sha256::digest(black_box(&big)));
        }),
        rate(big.len(), || {
            black_box(sha2::Sha256::digest(black_box(&big)));
        }),
    );
    row(
        "SHA-1 BitTorrent piece",
        piece.len(),
        rate(piece.len(), || {
            black_box(only_crypto::hash::Sha1::digest(black_box(&piece)));
        }),
        rate(piece.len(), || {
            black_box(sha1::Sha1::digest(black_box(&piece)));
        }),
    );
    row(
        "SHA-256",
        pkt.len(),
        rate(pkt.len(), || {
            black_box(only_crypto::hash::Sha256::digest(black_box(&pkt)));
        }),
        rate(pkt.len(), || {
            black_box(sha2::Sha256::digest(black_box(&pkt)));
        }),
    );
    row(
        "SHA-512",
        big.len(),
        rate(big.len(), || {
            black_box(only_crypto::hash::Sha512::digest(black_box(&big)));
        }),
        rate(big.len(), || {
            black_box(sha2::Sha512::digest(black_box(&big)));
        }),
    );
    row(
        "MD5",
        big.len(),
        rate(big.len(), || {
            black_box(only_crypto::hash::Md5::digest(black_box(&big)));
        }),
        rate(big.len(), || {
            black_box(md5::Md5::digest(black_box(&big)));
        }),
    );
    row(
        "CRC-32",
        pkt.len(),
        rate(pkt.len(), || {
            black_box(only_crypto::crc::crc32(black_box(&pkt)));
        }),
        rate(pkt.len(), || {
            black_box(crc32fast::hash(black_box(&pkt)));
        }),
    );
    row(
        "CRC-32",
        big.len(),
        rate(big.len(), || {
            black_box(only_crypto::crc::crc32(black_box(&big)));
        }),
        rate(big.len(), || {
            black_box(crc32fast::hash(black_box(&big)));
        }),
    );
    row1(
        "CRC-32C",
        pkt.len(),
        rate(pkt.len(), || {
            black_box(only_crypto::crc::crc32c(black_box(&pkt)));
        }),
    );
    row(
        "HMAC-SHA1 (STUN message)",
        stun.len(),
        rate(stun.len(), || {
            black_box(only_crypto::mac::Hmac::<only_crypto::hash::Sha1>::mac(
                b"key",
                black_box(&stun),
            ));
        }),
        rate(stun.len(), || {
            let mut m = <hmac::Hmac<sha1::Sha1> as Mac>::new_from_slice(b"key").unwrap();
            m.update(black_box(&stun));
            black_box(m.finalize());
        }),
    );

    let key = [7u8; 16];
    let ours = only_crypto::aes::Aes::new(&key).unwrap();
    let theirs = aes::Aes128::new(&key.into());
    row(
        "AES-128 one block (CFB chain)",
        16,
        rate(16, || {
            let mut b = [1u8; 16];
            ours.encrypt_block(black_box(&mut b));
            black_box(b);
        }),
        rate(16, || {
            let mut b = aes::Block::from([1u8; 16]);
            theirs.encrypt_block(black_box(&mut b));
            black_box(b);
        }),
    );
    let mut buf = pkt.clone();
    let mut buf2 = pkt.clone();
    row(
        "AES-128-CTR",
        pkt.len(),
        rate(pkt.len(), || {
            ours.apply_ctr(&[3; 16], black_box(&mut buf));
        }),
        rate(pkt.len(), || {
            ctr::Ctr128BE::<aes::Aes128>::new(&key.into(), &[3; 16].into())
                .apply_keystream(black_box(&mut buf2));
        }),
    );
    // The portable (fixsliced, constant-time) path, as on CPUs without AES instructions.
    let soft = only_crypto::aes::Aes::new_portable(&key).unwrap();
    row(
        "AES-128 one block, portable",
        16,
        rate(16, || {
            let mut b = [1u8; 16];
            soft.encrypt_block(black_box(&mut b));
            black_box(b);
        }),
        rate(16, || {
            let mut b = aes::Block::from([1u8; 16]);
            theirs.encrypt_block(black_box(&mut b));
            black_box(b);
        }),
    );
    row(
        "AES-128-CTR, portable",
        pkt.len(),
        rate(pkt.len(), || {
            soft.apply_ctr(&[3; 16], black_box(&mut buf));
        }),
        rate(pkt.len(), || {
            ctr::Ctr128BE::<aes::Aes128>::new(&key.into(), &[3; 16].into())
                .apply_keystream(black_box(&mut buf2));
        }),
    );
    let gcm_soft = only_crypto::gcm::AesGcm::with_cipher_portable(soft);
    let gcm = only_crypto::gcm::AesGcm::new(&key).unwrap();
    let gcm2 = aes_gcm::Aes128Gcm::new(&key.into());
    row(
        "AES-128-GCM seal, portable",
        pkt.len(),
        rate(pkt.len(), || {
            black_box(gcm_soft.encrypt_in_place_detached(&[1; 12], b"", black_box(&mut buf)));
        }),
        rate(pkt.len(), || {
            black_box(
                gcm2.encrypt_in_place_detached((&[1; 12]).into(), b"", black_box(&mut buf2))
                    .unwrap(),
            );
        }),
    );
    row(
        "AES-128-GCM seal",
        pkt.len(),
        rate(pkt.len(), || {
            black_box(gcm.encrypt_in_place_detached(&[1; 12], b"", black_box(&mut buf)));
        }),
        rate(pkt.len(), || {
            black_box(
                gcm2.encrypt_in_place_detached((&[1; 12]).into(), b"", black_box(&mut buf2))
                    .unwrap(),
            );
        }),
    );
    let mut bbuf = big.clone();
    let mut bbuf2 = big.clone();
    row(
        "AES-128-CTR",
        big.len(),
        rate(big.len(), || {
            ours.apply_ctr(&[3; 16], black_box(&mut bbuf));
        }),
        rate(big.len(), || {
            ctr::Ctr128BE::<aes::Aes128>::new(&key.into(), &[3; 16].into())
                .apply_keystream(black_box(&mut bbuf2));
        }),
    );
    row(
        "AES-128-GCM seal",
        big.len(),
        rate(big.len(), || {
            black_box(gcm.encrypt_in_place_detached(&[1; 12], b"", black_box(&mut bbuf)));
        }),
        rate(big.len(), || {
            black_box(
                gcm2.encrypt_in_place_detached((&[1; 12]).into(), b"", black_box(&mut bbuf2))
                    .unwrap(),
            );
        }),
    );
    let tag = gcm.encrypt_in_place_detached(&[1; 12], b"", &mut bbuf);
    let tag2 = gcm2
        .encrypt_in_place_detached((&[1; 12]).into(), b"", &mut bbuf2)
        .unwrap();
    row(
        "AES-128-GCM open",
        big.len(),
        rate(big.len(), || {
            // Decrypting twice restores the ciphertext only for valid tags, so verify the same
            // buffer each time: the tag check runs before decryption, and the result is ignored.
            let mut b = bbuf.clone();
            black_box(gcm.decrypt_in_place_detached(&[1; 12], b"", black_box(&mut b), &tag))
                .unwrap();
        }),
        rate(big.len(), || {
            let mut b = bbuf2.clone();
            black_box(gcm2.decrypt_in_place_detached(
                (&[1; 12]).into(),
                b"",
                black_box(&mut b),
                &tag2,
            ))
            .unwrap();
        }),
    );
    let gcm256 = only_crypto::gcm::AesGcm::new(&[7u8; 32]).unwrap();
    let gcm256b = aes_gcm::Aes256Gcm::new(&[7u8; 32].into());
    row(
        "AES-256-GCM seal",
        big.len(),
        rate(big.len(), || {
            black_box(gcm256.encrypt_in_place_detached(&[1; 12], b"", black_box(&mut bbuf)));
        }),
        rate(big.len(), || {
            black_box(
                gcm256b
                    .encrypt_in_place_detached((&[1; 12]).into(), b"", black_box(&mut bbuf2))
                    .unwrap(),
            );
        }),
    );
    let cp = only_crypto::chacha::ChaCha20Poly1305::new(&[9; 32]);
    let cp2 = {
        use chacha20poly1305::KeyInit;
        chacha20poly1305::ChaCha20Poly1305::new(&[9; 32].into())
    };
    row(
        "ChaCha20-Poly1305 seal",
        pkt.len(),
        rate(pkt.len(), || {
            black_box(cp.encrypt_in_place_detached(&[1; 12], b"", black_box(&mut buf)));
        }),
        rate(pkt.len(), || {
            use chacha20poly1305::AeadInPlace;
            black_box(
                cp2.encrypt_in_place_detached((&[1; 12]).into(), b"", black_box(&mut buf2))
                    .unwrap(),
            );
        }),
    );
    row(
        "ChaCha20-Poly1305 seal",
        big.len(),
        rate(big.len(), || {
            black_box(cp.encrypt_in_place_detached(&[1; 12], b"", black_box(&mut bbuf)));
        }),
        rate(big.len(), || {
            use chacha20poly1305::AeadInPlace;
            black_box(
                cp2.encrypt_in_place_detached((&[1; 12]).into(), b"", black_box(&mut bbuf2))
                    .unwrap(),
            );
        }),
    );
    row(
        "base64 encode",
        pkt.len(),
        rate(pkt.len(), || {
            black_box(only_crypto::base64::STANDARD.encode(black_box(&pkt)));
        }),
        rate(pkt.len(), || {
            use base64::Engine;
            black_box(base64::engine::general_purpose::STANDARD.encode(black_box(&pkt)));
        }),
    );
    // SEED (bitsliced, constant time; no reference crate to compare with).
    let seed = only_crypto::seed::Seed::new(&[5; 16]);
    row1(
        "SEED one block",
        16,
        rate(16, || {
            let mut b = [1u8; 16];
            seed.encrypt_block(black_box(&mut b));
            black_box(b);
        }),
    );
    let mut sbuf = vec![0u8; 1200];
    row1(
        "SEED-CTR",
        1200,
        rate(1200, || seed.apply_ctr(&[3; 16], black_box(&mut sbuf))),
    );
    let seed_gcm = only_crypto::seed::SeedGcm::new(&[5; 16]);
    row1(
        "SEED-GCM seal",
        1200,
        rate(1200, || {
            black_box(seed_gcm.encrypt_in_place_detached(&[1; 12], &[2; 12], black_box(&mut sbuf)));
        }),
    );
    let seed_ccm = only_crypto::seed::SeedCcm::new(&[5; 16]);
    row1(
        "SEED-CCM seal",
        1200,
        rate(1200, || {
            let mut tag = [0u8; 10];
            seed_ccm
                .encrypt_in_place_detached(&[1; 12], &[2; 12], black_box(&mut sbuf), &mut tag)
                .unwrap();
            black_box(tag);
        }),
    );
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let t = Instant::now();
    only_crypto::kdf::pbkdf2_hmac::<only_crypto::hash::Sha1>(
        b"passphrase",
        b"kcp-go",
        4096,
        &mut k1,
    );
    let ours = t.elapsed();
    let t = Instant::now();
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"passphrase", b"kcp-go", 4096, &mut k2);
    let theirs = t.elapsed();
    assert_eq!(k1, k2);
    println!("PBKDF2-HMAC-SHA1 4096 rounds (kcptun key): only-crypto {ours:?}, old {theirs:?}");
}
