#![no_main]
//! akio-crypto's AES (block, CTR), AES-GCM, ChaCha20-Poly1305 and XChaCha20-Poly1305 against the
//! RustCrypto crates they replaced: same ciphertexts, and the same verdict when opening arbitrary
//! bytes.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::aead::{Aead, Payload};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + 32 + 16 {
        return;
    }
    let klen = [16, 24, 32][usize::from(data[0]) % 3];
    let key = &data[1..1 + klen];
    let iv: [u8; 16] = data[33..49].try_into().unwrap();
    let rest = &data[49..];
    let aad_len = usize::from(data[0] >> 2).min(rest.len());
    let (aad, msg) = rest.split_at(aad_len);
    let nonce: [u8; 12] = iv[..12].try_into().unwrap();

    // Block cipher.
    let ours = akio_crypto::aes::Aes::new(key).unwrap();
    let mut a = iv;
    ours.encrypt_block(&mut a);
    // The CPU's AES instructions (when present) against the portable fixsliced code.
    let soft = akio_crypto::aes::Aes::new_portable(key).unwrap();
    let mut s = iv;
    soft.encrypt_block(&mut s);
    assert_eq!(s, a);
    soft.decrypt_block(&mut s);
    assert_eq!(s, iv);
    let mut b = aes::Block::from(iv);
    let mut c = b;
    match klen {
        16 => {
            let k = aes::Aes128::new_from_slice(key).unwrap();
            k.encrypt_block(&mut b);
            k.decrypt_block(&mut c);
        }
        24 => {
            let k = aes::Aes192::new_from_slice(key).unwrap();
            k.encrypt_block(&mut b);
            k.decrypt_block(&mut c);
        }
        _ => {
            let k = aes::Aes256::new_from_slice(key).unwrap();
            k.encrypt_block(&mut b);
            k.decrypt_block(&mut c);
        }
    }
    assert_eq!(a[..], b[..]);
    let mut d = iv;
    ours.decrypt_block(&mut d);
    assert_eq!(d[..], c[..]);

    // CTR (128-bit big-endian counter).
    if klen == 16 {
        let mut x = msg.to_vec();
        ours.apply_ctr(&iv, &mut x);
        let mut y = msg.to_vec();
        ctr::Ctr128BE::<aes::Aes128>::new(key.into(), (&iv).into()).apply_keystream(&mut y);
        assert_eq!(x, y);
    }

    // AES-GCM (the aes-gcm crate exposes 128 and 256).
    if klen != 24 {
        let gcm = akio_crypto::gcm::AesGcm::new(key).unwrap();
        let sealed = gcm.encrypt(&nonce, aad, msg);
        // Hardware AES / GHASH (fused when both are present) against the portable code.
        let soft_gcm = akio_crypto::gcm::AesGcm::with_cipher_portable(soft.clone());
        assert_eq!(soft_gcm.encrypt(&nonce, aad, msg), sealed);
        assert_eq!(
            soft_gcm.decrypt(&nonce, aad, msg).ok(),
            gcm.decrypt(&nonce, aad, msg).ok()
        );
        let mixed = akio_crypto::gcm::AesGcm::with_cipher(soft.clone());
        assert_eq!(mixed.encrypt(&nonce, aad, msg), sealed);
        // The VAES-AVX2 kernel and the 128-bit AES-NI / PCLMULQDQ one against the default
        // (VAES + VPCLMULQDQ + AVX-512 when the CPU has them), in place and out of place.
        let avx2 = akio_crypto::gcm::AesGcm::with_cipher_avx2(ours.clone());
        let narrow = akio_crypto::gcm::AesGcm::with_cipher_narrow(ours.clone());
        let split = usize::from(data[1]).min(msg.len());
        for k in [&gcm, &avx2, &narrow, &soft_gcm] {
            assert_eq!(k.encrypt(&nonce, aad, msg), sealed);
            assert_eq!(
                k.decrypt(&nonce, aad, msg).ok(),
                gcm.decrypt(&nonce, aad, msg).ok()
            );
            // Out of place (the TLS record layer): part of the plaintext from a separate buffer.
            let mut dst = msg.to_vec();
            let tag = k.encrypt_detached_from(&nonce, aad, &msg[..split], &mut dst);
            assert_eq!(dst[..], sealed[..msg.len()]);
            assert_eq!(tag[..], sealed[msg.len()..]);
            let mut back = vec![0u8; msg.len()];
            k.decrypt_detached_from(&nonce, aad, &dst, &tag, &mut back)
                .unwrap();
            assert_eq!(back, msg);
            // Appended into a vector's spare capacity (not zero-filled), after existing bytes,
            // the plaintext split between `src` and a trailer; a failed open appends nothing.
            let mut out = data[..usize::from(data[2] % 8)].to_vec();
            let head = out.len();
            let tag = k.encrypt_append(&nonce, aad, &msg[..split], &msg[split..], &mut out);
            assert_eq!(out[..head], data[..head]);
            assert_eq!(out[head..], sealed[..msg.len()]);
            assert_eq!(tag[..], sealed[msg.len()..]);
            let before = out.clone();
            let mut bad = tag;
            bad[usize::from(data[3]) % 16] ^= 1 << (data[3] >> 5);
            assert!(
                k.decrypt_append(&nonce, aad, &before[head..], &bad, &mut out)
                    .is_err()
            );
            assert_eq!(out, before);
            k.decrypt_append(&nonce, aad, &before[head..], &tag, &mut out)
                .unwrap();
            assert_eq!(out[..before.len()], before[..]);
            assert_eq!(out[before.len()..], msg[..]);
            // Opening `msg` as a forged ciphertext: the same verdict as `decrypt`.
            if msg.len() >= 16 {
                let (ct, t) = msg.split_at(msg.len() - 16);
                let ok = gcm.decrypt(&nonce, aad, msg).is_ok();
                let mut v = Vec::new();
                assert_eq!(k.decrypt_append(&nonce, aad, ct, t, &mut v).is_ok(), ok);
                assert_eq!(v.len(), if ok { ct.len() } else { 0 });
            }
        }
        let (theirs, opened) = if klen == 16 {
            let g = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
            (
                g.encrypt((&nonce).into(), Payload { msg, aad }).unwrap(),
                g.decrypt((&nonce).into(), Payload { msg, aad }),
            )
        } else {
            let g = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap();
            (
                g.encrypt((&nonce).into(), Payload { msg, aad }).unwrap(),
                g.decrypt((&nonce).into(), Payload { msg, aad }),
            )
        };
        assert_eq!(sealed, theirs);
        assert_eq!(gcm.decrypt(&nonce, aad, &sealed).unwrap(), msg);
        // `msg` as a forged ciphertext: both reject it (or, absurdly, both accept it).
        assert_eq!(gcm.decrypt(&nonce, aad, msg).ok(), opened.ok());
    }

    // ChaCha20-Poly1305.
    if klen == 32 {
        use chacha20poly1305::aead::{Aead as _, KeyInit as _};
        let k: [u8; 32] = key.try_into().unwrap();
        let ours = akio_crypto::chacha::ChaCha20Poly1305::new(&k);
        let theirs = chacha20poly1305::ChaCha20Poly1305::new((&k).into());
        let sealed = ours.encrypt(&nonce, aad, msg);
        // The AVX-512 / IFMA path (the default where the CPU has it) against the AVX2 path and
        // the portable code, in place, out of place and opening forgeries.
        for other in [
            akio_crypto::chacha::ChaCha20Poly1305::new_avx2(&k),
            akio_crypto::chacha::ChaCha20Poly1305::new_portable(&k),
        ] {
            assert_eq!(other.encrypt(&nonce, aad, msg), sealed);
            assert_eq!(
                other.decrypt(&nonce, aad, msg).ok(),
                ours.decrypt(&nonce, aad, msg).ok()
            );
        }
        let split = usize::from(data[1]).min(msg.len());
        let mut dst = msg.to_vec();
        let tag = ours.encrypt_detached_from(&nonce, aad, &msg[..split], &mut dst);
        assert_eq!(dst[..], sealed[..msg.len()]);
        assert_eq!(tag[..], sealed[msg.len()..]);
        let mut back = vec![0u8; msg.len()];
        ours.decrypt_detached_from(&nonce, aad, &dst, &tag, &mut back)
            .unwrap();
        assert_eq!(back, msg);
        // Appended into a vector's spare capacity (not zero-filled) on every path, after
        // existing bytes, the plaintext split between `src` and a trailer; a failed open
        // appends nothing.
        let forged_ok = ours.decrypt(&nonce, aad, msg).is_ok();
        for c in [
            ours.clone(),
            akio_crypto::chacha::ChaCha20Poly1305::new_avx2(&k),
            akio_crypto::chacha::ChaCha20Poly1305::new_portable(&k),
        ] {
            let mut out = data[..usize::from(data[2] % 8)].to_vec();
            let head = out.len();
            let tag = c.encrypt_append(&nonce, aad, &msg[..split], &msg[split..], &mut out);
            assert_eq!(out[..head], data[..head]);
            assert_eq!(out[head..], sealed[..msg.len()]);
            assert_eq!(tag[..], sealed[msg.len()..]);
            let before = out.clone();
            let mut bad = tag;
            bad[usize::from(data[3]) % 16] ^= 1 << (data[3] >> 5);
            assert!(
                c.decrypt_append(&nonce, aad, &before[head..], &bad, &mut out)
                    .is_err()
            );
            assert_eq!(out, before);
            c.decrypt_append(&nonce, aad, &before[head..], &tag, &mut out)
                .unwrap();
            assert_eq!(out[..before.len()], before[..]);
            assert_eq!(out[before.len()..], msg[..]);
            if msg.len() >= 16 {
                let (ct, t) = msg.split_at(msg.len() - 16);
                let mut v = Vec::new();
                assert_eq!(
                    c.decrypt_append(&nonce, aad, ct, t, &mut v).is_ok(),
                    forged_ok
                );
                assert_eq!(v.len(), if forged_ok { ct.len() } else { 0 });
            }
        }
        assert_eq!(
            sealed,
            theirs
                .encrypt(
                    (&nonce).into(),
                    chacha20poly1305::aead::Payload { msg, aad }
                )
                .unwrap()
        );
        assert_eq!(
            ours.decrypt(&nonce, aad, msg).ok(),
            theirs
                .decrypt(
                    (&nonce).into(),
                    chacha20poly1305::aead::Payload { msg, aad }
                )
                .ok()
        );

        // XChaCha20-Poly1305: a 24-byte nonce of the 12-byte one and the key's first 12 bytes.
        let mut xn = [0u8; 24];
        xn[..12].copy_from_slice(&nonce);
        xn[12..].copy_from_slice(&k[..12]);
        let ours = akio_crypto::chacha::XChaCha20Poly1305::new(&k);
        let theirs = chacha20poly1305::XChaCha20Poly1305::new((&k).into());
        let payload = || chacha20poly1305::aead::Payload { msg, aad };
        let sealed = ours.encrypt(&xn, aad, msg);
        assert_eq!(sealed, theirs.encrypt((&xn).into(), payload()).unwrap());
        assert_eq!(ours.decrypt(&xn, aad, &sealed).unwrap(), msg);
        assert_eq!(
            ours.decrypt(&xn, aad, msg).ok(),
            theirs.decrypt((&xn).into(), payload()).ok()
        );
    }
});
