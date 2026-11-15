#![no_main]
//! only-crypto's AES (block, CTR), AES-GCM and ChaCha20-Poly1305 against the RustCrypto crates
//! they replaced: same ciphertexts, and the same verdict when opening arbitrary bytes.

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
    let ours = only_crypto::aes::Aes::new(key).unwrap();
    let mut a = iv;
    ours.encrypt_block(&mut a);
    // The CPU's AES instructions (when present) against the portable fixsliced code.
    let soft = only_crypto::aes::Aes::new_portable(key).unwrap();
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
        let gcm = only_crypto::gcm::AesGcm::new(key).unwrap();
        let sealed = gcm.encrypt(&nonce, aad, msg);
        // Hardware AES / GHASH (fused when both are present) against the portable code.
        let soft_gcm = only_crypto::gcm::AesGcm::with_cipher_portable(soft.clone());
        assert_eq!(soft_gcm.encrypt(&nonce, aad, msg), sealed);
        assert_eq!(
            soft_gcm.decrypt(&nonce, aad, msg).ok(),
            gcm.decrypt(&nonce, aad, msg).ok()
        );
        let mixed = only_crypto::gcm::AesGcm::with_cipher(soft.clone());
        assert_eq!(mixed.encrypt(&nonce, aad, msg), sealed);
        // The VAES-AVX2 kernel and the 128-bit AES-NI / PCLMULQDQ one against the default
        // (VAES + VPCLMULQDQ + AVX-512 when the CPU has them), in place and out of place.
        let avx2 = only_crypto::gcm::AesGcm::with_cipher_avx2(ours.clone());
        let narrow = only_crypto::gcm::AesGcm::with_cipher_narrow(ours.clone());
        let split = usize::from(data[1]).min(msg.len());
        for k in [&gcm, &avx2, &narrow] {
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
        }
        let (theirs, opened) = if klen == 16 {
            let g = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
            (g.encrypt((&nonce).into(), Payload { msg, aad }).unwrap(), g.decrypt((&nonce).into(), Payload { msg, aad }))
        } else {
            let g = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap();
            (g.encrypt((&nonce).into(), Payload { msg, aad }).unwrap(), g.decrypt((&nonce).into(), Payload { msg, aad }))
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
        let ours = only_crypto::chacha::ChaCha20Poly1305::new(&k);
        let theirs = chacha20poly1305::ChaCha20Poly1305::new((&k).into());
        let sealed = ours.encrypt(&nonce, aad, msg);
        // The AVX-512 / IFMA path (the default where the CPU has it) against the AVX2 path and
        // the portable code, in place, out of place and opening forgeries.
        for other in [
            only_crypto::chacha::ChaCha20Poly1305::new_avx2(&k),
            only_crypto::chacha::ChaCha20Poly1305::new_portable(&k),
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
        assert_eq!(
            sealed,
            theirs
                .encrypt((&nonce).into(), chacha20poly1305::aead::Payload { msg, aad })
                .unwrap()
        );
        assert_eq!(
            ours.decrypt(&nonce, aad, msg).ok(),
            theirs
                .decrypt((&nonce).into(), chacha20poly1305::aead::Payload { msg, aad })
                .ok()
        );
    }
});
