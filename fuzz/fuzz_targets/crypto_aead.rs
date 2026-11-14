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
        let soft_gcm = only_crypto::gcm::AesGcm::with_cipher(soft.clone());
        assert_eq!(soft_gcm.encrypt(&nonce, aad, msg), sealed);
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
