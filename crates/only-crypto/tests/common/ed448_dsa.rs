//! The `crypto_ed448_dsa` fuzz target's checks, shared with the stable replay in
//! `tests/ed448_dsa.rs`. The first byte selects what the rest is:
//!
//! - 0: Ed448: a 57-byte seed and a message: sign, verify, and reject a corrupted signature;
//!   the same bytes as a public key and a signature never panic.
//! - 1: X448: two 56-byte scalars: Diffie-Hellman agrees both ways.
//! - 2: DSA: length-prefixed (two bytes, big-endian) `Dss-Parms`, `INTEGER y` and digest, then
//!   a DER signature: key checks and verification never panic.
//! - 3: SubjectPublicKeyInfo / PKCS#8 parsing and SHAKE256 (incremental equals one-shot).

use only_crypto::hash::Shake256;
use only_crypto::{dsa, ed448, pkey, x448};

fn take<'a>(d: &mut &'a [u8]) -> &'a [u8] {
    if d.len() < 2 {
        return &[];
    }
    let n = usize::from(u16::from_be_bytes([d[0], d[1]])).min(d.len() - 2);
    let (a, b) = d[2..].split_at(n);
    *d = b;
    a
}

pub(crate) fn check(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => {
            let mut seed = [0u8; 57];
            let n = rest.len().min(57);
            seed[..n].copy_from_slice(&rest[..n]);
            let msg = &rest[n..];
            let k = ed448::SigningKey::from_seed(&seed);
            let sig = k.sign(msg);
            let vk = k.verifying_key();
            assert!(vk.verify(msg, &sig).is_ok());
            let mut bad = sig;
            bad[usize::from(seed[0]) % 114] ^= 1 << (seed[1] % 8);
            assert!(vk.verify(msg, &bad).is_err());
            let back = ed448::VerifyingKey::from_bytes(vk.as_bytes()).unwrap();
            assert_eq!(back, vk);
            assert!(!back.is_weak());
            // Arbitrary bytes as a key and a signature.
            if let Ok(pk) = ed448::VerifyingKey::from_bytes(&rest[..rest.len().min(57)]) {
                let _ = pk.is_weak();
                let _ = pk.verify(msg, &rest[rest.len().min(57)..]);
            }
        }
        1 => {
            let mut a = [0u8; 56];
            let mut b = [0u8; 56];
            let n = rest.len().min(56);
            a[..n].copy_from_slice(&rest[..n]);
            let m = rest.len().saturating_sub(56).min(56);
            b[..m].copy_from_slice(&rest[56.min(rest.len())..56.min(rest.len()) + m]);
            let (a, b) = (
                x448::PrivateKey::from_bytes(a),
                x448::PrivateKey::from_bytes(b),
            );
            let ab = a.diffie_hellman(&b.public_key());
            let ba = b.diffie_hellman(&a.public_key());
            assert_eq!(ab, ba);
            // Arbitrary peer values never panic.
            let _ = a.diffie_hellman(&b.to_bytes());
        }
        2 => {
            let mut d = rest;
            let params = take(&mut d);
            let key = take(&mut d);
            let digest = take(&mut d);
            if let Ok(k) = dsa::PublicKey::from_der(params, key) {
                let _ = k.verify_prehash(digest, d);
                assert_eq!(
                    dsa::PublicKey::from_der(&k.params_der(), &k.key_der()).ok(),
                    Some(k)
                );
            }
        }
        _ => {
            if let Ok(k) = pkey::PublicKey::from_spki_der(rest) {
                assert_eq!(
                    pkey::PublicKey::from_spki_der(&k.to_spki_der()).ok(),
                    Some(k)
                );
            }
            if let Ok(k) = pkey::PrivateKey::from_pkcs8_der(rest) {
                let again = pkey::PrivateKey::from_pkcs8_der(&k.to_pkcs8_der()).unwrap();
                assert_eq!(again.to_pkcs8_der(), k.to_pkcs8_der());
            }
            let one: [u8; 200] = Shake256::digest(rest);
            let mut h = Shake256::new();
            for c in rest.chunks(usize::from(rest.first().copied().unwrap_or(1)).max(1)) {
                h.update(c);
            }
            let mut two = [0u8; 200];
            let (x, y) = two.split_at_mut(usize::from(rest.last().copied().unwrap_or(0)) % 200);
            h.squeeze(x);
            h.squeeze(y);
            assert_eq!(one, two);
        }
    }
}
