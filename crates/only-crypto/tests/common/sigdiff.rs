//! The signature-verification differential shared by the `crypto_sig_verify` fuzz target and
//! its stable replay test (`tests/sig_diff.rs`): only-crypto and ring must agree on every
//! (key, message, signature) the input describes.
//!
//! Input: `data[0]` picks the algorithm and mode, `data[1..33]` seeds a key, the rest is split
//! into a message and a mutation. Modes: a valid signature of the message, the same signature
//! with the mutation XORed in, the mutation used as the whole signature, and (Ed25519) the
//! mutation used as the public key.

#![allow(dead_code, unreachable_pub)]

use only_crypto::{ed25519, p256, p384};
use ring::signature::{self as rs, KeyPair as _};

pub fn check(data: &[u8]) {
    if data.len() < 34 {
        return;
    }
    let sel = data[0];
    let seed: [u8; 32] = data[1..33].try_into().unwrap_or([0; 32]);
    let rest = &data[33..];
    let split = usize::from(rest[0]).min(rest.len() - 1);
    let (msg, mutation) = rest[1..].split_at(split);
    let mode = (sel >> 2) & 3;
    let mutate = |sig: &[u8]| -> Vec<u8> {
        match mode {
            0 => sig.to_vec(),
            1 => {
                let mut s = sig.to_vec();
                for (i, m) in mutation.iter().enumerate() {
                    if let Some(x) = s.get_mut(i) {
                        *x ^= m;
                    }
                }
                s
            }
            _ => mutation.to_vec(),
        }
    };
    match sel & 3 {
        0 => {
            let k = ed25519::SigningKey::from_seed(&seed);
            let sig = mutate(&k.sign(msg));
            let pk: Vec<u8> = if mode == 3 && mutation.len() >= 32 {
                mutation[..32].to_vec()
            } else {
                k.verifying_key().as_bytes().to_vec()
            };
            let ours = ed25519::VerifyingKey::from_bytes(&pk)
                .and_then(|v| v.verify(msg, &sig))
                .is_ok();
            let theirs = rs::UnparsedPublicKey::new(&rs::ED25519, &pk)
                .verify(msg, &sig)
                .is_ok();
            assert_eq!(ours, theirs, "ed25519 pk {pk:02x?} sig {sig:02x?}");
            if mode == 0 {
                assert!(ours);
            }
        }
        1 => {
            let Ok(k) = p256::SecretKey::from_bytes(&seed) else {
                return;
            };
            let sig = mutate(&k.sign(msg).to_der());
            let pk = k.public_key();
            let ours = p256::Signature::from_der(&sig)
                .and_then(|s| pk.verify(msg, &s))
                .is_ok();
            let theirs =
                rs::UnparsedPublicKey::new(&rs::ECDSA_P256_SHA256_ASN1, pk.to_uncompressed())
                    .verify(msg, &sig)
                    .is_ok();
            assert_eq!(ours, theirs, "p256 sig {sig:02x?}");
            // The fixed-width form agrees too.
            let fixed = mutate(&k.sign(msg).to_fixed());
            let ours = p256::Signature::from_fixed(&fixed)
                .and_then(|s| pk.verify(msg, &s))
                .is_ok();
            let theirs =
                rs::UnparsedPublicKey::new(&rs::ECDSA_P256_SHA256_FIXED, pk.to_uncompressed())
                    .verify(msg, &fixed)
                    .is_ok();
            assert_eq!(ours, theirs, "p256 fixed sig {fixed:02x?}");
        }
        2 => {
            let mut s48 = [0u8; 48];
            s48[16..].copy_from_slice(&seed);
            s48[0] = 1;
            let Ok(k) = p384::SecretKey::from_bytes(&s48) else {
                return;
            };
            let sig = mutate(&k.sign(msg).to_der());
            let pk = k.public_key();
            let ours = p384::Signature::from_der(&sig)
                .and_then(|s| pk.verify(msg, &s))
                .is_ok();
            let theirs =
                rs::UnparsedPublicKey::new(&rs::ECDSA_P384_SHA384_ASN1, pk.to_uncompressed())
                    .verify(msg, &sig)
                    .is_ok();
            assert_eq!(ours, theirs, "p384 sig {sig:02x?}");
        }
        _ => {
            // Public keys from the mutation bytes: SEC1 decoding agrees with ring's.
            let ours = p256::PublicKey::from_sec1(mutation).is_ok();
            let k = ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, mutation);
            let eph = ring::agreement::EphemeralPrivateKey::generate(
                &ring::agreement::ECDH_P256,
                &ring::rand::SystemRandom::new(),
            );
            if let Ok(eph) = eph {
                let theirs = ring::agreement::agree_ephemeral(eph, &k, |_| ()).is_ok();
                // ring accepts only uncompressed points.
                if mutation.first() == Some(&4) || !ours {
                    assert_eq!(ours, theirs, "p256 point {mutation:02x?}");
                }
            }
            let _ = rs::Ed25519KeyPair::from_seed_unchecked(&seed)
                .map(|k| k.public_key().as_ref().len());
        }
    }
}
