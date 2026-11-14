//! Public-key operations per second, only-crypto vs ring:
//! `cargo run --release -p only-crypto --example pk_bench`.

use std::hint::black_box;
use std::time::{Duration, Instant};

use only_crypto::pkey::{PrivateKey, SignatureAlgorithm};
use only_crypto::{ed25519, p256, p384, x25519};
use ring::signature::{self as rs, KeyPair as _};

fn rate(mut f: impl FnMut()) -> f64 {
    // Warm up (and build the lazily computed tables), then run for ~0.5 s.
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    let mut n = 0u64;
    while start.elapsed() < Duration::from_millis(500) {
        f();
        n += 1;
    }
    n as f64 / start.elapsed().as_secs_f64()
}

fn row(name: &str, ours: f64, ring: f64) {
    println!("{name:<28} {ours:>10.0} {ring:>10.0} {:>8.2}x", ours / ring);
}

fn main() {
    let msg = [0x5au8; 64];
    let rand = ring::rand::SystemRandom::new();
    println!(
        "{:<28} {:>10} {:>10} {:>9}",
        "op/s", "only", "ring", "ratio"
    );

    // Ed25519.
    let ek = ed25519::SigningKey::from_seed(&[1; 32]);
    let rk = rs::Ed25519KeyPair::from_seed_unchecked(&[1; 32]).expect("ring key");
    let sig = ek.sign(&msg);
    let vk = ek.verifying_key();
    let rpk = rs::UnparsedPublicKey::new(&rs::ED25519, rk.public_key().as_ref().to_vec());
    row(
        "ed25519 sign",
        rate(|| {
            black_box(ek.sign(black_box(&msg)));
        }),
        rate(|| {
            black_box(rk.sign(black_box(&msg)));
        }),
    );
    row(
        "ed25519 verify",
        rate(|| vk.verify(black_box(&msg), &sig).expect("verify")),
        rate(|| rpk.verify(black_box(&msg), &sig).expect("verify")),
    );

    // X25519.
    let xk = x25519::PrivateKey::from_bytes([2; 32]);
    let peer = x25519::PrivateKey::from_bytes([3; 32]).public_key();
    row(
        "x25519 agree",
        rate(|| {
            black_box(xk.diffie_hellman(black_box(&peer)).expect("dh"));
        }),
        rate(|| {
            let e = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rand)
                .expect("key");
            let p = ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, peer);
            ring::agreement::agree_ephemeral(e, &p, |s| black_box(s[0])).expect("dh");
        }),
    );

    macro_rules! ec {
        ($label:literal, $m:ident, $wrap:ident, $len:literal, $ring_sign:expr, $ring_verify:expr, $ag:expr) => {{
            let k = $m::SecretKey::from_bytes(&[7; $len]).expect("key");
            let pk = k.public_key();
            let der = PrivateKey::$wrap(k.clone()).to_pkcs8_der();
            let rk = rs::EcdsaKeyPair::from_pkcs8($ring_sign, &der, &rand).expect("ring key");
            let sig = k.sign(&msg);
            let sig_der = sig.to_der();
            let rpk = rs::UnparsedPublicKey::new($ring_verify, pk.to_uncompressed());
            row(
                concat!($label, " ecdsa sign"),
                rate(|| {
                    black_box(k.sign(black_box(&msg)));
                }),
                rate(|| {
                    black_box(rk.sign(&rand, black_box(&msg)).expect("sign"));
                }),
            );
            row(
                concat!($label, " ecdsa verify"),
                rate(|| pk.verify(black_box(&msg), &sig).expect("verify")),
                rate(|| rpk.verify(black_box(&msg), &sig_der).expect("verify")),
            );
            let peer = $m::SecretKey::from_bytes(&[9; $len])
                .expect("key")
                .public_key();
            let peer_bytes = peer.to_uncompressed();
            row(
                concat!($label, " ecdh agree"),
                rate(|| {
                    // Includes decoding/validating the peer point, as a handshake does.
                    let p = $m::PublicKey::from_sec1(black_box(&peer_bytes)).expect("point");
                    black_box(k.diffie_hellman(&p));
                }),
                rate(|| {
                    let e =
                        ring::agreement::EphemeralPrivateKey::generate($ag, &rand).expect("key");
                    let p = ring::agreement::UnparsedPublicKey::new($ag, &peer_bytes);
                    ring::agreement::agree_ephemeral(e, &p, |s| black_box(s[0])).expect("dh");
                }),
            );
            row(
                concat!($label, " keygen"),
                rate(|| {
                    black_box($m::SecretKey::generate().expect("key").public_key());
                }),
                rate(|| {
                    black_box(
                        ring::agreement::EphemeralPrivateKey::generate($ag, &rand)
                            .expect("key")
                            .compute_public_key()
                            .expect("pk"),
                    );
                }),
            );
        }};
    }
    ec!(
        "p256",
        p256,
        P256,
        32,
        &rs::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rs::ECDSA_P256_SHA256_ASN1,
        &ring::agreement::ECDH_P256
    );
    ec!(
        "p384",
        p384,
        P384,
        48,
        &rs::ECDSA_P384_SHA384_ASN1_SIGNING,
        &rs::ECDSA_P384_SHA384_ASN1,
        &ring::agreement::ECDH_P384
    );

    // RSA 2048 (a test key generated by OpenSSL).
    let pem = include_str!("../tests/data/rsa2048_test_key.pem");
    let key = PrivateKey::from_pem(pem.as_bytes()).expect("rsa key");
    let der = key.to_pkcs8_der();
    let rk = rs::RsaKeyPair::from_pkcs8(&der).expect("ring rsa");
    let pk = key.public_key();
    let sig = key
        .sign(SignatureAlgorithm::RsaPkcs1Sha256, &msg)
        .expect("sign");
    let only_crypto::pkey::PublicKey::Rsa(rpub) = &pk else {
        unreachable!()
    };
    let n = rpub.modulus();
    let e = rpub.exponent().to_be_bytes();
    let e = &e[e.iter().take_while(|&&b| b == 0).count()..];
    let ring_pk = rs::RsaPublicKeyComponents { n: &n[..], e };
    row(
        "rsa2048 pkcs1 sign",
        rate(|| {
            black_box(
                key.sign(SignatureAlgorithm::RsaPkcs1Sha256, black_box(&msg))
                    .expect("sign"),
            );
        }),
        rate(|| {
            let mut out = vec![0u8; rk.public().modulus_len()];
            rk.sign(&rs::RSA_PKCS1_SHA256, &rand, black_box(&msg), &mut out)
                .expect("sign");
            black_box(out);
        }),
    );
    row(
        "rsa2048 pkcs1 verify",
        rate(|| {
            pk.verify(SignatureAlgorithm::RsaPkcs1Sha256, black_box(&msg), &sig)
                .expect("verify");
        }),
        rate(|| {
            ring_pk
                .verify(&rs::RSA_PKCS1_2048_8192_SHA256, black_box(&msg), &sig)
                .expect("verify");
        }),
    );
}
