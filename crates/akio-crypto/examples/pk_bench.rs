//! Public-key operations per second, akio-crypto vs ring:
//! `cargo run --release -p akio-crypto --example pk_bench [rsa|p256|448|521]` (`rsa`, `p256`:
//! those rows only; `448`: Ed448, X448 and DSA, which ring does not have, next to Ed25519 and
//! X25519; `521`: P-521, which ring does not have either, next to P-384).

use std::hint::black_box;
use std::time::{Duration, Instant};

use akio_crypto::pkey::{PrivateKey, SignatureAlgorithm};
use akio_crypto::{ed448, ed25519, p256, p384, p521, x448, x25519};
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
        "op/s", "akio", "ring", "ratio"
    );
    // `pk_bench rsa` / `pk_bench p256`: those rows only.
    let only = std::env::args().nth(1);
    if only.as_deref() == Some("rsa") {
        rsa_all(&msg, &rand);
        return;
    }
    if only.as_deref() == Some("448") {
        curve448_dsa(&msg);
        return;
    }
    if only.as_deref() == Some("521") {
        p521_rows(&msg);
        return;
    }
    let all = only.is_none();

    // Ed25519.
    if all {
        ed_x25519(msg, &rand);
    }
    ec_all(msg, &rand, all);
    if all {
        rsa_all(&msg, &rand);
    }
}

/// A row without a ring counterpart: our rate and the reference (`vs`) rate of a related
/// operation of ours, for the ratio.
fn row_vs(name: &str, ours: f64, vs_name: &str, vs: f64) {
    println!(
        "{name:<28} {ours:>10.0} {:>10} {:>8.2}x of {vs_name}",
        "-",
        ours / vs
    );
}

/// P-521 (ring has none) next to our P-384 rates.
fn p521_rows(msg: &[u8; 64]) {
    let k384 = p384::SecretKey::generate().expect("rng");
    let peer384 = p384::SecretKey::generate().expect("rng").public_key();
    let s384 = k384.sign(msg);
    let pk384 = k384.public_key();
    let k = p521::SecretKey::generate().expect("rng");
    let peer = p521::SecretKey::generate().expect("rng").public_key();
    let sig = k.sign(msg);
    let pk = k.public_key();
    let ref_keygen = rate(|| {
        black_box(black_box(&k384).public_key());
    });
    let keygen = rate(|| {
        black_box(black_box(&k).public_key());
    });
    row_vs("P-521 keygen (d·G)", keygen, "P-384", ref_keygen);
    let ref_ecdh = rate(|| {
        black_box(k384.diffie_hellman(black_box(&peer384)));
    });
    let ecdh = rate(|| {
        black_box(k.diffie_hellman(black_box(&peer)));
    });
    row_vs("P-521 ECDH", ecdh, "P-384", ref_ecdh);
    let ref_sign = rate(|| {
        black_box(k384.sign(black_box(msg)));
    });
    let sign = rate(|| {
        black_box(k.sign(black_box(msg)));
    });
    row_vs("P-521 ECDSA sign (SHA-512)", sign, "P-384", ref_sign);
    let ref_verify = rate(|| pk384.verify(black_box(msg), &s384).expect("verify"));
    let verify = rate(|| pk.verify(black_box(msg), &sig).expect("verify"));
    row_vs("P-521 ECDSA verify", verify, "P-384", ref_verify);
}

fn curve448_dsa(msg: &[u8; 64]) {
    let e25 = ed25519::SigningKey::from_seed(&[1; 32]);
    let s25 = e25.sign(msg);
    let v25 = e25.verifying_key();
    let ed25519_sign = rate(|| {
        black_box(e25.sign(black_box(msg)));
    });
    let ed25519_verify = rate(|| v25.verify(black_box(msg), &s25).expect("verify"));
    let k = ed448::SigningKey::from_seed(&[1; 57]);
    let sig = k.sign(msg);
    let vk = k.verifying_key();
    row_vs(
        "ed448 sign",
        rate(|| {
            black_box(k.sign(black_box(msg)));
        }),
        "ed25519",
        ed25519_sign,
    );
    row_vs(
        "ed448 verify",
        rate(|| vk.verify(black_box(msg), &sig).expect("verify")),
        "ed25519",
        ed25519_verify,
    );
    let x25 = x25519::PrivateKey::from_bytes([2; 32]);
    let p25 = x25519::PrivateKey::from_bytes([3; 32]).public_key();
    let x25519_agree = rate(|| {
        black_box(x25.diffie_hellman(black_box(&p25)).expect("dh"));
    });
    let xk = x448::PrivateKey::from_bytes([2; 56]);
    let peer = x448::PrivateKey::from_bytes([3; 56]).public_key();
    row_vs(
        "x448 agree",
        rate(|| {
            black_box(xk.diffie_hellman(black_box(&peer)).expect("dh"));
        }),
        "x25519",
        x25519_agree,
    );
    // DSA 2048/256 verification (the OpenSSL-made root of akio-x509's test data).
    let pem = include_bytes!("../../akio-x509/tests/data/ed448-dsa/dsa_root.pem");
    let der = akio_crypto::pem::decode_label(pem, "CERTIFICATE").expect("pem");
    let cert = &der[0];
    // tbsCertificate, signature value and SubjectPublicKeyInfo, by walking the DER.
    let mut r = akio_crypto::der::Reader::new(cert);
    let mut c = r.sequence().expect("cert");
    let tbs = c
        .read_element(akio_crypto::der::tag::SEQUENCE)
        .expect("tbs");
    let _alg = c
        .read_element(akio_crypto::der::tag::SEQUENCE)
        .expect("alg");
    let sig = c.read_bit_string().expect("sig");
    let mut t = akio_crypto::der::Reader::new(tbs).sequence().expect("tbs");
    for _ in 0..6 {
        t.read_tlv().expect("field");
    }
    let spki = t
        .read_element(akio_crypto::der::tag::SEQUENCE)
        .expect("spki");
    let akio_crypto::pkey::PublicKey::Dsa(key) =
        akio_crypto::pkey::PublicKey::from_spki_der(spki).expect("dsa key")
    else {
        panic!("not DSA");
    };
    let hash = akio_crypto::rsa::HashAlg::Sha256;
    row_vs(
        "dsa2048/256 verify",
        rate(|| key.verify(hash, black_box(tbs), sig).expect("verify")),
        "ed25519 verify",
        ed25519_verify,
    );
}

fn ed_x25519(msg: [u8; 64], rand: &ring::rand::SystemRandom) {
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
            let e = ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, rand)
                .expect("key");
            let p = ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, peer);
            ring::agreement::agree_ephemeral(e, &p, |s| black_box(s[0])).expect("dh");
        }),
    );
}

fn ec_all(msg: [u8; 64], rand: &ring::rand::SystemRandom, all: bool) {
    macro_rules! ec {
        ($label:literal, $m:ident, $wrap:ident, $len:literal, $ring_sign:expr, $ring_verify:expr, $ag:expr) => {{
            let k = $m::SecretKey::from_bytes(&[7; $len]).expect("key");
            let pk = k.public_key();
            let der = PrivateKey::$wrap(k.clone()).to_pkcs8_der();
            let rk = rs::EcdsaKeyPair::from_pkcs8($ring_sign, &der, rand).expect("ring key");
            let sig = k.sign(&msg);
            let sig_der = sig.to_der();
            let rpk = rs::UnparsedPublicKey::new($ring_verify, pk.to_uncompressed());
            row(
                concat!($label, " ecdsa sign"),
                rate(|| {
                    black_box(k.sign(black_box(&msg)));
                }),
                rate(|| {
                    black_box(rk.sign(rand, black_box(&msg)).expect("sign"));
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
                    let e = ring::agreement::EphemeralPrivateKey::generate($ag, rand).expect("key");
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
                        ring::agreement::EphemeralPrivateKey::generate($ag, rand)
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
    if !all {
        return;
    }
    ec!(
        "p384",
        p384,
        P384,
        48,
        &rs::ECDSA_P384_SHA384_ASN1_SIGNING,
        &rs::ECDSA_P384_SHA384_ASN1,
        &ring::agreement::ECDH_P384
    );
}

fn rsa_all(msg: &[u8], rand: &ring::rand::SystemRandom) {
    for (bits, pem) in [
        (2048, include_str!("../tests/data/rsa2048_test_key.pem")),
        (3072, include_str!("../tests/data/rsa3072_test_key.pem")),
        (4096, include_str!("../tests/data/rsa4096_test_key.pem")),
    ] {
        rsa_rows(bits, pem, msg, rand);
    }
}

/// RSA sign and verify at one size (test keys generated by OpenSSL). ring parses the public key
/// on every verification (it has no prepared public-key type), so the second verify row does
/// the same for akio-crypto: the cost of checking one certificate signature.
fn rsa_rows(bits: usize, pem: &str, msg: &[u8], rand: &ring::rand::SystemRandom) {
    let key = PrivateKey::from_pem(pem.as_bytes()).expect("rsa key");
    let der = key.to_pkcs8_der();
    let rk = rs::RsaKeyPair::from_pkcs8(&der).expect("ring rsa");
    let pk = key.public_key();
    let sig = key
        .sign(SignatureAlgorithm::RsaPkcs1Sha256, msg)
        .expect("sign");
    let akio_crypto::pkey::PublicKey::Rsa(rpub) = &pk else {
        unreachable!()
    };
    let n = rpub.modulus();
    let e = rpub.exponent().to_be_bytes();
    let e = &e[e.iter().take_while(|&&b| b == 0).count()..];
    let ring_pk = rs::RsaPublicKeyComponents { n: &n[..], e };
    let ring_sign = rate(|| {
        let mut out = vec![0u8; rk.public().modulus_len()];
        rk.sign(&rs::RSA_PKCS1_SHA256, rand, black_box(msg), &mut out)
            .expect("sign");
        black_box(out);
    });
    row(
        &format!("rsa{bits} pkcs1 sign"),
        rate(|| {
            black_box(
                key.sign(SignatureAlgorithm::RsaPkcs1Sha256, black_box(msg))
                    .expect("sign"),
            );
        }),
        ring_sign,
    );
    let ring_verify = rate(|| {
        ring_pk
            .verify(&rs::RSA_PKCS1_2048_8192_SHA256, black_box(msg), &sig)
            .expect("verify");
    });
    row(
        &format!("rsa{bits} pkcs1 verify"),
        rate(|| {
            pk.verify(SignatureAlgorithm::RsaPkcs1Sha256, black_box(msg), &sig)
                .expect("verify");
        }),
        ring_verify,
    );
    row(
        &format!("rsa{bits} verify + key parse"),
        rate(|| {
            let k = akio_crypto::rsa::PublicKey::from_components(black_box(&n), e).expect("key");
            k.verify_pkcs1v15(akio_crypto::rsa::HashAlg::Sha256, black_box(msg), &sig)
                .expect("verify");
        }),
        ring_verify,
    );
}
