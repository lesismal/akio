//! Public-key cross-checks against ring and the RustCrypto p256/p384 crates (dev-dependencies
//! only): identical deterministic signatures, mutual verification, identical shared secrets,
//! keys exchanged in PKCS#8 / SPKI.

mod common;

use common::wycheproof;
use only_crypto::pkey::{PrivateKey, PublicKey, SignatureAlgorithm};
use only_crypto::rand::ChaChaRng;
use only_crypto::rsa::HashAlg;
use only_crypto::{ed25519, p256 as op256, p384 as op384, x25519};
use ring::signature::{self as rs, KeyPair as _};

fn rng() -> ChaChaRng {
    ChaChaRng::from_seed([42; 32])
}

#[test]
fn ed25519_vs_ring() {
    let mut r = rng();
    for i in 0..64 {
        let mut seed = [0u8; 32];
        r.fill(&mut seed);
        let msg = vec![i as u8; i * 7];
        let ours = ed25519::SigningKey::from_seed(&seed);
        let theirs = rs::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        assert_eq!(
            ours.verifying_key().as_bytes()[..],
            theirs.public_key().as_ref()[..]
        );
        let s1 = ours.sign(&msg);
        let s2 = theirs.sign(&msg);
        assert_eq!(s1[..], s2.as_ref()[..]);
        rs::UnparsedPublicKey::new(&rs::ED25519, theirs.public_key().as_ref())
            .verify(&msg, &s1)
            .unwrap();
    }
    // ring's PKCS#8 v2 (with the public key) loads.
    let rand = ring::rand::SystemRandom::new();
    let doc = rs::Ed25519KeyPair::generate_pkcs8(&rand).unwrap();
    let k = PrivateKey::from_pkcs8_der(doc.as_ref()).unwrap();
    let rk = rs::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    assert_eq!(k.public_key().raw_key(), rk.public_key().as_ref());
}

macro_rules! ecdsa_vs {
    ($name:ident, $ours:ident, $rc:ident, $ring_sign:expr, $ring_verify:expr, $alg:expr, $len:expr) => {
        #[test]
        fn $name() {
            use $rc::ecdsa::signature::Signer as _;
            let mut r = rng();
            for i in 0..32 {
                let mut d = [0u8; $len];
                r.fill(&mut d);
                let Ok(ours) = $ours::SecretKey::from_bytes(&d) else {
                    continue;
                };
                let msg = vec![i as u8; i * 13];
                // Deterministic (RFC 6979) signatures are identical to RustCrypto's.
                let rc = $rc::ecdsa::SigningKey::from_slice(&d).unwrap();
                let s: $rc::ecdsa::Signature = rc.sign(&msg);
                let sig = ours.sign(&msg);
                assert_eq!(sig.to_fixed(), s.to_bytes().to_vec());
                assert_eq!(sig.to_der(), s.to_der().as_bytes());
                // ring verifies ours, we verify ring's (random nonces).
                let pk = ours.public_key().to_uncompressed();
                rs::UnparsedPublicKey::new($ring_verify, &pk)
                    .verify(&msg, &sig.to_der())
                    .unwrap();
                let key = ours.key();
                let rand = ring::rand::SystemRandom::new();
                let rk =
                    rs::EcdsaKeyPair::from_pkcs8($ring_sign, &key.to_pkcs8_der(), &rand).unwrap();
                let rsig = rk.sign(&rand, &msg).unwrap();
                key.public_key().verify($alg, &msg, rsig.as_ref()).unwrap();
                let mut bad = msg.clone();
                bad.push(1);
                assert!(key.public_key().verify($alg, &bad, rsig.as_ref()).is_err());
            }
            // ring-generated PKCS#8 loads.
            let rand = ring::rand::SystemRandom::new();
            let doc = rs::EcdsaKeyPair::generate_pkcs8($ring_sign, &rand).unwrap();
            let k = PrivateKey::from_pkcs8_der(doc.as_ref()).unwrap();
            let rk = rs::EcdsaKeyPair::from_pkcs8($ring_sign, doc.as_ref(), &rand).unwrap();
            assert_eq!(k.public_key().raw_key(), rk.public_key().as_ref());
        }
    };
}

/// Wraps a curve key as a `PrivateKey`.
trait IntoKey {
    fn key(&self) -> PrivateKey;
}
impl IntoKey for op256::SecretKey {
    fn key(&self) -> PrivateKey {
        PrivateKey::P256(self.clone())
    }
}
impl IntoKey for op384::SecretKey {
    fn key(&self) -> PrivateKey {
        PrivateKey::P384(self.clone())
    }
}
ecdsa_vs!(
    p256_vs_ring_and_rustcrypto,
    op256,
    p256,
    &rs::ECDSA_P256_SHA256_ASN1_SIGNING,
    &rs::ECDSA_P256_SHA256_ASN1,
    SignatureAlgorithm::EcdsaSha256,
    32
);
ecdsa_vs!(
    p384_vs_ring_and_rustcrypto,
    op384,
    p384,
    &rs::ECDSA_P384_SHA384_ASN1_SIGNING,
    &rs::ECDSA_P384_SHA384_ASN1,
    SignatureAlgorithm::EcdsaSha384,
    48
);

#[test]
fn ecdh_and_x25519_vs_ring() {
    use ring::agreement as ag;
    let rand = ring::rand::SystemRandom::new();
    for _ in 0..16 {
        // X25519.
        let theirs = ag::EphemeralPrivateKey::generate(&ag::X25519, &rand).unwrap();
        let their_pub = theirs.compute_public_key().unwrap();
        let ours = x25519::PrivateKey::generate().unwrap();
        let s1 = ours
            .diffie_hellman(&their_pub.as_ref().try_into().unwrap())
            .unwrap();
        let s2 = ag::agree_ephemeral(
            theirs,
            &ag::UnparsedPublicKey::new(&ag::X25519, ours.public_key()),
            |s| s.to_vec(),
        )
        .unwrap();
        assert_eq!(s1.to_vec(), s2);
        // P-256 and P-384.
        let theirs = ag::EphemeralPrivateKey::generate(&ag::ECDH_P256, &rand).unwrap();
        let their_pub = theirs.compute_public_key().unwrap();
        let ours = op256::SecretKey::generate().unwrap();
        let s1 = ours.diffie_hellman(&op256::PublicKey::from_sec1(their_pub.as_ref()).unwrap());
        let s2 = ag::agree_ephemeral(
            theirs,
            &ag::UnparsedPublicKey::new(&ag::ECDH_P256, ours.public_key().to_uncompressed()),
            |s| s.to_vec(),
        )
        .unwrap();
        assert_eq!(s1.to_vec(), s2);
        let theirs = ag::EphemeralPrivateKey::generate(&ag::ECDH_P384, &rand).unwrap();
        let their_pub = theirs.compute_public_key().unwrap();
        let ours = op384::SecretKey::generate().unwrap();
        let s1 = ours.diffie_hellman(&op384::PublicKey::from_sec1(their_pub.as_ref()).unwrap());
        let s2 = ag::agree_ephemeral(
            theirs,
            &ag::UnparsedPublicKey::new(&ag::ECDH_P384, ours.public_key().to_uncompressed()),
            |s| s.to_vec(),
        )
        .unwrap();
        assert_eq!(s1.to_vec(), s2);
    }
}

#[test]
fn rsa_vs_ring() {
    let groups = wycheproof("wycheproof_rsa_pkcs1_2048_sig_gen.json");
    let (g, _) = groups
        .iter()
        .find(|(g, _)| g.get("sha").str() == "SHA-256")
        .unwrap();
    let der = g.get("privateKeyPkcs8").hex();
    let ours = PrivateKey::from_pkcs8_der(&der).unwrap();
    let theirs = rs::RsaKeyPair::from_pkcs8(&der).unwrap();
    let rand = ring::rand::SystemRandom::new();
    let spki = ours.public_key().to_spki_der();
    let PublicKey::Rsa(pk) = ours.public_key() else {
        unreachable!()
    };
    let n = pk.modulus();
    let e = pk.exponent().to_be_bytes();
    let e = &e[e.iter().take_while(|&&b| b == 0).count()..];
    let ring_pk = rs::RsaPublicKeyComponents { n: &n[..], e };
    for (i, (alg, ring_alg, ring_ver)) in [
        (
            SignatureAlgorithm::RsaPkcs1Sha256,
            &rs::RSA_PKCS1_SHA256 as &dyn rs::RsaEncoding,
            &rs::RSA_PKCS1_2048_8192_SHA256,
        ),
        (
            SignatureAlgorithm::RsaPkcs1Sha512,
            &rs::RSA_PKCS1_SHA512,
            &rs::RSA_PKCS1_2048_8192_SHA512,
        ),
        (
            SignatureAlgorithm::RsaPssSha256,
            &rs::RSA_PSS_SHA256,
            &rs::RSA_PSS_2048_8192_SHA256,
        ),
        (
            SignatureAlgorithm::RsaPssSha384,
            &rs::RSA_PSS_SHA384,
            &rs::RSA_PSS_2048_8192_SHA384,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let msg = vec![i as u8; 100 + i];
        let sig = ours.sign(alg, &msg).unwrap();
        ring_pk.verify(ring_ver, &msg, &sig).unwrap();
        let mut rsig = vec![0u8; theirs.public().modulus_len()];
        theirs.sign(ring_alg, &rand, &msg, &mut rsig).unwrap();
        PublicKey::from_spki_der(&spki)
            .unwrap()
            .verify(alg, &msg, &rsig)
            .unwrap();
        if matches!(
            alg,
            SignatureAlgorithm::RsaPkcs1Sha256 | SignatureAlgorithm::RsaPkcs1Sha512
        ) {
            assert_eq!(sig, rsig, "PKCS#1 v1.5 is deterministic");
        }
    }
    let _ = HashAlg::Sha256;
}
