//! Known-answer tests from NIST CAVP (SHA, HMAC, AES, GCM) and Wycheproof (AES-GCM,
//! ChaCha20-Poly1305, HMAC, HKDF), vendored under `tests/data/`.

mod common;

use common::{lines, unhex, wycheproof};
use akio_crypto::Error;
use akio_crypto::aes::Aes;
use akio_crypto::chacha::ChaCha20Poly1305;
use akio_crypto::gcm::AesGcm;
use akio_crypto::hash::{Hash, Sha1, Sha224, Sha256, Sha384, Sha512};
use akio_crypto::kdf;
use akio_crypto::mac::Hmac;

fn digest_of(alg: &str, msg: &[u8]) -> Vec<u8> {
    match alg {
        "SHA1" => Sha1::digest(msg).to_vec(),
        "SHA224" => Sha224::digest(msg).to_vec(),
        "SHA256" => Sha256::digest(msg).to_vec(),
        "SHA384" => Sha384::digest(msg).to_vec(),
        "SHA512" => Sha512::digest(msg).to_vec(),
        _ => unreachable!("{alg}"),
    }
}

fn streamed<H: Hash>(msg: &[u8], step: usize) -> Vec<u8> {
    let mut h = H::default();
    for c in msg.chunks(step.max(1)) {
        h.update(c);
    }
    h.finalize().as_ref().to_vec()
}

#[test]
fn cavp_sha() {
    let mut n = 0;
    for l in lines("cavp_sha.txt") {
        let (alg, msg, md) = (&l[0], unhex(&l[1]), unhex(&l[2]));
        assert_eq!(digest_of(alg, &msg), md, "{alg} {}", l[1]);
        let step = msg.len() % 61 + 1;
        let s = match alg.as_str() {
            "SHA1" => streamed::<Sha1>(&msg, step),
            "SHA224" => streamed::<Sha224>(&msg, step),
            "SHA256" => streamed::<Sha256>(&msg, step),
            "SHA384" => streamed::<Sha384>(&msg, step),
            _ => streamed::<Sha512>(&msg, step),
        };
        assert_eq!(s, md, "{alg} streamed");
        n += 1;
    }
    assert!(n > 400, "{n}");
}

#[test]
fn cavp_hmac() {
    let mut n = 0;
    for l in lines("cavp_hmac.txt") {
        let (key, msg, tag) = (unhex(&l[1]), unhex(&l[2]), unhex(&l[3]));
        let got = match l[0].as_str() {
            "SHA1" => Hmac::<Sha1>::mac(&key, &msg).to_vec(),
            "SHA224" => Hmac::<Sha224>::mac(&key, &msg).to_vec(),
            "SHA256" => Hmac::<Sha256>::mac(&key, &msg).to_vec(),
            "SHA384" => Hmac::<Sha384>::mac(&key, &msg).to_vec(),
            "SHA512" => Hmac::<Sha512>::mac(&key, &msg).to_vec(),
            other => unreachable!("{other}"),
        };
        assert_eq!(got, tag, "{} {}", l[0], l[1]);
        n += 1;
    }
    assert_eq!(n, 75);
}

#[test]
fn cavp_aes_ecb() {
    let mut n = 0;
    for l in lines("cavp_aes_ecb.txt") {
        let pt: [u8; 16] = unhex(&l[1]).try_into().unwrap();
        let ct: [u8; 16] = unhex(&l[2]).try_into().unwrap();
        // The CPU's AES instructions (when present) and the portable implementation.
        for aes in [
            Aes::new(&unhex(&l[0])).unwrap(),
            Aes::new_portable(&unhex(&l[0])).unwrap(),
        ] {
            let mut b = pt;
            aes.encrypt_block(&mut b);
            assert_eq!(b, ct, "{}", l[0]);
            aes.decrypt_block(&mut b);
            assert_eq!(b, pt);
        }
        n += 1;
    }
    assert!(n > 300, "{n}");
}

#[test]
fn cavp_gcm() {
    let (mut ok, mut fail) = (0, 0);
    for l in lines("cavp_gcm.txt") {
        let key = unhex(&l[0]);
        let iv: [u8; 12] = unhex(&l[1]).try_into().unwrap();
        let (aad, ct, tag) = (unhex(&l[3]), unhex(&l[4]), unhex(&l[5]));
        // The default kernel (VAES + AVX-512 where the CPU has it), the VAES-AVX2 one, the
        // 128-bit one and portable AES.
        for gcm in [
            AesGcm::new(&key).unwrap(),
            AesGcm::with_cipher_avx2(Aes::new(&key).unwrap()),
            AesGcm::with_cipher_narrow(Aes::new(&key).unwrap()),
            AesGcm::with_cipher(Aes::new_portable(&key).unwrap()),
        ] {
            let mut buf = ct.clone();
            let r = gcm.decrypt_in_place_detached(&iv, &aad, &mut buf, &tag);
            if l[2] == "!" {
                assert_eq!(r, Err(Error::Verification), "{}", l[0]);
                assert_eq!(buf, ct, "left as it was");
                fail += 1;
            } else {
                r.unwrap();
                let pt = unhex(&l[2]);
                assert_eq!(buf, pt);
                let t = gcm.encrypt_in_place_detached(&iv, &aad, &mut buf);
                assert_eq!(buf, ct);
                assert_eq!(t.to_vec(), tag);
                ok += 1;
            }
        }
    }
    assert!(ok > 300 && fail > 60, "{ok} {fail}");
}

/// Runs an AEAD over Wycheproof tests: `valid` and `acceptable` must round-trip, `invalid` must
/// be rejected.
fn aead_vectors(
    name: &str,
    seal: impl Fn(&[u8], &[u8; 12], &[u8], &[u8]) -> Option<Vec<u8>>,
    open: impl Fn(&[u8], &[u8; 12], &[u8], &[u8]) -> Option<Result<Vec<u8>, Error>>,
) {
    let (mut valid, mut invalid) = (0, 0);
    for (_, t) in wycheproof(name) {
        let id = t.get("tcId").num();
        let (key, aad, msg, ct, tag) = (
            t.get("key").hex(),
            t.get("aad").hex(),
            t.get("msg").hex(),
            t.get("ct").hex(),
            t.get("tag").hex(),
        );
        let Ok(iv) = <[u8; 12]>::try_from(t.get("iv").hex()) else {
            continue;
        };
        let mut sealed = ct;
        sealed.extend_from_slice(&tag);
        let Some(r) = open(&key, &iv, &aad, &sealed) else {
            // Key size the AEAD does not take.
            continue;
        };
        match t.get("result").str() {
            "valid" | "acceptable" => {
                assert_eq!(r.unwrap(), msg, "tc {id}");
                assert_eq!(seal(&key, &iv, &aad, &msg).unwrap(), sealed, "tc {id}");
                valid += 1;
            }
            _ => {
                assert!(r.is_err(), "tc {id} must fail");
                invalid += 1;
            }
        }
    }
    assert!(valid > 50 && invalid > 20, "{valid} {invalid}");
}

#[test]
fn wycheproof_aes_gcm() {
    // Every kernel: the default (VAES + AVX-512 where the CPU has it), VAES-AVX2, the 128-bit
    // one, portable.
    type Key = fn(&[u8]) -> Option<AesGcm>;
    let kernels: [Key; 4] = [
        |k| AesGcm::new(k).ok(),
        |k| Some(AesGcm::with_cipher_avx2(Aes::new(k).ok()?)),
        |k| Some(AesGcm::with_cipher_narrow(Aes::new(k).ok()?)),
        |k| Some(AesGcm::with_cipher_portable(Aes::new_portable(k).ok()?)),
    ];
    for key in kernels {
        aead_vectors(
            "wycheproof_aes_gcm.json",
            |k, iv, aad, m| Some(key(k)?.encrypt(iv, aad, m)),
            |k, iv, aad, c| Some(key(k)?.decrypt(iv, aad, c)),
        );
    }
}

#[test]
fn wycheproof_chacha20_poly1305() {
    aead_vectors(
        "wycheproof_chacha20_poly1305.json",
        |k, iv, aad, m| Some(ChaCha20Poly1305::new(k.try_into().ok()?).encrypt(iv, aad, m)),
        |k, iv, aad, c| Some(ChaCha20Poly1305::new(k.try_into().ok()?).decrypt(iv, aad, c)),
    );
}

fn hmac_vectors<H: Hash>(name: &str) {
    let mut n = 0;
    for (g, t) in wycheproof(name) {
        let tag_len = g.get("tagSize").num() / 8;
        let (key, msg, tag) = (t.get("key").hex(), t.get("msg").hex(), t.get("tag").hex());
        let full = Hmac::<H>::mac(&key, &msg);
        let ok = Hmac::<H>::new(&key).chain(&msg).verify(&tag);
        let valid = t.get("result").str() == "valid";
        assert_eq!(ok, valid, "tc {}", t.get("tcId").num());
        if valid {
            assert_eq!(&full.as_ref()[..tag_len], &tag[..]);
        }
        n += 1;
    }
    assert!(n > 100);
}

#[test]
fn wycheproof_hmac() {
    hmac_vectors::<Sha1>("wycheproof_hmac_sha1.json");
    hmac_vectors::<Sha256>("wycheproof_hmac_sha256.json");
}

#[test]
fn wycheproof_hkdf_sha256() {
    let mut n = 0;
    for (_, t) in wycheproof("wycheproof_hkdf_sha256.json") {
        let mut okm = vec![0u8; t.get("size").num()];
        let r = kdf::hkdf::<Sha256>(
            &t.get("salt").hex(),
            &t.get("ikm").hex(),
            &t.get("info").hex(),
            &mut okm,
        );
        match t.get("result").str() {
            "valid" => {
                r.unwrap();
                assert_eq!(okm, t.get("okm").hex(), "tc {}", t.get("tcId").num());
            }
            _ => assert_eq!(r, Err(Error::InvalidLength)),
        }
        n += 1;
    }
    assert!(n > 80);
}
