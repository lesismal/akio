//! Cross-checks against the RustCrypto / `crc32fast` / `base64` crates this crate replaced
//! (dev-dependencies only), on pseudorandom inputs of many lengths.

use akio_crypto::rand::ChaChaRng;

fn inputs() -> Vec<Vec<u8>> {
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let mut v = Vec::new();
    for len in (0..300).chain([511, 512, 513, 1000, 1472, 4096, 10_000]) {
        let mut b = vec![0u8; len];
        rng.fill(&mut b);
        v.push(b);
    }
    v
}

#[test]
fn hashes_match() {
    use sha2::Digest as _;
    for m in inputs() {
        assert_eq!(
            akio_crypto::hash::Sha1::digest(&m)[..],
            sha1::Sha1::digest(&m)[..]
        );
        assert_eq!(
            akio_crypto::hash::Sha224::digest(&m)[..],
            sha2::Sha224::digest(&m)[..]
        );
        assert_eq!(
            akio_crypto::hash::Sha256::digest(&m)[..],
            sha2::Sha256::digest(&m)[..]
        );
        assert_eq!(
            akio_crypto::hash::Sha384::digest(&m)[..],
            sha2::Sha384::digest(&m)[..]
        );
        assert_eq!(
            akio_crypto::hash::Sha512::digest(&m)[..],
            sha2::Sha512::digest(&m)[..]
        );
        assert_eq!(
            akio_crypto::hash::Md5::digest(&m)[..],
            md5::Md5::digest(&m)[..]
        );
        assert_eq!(akio_crypto::crc::crc32(&m), crc32fast::hash(&m));
    }
}

#[test]
fn hmac_pbkdf2_hkdf_match() {
    use hmac::Mac as _;
    let ins = inputs();
    for (i, m) in ins.iter().enumerate() {
        let key = &ins[(i * 7) % ins.len()];
        let ours = akio_crypto::mac::Hmac::<akio_crypto::hash::Sha1>::mac(key, m);
        let mut theirs = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
        theirs.update(m);
        assert_eq!(ours[..], theirs.finalize().into_bytes()[..]);
        let ours = akio_crypto::mac::Hmac::<akio_crypto::hash::Sha256>::mac(key, m);
        let mut theirs = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        theirs.update(m);
        assert_eq!(ours[..], theirs.finalize().into_bytes()[..]);
        if i % 10 == 0 {
            let n = (i % 100) + 1;
            let mut a = vec![0u8; n];
            let mut b = vec![0u8; n];
            akio_crypto::kdf::pbkdf2_hmac::<akio_crypto::hash::Sha1>(key, m, 3, &mut a);
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(key, m, 3, &mut b);
            assert_eq!(a, b);
            akio_crypto::kdf::pbkdf2_hmac::<akio_crypto::hash::Sha256>(key, m, 2, &mut a);
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(key, m, 2, &mut b);
            assert_eq!(a, b);
            akio_crypto::kdf::hkdf::<akio_crypto::hash::Sha256>(key, m, b"info", &mut a).unwrap();
            hkdf::Hkdf::<sha2::Sha256>::new(Some(key), m)
                .expand(b"info", &mut b)
                .unwrap();
            assert_eq!(a, b);
        }
    }
    // kcp-go's XOR table: PBKDF2-HMAC-SHA1, 32 rounds, 1472 bytes.
    let mut a = vec![0u8; 1472];
    let mut b = vec![0u8; 1472];
    akio_crypto::kdf::pbkdf2_hmac::<akio_crypto::hash::Sha1>(
        b"pass",
        b"sH3CIVoF#rWLtJo6",
        32,
        &mut a,
    );
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"pass", b"sH3CIVoF#rWLtJo6", 32, &mut b);
    assert_eq!(a, b);
}

#[test]
fn aes_ctr_gcm_match() {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
    use aes_gcm::aead::{Aead, Payload};
    let ins = inputs();
    for (i, m) in ins.iter().enumerate() {
        let key: Vec<u8> = ins[299]
            .iter()
            .copied()
            .cycle()
            .skip(i)
            .take([16, 24, 32][i % 3])
            .collect();
        let ours = akio_crypto::aes::Aes::new(&key).unwrap();
        let mut blk = [0u8; 16];
        blk.copy_from_slice(&ins[100][i % 80..i % 80 + 16]);
        let mut a = blk;
        ours.encrypt_block(&mut a);
        let mut b = aes::Block::from(blk);
        match key.len() {
            16 => aes::Aes128::new_from_slice(&key)
                .unwrap()
                .encrypt_block(&mut b),
            24 => aes::Aes192::new_from_slice(&key)
                .unwrap()
                .encrypt_block(&mut b),
            _ => aes::Aes256::new_from_slice(&key)
                .unwrap()
                .encrypt_block(&mut b),
        }
        assert_eq!(a[..], b[..]);
        ours.decrypt_block(&mut a);
        assert_eq!(a, blk);
        if key.len() == 16 {
            let mut d = aes::Block::from(blk);
            aes::Aes128::new_from_slice(&key)
                .unwrap()
                .decrypt_block(&mut d);
            let mut e = blk;
            ours.decrypt_block(&mut e);
            assert_eq!(e[..], d[..]);
            // CTR (SRTP AES-CM), the counter starting near a 64-bit boundary.
            let mut iv = blk;
            iv[8..].fill(0xff);
            let mut x = m.clone();
            ours.apply_ctr(&iv, &mut x);
            let mut y = m.clone();
            ctr::Ctr128BE::<aes::Aes128>::new(key[..].into(), (&iv).into()).apply_keystream(&mut y);
            assert_eq!(x, y);
        }
        let nonce: [u8; 12] = blk[..12].try_into().unwrap();
        let aad = &ins[i % 40];
        let gcm = akio_crypto::gcm::AesGcm::new(&key).unwrap();
        let sealed = gcm.encrypt(&nonce, aad, m);
        let theirs = match key.len() {
            16 => aes_gcm::Aes128Gcm::new_from_slice(&key)
                .unwrap()
                .encrypt((&nonce).into(), Payload { msg: m, aad })
                .unwrap(),
            24 => continue,
            _ => aes_gcm::Aes256Gcm::new_from_slice(&key)
                .unwrap()
                .encrypt((&nonce).into(), Payload { msg: m, aad })
                .unwrap(),
        };
        assert_eq!(sealed, theirs, "len {}", m.len());
        assert_eq!(&gcm.decrypt(&nonce, aad, &theirs).unwrap(), m);
    }
}

#[test]
fn chacha20_poly1305_matches() {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    let ins = inputs();
    for (i, m) in ins.iter().enumerate() {
        let key: [u8; 32] = ins[299][i % 200..i % 200 + 32].try_into().unwrap();
        let nonce: [u8; 12] = ins[298][i % 200..i % 200 + 12].try_into().unwrap();
        let aad = &ins[(i * 3) % 50];
        let ours = akio_crypto::chacha::ChaCha20Poly1305::new(&key).encrypt(&nonce, aad, m);
        let theirs = chacha20poly1305::ChaCha20Poly1305::new((&key).into())
            .encrypt((&nonce).into(), Payload { msg: m, aad })
            .unwrap();
        assert_eq!(ours, theirs);
    }
}

#[test]
fn base64_matches() {
    use base64::Engine as _;
    use base64::engine::general_purpose as gp;
    let pairs = [
        (akio_crypto::base64::STANDARD, gp::STANDARD),
        (akio_crypto::base64::STANDARD_NO_PAD, gp::STANDARD_NO_PAD),
        (akio_crypto::base64::URL_SAFE, gp::URL_SAFE),
        (akio_crypto::base64::URL_SAFE_NO_PAD, gp::URL_SAFE_NO_PAD),
    ];
    let ins = inputs();
    for m in &ins[..120] {
        for (ours, theirs) in &pairs {
            assert_eq!(ours.encode(m), theirs.encode(m));
        }
    }
    // Decoding: same verdict on valid strings, mutated strings and random junk.
    let mut rng = ChaChaRng::from_seed([7; 32]);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_= \n.";
    for (n, m) in ins[..120].iter().enumerate() {
        for (ours, theirs) in &pairs {
            let mut s = theirs.encode(m).into_bytes();
            for round in 0..4 {
                let a = ours.decode(&s);
                let b = theirs.decode(&s);
                assert_eq!(
                    a.is_ok(),
                    b.is_ok(),
                    "{:?} {a:?} {b:?}",
                    String::from_utf8_lossy(&s)
                );
                if let (Ok(a), Ok(b)) = (a, b) {
                    assert_eq!(a, b);
                }
                // Mutate one symbol or the length.
                let r = rng.next_u32() as usize;
                match (round + n) % 3 {
                    0 if !s.is_empty() => {
                        let p = r % s.len();
                        s[p] = alphabet[(r >> 8) % alphabet.len()];
                    }
                    1 => s.push(alphabet[r % alphabet.len()]),
                    _ => {
                        s.pop();
                    }
                }
            }
        }
    }
}
