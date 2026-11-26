//! The measured operations. Each target turns a class (0 = the fixed secret, 1 = a fresh random
//! secret) into an input before the timed loop, and runs the operation on one input per
//! measurement. Inputs of both classes are separate objects laid out in measurement order, so
//! the fixed class is not favoured by staying in cache.

use std::hint::black_box;

use akio_crypto::chacha::{ChaCha20Poly1305, XChaCha20Poly1305};
use akio_crypto::ed25519::SigningKey;
use akio_crypto::gcm::AesGcm;
use akio_crypto::hash::{Blake2b, Sha256};
use akio_crypto::mac::Hmac;
use akio_crypto::rsa::HashAlg;
use akio_crypto::seed::Seed;
use akio_crypto::{ed448, p256, p521, rsa, x448, x25519};

use crate::ct;
use crate::rng::Rng;

/// What a target's verdict means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The classes differ in a secret: `|t|` above the threshold is a leak.
    Secret,
    /// The classes differ in something an attacker learns anyway (an AEAD tag that verifies or
    /// not): reported, never a leak.
    Public,
    /// A deliberately leaky function: `|t|` above the threshold shows the harness works; below
    /// it, the harness (or the machine) is not sensitive enough.
    Leaky,
}

impl Kind {
    /// The label in the report.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Secret => "secret",
            Self::Public => "public",
            Self::Leaky => "sanity",
        }
    }
}

/// One measured operation.
pub(crate) trait Target {
    /// Makes one input per entry of `classes`, in that order. With `fixed_random`, class 0 is
    /// not the special fixed value but the class-1 input drawn from a generator seeded with it
    /// (the same random-looking secret every time).
    fn prepare(&mut self, classes: &[u8], rng: &mut Rng, fixed_random: Option<u64>);
    /// Runs the operation on input `i` (the timed part).
    fn run(&mut self, i: usize);
}

/// A target and how to run it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Spec {
    /// Name on the command line and in the report.
    pub(crate) name: &'static str,
    /// What a difference means.
    pub(crate) kind: Kind,
    /// Whether the operation has a hardware path (`AKIO_CRYPTO_PORTABLE` changes it); the others
    /// run in the hardware pass only.
    pub(crate) hw: bool,
    /// Measurements per batch (one batch takes tens of milliseconds).
    pub(crate) batch: usize,
    /// Fixed class vs random class.
    pub(crate) about: &'static str,
    /// Builds the target (keys, ciphertexts).
    pub(crate) make: fn() -> Box<dyn Target>,
}

/// A target from an input generator and an operation.
struct FnTarget<S, I, G, O> {
    state: S,
    inputs: Vec<I>,
    gen_input: G,
    op: O,
}

impl<S, I, G, O> Target for FnTarget<S, I, G, O>
where
    G: FnMut(&S, u8, &mut Rng) -> I,
    O: FnMut(&S, &mut I),
{
    fn prepare(&mut self, classes: &[u8], rng: &mut Rng, fixed_random: Option<u64>) {
        self.inputs.clear();
        for &c in classes {
            let v = match fixed_random {
                Some(seed) if c == 0 => (self.gen_input)(&self.state, 1, &mut Rng::new(seed)),
                _ => (self.gen_input)(&self.state, c, rng),
            };
            self.inputs.push(v);
        }
    }

    fn run(&mut self, i: usize) {
        (self.op)(&self.state, &mut self.inputs[i]);
    }
}

fn boxed<S, I, G, O>(state: S, gen_input: G, op: O) -> Box<dyn Target>
where
    S: 'static,
    I: 'static,
    G: FnMut(&S, u8, &mut Rng) -> I + 'static,
    O: FnMut(&S, &mut I) + 'static,
{
    Box::new(FnTarget {
        state,
        inputs: Vec::new(),
        gen_input,
        op,
    })
}

/// Every target, in report order.
pub(crate) fn all() -> Vec<Spec> {
    vec![
        Spec {
            name: "p256-ecdh",
            kind: Kind::Secret,
            hw: true,
            batch: 1000,
            about: "P-256 ECDH d·Q: scalar 1 vs random scalar, fixed peer",
            make: p256_ecdh,
        },
        Spec {
            name: "p256-keygen",
            kind: Kind::Secret,
            hw: true,
            batch: 2000,
            about: "P-256 public key d·G (fixed-base comb): scalar 1 vs random scalar",
            make: p256_keygen,
        },
        Spec {
            name: "p256-sign",
            kind: Kind::Secret,
            hw: true,
            batch: 1000,
            about: "P-256 ECDSA sign (RFC 6979 nonce, k·G, k⁻¹): key 1 vs random key, fixed message",
            make: p256_sign,
        },
        Spec {
            name: "p521-ecdh",
            kind: Kind::Secret,
            hw: false,
            batch: 200,
            about: "P-521 ECDH d·Q (portable only): scalar 1 vs random scalar, fixed peer",
            make: p521_ecdh,
        },
        Spec {
            name: "p521-keygen",
            kind: Kind::Secret,
            hw: false,
            batch: 500,
            about: "P-521 public key d·G (fixed-base comb, portable only): scalar 1 vs random scalar",
            make: p521_keygen,
        },
        Spec {
            name: "p521-sign",
            kind: Kind::Secret,
            hw: false,
            batch: 300,
            about: "P-521 ECDSA sign (RFC 6979 nonce, k·G, k⁻¹; portable only): key 1 vs random key, fixed message",
            make: p521_sign,
        },
        Spec {
            name: "x25519",
            kind: Kind::Secret,
            hw: true,
            batch: 1000,
            about: "X25519 ladder: all-zero scalar (clamped: 2²⁵⁴) vs random scalar, fixed peer",
            make: x25519_dh,
        },
        Spec {
            name: "x25519-keygen",
            kind: Kind::Secret,
            hw: true,
            batch: 2000,
            about: "X25519 public key (Edwards fixed-base): all-zero vs random scalar",
            make: x25519_keygen,
        },
        Spec {
            name: "ed25519-sign",
            kind: Kind::Secret,
            hw: true,
            batch: 1000,
            about: "Ed25519 sign: all-zero seed vs random seed, fixed message",
            make: ed25519_sign,
        },
        Spec {
            name: "x448",
            kind: Kind::Secret,
            hw: false,
            batch: 50,
            about: "X448 ladder: all-zero scalar (clamped: 2⁴⁴⁷) vs random scalar, fixed peer",
            make: x448_dh,
        },
        Spec {
            name: "ed448-keygen",
            kind: Kind::Secret,
            hw: false,
            batch: 50,
            about: "Ed448 key from seed (SHAKE256, [s]B): all-zero vs random seed",
            make: ed448_keygen,
        },
        Spec {
            name: "ed448-sign",
            kind: Kind::Secret,
            hw: false,
            batch: 50,
            about: "Ed448 sign ([r]B, scalar arithmetic): all-zero seed vs random seed, fixed message",
            make: ed448_sign,
        },
        Spec {
            name: "rsa2048-sign-msg",
            kind: Kind::Secret,
            hw: true,
            batch: 100,
            about: "RSA-2048 PKCS#1 v1.5 sign (CRT, blinding): all-zero digest vs random digest",
            make: rsa_msg,
        },
        Spec {
            name: "rsa2048-sign-key",
            kind: Kind::Secret,
            hw: true,
            batch: 100,
            about: "RSA-2048 PKCS#1 v1.5 sign: test key A vs test key B (fixed vs fixed), fixed digest",
            make: rsa_key,
        },
        Spec {
            name: "aes128-gcm-open-tag",
            kind: Kind::Secret,
            hw: true,
            batch: 5000,
            about: "AES-128-GCM open, 256 B: tag wrong in the last byte vs random tag",
            make: gcm_tag,
        },
        Spec {
            name: "aes128-gcm-open-valid",
            kind: Kind::Public,
            hw: true,
            batch: 5000,
            about: "AES-128-GCM open, 256 B: valid tag vs random tag (failure undoes the decryption)",
            make: gcm_valid,
        },
        Spec {
            name: "chacha20poly1305-open-tag",
            kind: Kind::Secret,
            hw: true,
            batch: 5000,
            about: "ChaCha20-Poly1305 open, 256 B: tag wrong in the last byte vs random tag",
            make: chacha_tag,
        },
        Spec {
            name: "chacha20poly1305-open-tag-64",
            kind: Kind::Secret,
            hw: true,
            batch: 5000,
            about: "ChaCha20-Poly1305 open, 64 B (short-message head): tag wrong in the last byte vs random tag",
            make: chacha_tag_64,
        },
        Spec {
            name: "chacha20poly1305-open-valid",
            kind: Kind::Public,
            hw: true,
            batch: 5000,
            about: "ChaCha20-Poly1305 open, 256 B: valid tag vs random tag (failure skips decryption)",
            make: chacha_valid,
        },
        Spec {
            name: "xchacha20poly1305-open-tag",
            kind: Kind::Secret,
            hw: true,
            batch: 5000,
            about: "XChaCha20-Poly1305 open, 256 B (HChaCha20 subkey each call): tag wrong in the last byte vs random tag",
            make: xchacha_tag,
        },
        Spec {
            name: "blake2b-key",
            kind: Kind::Secret,
            hw: false,
            batch: 5000,
            about: "keyed BLAKE2b-256 over 256 B (Argon2id's hash of the password): all-zero key vs random key",
            make: blake2b_key,
        },
        Spec {
            name: "hmac-sha256-verify-tag",
            kind: Kind::Secret,
            hw: true,
            batch: 5000,
            about: "HMAC-SHA256 verify, 256 B: tag wrong in the last byte vs random tag",
            make: hmac_tag,
        },
        Spec {
            name: "hmac-sha256-verify-valid",
            kind: Kind::Secret,
            hw: true,
            batch: 5000,
            about: "HMAC-SHA256 verify, 256 B: valid tag vs random tag (both run to the end)",
            make: hmac_valid,
        },
        Spec {
            name: "seed-key",
            kind: Kind::Secret,
            hw: false,
            batch: 2000,
            about: "SEED key schedule and CTR over 256 B (one 16-block batch): all-zero key vs random key",
            make: seed_key,
        },
        Spec {
            name: "seed-block",
            kind: Kind::Secret,
            hw: false,
            batch: 5000,
            about: "SEED one block (the one-word G path), fixed key: all-zero block vs random block",
            make: seed_block,
        },
        Spec {
            name: "ct-eq",
            kind: Kind::Secret,
            hw: false,
            batch: 10_000,
            about: "akio_crypto::ct_eq, 32 B: equal but the last byte vs random",
            make: ct_eq_bytes,
        },
        Spec {
            name: "ct-word",
            kind: Kind::Secret,
            hw: false,
            batch: 10_000,
            about: "ct.rs mask, is_zero, eq, select over 64 words: zeros vs random",
            make: ct_word,
        },
        Spec {
            name: "ct-limbs",
            kind: Kind::Secret,
            hw: false,
            batch: 10_000,
            about: "ct.rs add_limbs, sub_limbs, lt_limbs, is_zero_limbs, assign, swap on 2048-bit limbs: zeros vs random",
            make: ct_limbs,
        },
        Spec {
            name: "sanity-null",
            kind: Kind::Secret,
            hw: false,
            batch: 10_000,
            about: "A/A test: SHA-256 of the same 256 B in both classes (false-positive check)",
            make: sanity_null,
        },
        Spec {
            name: "sanity-leaky-memcmp",
            kind: Kind::Leaky,
            hw: false,
            batch: 10_000,
            about: "early-exit compare, 256 B: equal but the last byte vs random (must be detected)",
            make: leaky_memcmp,
        },
        Spec {
            name: "sanity-leaky-modexp",
            kind: Kind::Leaky,
            hw: false,
            batch: 10_000,
            about: "square-and-multiply with a branch per exponent bit: exponent 2⁶³ vs random (must be detected)",
            make: leaky_modexp,
        },
    ]
}

// ---------------------------------------------------------------------------------------------
// Public-key targets

const ONE_256: [u8; 32] = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};

fn p256_key(c: u8, rng: &mut Rng) -> p256::SecretKey {
    if c == 0 {
        return p256::SecretKey::from_bytes(&ONE_256).expect("scalar 1");
    }
    loop {
        if let Ok(k) = p256::SecretKey::from_bytes(&rng.array::<32>()) {
            return k;
        }
    }
}

fn p256_ecdh() -> Box<dyn Target> {
    let peer = p256::SecretKey::from_bytes(&[0x42; 32])
        .expect("peer key")
        .public_key();
    boxed(
        peer,
        |_, c, rng| p256_key(c, rng),
        |peer, k| {
            black_box(black_box(&*k).diffie_hellman(peer));
        },
    )
}

fn p256_keygen() -> Box<dyn Target> {
    boxed(
        (),
        |(), c, rng| p256_key(c, rng),
        |(), k| {
            black_box(black_box(&*k).public_key());
        },
    )
}

fn p256_sign() -> Box<dyn Target> {
    boxed(
        [0x5a_u8; 32],
        |_, c, rng| p256_key(c, rng),
        |msg, k| {
            black_box(black_box(&*k).sign(msg));
        },
    )
}

const ONE_521: [u8; 66] = {
    let mut b = [0u8; 66];
    b[65] = 1;
    b
};

fn p521_key(c: u8, rng: &mut Rng) -> p521::SecretKey {
    if c == 0 {
        return p521::SecretKey::from_bytes(&ONE_521).expect("scalar 1");
    }
    loop {
        let mut b = rng.array::<66>();
        b[0] &= 1;
        if let Ok(k) = p521::SecretKey::from_bytes(&b) {
            return k;
        }
    }
}

fn p521_ecdh() -> Box<dyn Target> {
    let mut seed = [0x42; 66];
    seed[0] = 1;
    let peer = p521::SecretKey::from_bytes(&seed)
        .expect("peer key")
        .public_key();
    boxed(
        peer,
        |_, c, rng| p521_key(c, rng),
        |peer, k| {
            black_box(black_box(&*k).diffie_hellman(peer));
        },
    )
}

fn p521_keygen() -> Box<dyn Target> {
    boxed(
        (),
        |(), c, rng| p521_key(c, rng),
        |(), k| {
            black_box(black_box(&*k).public_key());
        },
    )
}

fn p521_sign() -> Box<dyn Target> {
    boxed(
        [0x5a_u8; 32],
        |_, c, rng| p521_key(c, rng),
        |msg, k| {
            black_box(black_box(&*k).sign(msg));
        },
    )
}

fn x25519_scalar(c: u8, rng: &mut Rng) -> x25519::PrivateKey {
    x25519::PrivateKey::from_bytes(if c == 0 { [0; 32] } else { rng.array() })
}

fn x25519_dh() -> Box<dyn Target> {
    let peer = x25519::PrivateKey::from_bytes([0x24; 32]).public_key();
    boxed(
        peer,
        |_, c, rng| x25519_scalar(c, rng),
        |peer, k| {
            black_box(black_box(&*k).diffie_hellman(peer).ok());
        },
    )
}

fn x25519_keygen() -> Box<dyn Target> {
    boxed(
        (),
        |(), c, rng| x25519_scalar(c, rng),
        |(), k| {
            black_box(black_box(&*k).public_key());
        },
    )
}

fn ed25519_sign() -> Box<dyn Target> {
    boxed(
        [0xa5_u8; 32],
        |_, c, rng| SigningKey::from_seed(&if c == 0 { [0; 32] } else { rng.array() }),
        |msg, k| {
            black_box(black_box(&*k).sign(msg));
        },
    )
}

fn x448_dh() -> Box<dyn Target> {
    let peer = x448::PrivateKey::from_bytes([0x24; 56]).public_key();
    boxed(
        peer,
        |_, c, rng| x448::PrivateKey::from_bytes(if c == 0 { [0; 56] } else { rng.array() }),
        |peer, k| {
            black_box(black_box(&*k).diffie_hellman(peer).ok());
        },
    )
}

fn ed448_seed(c: u8, rng: &mut Rng) -> [u8; 57] {
    if c == 0 { [0; 57] } else { rng.array() }
}

fn ed448_keygen() -> Box<dyn Target> {
    boxed(
        (),
        |(), c, rng| ed448_seed(c, rng),
        |(), seed| {
            black_box(ed448::SigningKey::from_seed(black_box(&*seed)));
        },
    )
}

fn ed448_sign() -> Box<dyn Target> {
    boxed(
        [0xa5_u8; 32],
        |_, c, rng| ed448::SigningKey::from_seed(&ed448_seed(c, rng)),
        |msg, k| {
            black_box(black_box(&*k).sign(msg));
        },
    )
}

/// The two RSA-2048 test keys: akio-crypto's (tests/data) and one generated for this tool
/// (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`; a test key, never used
/// for anything else).
fn rsa_keys() -> (rsa::PrivateKey, rsa::PrivateKey) {
    let load = |pem: &str| {
        let akio_crypto::pkey::PrivateKey::Rsa(k) =
            akio_crypto::pkey::PrivateKey::from_pem(pem.as_bytes()).expect("rsa test key")
        else {
            panic!("not an RSA key");
        };
        *k
    };
    (
        load(include_str!(
            "../../../crates/akio-crypto/tests/data/rsa2048_test_key.pem"
        )),
        load(include_str!("../data/rsa2048_second_test_key.pem")),
    )
}

fn rsa_msg() -> Box<dyn Target> {
    let (a, _) = rsa_keys();
    boxed(
        a,
        |_, c, rng| if c == 0 { [0u8; 32] } else { rng.array::<32>() },
        |key, digest| {
            black_box(
                key.sign_pkcs1v15_prehash(HashAlg::Sha256, black_box(&*digest))
                    .expect("sign"),
            );
        },
    )
}

fn rsa_key() -> Box<dyn Target> {
    let (a, b) = rsa_keys();
    boxed(
        ([a, b], [0x3c_u8; 32]),
        |_, c, _| usize::from(c),
        |(keys, digest), which| {
            let key = &keys[black_box(*which)];
            black_box(
                key.sign_pkcs1v15_prehash(HashAlg::Sha256, digest)
                    .expect("sign"),
            );
        },
    )
}

// ---------------------------------------------------------------------------------------------
// AEAD and MAC verification

const NONCE: [u8; 12] = [0x22; 12];
const AAD: &[u8] = b"ct-dudect";

/// The tag for class `c`: the valid tag with its last byte flipped (`near`) or a random tag;
/// or, for the validity targets, the valid tag itself.
fn tag_for<const N: usize>(valid: &[u8; N], c: u8, near: bool, rng: &mut Rng) -> [u8; N] {
    if c == 1 {
        let mut t: [u8; N] = rng.array();
        if t == *valid {
            t[0] ^= 1;
        }
        return t;
    }
    let mut t = *valid;
    if near {
        t[N - 1] ^= 1;
    }
    t
}

struct Aead<C> {
    cipher: C,
    ct: Vec<u8>,
    tag: [u8; 16],
}

fn gcm(near: bool) -> Box<dyn Target> {
    let cipher = AesGcm::new(&[0x11; 16]).expect("aes key");
    let mut ct = vec![0x33u8; 256];
    let tag = cipher.encrypt_in_place_detached(&NONCE, AAD, &mut ct);
    boxed(
        Aead { cipher, ct, tag },
        move |s: &Aead<AesGcm>, c, rng| (s.ct.clone(), tag_for(&s.tag, c, near, rng)),
        |s, (buf, tag)| {
            black_box(
                s.cipher
                    .decrypt_in_place_detached(&NONCE, AAD, black_box(buf), black_box(&*tag))
                    .is_ok(),
            );
        },
    )
}

fn gcm_tag() -> Box<dyn Target> {
    gcm(true)
}

fn gcm_valid() -> Box<dyn Target> {
    gcm(false)
}

fn chacha(near: bool, len: usize) -> Box<dyn Target> {
    let cipher = ChaCha20Poly1305::new(&[0x11; 32]);
    let mut ct = vec![0x33u8; len];
    let tag = cipher.encrypt_in_place_detached(&NONCE, AAD, &mut ct);
    boxed(
        Aead { cipher, ct, tag },
        move |s: &Aead<ChaCha20Poly1305>, c, rng| (s.ct.clone(), tag_for(&s.tag, c, near, rng)),
        |s, (buf, tag)| {
            black_box(
                s.cipher
                    .decrypt_in_place_detached(&NONCE, AAD, black_box(buf), black_box(&*tag))
                    .is_ok(),
            );
        },
    )
}

fn chacha_tag() -> Box<dyn Target> {
    chacha(true, 256)
}

/// The short-message path: the head is one row-kernel call that also hands the Poly1305 key over
/// in registers (up to 192 bytes on AVX-512).
fn chacha_tag_64() -> Box<dyn Target> {
    chacha(true, 64)
}

fn chacha_valid() -> Box<dyn Target> {
    chacha(false, 256)
}

fn xchacha_tag() -> Box<dyn Target> {
    const XNONCE: [u8; 24] = [0x22; 24];
    let cipher = XChaCha20Poly1305::new(&[0x11; 32]);
    let mut ct = vec![0x33u8; 256];
    let tag = cipher.encrypt_in_place_detached(&XNONCE, AAD, &mut ct);
    boxed(
        Aead { cipher, ct, tag },
        |s: &Aead<XChaCha20Poly1305>, c, rng| (s.ct.clone(), tag_for(&s.tag, c, true, rng)),
        |s, (buf, tag)| {
            black_box(
                s.cipher
                    .decrypt_in_place_detached(&XNONCE, AAD, black_box(buf), black_box(&*tag))
                    .is_ok(),
            );
        },
    )
}

fn blake2b_key() -> Box<dyn Target> {
    boxed(
        vec![0x55u8; 256],
        |_, c, rng| if c == 0 { [0u8; 32] } else { rng.array() },
        |msg, k| {
            let Ok(mut h) = Blake2b::new_keyed(black_box(&*k), 32) else {
                return;
            };
            h.update(msg);
            let mut out = [0u8; 32];
            if h.finalize_into(&mut out).is_ok() {
                black_box(out);
            }
        },
    )
}

fn hmac(near: bool) -> Box<dyn Target> {
    let key = [0x44u8; 32];
    let msg = vec![0x55u8; 256];
    let tag = Hmac::<Sha256>::mac(&key, &msg);
    boxed(
        (key, msg, tag),
        move |(_, _, tag), c, rng| tag_for(tag, c, near, rng),
        |(key, msg, _), tag| {
            black_box(Hmac::<Sha256>::new(key).chain(msg).verify(black_box(&*tag)));
        },
    )
}

fn hmac_tag() -> Box<dyn Target> {
    hmac(true)
}

fn hmac_valid() -> Box<dyn Target> {
    hmac(false)
}

// ---------------------------------------------------------------------------------------------
// Constant-time primitives

fn seed_key() -> Box<dyn Target> {
    boxed(
        (),
        |(), c, rng| if c == 0 { [0u8; 16] } else { rng.array() },
        |(), k| {
            let s = Seed::new(black_box(&*k));
            let mut buf = [0u8; 256];
            s.apply_ctr(&[0x44; 16], &mut buf);
            black_box(buf);
        },
    )
}

fn seed_block() -> Box<dyn Target> {
    boxed(
        Seed::new(&[0x11; 16]),
        |_, c, rng| if c == 0 { [0u8; 16] } else { rng.array() },
        |s, b| {
            let mut x = *b;
            s.encrypt_block(black_box(&mut x));
            black_box(x);
        },
    )
}

fn ct_eq_bytes() -> Box<dyn Target> {
    boxed(
        [0x66u8; 32],
        |r, c, rng| tag_for(r, c, true, rng),
        |r, x| {
            black_box(akio_crypto::ct_eq(black_box(r), black_box(&*x)));
        },
    )
}

fn words(c: u8, rng: &mut Rng) -> [u64; 64] {
    let mut w = [0u64; 64];
    if c == 1 {
        for x in &mut w {
            *x = rng.next_u64();
        }
    }
    w
}

fn ct_word() -> Box<dyn Target> {
    boxed(
        (),
        |(), c, rng| (words(c, rng), words(c, rng)),
        |(), (a, b)| {
            let (a, b) = (black_box(&*a), black_box(&*b));
            let mut acc = 0u64;
            for (&x, &y) in a.iter().zip(b) {
                let m = ct::eq(x, y);
                acc ^= ct::select(m, x, y) ^ ct::is_zero(x) ^ ct::mask(x & 1);
            }
            black_box(acc);
        },
    )
}

fn limbs(c: u8, rng: &mut Rng) -> [u64; 32] {
    let mut w = [0u64; 32];
    if c == 1 {
        for x in &mut w {
            *x = rng.next_u64();
        }
    }
    w
}

fn ct_limbs() -> Box<dyn Target> {
    boxed(
        (),
        |(), c, rng| (limbs(c, rng), limbs(c, rng)),
        |(), (a, b)| {
            let (a, b) = (black_box(&*a), black_box(&*b));
            let mut s = [0u64; 32];
            let mut d = [0u64; 32];
            let carry = ct::add_limbs(&mut s, a, b);
            let borrow = ct::sub_limbs(&mut d, a, b);
            let lt = ct::lt_limbs(a, b);
            let z = ct::is_zero_limbs(a);
            ct::assign(lt, &mut s, b);
            ct::swap(z, &mut s, &mut d);
            black_box((carry, borrow, s, d));
        },
    )
}

// ---------------------------------------------------------------------------------------------
// Sanity checks

fn sanity_null() -> Box<dyn Target> {
    boxed(
        (),
        |(), _, _| [0x77u8; 256],
        |(), x| {
            black_box(Sha256::digest(black_box(&x[..])));
        },
    )
}

/// The comparison a constant-time compare replaces: returns at the first differing byte.
#[inline(never)]
fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
    for (x, y) in a.iter().zip(b) {
        // `black_box` keeps the loop a byte loop (no vectorized compare of whole blocks).
        if black_box(*x) != *y {
            return false;
        }
    }
    true
}

fn leaky_memcmp() -> Box<dyn Target> {
    boxed(
        [0x88u8; 256],
        |r, c, rng| tag_for(r, c, true, rng),
        |r, x| {
            black_box(leaky_eq(r, &x[..]));
        },
    )
}

/// `b^e mod 2⁶¹-1` by square-and-multiply with a branch on each exponent bit.
#[inline(never)]
fn leaky_pow(b: u64, e: u64) -> u64 {
    const M: u128 = (1 << 61) - 1;
    let mut r = 1u128;
    let mut x = u128::from(b) % M;
    for i in 0..64 {
        if black_box(e >> i) & 1 == 1 {
            r = r * x % M;
        }
        x = x * x % M;
    }
    // Below 2⁶¹.
    #[allow(clippy::cast_possible_truncation)]
    let r = r as u64;
    r
}

fn leaky_modexp() -> Box<dyn Target> {
    boxed(
        0x1234_5678_9abc_def1_u64,
        |_, c, rng| if c == 0 { 1u64 << 63 } else { rng.next_u64() },
        |b, e| {
            black_box(leaky_pow(*b, black_box(*e)));
        },
    )
}
