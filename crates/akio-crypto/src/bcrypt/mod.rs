//! bcrypt password hashing (Provos and Mazières, "A Future-Adaptable Password Scheme", 1999), as
//! OpenBSD and Go's `golang.org/x/crypto/bcrypt` make and check it, for gateways that check HTTP
//! Basic passwords against `htpasswd -B` files.
//!
//! A hash is `$2a$`, `$2b$`, `$2y$` or `$2$`, a two-digit cost from 4 to 31, `$`, 22 characters
//! of salt and 31 of hash in bcrypt's base64. A check runs EksBlowfish with the hash's cost and
//! salt and compares the 23 bytes it makes with the hash's in constant time. The key is the
//! password and a NUL, cycled over Blowfish's 72 bytes of subkeys, as in Go: a password longer
//! than 72 bytes is checked by its first 72 (making a hash refuses it), and the minor versions
//! are checked alike (they differ only in an OpenBSD bug with passwords past 255 bytes).
//!
//! The work doubles with each step of the cost (2^cost key expansions): at cost 10 a check takes
//! tens of milliseconds of CPU. It belongs on the logical pool, never on an I/O thread.
//!
//! Timing: Blowfish indexes its S-boxes with key-dependent bytes, as every bcrypt does; the
//! cost of a check depends only on the hash's cost, and the comparison is constant time.
//!
//! ```
//! use akio_crypto::bcrypt;
//!
//! let h = bcrypt::hash(b"wonderland", bcrypt::MIN_COST).unwrap();
//! let parsed = bcrypt::Hash::parse(&h).unwrap();
//! assert!(parsed.verify(b"wonderland"));
//! assert!(!parsed.verify(b"Wonderland"));
//! assert_eq!(parsed.to_string(), h);
//! ```

mod consts;

use consts::{P, S0, S1, S2, S3};

use crate::Error;

/// The lowest cost a hash may have.
pub const MIN_COST: u32 = 4;
/// The highest cost a hash may have.
pub const MAX_COST: u32 = 31;
/// The cost `htpasswd -B` and Go use by default.
pub const DEFAULT_COST: u32 = 10;
/// The longest password [`hash`] takes, in bytes: bcrypt reads no further.
pub const MAX_PASSWORD_LEN: usize = 72;

/// bcrypt's base64 alphabet.
const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// What bcrypt encrypts, 64 times, with the expanded key.
const MAGIC: &[u8; 24] = b"OrpheanBeholderScryDoubt";

/// Why a string is not a bcrypt hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// It does not start with `$2a$`, `$2b$`, `$2y$` or `$2$`.
    Prefix,
    /// Its cost is not two digits from 4 to 31, followed by `$`.
    Cost,
    /// Its salt and hash are not 53 characters of bcrypt's base64.
    Encoding,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ParseError::Prefix => "it does not start with $2a$, $2b$ or $2y$",
            ParseError::Cost => "its cost is not two digits from 04 to 31",
            ParseError::Encoding => "its salt and hash are not 53 characters of bcrypt's base64",
        })
    }
}

impl std::error::Error for ParseError {}

/// A parsed bcrypt hash; [`Display`](std::fmt::Display) writes it back (as it was, unless the
/// last character of its salt or hash had bits set past the bytes they hold, which Go ignores
/// and so does this; they are written as zero).
#[derive(Clone, PartialEq, Eq)]
pub struct Hash {
    /// The minor version: `a`, `b`, `y`, or none (`$2$`).
    minor: Option<u8>,
    cost: u32,
    salt: [u8; 16],
    sum: [u8; 23],
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hash")
            .field("cost", &self.cost)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::with_capacity(60);
        s.push_str("$2");
        if let Some(m) = self.minor {
            s.push(char::from(m));
        }
        s.push('$');
        s.push(char::from(b'0' + (self.cost / 10) as u8));
        s.push(char::from(b'0' + (self.cost % 10) as u8));
        s.push('$');
        encode(&self.salt, &mut s);
        encode(&self.sum, &mut s);
        f.write_str(&s)
    }
}

impl Hash {
    /// Parses a hash in the modular crypt format.
    pub fn parse(s: &str) -> Result<Hash, ParseError> {
        let b = s.as_bytes();
        let (minor, rest) = match b {
            [b'$', b'2', b'$', rest @ ..] => (None, rest),
            [b'$', b'2', m @ (b'a' | b'b' | b'y'), b'$', rest @ ..] => (Some(*m), rest),
            _ => return Err(ParseError::Prefix),
        };
        let (cost, rest) = match rest {
            [d1 @ b'0'..=b'9', d2 @ b'0'..=b'9', b'$', rest @ ..] => {
                (u32::from(d1 - b'0') * 10 + u32::from(d2 - b'0'), rest)
            }
            _ => return Err(ParseError::Cost),
        };
        if !(MIN_COST..=MAX_COST).contains(&cost) {
            return Err(ParseError::Cost);
        }
        if rest.len() != 53 {
            return Err(ParseError::Encoding);
        }
        let (salt, sum) = rest.split_at(22);
        Ok(Hash {
            minor,
            cost,
            salt: decode(salt).ok_or(ParseError::Encoding)?,
            sum: decode(sum).ok_or(ParseError::Encoding)?,
        })
    }

    /// The cost: a check takes 2^cost key expansions.
    #[must_use]
    pub fn cost(&self) -> u32 {
        self.cost
    }

    /// Whether `password` is the one hashed (by its first 72 bytes), compared in constant time.
    /// Slow by design: see the module's documentation.
    #[must_use]
    pub fn verify(&self, password: &[u8]) -> bool {
        crate::ct_eq(&sum(password, self.cost, &self.salt), &self.sum)
    }
}

/// Hashes `password` with `cost` and a random salt, as `$2b$`.
///
/// # Errors
///
/// [`Error::InvalidLength`] for a password longer than [`MAX_PASSWORD_LEN`] or a cost outside
/// [`MIN_COST`]..=[`MAX_COST`]; [`Error::Random`] when the operating system gives no randomness.
pub fn hash(password: &[u8], cost: u32) -> Result<String, Error> {
    hash_with_salt(password, cost, &crate::random_array()?)
}

/// Hashes `password` with `cost` and `salt`, as `$2b$`: [`hash`] with a salt of the caller's
/// (tests, reproducing a hash).
///
/// # Errors
///
/// [`Error::InvalidLength`] as for [`hash`].
pub fn hash_with_salt(password: &[u8], cost: u32, salt: &[u8; 16]) -> Result<String, Error> {
    if password.len() > MAX_PASSWORD_LEN || !(MIN_COST..=MAX_COST).contains(&cost) {
        return Err(Error::InvalidLength);
    }
    Ok(Hash {
        minor: Some(b'b'),
        cost,
        salt: *salt,
        sum: sum(password, cost, salt),
    }
    .to_string())
}

/// The 23 bytes bcrypt makes of `password` with `cost` and `salt`.
fn sum(password: &[u8], cost: u32, salt: &[u8; 16]) -> [u8; 23] {
    let mut key = Vec::with_capacity(password.len() + 1);
    key.extend_from_slice(password);
    key.push(0);
    let mut c = Blowfish::new();
    c.expand_salted(&key, salt);
    for _ in 0..1u64 << cost.min(MAX_COST) {
        c.expand(&key);
        c.expand(salt);
    }
    let mut text = *MAGIC;
    for block in text.chunks_exact_mut(8) {
        let (mut l, mut r) = (
            u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
        );
        for _ in 0..64 {
            (l, r) = c.encrypt(l, r);
        }
        block[..4].copy_from_slice(&l.to_be_bytes());
        block[4..].copy_from_slice(&r.to_be_bytes());
    }
    let mut out = [0; 23];
    out.copy_from_slice(&text[..23]);
    // The key held the password; the state was keyed with it (best effort, as the crate does
    // not zeroize keys in general).
    key.fill(0);
    out
}

/// `chars` of bcrypt's base64 (no padding) as `N` bytes; bits past them are ignored, as Go's
/// decoder ignores them.
fn decode<const N: usize>(chars: &[u8]) -> Option<[u8; N]> {
    let mut out = [0; N];
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for c in chars {
        let v = ALPHABET.iter().position(|a| a == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *out.get_mut(n)? = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    (n == N).then_some(out)
}

/// Appends `bytes` in bcrypt's base64, without padding.
fn encode(bytes: &[u8], out: &mut String) {
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(char::from(ALPHABET[((acc >> bits) & 63) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((acc << (6 - bits)) & 63) as usize]));
    }
}

/// Blowfish's state: its subkeys and S-boxes.
struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

/// The next 4 bytes of `b` (never empty) from `*j`, big-endian, cycling over `b`.
fn next_word(b: &[u8], j: &mut usize) -> u32 {
    let mut w = 0u32;
    for _ in 0..4 {
        w = (w << 8) | u32::from(b[*j]);
        *j += 1;
        if *j == b.len() {
            *j = 0;
        }
    }
    w
}

impl Blowfish {
    fn new() -> Blowfish {
        Blowfish {
            p: P,
            s: [S0, S1, S2, S3],
        }
    }

    /// Blowfish's round function.
    #[inline(always)]
    fn f(&self, x: u32) -> u32 {
        let [a, b, c, d] = x.to_be_bytes();
        (self.s[0][usize::from(a)].wrapping_add(self.s[1][usize::from(b)])
            ^ self.s[2][usize::from(c)])
        .wrapping_add(self.s[3][usize::from(d)])
    }

    /// Encrypts the block `(l, r)`.
    #[inline(always)]
    fn encrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        l ^= self.p[0];
        for i in (1..17).step_by(2) {
            r ^= self.f(l) ^ self.p[i];
            l ^= self.f(r) ^ self.p[i + 1];
        }
        r ^= self.p[17];
        (r, l)
    }

    /// EksBlowfish's key schedule with a salt: the subkeys XORed with `key`, then the subkeys
    /// and S-boxes replaced by blocks encrypted in turn, each first XORed with the salt.
    fn expand_salted(&mut self, key: &[u8], salt: &[u8]) {
        self.mix_key(key);
        let mut j = 0;
        let (mut l, mut r) = (0, 0);
        for i in (0..18).step_by(2) {
            l ^= next_word(salt, &mut j);
            r ^= next_word(salt, &mut j);
            (l, r) = self.encrypt(l, r);
            self.p[i] = l;
            self.p[i + 1] = r;
        }
        for k in 0..4 {
            for i in (0..256).step_by(2) {
                l ^= next_word(salt, &mut j);
                r ^= next_word(salt, &mut j);
                (l, r) = self.encrypt(l, r);
                self.s[k][i] = l;
                self.s[k][i + 1] = r;
            }
        }
    }

    /// Blowfish's own key schedule, on the current state.
    fn expand(&mut self, key: &[u8]) {
        self.mix_key(key);
        let (mut l, mut r) = (0, 0);
        for i in (0..18).step_by(2) {
            (l, r) = self.encrypt(l, r);
            self.p[i] = l;
            self.p[i + 1] = r;
        }
        for k in 0..4 {
            for i in (0..256).step_by(2) {
                (l, r) = self.encrypt(l, r);
                self.s[k][i] = l;
                self.s[k][i + 1] = r;
            }
        }
    }

    fn mix_key(&mut self, key: &[u8]) {
        let mut j = 0;
        for p in &mut self.p {
            *p ^= next_word(key, &mut j);
        }
    }
}

#[cfg(test)]
mod tests;
