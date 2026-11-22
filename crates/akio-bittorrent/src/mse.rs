//! Message Stream Encryption (MSE/PE), the obfuscation handshake mainstream clients speak:
//! a 768-bit Diffie-Hellman exchange, then RC4 (first 1024 bytes of keystream dropped) keyed
//! from the shared secret and the info hash. Both roles are state machines without I/O:
//! [`Initiator`] and [`Receiver`] take the bytes read and return the bytes to write, until the
//! handshake is [`Established`].

use std::fmt;

use akio_crypto::hash::Sha1;

use crate::metainfo::InfoHash;

/// `crypto_provide` / `crypto_select` bit: plaintext after the handshake.
pub const CRYPTO_PLAINTEXT: u32 = 0x01;
/// `crypto_provide` / `crypto_select` bit: RC4 for the whole stream.
pub const CRYPTO_RC4: u32 = 0x02;

const MAX_PAD: usize = 512;
const KEY_LEN: usize = 96;
const VC: [u8; 8] = [0; 8];

/// How a connection may be encrypted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Policy {
    /// Plaintext only: no MSE handshake is started; incoming MSE is still accepted.
    Disabled,
    /// MSE when dialing (RC4 preferred, plaintext offered); incoming plaintext or MSE accepted.
    #[default]
    Prefer,
    /// MSE with RC4 only, both ways; plaintext peers are refused.
    Require,
}

/// RC4 with the first 1024 bytes of keystream discarded, as MSE uses it.
#[derive(Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl fmt::Debug for Rc4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rc4(..)")
    }
}

impl Rc4 {
    /// RC4 keyed with `key`, the first 1024 bytes of keystream already dropped.
    pub fn new(key: &[u8]) -> Rc4 {
        let mut s = [0u8; 256];
        for (i, x) in s.iter_mut().enumerate() {
            *x = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        let mut r = Rc4 { s, i: 0, j: 0 };
        let mut skip = [0u8; 1024];
        r.apply(&mut skip);
        r
    }

    /// XORs the keystream into `data` in place.
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(
                self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]),
            )];
            *b ^= k;
        }
    }
}

/// Why a handshake failed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MseError {
    /// The synchronisation pattern did not show up within the padding allowed.
    NoSync,
    /// The receiver does not serve the torrent the initiator asked for.
    UnknownTorrent,
    /// No crypto method both sides accept.
    NoCommonMethod,
    /// A field out of range (padding too long, a bad verification constant).
    Malformed(&'static str),
}

impl fmt::Display for MseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MseError::NoSync => f.write_str("mse: no synchronisation"),
            MseError::UnknownTorrent => f.write_str("mse: unknown torrent"),
            MseError::NoCommonMethod => f.write_str("mse: no common crypto method"),
            MseError::Malformed(m) => write!(f, "mse: malformed {m}"),
        }
    }
}

impl std::error::Error for MseError {}

/// A finished handshake.
#[derive(Debug)]
#[non_exhaustive]
pub struct Established {
    /// The torrent (for a receiver: the one the initiator asked for).
    pub info_hash: InfoHash,
    /// `(encrypt, decrypt)` for the rest of the stream; `None` when plaintext was selected.
    pub cipher: Option<(Rc4, Rc4)>,
    /// Stream bytes received past the handshake, already decrypted (for a receiver this starts
    /// with the initiator's initial payload, normally its BitTorrent handshake).
    pub data: Vec<u8>,
}

/// What a handshake step produced.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Progress {
    /// Bytes to write to the peer now.
    pub send: Vec<u8>,
    /// Set once the handshake is complete.
    pub done: Option<Established>,
}

fn hash(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

fn random_pad() -> Vec<u8> {
    let mut n = [0u8; 2];
    crate::rand_fill(&mut n);
    let len = usize::from(u16::from_le_bytes(n)) % (MAX_PAD + 1);
    let mut p = vec![0u8; len];
    crate::rand_fill(&mut p);
    p
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[derive(Debug)]
enum IState {
    WaitYb,
    WaitVc,
    WaitSelect,
    WaitPadD { select: u32, len: usize },
    Done,
}

/// The side that dials: knows the torrent, sends the BitTorrent handshake as the initial payload.
#[derive(Debug)]
pub struct Initiator {
    state: IState,
    private: [u8; 20],
    info_hash: InfoHash,
    provide: u32,
    ia: Vec<u8>,
    buf: Vec<u8>,
    enc: Option<Rc4>,
    dec: Option<Rc4>,
    vc_enc: [u8; 8],
}

impl Initiator {
    /// Starts a handshake for `info_hash`, offering `provide` ([`CRYPTO_RC4`] and/or
    /// [`CRYPTO_PLAINTEXT`]) and carrying `initial_payload` (normally the BitTorrent handshake).
    /// Returns the initiator and the first bytes to write.
    pub fn new(
        info_hash: InfoHash,
        provide: u32,
        initial_payload: Vec<u8>,
    ) -> (Initiator, Vec<u8>) {
        let mut private = [0u8; 20];
        crate::rand_fill(&mut private);
        let mut out = dh::public_key(&private).to_vec();
        out.extend_from_slice(&random_pad());
        (
            Initiator {
                state: IState::WaitYb,
                private,
                info_hash,
                provide,
                ia: initial_payload,
                buf: Vec::new(),
                enc: None,
                dec: None,
                vc_enc: [0; 8],
            },
            out,
        )
    }

    /// Takes bytes from the peer.
    pub fn feed(&mut self, data: &[u8]) -> Result<Progress, MseError> {
        self.buf.extend_from_slice(data);
        let mut p = Progress::default();
        loop {
            match self.state {
                IState::WaitYb => {
                    if self.buf.len() < KEY_LEN {
                        return Ok(p);
                    }
                    let s = dh::shared_secret(&self.private, &self.buf[..KEY_LEN]);
                    self.buf.drain(..KEY_LEN);
                    let skey = self.info_hash.0;
                    let mut enc = Rc4::new(&hash(&[b"keyA", &s, &skey]));
                    let dec = Rc4::new(&hash(&[b"keyB", &s, &skey]));
                    let mut vc = VC;
                    dec.clone().apply(&mut vc);
                    self.vc_enc = vc;
                    p.send.extend_from_slice(&hash(&[b"req1", &s]));
                    let r2 = hash(&[b"req2", &skey]);
                    let r3 = hash(&[b"req3", &s]);
                    p.send.extend(r2.iter().zip(r3.iter()).map(|(a, b)| a ^ b));
                    let pad_c: Vec<u8> = Vec::new();
                    let mut plain = VC.to_vec();
                    plain.extend_from_slice(&self.provide.to_be_bytes());
                    plain.extend_from_slice(&(pad_c.len() as u16).to_be_bytes());
                    plain.extend_from_slice(&pad_c);
                    plain.extend_from_slice(&(self.ia.len() as u16).to_be_bytes());
                    plain.extend_from_slice(&self.ia);
                    enc.apply(&mut plain);
                    p.send.extend_from_slice(&plain);
                    self.enc = Some(enc);
                    self.dec = Some(dec);
                    self.state = IState::WaitVc;
                }
                IState::WaitVc => match find(&self.buf, &self.vc_enc) {
                    Some(i) => {
                        self.buf.drain(..i + 8);
                        if let Some(d) = &mut self.dec {
                            let mut vc = VC;
                            d.apply(&mut vc);
                        }
                        self.state = IState::WaitSelect;
                    }
                    None if self.buf.len() >= MAX_PAD + 8 => return Err(MseError::NoSync),
                    None => return Ok(p),
                },
                IState::WaitSelect => {
                    if self.buf.len() < 6 {
                        return Ok(p);
                    }
                    let mut h: Vec<u8> = self.buf.drain(..6).collect();
                    if let Some(d) = &mut self.dec {
                        d.apply(&mut h);
                    }
                    let select = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
                    let len = usize::from(u16::from_be_bytes([h[4], h[5]]));
                    if len > MAX_PAD {
                        return Err(MseError::Malformed("padD length"));
                    }
                    if select & self.provide == 0
                        || (select != CRYPTO_RC4 && select != CRYPTO_PLAINTEXT)
                    {
                        return Err(MseError::NoCommonMethod);
                    }
                    self.state = IState::WaitPadD { select, len };
                }
                IState::WaitPadD { select, len } => {
                    if self.buf.len() < len {
                        return Ok(p);
                    }
                    let mut pad: Vec<u8> = self.buf.drain(..len).collect();
                    let mut dec = self.dec.take().ok_or(MseError::Malformed("state"))?;
                    dec.apply(&mut pad);
                    let enc = self.enc.take().ok_or(MseError::Malformed("state"))?;
                    let mut rest = std::mem::take(&mut self.buf);
                    let cipher = if select == CRYPTO_RC4 {
                        dec.apply(&mut rest);
                        Some((enc, dec))
                    } else {
                        None
                    };
                    self.state = IState::Done;
                    p.done = Some(Established {
                        info_hash: self.info_hash,
                        cipher,
                        data: rest,
                    });
                    return Ok(p);
                }
                IState::Done => return Ok(p),
            }
        }
    }
}

#[derive(Debug)]
enum RState {
    WaitYa,
    WaitReq1,
    WaitReq2,
    WaitProvide,
    WaitPadC { provide: u32, len: usize },
    WaitIaLen { provide: u32 },
    WaitIa { provide: u32, len: usize },
    Done,
}

/// The side that accepts: learns the torrent from the handshake.
#[derive(Debug)]
pub struct Receiver {
    state: RState,
    private: [u8; 20],
    accept: u32,
    buf: Vec<u8>,
    secret: [u8; KEY_LEN],
    req1: [u8; 20],
    skey: InfoHash,
    dec: Option<Rc4>,
    enc: Option<Rc4>,
}

impl Receiver {
    /// A receiver accepting the methods in `accept` ([`CRYPTO_RC4`] and/or
    /// [`CRYPTO_PLAINTEXT`]); RC4 is chosen when both sides allow it.
    pub fn new(accept: u32) -> Receiver {
        let mut private = [0u8; 20];
        crate::rand_fill(&mut private);
        Receiver {
            state: RState::WaitYa,
            private,
            accept,
            buf: Vec::new(),
            secret: [0; KEY_LEN],
            req1: [0; 20],
            skey: InfoHash::default(),
            dec: None,
            enc: None,
        }
    }

    /// Takes bytes from the peer. `lookup` maps `HASH('req2', info_hash)` to an info hash this
    /// side serves.
    pub fn feed(
        &mut self,
        data: &[u8],
        lookup: &dyn Fn(&[u8; 20]) -> Option<InfoHash>,
    ) -> Result<Progress, MseError> {
        self.buf.extend_from_slice(data);
        let mut p = Progress::default();
        loop {
            match self.state {
                RState::WaitYa => {
                    if self.buf.len() < KEY_LEN {
                        return Ok(p);
                    }
                    self.secret = dh::shared_secret(&self.private, &self.buf[..KEY_LEN]);
                    self.buf.drain(..KEY_LEN);
                    self.req1 = hash(&[b"req1", &self.secret]);
                    p.send.extend_from_slice(&dh::public_key(&self.private));
                    p.send.extend_from_slice(&random_pad());
                    self.state = RState::WaitReq1;
                }
                RState::WaitReq1 => match find(&self.buf, &self.req1) {
                    Some(i) => {
                        self.buf.drain(..i + 20);
                        self.state = RState::WaitReq2;
                    }
                    None if self.buf.len() >= MAX_PAD + 20 => {
                        return Err(MseError::NoSync);
                    }
                    None => return Ok(p),
                },
                RState::WaitReq2 => {
                    if self.buf.len() < 20 {
                        return Ok(p);
                    }
                    let r3 = hash(&[b"req3", &self.secret]);
                    let mut r2 = [0u8; 20];
                    for (i, o) in r2.iter_mut().enumerate() {
                        *o = self.buf[i] ^ r3[i];
                    }
                    self.buf.drain(..20);
                    self.skey = lookup(&r2).ok_or(MseError::UnknownTorrent)?;
                    let s = self.secret;
                    self.dec = Some(Rc4::new(&hash(&[b"keyA", &s, &self.skey.0])));
                    self.enc = Some(Rc4::new(&hash(&[b"keyB", &s, &self.skey.0])));
                    self.state = RState::WaitProvide;
                }
                RState::WaitProvide => {
                    if self.buf.len() < 14 {
                        return Ok(p);
                    }
                    let mut h: Vec<u8> = self.buf.drain(..14).collect();
                    self.decrypt(&mut h);
                    if h[..8] != VC {
                        return Err(MseError::Malformed("verification constant"));
                    }
                    let provide = u32::from_be_bytes([h[8], h[9], h[10], h[11]]);
                    let len = usize::from(u16::from_be_bytes([h[12], h[13]]));
                    if len > MAX_PAD {
                        return Err(MseError::Malformed("padC length"));
                    }
                    self.state = RState::WaitPadC { provide, len };
                }
                RState::WaitPadC { provide, len } => {
                    if self.buf.len() < len {
                        return Ok(p);
                    }
                    let mut pad: Vec<u8> = self.buf.drain(..len).collect();
                    self.decrypt(&mut pad);
                    self.state = RState::WaitIaLen { provide };
                }
                RState::WaitIaLen { provide } => {
                    if self.buf.len() < 2 {
                        return Ok(p);
                    }
                    let mut l: Vec<u8> = self.buf.drain(..2).collect();
                    self.decrypt(&mut l);
                    let len = usize::from(u16::from_be_bytes([l[0], l[1]]));
                    if len > 65535 {
                        return Err(MseError::Malformed("IA length"));
                    }
                    self.state = RState::WaitIa { provide, len };
                }
                RState::WaitIa { provide, len } => {
                    if self.buf.len() < len {
                        return Ok(p);
                    }
                    let mut ia: Vec<u8> = self.buf.drain(..len).collect();
                    self.decrypt(&mut ia);
                    let common = provide & self.accept;
                    let select = if common & CRYPTO_RC4 != 0 {
                        CRYPTO_RC4
                    } else if common & CRYPTO_PLAINTEXT != 0 {
                        CRYPTO_PLAINTEXT
                    } else {
                        return Err(MseError::NoCommonMethod);
                    };
                    let mut enc = self.enc.take().ok_or(MseError::Malformed("state"))?;
                    let mut dec = self.dec.take().ok_or(MseError::Malformed("state"))?;
                    let pad_d = random_pad();
                    let mut reply = VC.to_vec();
                    reply.extend_from_slice(&select.to_be_bytes());
                    reply.extend_from_slice(&(pad_d.len() as u16).to_be_bytes());
                    reply.extend_from_slice(&pad_d);
                    enc.apply(&mut reply);
                    p.send.extend_from_slice(&reply);
                    let mut rest = std::mem::take(&mut self.buf);
                    let cipher = if select == CRYPTO_RC4 {
                        dec.apply(&mut rest);
                        Some((enc, dec))
                    } else {
                        None
                    };
                    ia.extend_from_slice(&rest);
                    self.state = RState::Done;
                    p.done = Some(Established {
                        info_hash: self.skey,
                        cipher,
                        data: ia,
                    });
                    return Ok(p);
                }
                RState::Done => return Ok(p),
            }
        }
    }

    fn decrypt(&mut self, b: &mut [u8]) {
        if let Some(d) = &mut self.dec {
            d.apply(b);
        }
    }
}

/// `HASH('req2', info_hash)`: what a [`Receiver`]'s lookup is keyed by.
pub fn req2_hash(info_hash: &InfoHash) -> [u8; 20] {
    hash(&[b"req2", &info_hash.0])
}

/// The 768-bit Diffie-Hellman group of MSE, on Montgomery arithmetic over 12 64-bit limbs.
mod dh {
    const N: usize = 12;
    type Limbs = [u64; N];

    /// The prime, big-endian bytes.
    const P_BYTES: [u8; 96] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2,
        0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67,
        0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E,
        0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
        0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5,
        0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x21, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x09, 0x05, 0x63,
    ];

    fn from_be(b: &[u8]) -> Limbs {
        let mut padded = [0u8; 96];
        padded[96 - b.len()..].copy_from_slice(b);
        let mut l = [0u64; N];
        for (i, x) in l.iter_mut().enumerate() {
            let off = 96 - 8 * (i + 1);
            let mut w = [0u8; 8];
            w.copy_from_slice(&padded[off..off + 8]);
            *x = u64::from_be_bytes(w);
        }
        l
    }

    fn to_be(l: &Limbs) -> [u8; 96] {
        let mut b = [0u8; 96];
        for (i, x) in l.iter().enumerate() {
            let off = 96 - 8 * (i + 1);
            b[off..off + 8].copy_from_slice(&x.to_be_bytes());
        }
        b
    }

    fn geq(a: &Limbs, b: &Limbs) -> bool {
        for i in (0..N).rev() {
            if a[i] != b[i] {
                return a[i] > b[i];
            }
        }
        true
    }

    fn sub(a: &mut Limbs, b: &Limbs) {
        let mut borrow = 0u64;
        for i in 0..N {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            a[i] = d2;
            borrow = u64::from(b1 || b2);
        }
    }

    struct Mont {
        p: Limbs,
        n0inv: u64,
        r2: Limbs,
    }

    impl Mont {
        fn new() -> Mont {
            let p = from_be(&P_BYTES);
            // -p^-1 mod 2^64 by Newton's iteration.
            let mut inv: u64 = 1;
            for _ in 0..6 {
                inv = inv.wrapping_mul(2u64.wrapping_sub(p[0].wrapping_mul(inv)));
            }
            let n0inv = inv.wrapping_neg();
            // R^2 mod p, R = 2^768: double 1 modulo p 1536 times.
            let mut x = [0u64; N];
            x[0] = 1;
            for _ in 0..2 * 64 * N {
                let carry = x[N - 1] >> 63;
                for i in (1..N).rev() {
                    x[i] = (x[i] << 1) | (x[i - 1] >> 63);
                }
                x[0] <<= 1;
                if carry == 1 || geq(&x, &p) {
                    sub(&mut x, &p);
                }
            }
            Mont { p, n0inv, r2: x }
        }

        fn mul(&self, a: &Limbs, b: &Limbs) -> Limbs {
            let mut t = [0u64; N + 2];
            for &bi in b {
                let mut c: u128 = 0;
                for j in 0..N {
                    let v = u128::from(t[j]) + u128::from(a[j]) * u128::from(bi) + c;
                    t[j] = v as u64;
                    c = v >> 64;
                }
                let v = u128::from(t[N]) + c;
                t[N] = v as u64;
                t[N + 1] = (v >> 64) as u64;
                let m = t[0].wrapping_mul(self.n0inv);
                let v = u128::from(t[0]) + u128::from(m) * u128::from(self.p[0]);
                let mut c = v >> 64;
                for j in 1..N {
                    let v = u128::from(t[j]) + u128::from(m) * u128::from(self.p[j]) + c;
                    t[j - 1] = v as u64;
                    c = v >> 64;
                }
                let v = u128::from(t[N]) + c;
                t[N - 1] = v as u64;
                t[N] = t[N + 1] + (v >> 64) as u64;
            }
            let mut r = [0u64; N];
            r.copy_from_slice(&t[..N]);
            if t[N] != 0 || geq(&r, &self.p) {
                sub(&mut r, &self.p);
            }
            r
        }

        fn pow(&self, base: &Limbs, exp: &[u8]) -> Limbs {
            let mut b = *base;
            if geq(&b, &self.p) {
                sub(&mut b, &self.p);
            }
            let x = self.mul(&b, &self.r2);
            let mut one = [0u64; N];
            one[0] = 1;
            let mut acc = self.mul(&one, &self.r2);
            for &byte in exp {
                for bit in (0..8).rev() {
                    acc = self.mul(&acc, &acc);
                    if byte >> bit & 1 == 1 {
                        acc = self.mul(&acc, &x);
                    }
                }
            }
            self.mul(&acc, &one)
        }
    }

    fn mont() -> &'static Mont {
        static M: std::sync::OnceLock<Mont> = std::sync::OnceLock::new();
        M.get_or_init(Mont::new)
    }

    /// `2^private mod p`, 96 bytes big-endian.
    pub(super) fn public_key(private: &[u8]) -> [u8; 96] {
        let mut g = [0u64; N];
        g[0] = 2;
        to_be(&mont().pow(&g, private))
    }

    /// `their^private mod p`.
    pub(super) fn shared_secret(private: &[u8], their: &[u8]) -> [u8; 96] {
        to_be(&mont().pow(&from_be(their), private))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn known_values() {
            // 2^1 = 2, 2^0x10001 mod p cross-checked with Python's pow().
            let k = public_key(&[1]);
            assert_eq!(k[95], 2);
            assert!(k[..95].iter().all(|&b| b == 0));
            let a = [7u8; 20];
            assert_eq!(
                crate::metainfo::hex(&public_key(&a)),
                "ef73bd17b32dc4378e4f3d64b1b7692650f67cce83e48b902f304e26e139ba934cbd8d8260c5baf425e9bafd171b535e\
                 67340464866f90768f458ecc206d067eef265ccc96da8b36cf9a573a89cc87e453920fda0c48d967703be3f13a6247dc"
            );
            // Y^a for Ys not made by us (one >= p), cross-checked with Python's pow().
            assert_eq!(
                crate::metainfo::hex(&shared_secret(&a, &[0xab; 96])),
                "d95335083102d0b171fb7b7872816cee8bed6766b004fc0300d4726a9e1bf2abc325359e13c02e96ba7a364aa9f648ef\
                 027fc6d7a34c451caafc754d359280239977da4d2a26a612bb28b32017eb8d81a5a833495b3dfc5ff0620b69ce561a1b"
            );
            assert_eq!(
                crate::metainfo::hex(&shared_secret(&a, &[0x5c; 96])),
                "b8f11f3b3ee3d22fd8ce59cddabf77f75b44c5d00630441fb24d2fe0c709f24bddd5e0df10b9bd60fcadb025e0bcc226\
                 aba62f0550ebe41682762f9c68fb7d84a1b4b4235287fb5c7f5a8727e66d5fbc885ee880b9075338f4a9c969197eeaf2"
            );
            let b = [9u8; 20];
            let (ya, yb) = (public_key(&a), public_key(&b));
            assert_eq!(shared_secret(&a, &yb), shared_secret(&b, &ya));
            // (p - 1)^2 = 1 mod p
            let mut pm1 = P_BYTES;
            pm1[95] -= 1;
            let one = shared_secret(&[2], &pm1);
            assert_eq!(one[95], 1);
            assert!(one[..95].iter().all(|&b| b == 0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(provide: u32, accept: u32) -> Result<(Established, Established), MseError> {
        let ih = InfoHash::of(b"torrent");
        let key = req2_hash(&ih);
        let lookup = move |h: &[u8; 20]| (h == &key).then_some(ih);
        let (mut a, first) = Initiator::new(ih, provide, b"hello from A".to_vec());
        let mut b = Receiver::new(accept);
        // Deliver in odd-sized chunks both ways.
        let mut to_b = first;
        let mut to_a: Vec<u8> = Vec::new();
        let (mut da, mut db) = (None, None);
        for _ in 0..20 {
            for c in std::mem::take(&mut to_b).chunks(7) {
                let p = b.feed(c, &lookup)?;
                to_a.extend_from_slice(&p.send);
                if p.done.is_some() {
                    db = p.done;
                }
            }
            for c in std::mem::take(&mut to_a).chunks(5) {
                let p = a.feed(c)?;
                to_b.extend_from_slice(&p.send);
                if p.done.is_some() {
                    da = p.done;
                }
            }
            if da.is_some() && db.is_some() {
                break;
            }
        }
        Ok((da.ok_or(MseError::NoSync)?, db.ok_or(MseError::NoSync)?))
    }

    #[test]
    fn rc4_handshake_and_stream() {
        let (a, b) = run(CRYPTO_RC4 | CRYPTO_PLAINTEXT, CRYPTO_RC4 | CRYPTO_PLAINTEXT).unwrap();
        assert_eq!(b.data, b"hello from A");
        let (mut ae, mut ad) = a.cipher.unwrap();
        let (mut be, mut bd) = b.cipher.unwrap();
        let mut m = b"stream A->B".to_vec();
        ae.apply(&mut m);
        bd.apply(&mut m);
        assert_eq!(m, b"stream A->B");
        let mut m = b"stream B->A".to_vec();
        be.apply(&mut m);
        ad.apply(&mut m);
        assert_eq!(m, b"stream B->A");
    }

    #[test]
    fn plaintext_selected() {
        let (a, b) = run(CRYPTO_RC4 | CRYPTO_PLAINTEXT, CRYPTO_PLAINTEXT).unwrap();
        assert!(a.cipher.is_none() && b.cipher.is_none());
        assert_eq!(b.data, b"hello from A");
        assert_eq!(
            run(CRYPTO_PLAINTEXT, CRYPTO_RC4).unwrap_err(),
            MseError::NoCommonMethod
        );
    }

    #[test]
    fn unknown_torrent() {
        let (_, first) = Initiator::new(InfoHash::of(b"other"), CRYPTO_RC4, Vec::new());
        let mut b = Receiver::new(CRYPTO_RC4);
        let p = b.feed(&first, &|_| None).unwrap();
        assert!(!p.send.is_empty());
        // Feed a fake step 3 by running a real initiator against b's reply.
        let (mut a, first) = Initiator::new(InfoHash::of(b"other"), CRYPTO_RC4, Vec::new());
        let mut b = Receiver::new(CRYPTO_RC4);
        let p = b.feed(&first, &|_| None).unwrap();
        let step3 = a.feed(&p.send).unwrap().send;
        assert_eq!(
            b.feed(&step3, &|_| None).unwrap_err(),
            MseError::UnknownTorrent
        );
    }

    #[test]
    fn rc4_vector() {
        // RC4("Key") without the drop starts EB 9F 77 81; with the 1024-byte drop it is the
        // keystream from offset 1024, checked here for consistency between apply() calls.
        let mut a = Rc4::new(b"Key");
        let mut b = Rc4::new(b"Key");
        let mut x = [0u8; 10];
        a.apply(&mut x[..3]);
        a.apply(&mut x[3..]);
        let mut y = [0u8; 10];
        b.apply(&mut y);
        assert_eq!(x, y);
    }
}
