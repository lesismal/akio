//! SHA-224 and SHA-256 (FIPS 180-4, section 6.2 and 6.3).

use super::{Buffer, blocks, impl_hash};

pub(super) const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const H256: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const H224: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

#[derive(Clone)]
struct Core {
    state: [u32; 8],
    buf: Buffer<64>,
}

impl Core {
    const fn new(h: [u32; 8]) -> Self {
        Core {
            state: h,
            buf: Buffer::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.buf.update(data, |d| compress_blocks(state, d));
    }

    fn finish(mut self, out: &mut [u8]) {
        let state = &mut self.state;
        self.buf.finish(8, true, |d| compress_blocks(state, d));
        for (o, s) in out.chunks_mut(4).zip(self.state) {
            o.copy_from_slice(&s.to_be_bytes()[..o.len()]);
        }
    }
}

/// SHA-256: 32-byte digests.
#[derive(Clone)]
pub struct Sha256(Core);

impl Sha256 {
    /// A fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Sha256(Core::new(H256))
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes the hash and returns the digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.finish(&mut out);
        out
    }
}

impl_hash!(Sha256, 64, 32);

/// SHA-224: SHA-256 with other initial values, truncated to 28 bytes.
#[derive(Clone)]
pub struct Sha224(Core);

impl Sha224 {
    /// A fresh hasher.
    #[must_use]
    pub const fn new() -> Self {
        Sha224(Core::new(H224))
    }

    /// Absorbs `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes the hash and returns the digest.
    #[must_use]
    pub fn finalize(self) -> [u8; 28] {
        let mut out = [0u8; 28];
        self.0.finish(&mut out);
        out
    }
}

impl_hash!(Sha224, 64, 28);

/// Compresses whole 64-byte blocks: the SHA instructions when the CPU has them, else
/// [`compress`].
#[inline]
fn compress_blocks(state: &mut [u32; 8], data: &[u8]) {
    if super::hw::enabled() && super::hw::sha256(state, data) {
        return;
    }
    blocks(data).for_each(|b| compress(state, b));
}

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (w, b) in w.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, w) in K.iter().zip(w) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = g ^ (e & (f ^ g));
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(w);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) | (c & (a | b));
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

#[cfg(test)]
mod tests {
    use super::super::hex;
    use super::*;

    /// The SHA instructions (when present) and the portable compression agree.
    #[test]
    fn hardware_matches_portable() {
        let mut rng = crate::rand::ChaChaRng::from_seed([4; 32]);
        let mut data = vec![0u8; 64 * 9];
        for _ in 0..50 {
            rng.fill(&mut data);
            let mut a = H256;
            let mut b = H256;
            compress_blocks(&mut a, &data);
            blocks(&data).for_each(|blk| compress(&mut b, blk));
            assert_eq!(a, b);
        }
    }

    #[test]
    fn vectors() {
        assert_eq!(
            hex(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&Sha224::digest(b"abc")),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex(&h.finalize()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
