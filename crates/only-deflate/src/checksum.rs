//! Adler-32 (RFC 1950) and CRC-32 (RFC 1952, ISO-HDLC polynomial `0xEDB88320`).

/// Running Adler-32 checksum, as used by the zlib format.
///
/// ```
/// let mut a = only_deflate::Adler32::new();
/// a.update(b"Wiki");
/// a.update(b"pedia");
/// assert_eq!(a.finish(), 0x11E6_0398);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

impl Default for Adler32 {
    fn default() -> Self {
        Adler32::new()
    }
}

const MOD_ADLER: u32 = 65_521;
/// Largest n with 255·n·(n+1)/2 + (n+1)·(MOD−1) ≤ 2³²−1: bytes summable before reducing.
const NMAX: usize = 5552;

impl Adler32 {
    /// A checksum of no data (value 1).
    pub const fn new() -> Adler32 {
        Adler32 { a: 1, b: 0 }
    }

    /// Continues from a previously finished value.
    pub const fn from_value(v: u32) -> Adler32 {
        Adler32 {
            a: v & 0xffff,
            b: v >> 16,
        }
    }

    /// Adds `data` to the checksum.
    pub fn update(&mut self, data: &[u8]) {
        let (mut a, mut b) = (self.a, self.b);
        for chunk in data.chunks(NMAX) {
            let mut quads = chunk.chunks_exact(4);
            for q in &mut quads {
                a += u32::from(q[0]);
                b += a;
                a += u32::from(q[1]);
                b += a;
                a += u32::from(q[2]);
                b += a;
                a += u32::from(q[3]);
                b += a;
            }
            for &x in quads.remainder() {
                a += u32::from(x);
                b += a;
            }
            a %= MOD_ADLER;
            b %= MOD_ADLER;
        }
        self.a = a;
        self.b = b;
    }

    /// The checksum of everything added so far.
    pub const fn finish(&self) -> u32 {
        (self.b << 16) | self.a
    }
}

/// The Adler-32 checksum of `data`.
pub fn adler32(data: &[u8]) -> u32 {
    let mut a = Adler32::new();
    a.update(data);
    a.finish()
}

const fn crc_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut s = 1;
        while s < 8 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            s += 1;
        }
        i += 1;
    }
    t
}

static CRC: [[u32; 256]; 8] = crc_tables();

/// Running CRC-32 (the gzip / PNG / Ethernet CRC).
///
/// ```
/// let mut c = only_deflate::Crc32::new();
/// c.update(b"123456789");
/// assert_eq!(c.finish(), 0xCBF4_3926);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Crc32 {
    /// The finished value (pre- and post-conditioning are applied in `update`).
    v: u32,
}

impl Crc32 {
    /// A checksum of no data (value 0).
    pub const fn new() -> Crc32 {
        Crc32 { v: 0 }
    }

    /// Continues from a previously finished value.
    pub const fn from_value(v: u32) -> Crc32 {
        Crc32 { v }
    }

    /// Adds `data` to the checksum (slicing-by-8).
    pub fn update(&mut self, data: &[u8]) {
        let mut c = !self.v;
        let mut words = data.chunks_exact(8);
        for w in &mut words {
            let lo = c ^ u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            c = CRC[7][(lo & 0xff) as usize]
                ^ CRC[6][((lo >> 8) & 0xff) as usize]
                ^ CRC[5][((lo >> 16) & 0xff) as usize]
                ^ CRC[4][(lo >> 24) as usize]
                ^ CRC[3][usize::from(w[4])]
                ^ CRC[2][usize::from(w[5])]
                ^ CRC[1][usize::from(w[6])]
                ^ CRC[0][usize::from(w[7])];
        }
        for &b in words.remainder() {
            c = (c >> 8) ^ CRC[0][((c ^ u32::from(b)) & 0xff) as usize];
        }
        self.v = !c;
    }

    /// The checksum of everything added so far.
    pub const fn finish(&self) -> u32 {
        self.v
    }
}

/// The CRC-32 of `data`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adler_naive(d: &[u8]) -> u32 {
        let (mut a, mut b) = (1u32, 0u32);
        for &x in d {
            a = (a + u32::from(x)) % MOD_ADLER;
            b = (b + a) % MOD_ADLER;
        }
        (b << 16) | a
    }

    fn crc_naive(d: &[u8]) -> u32 {
        let mut c = !0u32;
        for &x in d {
            c ^= u32::from(x);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    #[test]
    fn known_answers() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }

    #[test]
    fn matches_naive_and_splits() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        let big = vec![0xffu8; 3 * NMAX + 17];
        for d in [&data[..], &big[..]] {
            assert_eq!(adler32(d), adler_naive(d));
            assert_eq!(crc32(d), crc_naive(d));
            for cut in [0, 1, 7, 8, 9, 5551, 5552, 5553, d.len()] {
                let cut = cut.min(d.len());
                let mut a = Adler32::new();
                a.update(&d[..cut]);
                let mut a = Adler32::from_value(a.finish());
                a.update(&d[cut..]);
                assert_eq!(a.finish(), adler_naive(d));
                let mut c = Crc32::new();
                c.update(&d[..cut]);
                let mut c = Crc32::from_value(c.finish());
                c.update(&d[cut..]);
                assert_eq!(c.finish(), crc_naive(d));
            }
        }
    }
}
