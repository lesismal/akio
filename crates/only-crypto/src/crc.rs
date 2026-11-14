//! CRC-32 checksums, slicing-by-8 table driven: [`crc32`] (IEEE 802.3 / zlib / PNG, the
//! polynomial `0xEDB88320` reflected; what `crc32fast` computes) and [`crc32c`] (Castagnoli,
//! `0x82F63B78` reflected; iSCSI, SCTP).
//!
//! ```
//! use only_crypto::crc::{Crc32, crc32};
//!
//! assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
//! let mut c = Crc32::new();
//! c.update(b"1234");
//! c.update(b"56789");
//! assert_eq!(c.finalize(), 0xcbf4_3926);
//! ```
//!
//! These are error-detecting codes, not cryptographic hashes.

const fn tables(poly: u32) -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ poly } else { c >> 1 };
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

static IEEE: [[u32; 256]; 8] = tables(0xedb8_8320);
static CASTAGNOLI: [[u32; 256]; 8] = tables(0x82f6_3b78);

fn update(t: &[[u32; 256]; 8], mut crc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(8);
    for c in &mut chunks {
        let lo = crc ^ u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        crc = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xff) as usize]
            ^ t[2][((hi >> 8) & 0xff) as usize]
            ^ t[1][((hi >> 16) & 0xff) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    for &b in chunks.remainder() {
        crc = (crc >> 8) ^ t[0][((crc ^ u32::from(b)) & 0xff) as usize];
    }
    crc
}

macro_rules! crc_type {
    ($name:ident, $func:ident, $table:ident, $doc:literal) => {
        #[doc = concat!("An incremental ", $doc, " computation.")]
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            state: u32,
        }

        impl $name {
            /// A fresh checksum.
            #[must_use]
            pub const fn new() -> Self {
                $name { state: 0 }
            }

            /// Absorbs `data`.
            pub fn update(&mut self, data: &[u8]) {
                self.state = !update(&$table, !self.state, data);
            }

            /// The checksum of everything absorbed so far.
            #[must_use]
            pub fn finalize(&self) -> u32 {
                self.state
            }
        }

        #[doc = concat!("The ", $doc, " of `data`.")]
        #[must_use]
        pub fn $func(data: &[u8]) -> u32 {
            !update(&$table, !0, data)
        }
    };
}

crc_type!(Crc32, crc32, IEEE, "CRC-32 (IEEE)");
crc_type!(Crc32c, crc32c, CASTAGNOLI, "CRC-32C (Castagnoli)");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(
            crc32(b"The quick brown fox jumps over the lazy dog"),
            0x414f_a339
        );
        // RFC 3720 B.4: 32 bytes of zeros / ones.
        assert_eq!(crc32c(&[0u8; 32]), 0x8a91_36aa);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62a8_ab43);
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        for split in [0, 1, 7, 8, 9, 500, 999, 1000] {
            let mut c = Crc32::new();
            c.update(&data[..split]);
            c.update(&data[split..]);
            assert_eq!(c.finalize(), crc32(&data));
        }
    }
}
