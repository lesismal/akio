//! Hash functions: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (FIPS 180-4) and MD5 (RFC 1321).
//!
//! Each type hashes incrementally ([`update`](Hash::update) any number of times, then
//! [`finalize`](Hash::finalize)) or in one call ([`digest`](Hash::digest)). The same methods
//! exist as inherent methods, so the [`Hash`] trait only needs to be in scope for generic code
//! such as [`Hmac`](crate::mac::Hmac).
//!
//! ```
//! use only_crypto::hash::Sha1;
//!
//! let mut h = Sha1::new();
//! h.update(b"The quick brown fox ");
//! h.update(b"jumps over the lazy dog");
//! assert_eq!(h.finalize(), Sha1::digest(b"The quick brown fox jumps over the lazy dog"));
//! ```
//!
//! SHA-1 and MD5 are broken as collision-resistant hashes; they are here because protocols
//! still use them (WebSocket handshakes, BitTorrent info hashes, STUN, HMAC-SHA1, RTSP digest
//! authentication).

mod hw;
mod md5;
mod sha1;
mod sha256;
mod sha512;

pub use md5::Md5;
pub use sha1::Sha1;
pub use sha256::{Sha224, Sha256};
pub use sha512::{Sha384, Sha512};

/// A cryptographic hash function with an incremental interface.
pub trait Hash: Clone + Default + std::fmt::Debug {
    /// The input block size in bytes (64 or 128), as HMAC needs it.
    const BLOCK_LEN: usize;
    /// The digest size in bytes.
    const OUTPUT_LEN: usize;
    /// The digest: `[u8; OUTPUT_LEN]`.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Copy + Eq + std::fmt::Debug + Send + Sync + 'static;

    /// Absorbs `data`.
    fn update(&mut self, data: &[u8]);

    /// Finishes the hash and returns the digest.
    fn finalize(self) -> Self::Output;

    /// The digest of `data` in one call.
    fn digest(data: &[u8]) -> Self::Output {
        let mut h = Self::default();
        h.update(data);
        h.finalize()
    }
}

/// The Merkle–Damgård block buffer shared by the hash functions: collects input into `N`-byte
/// blocks and appends the final padding with the message length.
#[derive(Clone)]
pub(crate) struct Buffer<const N: usize> {
    buf: [u8; N],
    pos: usize,
    /// Bytes absorbed so far.
    total: u64,
}

impl<const N: usize> Buffer<N> {
    pub(crate) const fn new() -> Self {
        Buffer {
            buf: [0; N],
            pos: 0,
            total: 0,
        }
    }

    /// Absorbs `data`; `compress` gets runs of whole `N`-byte blocks (a slice whose length is a
    /// non-zero multiple of `N`).
    #[inline]
    pub(crate) fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8])) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.pos > 0 {
            let n = (N - self.pos).min(data.len());
            self.buf[self.pos..self.pos + n].copy_from_slice(&data[..n]);
            self.pos += n;
            data = &data[n..];
            if self.pos < N {
                return;
            }
            compress(&self.buf);
            self.pos = 0;
        }
        let whole = data.len() - data.len() % N;
        if whole > 0 {
            compress(&data[..whole]);
        }
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.pos = rest.len();
    }

    /// Appends `0x80`, zeros and the message length in bits as a `len_field`-byte integer
    /// (big-endian for SHA, little-endian for MD5), compressing the final block(s).
    pub(crate) fn finish(
        &mut self,
        len_field: usize,
        big_endian: bool,
        mut compress: impl FnMut(&[u8]),
    ) {
        let bits = u128::from(self.total) << 3;
        self.buf[self.pos] = 0x80;
        self.pos += 1;
        if self.pos > N - len_field {
            self.buf[self.pos..].fill(0);
            compress(&self.buf);
            self.pos = 0;
        }
        self.buf[self.pos..N - len_field].fill(0);
        let len = if big_endian {
            bits.to_be_bytes()
        } else {
            bits.to_le_bytes()
        };
        if big_endian {
            self.buf[N - len_field..].copy_from_slice(&len[16 - len_field..]);
        } else {
            self.buf[N - len_field..].copy_from_slice(&len[..len_field]);
        }
        compress(&self.buf);
        self.pos = 0;
    }
}

/// The `N`-byte blocks of `data` (whose length is a multiple of `N`).
#[inline]
pub(crate) fn blocks<const N: usize>(data: &[u8]) -> impl Iterator<Item = &[u8; N]> {
    data.chunks_exact(N)
        .map(|b| b.try_into().unwrap_or_else(|_| unreachable!()))
}

/// Implements [`Hash`], `Default` and `Debug` for a hash type with `new` / `update` / `finalize`
/// inherent methods, and adds an inherent `digest`.
macro_rules! impl_hash {
    ($t:ident, $block:expr, $out:expr) => {
        impl $t {
            /// The digest of `data` in one call.
            #[must_use]
            pub fn digest(data: &[u8]) -> [u8; $out] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Default for $t {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($t)).finish_non_exhaustive()
            }
        }

        impl $crate::hash::Hash for $t {
            const BLOCK_LEN: usize = $block;
            const OUTPUT_LEN: usize = $out;
            type Output = [u8; $out];

            fn update(&mut self, data: &[u8]) {
                $t::update(self, data);
            }

            fn finalize(self) -> [u8; $out] {
                $t::finalize(self)
            }

            fn digest(data: &[u8]) -> [u8; $out] {
                $t::digest(data)
            }
        }
    };
}
pub(crate) use impl_hash;

#[cfg(test)]
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
