//! Randomness: the operating system's CSPRNG ([`fill_random`]) and a ChaCha20-based generator
//! ([`ChaChaRng`]) for bulk output.
//!
//! [`fill_random`] asks the kernel every time (`getrandom(2)` on Linux, `getentropy(2)` on macOS,
//! `/dev/urandom` elsewhere on Unix), which is also safe across `fork`. A [`ChaChaRng`] is
//! faster for many small values but must not be shared across `fork` (the child would repeat the
//! parent's output); seed a new one in each process.
//!
//! ```
//! use akio_crypto::rand::{ChaChaRng, fill_random};
//!
//! let mut nonce = [0u8; 12];
//! fill_random(&mut nonce).unwrap();
//! let mut rng = ChaChaRng::from_os().unwrap();
//! let _ = rng.next_u64();
//! ```

use std::io;

/// Fills `buf` with cryptographically secure random bytes from the operating system.
///
/// Fails only if the kernel's generator is unavailable (no `getrandom`, `getentropy` or
/// `/dev/urandom`; an unsupported platform).
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    os_fill(buf)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn os_fill(buf: &mut [u8]) -> io::Result<()> {
    akio_sys::fill_random(buf)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn os_fill(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

#[cfg(not(unix))]
fn os_fill(_: &mut [u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no operating system random number generator on this platform",
    ))
}

/// A cryptographically secure pseudorandom generator: the ChaCha20 keystream (20 rounds, 64-bit
/// block counter) under a 256-bit seed.
#[derive(Clone)]
pub struct ChaChaRng {
    state: [u32; 16],
    buf: [u8; 64],
    /// Bytes of `buf` already handed out.
    used: usize,
}

impl std::fmt::Debug for ChaChaRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaChaRng").finish_non_exhaustive()
    }
}

impl ChaChaRng {
    /// A generator from a 32-byte seed (deterministic: the same seed gives the same output).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
        for (s, k) in state[4..12].iter_mut().zip(seed.chunks_exact(4)) {
            *s = u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
        }
        ChaChaRng {
            state,
            buf: [0; 64],
            used: 64,
        }
    }

    /// A generator seeded from [`fill_random`].
    pub fn from_os() -> io::Result<Self> {
        let mut seed = [0u8; 32];
        fill_random(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    fn refill(&mut self) {
        self.buf = crate::chacha::block(&self.state);
        // 64-bit block counter in words 12 and 13: 2^70 bytes before it wraps.
        let (lo, carry) = self.state[12].overflowing_add(1);
        self.state[12] = lo;
        self.state[13] = self.state[13].wrapping_add(u32::from(carry));
        self.used = 0;
    }

    /// Fills `out` with random bytes.
    pub fn fill(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.used == 64 {
                self.refill();
            }
            let n = (64 - self.used).min(out.len());
            out[..n].copy_from_slice(&self.buf[self.used..self.used + n]);
            self.used += n;
            out = &mut out[n..];
        }
    }

    /// A random `u32`.
    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }

    /// A random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_randomness() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random(&mut a).unwrap();
        fill_random(&mut b).unwrap();
        assert_ne!(a, b);
        fill_random(&mut []).unwrap();
    }

    #[test]
    fn chacha_rng_is_the_chacha20_keystream() {
        // With an all-zero seed the output is the ChaCha20 keystream for the zero key and nonce
        // (RFC 8439 A.1, test vector #1).
        let mut r = ChaChaRng::from_seed([0; 32]);
        let mut out = [0u8; 64];
        r.fill(&mut out[..5]);
        r.fill(&mut out[5..]);
        assert_eq!(out[..8], [0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90]);
        assert_eq!(
            out[56..],
            [0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86][..]
        );
        let mut c = crate::chacha::ChaCha20::new(&[0; 32], &[0; 12], 1);
        let mut ks = [0u8; 64];
        c.apply_keystream(&mut ks);
        let mut next = [0u8; 64];
        r.fill(&mut next);
        assert_eq!(next, ks);
        let x = ChaChaRng::from_os().unwrap().next_u64();
        let y = ChaChaRng::from_os().unwrap().next_u64();
        assert_ne!(x, y);
    }
}
