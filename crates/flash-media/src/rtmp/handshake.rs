//! The RTMP handshake: the simple one (C2/S2 echo) and the Flash digest ("complex") one
//! (HMAC-SHA256 under Adobe's player and server keys) that Flash and Adobe-derived clients
//! check.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Size of C1/S1/C2/S2.
pub const SIZE: usize = 1536;
/// The RTMP version byte.
pub const VERSION: u8 = 3;

const FMS_KEY: &[u8] = b"Genuine Adobe Flash Media Server 001\xf0\xee\xc2\x4a\x80\x68\xbe\xe8\x2e\x00\xd0\xd1\x02\x9e\x7e\x57\x6e\xec\x5d\x2d\x29\x80\x6f\xab\x93\xb8\xe6\x36\xcf\xeb\x31\xae";
const FP_KEY: &[u8] = b"Genuine Adobe Flash Player 001\xf0\xee\xc2\x4a\x80\x68\xbe\xe8\x2e\x00\xd0\xd1\x02\x9e\x7e\x57\x6e\xec\x5d\x2d\x29\x80\x6f\xab\x93\xb8\xe6\x36\xcf\xeb\x31\xae";
const CLIENT_VERSION: [u8; 4] = [0x80, 0x00, 0x07, 0x02];
const SERVER_VERSION: [u8; 4] = [0x04, 0x05, 0x00, 0x01];

/// A handshake the peer got wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeError;

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RTMP handshake failed")
    }
}

impl std::error::Error for HandshakeError {}

fn mac(key: &[u8]) -> Hmac<Sha256> {
    // HMAC accepts keys of any length.
    <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!())
}

fn digest_offset(b: &[u8], scheme: usize) -> usize {
    let base = if scheme == 0 { 772 } else { 8 };
    let sum: usize = b[base..base + 4].iter().map(|&x| usize::from(x)).sum();
    base + 4 + sum % 728
}

fn digest(key: &[u8], b: &[u8], off: usize) -> [u8; 32] {
    let mut m = mac(key);
    m.update(&b[..off]);
    m.update(&b[off + 32..]);
    m.finalize().into_bytes().into()
}

fn find_digest(b: &[u8], key: &[u8]) -> Option<(usize, [u8; 32])> {
    for scheme in [1, 0] {
        let off = digest_offset(b, scheme);
        let d = digest(key, b, off);
        if d[..] == b[off..off + 32] {
            return Some((scheme, d));
        }
    }
    None
}

fn random(b: &mut [u8]) {
    if getrandom::getrandom(b).is_err() {
        // Not security relevant: the handshake bytes only need to look random.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos() as u64);
        let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ t;
        for v in b {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *v = x as u8;
        }
    }
}

fn sign(b: &mut [u8], version: [u8; 4], key: &[u8], scheme: usize) {
    random(&mut b[8..]);
    b[4..8].copy_from_slice(&version);
    let off = digest_offset(b, scheme);
    let d = digest(key, b, off);
    b[off..off + 32].copy_from_slice(&d);
}

fn answer(b: &mut [u8], key: &[u8], peer_digest: &[u8]) {
    random(&mut b[..SIZE - 32]);
    let mut tmp = mac(key);
    tmp.update(peer_digest);
    let k = tmp.finalize().into_bytes();
    let mut m = mac(&k);
    m.update(&b[..SIZE - 32]);
    let d = m.finalize().into_bytes();
    b[SIZE - 32..].copy_from_slice(&d);
}

/// The server's S0 S1 S2 for a client's C0 C1 (`1 + 1536` bytes): the digest handshake when
/// C1 carries a valid Flash Player digest, the simple one otherwise.
pub fn server_reply(c0c1: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    if c0c1.len() < 1 + SIZE || c0c1[0] != VERSION {
        return Err(HandshakeError);
    }
    let c1 = &c0c1[1..1 + SIZE];
    let mut out = vec![0u8; 1 + 2 * SIZE];
    out[0] = VERSION;
    let (s1, s2) = out[1..].split_at_mut(SIZE);
    if c1[4..8] != [0, 0, 0, 0] {
        if let Some((scheme, d)) = find_digest(c1, &FP_KEY[..30]) {
            sign(s1, SERVER_VERSION, &FMS_KEY[..36], scheme);
            answer(s2, FMS_KEY, &d);
            return Ok(out);
        }
    }
    random(&mut s1[8..]);
    s2.copy_from_slice(c1);
    Ok(out)
}

/// A client's C0 C1: signed with the Flash Player digest unless `simple`.
pub fn client_hello(simple: bool) -> Vec<u8> {
    let mut out = vec![0u8; 1 + SIZE];
    out[0] = VERSION;
    if simple {
        random(&mut out[9..]);
    } else {
        sign(&mut out[1..], CLIENT_VERSION, &FP_KEY[..30], 1);
    }
    out
}

/// A client's C2 for the server's S0 S1 (at least `1 + 1536` bytes).
pub fn client_reply(s0s1: &[u8]) -> Result<Vec<u8>, HandshakeError> {
    if s0s1.len() < 1 + SIZE || s0s1[0] != VERSION {
        return Err(HandshakeError);
    }
    let s1 = &s0s1[1..1 + SIZE];
    let mut c2 = vec![0u8; SIZE];
    if let Some((_, d)) = find_digest(s1, &FMS_KEY[..36]) {
        answer(&mut c2, FP_KEY, &d);
    } else {
        c2.copy_from_slice(s1);
    }
    Ok(c2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_handshake() {
        let c0c1 = client_hello(false);
        assert!(find_digest(&c0c1[1..], &FP_KEY[..30]).is_some());
        let s = server_reply(&c0c1).unwrap();
        assert_eq!(s.len(), 1 + 2 * SIZE);
        // S1 is signed with the server key, S2 answers the client's digest.
        let (_, d) = find_digest(&s[1..1 + SIZE], &FMS_KEY[..36]).unwrap();
        let c2 = client_reply(&s).unwrap();
        assert_eq!(c2.len(), SIZE);
        let mut tmp = mac(FP_KEY);
        tmp.update(&d);
        let k = tmp.finalize().into_bytes();
        let mut m = mac(&k);
        m.update(&c2[..SIZE - 32]);
        assert_eq!(m.finalize().into_bytes()[..], c2[SIZE - 32..]);
    }

    #[test]
    fn simple_handshake_echoes() {
        let c0c1 = client_hello(true);
        let s = server_reply(&c0c1).unwrap();
        assert_eq!(&s[1 + SIZE..], &c0c1[1..]);
        assert_eq!(client_reply(&s).unwrap(), s[1..1 + SIZE].to_vec());
        assert!(server_reply(&[6; 1 + SIZE]).is_err());
        assert!(server_reply(&[3; 10]).is_err());
    }
}
