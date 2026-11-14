//! TLS 1.2 key derivation: master secret (RFC 5246 8.1, RFC 7627) and key block (6.3).

use super::common::Keys;
use super::suites::Suite;

/// The master secret from the ECDHE pre-master secret: the extended one (RFC 7627) over the
/// session hash when `ems`, else the RFC 5246 one over the randoms.
pub(crate) fn master_secret(
    suite: &'static Suite,
    pms: &[u8],
    ems: bool,
    session_hash: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Vec<u8> {
    if ems {
        suite
            .hash
            .prf(pms, b"extended master secret", session_hash, 48)
    } else {
        let mut seed = client_random.to_vec();
        seed.extend_from_slice(server_random);
        suite.hash.prf(pms, b"master secret", &seed, 48)
    }
}

/// The (client write, server write) keys.
pub(crate) fn keys(
    suite: &'static Suite,
    master: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> (Keys, Keys) {
    let kl = suite.aead.key_len();
    let il = suite.aead.fixed_iv_len_12();
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);
    let kb = suite
        .hash
        .prf(master, b"key expansion", &seed, 2 * kl + 2 * il);
    let c = Keys::Tls12 {
        suite,
        key: kb[..kl].to_vec(),
        iv: kb[2 * kl..2 * kl + il].to_vec(),
    };
    let s = Keys::Tls12 {
        suite,
        key: kb[kl..2 * kl].to_vec(),
        iv: kb[2 * kl + il..].to_vec(),
    };
    (c, s)
}
