//! What an embedding server sets: the shared nonce key, on the state machine.

use super::*;
use crate::fuzzing::{CLIENT, REALM, USER};

/// Servers sharing a nonce secret take each other's nonces, whenever each started; others
/// do not.
#[test]
fn shared_nonce_secret() {
    let cfg = |secret: Option<&[u8]>| {
        let c = TurnConfig::new(
            REALM,
            crate::static_auth(REALM, [USER]),
            "192.0.2.1".parse().unwrap(),
        );
        match secret {
            Some(s) => c.nonce_secret(s),
            None => c,
        }
    };
    let a = Shared::new(cfg(Some(b"s3cret")));
    let now = Instant::now();
    let n = a.nonce(now, CLIENT);
    let b = Shared::new(cfg(Some(b"s3cret")));
    let later = Instant::now();
    assert!(b.nonce_valid(later, CLIENT, &n));
    assert!(!b.nonce_valid(later, "10.0.0.9:1".parse().unwrap(), &n));
    assert!(!Shared::new(cfg(Some(b"other"))).nonce_valid(later, CLIENT, &n));
    assert!(!Shared::new(cfg(None)).nonce_valid(later, CLIENT, &n));
    // Expiries are UNIX seconds.
    let exp = u64::from_str_radix(&n[..16], 16).unwrap();
    let unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(exp.abs_diff(unix + 600) <= 2, "{exp} {unix}");
    assert!(!format!("{:?}", cfg(Some(b"s3cret"))).contains("s3cret"));
}
