//! Long-term credentials: how a [`TurnServer`](crate::TurnServer) finds a user's key.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::stun::long_term_key;

/// Looks up the long-term key ([`long_term_key`]) of `username` in `realm`; `None` refuses the
/// user. Called on the I/O thread for every authenticated request: it must not block.
pub type AuthFn = Arc<dyn Fn(&str, &str) -> Option<[u8; 16]> + Send + Sync>;

/// Fixed users and passwords. Keys are derived once.
pub fn static_auth<'a>(realm: &str, users: impl IntoIterator<Item = (&'a str, &'a str)>) -> AuthFn {
    let keys: HashMap<String, [u8; 16]> = users
        .into_iter()
        .map(|(u, p)| (u.to_owned(), long_term_key(u, realm, p)))
        .collect();
    let realm = realm.to_owned();
    Arc::new(move |user, r| {
        if r != realm {
            return None;
        }
        keys.get(user).copied()
    })
}

/// Time-limited credentials of the "TURN REST API" (draft-uberti-behave-turn-rest, as coturn's
/// `use-auth-secret`): the username is `<expiry unix seconds>:<user>` and the password
/// `base64(HMAC-SHA1(secret, username))`. A web service that shares `secret` with the server
/// hands them out with [`ephemeral_credentials`].
pub fn ephemeral_auth(secret: &[u8]) -> AuthFn {
    let secret = secret.to_vec();
    Arc::new(move |user, realm| {
        let expiry: u64 = user.split(':').next()?.parse().ok()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        if expiry < now {
            return None;
        }
        let password = rest_password(&secret, user);
        Some(long_term_key(user, realm, &password))
    })
}

/// Username and password for `user` valid for `ttl` under [`ephemeral_auth`] with `secret`.
pub fn ephemeral_credentials(secret: &[u8], user: &str, ttl: Duration) -> (String, String) {
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        + ttl.as_secs();
    let username = format!("{expiry}:{user}");
    let password = rest_password(secret, &username);
    (username, password)
}

fn rest_password(secret: &[u8], username: &str) -> String {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(username.as_bytes());
    base64(&mac.finalize().into_bytes())
}

/// Standard base64 with padding.
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn static_and_ephemeral() {
        let a = static_auth("r", [("u", "p")]);
        assert_eq!(a("u", "r"), Some(long_term_key("u", "r", "p")));
        assert_eq!(a("u", "other"), None);
        assert_eq!(a("x", "r"), None);

        let e = ephemeral_auth(b"s3cret");
        let (u, p) = ephemeral_credentials(b"s3cret", "alice", Duration::from_secs(60));
        assert_eq!(e(&u, "r"), Some(long_term_key(&u, "r", &p)));
        assert_eq!(e("1:alice", "r"), None, "expired");
        assert_eq!(e("alice", "r"), None, "no expiry");
    }
}
