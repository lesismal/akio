//! RTSP authentication: Digest (RFC 2617, MD5, as RTSP clients speak it) and Basic.

use only_crypto::base64::STANDARD as B64;
use only_crypto::hash::Md5;

fn md5_hex(s: &str) -> String {
    let d = Md5::digest(s.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `WWW-Authenticate` challenges for `realm` and `nonce` (Digest first, then Basic).
pub(crate) fn challenges(realm: &str, nonce: &str) -> [String; 2] {
    [
        format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5"),
        format!("Basic realm=\"{realm}\""),
    ]
}

/// Parses `k="v", k2=v2` parameters.
fn params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s.trim();
    while !rest.is_empty() {
        let Some(eq) = rest.find('=') else { break };
        let k = rest[..eq]
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        rest = rest[eq + 1..].trim_start();
        let v;
        if let Some(r) = rest.strip_prefix('"') {
            let end = r.find('"').unwrap_or(r.len());
            v = r[..end].to_owned();
            rest = r.get(end + 1..).unwrap_or("");
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            v = rest[..end].trim().to_owned();
            rest = &rest[end..];
        }
        rest = rest.trim_start().trim_start_matches(',').trim_start();
        out.push((k, v));
    }
    out
}

/// Checks an `Authorization` header for `method` against the password `lookup` returns for
/// the user it names. Returns the user on success.
pub(crate) fn verify(
    header: &str,
    method: &str,
    realm: &str,
    nonce: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let (scheme, rest) = header.trim().split_once(' ')?;
    if scheme.eq_ignore_ascii_case("basic") {
        let raw = B64.decode(rest.trim()).ok()?;
        let s = String::from_utf8(raw).ok()?;
        let (u, p) = s.split_once(':')?;
        return (lookup(u)? == p).then(|| u.to_owned());
    }
    if !scheme.eq_ignore_ascii_case("digest") {
        return None;
    }
    let ps = params(rest);
    let get = |k: &str| ps.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let user = get("username")?;
    if get("realm")? != realm || get("nonce")? != nonce {
        return None;
    }
    let uri = get("uri")?;
    let pass = lookup(user)?;
    let ha1 = md5_hex(&format!("{user}:{realm}:{pass}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let want = match (get("qop"), get("nc"), get("cnonce")) {
        (Some(qop), Some(nc), Some(cn)) => md5_hex(&format!("{ha1}:{nonce}:{nc}:{cn}:{qop}:{ha2}")),
        _ => md5_hex(&format!("{ha1}:{nonce}:{ha2}")),
    };
    (get("response")?.eq_ignore_ascii_case(&want)).then(|| user.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_and_basic() {
        let lookup = |u: &str| (u == "admin").then(|| "secret".to_owned());
        let ha1 = md5_hex("admin:only:secret");
        let ha2 = md5_hex("DESCRIBE:rtsp://h/live/s");
        let resp = md5_hex(&format!("{ha1}:n1:{ha2}"));
        let h = format!(
            "Digest username=\"admin\", realm=\"only\", nonce=\"n1\", uri=\"rtsp://h/live/s\", response=\"{resp}\""
        );
        assert_eq!(
            verify(&h, "DESCRIBE", "only", "n1", &lookup).as_deref(),
            Some("admin")
        );
        assert!(verify(&h, "SETUP", "only", "n1", &lookup).is_none());
        assert!(verify(&h, "DESCRIBE", "only", "n2", &lookup).is_none());
        let b = format!("Basic {}", B64.encode("admin:secret"));
        assert!(verify(&b, "X", "only", "n", &lookup).is_some());
        let bad = format!("Basic {}", B64.encode("admin:nope"));
        assert!(verify(&bad, "X", "only", "n", &lookup).is_none());
        assert!(verify("Bearer x", "X", "only", "n", &lookup).is_none());
        assert_eq!(
            challenges("r", "n")[0],
            "Digest realm=\"r\", nonce=\"n\", algorithm=MD5"
        );
    }
}
