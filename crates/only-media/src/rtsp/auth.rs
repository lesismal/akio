//! RTSP authentication: Digest (RFC 2617, MD5, as RTSP clients speak it) and Basic, for the
//! server (challenges, verification) and the client (answering a challenge).

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
pub(crate) fn params(s: &str) -> Vec<(String, String)> {
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

/// The Digest `response` (RFC 2617 section 3.2.2.1, MD5): with `qop` = `Some((nc, cnonce))`
/// for `qop=auth`, else the RFC 2069 form.
#[allow(clippy::too_many_arguments)]
pub(crate) fn digest_response(
    user: &str,
    realm: &str,
    pass: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    qop: Option<(&str, &str)>,
) -> String {
    let ha1 = md5_hex(&format!("{user}:{realm}:{pass}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    match qop {
        Some((nc, cnonce)) => md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")),
        None => md5_hex(&format!("{ha1}:{nonce}:{ha2}")),
    }
}

/// A server's challenge, as a client answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Challenge {
    /// `Basic`.
    Basic,
    /// `Digest` with MD5.
    Digest {
        realm: String,
        nonce: String,
        opaque: Option<String>,
        /// The server offered `qop=auth`.
        qop: bool,
    },
}

impl Challenge {
    /// The challenge to answer among a response's `WWW-Authenticate` headers: Digest (MD5)
    /// when offered, else Basic.
    pub(crate) fn pick<'a>(headers: impl Iterator<Item = &'a str>) -> Option<Challenge> {
        let mut basic = false;
        for h in headers {
            let h = h.trim();
            let (scheme, rest) = h.split_once(' ').unwrap_or((h, ""));
            if scheme.eq_ignore_ascii_case("basic") {
                basic = true;
                continue;
            }
            if !scheme.eq_ignore_ascii_case("digest") {
                continue;
            }
            let ps = params(rest);
            let get = |k: &str| ps.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
            if get("algorithm").is_some_and(|a| !a.eq_ignore_ascii_case("md5")) {
                continue;
            }
            let (Some(realm), Some(nonce)) = (get("realm"), get("nonce")) else {
                continue;
            };
            let qop = get("qop")
                .is_some_and(|q| q.split(',').any(|x| x.trim().eq_ignore_ascii_case("auth")));
            return Some(Challenge::Digest {
                realm,
                nonce,
                opaque: get("opaque"),
                qop,
            });
        }
        basic.then_some(Challenge::Basic)
    }

    /// The `Authorization` header answering this challenge for `method` on `uri`; `nc` is the
    /// count of requests answered with this nonce so far plus one.
    pub(crate) fn authorization(
        &self,
        user: &str,
        pass: &str,
        method: &str,
        uri: &str,
        nc: u32,
    ) -> String {
        match self {
            Challenge::Basic => format!("Basic {}", B64.encode(format!("{user}:{pass}"))),
            Challenge::Digest {
                realm,
                nonce,
                opaque,
                qop,
            } => {
                let q = |s: &str| s.replace(['"', '\\', '\r', '\n'], "");
                let mut h = format!(
                    "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\"",
                    q(user),
                    q(realm),
                    q(nonce),
                    q(uri)
                );
                if *qop {
                    let mut c = [0u8; 8];
                    let _ = only_crypto::rand::fill_random(&mut c);
                    let cnonce: String = c.iter().map(|b| format!("{b:02x}")).collect();
                    let nc = format!("{nc:08x}");
                    let r = digest_response(
                        user,
                        realm,
                        pass,
                        method,
                        uri,
                        nonce,
                        Some((&nc, &cnonce)),
                    );
                    h.push_str(&format!(
                        ", response=\"{r}\", qop=auth, nc={nc}, cnonce=\"{cnonce}\""
                    ));
                } else {
                    let r = digest_response(user, realm, pass, method, uri, nonce, None);
                    h.push_str(&format!(", response=\"{r}\""));
                }
                if let Some(o) = opaque {
                    h.push_str(&format!(", opaque=\"{}\"", q(o)));
                }
                h.push_str(", algorithm=MD5");
                h
            }
        }
    }
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

    #[test]
    fn digest_rfc2617_vector() {
        // RFC 2617 section 3.5.
        assert_eq!(
            digest_response(
                "Mufasa",
                "testrealm@host.com",
                "Circle Of Life",
                "GET",
                "/dir/index.html",
                "dcd98b7102dd2f0e8b11d0f600bfb0c093",
                Some(("00000001", "0a4f113b")),
            ),
            "6629fae49393a05397450978507c4ef1"
        );
    }

    #[test]
    fn client_answers_verify_on_the_server() {
        let lookup = |u: &str| (u == "admin").then(|| "secret".to_owned());
        let [d, b] = challenges("only", "n1");
        let digest = Challenge::pick([b.as_str(), d.as_str()].into_iter()).unwrap();
        assert!(matches!(digest, Challenge::Digest { qop: false, .. }));
        let h = digest.authorization("admin", "secret", "DESCRIBE", "rtsp://h/s", 1);
        assert_eq!(
            verify(&h, "DESCRIBE", "only", "n1", &lookup).as_deref(),
            Some("admin")
        );
        let qop = Challenge::pick(
            ["Digest realm=\"only\", nonce=\"n1\", qop=\"auth,auth-int\", opaque=\"o\""]
                .into_iter(),
        )
        .unwrap();
        let h = qop.authorization("admin", "secret", "SETUP", "rtsp://h/s/trackID=0", 3);
        assert!(h.contains("nc=00000003") && h.contains("opaque=\"o\""));
        assert!(verify(&h, "SETUP", "only", "n1", &lookup).is_some());
        let basic = Challenge::pick([b.as_str()].into_iter()).unwrap();
        assert_eq!(basic, Challenge::Basic);
        let h = basic.authorization("admin", "secret", "X", "u", 1);
        assert!(verify(&h, "X", "only", "n", &lookup).is_some());
        assert!(
            Challenge::pick(["Digest realm=\"r\", nonce=\"n\", algorithm=SHA-256"].into_iter())
                .is_none()
        );
        assert!(Challenge::pick(["Bearer x"].into_iter()).is_none());
    }
}
