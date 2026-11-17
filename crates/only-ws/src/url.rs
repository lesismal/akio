//! Resolving a `Location` against the URL it came from (RFC 3986 section 5.2), for the clients'
//! redirects. Shared with only-http; `#[doc(hidden)]`, outside the semver promise.

fn has_scheme(r: &str) -> bool {
    let Some(i) = r.find(':') else { return false };
    let s = &r[..i];
    !s.is_empty()
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

/// `scheme`, `authority`, `path` (starting with `/`) and `query` (with its `?`, or empty) of an
/// absolute `scheme://authority...` URL.
fn split(u: &str) -> Option<(&str, &str, &str, &str)> {
    let (scheme, rest) = u.split_once("://")?;
    let rest = rest.split('#').next().unwrap_or("");
    let a_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(a_end);
    let (path, query) = match tail.find('?') {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    Some((
        scheme,
        authority,
        if path.is_empty() { "/" } else { path },
        query,
    ))
}

/// Removes `.` and `..` segments from an absolute path (RFC 3986 section 5.2.4).
fn remove_dots(path: &str) -> String {
    let segs: Vec<&str> = path.split('/').collect();
    let mut out: Vec<&str> = Vec::new();
    let n = segs.len();
    for (i, s) in segs.iter().enumerate().skip(1) {
        let last = i == n - 1;
        match *s {
            "." => {
                if last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// `reference` (a `Location` value) resolved against the absolute URL `base`; the fragment is
/// dropped. `None` when `base` is not an absolute `scheme://` URL.
pub fn resolve(base: &str, reference: &str) -> Option<String> {
    let r = reference.trim();
    let r = r.split('#').next().unwrap_or("");
    if has_scheme(r) {
        let (s, rest) = r.split_once(':')?;
        return Some(format!("{}:{rest}", s.to_ascii_lowercase()));
    }
    let (bs, ba, bp, bq) = split(base)?;
    if let Some(rest) = r.strip_prefix("//") {
        return Some(format!("{bs}://{rest}"));
    }
    if r.is_empty() {
        return Some(format!("{bs}://{ba}{bp}{bq}"));
    }
    if r.starts_with('?') {
        return Some(format!("{bs}://{ba}{bp}{r}"));
    }
    let (rp, rq) = match r.find('?') {
        Some(i) => r.split_at(i),
        None => (r, ""),
    };
    let path = if rp.starts_with('/') {
        remove_dots(rp)
    } else {
        let dir = &bp[..=bp.rfind('/').unwrap_or(0)];
        remove_dots(&format!("{dir}{rp}"))
    };
    Some(format!("{bs}://{ba}{path}{rq}"))
}

#[cfg(test)]
mod tests {
    use super::resolve;

    #[test]
    fn rfc3986_examples() {
        // RFC 3986 section 5.4.1 (normal examples), base without the `;p` parameter subtleties.
        let base = "http://a/b/c/d;p?q";
        for (r, want) in [
            ("g:h", "g:h"),
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q"),
            ("g#s", "http://a/b/c/g"),
            ("", "http://a/b/c/d;p?q"),
            (".", "http://a/b/c/"),
            ("./", "http://a/b/c/"),
            ("..", "http://a/b/"),
            ("../", "http://a/b/"),
            ("../g", "http://a/b/g"),
            ("../..", "http://a/"),
            ("../../g", "http://a/g"),
            ("../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("g/../h", "http://a/b/c/h"),
            ("HTTPS://Other:8443/x", "https://Other:8443/x"),
        ] {
            assert_eq!(resolve(base, r).as_deref(), Some(want), "{r}");
        }
        assert_eq!(
            resolve("https://h:1?x", "y").as_deref(),
            Some("https://h:1/y")
        );
        assert_eq!(resolve("not a url", "/x"), None);
    }
}
