//! PEM (RFC 7468): `-----BEGIN LABEL-----`, base64 lines, `-----END LABEL-----`.
//!
//! Decoding skips text outside the blocks (explanatory text, as `openssl x509 -text` writes),
//! accepts any line length and CRLF line ends, and rejects blocks with headers, mismatched
//! labels or invalid base64.
//!
//! ```
//! use only_crypto::pem;
//!
//! let text = pem::encode("TEST", &[1, 2, 3]);
//! assert_eq!(text, "-----BEGIN TEST-----\nAQID\n-----END TEST-----\n");
//! let blocks = pem::decode(text.as_bytes()).unwrap();
//! assert_eq!(blocks, vec![("TEST".to_string(), vec![1, 2, 3])]);
//! ```

use crate::Error;
use crate::base64::STANDARD;

/// Every block in `text`, in order: `(label, decoded bytes)`. Fails if a block is malformed.
pub fn decode(text: &[u8]) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let text = std::str::from_utf8(text).map_err(|_| Error::Encoding)?;
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        else {
            continue;
        };
        let mut b64 = String::new();
        let mut ended = false;
        for l in lines.by_ref() {
            if let Some(end) = l
                .strip_prefix("-----END ")
                .and_then(|l| l.strip_suffix("-----"))
            {
                if end != label {
                    return Err(Error::Encoding);
                }
                ended = true;
                break;
            }
            if l.contains(':') || l.starts_with("-----") {
                return Err(Error::Encoding); // RFC 1421 headers: not supported
            }
            b64.push_str(l);
        }
        if !ended {
            return Err(Error::Encoding);
        }
        let der = STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| Error::Encoding)?;
        out.push((label.to_string(), der));
    }
    Ok(out)
}

/// The decoded contents of every block labelled `label`.
pub fn decode_label(text: &[u8], label: &str) -> Result<Vec<Vec<u8>>, Error> {
    Ok(decode(text)?
        .into_iter()
        .filter(|(l, _)| l == label)
        .map(|(_, d)| d)
        .collect())
}

/// One block with 64-character lines and a trailing newline.
#[must_use]
pub fn encode(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut s = String::with_capacity(b64.len() + b64.len() / 64 + 2 * label.len() + 40);
    s.push_str("-----BEGIN ");
    s.push_str(label);
    s.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        s.push('\n');
    }
    s.push_str("-----END ");
    s.push_str(label);
    s.push_str("-----\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks() {
        let data: Vec<u8> = (0..100).collect();
        let mut text = String::from("subject=foo\r\n");
        text.push_str(&encode("CERTIFICATE", &data).replace('\n', "\r\n"));
        text.push_str("junk\n");
        text.push_str(&encode("PRIVATE KEY", &[9]));
        let b = decode(text.as_bytes()).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b[0], ("CERTIFICATE".into(), data));
        assert_eq!(
            decode_label(text.as_bytes(), "PRIVATE KEY").unwrap(),
            vec![vec![9]]
        );
        assert!(decode(b"-----BEGIN A-----\nAQID\n-----END B-----\n").is_err());
        assert!(decode(b"-----BEGIN A-----\nAQID\n").is_err());
        assert!(decode(b"-----BEGIN A-----\nAQ!D\n-----END A-----\n").is_err());
        assert!(decode(b"-----BEGIN A-----\nProc-Type: 4\n-----END A-----\n").is_err());
        assert!(decode(b"nothing").unwrap().is_empty());
    }
}
