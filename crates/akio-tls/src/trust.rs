//! macOS trust settings (ADR-059): what `security trust-settings-export` writes (an XML
//! property list) turned into a verdict per certificate.
//!
//! The export maps each certificate's SHA-1 (40 hex digits) to an array of usage constraints
//! (`trustSettings`). An empty array trusts the certificate as a root for everything; otherwise
//! the first constraint that applies to TLS server authentication decides: its
//! `kSecTrustSettingsResult` (1 TrustRoot or 2 TrustAsRoot: trusted, 3 Deny: distrusted, 4
//! Unspecified: look further; 1 when absent). A constraint applies when it names no policy or
//! the `sslServer` or `basicX509` policy, and is not limited to one application
//! (`kSecTrustSettingsApplication`) or one host name (`kSecTrustSettingsPolicyString`). The
//! domains are consulted user first, then admin, then system, as the Security framework does.
//!
//! The parser handles the plist subset the export uses (`dict`, `key`, `array`, `data`,
//! `string`, `integer`, `date`, `true`, `false`, `real`) and is bounded: at most
//! [`MAX_DEPTH`] levels of nesting and [`MAX_INPUT`] bytes of input.

use std::collections::HashMap;

/// Deepest nesting accepted.
pub(crate) const MAX_DEPTH: usize = 16;
/// Largest export accepted (the system domain's is about 60 KB).
pub(crate) const MAX_INPUT: usize = 8 << 20;

/// What the trust settings say about a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A root for TLS servers.
    Trusted,
    /// Never trusted (`Deny`).
    Distrusted,
    /// Nothing that applies: the next domain decides.
    Unspecified,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Value {
    Dict(Vec<(String, Value)>),
    Array(Vec<Value>),
    Data(Vec<u8>),
    String(String),
    Integer(i64),
    /// `date`, `real`, `true`, `false`: not needed here.
    Other,
}

impl Value {
    fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(d) => d.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

impl<'a> Parser<'a> {
    /// Skips whitespace, the XML declaration, the doctype and comments.
    fn skip(&mut self) {
        loop {
            let rest = &self.s[self.pos..];
            let t = rest.trim_start();
            self.pos += rest.len() - t.len();
            let end = if t.starts_with("<?") {
                t.find("?>").map(|i| i + 2)
            } else if t.starts_with("<!--") {
                t.find("-->").map(|i| i + 3)
            } else if t.starts_with("<!") {
                t.find('>').map(|i| i + 1)
            } else {
                return;
            };
            match end {
                Some(n) => self.pos += n,
                None => {
                    self.pos = self.s.len();
                    return;
                }
            }
        }
    }

    /// The next tag: its name and whether it is self-closing (`<x/>`), or `None` at the end
    /// or on garbage. Closing tags come back as `/name`.
    fn tag(&mut self) -> Option<(&'a str, bool)> {
        self.skip();
        let rest = &self.s[self.pos..];
        let body = rest.strip_prefix('<')?;
        let end = body.find('>')?;
        self.pos += end + 2;
        let inner = &body[..end];
        let (inner, empty) = match inner.strip_suffix('/') {
            Some(i) => (i, true),
            None => (inner, false),
        };
        // No attributes in a plist we read (`<plist version="1.0">` aside).
        let name = inner.split_whitespace().next()?;
        Some((name, empty))
    }

    /// Text up to `</name>`, consumed with it.
    fn text(&mut self, name: &str) -> Option<&'a str> {
        let rest = &self.s[self.pos..];
        let close = format!("</{name}>");
        let i = rest.find(&close)?;
        self.pos += i + close.len();
        Some(&rest[..i])
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (name, empty) = self.tag()?;
        self.value_of(name, empty, depth)
    }

    fn value_of(&mut self, name: &'a str, empty: bool, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        Some(match name {
            "dict" => {
                let mut d = Vec::new();
                if !empty {
                    loop {
                        match self.tag()? {
                            ("/dict", _) => break,
                            ("key", false) => {
                                let k = unescape(self.text("key")?);
                                d.push((k, self.value(depth + 1)?));
                            }
                            _ => return None,
                        }
                    }
                }
                Value::Dict(d)
            }
            "array" => {
                let mut a = Vec::new();
                if !empty {
                    loop {
                        let (n, e) = self.tag()?;
                        if n == "/array" {
                            break;
                        }
                        a.push(self.value_of(n, e, depth + 1)?);
                    }
                }
                Value::Array(a)
            }
            "data" if empty => Value::Data(Vec::new()),
            "data" => {
                let t: String = self
                    .text("data")?
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect();
                Value::Data(akio_crypto::base64::STANDARD.decode(t).ok()?)
            }
            "string" if empty => Value::String(String::new()),
            "string" => Value::String(unescape(self.text("string")?)),
            "integer" => Value::Integer(self.text("integer")?.trim().parse().ok()?),
            "true" | "false" if empty => Value::Other,
            "date" | "real" => {
                self.text(name)?;
                Value::Other
            }
            _ => return None,
        })
    }
}

/// Parses a property list document; `None` when it is not one this parser reads.
pub(crate) fn parse(xml: &str) -> Option<Value> {
    if xml.len() > MAX_INPUT {
        return None;
    }
    let mut p = Parser { s: xml, pos: 0 };
    let (name, empty) = p.tag()?;
    if name != "plist" || empty {
        return None;
    }
    let v = p.value(0)?;
    match p.tag() {
        Some(("/plist", _)) => Some(v),
        _ => None,
    }
}

/// `sslServer` (1.2.840.113635.100.1.3) and `basicX509` (1.2.840.113635.100.1.2), as the
/// export stores them: the OID's DER content octets.
const SSL_SERVER: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x01, 0x03];
const BASIC_X509: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x01, 0x02];

fn verdict(settings: Option<&Value>) -> Verdict {
    let list = match settings {
        Some(Value::Array(a)) => a.as_slice(),
        None => &[],
        Some(_) => return Verdict::Unspecified,
    };
    if list.is_empty() {
        return Verdict::Trusted;
    }
    for s in list {
        if !matches!(s, Value::Dict(_))
            || s.get("kSecTrustSettingsApplication").is_some()
            || s.get("kSecTrustSettingsPolicyString").is_some()
        {
            continue;
        }
        match s.get("kSecTrustSettingsPolicy") {
            None => {}
            Some(Value::Data(oid)) if oid == SSL_SERVER || oid == BASIC_X509 => {}
            Some(_) => continue,
        }
        match s.get("kSecTrustSettingsResult") {
            None | Some(Value::Integer(1 | 2)) => return Verdict::Trusted,
            Some(Value::Integer(3)) => return Verdict::Distrusted,
            _ => {}
        }
    }
    Verdict::Unspecified
}

/// The verdicts of one domain's export, by certificate SHA-1; `None` when it does not parse.
pub(crate) fn trust_list(xml: &str) -> Option<HashMap<[u8; 20], Verdict>> {
    let root = parse(xml)?;
    let Some(Value::Dict(list)) = root.get("trustList") else {
        return None;
    };
    let mut out = HashMap::new();
    for (k, v) in list {
        let Some(sha1) = hex20(k) else { continue };
        out.insert(sha1, verdict(v.get("trustSettings")));
    }
    Some(out)
}

fn hex20(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The fuzz entry (`tls_trust_plist`): never panics, and parses what it accepts the same way
/// twice.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn fuzz(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let a = trust_list(s);
    assert_eq!(a, trust_list(s));
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const ADMIN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>trustList</key>
	<dict>
		<key>1111111111111111111111111111111111111111</key>
		<dict>
			<key>issuerName</key>
			<data>
			MAA=
			</data>
			<key>modDate</key>
			<date>2025-05-11T08:27:10Z</date>
			<key>trustSettings</key>
			<array>
				<dict>
					<key>kSecTrustSettingsPolicy</key>
					<data>
					KoZIhvdjZAEC
					</data>
					<key>kSecTrustSettingsPolicyName</key>
					<string>basicX509</string>
				</dict>
			</array>
		</dict>
		<key>00000000000000000000000000000000000000AA</key>
		<dict>
			<key>trustSettings</key>
			<array>
				<dict>
					<key>kSecTrustSettingsPolicy</key>
					<data>KoZIhvdjZAED</data>
					<key>kSecTrustSettingsResult</key>
					<integer>3</integer>
				</dict>
			</array>
		</dict>
		<key>00000000000000000000000000000000000000BB</key>
		<dict>
			<key>trustSettings</key>
			<array/>
		</dict>
		<key>00000000000000000000000000000000000000CC</key>
		<dict>
			<key>trustSettings</key>
			<array>
				<dict>
					<key>kSecTrustSettingsPolicy</key>
					<data>KoZIhvdjZAEI</data>
					<key>kSecTrustSettingsResult</key>
					<integer>3</integer>
				</dict>
				<dict>
					<key>kSecTrustSettingsPolicyString</key>
					<string>akio.example &amp; co</string>
				</dict>
				<dict>
					<key>kSecTrustSettingsResult</key>
					<integer>4</integer>
				</dict>
			</array>
		</dict>
		<key>not-a-hash</key>
		<dict/>
	</dict>
	<key>trustVersion</key>
	<integer>1</integer>
	<key>flag</key>
	<true/>
</dict>
</plist>
"#;

    #[test]
    fn verdicts() {
        let l = trust_list(ADMIN).unwrap();
        assert_eq!(l.len(), 4);
        let h = |s: &str| hex20(s).unwrap();
        assert_eq!(
            l[&h("1111111111111111111111111111111111111111")],
            Verdict::Trusted
        );
        assert_eq!(
            l[&h("00000000000000000000000000000000000000AA")],
            Verdict::Distrusted
        );
        assert_eq!(
            l[&h("00000000000000000000000000000000000000BB")],
            Verdict::Trusted
        );
        assert_eq!(
            l[&h("00000000000000000000000000000000000000CC")],
            Verdict::Unspecified,
            "S/MIME deny, host-limited and unspecified constraints do not decide"
        );
        let empty = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>trustList</key><dict/></dict></plist>";
        assert_eq!(trust_list(empty).unwrap().len(), 0);
    }

    #[test]
    fn rejects_what_it_does_not_read() {
        for bad in [
            "",
            "<plist>",
            "<plist version=\"1.0\"><dict><key>trustList</key></dict></plist>",
            "<plist version=\"1.0\"><dict><key>a</key><integer>x</integer></dict></plist>",
            "<plist version=\"1.0\"><dict><key>a</key><data>!!</data></dict></plist>",
            "<plist version=\"1.0\"><unknown/></plist>",
            "<plist version=\"1.0\"><dict></dict>",
        ] {
            assert!(trust_list(bad).is_none(), "{bad}");
        }
        let deep = format!(
            "<plist version=\"1.0\">{}{}</plist>",
            "<array>".repeat(MAX_DEPTH + 2),
            "</array>".repeat(MAX_DEPTH + 2)
        );
        assert!(parse(&deep).is_none());
        let ok = format!(
            "<plist version=\"1.0\">{}{}</plist>",
            "<array>".repeat(MAX_DEPTH),
            "</array>".repeat(MAX_DEPTH)
        );
        assert!(parse(&ok).is_some());
    }

    #[test]
    fn fuzz_seeds() {
        fuzz(ADMIN.as_bytes());
        fuzz(&ADMIN.as_bytes()[..ADMIN.len() / 2]);
        fuzz(b"<plist><dict><key>");
    }
}
