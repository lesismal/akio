//! Distinguished names and general names.

use std::net::IpAddr;

use only_crypto::der::{Reader, Writer, oid, tag};

use crate::Error;

/// Attribute type OIDs (2.5.4.x) used in names.
pub mod attr {
    /// commonName, 2.5.4.3.
    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
    /// countryName, 2.5.4.6.
    pub const COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
    /// localityName, 2.5.4.7.
    pub const LOCALITY: &[u8] = &[0x55, 0x04, 0x07];
    /// stateOrProvinceName, 2.5.4.8.
    pub const STATE: &[u8] = &[0x55, 0x04, 0x08];
    /// organizationName, 2.5.4.10.
    pub const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
    /// organizationalUnitName, 2.5.4.11.
    pub const ORGANIZATIONAL_UNIT: &[u8] = &[0x55, 0x04, 0x0b];
}

/// One attribute of a distinguished name: type, string tag and value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The attribute type OID (content bytes).
    pub oid: Vec<u8>,
    /// The DER tag of the value (UTF8String, PrintableString, ...).
    pub tag: u8,
    /// The value's content bytes.
    pub value: Vec<u8>,
}

impl Attribute {
    /// The value as text, for the string types (BMPString decoded from UTF-16).
    #[must_use]
    pub fn value_str(&self) -> Option<String> {
        match self.tag {
            tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING | tag::TELETEX_STRING => {
                String::from_utf8(self.value.clone()).ok()
            }
            tag::BMP_STRING if self.value.len() % 2 == 0 => {
                let u: Vec<u16> = self
                    .value
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&u).ok()
            }
            _ => None,
        }
    }
}

/// An X.501 distinguished name: the raw DER (compared byte for byte when chaining
/// certificates, as RFC 5280 §7.1 allows) and the parsed relative distinguished names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    der: Vec<u8>,
    /// Each RDN's whole DER (`SET`), for subtree prefix matching.
    rdn_der: Vec<Vec<u8>>,
    rdns: Vec<Vec<Attribute>>,
}

impl Name {
    /// Parses a DER `Name` (the whole SEQUENCE element).
    pub fn from_der(der: &[u8]) -> Result<Name, Error> {
        let mut r = Reader::new(der);
        let mut seq = r.sequence()?;
        r.finish()?;
        let mut rdns = Vec::new();
        let mut rdn_der = Vec::new();
        while !seq.is_empty() {
            let whole = seq.read_element(tag::SET)?;
            let mut set = Reader::new(whole).constructed(tag::SET)?;
            let mut attrs = Vec::new();
            if set.is_empty() {
                return Err(Error::Encoding);
            }
            while !set.is_empty() {
                let mut a = set.sequence()?;
                let oid = a.read_oid()?.to_vec();
                let (t, v, _) = a.read_tlv()?;
                a.finish()?;
                attrs.push(Attribute {
                    oid,
                    tag: t,
                    value: v.to_vec(),
                });
            }
            rdn_der.push(whole.to_vec());
            rdns.push(attrs);
        }
        Ok(Name {
            der: der.to_vec(),
            rdn_der,
            rdns,
        })
    }

    /// A name built from `(attribute OID, UTF-8 value)` pairs, one attribute per RDN
    /// (PrintableString for countryName, UTF8String otherwise).
    #[must_use]
    pub fn from_attributes<'a>(attrs: impl IntoIterator<Item = (&'a [u8], &'a str)>) -> Name {
        let mut w = Writer::new();
        w.sequence(|w| {
            for (o, v) in attrs {
                w.nested(tag::SET, |w| {
                    w.sequence(|w| {
                        w.oid(o);
                        let t = if o == attr::COUNTRY {
                            tag::PRINTABLE_STRING
                        } else {
                            tag::UTF8_STRING
                        };
                        w.tlv(t, v.as_bytes());
                    });
                });
            }
        });
        // Our own encoding always parses.
        Name::from_der(w.as_bytes()).unwrap_or_else(|_| Name {
            der: w.into_vec(),
            rdn_der: Vec::new(),
            rdns: Vec::new(),
        })
    }

    /// The DER encoding.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The relative distinguished names in order, each a set of attributes.
    #[must_use]
    pub fn rdns(&self) -> &[Vec<Attribute>] {
        &self.rdns
    }

    /// Whether the name has no RDNs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    /// The values of every attribute of type `oid`, as text.
    pub fn values<'a>(&'a self, oid: &'a [u8]) -> impl Iterator<Item = String> + 'a {
        self.rdns
            .iter()
            .flatten()
            .filter(move |a| a.oid == oid)
            .filter_map(Attribute::value_str)
    }

    /// The (last) common name.
    #[must_use]
    pub fn common_name(&self) -> Option<String> {
        self.values(attr::COMMON_NAME).last()
    }

    /// Whether `prefix`'s RDNs are the first RDNs of `self` (directoryName name constraints).
    pub(crate) fn has_prefix(&self, prefix: &Name) -> bool {
        prefix.rdn_der.len() <= self.rdn_der.len()
            && prefix
                .rdn_der
                .iter()
                .zip(&self.rdn_der)
                .all(|(a, b)| a == b)
    }
}

impl std::fmt::Display for Name {
    /// RFC 4514-like, most significant RDN first (`C=US, O=Example, CN=host`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for a in self.rdns.iter().flatten() {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            let k = match a.oid.as_slice() {
                attr::COMMON_NAME => "CN".to_string(),
                attr::COUNTRY => "C".to_string(),
                attr::LOCALITY => "L".to_string(),
                attr::STATE => "ST".to_string(),
                attr::ORGANIZATION => "O".to_string(),
                attr::ORGANIZATIONAL_UNIT => "OU".to_string(),
                o => oid::to_string(o).unwrap_or_else(|| "?".into()),
            };
            match a.value_str() {
                Some(v) => write!(f, "{k}={v}")?,
                None => write!(f, "{k}=#{}", hex(&a.value))?,
            }
        }
        Ok(())
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A `GeneralName` (RFC 5280 §4.2.1.6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GeneralName {
    /// `dNSName`: an ASCII host name or wildcard pattern.
    Dns(String),
    /// `iPAddress`: 4 or 16 bytes in a SAN; address and mask (8 or 32 bytes) in a name
    /// constraint.
    Ip(Vec<u8>),
    /// `rfc822Name`: an e-mail address.
    Email(String),
    /// `uniformResourceIdentifier`.
    Uri(String),
    /// `directoryName`.
    DirectoryName(Name),
    /// Any other form: `(tag, contents)`.
    Other(u8, Vec<u8>),
}

impl GeneralName {
    /// Reads one `GeneralName`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<GeneralName, Error> {
        let (t, c, _) = r.read_tlv()?;
        let ascii = |c: &[u8]| -> Result<String, Error> {
            if c.is_ascii() {
                Ok(String::from_utf8(c.to_vec()).map_err(|_| Error::Encoding)?)
            } else {
                Err(Error::Encoding)
            }
        };
        Ok(match t {
            0x81 => GeneralName::Email(ascii(c)?),
            0x82 => GeneralName::Dns(ascii(c)?),
            0x86 => GeneralName::Uri(ascii(c)?),
            0x87 => GeneralName::Ip(c.to_vec()),
            0xa4 => {
                let mut inner = Reader::new(c);
                let n = inner.read_element(tag::SEQUENCE)?;
                inner.finish()?;
                GeneralName::DirectoryName(Name::from_der(n)?)
            }
            _ => GeneralName::Other(t, c.to_vec()),
        })
    }

    /// Writes one `GeneralName`.
    pub(crate) fn write(&self, w: &mut Writer) {
        match self {
            GeneralName::Email(s) => w.tlv(0x81, s.as_bytes()),
            GeneralName::Dns(s) => w.tlv(0x82, s.as_bytes()),
            GeneralName::Uri(s) => w.tlv(0x86, s.as_bytes()),
            GeneralName::Ip(b) => w.tlv(0x87, b),
            GeneralName::DirectoryName(n) => w.nested(0xa4, |w| w.raw(n.as_der())),
            GeneralName::Other(t, c) => w.tlv(*t, c),
        }
    }

    /// A DNS name or, if `s` parses as one, an IP address.
    #[must_use]
    pub fn from_host(s: &str) -> GeneralName {
        match s.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => GeneralName::Ip(a.octets().to_vec()),
            Ok(IpAddr::V6(a)) => GeneralName::Ip(a.octets().to_vec()),
            Err(_) => GeneralName::Dns(s.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let n = Name::from_attributes([
            (attr::COUNTRY, "US"),
            (attr::ORGANIZATION, "Example"),
            (attr::COMMON_NAME, "host.example"),
        ]);
        assert_eq!(n.to_string(), "C=US, O=Example, CN=host.example");
        assert_eq!(n.common_name().as_deref(), Some("host.example"));
        let p = Name::from_attributes([(attr::COUNTRY, "US")]);
        assert!(n.has_prefix(&p));
        assert!(!p.has_prefix(&n));
        assert_eq!(Name::from_der(n.as_der()).unwrap(), n);
        // Empty SET is not allowed.
        assert!(Name::from_der(&[0x30, 0x02, 0x31, 0x00]).is_err());
        let mut w = Writer::new();
        GeneralName::from_host("10.0.0.1").write(&mut w);
        GeneralName::from_host("a.example").write(&mut w);
        let v = w.into_vec();
        let mut r = Reader::new(&v);
        assert_eq!(
            GeneralName::read(&mut r).unwrap(),
            GeneralName::Ip(vec![10, 0, 0, 1])
        );
        assert_eq!(
            GeneralName::read(&mut r).unwrap(),
            GeneralName::Dns("a.example".into())
        );
    }
}
