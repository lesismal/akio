//! Handshake messages and extensions: parsing (strict: lengths, duplicates, trailing bytes)
//! and encoding.

use super::alert::{Alert, Fatal, fatal};
use super::codec::{DResult, Reader, put_u8, put_u16, put_u24, put_vec, put_vec8, put_vec16};

// Handshake message types.
pub(crate) const HELLO_REQUEST: u8 = 0;
pub(crate) const CLIENT_HELLO: u8 = 1;
pub(crate) const SERVER_HELLO: u8 = 2;
pub(crate) const NEW_SESSION_TICKET: u8 = 4;
pub(crate) const END_OF_EARLY_DATA: u8 = 5;
pub(crate) const ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const CERTIFICATE: u8 = 11;
pub(crate) const SERVER_KEY_EXCHANGE: u8 = 12;
pub(crate) const CERTIFICATE_REQUEST: u8 = 13;
pub(crate) const SERVER_HELLO_DONE: u8 = 14;
pub(crate) const CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const CLIENT_KEY_EXCHANGE: u8 = 16;
pub(crate) const FINISHED: u8 = 20;
pub(crate) const KEY_UPDATE: u8 = 24;
pub(crate) const MESSAGE_HASH: u8 = 254;

// Extensions.
pub(crate) const EXT_SERVER_NAME: u16 = 0;
pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 10;
pub(crate) const EXT_EC_POINT_FORMATS: u16 = 11;
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub(crate) const EXT_ALPN: u16 = 16;
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub(crate) const EXT_SESSION_TICKET: u16 = 35;
pub(crate) const EXT_PRE_SHARED_KEY: u16 = 41;
pub(crate) const EXT_EARLY_DATA: u16 = 42;
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub(crate) const EXT_COOKIE: u16 = 44;
pub(crate) const EXT_PSK_MODES: u16 = 45;
pub(crate) const EXT_KEY_SHARE: u16 = 51;
pub(crate) const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 57;
pub(crate) const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

pub(crate) const TLS12: u16 = 0x0303;
pub(crate) const TLS13: u16 = 0x0304;

/// psk_dhe_ke (RFC 8446 section 4.2.9).
pub(crate) const PSK_DHE_KE: u8 = 1;

/// The ServerHello.random of a HelloRetryRequest (SHA-256 of "HelloRetryRequest").
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Last 8 bytes of a TLS 1.3 server's random when it negotiates TLS 1.2 (RFC 8446 4.1.3).
pub(crate) const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";
/// The same for TLS 1.1 and below.
pub(crate) const DOWNGRADE_TLS11: [u8; 8] = *b"DOWNGRD\x00";

/// Encodes a handshake message: type, 24-bit length, body.
pub(crate) fn message(typ: u8, body: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    put_u8(&mut out, typ);
    put_vec(&mut out, 3, body);
    out
}

/// Reads an extension block: `(type, data)` pairs, rejecting duplicates.
pub(crate) fn extensions<'a>(r: &mut Reader<'a>) -> DResult<Vec<(u16, &'a [u8])>> {
    let mut out: Vec<(u16, &'a [u8])> = Vec::new();
    if r.is_empty() {
        return Ok(out); // the extensions block may be absent (TLS 1.2 hellos)
    }
    let mut x = r.sub16()?;
    while !x.is_empty() {
        let t = x.u16()?;
        let d = x.vec16()?;
        if out.iter().any(|(o, _)| *o == t) {
            return fatal(Alert::IllegalParameter, "duplicate extension");
        }
        out.push((t, d));
    }
    Ok(out)
}

/// A pre_shared_key offer (RFC 8446 section 4.2.11).
#[derive(Debug, Clone)]
pub(crate) struct OfferedPsk<'a> {
    pub(crate) identities: Vec<(&'a [u8], u32)>,
    pub(crate) binders: Vec<&'a [u8]>,
    /// Length of the encoded binders list, including its two-byte length.
    pub(crate) binders_len: usize,
}

/// A parsed ClientHello.
#[derive(Debug, Clone, Default)]
pub(crate) struct ClientHello<'a> {
    pub(crate) legacy_version: u16,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: &'a [u8],
    pub(crate) suites: Vec<u16>,
    pub(crate) compression: &'a [u8],
    pub(crate) exts: Vec<(u16, &'a [u8])>,
    pub(crate) sni: Option<String>,
    pub(crate) versions: Option<Vec<u16>>,
    pub(crate) groups: Option<Vec<u16>>,
    pub(crate) key_shares: Option<Vec<(u16, &'a [u8])>>,
    pub(crate) sig_algs: Option<Vec<u16>>,
    pub(crate) alpn: Option<Vec<&'a [u8]>>,
    pub(crate) psk_modes: Option<&'a [u8]>,
    pub(crate) psk: Option<OfferedPsk<'a>>,
    pub(crate) early_data: bool,
    pub(crate) cookie: Option<&'a [u8]>,
    pub(crate) ems: bool,
    pub(crate) reneg_info: Option<&'a [u8]>,
    pub(crate) session_ticket: Option<&'a [u8]>,
    pub(crate) ec_point_formats: Option<&'a [u8]>,
    pub(crate) quic_params: Option<&'a [u8]>,
}

impl<'a> ClientHello<'a> {
    /// Parses a ClientHello body (after the 4-byte handshake header).
    pub(crate) fn parse(body: &'a [u8]) -> DResult<ClientHello<'a>> {
        let mut r = Reader::new(body);
        let mut ch = ClientHello {
            legacy_version: r.u16()?,
            random: r.array()?,
            session_id: r.vec8()?,
            ..ClientHello::default()
        };
        if ch.session_id.len() > 32 {
            return fatal(Alert::DecodeError, "session id too long");
        }
        let mut s = r.sub16()?;
        if s.is_empty() {
            return fatal(Alert::DecodeError, "no cipher suites");
        }
        while !s.is_empty() {
            ch.suites.push(s.u16()?);
        }
        ch.compression = r.vec8()?;
        if ch.compression.is_empty() {
            return fatal(Alert::DecodeError, "no compression methods");
        }
        ch.exts = extensions(&mut r)?;
        r.finish()?;
        let n = ch.exts.len();
        for (i, (t, d)) in ch.exts.clone().into_iter().enumerate() {
            let mut x = Reader::new(d);
            match t {
                EXT_SERVER_NAME => {
                    let mut l = x.sub16()?;
                    while !l.is_empty() {
                        let kind = l.u8()?;
                        let name = l.vec16()?;
                        if kind == 0 {
                            if ch.sni.is_some() {
                                return fatal(Alert::IllegalParameter, "two host names");
                            }
                            ch.sni = Some(parse_host_name(name)?);
                        }
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    let mut l = x.sub8()?;
                    let mut v = Vec::new();
                    if l.is_empty() {
                        return fatal(Alert::DecodeError, "empty supported_versions");
                    }
                    while !l.is_empty() {
                        v.push(l.u16()?);
                    }
                    ch.versions = Some(v);
                }
                EXT_SUPPORTED_GROUPS => ch.groups = Some(x.u16_list()?),
                EXT_KEY_SHARE => {
                    let mut l = x.sub16()?;
                    let mut v: Vec<(u16, &[u8])> = Vec::new();
                    while !l.is_empty() {
                        let g = l.u16()?;
                        let k = l.vec16()?;
                        if k.is_empty() {
                            return fatal(Alert::IllegalParameter, "empty key share");
                        }
                        if v.iter().any(|(o, _)| *o == g) {
                            return fatal(Alert::IllegalParameter, "duplicate key share");
                        }
                        v.push((g, k));
                    }
                    ch.key_shares = Some(v);
                }
                EXT_SIGNATURE_ALGORITHMS => ch.sig_algs = Some(x.u16_list()?),
                EXT_ALPN => ch.alpn = Some(parse_alpn(&mut x)?),
                EXT_PSK_MODES => {
                    let m = x.vec8()?;
                    if m.is_empty() {
                        return fatal(Alert::DecodeError, "empty psk modes");
                    }
                    ch.psk_modes = Some(m);
                }
                EXT_PRE_SHARED_KEY => {
                    if i + 1 != n {
                        return fatal(Alert::IllegalParameter, "pre_shared_key not last");
                    }
                    let mut ids = x.sub16()?;
                    let mut identities = Vec::new();
                    while !ids.is_empty() {
                        let id = ids.vec16()?;
                        let age = ids.u32()?;
                        if id.is_empty() {
                            return fatal(Alert::DecodeError, "empty psk identity");
                        }
                        identities.push((id, age));
                    }
                    let rest_len = x.clone().rest().len();
                    let mut bs = x.sub16()?;
                    let mut binders = Vec::new();
                    while !bs.is_empty() {
                        let b = bs.vec8()?;
                        if b.len() < 32 {
                            return fatal(Alert::DecodeError, "short psk binder");
                        }
                        binders.push(b);
                    }
                    if identities.is_empty() || identities.len() != binders.len() {
                        return fatal(Alert::IllegalParameter, "psk identities and binders");
                    }
                    ch.psk = Some(OfferedPsk {
                        identities,
                        binders,
                        binders_len: rest_len,
                    });
                }
                EXT_EARLY_DATA => {
                    ch.early_data = true;
                }
                EXT_COOKIE => {
                    let c = x.vec16()?;
                    if c.is_empty() {
                        return fatal(Alert::DecodeError, "empty cookie");
                    }
                    ch.cookie = Some(c);
                }
                EXT_EXTENDED_MASTER_SECRET => ch.ems = true,
                EXT_RENEGOTIATION_INFO => ch.reneg_info = Some(x.vec8()?),
                EXT_SESSION_TICKET => {
                    ch.session_ticket = Some(x.rest());
                }
                EXT_EC_POINT_FORMATS => {
                    // An empty list matters only to TLS 1.2 (no uncompressed format there).
                    ch.ec_point_formats = Some(x.vec8()?);
                }
                EXT_QUIC_TRANSPORT_PARAMETERS => ch.quic_params = Some(x.rest()),
                _ => {
                    x.rest();
                }
            }
            x.finish()?;
        }
        Ok(ch)
    }
}

/// A host name of a server_name extension: ASCII, no trailing dot, lowercased.
fn parse_host_name(name: &[u8]) -> DResult<String> {
    let s = std::str::from_utf8(name)
        .map_err(|_| Fatal::new(Alert::DecodeError, "server name is not ASCII"))?;
    if s.is_empty() || !s.is_ascii() || s.ends_with('.') || s.parse::<std::net::IpAddr>().is_ok() {
        return fatal(Alert::DecodeError, "invalid server name");
    }
    Ok(s.to_ascii_lowercase())
}

fn parse_alpn<'a>(x: &mut Reader<'a>) -> DResult<Vec<&'a [u8]>> {
    let mut l = x.sub16()?;
    let mut v = Vec::new();
    if l.is_empty() {
        return fatal(Alert::DecodeError, "empty ALPN list");
    }
    while !l.is_empty() {
        let p = l.vec8()?;
        if p.is_empty() {
            return fatal(Alert::DecodeError, "empty ALPN protocol");
        }
        v.push(p);
    }
    Ok(v)
}

/// The single protocol of a server's ALPN extension.
pub(crate) fn parse_alpn_selected(d: &[u8]) -> DResult<Vec<u8>> {
    let mut x = Reader::new(d);
    let v = parse_alpn(&mut x)?;
    x.finish()?;
    if v.len() != 1 {
        return fatal(Alert::DecodeError, "server selected several ALPN protocols");
    }
    Ok(v[0].to_vec())
}

/// Writes an ALPN extension body.
pub(crate) fn alpn_body(out: &mut Vec<u8>, protocols: &[impl AsRef<[u8]>]) {
    put_vec(out, 2, |o| {
        for p in protocols {
            put_vec8(o, p.as_ref());
        }
    });
}

/// A parsed ServerHello (or HelloRetryRequest).
#[derive(Debug, Clone, Default)]
pub(crate) struct ServerHello<'a> {
    pub(crate) legacy_version: u16,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: &'a [u8],
    pub(crate) suite: u16,
    pub(crate) exts: Vec<(u16, &'a [u8])>,
    pub(crate) version: Option<u16>,
    /// key_share: `(group, public)`; for a HelloRetryRequest the public part is empty.
    pub(crate) key_share: Option<(u16, &'a [u8])>,
    pub(crate) psk_index: Option<u16>,
    pub(crate) cookie: Option<&'a [u8]>,
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) ems: bool,
    pub(crate) reneg_info: Option<&'a [u8]>,
    pub(crate) session_ticket: bool,
    pub(crate) ec_point_formats: Option<&'a [u8]>,
}

impl<'a> ServerHello<'a> {
    pub(crate) fn parse(body: &'a [u8]) -> DResult<ServerHello<'a>> {
        let mut r = Reader::new(body);
        let mut sh = ServerHello {
            legacy_version: r.u16()?,
            random: r.array()?,
            session_id: r.vec8()?,
            suite: r.u16()?,
            ..ServerHello::default()
        };
        if sh.session_id.len() > 32 {
            return fatal(Alert::DecodeError, "session id too long");
        }
        if r.u8()? != 0 {
            return fatal(Alert::IllegalParameter, "server chose compression");
        }
        sh.exts = extensions(&mut r)?;
        r.finish()?;
        let hrr = sh.random == HRR_RANDOM;
        for (t, d) in sh.exts.clone() {
            let mut x = Reader::new(d);
            match t {
                EXT_SUPPORTED_VERSIONS => sh.version = Some(x.u16()?),
                EXT_KEY_SHARE => {
                    let g = x.u16()?;
                    let k = if hrr { &[][..] } else { x.vec16()? };
                    if !hrr && k.is_empty() {
                        return fatal(Alert::DecodeError, "empty key share");
                    }
                    sh.key_share = Some((g, k));
                }
                EXT_PRE_SHARED_KEY => sh.psk_index = Some(x.u16()?),
                EXT_COOKIE => {
                    let c = x.vec16()?;
                    if c.is_empty() {
                        return fatal(Alert::DecodeError, "empty cookie");
                    }
                    sh.cookie = Some(c);
                }
                EXT_ALPN => sh.alpn = Some(parse_alpn_selected(x.rest())?),
                EXT_EXTENDED_MASTER_SECRET => sh.ems = true,
                EXT_RENEGOTIATION_INFO => sh.reneg_info = Some(x.vec8()?),
                EXT_SESSION_TICKET => sh.session_ticket = true,
                EXT_EC_POINT_FORMATS => sh.ec_point_formats = Some(x.vec8()?),
                _ => {
                    x.rest();
                }
            }
            x.finish()?;
        }
        Ok(sh)
    }
}

/// Encodes a TLS 1.3 Certificate message (`context` empty for server certificates).
pub(crate) fn certificate13(context: &[u8], chain: &[Vec<u8>]) -> Vec<u8> {
    message(CERTIFICATE, |o| {
        put_vec8(o, context);
        put_vec(o, 3, |o| {
            for c in chain {
                put_u24(o, c.len());
                o.extend_from_slice(c);
                put_u16(o, 0);
            }
        });
    })
}

/// Parses a TLS 1.3 Certificate body: `(context, chain)`.
pub(crate) fn parse_certificate13(body: &[u8]) -> DResult<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut r = Reader::new(body);
    let ctx = r.vec8()?.to_vec();
    let mut l = r.sub24()?;
    r.finish()?;
    let mut chain = Vec::new();
    while !l.is_empty() {
        let c = l.vec24()?;
        if c.is_empty() {
            return fatal(Alert::DecodeError, "empty certificate");
        }
        let exts = l.vec16()?;
        let mut e = Reader::new(exts);
        while !e.is_empty() {
            e.u16()?;
            e.vec16()?;
        }
        chain.push(c.to_vec());
    }
    Ok((ctx, chain))
}

/// Encodes a TLS 1.2 Certificate message.
pub(crate) fn certificate12(chain: &[Vec<u8>]) -> Vec<u8> {
    message(CERTIFICATE, |o| {
        put_vec(o, 3, |o| {
            for c in chain {
                put_u24(o, c.len());
                o.extend_from_slice(c);
            }
        });
    })
}

/// Parses a TLS 1.2 Certificate body.
pub(crate) fn parse_certificate12(body: &[u8]) -> DResult<Vec<Vec<u8>>> {
    let mut r = Reader::new(body);
    let mut l = r.sub24()?;
    r.finish()?;
    let mut chain = Vec::new();
    while !l.is_empty() {
        let c = l.vec24()?;
        if c.is_empty() {
            return fatal(Alert::DecodeError, "empty certificate");
        }
        chain.push(c.to_vec());
    }
    Ok(chain)
}

/// Encodes a CertificateVerify (also the signature part of a ServerKeyExchange).
pub(crate) fn certificate_verify(scheme: u16, sig: &[u8]) -> Vec<u8> {
    message(CERTIFICATE_VERIFY, |o| {
        put_u16(o, scheme);
        put_vec16(o, sig);
    })
}

/// Parses `scheme, signature<0..2^16-1>`.
pub(crate) fn parse_signature<'a>(r: &mut Reader<'a>) -> DResult<(u16, &'a [u8])> {
    let s = r.u16()?;
    let sig = r.vec16()?;
    Ok((s, sig))
}

/// Encodes the signature_algorithms extension body.
pub(crate) fn sig_algs_body(out: &mut Vec<u8>, schemes: &[u16]) {
    put_vec(out, 2, |o| {
        for s in schemes {
            put_u16(o, *s);
        }
    });
}

/// Writes one extension.
pub(crate) fn ext(out: &mut Vec<u8>, t: u16, body: impl FnOnce(&mut Vec<u8>)) {
    put_u16(out, t);
    put_vec(out, 2, body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_extensions_rejected() {
        let mut b = Vec::new();
        put_vec(&mut b, 2, |o| {
            ext(o, 1, |_| {});
            ext(o, 1, |_| {});
        });
        assert!(extensions(&mut Reader::new(&b)).is_err());
    }

    #[test]
    fn host_names() {
        assert_eq!(parse_host_name(b"Example.COM").unwrap(), "example.com");
        assert!(parse_host_name(b"a.").is_err());
        assert!(parse_host_name(b"127.0.0.1").is_err());
        assert!(parse_host_name(b"").is_err());
        assert!(parse_host_name(&[0xff]).is_err());
    }

    #[test]
    fn certificates_roundtrip() {
        let chain = vec![vec![1, 2, 3], vec![4]];
        let m = certificate13(b"ctx", &chain);
        let (c, ch) = parse_certificate13(&m[4..]).unwrap();
        assert_eq!((c.as_slice(), ch), (&b"ctx"[..], chain.clone()));
        let m = certificate12(&chain);
        assert_eq!(parse_certificate12(&m[4..]).unwrap(), chain);
        assert!(parse_certificate12(&[0, 0, 3, 0, 0, 0]).is_err());
    }
}
