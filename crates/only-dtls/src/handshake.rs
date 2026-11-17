//! Handshake messages (RFC 5246 §7.4, RFC 6347 §4.2/4.3), extensions and reassembly of
//! fragmented messages.

use crate::codec::{Reader, put_u16, put_u24, put_vec8, put_vec16};
use crate::{AlertDescription, Error};

pub(crate) const HELLO_REQUEST: u8 = 0;
pub(crate) const CLIENT_HELLO: u8 = 1;
pub(crate) const SERVER_HELLO: u8 = 2;
pub(crate) const HELLO_VERIFY_REQUEST: u8 = 3;
pub(crate) const CERTIFICATE: u8 = 11;
pub(crate) const SERVER_KEY_EXCHANGE: u8 = 12;
pub(crate) const CERTIFICATE_REQUEST: u8 = 13;
pub(crate) const SERVER_HELLO_DONE: u8 = 14;
pub(crate) const CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const CLIENT_KEY_EXCHANGE: u8 = 16;
pub(crate) const FINISHED: u8 = 20;
pub(crate) const NEW_SESSION_TICKET: u8 = 4;
pub(crate) const ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const KEY_UPDATE: u8 = 24;
/// The synthetic `message_hash` that replaces ClientHello1 in the transcript after a
/// HelloRetryRequest (RFC 8446 §4.4.1).
pub(crate) const MESSAGE_HASH: u8 = 254;

/// Handshake header: type, length, message_seq, fragment_offset, fragment_length.
pub(crate) const HEADER_LEN: usize = 12;
/// Largest handshake message accepted (certificate chains included).
pub(crate) const MAX_MESSAGE: usize = 1 << 16;
/// Largest ClientHello accepted. It is the one message a server reassembles before the cookie
/// exchange has proven the client's address, so it gets a tighter bound than [`MAX_MESSAGE`]
/// (real DTLS 1.2 ClientHellos are a few hundred bytes).
pub(crate) const MAX_CLIENT_HELLO: usize = 8 << 10;

pub(crate) const EXT_SUPPORTED_GROUPS: u16 = 10;
pub(crate) const EXT_EC_POINT_FORMATS: u16 = 11;
pub(crate) const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub(crate) const EXT_USE_SRTP: u16 = 14;
pub(crate) const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
pub(crate) const EXT_SESSION_TICKET: u16 = 35;
pub(crate) const EXT_PRE_SHARED_KEY: u16 = 41;
pub(crate) const EXT_EARLY_DATA: u16 = 42;
pub(crate) const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub(crate) const EXT_COOKIE: u16 = 44;
pub(crate) const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub(crate) const EXT_KEY_SHARE: u16 = 51;
pub(crate) const EXT_CONNECTION_ID: u16 = 54;
pub(crate) const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The ServerHello.random of a HelloRetryRequest: SHA-256("HelloRetryRequest").
pub(crate) const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
/// The last eight bytes of a DTLS 1.2 ServerHello.random from a server that supports
/// DTLS 1.3 (RFC 8446 §4.1.3 downgrade protection).
pub(crate) const DOWNGRADE_12: [u8; 8] = *b"DOWNGRD\x01";
/// `psk_dhe_ke`, the only PSK key exchange mode used (no `psk_ke`: always forward secret).
pub(crate) const PSK_DHE_KE: u8 = 1;

/// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (RFC 5746).
pub(crate) const SCSV_RENEGOTIATION: u16 = 0x00ff;

/// One handshake fragment as carried in a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fragment<'a> {
    pub(crate) msg_type: u8,
    pub(crate) length: usize,
    pub(crate) seq: u16,
    pub(crate) offset: usize,
    pub(crate) body: &'a [u8],
}

/// The handshake fragments of a record payload.
pub(crate) fn parse_fragments(payload: &[u8]) -> Result<Vec<Fragment<'_>>, Error> {
    let mut r = Reader::new(payload);
    let mut out = Vec::new();
    while !r.is_empty() {
        let msg_type = r.u8()?;
        let length = r.u24()?;
        let seq = r.u16()?;
        let offset = r.u24()?;
        let body = r.vec24()?;
        if offset + body.len() > length || length > MAX_MESSAGE {
            return Err(Error::decode("bad handshake fragment"));
        }
        out.push(Fragment {
            msg_type,
            length,
            seq,
            offset,
            body,
        });
    }
    Ok(out)
}

/// A handshake fragment with its 12-byte header (a whole message when `offset == 0` and
/// `frag.len() == total`).
pub(crate) fn encode_fragment(
    msg_type: u8,
    seq: u16,
    total: usize,
    offset: usize,
    frag: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + frag.len());
    out.push(msg_type);
    put_u24(&mut out, total);
    put_u16(&mut out, seq);
    put_u24(&mut out, offset);
    put_u24(&mut out, frag.len());
    out.extend_from_slice(frag);
    out
}

/// A whole message as it enters the transcript (RFC 6347 §4.2.6).
pub(crate) fn encode_message(msg_type: u8, seq: u16, body: &[u8]) -> Vec<u8> {
    encode_fragment(msg_type, seq, body.len(), 0, body)
}

/// A message being reassembled from fragments. The buffer grows with the fragments received
/// (up to the highest byte seen), not with the length a fragment claims: a single small
/// datagram claiming a 64 KiB message costs what it carries, not 64 KiB.
#[derive(Debug, Clone)]
pub(crate) struct Partial {
    msg_type: u8,
    length: usize,
    body: Vec<u8>,
    /// Received byte ranges, sorted and merged.
    ranges: Vec<(usize, usize)>,
}

impl Partial {
    pub(crate) fn new(f: &Fragment<'_>) -> Partial {
        Partial {
            msg_type: f.msg_type,
            length: f.length,
            body: Vec::new(),
            ranges: Vec::new(),
        }
    }

    /// Bytes held for the message so far.
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.body.capacity()
    }

    /// Adds a fragment; inconsistent ones (other type or length) are ignored.
    pub(crate) fn add(&mut self, f: &Fragment<'_>) {
        if f.msg_type != self.msg_type || f.length != self.length || f.body.is_empty() {
            return;
        }
        let (s, e) = (f.offset, f.offset + f.body.len());
        if self.body.len() < e {
            self.body.resize(e, 0);
        }
        self.body[s..e].copy_from_slice(f.body);
        self.ranges.push((s, e));
        self.ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.ranges.len());
        for &(s, e) in &self.ranges {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.ranges = merged;
    }

    /// End of the bytes received contiguously from the start.
    pub(crate) fn prefix(&self) -> usize {
        match self.ranges.first() {
            Some(&(0, e)) => e,
            _ => 0,
        }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.length == 0 || self.ranges.first() == Some(&(0, self.length))
    }

    pub(crate) fn into_message(self) -> (u8, Vec<u8>) {
        let mut body = self.body;
        body.resize(self.length, 0);
        (self.msg_type, body)
    }
}

/// Where an extension block appears: some extensions have a different shape per message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    ClientHello,
    ServerHello,
    HelloRetryRequest,
    EncryptedExtensions,
    CertificateRequest,
    NewSessionTicket,
}

/// The `pre_shared_key` offer of a ClientHello: identities with their obfuscated ages, and the
/// binders (same count).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PskOffer {
    pub(crate) identities: Vec<(Vec<u8>, u32)>,
    pub(crate) binders: Vec<Vec<u8>>,
}

impl PskOffer {
    /// Encoded length of the binders list (with its 2-byte length), which a binder's
    /// truncated ClientHello leaves out.
    pub(crate) fn binders_len(&self) -> usize {
        2 + self.binders.iter().map(|b| 1 + b.len()).sum::<usize>()
    }
}

/// Hello (and DTLS 1.3 EncryptedExtensions / CertificateRequest / NewSessionTicket)
/// extensions we understand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Extensions {
    pub(crate) groups: Option<Vec<u16>>,
    pub(crate) point_formats: Option<Vec<u8>>,
    pub(crate) signature_algorithms: Option<Vec<u16>>,
    /// `use_srtp`: profiles and MKI.
    pub(crate) srtp: Option<(Vec<u16>, Vec<u8>)>,
    pub(crate) extended_master_secret: bool,
    pub(crate) renegotiation_info: Option<Vec<u8>>,
    /// RFC 5077 `session_ticket` (DTLS 1.2): empty asks for or acknowledges a ticket.
    pub(crate) session_ticket: Option<Vec<u8>>,
    /// RFC 9146 `connection_id`: the CID the sender wants to receive.
    pub(crate) connection_id: Option<Vec<u8>>,
    /// `supported_versions`: the offered list (ClientHello) or the one selected.
    pub(crate) supported_versions: Option<Vec<u16>>,
    /// `key_share`: the client's shares, or the server's one.
    pub(crate) key_shares: Option<Vec<(u16, Vec<u8>)>>,
    /// `key_share` of a HelloRetryRequest: the group the server asks for.
    pub(crate) hrr_group: Option<u16>,
    /// DTLS 1.3 `cookie`.
    pub(crate) cookie: Option<Vec<u8>>,
    pub(crate) psk_modes: Option<Vec<u8>>,
    pub(crate) psk_offer: Option<PskOffer>,
    pub(crate) psk_selected: Option<u16>,
    pub(crate) early_data: bool,
    /// Types of extensions we ignored.
    pub(crate) unknown: Vec<u16>,
}

fn u16_list(data: &[u8], min: usize) -> Result<Vec<u16>, Error> {
    let mut r = Reader::new(data);
    let list = r.vec16()?;
    r.finish()?;
    if list.len() % 2 != 0 || list.len() < min {
        return Err(Error::decode("bad list"));
    }
    Ok(list
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

fn put_u16_list16(out: &mut Vec<u8>, v: &[u16]) {
    put_vec16(
        out,
        &v.iter().flat_map(|x| x.to_be_bytes()).collect::<Vec<u8>>(),
    );
}

fn key_share_entry(r: &mut Reader<'_>) -> Result<(u16, Vec<u8>), Error> {
    let g = r.u16()?;
    let k = r.vec16()?;
    if k.is_empty() {
        return Err(Error::decode("empty key share"));
    }
    Ok((g, k.to_vec()))
}

impl Extensions {
    pub(crate) fn parse(r: &mut Reader<'_>) -> Result<Extensions, Error> {
        Extensions::parse_kind(r, Kind::ClientHello, false)
    }

    /// Parses an extension block of `kind`; `required` blocks (DTLS 1.3 messages) carry the
    /// length even when empty, hello blocks may be absent.
    pub(crate) fn parse_kind(
        r: &mut Reader<'_>,
        kind: Kind,
        required: bool,
    ) -> Result<Extensions, Error> {
        let mut e = Extensions::default();
        if r.is_empty() && !required {
            return Ok(e);
        }
        let mut list = Reader::new(r.vec16()?);
        let mut seen = Vec::new();
        while !list.is_empty() {
            let ty = list.u16()?;
            let data = list.vec16()?;
            if seen.contains(&ty) {
                return Err(Error::decode("duplicate extension"));
            }
            if e.psk_offer.is_some() {
                return Err(Error::protocol(
                    AlertDescription::IllegalParameter,
                    "pre_shared_key is not the last extension",
                ));
            }
            seen.push(ty);
            let mut d = Reader::new(data);
            match ty {
                EXT_SUPPORTED_GROUPS => e.groups = Some(u16_list(data, 2)?),
                EXT_SIGNATURE_ALGORITHMS => e.signature_algorithms = Some(u16_list(data, 2)?),
                EXT_EC_POINT_FORMATS => {
                    let f = d.vec8()?;
                    d.finish()?;
                    if f.is_empty() {
                        return Err(Error::decode("empty ec_point_formats"));
                    }
                    e.point_formats = Some(f.to_vec());
                }
                EXT_USE_SRTP => {
                    let p = d.vec16()?;
                    let mki = d.vec8()?;
                    d.finish()?;
                    if p.len() % 2 != 0 || p.is_empty() {
                        return Err(Error::decode("bad use_srtp"));
                    }
                    let profiles = p
                        .chunks(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    e.srtp = Some((profiles, mki.to_vec()));
                }
                EXT_EXTENDED_MASTER_SECRET => {
                    if !data.is_empty() {
                        return Err(Error::decode("bad extended_master_secret"));
                    }
                    e.extended_master_secret = true;
                }
                EXT_RENEGOTIATION_INFO => {
                    let v = d.vec8()?;
                    d.finish()?;
                    e.renegotiation_info = Some(v.to_vec());
                }
                EXT_SESSION_TICKET => e.session_ticket = Some(data.to_vec()),
                EXT_CONNECTION_ID => {
                    let v = d.vec8()?;
                    d.finish()?;
                    e.connection_id = Some(v.to_vec());
                }
                EXT_SUPPORTED_VERSIONS => {
                    if kind == Kind::ClientHello {
                        let v = d.vec8()?;
                        if v.is_empty() || v.len() % 2 != 0 {
                            return Err(Error::decode("bad supported_versions"));
                        }
                        e.supported_versions = Some(
                            v.chunks(2)
                                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                                .collect(),
                        );
                    } else {
                        e.supported_versions = Some(vec![d.u16()?]);
                    }
                    d.finish()?;
                }
                EXT_KEY_SHARE => {
                    match kind {
                        Kind::ClientHello => {
                            let mut l = Reader::new(d.vec16()?);
                            let mut shares = Vec::new();
                            while !l.is_empty() {
                                let s = key_share_entry(&mut l)?;
                                if shares.iter().any(|(g, _)| *g == s.0) {
                                    return Err(Error::protocol(
                                        AlertDescription::IllegalParameter,
                                        "duplicate key share group",
                                    ));
                                }
                                shares.push(s);
                            }
                            e.key_shares = Some(shares);
                        }
                        Kind::HelloRetryRequest => e.hrr_group = Some(d.u16()?),
                        _ => e.key_shares = Some(vec![key_share_entry(&mut d)?]),
                    }
                    d.finish()?;
                }
                EXT_COOKIE => {
                    let c = d.vec16()?;
                    d.finish()?;
                    if c.is_empty() {
                        return Err(Error::decode("empty cookie"));
                    }
                    e.cookie = Some(c.to_vec());
                }
                EXT_PSK_KEY_EXCHANGE_MODES => {
                    let m = d.vec8()?;
                    d.finish()?;
                    if m.is_empty() {
                        return Err(Error::decode("empty psk_key_exchange_modes"));
                    }
                    e.psk_modes = Some(m.to_vec());
                }
                EXT_PRE_SHARED_KEY => {
                    if kind == Kind::ClientHello {
                        let mut ids = Reader::new(d.vec16()?);
                        let mut binders = Reader::new(d.vec16()?);
                        d.finish()?;
                        let mut offer = PskOffer::default();
                        while !ids.is_empty() {
                            let id = ids.vec16()?;
                            let age = ids.u32()?;
                            if id.is_empty() {
                                return Err(Error::decode("empty PSK identity"));
                            }
                            offer.identities.push((id.to_vec(), age));
                        }
                        while !binders.is_empty() {
                            let b = binders.vec8()?;
                            if b.len() < 32 {
                                return Err(Error::decode("short PSK binder"));
                            }
                            offer.binders.push(b.to_vec());
                        }
                        if offer.identities.is_empty()
                            || offer.identities.len() != offer.binders.len()
                        {
                            return Err(Error::decode("bad pre_shared_key"));
                        }
                        e.psk_offer = Some(offer);
                    } else {
                        e.psk_selected = Some(d.u16()?);
                        d.finish()?;
                    }
                }
                EXT_EARLY_DATA => e.early_data = true,
                other => e.unknown.push(other),
            }
        }
        Ok(e)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        self.encode_kind(out, Kind::ClientHello, false);
    }

    /// Encodes the block (`required`: with the length even when empty). `pre_shared_key`
    /// goes last, as RFC 8446 requires.
    pub(crate) fn encode_kind(&self, out: &mut Vec<u8>, kind: Kind, required: bool) {
        let mut body = Vec::new();
        let mut ext = |ty: u16, data: &[u8]| {
            put_u16(&mut body, ty);
            put_vec16(&mut body, data);
        };
        if let Some(g) = &self.groups {
            let mut d = Vec::new();
            put_u16_list16(&mut d, g);
            ext(EXT_SUPPORTED_GROUPS, &d);
        }
        if let Some(f) = &self.point_formats {
            let mut d = Vec::new();
            put_vec8(&mut d, f);
            ext(EXT_EC_POINT_FORMATS, &d);
        }
        if let Some(s) = &self.signature_algorithms {
            let mut d = Vec::new();
            put_u16_list16(&mut d, s);
            ext(EXT_SIGNATURE_ALGORITHMS, &d);
        }
        if let Some((p, mki)) = &self.srtp {
            let mut d = Vec::new();
            put_u16_list16(&mut d, p);
            put_vec8(&mut d, mki);
            ext(EXT_USE_SRTP, &d);
        }
        if self.extended_master_secret {
            ext(EXT_EXTENDED_MASTER_SECRET, &[]);
        }
        if let Some(t) = &self.session_ticket {
            ext(EXT_SESSION_TICKET, t);
        }
        if let Some(v) = &self.supported_versions {
            let mut d = Vec::new();
            if kind == Kind::ClientHello {
                put_vec8(
                    &mut d,
                    &v.iter().flat_map(|x| x.to_be_bytes()).collect::<Vec<u8>>(),
                );
            } else if let Some(x) = v.first() {
                put_u16(&mut d, *x);
            }
            ext(EXT_SUPPORTED_VERSIONS, &d);
        }
        if let Some(c) = &self.cookie {
            let mut d = Vec::new();
            put_vec16(&mut d, c);
            ext(EXT_COOKIE, &d);
        }
        if let Some(m) = &self.psk_modes {
            let mut d = Vec::new();
            put_vec8(&mut d, m);
            ext(EXT_PSK_KEY_EXCHANGE_MODES, &d);
        }
        if let Some(g) = self.hrr_group {
            ext(EXT_KEY_SHARE, &g.to_be_bytes());
        }
        if let Some(shares) = &self.key_shares {
            let mut entries = Vec::new();
            for (g, k) in shares {
                put_u16(&mut entries, *g);
                put_vec16(&mut entries, k);
            }
            if kind == Kind::ClientHello {
                let mut d = Vec::new();
                put_vec16(&mut d, &entries);
                ext(EXT_KEY_SHARE, &d);
            } else {
                ext(EXT_KEY_SHARE, &entries);
            }
        }
        if let Some(c) = &self.connection_id {
            let mut d = Vec::new();
            put_vec8(&mut d, c);
            ext(EXT_CONNECTION_ID, &d);
        }
        if let Some(r) = &self.renegotiation_info {
            let mut d = Vec::new();
            put_vec8(&mut d, r);
            ext(EXT_RENEGOTIATION_INFO, &d);
        }
        if self.early_data {
            ext(EXT_EARLY_DATA, &[]);
        }
        if let Some(i) = self.psk_selected {
            ext(EXT_PRE_SHARED_KEY, &i.to_be_bytes());
        }
        if let Some(o) = &self.psk_offer {
            let mut ids = Vec::new();
            for (id, age) in &o.identities {
                put_vec16(&mut ids, id);
                ids.extend_from_slice(&age.to_be_bytes());
            }
            let mut binders = Vec::new();
            for b in &o.binders {
                put_vec8(&mut binders, b);
            }
            let mut d = Vec::new();
            put_vec16(&mut d, &ids);
            put_vec16(&mut d, &binders);
            ext(EXT_PRE_SHARED_KEY, &d);
        }
        if !body.is_empty() || required {
            put_vec16(out, &body);
        }
    }
}

/// ClientHello (RFC 6347 §4.2.1 adds the cookie).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientHello {
    pub(crate) version: u16,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: Vec<u8>,
    pub(crate) cookie: Vec<u8>,
    pub(crate) cipher_suites: Vec<u16>,
    pub(crate) compression: Vec<u8>,
    pub(crate) extensions: Extensions,
}

fn random(r: &mut Reader<'_>) -> Result<[u8; 32], Error> {
    let mut a = [0u8; 32];
    a.copy_from_slice(r.bytes(32)?);
    Ok(a)
}

impl ClientHello {
    pub(crate) fn parse(body: &[u8]) -> Result<ClientHello, Error> {
        let mut r = Reader::new(body);
        let version = r.u16()?;
        let random = random(&mut r)?;
        let session_id = r.vec8()?.to_vec();
        let cookie = r.vec8()?.to_vec();
        let suites = r.vec16()?;
        let compression = r.vec8()?.to_vec();
        if session_id.len() > 32
            || suites.len() % 2 != 0
            || suites.is_empty()
            || compression.is_empty()
        {
            return Err(Error::decode("bad ClientHello"));
        }
        let extensions = Extensions::parse(&mut r)?;
        r.finish()?;
        Ok(ClientHello {
            version,
            random,
            session_id,
            cookie,
            cipher_suites: suites
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect(),
            compression,
            extensions,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u16(&mut out, self.version);
        out.extend_from_slice(&self.random);
        put_vec8(&mut out, &self.session_id);
        put_vec8(&mut out, &self.cookie);
        let suites: Vec<u8> = self
            .cipher_suites
            .iter()
            .flat_map(|s| s.to_be_bytes())
            .collect();
        put_vec16(&mut out, &suites);
        put_vec8(&mut out, &self.compression);
        self.extensions.encode(&mut out);
        out
    }
}

/// ServerHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerHello {
    pub(crate) version: u16,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: Vec<u8>,
    pub(crate) cipher_suite: u16,
    pub(crate) compression: u8,
    pub(crate) extensions: Extensions,
}

impl ServerHello {
    pub(crate) fn parse(body: &[u8]) -> Result<ServerHello, Error> {
        let mut r = Reader::new(body);
        let version = r.u16()?;
        let random = random(&mut r)?;
        let session_id = r.vec8()?.to_vec();
        let cipher_suite = r.u16()?;
        let compression = r.u8()?;
        if session_id.len() > 32 {
            return Err(Error::decode("bad ServerHello"));
        }
        let kind = if random == HRR_RANDOM {
            Kind::HelloRetryRequest
        } else {
            Kind::ServerHello
        };
        let extensions = Extensions::parse_kind(&mut r, kind, false)?;
        r.finish()?;
        Ok(ServerHello {
            version,
            random,
            session_id,
            cipher_suite,
            compression,
            extensions,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u16(&mut out, self.version);
        out.extend_from_slice(&self.random);
        put_vec8(&mut out, &self.session_id);
        put_u16(&mut out, self.cipher_suite);
        out.push(self.compression);
        let kind = if self.random == HRR_RANDOM {
            Kind::HelloRetryRequest
        } else {
            Kind::ServerHello
        };
        self.extensions.encode_kind(&mut out, kind, false);
        out
    }

    pub(crate) fn is_hrr(&self) -> bool {
        self.random == HRR_RANDOM
    }
}

/// HelloVerifyRequest: `server_version` and the cookie.
pub(crate) fn encode_hello_verify(cookie: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, crate::record::DTLS10);
    put_vec8(&mut out, cookie);
    out
}

pub(crate) fn parse_hello_verify(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(body);
    let _version = r.u16()?;
    let cookie = r.vec8()?;
    r.finish()?;
    if cookie.is_empty() {
        return Err(Error::protocol(
            AlertDescription::IllegalParameter,
            "empty cookie",
        ));
    }
    Ok(cookie.to_vec())
}

/// Certificate: a list of DER certificates.
pub(crate) fn encode_certificate(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for c in chain {
        crate::codec::put_vec24(&mut list, c);
    }
    let mut out = Vec::new();
    crate::codec::put_vec24(&mut out, &list);
    out
}

pub(crate) fn parse_certificate(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut r = Reader::new(body);
    let mut list = Reader::new(r.vec24()?);
    r.finish()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let c = list.vec24()?;
        if c.is_empty() {
            return Err(Error::decode("empty certificate"));
        }
        out.push(c.to_vec());
    }
    Ok(out)
}

/// ServerKeyExchange for ECDHE: the named-curve parameters (signed) and the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerKeyExchange {
    pub(crate) group: u16,
    pub(crate) public: Vec<u8>,
    pub(crate) scheme: u16,
    pub(crate) signature: Vec<u8>,
}

impl ServerKeyExchange {
    /// `ServerECDHParams` as signed: curve_type named_curve(3), group, public point.
    pub(crate) fn params(group: u16, public: &[u8]) -> Vec<u8> {
        let mut out = vec![3];
        put_u16(&mut out, group);
        put_vec8(&mut out, public);
        out
    }

    pub(crate) fn parse(body: &[u8]) -> Result<ServerKeyExchange, Error> {
        let mut r = Reader::new(body);
        if r.u8()? != 3 {
            return Err(Error::protocol(
                AlertDescription::HandshakeFailure,
                "not a named curve",
            ));
        }
        let group = r.u16()?;
        let public = r.vec8()?.to_vec();
        let scheme = r.u16()?;
        let signature = r.vec16()?.to_vec();
        r.finish()?;
        if public.is_empty() {
            return Err(Error::decode("empty ECDHE key"));
        }
        Ok(ServerKeyExchange {
            group,
            public,
            scheme,
            signature,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Self::params(self.group, &self.public);
        put_u16(&mut out, self.scheme);
        put_vec16(&mut out, &self.signature);
        out
    }
}

/// CertificateRequest (TLS 1.2): certificate types and signature schemes; no CA names.
pub(crate) fn encode_certificate_request(schemes: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    // rsa_sign(1), ecdsa_sign(64)
    put_vec8(&mut out, &[64, 1]);
    put_vec16(
        &mut out,
        &schemes
            .iter()
            .flat_map(|s| s.to_be_bytes())
            .collect::<Vec<u8>>(),
    );
    put_u16(&mut out, 0);
    out
}

/// The signature schemes of a CertificateRequest.
pub(crate) fn parse_certificate_request(body: &[u8]) -> Result<Vec<u16>, Error> {
    let mut r = Reader::new(body);
    let types = r.vec8()?;
    let schemes = r.vec16()?;
    let _cas = r.vec16()?;
    r.finish()?;
    if types.is_empty() || schemes.len() % 2 != 0 {
        return Err(Error::decode("bad CertificateRequest"));
    }
    Ok(schemes
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

/// CertificateVerify / the signature part of ServerKeyExchange: scheme and signature.
pub(crate) fn encode_signed(scheme: u16, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, scheme);
    put_vec16(&mut out, signature);
    out
}

pub(crate) fn parse_signed(body: &[u8]) -> Result<(u16, Vec<u8>), Error> {
    let mut r = Reader::new(body);
    let scheme = r.u16()?;
    let sig = r.vec16()?.to_vec();
    r.finish()?;
    Ok((scheme, sig))
}

/// ClientKeyExchange for ECDHE: the client's public point.
pub(crate) fn encode_client_key_exchange(public: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_vec8(&mut out, public);
    out
}

pub(crate) fn parse_client_key_exchange(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::new(body);
    let p = r.vec8()?;
    r.finish()?;
    if p.is_empty() {
        return Err(Error::decode("empty ECDHE key"));
    }
    Ok(p.to_vec())
}

/// The TLS 1.3-style transcript form of a message: type and 24-bit length, no DTLS fields
/// (RFC 9147 §5.2).
pub(crate) fn transcript13(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    put_u24(&mut out, body.len());
    out.extend_from_slice(body);
    out
}

/// DTLS 1.2 NewSessionTicket (RFC 5077 §3.3): lifetime hint and ticket.
pub(crate) fn encode_ticket12(lifetime: u32, ticket: &[u8]) -> Vec<u8> {
    let mut out = lifetime.to_be_bytes().to_vec();
    put_vec16(&mut out, ticket);
    out
}

pub(crate) fn parse_ticket12(body: &[u8]) -> Result<(u32, Vec<u8>), Error> {
    let mut r = Reader::new(body);
    let lifetime = r.u32()?;
    let t = r.vec16()?;
    r.finish()?;
    Ok((lifetime, t.to_vec()))
}

/// DTLS 1.3 NewSessionTicket (RFC 8446 §4.6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ticket13 {
    pub(crate) lifetime: u32,
    pub(crate) age_add: u32,
    pub(crate) nonce: Vec<u8>,
    pub(crate) ticket: Vec<u8>,
}

impl Ticket13 {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = self.lifetime.to_be_bytes().to_vec();
        out.extend_from_slice(&self.age_add.to_be_bytes());
        put_vec8(&mut out, &self.nonce);
        put_vec16(&mut out, &self.ticket);
        put_u16(&mut out, 0);
        out
    }

    pub(crate) fn parse(body: &[u8]) -> Result<Ticket13, Error> {
        let mut r = Reader::new(body);
        let lifetime = r.u32()?;
        let age_add = r.u32()?;
        let nonce = r.vec8()?.to_vec();
        let ticket = r.vec16()?.to_vec();
        let _ = Extensions::parse_kind(&mut r, Kind::NewSessionTicket, true)?;
        r.finish()?;
        if ticket.is_empty() {
            return Err(Error::decode("empty ticket"));
        }
        Ok(Ticket13 {
            lifetime,
            age_add,
            nonce,
            ticket,
        })
    }
}

/// DTLS 1.3 Certificate: request context and the DER chain (per-entry extensions empty).
pub(crate) fn encode_certificate13(context: &[u8], chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for c in chain {
        crate::codec::put_vec24(&mut list, c);
        put_u16(&mut list, 0);
    }
    let mut out = Vec::new();
    put_vec8(&mut out, context);
    crate::codec::put_vec24(&mut out, &list);
    out
}

pub(crate) fn parse_certificate13(body: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), Error> {
    let mut r = Reader::new(body);
    let context = r.vec8()?.to_vec();
    let mut list = Reader::new(r.vec24()?);
    r.finish()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let c = list.vec24()?;
        let _exts = list.vec16()?;
        if c.is_empty() {
            return Err(Error::decode("empty certificate"));
        }
        out.push(c.to_vec());
    }
    Ok((context, out))
}

/// DTLS 1.3 CertificateRequest: context and extensions (signature_algorithms).
pub(crate) fn encode_certificate_request13(context: &[u8], schemes: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    put_vec8(&mut out, context);
    Extensions {
        signature_algorithms: Some(schemes.to_vec()),
        ..Extensions::default()
    }
    .encode_kind(&mut out, Kind::CertificateRequest, true);
    out
}

pub(crate) fn parse_certificate_request13(body: &[u8]) -> Result<(Vec<u8>, Vec<u16>), Error> {
    let mut r = Reader::new(body);
    let context = r.vec8()?.to_vec();
    let e = Extensions::parse_kind(&mut r, Kind::CertificateRequest, true)?;
    r.finish()?;
    let schemes = e.signature_algorithms.ok_or_else(|| {
        Error::protocol(
            AlertDescription::MissingExtension,
            "CertificateRequest without signature_algorithms",
        )
    })?;
    Ok((context, schemes))
}

pub(crate) fn encode_encrypted_extensions(e: &Extensions) -> Vec<u8> {
    let mut out = Vec::new();
    e.encode_kind(&mut out, Kind::EncryptedExtensions, true);
    out
}

pub(crate) fn parse_encrypted_extensions(body: &[u8]) -> Result<Extensions, Error> {
    let mut r = Reader::new(body);
    let e = Extensions::parse_kind(&mut r, Kind::EncryptedExtensions, true)?;
    r.finish()?;
    Ok(e)
}

/// KeyUpdate: `update_requested`.
pub(crate) fn parse_key_update(body: &[u8]) -> Result<bool, Error> {
    match body {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(Error::protocol(
            AlertDescription::IllegalParameter,
            "bad KeyUpdate",
        )),
    }
}

/// An ACK record body (RFC 9147 §7): record numbers as (epoch, sequence number).
pub(crate) fn encode_ack(records: &[(u64, u64)]) -> Vec<u8> {
    let mut list = Vec::with_capacity(records.len() * 16);
    for (e, s) in records {
        list.extend_from_slice(&e.to_be_bytes());
        list.extend_from_slice(&s.to_be_bytes());
    }
    let mut out = Vec::new();
    put_vec16(&mut out, &list);
    out
}

pub(crate) fn parse_ack(body: &[u8]) -> Result<Vec<(u64, u64)>, Error> {
    let mut r = Reader::new(body);
    let mut list = Reader::new(r.vec16()?);
    r.finish()?;
    let mut out = Vec::new();
    while !list.is_empty() {
        out.push((list.u64()?, list.u64()?));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let ch = ClientHello {
            version: 0xfefd,
            random: [7; 32],
            session_id: vec![],
            cookie: vec![1, 2, 3],
            cipher_suites: vec![0xc02b, 0xc02f],
            compression: vec![0],
            extensions: Extensions {
                groups: Some(vec![29, 23]),
                point_formats: Some(vec![0]),
                signature_algorithms: Some(vec![0x0403]),
                srtp: Some((vec![7, 1], vec![])),
                extended_master_secret: true,
                renegotiation_info: Some(vec![]),
                ..Extensions::default()
            },
        };
        assert_eq!(ClientHello::parse(&ch.encode()).unwrap(), ch);
        let sh = ServerHello {
            version: 0xfefd,
            random: [1; 32],
            session_id: vec![9; 32],
            cipher_suite: 0xc02b,
            compression: 0,
            extensions: Extensions::default(),
        };
        assert_eq!(ServerHello::parse(&sh.encode()).unwrap(), sh);
        let mut dup = ch.encode();
        // Duplicate an extension: append another extended_master_secret.
        let n = dup.len();
        dup.extend_from_slice(&[0, 23, 0, 0]);
        let ext_len_pos = n - ch.extensions_len() - 2;
        let l = u16::from_be_bytes([dup[ext_len_pos], dup[ext_len_pos + 1]]) + 4;
        dup[ext_len_pos..ext_len_pos + 2].copy_from_slice(&l.to_be_bytes());
        assert!(ClientHello::parse(&dup).is_err());
    }

    impl ClientHello {
        fn extensions_len(&self) -> usize {
            let mut v = Vec::new();
            self.extensions.encode(&mut v);
            v.len() - 2
        }
    }

    #[test]
    fn reassembly() {
        let body: Vec<u8> = (0..100).collect();
        let frag = |o: usize, l: usize| Fragment {
            msg_type: CERTIFICATE,
            length: 100,
            seq: 3,
            offset: o,
            body: &body[o..o + l],
        };
        let mut p = Partial::new(&frag(0, 10));
        p.add(&frag(50, 50));
        assert!(!p.is_complete());
        p.add(&frag(0, 30));
        p.add(&frag(20, 20));
        assert!(!p.is_complete());
        p.add(&frag(40, 10));
        assert!(p.is_complete());
        assert_eq!(p.into_message(), (CERTIFICATE, body.clone()));
        // Out of order: the tail first.
        let mut p = Partial::new(&frag(90, 10));
        p.add(&frag(90, 10));
        p.add(&frag(0, 90));
        assert!(p.is_complete());
        assert_eq!(p.into_message(), (CERTIFICATE, body.clone()));
        // An empty message is complete at once.
        let empty = Fragment {
            msg_type: CERTIFICATE,
            length: 0,
            seq: 1,
            offset: 0,
            body: &[],
        };
        assert_eq!(Partial::new(&empty).into_message(), (CERTIFICATE, vec![]));
        let enc = encode_fragment(CERTIFICATE, 3, 100, 10, &body[10..20]);
        let f = parse_fragments(&enc).unwrap();
        assert_eq!(f, vec![frag(10, 10)]);
        // Offset past the end.
        let enc = encode_fragment(CERTIFICATE, 3, 5, 10, &body[10..20]);
        assert!(parse_fragments(&enc).is_err());
    }

    /// A fragment claiming the largest message allocates what it carries, not the claim.
    #[test]
    fn reassembly_grows_with_data() {
        let small = [7u8; 10];
        let f = Fragment {
            msg_type: CERTIFICATE,
            length: MAX_MESSAGE,
            seq: 0,
            offset: 0,
            body: &small,
        };
        let mut p = Partial::new(&f);
        assert_eq!(p.allocated(), 0);
        p.add(&f);
        assert!(p.allocated() < 1024, "{}", p.allocated());
        assert!(!p.is_complete());
    }

    #[test]
    fn messages_roundtrip() {
        let chain = vec![vec![1, 2, 3], vec![4]];
        assert_eq!(
            parse_certificate(&encode_certificate(&chain)).unwrap(),
            chain
        );
        assert_eq!(
            parse_certificate(&encode_certificate(&[])).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        let ske = ServerKeyExchange {
            group: 29,
            public: vec![5; 32],
            scheme: 0x0403,
            signature: vec![6; 70],
        };
        assert_eq!(ServerKeyExchange::parse(&ske.encode()).unwrap(), ske);
        assert_eq!(
            parse_certificate_request(&encode_certificate_request(&[0x0403])).unwrap(),
            vec![0x0403]
        );
        assert_eq!(
            parse_signed(&encode_signed(0x0807, b"sig")).unwrap(),
            (0x0807, b"sig".to_vec())
        );
        assert_eq!(
            parse_client_key_exchange(&encode_client_key_exchange(b"pt")).unwrap(),
            b"pt"
        );
        assert_eq!(
            parse_hello_verify(&encode_hello_verify(b"ck")).unwrap(),
            b"ck"
        );
        assert!(parse_hello_verify(&encode_hello_verify(b"")).is_err());
    }
}
