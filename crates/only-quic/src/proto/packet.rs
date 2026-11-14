//! Packet headers (RFC 9000 section 17): long and short headers, Version Negotiation, Retry,
//! packet number encoding (Appendix A), header protection (RFC 9001 section 5.4) and sealing.

use super::cid::{ConnectionId, MAX_CID_LEN};
use super::coding::{Reader, patch_varint2, put_varint};
use super::crypto::{HeaderKey, PacketKey, TAG_LEN};

/// QUIC version 1.
pub const VERSION_1: u32 = 1;

/// The smallest datagram that may carry a client's Initial packet.
pub const MIN_INITIAL_SIZE: usize = 1200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short,
    VersionNegotiation,
}

impl PacketType {
    pub fn is_long(self) -> bool {
        self != PacketType::Short
    }

    fn long_bits(self) -> u8 {
        match self {
            PacketType::Initial => 0,
            PacketType::ZeroRtt => 1,
            PacketType::Handshake => 2,
            _ => 3,
        }
    }
}

/// A parsed (still protected) packet header.
#[derive(Clone, Debug)]
pub struct Header<'a> {
    pub ty: PacketType,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    /// The Initial packet's token, or the Retry packet's.
    pub token: &'a [u8],
    /// Where the (protected) packet number starts.
    pub pn_offset: usize,
    /// Bytes of this packet in the datagram (the rest is further coalesced packets).
    pub len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Not a QUIC packet we can parse: drop it (and the rest of the datagram).
    Invalid,
    /// A long header of a version we do not speak: answer with Version Negotiation.
    UnsupportedVersion {
        dcid: ConnectionId,
        scid: ConnectionId,
    },
}

/// Parses the header of the packet at the start of `buf`; short headers carry a destination
/// connection ID of `local_cid_len` bytes.
pub fn parse_header(buf: &[u8], local_cid_len: usize) -> Result<Header<'_>, HeaderError> {
    let mut r = Reader::new(buf);
    let first = r.u8().ok_or(HeaderError::Invalid)?;
    if first & 0x80 == 0 {
        // Short header.
        if first & 0x40 == 0 {
            return Err(HeaderError::Invalid);
        }
        let dcid = r.bytes(local_cid_len).ok_or(HeaderError::Invalid)?;
        return Ok(Header {
            ty: PacketType::Short,
            version: VERSION_1,
            dcid: ConnectionId::new(dcid).ok_or(HeaderError::Invalid)?,
            scid: ConnectionId::default(),
            token: &[],
            pn_offset: r.pos(),
            len: buf.len(),
        });
    }
    let version = r.u32().ok_or(HeaderError::Invalid)?;
    let dl = usize::from(r.u8().ok_or(HeaderError::Invalid)?);
    let dcid = r.bytes(dl).ok_or(HeaderError::Invalid)?;
    let sl = usize::from(r.u8().ok_or(HeaderError::Invalid)?);
    let scid = r.bytes(sl).ok_or(HeaderError::Invalid)?;
    if dl > MAX_CID_LEN || sl > MAX_CID_LEN {
        return Err(HeaderError::Invalid);
    }
    let dcid = ConnectionId::new(dcid).ok_or(HeaderError::Invalid)?;
    let scid = ConnectionId::new(scid).ok_or(HeaderError::Invalid)?;
    if version == 0 {
        return Ok(Header {
            ty: PacketType::VersionNegotiation,
            version,
            dcid,
            scid,
            token: r.rest(),
            pn_offset: 0,
            len: buf.len(),
        });
    }
    if version != VERSION_1 {
        return Err(HeaderError::UnsupportedVersion { dcid, scid });
    }
    if first & 0x40 == 0 {
        return Err(HeaderError::Invalid);
    }
    let ty = match (first >> 4) & 3 {
        0 => PacketType::Initial,
        1 => PacketType::ZeroRtt,
        2 => PacketType::Handshake,
        _ => PacketType::Retry,
    };
    if ty == PacketType::Retry {
        let rest = r.rest();
        if rest.len() < TAG_LEN {
            return Err(HeaderError::Invalid);
        }
        return Ok(Header {
            ty,
            version,
            dcid,
            scid,
            token: &rest[..rest.len() - TAG_LEN],
            pn_offset: 0,
            len: buf.len(),
        });
    }
    let token = if ty == PacketType::Initial {
        r.vbytes().ok_or(HeaderError::Invalid)?
    } else {
        &[]
    };
    let length = r.varint().ok_or(HeaderError::Invalid)?;
    let pn_offset = r.pos();
    let len = usize::try_from(length)
        .ok()
        .and_then(|l| pn_offset.checked_add(l))
        .filter(|&l| l <= buf.len())
        .ok_or(HeaderError::Invalid)?;
    Ok(Header {
        ty,
        version,
        dcid,
        scid,
        token,
        pn_offset,
        len,
    })
}

/// The full packet number closest to the expected one (RFC 9000 Appendix A.3).
pub fn decode_pn(largest: Option<u64>, truncated: u64, pn_len: usize) -> u64 {
    let expected = largest.map_or(0, |l| l + 1);
    let win = 1u64 << (pn_len * 8);
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + hwin <= expected && candidate < (1 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

/// Bytes to encode `pn` with, given the largest packet number the peer acknowledged
/// (RFC 9000 Appendix A.2).
pub fn pn_len(pn: u64, largest_acked: Option<u64>) -> usize {
    let unacked = match largest_acked {
        Some(l) => pn.saturating_sub(l),
        None => pn + 1,
    };
    let range = unacked.saturating_mul(2);
    if range < 1 << 8 {
        1
    } else if range < 1 << 16 {
        2
    } else if range < 1 << 24 {
        3
    } else {
        4
    }
}

/// Removes header protection of the packet `pkt` (its bytes only) in place; returns the packet
/// number length and the truncated packet number. `None` if too short to sample.
pub fn unprotect_header(hk: &HeaderKey, pkt: &mut [u8], pn_offset: usize) -> Option<(usize, u64)> {
    let s = pn_offset + 4;
    let sample: [u8; 16] = pkt.get(s..s + 16)?.try_into().ok()?;
    let mask = hk.mask(&sample);
    let long = pkt[0] & 0x80 != 0;
    pkt[0] ^= mask[0] & if long { 0x0f } else { 0x1f };
    let n = usize::from(pkt[0] & 3) + 1;
    let mut pn = 0u64;
    for i in 0..n {
        pkt[pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(pkt[pn_offset + i]);
    }
    Some((n, pn))
}

/// Applies header protection to the packet starting at `start` in `buf`.
fn protect_header(hk: &HeaderKey, buf: &mut [u8], start: usize, pn_offset: usize, pn_len: usize) {
    let s = pn_offset + 4;
    let mut sample = [0u8; 16];
    sample.copy_from_slice(&buf[s..s + 16]);
    let mask = hk.mask(&sample);
    let long = buf[start] & 0x80 != 0;
    buf[start] ^= mask[0] & if long { 0x0f } else { 0x1f };
    for i in 0..pn_len {
        buf[pn_offset + i] ^= mask[1 + i];
    }
}

/// A packet being written into a buffer: header written, frames follow.
#[derive(Clone, Copy, Debug)]
pub struct PacketBuilder {
    pub start: usize,
    pub ty: PacketType,
    /// Offset of the 2-byte Length field (long headers).
    len_at: usize,
    pub pn_offset: usize,
    pub pn_len: usize,
    pub pn: u64,
}

impl PacketBuilder {
    /// Writes a long header (Initial with `token`, Handshake, 0-RTT).
    #[allow(clippy::too_many_arguments)]
    pub fn long(
        buf: &mut Vec<u8>,
        ty: PacketType,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        token: &[u8],
        pn: u64,
        pn_len: usize,
    ) -> PacketBuilder {
        let start = buf.len();
        buf.push(0xc0 | (ty.long_bits() << 4) | (pn_len as u8 - 1));
        buf.extend_from_slice(&VERSION_1.to_be_bytes());
        buf.push(dcid.len() as u8);
        buf.extend_from_slice(dcid);
        buf.push(scid.len() as u8);
        buf.extend_from_slice(scid);
        if ty == PacketType::Initial {
            put_varint(buf, token.len() as u64);
            buf.extend_from_slice(token);
        }
        let len_at = buf.len();
        buf.extend_from_slice(&[0x40, 0]);
        let pn_offset = buf.len();
        buf.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
        PacketBuilder {
            start,
            ty,
            len_at,
            pn_offset,
            pn_len,
            pn,
        }
    }

    /// Writes a short header.
    pub fn short(
        buf: &mut Vec<u8>,
        dcid: &ConnectionId,
        key_phase: bool,
        pn: u64,
        pn_len: usize,
    ) -> PacketBuilder {
        let start = buf.len();
        buf.push(0x40 | (u8::from(key_phase) << 2) | (pn_len as u8 - 1));
        buf.extend_from_slice(dcid);
        let pn_offset = buf.len();
        buf.extend_from_slice(&pn.to_be_bytes()[8 - pn_len..]);
        PacketBuilder {
            start,
            ty: PacketType::Short,
            len_at: 0,
            pn_offset,
            pn_len,
            pn,
        }
    }

    /// Header bytes before the payload.
    pub fn header_len(&self) -> usize {
        self.pn_offset + self.pn_len - self.start
    }

    /// Payload bytes the packet needs at least for header protection sampling.
    pub fn min_payload(&self) -> usize {
        4usize.saturating_sub(self.pn_len)
    }

    /// Encrypts the payload, appends the tag, fills the Length field and protects the header.
    pub fn finish(&self, buf: &mut Vec<u8>, packet: &PacketKey, header: &HeaderKey) {
        let payload_at = self.pn_offset + self.pn_len;
        if self.ty.is_long() {
            let len = buf.len() - self.pn_offset + TAG_LEN;
            patch_varint2(buf, self.len_at, len);
        }
        let (head, payload) = buf.split_at_mut(payload_at);
        let tag = packet.seal(self.pn, &head[self.start..], payload);
        buf.extend_from_slice(&tag);
        protect_header(header, buf, self.start, self.pn_offset, self.pn_len);
    }
}

/// A Version Negotiation packet answering a packet with `dcid`/`scid` (their IDs swapped).
pub fn version_negotiation(dcid: &ConnectionId, scid: &ConnectionId, random: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(0x80 | random);
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.extend_from_slice(&VERSION_1.to_be_bytes());
    // A reserved version (RFC 9000 section 15) so clients keep handling unknown entries.
    out.extend_from_slice(&0x1a2a_3a4au32.to_be_bytes());
    out
}

/// A Retry packet to a client whose Initial had `client_scid` / `odcid`.
pub fn retry(
    client_scid: &ConnectionId,
    new_scid: &ConnectionId,
    odcid: &ConnectionId,
    token: &[u8],
    random: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + token.len());
    out.push(0xf0 | (random & 0x0f));
    out.extend_from_slice(&VERSION_1.to_be_bytes());
    out.push(client_scid.len() as u8);
    out.extend_from_slice(client_scid);
    out.push(new_scid.len() as u8);
    out.extend_from_slice(new_scid);
    out.extend_from_slice(token);
    let tag = super::crypto::retry_tag(odcid, &out);
    out.extend_from_slice(&tag);
    out
}

#[cfg(test)]
mod tests {
    use super::super::crypto::initial_keys;
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn packet_numbers() {
        // RFC 9000 A.3.
        assert_eq!(decode_pn(Some(0xa82f30ea), 0x9b32, 2), 0xa82f9b32);
        assert_eq!(decode_pn(None, 0, 1), 0);
        assert_eq!(decode_pn(Some(0xff), 0x02, 1), 0x102);
        assert_eq!(decode_pn(Some(0x102), 0xff, 1), 0xff);
        // A.2.
        assert_eq!(pn_len(0xac5c02, Some(0xabe8b3)), 2);
        assert_eq!(pn_len(0xace8fe, Some(0xabe8b3)), 3);
        assert_eq!(pn_len(0, None), 1);
        assert_eq!(pn_len(1 << 30, None), 4);
    }

    #[test]
    fn rfc9001_client_initial_round_trip() {
        // A.2: the client's Initial (CRYPTO frame with the ClientHello, padded to 1162 bytes of
        // payload), header c300000001088394c8f03e5157080000449e00000002.
        let dcid = ConnectionId::new(&unhex("8394c8f03e515708")).unwrap();
        let k = initial_keys(&dcid, true);
        // Seal our own Initial and open it with the server's view of the keys.
        let mut buf = Vec::new();
        let b = PacketBuilder::long(
            &mut buf,
            PacketType::Initial,
            &dcid,
            &ConnectionId::default(),
            &[],
            2,
            4,
        );
        assert_eq!(buf, unhex("c300000001088394c8f03e5157080000400000000002"));
        buf.extend_from_slice(&[0x01; 1162]);
        b.finish(&mut buf, &k.local.packet, &k.local.header);
        let server = initial_keys(&dcid, false);
        let h = parse_header(&buf, 8).unwrap();
        assert_eq!(h.ty, PacketType::Initial);
        assert_eq!(h.len, buf.len());
        let mut pkt = buf.clone();
        let (n, tpn) = unprotect_header(&server.remote.header, &mut pkt, h.pn_offset).unwrap();
        assert_eq!((n, tpn), (4, 2));
        let (head, rest) = pkt.split_at_mut(h.pn_offset + n);
        let (ct, tag) = rest.split_at_mut(rest.len() - 16);
        assert!(server.remote.packet.open(2, head, ct, tag));
        assert!(ct.iter().all(|&b| b == 1));
    }

    #[test]
    fn rfc9001_server_initial_vector() {
        // A.3: the server's protected Initial, opened with the client's keys.
        let pkt = unhex(
            "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a
             5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3
             dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84
             022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4
             2158407dd074ee",
        );
        let dcid = ConnectionId::new(&unhex("8394c8f03e515708")).unwrap();
        let k = initial_keys(&dcid, true);
        let h = parse_header(&pkt, 8).unwrap();
        assert_eq!(h.ty, PacketType::Initial);
        assert_eq!(&h.scid[..], &unhex("f067a5502a4262b5")[..]);
        let mut p = pkt.clone();
        let (n, tpn) = unprotect_header(&k.remote.header, &mut p, h.pn_offset).unwrap();
        assert_eq!((n, tpn), (2, 1));
        let (head, rest) = p.split_at_mut(h.pn_offset + n);
        let (ct, tag) = rest[..h.len - h.pn_offset - n].split_at_mut(h.len - h.pn_offset - n - 16);
        assert!(k.remote.packet.open(1, head, ct, tag));
        // An ACK frame then a CRYPTO frame with the ServerHello.
        assert_eq!(&ct[..6], &unhex("02000000000600")[..6]);
    }

    #[test]
    fn rfc9001_chacha20_short_header_vector() {
        // A.5: a short header packet with ChaCha20-Poly1305, packet number 654360564.
        let secret = unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        static S: only_tls::quic::Suite = only_tls::quic::Suite {
            id: 0x1303,
            name: "TLS_CHACHA20_POLY1305_SHA256",
            tls12: None,
            aead: only_tls::quic::AeadAlg::ChaCha20Poly1305,
            hash: only_tls::quic::HashAlg::Sha256,
        };
        let k = super::super::crypto::DirKeys::from_secret(&S, &secret);
        let mut buf = Vec::new();
        let b = PacketBuilder::short(&mut buf, &ConnectionId::default(), false, 654_360_564, 3);
        assert_eq!(buf, unhex("4200bff4"));
        buf.push(0x01);
        b.finish(&mut buf, &k.packet, &k.header);
        assert_eq!(buf, unhex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));
        // And back.
        let h = parse_header(&buf, 0).unwrap();
        let mut p = buf.clone();
        let (n, tpn) = unprotect_header(&k.header, &mut p, h.pn_offset).unwrap();
        assert_eq!(decode_pn(Some(654_360_563), tpn, n), 654_360_564);
    }

    #[test]
    fn headers_parse_and_reject() {
        let d = ConnectionId::new(&[1; 8]).unwrap();
        let s = ConnectionId::new(&[2; 4]).unwrap();
        let vn = version_negotiation(&d, &s, 0x11);
        let h = parse_header(&vn, 8).unwrap();
        assert_eq!(h.ty, PacketType::VersionNegotiation);
        assert_eq!((h.dcid, h.scid), (s, d));
        assert_eq!(h.token.len(), 8);
        let r = retry(&s, &d, &d, b"tok", 3);
        let h = parse_header(&r, 8).unwrap();
        assert_eq!((h.ty, h.token), (PacketType::Retry, &b"tok"[..]));
        // Version 2 is unsupported here.
        let mut v2 = r.clone();
        v2[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());
        assert!(matches!(
            parse_header(&v2, 8),
            Err(HeaderError::UnsupportedVersion { .. })
        ));
        for bad in [&[][..], &[0x00][..], &[0x40, 1][..], &[0xc0, 0, 0, 0, 1, 30][..]] {
            assert_eq!(parse_header(bad, 8).unwrap_err(), HeaderError::Invalid);
        }
        // Length beyond the datagram.
        let mut buf = Vec::new();
        let b = PacketBuilder::long(&mut buf, PacketType::Handshake, &d, &s, &[], 0, 1);
        let _ = b;
        buf[b.pn_offset - 1] = 0x50;
        assert_eq!(parse_header(&buf, 8).unwrap_err(), HeaderError::Invalid);
        assert_eq!(b.header_len(), buf.len());
        assert_eq!(b.min_payload(), 3);
    }
}
