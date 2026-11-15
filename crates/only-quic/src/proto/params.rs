//! Transport parameters (RFC 9000 section 18, RFC 9221 max_datagram_frame_size).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use super::cid::{ConnectionId, ResetToken};
use super::coding::{Reader, put_varint, varint_len};
use super::frame::{TransportError, code};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParams {
    pub original_dcid: Option<ConnectionId>,
    /// Milliseconds; 0 = none.
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<ResetToken>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    /// Milliseconds.
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub active_connection_id_limit: u64,
    pub initial_scid: Option<ConnectionId>,
    pub retry_scid: Option<ConnectionId>,
    /// 0 = datagrams not accepted.
    pub max_datagram_frame_size: u64,
    /// The address the server would rather be reached at (RFC 9000 section 9.6).
    pub preferred_address: Option<PreferredAddress>,
    /// version_information (RFC 9368 section 3): the chosen version, then the available ones.
    pub version_info: Option<(u32, Vec<u32>)>,
}

/// The preferred_address transport parameter: an IPv4 and/or an IPv6 address, the connection
/// ID (sequence number 1) to use there and its stateless reset token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferredAddress {
    pub v4: Option<SocketAddrV4>,
    pub v6: Option<SocketAddrV6>,
    pub cid: ConnectionId,
    pub token: ResetToken,
}

impl PreferredAddress {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(41 + self.cid.len());
        let v4 = self
            .v4
            .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        out.extend_from_slice(&v4.ip().octets());
        out.extend_from_slice(&v4.port().to_be_bytes());
        let v6 = self
            .v6
            .unwrap_or(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        out.extend_from_slice(&v6.ip().octets());
        out.extend_from_slice(&v6.port().to_be_bytes());
        out.push(self.cid.len() as u8);
        out.extend_from_slice(&self.cid);
        out.extend_from_slice(&self.token);
        out
    }

    fn decode(val: &[u8]) -> Option<PreferredAddress> {
        let mut r = Reader::new(val);
        let ip4: [u8; 4] = r.bytes(4)?.try_into().ok()?;
        let p4 = r.u16()?;
        let ip6: [u8; 16] = r.bytes(16)?.try_into().ok()?;
        let p6 = r.u16()?;
        let n = usize::from(r.u8()?);
        // A server with zero-length connection IDs cannot offer a preferred address.
        if n == 0 {
            return None;
        }
        let cid = ConnectionId::new(r.bytes(n)?)?;
        let token: ResetToken = r.bytes(16)?.try_into().ok()?;
        if !r.is_empty() {
            return None;
        }
        // An all-zero address and port: that family is not offered.
        let v4 = (ip4 != [0; 4] || p4 != 0).then(|| SocketAddrV4::new(Ipv4Addr::from(ip4), p4));
        let v6 =
            (ip6 != [0; 16] || p6 != 0).then(|| SocketAddrV6::new(Ipv6Addr::from(ip6), p6, 0, 0));
        Some(PreferredAddress { v4, v6, cid, token })
    }
}

impl Default for TransportParams {
    /// The values that apply when a parameter is absent.
    fn default() -> TransportParams {
        TransportParams {
            original_dcid: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_connection_id_limit: 2,
            initial_scid: None,
            retry_scid: None,
            max_datagram_frame_size: 0,
            preferred_address: None,
            version_info: None,
        }
    }
}

mod id {
    pub const ORIGINAL_DCID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD: u64 = 0x03;
    pub const MAX_DATA: u64 = 0x04;
    pub const MSD_BIDI_LOCAL: u64 = 0x05;
    pub const MSD_BIDI_REMOTE: u64 = 0x06;
    pub const MSD_UNI: u64 = 0x07;
    pub const MAX_STREAMS_BIDI: u64 = 0x08;
    pub const MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXP: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_MIGRATION: u64 = 0x0c;
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
    pub const CID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SCID: u64 = 0x0f;
    pub const RETRY_SCID: u64 = 0x10;
    pub const VERSION_INFO: u64 = 0x11;
    pub const MAX_DATAGRAM: u64 = 0x20;
}

fn put_int(out: &mut Vec<u8>, id: u64, v: u64) {
    put_varint(out, id);
    put_varint(out, varint_len(v) as u64);
    put_varint(out, v);
}

fn put_bytes(out: &mut Vec<u8>, id: u64, b: &[u8]) {
    put_varint(out, id);
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn perr(reason: &str) -> TransportError {
    TransportError::new(code::TRANSPORT_PARAMETER_ERROR, reason)
}

impl TransportParams {
    /// Encodes the parameters that differ from the defaults (and the connection IDs).
    pub fn encode(&self) -> Vec<u8> {
        let d = TransportParams::default();
        let mut out = Vec::with_capacity(128);
        if let Some(c) = &self.original_dcid {
            put_bytes(&mut out, id::ORIGINAL_DCID, c);
        }
        let ints = [
            (
                id::MAX_IDLE_TIMEOUT,
                self.max_idle_timeout,
                d.max_idle_timeout,
            ),
            (
                id::MAX_UDP_PAYLOAD,
                self.max_udp_payload_size,
                d.max_udp_payload_size,
            ),
            (id::MAX_DATA, self.initial_max_data, 0),
            (
                id::MSD_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
                0,
            ),
            (
                id::MSD_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
                0,
            ),
            (id::MSD_UNI, self.initial_max_stream_data_uni, 0),
            (id::MAX_STREAMS_BIDI, self.initial_max_streams_bidi, 0),
            (id::MAX_STREAMS_UNI, self.initial_max_streams_uni, 0),
            (id::ACK_DELAY_EXP, self.ack_delay_exponent, 3),
            (id::MAX_ACK_DELAY, self.max_ack_delay, 25),
            (id::CID_LIMIT, self.active_connection_id_limit, 2),
            (id::MAX_DATAGRAM, self.max_datagram_frame_size, 0),
        ];
        for (i, v, def) in ints {
            if v != def {
                put_int(&mut out, i, v);
            }
        }
        if let Some(t) = &self.stateless_reset_token {
            put_bytes(&mut out, id::RESET_TOKEN, t);
        }
        if self.disable_active_migration {
            put_bytes(&mut out, id::DISABLE_MIGRATION, &[]);
        }
        if let Some(c) = &self.initial_scid {
            put_bytes(&mut out, id::INITIAL_SCID, c);
        }
        if let Some(c) = &self.retry_scid {
            put_bytes(&mut out, id::RETRY_SCID, c);
        }
        if let Some(a) = &self.preferred_address {
            put_bytes(&mut out, id::PREFERRED_ADDRESS, &a.encode());
        }
        if let Some((chosen, avail)) = &self.version_info {
            let mut v = chosen.to_be_bytes().to_vec();
            for a in avail {
                v.extend_from_slice(&a.to_be_bytes());
            }
            put_bytes(&mut out, id::VERSION_INFO, &v);
        }
        // A reserved parameter (31 * N + 27) exercises the peer's handling of unknown ones.
        put_bytes(&mut out, 31 * 5 + 27, &[]);
        out
    }

    /// Decodes and validates the peer's parameters; `from_server` enables the server-only
    /// ones.
    pub fn decode(b: &[u8], from_server: bool) -> Result<TransportParams, TransportError> {
        let mut p = TransportParams::default();
        let mut seen: Vec<u64> = Vec::new();
        let mut r = Reader::new(b);
        while !r.is_empty() {
            let pid = r.varint().ok_or_else(|| perr("truncated parameter id"))?;
            let val = r.vbytes().ok_or_else(|| perr("truncated parameter"))?;
            if pid <= id::MAX_DATAGRAM {
                if seen.contains(&pid) {
                    return Err(perr("duplicate transport parameter"));
                }
                seen.push(pid);
            }
            let int = || -> Result<u64, TransportError> {
                let mut vr = Reader::new(val);
                let v = vr.varint().ok_or_else(|| perr("bad integer parameter"))?;
                if !vr.is_empty() {
                    return Err(perr("bad integer parameter"));
                }
                Ok(v)
            };
            let cid = || ConnectionId::new(val).ok_or_else(|| perr("connection id too long"));
            let server_only = || {
                if from_server {
                    Ok(())
                } else {
                    Err(perr("server-only transport parameter from a client"))
                }
            };
            match pid {
                id::ORIGINAL_DCID => {
                    server_only()?;
                    p.original_dcid = Some(cid()?);
                }
                id::MAX_IDLE_TIMEOUT => p.max_idle_timeout = int()?,
                id::RESET_TOKEN => {
                    server_only()?;
                    p.stateless_reset_token =
                        Some(val.try_into().map_err(|_| perr("bad reset token"))?);
                }
                id::MAX_UDP_PAYLOAD => {
                    p.max_udp_payload_size = int()?;
                    if p.max_udp_payload_size < 1200 {
                        return Err(perr("max_udp_payload_size below 1200"));
                    }
                }
                id::MAX_DATA => p.initial_max_data = int()?,
                id::MSD_BIDI_LOCAL => p.initial_max_stream_data_bidi_local = int()?,
                id::MSD_BIDI_REMOTE => p.initial_max_stream_data_bidi_remote = int()?,
                id::MSD_UNI => p.initial_max_stream_data_uni = int()?,
                id::MAX_STREAMS_BIDI => {
                    p.initial_max_streams_bidi = int()?;
                    if p.initial_max_streams_bidi > 1 << 60 {
                        return Err(perr("initial_max_streams_bidi too large"));
                    }
                }
                id::MAX_STREAMS_UNI => {
                    p.initial_max_streams_uni = int()?;
                    if p.initial_max_streams_uni > 1 << 60 {
                        return Err(perr("initial_max_streams_uni too large"));
                    }
                }
                id::ACK_DELAY_EXP => {
                    p.ack_delay_exponent = int()?;
                    if p.ack_delay_exponent > 20 {
                        return Err(perr("ack_delay_exponent above 20"));
                    }
                }
                id::MAX_ACK_DELAY => {
                    p.max_ack_delay = int()?;
                    if p.max_ack_delay >= 1 << 14 {
                        return Err(perr("max_ack_delay too large"));
                    }
                }
                id::DISABLE_MIGRATION => {
                    if !val.is_empty() {
                        return Err(perr("disable_active_migration with a value"));
                    }
                    p.disable_active_migration = true;
                }
                id::PREFERRED_ADDRESS => {
                    server_only()?;
                    // IPv4 (6) + IPv6 (18) + CID length + CID + reset token (16).
                    p.preferred_address = Some(
                        PreferredAddress::decode(val)
                            .ok_or_else(|| perr("bad preferred_address"))?,
                    );
                }
                id::CID_LIMIT => {
                    p.active_connection_id_limit = int()?;
                    if p.active_connection_id_limit < 2 {
                        return Err(perr("active_connection_id_limit below 2"));
                    }
                }
                id::INITIAL_SCID => p.initial_scid = Some(cid()?),
                id::RETRY_SCID => {
                    server_only()?;
                    p.retry_scid = Some(cid()?);
                }
                id::MAX_DATAGRAM => p.max_datagram_frame_size = int()?,
                id::VERSION_INFO => {
                    let vi = (val.len() >= 4 && val.len() % 4 == 0)
                        .then(|| {
                            let mut words = val
                                .chunks(4)
                                .map(|w| u32::from_be_bytes([w[0], w[1], w[2], w[3]]));
                            let chosen = words.next()?;
                            Some((chosen, words.collect::<Vec<u32>>()))
                        })
                        .flatten()
                        .filter(|(c, a)| *c != 0 && !a.contains(&0));
                    p.version_info = Some(vi.ok_or_else(|| perr("bad version_information"))?);
                }
                _ => {}
            }
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = TransportParams {
            original_dcid: ConnectionId::new(&[1; 8]),
            max_idle_timeout: 30_000,
            stateless_reset_token: Some([5; 16]),
            max_udp_payload_size: 1472,
            initial_max_data: 1 << 20,
            initial_max_stream_data_bidi_local: 1,
            initial_max_stream_data_bidi_remote: 2,
            initial_max_stream_data_uni: 3,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 4,
            ack_delay_exponent: 2,
            max_ack_delay: 20,
            disable_active_migration: true,
            active_connection_id_limit: 8,
            initial_scid: ConnectionId::new(&[2; 8]),
            retry_scid: ConnectionId::new(&[3; 4]),
            max_datagram_frame_size: 65535,
            preferred_address: Some(PreferredAddress {
                v4: Some("192.0.2.1:4433".parse().unwrap()),
                v6: None,
                cid: ConnectionId::new(&[4; 8]).unwrap(),
                token: [6; 16],
            }),
            version_info: Some((1, vec![0x6b33_43cf, 1])),
        };
        let b = p.encode();
        assert_eq!(TransportParams::decode(&b, true).unwrap(), p);
        // Server-only parameters from a client are an error.
        assert!(TransportParams::decode(&b, false).is_err());
        let d = TransportParams::default();
        assert_eq!(TransportParams::decode(&d.encode(), false).unwrap(), d);
    }

    #[test]
    fn invalid_parameters() {
        let enc = |pid: u64, val: &[u8]| {
            let mut o = Vec::new();
            put_bytes(&mut o, pid, val);
            o
        };
        for (pid, val) in [
            (id::MAX_UDP_PAYLOAD, &[0x44, 0xaf][..]), // 1199
            (id::ACK_DELAY_EXP, &[21][..]),
            (id::MAX_ACK_DELAY, &[0x80, 0, 0x40, 0][..]),
            (id::CID_LIMIT, &[1][..]),
            (id::DISABLE_MIGRATION, &[1][..]),
            (id::RESET_TOKEN, &[1, 2][..]),
            (id::MAX_DATA, &[1, 2][..]),
            (id::INITIAL_SCID, &[0; 21][..]),
            (id::PREFERRED_ADDRESS, &[0; 10][..]),
            (id::MAX_STREAMS_BIDI, &[0xd0, 0, 0, 0, 0, 0, 0, 1][..]),
            (id::MAX_STREAMS_UNI, &[0xd0, 0, 0, 0, 0, 0, 0, 1][..]),
        ] {
            assert!(
                TransportParams::decode(&enc(pid, val), true).is_err(),
                "{pid}"
            );
        }
        let mut dup = enc(id::MAX_DATA, &[1]);
        dup.extend(enc(id::MAX_DATA, &[1]));
        assert!(TransportParams::decode(&dup, true).is_err());
        assert!(TransportParams::decode(&[1], true).is_err());
        assert!(TransportParams::decode(&[1, 5, 0], true).is_err());
        // Unknown parameters are ignored; a valid preferred_address is recorded.
        let mut pa = vec![0u8; 49];
        pa[22..24].copy_from_slice(&443u16.to_be_bytes());
        pa[24] = 8;
        let mut b = enc(0x1234, &[1, 2, 3]);
        b.extend(enc(id::PREFERRED_ADDRESS, &pa));
        let got = TransportParams::decode(&b, true)
            .unwrap()
            .preferred_address
            .unwrap();
        assert_eq!((got.v4, got.v6.map(|a| a.port())), (None, Some(443)));
        // A zero-length connection ID is not allowed there.
        pa.truncate(41);
        pa[24] = 0;
        assert!(TransportParams::decode(&enc(id::PREFERRED_ADDRESS, &pa), true).is_err());
    }
}
