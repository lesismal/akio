//! SCTP packet and chunk codec: the common header with its CRC-32C (RFC 9260 §3.1, appendix
//! A), the chunks this crate speaks (RFC 9260 §3.3, RFC 3758 §3.2, RFC 6525 §3-4, RFC 8260
//! §2.1 and §2.3.1, RFC 9653) and their parameters. Parsers are bounds-checked and return
//! `None` on anything malformed.

use only_crypto::crc::crc32c;

pub(crate) const COMMON_HEADER_LEN: usize = 12;
pub(crate) const CHUNK_HEADER_LEN: usize = 4;
pub(crate) const DATA_HEADER_LEN: usize = 16;
pub(crate) const IDATA_HEADER_LEN: usize = 20;

pub(crate) const CT_DATA: u8 = 0;
pub(crate) const CT_INIT: u8 = 1;
pub(crate) const CT_INIT_ACK: u8 = 2;
pub(crate) const CT_SACK: u8 = 3;
pub(crate) const CT_HEARTBEAT: u8 = 4;
pub(crate) const CT_HEARTBEAT_ACK: u8 = 5;
pub(crate) const CT_ABORT: u8 = 6;
pub(crate) const CT_SHUTDOWN: u8 = 7;
pub(crate) const CT_SHUTDOWN_ACK: u8 = 8;
pub(crate) const CT_ERROR: u8 = 9;
pub(crate) const CT_COOKIE_ECHO: u8 = 10;
pub(crate) const CT_COOKIE_ACK: u8 = 11;
pub(crate) const CT_SHUTDOWN_COMPLETE: u8 = 14;
pub(crate) const CT_IDATA: u8 = 64;
pub(crate) const CT_RECONFIG: u8 = 130;
pub(crate) const CT_FORWARD_TSN: u8 = 192;
pub(crate) const CT_IFORWARD_TSN: u8 = 194;

/// DATA chunk flags (RFC 9260 §3.3.1, RFC 7053).
pub(crate) const FLAG_END: u8 = 0x01;
pub(crate) const FLAG_BEGIN: u8 = 0x02;
pub(crate) const FLAG_UNORDERED: u8 = 0x04;
pub(crate) const FLAG_IMMEDIATE: u8 = 0x08;
/// The T bit of ABORT and SHUTDOWN COMPLETE: the verification tag is the sender's own.
pub(crate) const FLAG_T: u8 = 0x01;

const PARAM_HEARTBEAT_INFO: u16 = 1;
const PARAM_STATE_COOKIE: u16 = 7;
const PARAM_SUPPORTED_EXTENSIONS: u16 = 0x8008;
const PARAM_FORWARD_TSN_SUPPORTED: u16 = 0xC000;
/// Zero Checksum Acceptable (RFC 9653 §4).
const PARAM_ZERO_CHECKSUM: u16 = 0x8001;
/// Error detection method "SCTP over DTLS" (RFC 9653 §7).
pub(crate) const EDMID_DTLS: u32 = 1;

pub(crate) const PARAM_OUTGOING_RESET: u16 = 13;
pub(crate) const PARAM_INCOMING_RESET: u16 = 14;
pub(crate) const PARAM_SSN_TSN_RESET: u16 = 15;
pub(crate) const PARAM_RECONFIG_RESPONSE: u16 = 16;
pub(crate) const PARAM_ADD_OUTGOING: u16 = 17;
pub(crate) const PARAM_ADD_INCOMING: u16 = 18;

/// Re-configuration response results (RFC 6525 §4.4).
pub(crate) const RESULT_NOTHING_TO_DO: u32 = 0;
pub(crate) const RESULT_PERFORMED: u32 = 1;
pub(crate) const RESULT_DENIED: u32 = 2;
pub(crate) const RESULT_BAD_SEQUENCE: u32 = 5;
pub(crate) const RESULT_IN_PROGRESS: u32 = 6;

/// Error causes we send (RFC 9260 §3.3.10).
pub(crate) const CAUSE_UNRECOGNIZED_CHUNK: u16 = 6;
pub(crate) const CAUSE_COOKIE_WHILE_SHUTTING_DOWN: u16 = 10;
pub(crate) const CAUSE_PROTOCOL_VIOLATION: u16 = 13;
pub(crate) const CAUSE_USER_ABORT: u16 = 12;

pub(crate) fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// The SCTP common header (RFC 9260 §3.1) without the checksum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) vtag: u32,
}

/// One chunk as found in a packet: type, flags and the value after the 4-byte chunk header
/// (without padding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawChunk<'a> {
    pub(crate) typ: u8,
    pub(crate) flags: u8,
    pub(crate) value: &'a [u8],
}

/// Checks the CRC-32C and splits a packet into its header and chunks. A malformed chunk
/// length ends the chunk list (the chunks before it are kept). With `accept_zero` (we
/// announced Zero Checksum Acceptable, RFC 9653 §5.3) a checksum field of 0 is taken
/// without computing the CRC.
pub(crate) fn parse_packet(buf: &[u8], accept_zero: bool) -> Option<(Header, Vec<RawChunk<'_>>)> {
    if buf.len() < COMMON_HEADER_LEN {
        return None;
    }
    let want = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if !(accept_zero && want == 0) {
        let mut c = only_crypto::crc::Crc32c::new();
        c.update(&buf[..8]);
        c.update(&[0; 4]);
        c.update(&buf[12..]);
        if c.finalize() != want {
            return None;
        }
    }
    let header = Header {
        src_port: be16(buf, 0)?,
        dst_port: be16(buf, 2)?,
        vtag: be32(buf, 4)?,
    };
    let mut chunks = Vec::new();
    let mut at = COMMON_HEADER_LEN;
    while at + CHUNK_HEADER_LEN <= buf.len() {
        let typ = buf[at];
        let flags = buf[at + 1];
        let len = usize::from(be16(buf, at + 2)?);
        if len < CHUNK_HEADER_LEN || at + len > buf.len() {
            break;
        }
        chunks.push(RawChunk {
            typ,
            flags,
            value: &buf[at + CHUNK_HEADER_LEN..at + len],
        });
        at += pad4(len);
    }
    Some((header, chunks))
}

/// Builds one packet: the common header, then whole chunks, then the CRC-32C on `finish`.
#[derive(Debug)]
pub(crate) struct PacketWriter {
    buf: Vec<u8>,
    limit: usize,
}

impl PacketWriter {
    pub(crate) fn new(header: Header, limit: usize) -> PacketWriter {
        let mut buf = Vec::with_capacity(limit.min(1500));
        buf.extend_from_slice(&header.src_port.to_be_bytes());
        buf.extend_from_slice(&header.dst_port.to_be_bytes());
        buf.extend_from_slice(&header.vtag.to_be_bytes());
        buf.extend_from_slice(&[0; 4]);
        PacketWriter { buf, limit }
    }

    /// Bytes still available for chunks (padded).
    pub(crate) fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.buf.len())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.len() == COMMON_HEADER_LEN
    }

    /// Appends an encoded chunk (already padded or not; padding is added here).
    pub(crate) fn push_raw(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
        self.buf.resize(pad4(self.buf.len()), 0);
    }

    /// Appends a DATA chunk.
    pub(crate) fn push_data(&mut self, d: &Data<'_>) {
        let len = DATA_HEADER_LEN + d.payload.len();
        self.buf.push(CT_DATA);
        self.buf.push(d.flags);
        self.buf.extend_from_slice(&(len as u16).to_be_bytes());
        self.buf.extend_from_slice(&d.tsn.to_be_bytes());
        self.buf.extend_from_slice(&d.stream.to_be_bytes());
        self.buf.extend_from_slice(&d.ssn.to_be_bytes());
        self.buf.extend_from_slice(&d.ppid.to_be_bytes());
        self.buf.extend_from_slice(d.payload);
        self.buf.resize(pad4(self.buf.len()), 0);
    }

    /// Appends an I-DATA chunk (RFC 8260 §2.1).
    pub(crate) fn push_idata(&mut self, d: &IData<'_>) {
        let len = IDATA_HEADER_LEN + d.payload.len();
        self.buf.push(CT_IDATA);
        self.buf.push(d.flags);
        self.buf.extend_from_slice(&(len as u16).to_be_bytes());
        self.buf.extend_from_slice(&d.tsn.to_be_bytes());
        self.buf.extend_from_slice(&d.stream.to_be_bytes());
        self.buf.extend_from_slice(&[0, 0]);
        self.buf.extend_from_slice(&d.mid.to_be_bytes());
        // The first fragment carries the PPID, the others their FSN (the first one's is 0).
        let word = if d.flags & FLAG_BEGIN != 0 {
            d.ppid
        } else {
            d.fsn
        };
        self.buf.extend_from_slice(&word.to_be_bytes());
        self.buf.extend_from_slice(d.payload);
        self.buf.resize(pad4(self.buf.len()), 0);
    }

    /// The packet with its CRC-32C.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.finish_with(false)
    }

    /// The packet with its CRC-32C, or with a zero checksum field when `zero` (RFC 9653:
    /// the peer accepts it because DTLS protects the packet).
    pub(crate) fn finish_with(mut self, zero: bool) -> Vec<u8> {
        if !zero {
            let crc = crc32c(&self.buf);
            self.buf[8..12].copy_from_slice(&crc.to_le_bytes());
        }
        self.buf
    }
}

/// Encodes a chunk with the given value (no padding; [`PacketWriter::push_raw`] pads).
pub(crate) fn chunk(typ: u8, flags: u8, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CHUNK_HEADER_LEN + value.len());
    v.push(typ);
    v.push(flags);
    v.extend_from_slice(&((CHUNK_HEADER_LEN + value.len()) as u16).to_be_bytes());
    v.extend_from_slice(value);
    v
}

fn put_param(out: &mut Vec<u8>, typ: u16, value: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    out.extend_from_slice(value);
    out.resize(pad4(out.len()), 0);
}

/// Iterates over TLV parameters (RFC 9260 §3.2.1); stops at the first malformed one.
pub(crate) fn params(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let typ = be16(b, 0)?;
        let len = usize::from(be16(b, 2)?);
        if len < 4 || len > b.len() {
            return None;
        }
        let value = &b[4..len];
        b = b.get(pad4(len)..).unwrap_or(&[]);
        Some((typ, value))
    })
}

/// A DATA chunk (RFC 9260 §3.3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Data<'a> {
    pub(crate) flags: u8,
    pub(crate) tsn: u32,
    pub(crate) stream: u16,
    pub(crate) ssn: u16,
    pub(crate) ppid: u32,
    pub(crate) payload: &'a [u8],
}

impl<'a> Data<'a> {
    pub(crate) fn parse(flags: u8, v: &'a [u8]) -> Option<Data<'a>> {
        Some(Data {
            flags,
            tsn: be32(v, 0)?,
            stream: be16(v, 4)?,
            ssn: be16(v, 6)?,
            ppid: be32(v, 8)?,
            payload: v.get(12..)?,
        })
    }
}

/// An I-DATA chunk (RFC 8260 §2.1): a DATA chunk with a 32-bit message identifier per stream
/// and a fragment sequence number, so that fragments of messages on different streams can be
/// interleaved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IData<'a> {
    pub(crate) flags: u8,
    pub(crate) tsn: u32,
    pub(crate) stream: u16,
    pub(crate) mid: u32,
    /// Only meaningful on the first fragment (B bit).
    pub(crate) ppid: u32,
    /// Fragment sequence number: 0 on the first fragment.
    pub(crate) fsn: u32,
    pub(crate) payload: &'a [u8],
}

impl<'a> IData<'a> {
    pub(crate) fn parse(flags: u8, v: &'a [u8]) -> Option<IData<'a>> {
        let word = be32(v, 12)?;
        let begin = flags & FLAG_BEGIN != 0;
        Some(IData {
            flags,
            tsn: be32(v, 0)?,
            stream: be16(v, 4)?,
            mid: be32(v, 8)?,
            ppid: if begin { word } else { 0 },
            fsn: if begin { 0 } else { word },
            payload: v.get(16..)?,
        })
    }
}

/// The fields of INIT and INIT ACK (RFC 9260 §3.3.2-3) that we use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Init {
    pub(crate) initiate_tag: u32,
    pub(crate) a_rwnd: u32,
    pub(crate) outbound_streams: u16,
    pub(crate) inbound_streams: u16,
    pub(crate) initial_tsn: u32,
    /// The state cookie (INIT ACK only).
    pub(crate) cookie: Option<Vec<u8>>,
    /// Forward-TSN (RFC 3758) offered: the 0xC000 parameter or 0xC0 in Supported Extensions.
    pub(crate) forward_tsn: bool,
    /// RE-CONFIG (RFC 6525) offered: 0x82 in Supported Extensions.
    pub(crate) reconfig: bool,
    /// I-DATA (RFC 8260) offered: 0x40 in Supported Extensions. We list I-FORWARD-TSN (0xC2)
    /// with it; with partial reliability it replaces FORWARD TSN (RFC 8260 §2.3).
    pub(crate) i_data: bool,
    /// Zero Checksum Acceptable (RFC 9653): the error detection method identifier.
    pub(crate) zero_checksum: Option<u32>,
}

impl Init {
    pub(crate) fn parse(v: &[u8]) -> Option<Init> {
        let mut init = Init {
            initiate_tag: be32(v, 0)?,
            a_rwnd: be32(v, 4)?,
            outbound_streams: be16(v, 8)?,
            inbound_streams: be16(v, 10)?,
            initial_tsn: be32(v, 12)?,
            ..Init::default()
        };
        for (typ, value) in params(v.get(16..)?) {
            match typ {
                PARAM_STATE_COOKIE => init.cookie = Some(value.to_vec()),
                PARAM_FORWARD_TSN_SUPPORTED => init.forward_tsn = true,
                PARAM_ZERO_CHECKSUM => init.zero_checksum = be32(value, 0),
                PARAM_SUPPORTED_EXTENSIONS => {
                    for &t in value {
                        match t {
                            CT_FORWARD_TSN => init.forward_tsn = true,
                            CT_RECONFIG => init.reconfig = true,
                            CT_IDATA => init.i_data = true,
                            _ => {}
                        }
                    }
                }
                // RFC 9260 §3.2.1: upper bits 00 / 01 mean "stop processing parameters".
                t if t & 0x8000 == 0 && !matches!(t, 5 | 6 | 9 | 11 | 12) => break,
                _ => {}
            }
        }
        Some(init)
    }

    /// The whole INIT (or INIT ACK, when `ack`) chunk.
    pub(crate) fn encode(&self, ack: bool) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&self.initiate_tag.to_be_bytes());
        v.extend_from_slice(&self.a_rwnd.to_be_bytes());
        v.extend_from_slice(&self.outbound_streams.to_be_bytes());
        v.extend_from_slice(&self.inbound_streams.to_be_bytes());
        v.extend_from_slice(&self.initial_tsn.to_be_bytes());
        if let Some(c) = &self.cookie {
            put_param(&mut v, PARAM_STATE_COOKIE, c);
        }
        let mut ext = Vec::new();
        if self.reconfig {
            ext.push(CT_RECONFIG);
        }
        if self.forward_tsn {
            ext.push(CT_FORWARD_TSN);
        }
        if self.i_data {
            ext.push(CT_IDATA);
            ext.push(CT_IFORWARD_TSN);
        }
        if !ext.is_empty() {
            put_param(&mut v, PARAM_SUPPORTED_EXTENSIONS, &ext);
        }
        if self.forward_tsn {
            put_param(&mut v, PARAM_FORWARD_TSN_SUPPORTED, &[]);
        }
        if let Some(edmid) = self.zero_checksum {
            put_param(&mut v, PARAM_ZERO_CHECKSUM, &edmid.to_be_bytes());
        }
        chunk(if ack { CT_INIT_ACK } else { CT_INIT }, 0, &v)
    }
}

/// A SACK chunk (RFC 9260 §3.3.4). Gap blocks are offsets from `cum_tsn`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sack {
    pub(crate) cum_tsn: u32,
    pub(crate) a_rwnd: u32,
    pub(crate) gaps: Vec<(u16, u16)>,
    pub(crate) dups: Vec<u32>,
}

impl Sack {
    pub(crate) fn parse(v: &[u8]) -> Option<Sack> {
        let cum_tsn = be32(v, 0)?;
        let a_rwnd = be32(v, 4)?;
        let ngaps = usize::from(be16(v, 8)?);
        let ndups = usize::from(be16(v, 10)?);
        if v.len() < 12 + 4 * ngaps + 4 * ndups {
            return None;
        }
        let mut gaps = Vec::with_capacity(ngaps);
        for i in 0..ngaps {
            gaps.push((be16(v, 12 + 4 * i)?, be16(v, 14 + 4 * i)?));
        }
        let mut dups = Vec::with_capacity(ndups);
        for i in 0..ndups {
            dups.push(be32(v, 12 + 4 * ngaps + 4 * i)?);
        }
        Some(Sack {
            cum_tsn,
            a_rwnd,
            gaps,
            dups,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12 + 4 * (self.gaps.len() + self.dups.len()));
        v.extend_from_slice(&self.cum_tsn.to_be_bytes());
        v.extend_from_slice(&self.a_rwnd.to_be_bytes());
        v.extend_from_slice(&(self.gaps.len() as u16).to_be_bytes());
        v.extend_from_slice(&(self.dups.len() as u16).to_be_bytes());
        for &(s, e) in &self.gaps {
            v.extend_from_slice(&s.to_be_bytes());
            v.extend_from_slice(&e.to_be_bytes());
        }
        for d in &self.dups {
            v.extend_from_slice(&d.to_be_bytes());
        }
        chunk(CT_SACK, 0, &v)
    }
}

/// A FORWARD TSN chunk (RFC 3758 §3.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ForwardTsn {
    pub(crate) new_cum_tsn: u32,
    pub(crate) streams: Vec<(u16, u16)>,
}

impl ForwardTsn {
    pub(crate) fn parse(v: &[u8]) -> Option<ForwardTsn> {
        let new_cum_tsn = be32(v, 0)?;
        let rest = v.get(4..)?;
        let streams = rest
            .chunks_exact(4)
            .map(|c| {
                (
                    u16::from_be_bytes([c[0], c[1]]),
                    u16::from_be_bytes([c[2], c[3]]),
                )
            })
            .collect();
        Some(ForwardTsn {
            new_cum_tsn,
            streams,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 4 * self.streams.len());
        v.extend_from_slice(&self.new_cum_tsn.to_be_bytes());
        for &(s, n) in &self.streams {
            v.extend_from_slice(&s.to_be_bytes());
            v.extend_from_slice(&n.to_be_bytes());
        }
        chunk(CT_FORWARD_TSN, 0, &v)
    }
}

/// An I-FORWARD-TSN chunk (RFC 8260 §2.3.1): the new cumulative TSN and, per stream and
/// ordered / unordered kind, the message identifier skipped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct IForwardTsn {
    pub(crate) new_cum_tsn: u32,
    /// (stream, unordered, MID).
    pub(crate) streams: Vec<(u16, bool, u32)>,
}

impl IForwardTsn {
    pub(crate) fn parse(v: &[u8]) -> Option<IForwardTsn> {
        let new_cum_tsn = be32(v, 0)?;
        let streams = v
            .get(4..)?
            .chunks_exact(8)
            .map(|c| {
                (
                    u16::from_be_bytes([c[0], c[1]]),
                    c[3] & 1 != 0,
                    u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                )
            })
            .collect();
        Some(IForwardTsn {
            new_cum_tsn,
            streams,
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 8 * self.streams.len());
        v.extend_from_slice(&self.new_cum_tsn.to_be_bytes());
        for &(s, u, mid) in &self.streams {
            v.extend_from_slice(&s.to_be_bytes());
            v.extend_from_slice(&[0, u8::from(u)]);
            v.extend_from_slice(&mid.to_be_bytes());
        }
        chunk(CT_IFORWARD_TSN, 0, &v)
    }
}

/// One RE-CONFIG parameter (RFC 6525 §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReconfigParam {
    /// Outgoing SSN Reset Request (13).
    OutgoingReset {
        req_seq: u32,
        resp_seq: u32,
        last_tsn: u32,
        streams: Vec<u16>,
    },
    /// Incoming SSN Reset Request (14): the peer asks us to reset our outgoing streams.
    IncomingReset { req_seq: u32, streams: Vec<u16> },
    /// SSN/TSN Reset Request (15).
    SsnTsnReset { req_seq: u32 },
    /// Re-configuration Response (16); `tsns` (Sender's, Receiver's Next TSN) answer an
    /// SSN/TSN Reset Request.
    Response {
        resp_seq: u32,
        result: u32,
        tsns: Option<(u32, u32)>,
    },
    /// An Add Outgoing / Incoming Streams Request (17, 18) with its request sequence number.
    OtherRequest { typ: u16, req_seq: u32 },
}

impl ReconfigParam {
    pub(crate) fn parse_all(v: &[u8]) -> Vec<ReconfigParam> {
        let mut out = Vec::new();
        for (typ, p) in params(v) {
            let parsed = match typ {
                PARAM_OUTGOING_RESET => (|| {
                    Some(ReconfigParam::OutgoingReset {
                        req_seq: be32(p, 0)?,
                        resp_seq: be32(p, 4)?,
                        last_tsn: be32(p, 8)?,
                        streams: p
                            .get(12..)?
                            .chunks_exact(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]]))
                            .collect(),
                    })
                })(),
                PARAM_RECONFIG_RESPONSE => (|| {
                    Some(ReconfigParam::Response {
                        resp_seq: be32(p, 0)?,
                        result: be32(p, 4)?,
                        tsns: be32(p, 8).zip(be32(p, 12)),
                    })
                })(),
                PARAM_INCOMING_RESET => (|| {
                    Some(ReconfigParam::IncomingReset {
                        req_seq: be32(p, 0)?,
                        streams: p
                            .get(4..)?
                            .chunks_exact(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]]))
                            .collect(),
                    })
                })(),
                PARAM_SSN_TSN_RESET => {
                    be32(p, 0).map(|req_seq| ReconfigParam::SsnTsnReset { req_seq })
                }
                PARAM_ADD_OUTGOING | PARAM_ADD_INCOMING => {
                    be32(p, 0).map(|req_seq| ReconfigParam::OtherRequest { typ, req_seq })
                }
                _ => None,
            };
            if let Some(x) = parsed {
                out.push(x);
            }
        }
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let mut v = Vec::new();
        let typ = match self {
            ReconfigParam::OutgoingReset {
                req_seq,
                resp_seq,
                last_tsn,
                streams,
            } => {
                v.extend_from_slice(&req_seq.to_be_bytes());
                v.extend_from_slice(&resp_seq.to_be_bytes());
                v.extend_from_slice(&last_tsn.to_be_bytes());
                for s in streams {
                    v.extend_from_slice(&s.to_be_bytes());
                }
                PARAM_OUTGOING_RESET
            }
            ReconfigParam::IncomingReset { req_seq, streams } => {
                v.extend_from_slice(&req_seq.to_be_bytes());
                for s in streams {
                    v.extend_from_slice(&s.to_be_bytes());
                }
                PARAM_INCOMING_RESET
            }
            ReconfigParam::SsnTsnReset { req_seq } => {
                v.extend_from_slice(&req_seq.to_be_bytes());
                PARAM_SSN_TSN_RESET
            }
            ReconfigParam::Response {
                resp_seq,
                result,
                tsns,
            } => {
                v.extend_from_slice(&resp_seq.to_be_bytes());
                v.extend_from_slice(&result.to_be_bytes());
                if let Some((s, r)) = tsns {
                    v.extend_from_slice(&s.to_be_bytes());
                    v.extend_from_slice(&r.to_be_bytes());
                }
                PARAM_RECONFIG_RESPONSE
            }
            ReconfigParam::OtherRequest { typ, req_seq } => {
                v.extend_from_slice(&req_seq.to_be_bytes());
                if matches!(*typ, PARAM_ADD_OUTGOING | PARAM_ADD_INCOMING) {
                    v.extend_from_slice(&[0; 4]);
                }
                *typ
            }
        };
        put_param(out, typ, &v);
    }

    /// A RE-CONFIG chunk carrying `params`.
    pub(crate) fn encode_chunk(params: &[ReconfigParam]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in params {
            p.encode_into(&mut v);
        }
        chunk(CT_RECONFIG, 0, &v)
    }
}

/// A HEARTBEAT ACK echoing the Heartbeat Info of a HEARTBEAT (RFC 9260 §3.3.6).
pub(crate) fn heartbeat_ack(heartbeat_value: &[u8]) -> Option<Vec<u8>> {
    let (typ, info) = params(heartbeat_value).next()?;
    if typ != PARAM_HEARTBEAT_INFO {
        return None;
    }
    let mut v = Vec::with_capacity(4 + info.len());
    put_param(&mut v, PARAM_HEARTBEAT_INFO, info);
    Some(chunk(CT_HEARTBEAT_ACK, 0, &v))
}

/// A HEARTBEAT carrying `info` as its Heartbeat Information (RFC 9260 §3.3.5).
pub(crate) fn heartbeat(info: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + info.len());
    put_param(&mut v, PARAM_HEARTBEAT_INFO, info);
    chunk(CT_HEARTBEAT, 0, &v)
}

/// The Heartbeat Information of a HEARTBEAT ACK.
pub(crate) fn parse_heartbeat_ack(v: &[u8]) -> Option<&[u8]> {
    let (typ, info) = params(v).next()?;
    (typ == PARAM_HEARTBEAT_INFO).then_some(info)
}

/// An error cause TLV (RFC 9260 §3.3.10).
pub(crate) fn cause(code: u16, info: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + info.len());
    put_param(&mut v, code, info);
    v
}

pub(crate) fn shutdown(cum_tsn: u32) -> Vec<u8> {
    chunk(CT_SHUTDOWN, 0, &cum_tsn.to_be_bytes())
}

pub(crate) fn parse_shutdown(v: &[u8]) -> Option<u32> {
    be32(v, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header {
            src_port: 5000,
            dst_port: 5000,
            vtag: 0x1234_5678,
        }
    }

    #[test]
    fn packet_round_trip_and_crc() {
        let mut w = PacketWriter::new(header(), 1200);
        w.push_raw(&chunk(CT_COOKIE_ACK, 0, &[]));
        w.push_data(&Data {
            flags: FLAG_BEGIN | FLAG_END,
            tsn: 7,
            stream: 1,
            ssn: 2,
            ppid: 51,
            payload: b"hey",
        });
        let pkt = w.finish();
        assert_eq!(pkt.len(), 12 + 4 + pad4(19));
        let (h, chunks) = parse_packet(&pkt, false).unwrap();
        assert_eq!(h, header());
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].typ, CT_COOKIE_ACK);
        let d = Data::parse(chunks[1].flags, chunks[1].value).unwrap();
        assert_eq!(
            (d.tsn, d.stream, d.ssn, d.ppid, d.payload),
            (7, 1, 2, 51, &b"hey"[..])
        );
        // Any flipped bit fails the checksum.
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 0x10;
            assert!(parse_packet(&bad, false).is_none(), "byte {i}");
        }
    }

    /// The checksum is stored little-endian: a COOKIE ACK packet captured from pion/sctp
    /// v1.12.0 (ports 5000/5000, tag 0x2a821de9) during the UDP interop run.
    #[test]
    fn checksum_little_endian_as_pion() {
        let (h, chunks) = parse_packet(&PION_COOKIE_ACK, false).unwrap();
        assert_eq!(h.vtag, 0x2a82_1de9);
        assert_eq!(chunks[0].typ, CT_COOKIE_ACK);
        let mut w = PacketWriter::new(h, 1200);
        w.push_raw(&chunk(CT_COOKIE_ACK, 0, &[]));
        assert_eq!(w.finish(), PION_COOKIE_ACK);
        // Big-endian would not verify.
        let mut be = PION_COOKIE_ACK;
        be[8..12].reverse();
        assert!(parse_packet(&be, false).is_none());
    }

    const PION_COOKIE_ACK: [u8; 16] = [
        0x13, 0x88, 0x13, 0x88, 0x2a, 0x82, 0x1d, 0xe9, 0x59, 0x73, 0xd2, 0xd9, 0x0b, 0x00, 0x00,
        0x04,
    ];

    #[test]
    fn init_round_trip() {
        let init = Init {
            initiate_tag: 0xdead_beef,
            a_rwnd: 1 << 20,
            outbound_streams: 65535,
            inbound_streams: 65535,
            initial_tsn: 42,
            cookie: Some(vec![1, 2, 3, 4, 5]),
            forward_tsn: true,
            reconfig: true,
            i_data: true,
            zero_checksum: Some(EDMID_DTLS),
        };
        let enc = init.encode(true);
        assert_eq!(enc[0], CT_INIT_ACK);
        let back = Init::parse(&enc[4..]).unwrap();
        assert_eq!(back, init);
        assert!(Init::parse(&enc[4..10]).is_none());
    }

    #[test]
    fn sack_forward_tsn_reconfig_round_trip() {
        let s = Sack {
            cum_tsn: 9,
            a_rwnd: 1000,
            gaps: vec![(2, 3), (5, 9)],
            dups: vec![4, 5],
        };
        assert_eq!(Sack::parse(&s.encode()[4..]).unwrap(), s);
        assert!(Sack::parse(&s.encode()[4..20]).is_none());
        let f = ForwardTsn {
            new_cum_tsn: 77,
            streams: vec![(1, 2), (3, 4)],
        };
        assert_eq!(ForwardTsn::parse(&f.encode()[4..]).unwrap(), f);
        let f = IForwardTsn {
            new_cum_tsn: 0xffff_fff0,
            streams: vec![(1, false, 7), (1, true, 0x1234_5678), (65535, true, 0)],
        };
        assert_eq!(f.encode()[0], CT_IFORWARD_TSN);
        assert_eq!(IForwardTsn::parse(&f.encode()[4..]).unwrap(), f);
        let ps = vec![
            ReconfigParam::OutgoingReset {
                req_seq: 1,
                resp_seq: 2,
                last_tsn: 3,
                streams: vec![4, 5, 6],
            },
            ReconfigParam::Response {
                resp_seq: 9,
                result: RESULT_PERFORMED,
                tsns: None,
            },
            ReconfigParam::IncomingReset {
                req_seq: 10,
                streams: vec![1, 3],
            },
            ReconfigParam::IncomingReset {
                req_seq: 12,
                streams: vec![],
            },
            ReconfigParam::SsnTsnReset { req_seq: 13 },
            ReconfigParam::Response {
                resp_seq: 14,
                result: RESULT_PERFORMED,
                tsns: Some((0xffff_0000, 7)),
            },
            ReconfigParam::OtherRequest {
                typ: PARAM_ADD_OUTGOING,
                req_seq: 11,
            },
        ];
        let enc = ReconfigParam::encode_chunk(&ps);
        assert_eq!(ReconfigParam::parse_all(&enc[4..]), ps);
    }

    #[test]
    fn idata_round_trip() {
        let mut w = PacketWriter::new(header(), 1200);
        for d in [
            IData {
                flags: FLAG_BEGIN | FLAG_UNORDERED,
                tsn: 7,
                stream: 3,
                mid: 0x0102_0304,
                ppid: 53,
                fsn: 0,
                payload: b"first",
            },
            IData {
                flags: FLAG_END,
                tsn: 8,
                stream: 3,
                mid: 9,
                ppid: 0,
                fsn: 0xdead_beef,
                payload: b"x",
            },
        ] {
            w.push_idata(&d);
        }
        let pkt = w.finish();
        let (_, chunks) = parse_packet(&pkt, false).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|c| c.typ == CT_IDATA));
        // RFC 8260 §2.1: the 16-byte I-DATA header after the chunk header, reserved field 0.
        assert_eq!(chunks[0].value.len(), 16 + 5);
        assert_eq!(&chunks[0].value[6..8], &[0, 0]);
        let a = IData::parse(chunks[0].flags, chunks[0].value).unwrap();
        assert_eq!(
            (a.tsn, a.stream, a.mid, a.ppid, a.fsn),
            (7, 3, 0x0102_0304, 53, 0)
        );
        assert_eq!(a.payload, b"first");
        let b = IData::parse(chunks[1].flags, chunks[1].value).unwrap();
        assert_eq!(
            (b.mid, b.ppid, b.fsn, b.payload),
            (9, 0, 0xdead_beef, &b"x"[..])
        );
        assert!(IData::parse(0, &chunks[1].value[..15]).is_none());
    }

    #[test]
    fn init_without_idata() {
        let init = Init {
            initiate_tag: 1,
            a_rwnd: 1,
            outbound_streams: 1,
            inbound_streams: 1,
            forward_tsn: true,
            reconfig: true,
            ..Init::default()
        };
        let enc = init.encode(false);
        assert!(!enc.contains(&CT_IDATA));
        assert!(!Init::parse(&enc[4..]).unwrap().i_data);
    }

    /// RFC 9653: a zero checksum field passes only when we accept it; anything else still
    /// needs the right CRC.
    #[test]
    fn zero_checksum() {
        let mut w = PacketWriter::new(header(), 1200);
        w.push_raw(&chunk(CT_COOKIE_ACK, 0, &[]));
        let pkt = w.finish_with(true);
        assert_eq!(&pkt[8..12], &[0; 4]);
        assert!(parse_packet(&pkt, false).is_none());
        let (h, chunks) = parse_packet(&pkt, true).unwrap();
        assert_eq!((h, chunks[0].typ), (header(), CT_COOKIE_ACK));
        let mut bad = pkt.clone();
        bad[8] = 1;
        assert!(parse_packet(&bad, true).is_none());
        let mut w = PacketWriter::new(header(), 1200);
        w.push_raw(&chunk(CT_COOKIE_ACK, 0, &[]));
        assert!(parse_packet(&w.finish(), true).is_some());
        // The INIT parameter: type 0x8001, length 8, EDMID 1.
        let init = Init {
            initiate_tag: 1,
            a_rwnd: 1,
            outbound_streams: 1,
            inbound_streams: 1,
            zero_checksum: Some(EDMID_DTLS),
            ..Init::default()
        };
        let enc = init.encode(false);
        assert_eq!(&enc[enc.len() - 8..], &[0x80, 0x01, 0, 8, 0, 0, 0, 1]);
        assert_eq!(Init::parse(&enc[4..]).unwrap().zero_checksum, Some(1));
    }

    #[test]
    fn heartbeat_round_trip() {
        let hb = heartbeat(b"0123456789abcdef");
        assert_eq!(hb[0], CT_HEARTBEAT);
        let ack = heartbeat_ack(&hb[4..]).unwrap();
        assert_eq!(
            parse_heartbeat_ack(&ack[4..]),
            Some(&b"0123456789abcdef"[..])
        );
        assert_eq!(parse_heartbeat_ack(&[0, 2, 0, 4]), None);
    }

    #[test]
    fn heartbeat_ack_echoes_info() {
        let mut v = Vec::new();
        put_param(&mut v, PARAM_HEARTBEAT_INFO, b"abcde");
        let ack = heartbeat_ack(&v).unwrap();
        assert_eq!(ack[0], CT_HEARTBEAT_ACK);
        assert_eq!(&ack[4..], &v[..]);
        assert!(heartbeat_ack(&[0, 2, 0, 4]).is_none());
    }

    #[test]
    fn garbage_never_panics() {
        for len in 0..64 {
            let b: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let _ = parse_packet(&b, false);
            let _ = Init::parse(&b);
            let _ = Sack::parse(&b);
            let _ = ForwardTsn::parse(&b);
            let _ = ReconfigParam::parse_all(&b);
            let _ = Data::parse(0, &b);
            let _ = IData::parse(0, &b);
            let _ = IData::parse(FLAG_BEGIN, &b);
            let _ = IForwardTsn::parse(&b);
            let _ = heartbeat_ack(&b);
            let _ = parse_heartbeat_ack(&b);
            let _ = parse_packet(&b, true);
        }
    }
}
