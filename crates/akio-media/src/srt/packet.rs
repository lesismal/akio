//! SRT packet formats (draft-sharabayko-srt-01 section 3): the header, the handshake with its
//! extensions, and loss lists.

pub(crate) const HEADER_SIZE: usize = 16;

pub(crate) const CTRL_HANDSHAKE: u16 = 0x0000;
pub(crate) const CTRL_KEEPALIVE: u16 = 0x0001;
pub(crate) const CTRL_ACK: u16 = 0x0002;
pub(crate) const CTRL_NAK: u16 = 0x0003;
pub(crate) const CTRL_SHUTDOWN: u16 = 0x0005;
pub(crate) const CTRL_ACKACK: u16 = 0x0006;
pub(crate) const CTRL_DROPREQ: u16 = 0x0007;
pub(crate) const CTRL_USER: u16 = 0x7fff;

pub(crate) const HS_CONCLUSION: u32 = 0xffff_ffff;
pub(crate) const HS_INDUCTION: u32 = 0x0000_0001;
pub(crate) const HS_DONE: u32 = 0xffff_fffd;
pub(crate) const HS_AGREEMENT: u32 = 0xffff_fffe;
pub(crate) const HS_WAVEAHAND: u32 = 0x0000_0000;
pub(crate) const HS_REJECT_BASE: u32 = 1000;

pub(crate) const EXT_HSREQ: u16 = 1;
pub(crate) const EXT_HSRSP: u16 = 2;
pub(crate) const EXT_KMREQ: u16 = 3;
pub(crate) const EXT_KMRSP: u16 = 4;
pub(crate) const EXT_SID: u16 = 5;

pub(crate) const EXT_FLAG_HSREQ: u16 = 0x0001;
pub(crate) const EXT_FLAG_KMREQ: u16 = 0x0002;
pub(crate) const EXT_FLAG_CONFIG: u16 = 0x0004;

/// The "SRT magic" an HSv5 listener puts in the extension field of its induction response.
pub(crate) const SRT_MAGIC: u16 = 0x4a17;

pub(crate) const FLAG_TSBPD_SND: u32 = 0x01;
pub(crate) const FLAG_TSBPD_RCV: u32 = 0x02;
pub(crate) const FLAG_CRYPT: u32 = 0x04;
pub(crate) const FLAG_TLPKTDROP: u32 = 0x08;
pub(crate) const FLAG_PERIODIC_NAK: u32 = 0x10;
pub(crate) const FLAG_REXMIT: u32 = 0x20;

/// SRT version 1.5.0.
pub(crate) const SRT_VERSION: u32 = 0x0001_0500;

pub(crate) const MAX_SEQ: u32 = 1 << 31;

/// `s + n` in the 31-bit sequence space.
pub(crate) fn seq_add(s: u32, n: i64) -> u32 {
    ((i64::from(s) + n) as u32) & (MAX_SEQ - 1)
}

/// `a - b` in the 31-bit sequence space, as a signed distance.
pub(crate) fn seq_diff(a: u32, b: u32) -> i64 {
    i64::from(((a.wrapping_sub(b)) << 1) as i32 >> 1)
}

// Data packet message field.
pub(crate) const PP_SOLO: u32 = 3 << 30;
pub(crate) const KK_SHIFT: u32 = 27;
pub(crate) const KK_MASK: u32 = 3 << KK_SHIFT;
pub(crate) const FLAG_REXMIT_PKT: u32 = 1 << 26;
pub(crate) const MSGNO_MASK: u32 = (1 << 26) - 1;

pub(crate) const KK_NONE: u8 = 0;
pub(crate) const KK_EVEN: u8 = 1;
pub(crate) const KK_ODD: u8 = 2;

/// A packet header (data or control).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Header {
    pub(crate) ctrl: bool,
    pub(crate) seq: u32,
    pub(crate) typ: u16,
    pub(crate) subtype: u16,
    pub(crate) info: u32,
    pub(crate) ts: u32,
    pub(crate) dst: u32,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

impl Header {
    pub(crate) fn parse(b: &[u8]) -> Option<Header> {
        if b.len() < HEADER_SIZE {
            return None;
        }
        let w0 = be32(b, 0);
        let ctrl = w0 & 0x8000_0000 != 0;
        Some(Header {
            ctrl,
            seq: if ctrl { 0 } else { w0 },
            typ: if ctrl {
                ((w0 >> 16) & 0x7fff) as u16
            } else {
                0
            },
            subtype: if ctrl { w0 as u16 } else { 0 },
            info: be32(b, 4),
            ts: be32(b, 8),
            dst: be32(b, 12),
        })
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        let w0 = if self.ctrl {
            0x8000_0000 | (u32::from(self.typ & 0x7fff) << 16) | u32::from(self.subtype)
        } else {
            self.seq & (MAX_SEQ - 1)
        };
        out.extend_from_slice(&w0.to_be_bytes());
        out.extend_from_slice(&self.info.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.dst.to_be_bytes());
    }
}

/// The HSREQ / HSRSP extension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct HsExt {
    pub(crate) version: u32,
    pub(crate) flags: u32,
    /// Receiver TSBPD delay, ms.
    pub(crate) rcv_delay: u16,
    /// Sender TSBPD delay, ms.
    pub(crate) snd_delay: u16,
}

pub(crate) const HANDSHAKE_SIZE: usize = 48;
pub(crate) const MAX_STREAM_ID: usize = 512;

/// A handshake control packet body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Handshake {
    pub(crate) version: u32,
    pub(crate) encryption: u16,
    pub(crate) ext_field: u16,
    pub(crate) isn: u32,
    pub(crate) mtu: u32,
    pub(crate) flow_window: u32,
    pub(crate) typ: u32,
    pub(crate) socket_id: u32,
    pub(crate) cookie: u32,
    pub(crate) peer_ip: [u8; 16],
    pub(crate) hs: Option<HsExt>,
    pub(crate) hs_rsp: bool,
    pub(crate) km: Option<Vec<u8>>,
    pub(crate) km_rsp: bool,
    pub(crate) stream_id: Option<String>,
}

impl Handshake {
    pub(crate) fn parse(b: &[u8]) -> Option<Handshake> {
        if b.len() < HANDSHAKE_SIZE {
            return None;
        }
        let mut hs = Handshake {
            version: be32(b, 0),
            encryption: be16(b, 4),
            ext_field: be16(b, 6),
            isn: be32(b, 8) & (MAX_SEQ - 1),
            mtu: be32(b, 12),
            flow_window: be32(b, 16),
            typ: be32(b, 20),
            socket_id: be32(b, 24),
            cookie: be32(b, 28),
            ..Handshake::default()
        };
        hs.peer_ip.copy_from_slice(&b[32..48]);
        if hs.version < 5 || hs.typ != HS_CONCLUSION {
            return Some(hs);
        }
        let mut rest = &b[HANDSHAKE_SIZE..];
        while rest.len() >= 4 {
            let typ = be16(rest, 0);
            let n = usize::from(be16(rest, 2)) * 4;
            let body = rest.get(4..4 + n)?;
            rest = &rest[4 + n..];
            match typ {
                EXT_HSREQ | EXT_HSRSP => {
                    if n < 12 {
                        return None;
                    }
                    hs.hs = Some(HsExt {
                        version: be32(body, 0),
                        flags: be32(body, 4),
                        rcv_delay: be16(body, 8),
                        snd_delay: be16(body, 10),
                    });
                    hs.hs_rsp = typ == EXT_HSRSP;
                }
                EXT_KMREQ | EXT_KMRSP => {
                    hs.km = Some(body.to_vec());
                    hs.km_rsp = typ == EXT_KMRSP;
                }
                EXT_SID => {
                    if n > MAX_STREAM_ID {
                        return None;
                    }
                    hs.stream_id = Some(String::from_utf8_lossy(&unswap_words(body)).into_owned());
                }
                _ => {}
            }
        }
        Some(hs)
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.encryption.to_be_bytes());
        out.extend_from_slice(&self.ext_field.to_be_bytes());
        out.extend_from_slice(&self.isn.to_be_bytes());
        out.extend_from_slice(&self.mtu.to_be_bytes());
        out.extend_from_slice(&self.flow_window.to_be_bytes());
        out.extend_from_slice(&self.typ.to_be_bytes());
        out.extend_from_slice(&self.socket_id.to_be_bytes());
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.peer_ip);
        if let Some(h) = &self.hs {
            let t = if self.hs_rsp { EXT_HSRSP } else { EXT_HSREQ };
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&3u16.to_be_bytes());
            out.extend_from_slice(&h.version.to_be_bytes());
            out.extend_from_slice(&h.flags.to_be_bytes());
            out.extend_from_slice(&h.rcv_delay.to_be_bytes());
            out.extend_from_slice(&h.snd_delay.to_be_bytes());
        }
        if let Some(km) = &self.km {
            let t = if self.km_rsp { EXT_KMRSP } else { EXT_KMREQ };
            out.extend_from_slice(&t.to_be_bytes());
            out.extend_from_slice(&(km.len().div_ceil(4) as u16).to_be_bytes());
            out.extend_from_slice(km);
            out.resize(out.len() + (4 - km.len() % 4) % 4, 0);
        }
        if let Some(sid) = &self.stream_id {
            let w = swap_words(sid.as_bytes());
            out.extend_from_slice(&EXT_SID.to_be_bytes());
            out.extend_from_slice(&((w.len() / 4) as u16).to_be_bytes());
            out.extend_from_slice(&w);
        }
    }
}

/// The stream ID travels as 32-bit little-endian words.
fn swap_words(b: &[u8]) -> Vec<u8> {
    let mut out = b.to_vec();
    out.resize(b.len().div_ceil(4) * 4, 0);
    for w in out.chunks_exact_mut(4) {
        w.reverse();
    }
    out
}

fn unswap_words(b: &[u8]) -> Vec<u8> {
    let mut out = b[..b.len() / 4 * 4].to_vec();
    for w in out.chunks_exact_mut(4) {
        w.reverse();
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

/// A range of lost sequence numbers, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LossRange {
    pub(crate) from: u32,
    pub(crate) to: u32,
}

pub(crate) fn write_loss_list(out: &mut Vec<u8>, ranges: &[LossRange]) {
    for r in ranges {
        if r.from == r.to {
            out.extend_from_slice(&r.from.to_be_bytes());
        } else {
            out.extend_from_slice(&(r.from | 0x8000_0000).to_be_bytes());
            out.extend_from_slice(&r.to.to_be_bytes());
        }
    }
}

pub(crate) fn parse_loss_list(mut b: &[u8], mut f: impl FnMut(u32, u32)) {
    while b.len() >= 4 {
        let w = be32(b, 0);
        b = &b[4..];
        if w & 0x8000_0000 == 0 {
            f(w, w);
            continue;
        }
        if b.len() < 4 {
            return;
        }
        let to = be32(b, 0) & (MAX_SEQ - 1);
        b = &b[4..];
        let from = w & (MAX_SEQ - 1);
        if seq_diff(to, from) < 0 {
            return;
        }
        f(from, to);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_arithmetic() {
        assert_eq!(seq_add(MAX_SEQ - 1, 1), 0);
        assert_eq!(seq_add(0, -1), MAX_SEQ - 1);
        assert_eq!(seq_diff(0, MAX_SEQ - 1), 1);
        assert_eq!(seq_diff(MAX_SEQ - 1, 0), -1);
        assert_eq!(seq_diff(100, 40), 60);
    }

    #[test]
    fn handshake_round_trip() {
        let hs = Handshake {
            version: 5,
            encryption: 2,
            ext_field: EXT_FLAG_HSREQ | EXT_FLAG_KMREQ | EXT_FLAG_CONFIG,
            isn: 12345,
            mtu: 1500,
            flow_window: 8192,
            typ: HS_CONCLUSION,
            socket_id: 77,
            cookie: 0xdead,
            peer_ip: [1; 16],
            hs: Some(HsExt {
                version: SRT_VERSION,
                flags: FLAG_TSBPD_RCV,
                rcv_delay: 120,
                snd_delay: 200,
            }),
            hs_rsp: false,
            km: Some(vec![1, 2, 3, 4, 5]),
            km_rsp: false,
            stream_id: Some("#!::r=live/s,m=publish".into()),
        };
        let mut b = Vec::new();
        Header {
            ctrl: true,
            typ: CTRL_HANDSHAKE,
            dst: 9,
            ..Header::default()
        }
        .write(&mut b);
        hs.write(&mut b);
        let h = Header::parse(&b).unwrap();
        assert!(h.ctrl && h.typ == CTRL_HANDSHAKE && h.dst == 9);
        let back = Handshake::parse(&b[HEADER_SIZE..]).unwrap();
        let mut want = hs.clone();
        want.km = Some(vec![1, 2, 3, 4, 5, 0, 0, 0]); // padded to words
        assert_eq!(back, want);
        assert!(Handshake::parse(&b[HEADER_SIZE..HEADER_SIZE + 40]).is_none());
        assert!(Handshake::parse(&b[HEADER_SIZE..b.len() - 2]).is_none());
    }

    #[test]
    fn loss_lists() {
        let mut b = Vec::new();
        let r = [LossRange { from: 5, to: 5 }, LossRange { from: 10, to: 20 }];
        write_loss_list(&mut b, &r);
        let mut got = Vec::new();
        parse_loss_list(&b, |f, t| got.push(LossRange { from: f, to: t }));
        assert_eq!(got, r);
        let mut n = 0;
        parse_loss_list(&[0x80, 0, 0, 9, 0, 0, 0, 1], |_, _| n += 1); // backwards range
        assert_eq!(n, 0);
    }
}
