//! A session's KCP packets as datagrams: kcp-go's FEC shards (when configured) inside its crypt.

use crate::crypt::Crypt;
use crate::fec;

pub(crate) struct Framer {
    enc: Option<fec::Encoder>,
    dec: Option<fec::Decoder>,
    /// Packets the FEC recovered.
    pub recovered: u64,
}

impl Framer {
    /// Either shard count at zero turns FEC off, as in kcp-go.
    pub(crate) fn new(data: usize, parity: usize) -> Option<Framer> {
        if data == 0 || parity == 0 {
            return Some(Framer {
                enc: None,
                dec: None,
                recovered: 0,
            });
        }
        Some(Framer {
            enc: Some(fec::Encoder::new(data, parity)?),
            dec: Some(fec::Decoder::new(data, parity)?),
            recovered: 0,
        })
    }

    /// Bytes the framing adds to a KCP packet.
    pub(crate) fn overhead(&self, crypt: Option<&Crypt>) -> usize {
        let c = crypt.map_or(0, |c| c.header() + c.trailer());
        c + if self.enc.is_some() {
            fec::HEADER_PLUS2
        } else {
            0
        }
    }

    /// Frames a KCP packet into its datagram and any parity datagrams it completes.
    pub(crate) fn encode(
        &mut self,
        crypt: Option<&Crypt>,
        p: &[u8],
        now_ms: i64,
        emit: &mut dyn FnMut(Vec<u8>),
    ) {
        let ch = crypt.map_or(0, Crypt::header);
        let fh = if self.enc.is_some() {
            fec::HEADER_PLUS2
        } else {
            0
        };
        let mut b = Vec::with_capacity(ch + fh + p.len() + 16);
        b.resize(ch + fh, 0);
        b.extend_from_slice(p);
        let parity = match self.enc.as_mut() {
            Some(e) => e.add(&mut b[ch..], now_ms),
            None => Vec::new(),
        };
        let seal = |b: Vec<u8>| match crypt {
            Some(c) => c.seal(b),
            None => b,
        };
        emit(seal(b));
        for sh in parity {
            let mut b = Vec::with_capacity(ch + sh.len() + 16);
            b.resize(ch, 0);
            b.extend_from_slice(&sh);
            emit(seal(b));
        }
    }

    /// Passes the KCP packets of an opened datagram to `input`: its own and those its FEC
    /// recovers. FEC shards from a peer are read even without FEC of our own (parity ignored).
    pub(crate) fn decode(&mut self, b: &[u8], input: &mut dyn FnMut(&[u8])) {
        let ty = u16::from_le_bytes([b[4], b[5]]);
        match ty {
            fec::TYPE_DATA | fec::TYPE_PARITY => {
                if b.len() < fec::HEADER_PLUS2 {
                    return;
                }
                if ty == fec::TYPE_DATA {
                    input(&b[fec::HEADER_PLUS2..]);
                }
                let Some(dec) = self.dec.as_mut() else {
                    return;
                };
                for r in dec.decode(b) {
                    let sz = u16::from_le_bytes([r[0], r[1]]) as usize;
                    if sz >= 2 && sz <= r.len() {
                        self.recovered += 1;
                        input(&r[2..sz]);
                    }
                }
            }
            fec::TYPE_OOB => {}
            _ => input(b),
        }
    }
}

/// Decrypts a datagram, `None` if it fails its check or is too short to be anything.
pub(crate) fn open(crypt: Option<&Crypt>, b: &[u8]) -> Option<Vec<u8>> {
    let o = match crypt {
        Some(c) => c.open(b.to_vec())?,
        None => b.to_vec(),
    };
    (o.len() >= fec::HEADER).then_some(o)
}

/// The conversation, command and sequence number of an opened datagram's first segment.
pub(crate) fn peek(b: &[u8]) -> Option<(u32, u8, u32)> {
    let b = match u16::from_le_bytes([b[4], b[5]]) {
        fec::TYPE_DATA => b.get(fec::HEADER_PLUS2..)?,
        fec::TYPE_PARITY | fec::TYPE_OOB => return None,
        _ => b,
    };
    if b.len() < crate::kcp::OVERHEAD {
        return None;
    }
    Some((
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        b[4],
        u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fec_recovers_lost_datagrams_through_crypt() {
        let c = Crypt::new("aes-128", &[4; 16]).unwrap();
        let (mut tx, mut rx) = (Framer::new(10, 3).unwrap(), Framer::new(10, 3).unwrap());
        let pkts: Vec<Vec<u8>> = (0..30u8).map(|i| vec![i; 30 + i as usize * 11]).collect();
        let mut wire = Vec::new();
        for p in &pkts {
            tx.encode(Some(&c), p, 0, &mut |d| wire.push(d));
        }
        assert_eq!(wire.len(), 39, "3 groups of 10 data + 3 parity");
        let mut got = Vec::new();
        for (i, d) in wire.iter().enumerate() {
            if [0, 4, 9, 13, 14, 15, 30].contains(&i) {
                continue; // up to 3 per group
            }
            let o = open(Some(&c), d).unwrap();
            rx.decode(&o, &mut |p| got.push(p.to_vec()));
        }
        got.sort();
        let mut want = pkts.clone();
        want.sort();
        assert_eq!(got, want);
        assert_eq!(rx.recovered, 7);
    }
}
