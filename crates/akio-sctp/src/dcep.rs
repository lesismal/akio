//! The Data Channel Establishment Protocol (RFC 8832 §5).

use crate::Reliability;

pub(crate) const MSG_ACK: u8 = 0x02;
pub(crate) const MSG_OPEN: u8 = 0x03;

/// DATA_CHANNEL_OPEN (RFC 8832 §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Open {
    pub(crate) ordered: bool,
    pub(crate) reliability: Reliability,
    pub(crate) priority: u16,
    pub(crate) label: String,
    pub(crate) protocol: String,
}

impl Open {
    pub(crate) fn parse(b: &[u8]) -> Option<Open> {
        if b.len() < 12 || b[0] != MSG_OPEN {
            return None;
        }
        let channel_type = b[1];
        let priority = u16::from_be_bytes([b[2], b[3]]);
        let param = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        let label_len = usize::from(u16::from_be_bytes([b[8], b[9]]));
        let proto_len = usize::from(u16::from_be_bytes([b[10], b[11]]));
        let label = b.get(12..12 + label_len)?;
        let protocol = b.get(12 + label_len..12 + label_len + proto_len)?;
        // Values above u16 are clamped; browsers never send them.
        let p16 = u16::try_from(param).unwrap_or(u16::MAX);
        let reliability = match channel_type & 0x7f {
            0x00 => Reliability::Reliable,
            0x01 => Reliability::MaxRetransmits(p16),
            0x02 => Reliability::MaxLifetime(p16),
            _ => return None,
        };
        Some(Open {
            ordered: channel_type & 0x80 == 0,
            reliability,
            priority,
            label: String::from_utf8_lossy(label).into_owned(),
            protocol: String::from_utf8_lossy(protocol).into_owned(),
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let (t, param) = match self.reliability {
            Reliability::Reliable => (0x00, 0),
            Reliability::MaxRetransmits(n) => (0x01, u32::from(n)),
            Reliability::MaxLifetime(ms) => (0x02, u32::from(ms)),
        };
        let t = if self.ordered { t } else { t | 0x80 };
        let mut v = Vec::with_capacity(12 + self.label.len() + self.protocol.len());
        v.push(MSG_OPEN);
        v.push(t);
        v.extend_from_slice(&self.priority.to_be_bytes());
        v.extend_from_slice(&param.to_be_bytes());
        v.extend_from_slice(&(self.label.len() as u16).to_be_bytes());
        v.extend_from_slice(&(self.protocol.len() as u16).to_be_bytes());
        v.extend_from_slice(self.label.as_bytes());
        v.extend_from_slice(self.protocol.as_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_round_trip() {
        for (ordered, reliability) in [
            (true, Reliability::Reliable),
            (false, Reliability::Reliable),
            (true, Reliability::MaxRetransmits(3)),
            (false, Reliability::MaxLifetime(1500)),
        ] {
            let o = Open {
                ordered,
                reliability,
                priority: 256,
                label: "chat".into(),
                protocol: "json".into(),
            };
            assert_eq!(Open::parse(&o.encode()), Some(o));
        }
        // A pion-encoded OPEN: reliable unordered... "data", no protocol.
        let pion = [
            0x03, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, b'd', b'a',
            b't', b'a',
        ];
        let o = Open::parse(&pion).unwrap();
        assert!(!o.ordered);
        assert_eq!(o.label, "data");
        assert!(Open::parse(&pion[..14]).is_none());
        assert!(Open::parse(&[MSG_ACK]).is_none());
    }
}
