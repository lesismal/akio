//! The TLS record layer over a byte stream (RFC 8446 section 5, RFC 5246 section 6): framing,
//! fragmentation, AEAD protection with per-direction sequence numbers, TLS 1.3 inner content
//! types and padding.

use super::alert::{Alert, Fatal, fatal};
use super::common::Keys;
use super::suites::{Aead, AeadAlg, TAG_LEN};

pub(crate) const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub(crate) const CT_ALERT: u8 = 21;
pub(crate) const CT_HANDSHAKE: u8 = 22;
pub(crate) const CT_APPLICATION_DATA: u8 = 23;

/// Largest plaintext fragment.
pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;
/// Largest record payload accepted (TLS 1.2 allows 2048 bytes of expansion; TLS 1.3 256).
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 2048;
pub(crate) const HEADER_LEN: usize = 5;

/// How records are protected in one direction.
#[derive(Clone)]
struct Cipher {
    aead: Aead,
    /// TLS 1.3 / ChaCha20-Poly1305: the 12-byte IV XORed with the sequence number. TLS 1.2 GCM:
    /// the 4-byte salt in the first bytes.
    iv: [u8; 12],
    kind: Kind,
    seq: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tls13,
    Tls12Gcm,
    Tls12ChaCha,
}

impl Cipher {
    fn new(keys: &Keys) -> Cipher {
        match keys {
            Keys::Tls13 { suite, secret } => {
                let h = suite.hash;
                let key = h.expand_label(secret, b"key", &[], suite.aead.key_len());
                let iv = h.expand_label(secret, b"iv", &[], 12);
                let mut ivb = [0u8; 12];
                ivb.copy_from_slice(&iv);
                Cipher {
                    aead: suite.aead.key(&key),
                    iv: ivb,
                    kind: Kind::Tls13,
                    seq: 0,
                }
            }
            Keys::Tls12 { suite, key, iv } => {
                let mut ivb = [0u8; 12];
                ivb[..iv.len()].copy_from_slice(iv);
                Cipher {
                    aead: suite.aead.key(key),
                    iv: ivb,
                    kind: if suite.aead == AeadAlg::ChaCha20Poly1305 {
                        Kind::Tls12ChaCha
                    } else {
                        Kind::Tls12Gcm
                    },
                    seq: 0,
                }
            }
        }
    }

    fn xor_nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        for (a, b) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *a ^= b;
        }
        n
    }

    fn aad12(&self, typ: u8, len: usize) -> [u8; 13] {
        let mut a = [0u8; 13];
        a[..8].copy_from_slice(&self.seq.to_be_bytes());
        a[8] = typ;
        a[9] = 3;
        a[10] = 3;
        a[11..].copy_from_slice(&(len as u16).to_be_bytes());
        a
    }
}

/// The record layer state of one connection.
pub(crate) struct RecordLayer {
    read: Option<Cipher>,
    write: Option<Cipher>,
    /// The client's first record (the ClientHello) carries version 0x0301 for compatibility;
    /// everything else, and everything a server sends, 0x0303.
    pub(crate) first_write: bool,
    /// Bytes of rejected 0-RTT data still allowed to be skipped.
    pub(crate) skip_early: usize,
}

/// A record decoded in place: content type and the plaintext range within the buffer.
#[derive(Debug)]
pub(crate) struct Opened {
    pub(crate) typ: u8,
    pub(crate) start: usize,
    pub(crate) end: usize,
    /// The record was rejected 0-RTT data and is to be ignored.
    pub(crate) skipped: bool,
}

impl RecordLayer {
    pub(crate) fn new() -> RecordLayer {
        RecordLayer {
            read: None,
            write: None,
            first_write: true,
            skip_early: 0,
        }
    }

    pub(crate) fn set_read(&mut self, keys: &Keys) {
        self.read = Some(Cipher::new(keys));
    }

    pub(crate) fn set_write(&mut self, keys: &Keys) {
        self.write = Some(Cipher::new(keys));
    }

    pub(crate) fn read_is_tls13(&self) -> bool {
        self.read.as_ref().is_some_and(|c| c.kind == Kind::Tls13)
    }

    /// Records written under the current write keys.
    pub(crate) fn write_seq(&self) -> u64 {
        self.write.as_ref().map_or(0, |c| c.seq)
    }

    /// The length of the record at the start of `buf` (header included), once complete.
    pub(crate) fn frame(buf: &[u8]) -> Result<Option<usize>, Fatal> {
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let total = RecordLayer::record_len(buf)?;
        Ok((buf.len() >= total).then_some(total))
    }

    /// The length of a record (header included) from its header, the first `HEADER_LEN`
    /// bytes of `buf`.
    pub(crate) fn record_len(buf: &[u8]) -> Result<usize, Fatal> {
        let typ = buf[0];
        if !(CT_CHANGE_CIPHER_SPEC..=CT_APPLICATION_DATA).contains(&typ) {
            return fatal(Alert::UnexpectedMessage, "unknown record type");
        }
        if buf[1] != 3 {
            return fatal(Alert::ProtocolVersion, "not a TLS record");
        }
        let len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
        if len > MAX_CIPHERTEXT {
            return fatal(Alert::RecordOverflow, "record too long");
        }
        Ok(HEADER_LEN + len)
    }

    /// Bytes between the header and the encrypted payload of a record of type `typ` (the
    /// explicit nonce of TLS 1.2 AES-GCM).
    fn explicit_len(&self, typ: u8) -> usize {
        match &self.read {
            Some(c) if c.kind == Kind::Tls12Gcm && typ != CT_CHANGE_CIPHER_SPEC => 8,
            _ => 0,
        }
    }

    /// Decrypts the complete record `rec` (header included) in place.
    pub(crate) fn open(&mut self, rec: &mut [u8]) -> Result<Opened, Fatal> {
        let x = self.explicit_len(rec[0]).min(rec.len() - HEADER_LEN);
        let (head, rest) = rec.split_at_mut(HEADER_LEN);
        let (explicit, body) = rest.split_at_mut(x);
        let o = self.open_body(head, explicit, body)?;
        let off = HEADER_LEN + x;
        Ok(Opened {
            start: o.start + off,
            end: o.end + off,
            ..o
        })
    }

    /// Decrypts the complete record `rec` (header included) into `dst`: the record content is
    /// appended (copied once and decrypted where it landed, so application data needs no
    /// second copy out of a receive buffer). The result's range is the content within `dst`;
    /// nothing is appended for a skipped record or on error.
    pub(crate) fn open_into(&mut self, rec: &[u8], dst: &mut Vec<u8>) -> Result<Opened, Fatal> {
        let x = self.explicit_len(rec[0]).min(rec.len() - HEADER_LEN);
        let at = dst.len();
        dst.extend_from_slice(&rec[HEADER_LEN + x..]);
        let (head, explicit) = (&rec[..HEADER_LEN], &rec[HEADER_LEN..HEADER_LEN + x]);
        match self.open_body(head, explicit, &mut dst[at..]) {
            Ok(o) if !o.skipped => {
                // Content always starts the decrypted body.
                debug_assert_eq!(o.start, 0);
                dst.truncate(at + o.end);
                Ok(Opened {
                    start: at,
                    end: at + o.end,
                    ..o
                })
            }
            r => {
                dst.truncate(at);
                r
            }
        }
    }

    /// Decrypts a record given as its header, its explicit nonce (TLS 1.2 AES-GCM, else empty)
    /// and the rest, which is decrypted in place. The content range is relative to `body`.
    fn open_body(
        &mut self,
        head: &[u8],
        explicit: &[u8],
        body: &mut [u8],
    ) -> Result<Opened, Fatal> {
        let typ = head[0];
        let len = explicit.len() + body.len();
        let blen = body.len();
        // ChangeCipherSpec is never protected; TLS 1.3 uses it only for compatibility.
        let plain = |typ| {
            if len > MAX_PLAINTEXT {
                return fatal(Alert::RecordOverflow, "plaintext record too long");
            }
            Ok(Opened {
                typ,
                start: 0,
                end: blen,
                skipped: false,
            })
        };
        let Some(c) = self.read.as_mut() else {
            if self.skip_early > 0 && typ == CT_APPLICATION_DATA {
                return self.skip(len);
            }
            return plain(typ);
        };
        if typ == CT_CHANGE_CIPHER_SPEC {
            return plain(typ);
        }
        match c.kind {
            Kind::Tls13 => {
                if typ == CT_ALERT && len == 2 {
                    // An unprotected alert (a peer that failed before or while switching
                    // keys): taken as what it says, never answered.
                    return plain(typ);
                }
                if typ != CT_APPLICATION_DATA {
                    return fatal(Alert::UnexpectedMessage, "unprotected record after keys");
                }
                if !(TAG_LEN + 1..=MAX_PLAINTEXT + 256).contains(&len) {
                    return if self.skip_early > 0 {
                        self.skip(len)
                    } else {
                        fatal(Alert::RecordOverflow, "bad protected record length")
                    };
                }
                let nonce = c.xor_nonce();
                let (ct, tag) = body.split_at_mut(len - TAG_LEN);
                if c.aead.open(&nonce, head, ct, tag).is_err() {
                    if self.skip_early > 0 {
                        return self.skip(len);
                    }
                    return fatal(Alert::BadRecordMac, "record authentication failed");
                }
                self.skip_early = 0;
                c.seq += 1;
                let Some(pos) = ct.iter().rposition(|b| *b != 0) else {
                    return fatal(Alert::UnexpectedMessage, "record without content type");
                };
                if pos > MAX_PLAINTEXT {
                    return fatal(Alert::RecordOverflow, "plaintext too long");
                }
                let inner = ct[pos];
                Ok(Opened {
                    typ: inner,
                    start: 0,
                    end: pos,
                    skipped: false,
                })
            }
            Kind::Tls12Gcm | Kind::Tls12ChaCha => {
                let need = if c.kind == Kind::Tls12Gcm { 8 } else { 0 };
                if len < need + TAG_LEN {
                    return fatal(Alert::BadRecordMac, "record too short");
                }
                let plen = len - need - TAG_LEN;
                if plen > MAX_PLAINTEXT {
                    return fatal(Alert::RecordOverflow, "plaintext too long");
                }
                let nonce = if need > 0 {
                    let mut n = c.iv;
                    n[4..].copy_from_slice(&explicit[..8]);
                    n
                } else {
                    c.xor_nonce()
                };
                let aad = c.aad12(typ, plen);
                let (ct, tag) = body.split_at_mut(plen);
                if c.aead.open(&nonce, &aad, ct, tag).is_err() {
                    return fatal(Alert::BadRecordMac, "record authentication failed");
                }
                c.seq += 1;
                Ok(Opened {
                    typ,
                    start: 0,
                    end: plen,
                    skipped: false,
                })
            }
        }
    }

    fn skip(&mut self, len: usize) -> Result<Opened, Fatal> {
        if len > self.skip_early {
            return fatal(Alert::UnexpectedMessage, "too much rejected early data");
        }
        self.skip_early -= len;
        Ok(Opened {
            typ: CT_APPLICATION_DATA,
            start: 0,
            end: 0,
            skipped: true,
        })
    }

    /// Appends `data` as records of type `typ` (fragmented to 16 KiB) to `out`.
    pub(crate) fn seal(&mut self, typ: u8, data: &[u8], out: &mut Vec<u8>) -> Result<(), Fatal> {
        if data.is_empty() {
            return self.seal_one(typ, data, out);
        }
        // Room for every record at once: growing `out` record by record would copy what was
        // already sealed.
        let records = data.len().div_ceil(MAX_PLAINTEXT);
        out.reserve(data.len() + records * (HEADER_LEN + 8 + 1 + TAG_LEN));
        for chunk in data.chunks(MAX_PLAINTEXT) {
            self.seal_one(typ, chunk, out)?;
        }
        Ok(())
    }

    fn seal_one(&mut self, typ: u8, data: &[u8], out: &mut Vec<u8>) -> Result<(), Fatal> {
        let version: [u8; 2] = if self.first_write { [3, 1] } else { [3, 3] };
        self.first_write = false;
        let c = match self.write.as_mut() {
            Some(c) if typ != CT_CHANGE_CIPHER_SPEC => c,
            _ => {
                out.reserve(HEADER_LEN + data.len());
                out.push(typ);
                out.extend_from_slice(&version);
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(data);
                return Ok(());
            }
        };
        if c.seq == u64::MAX {
            return fatal(Alert::InternalError, "sequence number exhausted");
        }
        match c.kind {
            Kind::Tls13 => {
                let len = data.len() + 1 + TAG_LEN;
                let at = out.len();
                out.reserve(HEADER_LEN + len);
                out.push(CT_APPLICATION_DATA);
                out.extend_from_slice(&[3, 3]);
                out.extend_from_slice(&(len as u16).to_be_bytes());
                out.extend_from_slice(data);
                out.push(typ);
                let nonce = c.xor_nonce();
                let (head, body) = out[at..].split_at_mut(HEADER_LEN);
                let tag = c.aead.seal(&nonce, head, body);
                out.extend_from_slice(&tag);
            }
            Kind::Tls12Gcm | Kind::Tls12ChaCha => {
                let explicit = if c.kind == Kind::Tls12Gcm { 8 } else { 0 };
                let len = explicit + data.len() + TAG_LEN;
                out.reserve(HEADER_LEN + len);
                out.push(typ);
                out.extend_from_slice(&[3, 3]);
                out.extend_from_slice(&(len as u16).to_be_bytes());
                let nonce = if explicit > 0 {
                    let e = c.seq.to_be_bytes();
                    out.extend_from_slice(&e);
                    let mut n = c.iv;
                    n[4..].copy_from_slice(&e);
                    n
                } else {
                    c.xor_nonce()
                };
                let aad = c.aad12(typ, data.len());
                let at = out.len();
                out.extend_from_slice(data);
                let tag = c.aead.seal(&nonce, &aad, &mut out[at..]);
                out.extend_from_slice(&tag);
            }
        }
        c.seq += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::suites::{self, Suite};

    fn pair(keys: &Keys) -> (RecordLayer, RecordLayer) {
        let mut a = RecordLayer::new();
        let mut b = RecordLayer::new();
        a.set_write(keys);
        b.set_read(keys);
        (a, b)
    }

    fn keys(s: &'static Suite) -> Keys {
        if s.is_tls13() {
            Keys::Tls13 {
                suite: s,
                secret: vec![9; s.hash.len()],
            }
        } else {
            Keys::Tls12 {
                suite: s,
                key: vec![5; s.aead.key_len()],
                iv: vec![6; s.aead.fixed_iv_len_12()],
            }
        }
    }

    #[test]
    fn roundtrip_all_suites() {
        for s in suites::ALL {
            let (mut w, mut r) = pair(&keys(s));
            let mut out = Vec::new();
            let data = vec![0x42u8; 40_000];
            w.seal(CT_APPLICATION_DATA, &data, &mut out).unwrap();
            w.seal(CT_HANDSHAKE, b"hs", &mut out).unwrap();
            let mut got = Vec::new();
            let mut pos = 0;
            let mut types = Vec::new();
            while pos < out.len() {
                let n = RecordLayer::frame(&out[pos..]).unwrap().unwrap();
                let o = r.open(&mut out[pos..pos + n]).unwrap();
                types.push(o.typ);
                if o.typ == CT_APPLICATION_DATA {
                    got.extend_from_slice(&out[pos + o.start..pos + o.end]);
                }
                pos += n;
            }
            assert_eq!(got, data, "{}", s.name);
            assert_eq!(types, vec![23, 23, 23, 22]);
        }
    }

    #[test]
    fn tampering_and_replay_fail() {
        for s in suites::ALL {
            let (mut w, mut r) = pair(&keys(s));
            let mut out = Vec::new();
            w.seal(CT_APPLICATION_DATA, b"hello", &mut out).unwrap();
            let mut bad = out.clone();
            let l = bad.len();
            bad[l - 1] ^= 1;
            let e = r.clone_read().open(&mut bad).unwrap_err();
            assert_eq!(e.alert, Alert::BadRecordMac);
            let mut first = out.clone();
            r.open(&mut first).unwrap();
            // The same record again: the sequence number moved on.
            let mut again = out.clone();
            assert!(r.open(&mut again).is_err());
        }
    }

    #[test]
    fn tls13_padding_and_empty_types() {
        let s = &suites::TLS13_AES_128_GCM_SHA256;
        let k = keys(s);
        let (_, mut r) = pair(&k);
        let mut c = Cipher::new(&k);
        // Inner plaintext: "ab", type 23, three bytes of padding.
        let inner = [b'a', b'b', 23, 0, 0, 0];
        let mut rec = vec![23, 3, 3, 0, (inner.len() + 16) as u8];
        rec.extend_from_slice(&inner);
        let nonce = c.xor_nonce();
        let (h, b) = rec.split_at_mut(5);
        let tag = c.aead.seal(&nonce, h, b);
        rec.extend_from_slice(&tag);
        c.seq += 1;
        let o = r.open(&mut rec).unwrap();
        assert_eq!((o.typ, &rec[o.start..o.end]), (23, &b"ab"[..]));
        // All padding, no type: unexpected_message.
        let mut rec = vec![23, 3, 3, 0, 20, 0, 0, 0, 0];
        let nonce = c.xor_nonce();
        let (h, b) = rec.split_at_mut(5);
        let tag = c.aead.seal(&nonce, h, b);
        rec.extend_from_slice(&tag);
        assert_eq!(
            r.open(&mut rec).unwrap_err().alert,
            Alert::UnexpectedMessage
        );
    }

    #[test]
    fn framing_limits() {
        assert!(RecordLayer::frame(&[22, 3, 1, 0]).unwrap().is_none());
        assert_eq!(RecordLayer::frame(&[22, 3, 1, 0, 1, 0]).unwrap(), Some(6));
        assert!(RecordLayer::frame(&[99, 3, 1, 0, 1]).is_err());
        assert!(RecordLayer::frame(&[22, 2, 0, 0, 1]).is_err());
        assert!(RecordLayer::frame(&[23, 3, 3, 0xff, 0xff]).is_err());
        let mut r = RecordLayer::new();
        let mut big = vec![23, 3, 3, 0x40, 0x01];
        big.resize(5 + 0x4001, 0);
        assert_eq!(r.open(&mut big).unwrap_err().alert, Alert::RecordOverflow);
        // An unprotected handshake record after TLS 1.3 keys is refused.
        r.set_read(&keys(&suites::TLS13_AES_128_GCM_SHA256));
        let mut hs = vec![22, 3, 3, 0, 1, 0];
        assert_eq!(r.open(&mut hs).unwrap_err().alert, Alert::UnexpectedMessage);
    }

    #[test]
    fn skips_rejected_early_data() {
        let mut r = RecordLayer::new();
        r.skip_early = 100;
        let mut ed = vec![23, 3, 3, 0, 50];
        ed.resize(55, 7);
        assert!(r.open(&mut ed).unwrap().skipped);
        r.set_read(&keys(&suites::TLS13_AES_128_GCM_SHA256));
        let mut ed2 = vec![23, 3, 3, 0, 40];
        ed2.resize(45, 7);
        assert!(r.open(&mut ed2).unwrap().skipped);
        let mut ed3 = vec![23, 3, 3, 0, 40];
        ed3.resize(45, 7);
        assert!(r.open(&mut ed3).is_err());
    }

    impl RecordLayer {
        fn clone_read(&self) -> RecordLayer {
            RecordLayer {
                read: self.read.clone(),
                write: None,
                first_write: false,
                skip_early: 0,
            }
        }
    }
}
