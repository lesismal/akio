//! The DTLS 1.3 key schedule (RFC 8446 §7.1 with the `"dtls13"` label prefix of RFC 9147
//! §5.9), traffic keys with the record number key (§4.2.3), Finished/binder MACs and the
//! exporter.
//!
//! The structure is TLS 1.3's (only-tls has the same schedule with `"tls13 "`); it is not
//! shared with only-tls because only-dtls must not pull in only-tls's engine dependencies and
//! the prefix differs. The unit tests check the shared structure against RFC 8448 with the
//! TLS prefix.

use crate::Error;
use crate::crypto::{CipherSuite, PrfHash, Protection13};

/// The TLS 1.3 label prefix (tests only: RFC 8448 vectors).
#[cfg(test)]
const TLS13: &[u8] = b"tls13 ";
/// The DTLS 1.3 label prefix (RFC 9147 §5.9; six bytes like `"tls13 "`).
const DTLS13: &[u8] = b"dtls13";

fn expand(h: PrfHash, prk: &[u8], info: &[u8], out: &mut [u8]) {
    use only_crypto::hash::{Sha256, Sha384};
    use only_crypto::kdf::hkdf_expand;
    // Lengths come from the suite (at most 48 bytes, far below 255 * hash length).
    let r = match h {
        PrfHash::Sha256 => hkdf_expand::<Sha256>(prk, info, out),
        PrfHash::Sha384 => hkdf_expand::<Sha384>(prk, info, out),
    };
    debug_assert!(r.is_ok());
}

pub(crate) fn extract(h: PrfHash, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    h.hmac(salt, ikm)
}

fn expand_label_with(
    h: PrfHash,
    prefix: &[u8],
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut info = Vec::with_capacity(4 + prefix.len() + label.len() + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((prefix.len() + label.len()) as u8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = vec![0u8; len];
    expand(h, secret, &info, &mut out);
    out
}

/// HKDF-Expand-Label with the `"dtls13"` prefix.
pub(crate) fn expand_label(
    h: PrfHash,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    expand_label_with(h, DTLS13, secret, label, context, len)
}

/// Derive-Secret(secret, label, messages) given the transcript hash of the messages.
pub(crate) fn derive_secret(h: PrfHash, secret: &[u8], label: &[u8], hash: &[u8]) -> Vec<u8> {
    expand_label(h, secret, label, hash, h.len())
}

/// The secret of the current key schedule stage.
#[derive(Clone)]
pub(crate) struct Schedule {
    pub(crate) hash: PrfHash,
    pub(crate) current: Vec<u8>,
    prefix: &'static [u8],
}

impl std::fmt::Debug for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Schedule").finish_non_exhaustive()
    }
}

impl Schedule {
    /// The early secret from `psk` (zeros without one).
    pub(crate) fn early(hash: PrfHash, psk: Option<&[u8]>) -> Schedule {
        Schedule::early_with(hash, psk, DTLS13)
    }

    fn early_with(hash: PrfHash, psk: Option<&[u8]>, prefix: &'static [u8]) -> Schedule {
        let zeros = vec![0u8; hash.len()];
        Schedule {
            hash,
            current: extract(hash, &zeros, psk.unwrap_or(&zeros)),
            prefix,
        }
    }

    pub(crate) fn derive(&self, label: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        expand_label_with(
            self.hash,
            self.prefix,
            &self.current,
            label,
            transcript_hash,
            self.hash.len(),
        )
    }

    /// The next stage: the handshake secret with `ikm` = the (EC)DHE secret, then the master
    /// secret with `None`.
    pub(crate) fn next(&mut self, ikm: Option<&[u8]>) {
        let empty = self.hash.digest(&[]);
        let derived = self.derive(b"derived", &empty);
        let zeros = vec![0u8; self.hash.len()];
        self.current = extract(self.hash, &derived, ikm.unwrap_or(&zeros));
    }

    /// The PSK binder key (`ext binder` for external PSKs, `res binder` for tickets).
    pub(crate) fn binder_key(&self, external: bool) -> Vec<u8> {
        let empty = self.hash.digest(&[]);
        let label: &[u8] = if external {
            b"ext binder"
        } else {
            b"res binder"
        };
        self.derive(label, &empty)
    }
}

/// verify_data of a Finished (or a PSK binder) with `base_key` over `transcript_hash`.
pub(crate) fn finished_mac(h: PrfHash, base_key: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let k = expand_label(h, base_key, b"finished", &[], h.len());
    h.hmac(&k, transcript_hash)
}

/// The next application traffic secret (KeyUpdate).
pub(crate) fn next_secret(h: PrfHash, secret: &[u8]) -> Vec<u8> {
    expand_label(h, secret, b"traffic upd", &[], h.len())
}

/// Record protection for a traffic secret: `key`, `iv` and the record number key `sn`.
pub(crate) fn protection(suite: CipherSuite, secret: &[u8]) -> Result<Protection13, Error> {
    let h = suite.prf_hash();
    let key = expand_label(h, secret, b"key", &[], suite.key_len());
    let iv = expand_label(h, secret, b"iv", &[], 12);
    let sn = expand_label(h, secret, b"sn", &[], suite.key_len());
    Protection13::new(suite, &key, &iv, &sn)
}

/// The TLS 1.3 exporter (RFC 8446 §7.5) from the exporter master secret.
pub(crate) fn export(
    h: PrfHash,
    exporter_master: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let empty = h.digest(&[]);
    let secret = derive_secret(h, exporter_master, label, &empty);
    expand_label(h, &secret, b"exporter", &h.digest(context), len)
}

/// The resumption PSK of a NewSessionTicket (RFC 8446 §4.6.1).
pub(crate) fn ticket_psk(h: PrfHash, resumption_master: &[u8], nonce: &[u8]) -> Vec<u8> {
    expand_label(h, resumption_master, b"resumption", nonce, h.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8448 §3 (Simple 1-RTT Handshake).
    const CH: &str = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001";
    const SH: &str = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";
    const EARLY: &str = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    const ECDHE: &str = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    const HS_SECRET: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    const C_HS: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    const S_HS: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    const MASTER: &str = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    const S_HS_KEY: &str = "3fce516009c21727d0f2e4e86ee403bc";
    const S_HS_IV: &str = "5d313eb2671276ee13000b30";

    /// The schedule's structure (extract, Derive-Secret, HKDF-Expand-Label) against RFC 8448
    /// with the TLS 1.3 prefix: only the prefix differs in DTLS 1.3.
    #[test]
    fn rfc8448_schedule() {
        let h = PrfHash::Sha256;
        let mut s = Schedule::early_with(h, None, TLS13);
        assert_eq!(s.current, hex(EARLY));
        s.next(Some(&hex(ECDHE)));
        assert_eq!(s.current, hex(HS_SECRET));
        let mut t = hex(CH);
        t.extend_from_slice(&hex(SH));
        let th = h.digest(&t);
        assert_eq!(s.derive(b"c hs traffic", &th), hex(C_HS));
        let shs = s.derive(b"s hs traffic", &th);
        assert_eq!(shs, hex(S_HS));
        assert_eq!(
            expand_label_with(h, TLS13, &shs, b"key", &[], 16),
            hex(S_HS_KEY)
        );
        assert_eq!(
            expand_label_with(h, TLS13, &shs, b"iv", &[], 12),
            hex(S_HS_IV)
        );
        s.next(None);
        assert_eq!(s.current, hex(MASTER));
    }

    /// The DTLS 1.3 HkdfLabel: `"dtls13" || label` with no space (RFC 9147 §5.9).
    #[test]
    fn dtls13_label_layout() {
        let h = PrfHash::Sha256;
        let secret = [7u8; 32];
        let mut info = vec![0, 16, 6 + 3];
        info.extend_from_slice(b"dtls13key");
        info.push(0);
        let mut want = [0u8; 16];
        expand(h, &secret, &info, &mut want);
        assert_eq!(expand_label(h, &secret, b"key", &[], 16), want);
        assert_ne!(
            expand_label(h, &secret, b"key", &[], 16),
            expand_label_with(h, TLS13, &secret, b"key", &[], 16)
        );
    }

    #[test]
    fn record_number_masks() {
        for suite in CipherSuite::TLS13 {
            let p = protection(suite, &vec![1u8; suite.prf_hash().len()]).unwrap();
            let a = p.mask(&[0u8; 16]);
            let b = p.mask(&[1u8; 16]);
            assert_ne!(a, b, "{suite}");
            assert_eq!(a, p.mask(&[0u8; 16]));
            let ct = p.seal(5, b"hdr", b"hello\x17");
            assert_eq!(p.open(5, b"hdr", &ct).unwrap(), b"hello\x17");
            assert!(p.open(6, b"hdr", &ct).is_none());
            assert!(p.open(5, b"hdX", &ct).is_none());
        }
    }
}
