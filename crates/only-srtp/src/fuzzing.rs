//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use crate::{Context, Profile};

const MKI0: [u8; 4] = [1, 2, 3, 4];
const MKI1: [u8; 4] = [0x0a, 0x0b, 0x0c, 0x0d];
/// Header extension IDs `srtp_features` encrypts (RFC 6904).
const HDR_IDS: [u8; 5] = [1, 2, 3, 14, 200];

fn keys(profile: Profile) -> (Vec<u8>, Vec<u8>) {
    let key = (1..=profile.key_len()).map(|i| i as u8).collect();
    let salt = (0..profile.salt_len()).map(|i| 0xa0 + i as u8).collect();
    (key, salt)
}

fn context(profile: Profile) -> Option<Context> {
    let (key, salt) = keys(profile);
    Context::new(profile, &key, &salt).ok()
}

/// `srtp_unprotect`: arbitrary bytes through `unprotect_rtp` and `unprotect_rtcp` of every
/// profile (fixed keys); when the input parses as RTP / RTCP it is also protected and must
/// unprotect back to itself. Never panics.
pub fn srtp_unprotect(data: &[u8]) {
    for profile in Profile::ALL {
        let Some(mut rx) = context(profile) else {
            return;
        };
        let _ = rx.unprotect_rtp(data);
        let _ = rx.unprotect_rtcp(data);
        let _ = rx.unprotect_rtp(data);
        let Some(mut tx) = context(profile) else {
            return;
        };
        let Some(mut rx) = context(profile) else {
            return;
        };
        if let Ok(p) = tx.protect_rtp(data) {
            assert!(rx.unprotect_rtp(&p).ok().as_deref() == Some(data));
        }
        if let Ok(p) = tx.protect_rtcp(data) {
            assert!(rx.unprotect_rtcp(&p).ok().as_deref() == Some(data));
        }
    }
}

/// A context for `srtp_features`: `flags` bit 0 MKIs (two keys, sending with the second when
/// bit 4 is set), bit 1 RFC 6904 header extension encryption, bit 2 cryptex, bit 3 key
/// derivation rate 4.
fn feature_context(profile: Profile, flags: u8) -> Option<Context> {
    let (key, salt) = keys(profile);
    let mut c = if flags & 1 != 0 {
        let mut c = Context::new_with_mki(profile, &MKI0, &key, &salt).ok()?;
        let key1: Vec<u8> = key.iter().map(|b| b ^ 0x55).collect();
        c.add_master_key(&MKI1, &key1, &salt).ok()?;
        if flags & 16 != 0 {
            c.set_send_mki(&MKI1).ok()?;
        }
        c
    } else {
        Context::new(profile, &key, &salt).ok()?
    };
    if flags & 2 != 0 {
        c = c.with_encrypted_header_extensions(&HDR_IDS);
    }
    if flags & 4 != 0 {
        c = c.with_cryptex(true);
    }
    if flags & 8 != 0 {
        c = c.with_key_derivation_rate(4).ok()?;
    }
    Some(c)
}

/// What `unprotect_rtp` gives back for an RTP packet `p` protected with cryptex: CSRCs without
/// an extension get an empty one (RFC 9335 §5.1).
fn cryptex_expected(p: &[u8], profile: Profile) -> Vec<u8> {
    let cc = usize::from(p[0] & 0x0f);
    if !profile.encrypts() || cc == 0 || p[0] & 0x10 != 0 {
        return p.to_vec();
    }
    let mut v = p.to_vec();
    v[0] |= 0x10;
    v.splice(12 + 4 * cc..12 + 4 * cc, [0xbe, 0xde, 0, 0]);
    v
}

/// `srtp_features`: the first byte picks a profile and a configuration (MKIs and re-keying,
/// RFC 6904 header extension encryption, cryptex, key derivation rate); the rest goes through
/// `unprotect_rtp` / `unprotect_rtcp` (MKI lookup, trailer layout, cryptex and header
/// extension parsing) and, when it parses as RTP / RTCP, is protected and must unprotect
/// back to itself (with cryptex's empty extension added). Never panics.
pub fn srtp_features(data: &[u8]) {
    let Some((&sel, data)) = data.split_first() else {
        return;
    };
    let profile = Profile::ALL[usize::from(sel) % Profile::ALL.len()];
    let flags = sel / 10 % 32;
    let (Some(mut rx), Some(mut tx), Some(mut rx2)) = (
        feature_context(profile, flags),
        feature_context(profile, flags),
        feature_context(profile, flags),
    ) else {
        return;
    };
    let mut out = Vec::new();
    let _ = rx.unprotect_rtp_into(data, &mut out);
    let _ = rx.unprotect_rtcp_into(data, &mut out);
    if let Ok(p) = tx.protect_rtp(data) {
        let want = if flags & 4 != 0 {
            cryptex_expected(data, profile)
        } else {
            data.to_vec()
        };
        assert!(rx2.unprotect_rtp(&p).ok() == Some(want));
        assert!(rx2.unprotect_rtp(&p) == Err(crate::Error::Replay));
    }
    if let Ok(p) = tx.protect_rtcp(data) {
        assert!(rx2.unprotect_rtcp(&p).ok().as_deref() == Some(data));
    }
}

#[cfg(test)]
mod tests {
    use super::{context, feature_context, srtp_features, srtp_unprotect};
    use crate::Profile;
    use crate::tests::hex;

    fn seeds() -> Vec<Vec<u8>> {
        let rtp = [
            "9160fffe11223344cafebabe01020304bede000110aa000068656c6c6f207372747020776f726c64",
            "a0e0ffff11223345cafebabe0102030405000003",
            "8060000111223347cafebabe090909",
        ];
        let rtcp = "81c90007cafebabe000000010500000200010003000000040000000500000006";
        let mut out = Vec::new();
        for profile in Profile::ALL {
            let mut tx = context(profile).unwrap();
            for r in rtp {
                out.push(hex(r));
                out.push(tx.protect_rtp(&hex(r)).unwrap());
            }
            out.push(tx.protect_rtcp(&hex(rtcp)).unwrap());
        }
        out.push(hex(rtcp));
        out
    }

    fn feature_seeds() -> Vec<Vec<u8>> {
        let rtp = [
            // CSRC + one-byte extension (IDs 1, 2, 3; padding), two-byte extension (ID 200),
            // CSRCs without an extension, a plain packet.
            "9160100011223344cafebabe01020304bede000410aa21bbcc3311223344e0550000000068656c6c6f",
            "9060100111223345cafebabe100000040103aabbccc8030102030e0155000000776f726c64",
            "8260100211223346cafebabe0001e2400000b26e616263",
            "8060100311223347cafebabe090909",
        ];
        let rtcp = "81c90007cafebabe000000010500000200010003000000040000000500000006";
        let mut out = Vec::new();
        for sel in [0u8, 12, 23, 34, 45, 56, 67, 78, 89, 100, 151, 158, 249] {
            let profile = Profile::ALL[usize::from(sel) % Profile::ALL.len()];
            let mut tx = feature_context(profile, sel / 10 % 32).unwrap();
            for r in rtp {
                for p in [hex(r), tx.protect_rtp(&hex(r)).unwrap()] {
                    let mut s = vec![sel];
                    s.extend_from_slice(&p);
                    out.push(s);
                }
            }
            let mut s = vec![sel];
            s.extend_from_slice(&tx.protect_rtcp(&hex(rtcp)).unwrap());
            out.push(s);
        }
        out
    }

    #[test]
    fn replay_feature_corpus() {
        let n = only_core::fuzzing::replay(env!("CARGO_MANIFEST_DIR"), "srtp_features", |d| {
            srtp_features(d);
        });
        assert!(n > 0, "fuzz/corpus/srtp_features is empty");
        for s in feature_seeds() {
            srtp_features(&s);
            for cut in 0..s.len() {
                srtp_features(&s[..cut]);
            }
            for i in 1..s.len() {
                let mut t = s.clone();
                t[i] ^= 0x41;
                srtp_features(&t);
            }
        }
    }

    #[test]
    fn replay_corpus() {
        let n = only_core::fuzzing::replay(env!("CARGO_MANIFEST_DIR"), "srtp_unprotect", |d| {
            srtp_unprotect(d);
        });
        assert!(n > 0, "fuzz/corpus/srtp_unprotect is empty");
        for s in seeds() {
            srtp_unprotect(&s);
            for cut in 0..s.len() {
                srtp_unprotect(&s[..cut]);
            }
        }
    }

    /// `cargo test -p only-srtp -- --ignored write_corpus`.
    #[test]
    #[ignore = "writes fuzz/corpus"]
    fn write_corpus() {
        only_core::fuzzing::write_target_seeds(
            env!("CARGO_MANIFEST_DIR"),
            "srtp_unprotect",
            &seeds(),
        );
        only_core::fuzzing::write_target_seeds(
            env!("CARGO_MANIFEST_DIR"),
            "srtp_features",
            &feature_seeds(),
        );
    }
}
