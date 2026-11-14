//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use crate::{Context, Profile};

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

#[cfg(test)]
mod tests {
    use super::{context, srtp_unprotect};
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
    }
}
