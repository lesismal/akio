//! SDP security descriptions for SRTP (SDES, RFC 4568): `a=crypto` lines that carry the SRTP
//! master keys in the SDP itself, for peers without DTLS-SRTP (SIP gateways). Off unless
//! [`RtcConfig::enable_sdes_srtp`](crate::RtcConfig::enable_sdes_srtp); DTLS-SRTP stays the
//! default and offers to browsers never carry `a=crypto`.
//!
//! - An offer lists one line per suite in [`OFFERED`], each with its own random key; the
//!   answer picks one (tag and suite) and brings the answerer's key for the same suite. Each
//!   side encrypts with its own key and decrypts with the other's.
//! - Lines with an MKI, several keys, session parameters (`KDR=`, `UNENCRYPTED_SRTP`, ...), an
//!   unknown suite or a key of the wrong length are not taken (RFC 4568 §6.1: the answerer
//!   ignores lines it does not understand); a lifetime is accepted and not enforced (the
//!   SRTP context refuses to wrap its index anyway).
//! - Every section of the BUNDLE carries the same lines: one SRTP context per direction
//!   serves the transport, so a remote description whose sections disagree is refused.

use only_crypto::base64::STANDARD as B64;
use only_srtp::Profile;

use crate::fill_random;
use crate::sdp::{Media, Sdp};

/// The suites offered, strongest first (the answerer takes the first it supports).
pub(super) const OFFERED: [Profile; 5] = [
    Profile::AeadAes256Gcm,
    Profile::AeadAes128Gcm,
    Profile::Aes256CmHmacSha1_80,
    Profile::Aes128CmHmacSha1_80,
    Profile::Aes128CmHmacSha1_32,
];

/// The protocols of an SDES media section (an offer of ours uses the first).
pub(super) const PROTOS: [&str; 2] = ["RTP/SAVPF", "RTP/SAVP"];

/// One usable `a=crypto` line.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Crypto {
    pub(super) tag: u32,
    pub(super) profile: Profile,
    /// Master key then master salt.
    pub(super) key: Vec<u8>,
}

impl std::fmt::Debug for Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Crypto")
            .field("tag", &self.tag)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl Crypto {
    /// A fresh random key for `profile`.
    pub(super) fn generate(tag: u32, profile: Profile) -> Crypto {
        let mut key = vec![0u8; profile.key_len() + profile.salt_len()];
        fill_random(&mut key);
        Crypto { tag, profile, key }
    }

    /// The master key and salt.
    pub(super) fn key_salt(&self) -> (&[u8], &[u8]) {
        self.key.split_at(self.profile.key_len())
    }

    /// The value of the `a=crypto` attribute.
    pub(super) fn to_attr(&self) -> String {
        format!(
            "{} {} inline:{}",
            self.tag,
            self.profile.sdes_name().unwrap_or("?"),
            B64.encode(&self.key)
        )
    }

    /// Parses an `a=crypto` value; `None` when the line cannot be used here (see the module
    /// docs).
    pub(super) fn parse(v: &str) -> Option<Crypto> {
        let mut it = v.split_ascii_whitespace();
        let tag = it.next()?;
        if tag.is_empty() || tag.len() > 9 || !tag.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let tag = tag.parse().ok()?;
        let profile = Profile::from_sdes_name(it.next()?)?;
        let params = it.next()?;
        if it.next().is_some() || params.contains(';') {
            return None; // session parameters, or several keys (which need MKIs)
        }
        let inline = params.strip_prefix("inline:")?;
        let mut parts = inline.split('|');
        let key = B64.decode(parts.next()?).ok()?;
        for p in parts {
            // A lifetime (`2^31` or decimal) is fine; anything with ':' is an MKI.
            let ok = match p.strip_prefix("2^") {
                Some(e) => e.parse::<u8>().is_ok_and(|e| e <= 64),
                None => !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()),
            };
            if !ok {
                return None;
            }
        }
        (key.len() == profile.key_len() + profile.salt_len()).then_some(Crypto {
            tag,
            profile,
            key,
        })
    }
}

/// The SDES state of a peer connection.
#[derive(Debug, Default)]
pub(super) struct Sdes {
    /// The session is keyed by SDES (decided by the first offer: ours with SDES on, or a
    /// remote one in SDES form); DTLS-SRTP otherwise.
    pub(super) active: bool,
    /// The media protocol: what our offers use, what the remote offer used.
    pub(super) proto: String,
    /// The lines of our offers (made once, so re-offers keep the keys).
    pub(super) offered: Vec<Crypto>,
    /// Our key in use (what we encrypt with), and the remote's (what we decrypt with).
    pub(super) local: Option<Crypto>,
    pub(super) remote: Option<Crypto>,
    /// The keys the SRTP contexts were made with.
    pub(super) keyed_tx: Option<Crypto>,
    pub(super) keyed_rx: Option<Crypto>,
}

/// Whether a remote offer asks for SDES: its first section in use has an `RTP/SAVP(F)`
/// protocol and `a=crypto` lines.
pub(super) fn is_sdes_offer(sdp: &Sdp) -> bool {
    sdp.media
        .iter()
        .find(|m| m.port != 0)
        .is_some_and(|m| PROTOS.contains(&m.proto.as_str()) && m.has("crypto"))
}

/// The usable `a=crypto` lines of each section in use, which must be the same everywhere
/// (sections without any are skipped); `Err` when they differ.
pub(super) fn remote_lines(sdp: &Sdp) -> Result<Vec<Crypto>, &'static str> {
    let mut found: Option<Vec<Crypto>> = None;
    for m in sdp.media.iter().filter(|m| m.port != 0 && m.has("crypto")) {
        let lines = section_lines(m);
        match &found {
            Some(f) if *f != lines => {
                return Err("SDES: the bundled sections carry different keys");
            }
            Some(_) => {}
            None => found = Some(lines),
        }
    }
    Ok(found.unwrap_or_default())
}

fn section_lines(m: &Media) -> Vec<Crypto> {
    m.all("crypto").filter_map(Crypto::parse).collect()
}

impl Sdes {
    /// The lines of our offer, made on first use.
    pub(super) fn offer_lines(&mut self) -> &[Crypto] {
        if self.offered.is_empty() {
            self.offered = OFFERED
                .iter()
                .zip(1u32..)
                .map(|(&p, tag)| Crypto::generate(tag, p))
                .collect();
        }
        &self.offered
    }

    /// Takes the answer to our offer: its one line must name a tag and suite we offered.
    pub(super) fn accept_answer(&mut self, sdp: &Sdp) -> Result<(), &'static str> {
        let lines = remote_lines(sdp)?;
        let [r] = lines.as_slice() else {
            return Err("SDES: the answer has no usable a=crypto line (or several)");
        };
        let ours = self
            .offered
            .iter()
            .find(|o| o.tag == r.tag && o.profile == r.profile)
            .ok_or("SDES: the answer's a=crypto matches no offered line")?;
        self.local = Some(ours.clone());
        self.remote = Some(r.clone());
        Ok(())
    }

    /// Picks the first usable line of a remote offer and the key we answer with (kept from
    /// the previous answer when the tag and suite are the same).
    pub(super) fn accept_offer(&mut self, sdp: &Sdp) -> Result<(), &'static str> {
        let lines = remote_lines(sdp)?;
        let r = lines
            .into_iter()
            .next()
            .ok_or("SDES: no usable a=crypto line in the offer (suites, MKIs, parameters)")?;
        let keep = self
            .local
            .as_ref()
            .is_some_and(|l| l.tag == r.tag && l.profile == r.profile);
        if !keep {
            self.local = Some(Crypto::generate(r.tag, r.profile));
        }
        self.remote = Some(r);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_lines() {
        // RFC 4568 §4's example key (inline key||salt, lifetime, MKI).
        let k = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz";
        let c = Crypto::parse(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k}")).unwrap();
        assert_eq!(
            (c.tag, c.profile, c.key.len()),
            (1, Profile::Aes128CmHmacSha1_80, 30)
        );
        assert_eq!(c.to_attr(), format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k}"));
        let (key, salt) = c.key_salt();
        assert_eq!((key.len(), salt.len()), (16, 14));
        // A lifetime is fine.
        assert!(Crypto::parse(&format!("2 AES_CM_128_HMAC_SHA1_32 inline:{k}|2^20")).is_some());
        assert!(Crypto::parse(&format!("2 AES_CM_128_HMAC_SHA1_32 inline:{k}|1048576")).is_some());
        for bad in [
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k}|2^20|1:4"), // MKI
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k}|1:4"),
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k};inline:{k}"), // two keys
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k} KDR=1"),      // session parameter
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k} UNENCRYPTED_SRTP"),
            format!("1 F8_128_HMAC_SHA1_80 inline:{k}"), // unsupported suite
            format!("1 AES_256_CM_HMAC_SHA1_80 inline:{k}"), // key too short for the suite
            format!("x AES_CM_128_HMAC_SHA1_80 inline:{k}"),
            format!("1234567890 AES_CM_128_HMAC_SHA1_80 inline:{k}"),
            format!("1 AES_CM_128_HMAC_SHA1_80 {k}"),
            format!("1 AES_CM_128_HMAC_SHA1_80 inline:{k}|"),
            "1 AES_CM_128_HMAC_SHA1_80 inline:!!!".to_owned(),
            "1 AES_CM_128_HMAC_SHA1_80".to_owned(),
            String::new(),
        ] {
            assert!(Crypto::parse(&bad).is_none(), "{bad}");
        }
        // Every offered suite round-trips with a generated key.
        for (tag, p) in (1..).zip(OFFERED) {
            let c = Crypto::generate(tag, p);
            assert_eq!(Crypto::parse(&c.to_attr()), Some(c));
        }
    }

    fn sdp(lines: &[&str]) -> Sdp {
        let mut s = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n".to_owned();
        for l in lines {
            s.push_str(l);
            s.push_str("\r\n");
        }
        Sdp::parse(&s).unwrap()
    }

    #[test]
    fn offer_and_answer() {
        let mut a = Sdes::default();
        let offered = a.offer_lines().to_vec();
        assert_eq!(offered.len(), OFFERED.len());
        assert_eq!(a.offer_lines(), &offered[..], "made once");
        // The remote offers a suite we do not take first, then one we do.
        let k = Crypto::generate(7, Profile::Aes128CmHmacSha1_80);
        let offer = sdp(&[
            "m=audio 9 RTP/SAVPF 0",
            "a=crypto:3 F8_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
            &format!("a=crypto:{}", k.to_attr()),
            "m=video 9 RTP/SAVPF 96",
            "a=crypto:3 F8_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
            &format!("a=crypto:{}", k.to_attr()),
        ]);
        assert!(is_sdes_offer(&offer));
        let mut b = Sdes::default();
        b.accept_offer(&offer).unwrap();
        assert_eq!(b.remote.as_ref(), Some(&k));
        let local = b.local.clone().unwrap();
        assert_eq!(
            (local.tag, local.profile),
            (7, Profile::Aes128CmHmacSha1_80)
        );
        assert_ne!(local.key, k.key);
        // A re-offer with the same line keeps our key.
        b.accept_offer(&offer).unwrap();
        assert_eq!(b.local.as_ref(), Some(&local));
        // Sections that disagree.
        let k2 = Crypto::generate(7, Profile::Aes128CmHmacSha1_80);
        let split = sdp(&[
            "m=audio 9 RTP/SAVPF 0",
            &format!("a=crypto:{}", k.to_attr()),
            "m=video 9 RTP/SAVPF 96",
            &format!("a=crypto:{}", k2.to_attr()),
        ]);
        assert!(b.accept_offer(&split).is_err());
        // Nothing usable.
        let none = sdp(&[
            "m=audio 9 RTP/SAVP 0",
            "a=crypto:1 F8_128_HMAC_SHA1_80 inline:x",
        ]);
        assert!(is_sdes_offer(&none));
        assert!(b.accept_offer(&none).is_err());
        // DTLS-SRTP offers are not SDES, even with a=crypto.
        let dtls = sdp(&[
            "m=audio 9 UDP/TLS/RTP/SAVPF 0",
            &format!("a=crypto:{}", k.to_attr()),
        ]);
        assert!(!is_sdes_offer(&dtls));

        // The answer to `a`'s offer.
        let pick = offered[3].clone();
        let mine = Crypto::generate(pick.tag, pick.profile);
        let answer = sdp(&[
            "m=audio 9 RTP/SAVPF 0",
            &format!("a=crypto:{}", mine.to_attr()),
        ]);
        a.accept_answer(&answer).unwrap();
        assert_eq!(
            (a.local.as_ref(), a.remote.as_ref()),
            (Some(&pick), Some(&mine))
        );
        // A tag we did not offer with that suite, or two lines.
        let wrong = Crypto::generate(1, Profile::Aes128CmHmacSha1_80);
        let answer = sdp(&[
            "m=audio 9 RTP/SAVPF 0",
            &format!("a=crypto:{}", wrong.to_attr()),
        ]);
        assert!(a.accept_answer(&answer).is_err());
        let two = sdp(&[
            "m=audio 9 RTP/SAVPF 0",
            &format!("a=crypto:{}", mine.to_attr()),
            &format!("a=crypto:{}", offered[0].to_attr()),
        ]);
        assert!(a.accept_answer(&two).is_err());
    }
}
