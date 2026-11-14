//! The per-direction SRTP/SRTCP context with per-SSRC state.

use std::collections::HashMap;

use crate::cipher::{self, Cipher, E_FLAG};
use crate::replay::ReplayWindow;
use crate::{Error, Profile};

/// Default replay window: 64 packets (RFC 3711 §3.3.2 minimum).
pub const DEFAULT_REPLAY_WINDOW: usize = 64;
/// Largest accepted replay window ([`Context::with_replay_window`] clamps to it).
pub const MAX_REPLAY_WINDOW: usize = 32_768;
/// Default number of SSRCs tracked per direction before the least recently used is evicted.
pub const DEFAULT_MAX_SSRCS: usize = 1024;

/// Largest SRTCP index (31 bits).
const MAX_SRTCP_INDEX: u32 = 0x7fff_ffff;

/// A value with the tick of its last use, for least-recently-used eviction.
#[derive(Debug)]
struct Slot<T> {
    used: u64,
    v: T,
}

/// One direction of an SRTP session (RFC 3711): the session keys derived from a master key
/// and salt, plus per-SSRC rollover counters, replay windows and SRTCP indices.
///
/// Use one `Context` for what you send (`protect_*`) and another, keyed with the remote master
/// key, for what you receive (`unprotect_*`). Sending and receiving state are kept apart, so
/// using one context both ways does not corrupt either.
pub struct Context {
    profile: Profile,
    cipher: Cipher,
    window_words: usize,
    max_ssrcs: usize,
    tick: u64,
    /// Highest SRTP index sent per SSRC.
    rtp_out: HashMap<u32, Slot<u64>>,
    /// Replay window (and highest index) received per SSRC.
    rtp_in: HashMap<u32, Slot<ReplayWindow>>,
    /// Next SRTCP index to send per SSRC.
    rtcp_out: HashMap<u32, Slot<u32>>,
    /// SRTCP replay window per SSRC.
    rtcp_in: HashMap<u32, Slot<ReplayWindow>>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("profile", &self.profile)
            .field("replay_window", &(self.window_words * 64))
            .field("ssrcs_out", &self.rtp_out.len())
            .field("ssrcs_in", &self.rtp_in.len())
            .finish_non_exhaustive()
    }
}

/// RTP header length (fixed header, CSRCs and header extension), or `None` when `p` is not
/// a well-formed RTP version 2 header.
pub(crate) fn rtp_header_len(p: &[u8]) -> Option<usize> {
    let b0 = *p.first()?;
    if p.len() < 12 || b0 >> 6 != 2 {
        return None;
    }
    let mut n = 12 + 4 * usize::from(b0 & 0x0f);
    if b0 & 0x10 != 0 {
        let ext = p.get(n..n + 4)?;
        n += 4 + 4 * usize::from(u16::from_be_bytes([ext[2], ext[3]]));
    }
    (n <= p.len()).then_some(n)
}

fn be32(p: &[u8], at: usize) -> Option<u32> {
    let b = p.get(at..at + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// RFC 3711 §3.3.1 / Appendix A: the rollover counter `v` to use for `seq` given the highest
/// index seen so far. `None` when the guess would be negative (older than index 0) or overflow.
fn estimate_roc(highest: u64, seq: u16) -> Option<u32> {
    let roc = u32::try_from(highest >> 16).ok()?;
    let s_l = i32::from((highest & 0xffff) as u16);
    let seq = i32::from(seq);
    if s_l < 32_768 {
        if seq - s_l > 32_768 {
            roc.checked_sub(1)
        } else {
            Some(roc)
        }
    } else if s_l - 32_768 > seq {
        roc.checked_add(1)
    } else {
        Some(roc)
    }
}

fn index(roc: u32, seq: u16) -> u64 {
    (u64::from(roc) << 16) | u64::from(seq)
}

impl Context {
    /// A context for `profile` keyed with the master key and salt (for example from
    /// DTLS-SRTP). Session keys are derived with key derivation rate 0.
    ///
    /// # Errors
    ///
    /// [`Error::KeyLength`] when the lengths do not match [`Profile::key_len`] /
    /// [`Profile::salt_len`].
    pub fn new(profile: Profile, master_key: &[u8], master_salt: &[u8]) -> Result<Context, Error> {
        let keys = cipher::derive(profile, master_key, master_salt)?;
        Ok(Context::from_cipher(profile, Cipher::new(profile, &keys)?))
    }

    fn from_cipher(profile: Profile, cipher: Cipher) -> Context {
        Context {
            profile,
            cipher,
            window_words: DEFAULT_REPLAY_WINDOW / 64,
            max_ssrcs: DEFAULT_MAX_SSRCS,
            tick: 0,
            rtp_out: HashMap::new(),
            rtp_in: HashMap::new(),
            rtcp_out: HashMap::new(),
            rtcp_in: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_session_keys(profile: Profile, keys: &cipher::SessionKeys) -> Context {
        Context::from_cipher(profile, Cipher::new(profile, keys).expect("keys"))
    }

    /// Sets the replay window size in packets (rounded up to a multiple of 64, clamped to
    /// 64..=[`MAX_REPLAY_WINDOW`]); applies to SSRCs first seen afterwards. Larger windows
    /// accept packets reordered further, which video with NACK/RTX can need.
    #[must_use]
    pub fn with_replay_window(mut self, packets: usize) -> Context {
        self.window_words = packets.clamp(64, MAX_REPLAY_WINDOW).div_ceil(64);
        self
    }

    /// Sets how many SSRCs are tracked per direction (at least 1); beyond it the least
    /// recently used SSRC's state is dropped (default [`DEFAULT_MAX_SSRCS`]).
    #[must_use]
    pub fn with_max_ssrcs(mut self, n: usize) -> Context {
        self.max_ssrcs = n.max(1);
        self
    }

    /// The profile.
    #[must_use]
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The rollover counter last used for sending (`protect_rtp`) on `ssrc`.
    #[must_use]
    pub fn send_roc(&self, ssrc: u32) -> Option<u32> {
        self.rtp_out.get(&ssrc).map(|s| (s.v >> 16) as u32)
    }

    /// The rollover counter of the highest packet received (`unprotect_rtp`) on `ssrc`.
    #[must_use]
    pub fn recv_roc(&self, ssrc: u32) -> Option<u32> {
        self.rtp_in.get(&ssrc).map(|s| (s.v.max() >> 16) as u32)
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Encrypts and authenticates an RTP packet: the payload (including any padding) is
    /// encrypted, the header (CSRCs and extension included) is not; the tag is appended. The
    /// rollover counter is tracked per SSRC from the sequence numbers.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an invalid RTP header, [`Error::IndexExhausted`] after 2^48
    /// packets on one SSRC.
    pub fn protect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let hlen = rtp_header_len(packet).ok_or(Error::Malformed)?;
        let ssrc = be32(packet, 8).ok_or(Error::Malformed)?;
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let tick = self.next_tick();
        let roc = match self.rtp_out.get(&ssrc) {
            Some(s) => estimate_roc(s.v, seq).ok_or(Error::IndexExhausted)?,
            None => 0,
        };
        let idx = index(roc, seq);
        let out = self.cipher.protect_rtp(packet, hlen, ssrc, roc);
        match self.rtp_out.get_mut(&ssrc) {
            Some(s) => {
                s.used = tick;
                s.v = s.v.max(idx);
            }
            None => {
                evict(&mut self.rtp_out, self.max_ssrcs);
                self.rtp_out.insert(ssrc, Slot { used: tick, v: idx });
            }
        }
        Ok(out)
    }

    /// Authenticates and decrypts an SRTP packet; returns the RTP packet. The packet index is
    /// estimated from the sequence number (RFC 3711 §3.3.1), checked against the replay
    /// window, the tag is verified before anything is decrypted, and only then is the replay
    /// window (and rollover counter) updated. The first packet of an SSRC starts with
    /// rollover counter 0.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::Replay`] (already received or too old) or
    /// [`Error::Authentication`].
    pub fn unprotect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let hlen = rtp_header_len(packet).ok_or(Error::Malformed)?;
        if packet.len() < hlen + self.cipher.rtp_tag_len() {
            return Err(Error::Malformed);
        }
        let ssrc = be32(packet, 8).ok_or(Error::Malformed)?;
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let roc = match self.rtp_in.get(&ssrc) {
            Some(s) => {
                let roc = estimate_roc(s.v.max(), seq).ok_or(Error::Replay)?;
                s.v.check(index(roc, seq))?;
                roc
            }
            None => 0,
        };
        let out = self.cipher.unprotect_rtp(packet, hlen, ssrc, roc)?;
        let tick = self.next_tick();
        let idx = index(roc, seq);
        match self.rtp_in.get_mut(&ssrc) {
            Some(s) => {
                s.used = tick;
                s.v.accept(idx);
            }
            None => {
                evict(&mut self.rtp_in, self.max_ssrcs);
                let w = ReplayWindow::new(self.window_words, idx);
                self.rtp_in.insert(ssrc, Slot { used: tick, v: w });
            }
        }
        Ok(out)
    }

    /// Encrypts and authenticates a (compound) RTCP packet: everything after the first 8
    /// bytes is encrypted, then the E flag and the 31-bit SRTCP index of the sender SSRC
    /// (bytes 4..8) and the tag (always 80 bits for the AES-CM profiles) are appended.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for fewer than 8 bytes or a version other than 2,
    /// [`Error::IndexExhausted`] after 2^31 packets on one SSRC.
    pub fn protect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let ssrc = rtcp_ssrc(packet)?;
        let tick = self.next_tick();
        let idx = self.rtcp_out.get(&ssrc).map_or(0, |s| s.v);
        if idx > MAX_SRTCP_INDEX {
            return Err(Error::IndexExhausted);
        }
        let out = self.cipher.protect_rtcp(packet, ssrc, idx);
        match self.rtcp_out.get_mut(&ssrc) {
            Some(s) => {
                s.used = tick;
                s.v = idx + 1;
            }
            None => {
                evict(&mut self.rtcp_out, self.max_ssrcs);
                self.rtcp_out.insert(
                    ssrc,
                    Slot {
                        used: tick,
                        v: idx + 1,
                    },
                );
            }
        }
        Ok(out)
    }

    /// Authenticates and decrypts an SRTCP packet; returns the compound RTCP packet. Packets
    /// with the E flag clear are authenticated but not decrypted. Replay protected per sender
    /// SSRC like [`unprotect_rtp`](Self::unprotect_rtp).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::Replay`] or [`Error::Authentication`].
    pub fn unprotect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let ssrc = rtcp_ssrc(packet)?;
        let tag = self.cipher.rtcp_tag_len();
        if packet.len() < 8 + 4 + tag {
            return Err(Error::Malformed);
        }
        let word_at = if self.profile.is_aead() {
            packet.len() - 4
        } else {
            packet.len() - tag - 4
        };
        let idx = u64::from(be32(packet, word_at).ok_or(Error::Malformed)? & !E_FLAG);
        if let Some(s) = self.rtcp_in.get(&ssrc) {
            s.v.check(idx)?;
        }
        let out = self.cipher.unprotect_rtcp(packet, ssrc)?;
        let tick = self.next_tick();
        match self.rtcp_in.get_mut(&ssrc) {
            Some(s) => {
                s.used = tick;
                s.v.accept(idx);
            }
            None => {
                evict(&mut self.rtcp_in, self.max_ssrcs);
                let w = ReplayWindow::new(self.window_words, idx);
                self.rtcp_in.insert(ssrc, Slot { used: tick, v: w });
            }
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn set_next_rtcp_index(&mut self, ssrc: u32, index: u32) {
        self.rtcp_out.insert(ssrc, Slot { used: 0, v: index });
    }
}

fn rtcp_ssrc(p: &[u8]) -> Result<u32, Error> {
    match p.first() {
        Some(b) if b >> 6 == 2 => be32(p, 4).ok_or(Error::Malformed),
        _ => Err(Error::Malformed),
    }
}

/// Drops the least recently used entry when `m` is full.
fn evict<T>(m: &mut HashMap<u32, Slot<T>>, max: usize) {
    while m.len() >= max {
        let Some(oldest) = m.iter().min_by_key(|(_, s)| s.used).map(|(k, _)| *k) else {
            return;
        };
        m.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roc_estimation() {
        // Appendix A cases.
        assert_eq!(estimate_roc(index(0, 100), 99), Some(0));
        assert_eq!(estimate_roc(index(0, 100), 40_000), None);
        assert_eq!(estimate_roc(index(1, 100), 40_000), Some(0));
        assert_eq!(estimate_roc(index(0, 100), 33_000), None);
        assert_eq!(estimate_roc(index(0, 65_535), 0), Some(1));
        assert_eq!(estimate_roc(index(0, 65_535), 65_534), Some(0));
        assert_eq!(estimate_roc(index(3, 40_000), 7_000), Some(4));
        assert_eq!(estimate_roc(index(u32::MAX, 65_000), 1), None);
    }

    #[test]
    fn header_len() {
        let mut p = vec![0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(rtp_header_len(&p), Some(12));
        p[0] = 0x91; // X + 1 CSRC
        p.extend_from_slice(&[0, 0, 0, 2]);
        assert_eq!(rtp_header_len(&p), None);
        p.extend_from_slice(&[0xbe, 0xde, 0, 1, 1, 2, 3, 4]);
        assert_eq!(rtp_header_len(&p), Some(24));
        p[0] = 0x40;
        assert_eq!(rtp_header_len(&p), None);
        assert_eq!(rtp_header_len(&[]), None);
    }
}
