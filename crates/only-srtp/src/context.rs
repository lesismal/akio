//! The per-direction SRTP/SRTCP context: master keys (with MKIs), session keys and per-SSRC
//! state.

use std::collections::HashMap;

use crate::cipher::{self, E_FLAG, GCM_TAG, Master, Session, Stream};
use crate::replay::ReplayWindow;
use crate::{Error, Profile};

/// Default replay window: 64 packets (RFC 3711 §3.3.2 minimum).
pub const DEFAULT_REPLAY_WINDOW: usize = 64;
/// Largest accepted replay window ([`Context::with_replay_window`] clamps to it).
pub const MAX_REPLAY_WINDOW: usize = 32_768;
/// Default number of SSRCs tracked per direction before the least recently used is evicted.
pub const DEFAULT_MAX_SSRCS: usize = 1024;
/// Most master keys one context holds ([`Context::add_master_key`]).
pub const MAX_MASTER_KEYS: usize = 16;
/// Longest MKI (the DTLS-SRTP `srtp_mki<0..255>` limit, RFC 5764 §4.1.1).
pub const MAX_MKI_LEN: usize = 255;
/// Largest key derivation rate (RFC 3711 §8.1: a power of two up to 2^24).
pub const MAX_KEY_DERIVATION_RATE: u32 = 1 << 24;

/// Largest SRTCP index (31 bits).
const MAX_SRTCP_INDEX: u32 = 0x7fff_ffff;

/// A value with the tick of its last use, for least-recently-used eviction.
#[derive(Debug)]
struct Slot<T> {
    used: u64,
    v: T,
}

/// One master key with the session keys derived from it.
struct Key {
    mki: Vec<u8>,
    master: Master,
    /// SRTP session keys and the `r` (index DIV key derivation rate) they were derived at.
    rtp: Session,
    rtp_r: u64,
    rtcp: Session,
    rtcp_r: u64,
}

/// One direction of an SRTP session (RFC 3711): one or more master keys (told apart by their
/// MKI), the session keys derived from them, and per-SSRC rollover counters, replay windows
/// and SRTCP indices.
///
/// Use one `Context` for what you send (`protect_*`) and another, keyed with the remote master
/// key, for what you receive (`unprotect_*`). Sending and receiving state are kept apart, so
/// using one context both ways does not corrupt either.
pub struct Context {
    profile: Profile,
    keys: Vec<Key>,
    /// Index in `keys` of the master key `protect_*` uses.
    send: usize,
    /// MKI length carried in every packet (0: no MKI).
    mki_len: usize,
    /// log2 of the key derivation rate, `None` for rate 0.
    kdr_shift: Option<u32>,
    /// RFC 6904: header extension IDs to encrypt (bit set over 0..=255).
    hdr_ids: [u64; 4],
    /// RFC 9335: encrypt CSRCs and header extensions.
    cryptex: bool,
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
            .field("master_keys", &self.keys.len())
            .field("mki_len", &self.mki_len)
            .field(
                "key_derivation_rate",
                &self.kdr_shift.map_or(0, |s| 1u32 << s),
            )
            .field("cryptex", &self.cryptex)
            .field("replay_window", &(self.window_words * 64))
            .field("ssrcs_out", &self.rtp_out.len())
            .field("ssrcs_in", &self.rtp_in.len())
            .finish_non_exhaustive()
    }
}

/// The parsed fixed part of an RTP header.
#[derive(Clone, Copy)]
struct RtpHeader {
    /// Header length: fixed header, CSRCs and header extension.
    len: usize,
    /// CSRC count.
    cc: usize,
    /// Offset of the header extension (its 4-byte header), if the X bit is set.
    ext: Option<usize>,
    ssrc: u32,
    seq: u16,
}

fn parse_rtp(p: &[u8]) -> Option<RtpHeader> {
    let b0 = *p.first()?;
    if p.len() < 12 || b0 >> 6 != 2 {
        return None;
    }
    let cc = usize::from(b0 & 0x0f);
    let mut n = 12 + 4 * cc;
    let mut ext = None;
    if b0 & 0x10 != 0 {
        let e = p.get(n..n + 4)?;
        ext = Some(n);
        n += 4 + 4 * usize::from(u16::from_be_bytes([e[2], e[3]]));
    }
    (n <= p.len()).then(|| RtpHeader {
        len: n,
        cc,
        ext,
        ssrc: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
        seq: u16::from_be_bytes([p[2], p[3]]),
    })
}

/// RTP header length (fixed header, CSRCs and header extension), or `None` when `p` is not
/// a well-formed RTP version 2 header.
#[cfg(test)]
pub(crate) fn rtp_header_len(p: &[u8]) -> Option<usize> {
    parse_rtp(p).map(|h| h.len)
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
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

/// Cryptex (RFC 9335 §5) "defined by profile" values.
const CRYPTEX_ONE_BYTE: u16 = 0xc0de;
const CRYPTEX_TWO_BYTE: u16 = 0xc2de;

/// Swaps the CSRC list and the 4-byte extension header so that the cryptex AAD (fixed header
/// and extension header) and the encrypted portion are contiguous (RFC 9335 §6.2, Figure 2);
/// `back` undoes it.
fn cryptex_swap(buf: &mut [u8], cc: usize, back: bool) {
    let region = &mut buf[12..12 + 4 * cc + 4];
    if back {
        region.rotate_left(4);
    } else {
        region.rotate_right(4);
    }
}

/// Fills `out` with the SRTP packet for `p` (header `h`) under `s`.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn seal_rtp(
    profile: Profile,
    s: &Session,
    cryptex: bool,
    hdr_ids: &[u64; 4],
    mki: &[u8],
    p: &[u8],
    h: RtpHeader,
    roc: u32,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let idx = index(roc, h.seq);
    if cryptex && profile.encrypts() && (h.cc > 0 || h.ext.is_some()) {
        let csrc_end = 12 + 4 * h.cc;
        match h.ext {
            Some(off) => {
                let marker = match be16(p, off) {
                    0xbede => CRYPTEX_ONE_BYTE,
                    0x1000 => CRYPTEX_TWO_BYTE,
                    _ => return Err(Error::Unsupported),
                };
                out.extend_from_slice(p);
                out[off..off + 2].copy_from_slice(&marker.to_be_bytes());
            }
            None => {
                // CSRCs without an extension: add an empty one (RFC 9335 §5.1).
                out.extend_from_slice(&p[..csrc_end]);
                out[0] |= 0x10;
                out.extend_from_slice(&[0xc0, 0xde, 0, 0]);
                out.extend_from_slice(&p[csrc_end..]);
            }
        }
        cryptex_swap(out, h.cc, false);
        s.seal_rtp(out, 16, h.ssrc, roc, h.seq);
        cryptex_swap(out, h.cc, true);
    } else {
        out.extend_from_slice(p);
        if let Some(off) = h.ext {
            s.crypt_header_extension(hdr_ids, &mut out[off..h.len], h.ssrc, idx)?;
        }
        s.seal_rtp(out, h.len, h.ssrc, roc, h.seq);
    }
    if profile.is_aead() {
        if !mki.is_empty() {
            out.extend_from_slice(mki);
        }
    } else {
        let mac = s.mac(out, &roc.to_be_bytes());
        if !mki.is_empty() {
            out.extend_from_slice(mki);
        }
        out.extend_from_slice(&mac[..profile.rtp_tag_len()]);
    }
    Ok(())
}

/// Verifies and decrypts the SRTP packet `p` (header `h`, trailer already checked to fit)
/// under `s` into `out`.
#[allow(clippy::too_many_arguments)]
fn open_rtp(
    profile: Profile,
    s: &Session,
    cryptex: bool,
    hdr_ids: &[u64; 4],
    mki_len: usize,
    p: &[u8],
    h: RtpHeader,
    roc: u32,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    // Cryptex means nothing without encryption: a NULL receiver leaves the marker alone, as
    // a NULL sender never sets it.
    let cryptex = cryptex
        && profile.encrypts()
        && h.ext
            .is_some_and(|off| matches!(be16(p, off), CRYPTEX_ONE_BYTE | CRYPTEX_TWO_BYTE));
    let aad = if cryptex { 16 } else { h.len };
    if profile.is_aead() {
        let ct_end = p.len() - mki_len;
        let (data, tag) = p[..ct_end].split_at(ct_end - GCM_TAG);
        out.extend_from_slice(data);
        if cryptex {
            cryptex_swap(out, h.cc, false);
        }
        s.open_rtp(out, aad, tag, h.ssrc, roc, h.seq)?;
    } else {
        let tag_len = profile.rtp_tag_len();
        let auth_end = p.len() - tag_len - mki_len;
        let mac = s.mac(&p[..auth_end], &roc.to_be_bytes());
        if !only_crypto::ct_eq(&mac[..tag_len], &p[p.len() - tag_len..]) {
            return Err(Error::Authentication);
        }
        out.extend_from_slice(&p[..auth_end]);
        if cryptex {
            cryptex_swap(out, h.cc, false);
        }
        s.open_rtp(out, aad, &[], h.ssrc, roc, h.seq)?;
    }
    match h.ext {
        Some(off) if cryptex => {
            cryptex_swap(out, h.cc, true);
            let plain: u16 = if be16(out, off) == CRYPTEX_ONE_BYTE {
                0xbede
            } else {
                0x1000
            };
            out[off..off + 2].copy_from_slice(&plain.to_be_bytes());
        }
        Some(off) => {
            s.crypt_header_extension(hdr_ids, &mut out[off..h.len], h.ssrc, index(roc, h.seq))?;
        }
        None => {}
    }
    Ok(())
}

impl Context {
    /// A context for `profile` keyed with the master key and salt (for example from
    /// DTLS-SRTP), without MKI. Session keys are derived with key derivation rate 0.
    ///
    /// # Errors
    ///
    /// [`Error::KeyLength`] when the lengths do not match [`Profile::key_len`] /
    /// [`Profile::salt_len`].
    pub fn new(profile: Profile, master_key: &[u8], master_salt: &[u8]) -> Result<Context, Error> {
        let key = Context::make_key(profile, Vec::new(), master_key, master_salt, false)?;
        Ok(Context::from_key(profile, key, 0))
    }

    /// A context whose packets carry the Master Key Identifier `mki` (1 to [`MAX_MKI_LEN`]
    /// bytes; RFC 3711 §3.1, RFC 5764 §4.1.3). More master keys with MKIs of the same length
    /// can be added with [`add_master_key`](Self::add_master_key) for re-keying.
    ///
    /// # Errors
    ///
    /// [`Error::KeyLength`], or [`Error::Config`] for an empty or too long MKI.
    pub fn new_with_mki(
        profile: Profile,
        mki: &[u8],
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<Context, Error> {
        if mki.is_empty() || mki.len() > MAX_MKI_LEN {
            return Err(Error::Config);
        }
        let key = Context::make_key(profile, mki.to_vec(), master_key, master_salt, false)?;
        Ok(Context::from_key(profile, key, mki.len()))
    }

    fn make_key(
        profile: Profile,
        mki: Vec<u8>,
        master_key: &[u8],
        master_salt: &[u8],
        hdr: bool,
    ) -> Result<Key, Error> {
        // Keys start at r = 0 whatever the key derivation rate.
        let master = Master::new(profile, master_key, master_salt)?;
        Ok(Key {
            rtp: Session::derive(profile, &master, Stream::Rtp, 0, hdr)?,
            rtp_r: 0,
            rtcp: Session::derive(profile, &master, Stream::Rtcp, 0, false)?,
            rtcp_r: 0,
            mki,
            master,
        })
    }

    fn from_key(profile: Profile, key: Key, mki_len: usize) -> Context {
        Context {
            profile,
            keys: vec![key],
            send: 0,
            mki_len,
            kdr_shift: None,
            hdr_ids: [0; 4],
            cryptex: false,
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
    pub(crate) fn from_session_keys(
        profile: Profile,
        key: &[u8],
        salt: &[u8],
        auth: &[u8],
    ) -> Context {
        let mut ctx = Context::new(
            profile,
            &vec![0; profile.key_len()],
            &vec![0; profile.salt_len()],
        )
        .expect("lengths");
        ctx.keys[0].rtp = Session::from_keys(profile, key, salt, auth).expect("keys");
        ctx.keys[0].rtcp = Session::from_keys(profile, key, salt, auth).expect("keys");
        ctx
    }

    fn hdr_enabled(&self) -> bool {
        self.hdr_ids != [0; 4]
    }

    /// Re-derives every master key's session keys at `r` = 0 (after a configuration change).
    fn rederive(&mut self) -> Result<(), Error> {
        let hdr = self.hdr_enabled();
        for k in &mut self.keys {
            k.rtp = Session::derive(self.profile, &k.master, Stream::Rtp, 0, hdr)?;
            k.rtcp = Session::derive(self.profile, &k.master, Stream::Rtcp, 0, false)?;
            k.rtp_r = 0;
            k.rtcp_r = 0;
        }
        Ok(())
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

    /// Sets the key derivation rate (RFC 3711 §4.3.1): 0 (the default: session keys are
    /// derived once) or a power of two up to [`MAX_KEY_DERIVATION_RATE`], in which case
    /// session keys are derived again from the master key for every `rate` packets of index
    /// (SRTP: the 48-bit packet index; SRTCP: the 31-bit SRTCP index). It applies to every
    /// master key of the context, and must match the peer's.
    ///
    /// The session keys of the last `r` used are kept per master key; a packet at another
    /// `r` (a new block of indices, a reordered packet from the previous block, another SSRC
    /// at a different index) derives its keys first.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for a rate that is not 0 or a power of two up to 2^24.
    pub fn with_key_derivation_rate(mut self, rate: u32) -> Result<Context, Error> {
        self.kdr_shift = match rate {
            0 => None,
            r if r.is_power_of_two() && r <= MAX_KEY_DERIVATION_RATE => Some(r.trailing_zeros()),
            _ => return Err(Error::Config),
        };
        self.rederive()?;
        Ok(self)
    }

    /// Encrypts the RTP header extension elements with these IDs (RFC 6904; RFC 7714 §8.3
    /// for AEAD): one-byte (`0xBEDE`) IDs 1-14 or two-byte (`0x100X`) IDs 1-255, as negotiated
    /// with `a=extmap:<id> urn:ietf:params:rtp-hdrext:encrypt <uri>`. Only the element data
    /// is encrypted (IDs, lengths and padding stay in the clear), with a keystream from the
    /// header encryption key and salt (labels 6 and 7). ID 0 is ignored; an empty list turns
    /// header extension encryption off. Has no effect with a NULL profile (RFC 6904 §3.2).
    /// Must match the peer's.
    #[must_use]
    pub fn with_encrypted_header_extensions(mut self, ids: &[u8]) -> Context {
        self.hdr_ids = [0; 4];
        for &id in ids.iter().filter(|&&id| id != 0) {
            self.hdr_ids[usize::from(id) / 64] |= 1 << (id % 64);
        }
        // Derivation only fails for bad key lengths, which `new` already ruled out.
        let _ = self.rederive();
        self
    }

    /// Uses cryptex (RFC 9335): with `true`, `protect_rtp` encrypts the CSRCs and the whole
    /// header extension body (IDs, lengths and values) of every packet that has either,
    /// marking the extension `0xC0DE` / `0xC2DE` (a packet with CSRCs but no extension gets an
    /// empty one), and `unprotect_rtp` decrypts packets so marked (and still accepts
    /// packets without cryptex). Has no effect with a NULL profile. Negotiated
    /// with `a=cryptex`; a packet sent with cryptex is never also RFC 6904 encrypted.
    #[must_use]
    pub fn with_cryptex(mut self, on: bool) -> Context {
        self.cryptex = on;
        self
    }

    /// Adds a master key with MKI `mki` (of the context's MKI length), for re-keying: it
    /// unprotects packets that carry its MKI at once, and protects what is sent after
    /// [`set_send_mki`](Self::set_send_mki).
    ///
    /// # Errors
    ///
    /// [`Error::KeyLength`]; [`Error::Config`] when the context has no MKI, `mki` has another
    /// length or is already used, or the context holds [`MAX_MASTER_KEYS`] keys.
    pub fn add_master_key(
        &mut self,
        mki: &[u8],
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<(), Error> {
        if self.mki_len == 0
            || mki.len() != self.mki_len
            || self.keys.len() >= MAX_MASTER_KEYS
            || self.keys.iter().any(|k| k.mki == mki)
        {
            return Err(Error::Config);
        }
        let key = Context::make_key(
            self.profile,
            mki.to_vec(),
            master_key,
            master_salt,
            self.hdr_enabled(),
        )?;
        self.keys.push(key);
        Ok(())
    }

    /// Protects what is sent from now on with the master key whose MKI is `mki`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownMki`] when no master key has this MKI.
    pub fn set_send_mki(&mut self, mki: &[u8]) -> Result<(), Error> {
        self.send = self.find_key(mki).ok_or(Error::UnknownMki)?;
        Ok(())
    }

    /// Forgets the master key whose MKI is `mki` (packets carrying it are then rejected with
    /// [`Error::UnknownMki`]). Returns false when there is no such key or it is the one
    /// sending uses.
    pub fn remove_master_key(&mut self, mki: &[u8]) -> bool {
        match self.find_key(mki) {
            Some(i) if i != self.send => {
                self.keys.remove(i);
                if i < self.send {
                    self.send -= 1;
                }
                true
            }
            _ => false,
        }
    }

    /// The MKI of the master key protecting what is sent; `None` when the context has no
    /// MKI.
    #[must_use]
    pub fn send_mki(&self) -> Option<&[u8]> {
        (self.mki_len > 0).then(|| self.keys[self.send].mki.as_slice())
    }

    /// The MKI length every packet carries (0: none).
    #[must_use]
    pub fn mki_len(&self) -> usize {
        self.mki_len
    }

    fn find_key(&self, mki: &[u8]) -> Option<usize> {
        self.keys.iter().position(|k| k.mki == mki)
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

    /// Bytes `protect_rtp` adds at most (MKI, tag, and 4 for a cryptex empty extension).
    fn rtp_overhead(&self) -> usize {
        self.mki_len + self.profile.rtp_tag_len() + if self.cryptex { 4 } else { 0 }
    }

    /// Encrypts and authenticates an RTP packet: the payload (including any padding) is
    /// encrypted; the header is authenticated but stays in the clear, except header extension
    /// elements chosen for RFC 6904 encryption and, with [cryptex](Self::with_cryptex), the
    /// CSRCs and header extension body. The MKI (if any) and the tag are appended. The
    /// rollover counter is tracked per SSRC from the sequence numbers.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an invalid RTP header (or a header extension element running
    /// past the extension, with RFC 6904), [`Error::IndexExhausted`] after 2^48 packets on one
    /// SSRC, [`Error::Unsupported`] for a header extension cryptex cannot carry (not one-byte
    /// `0xBEDE` or two-byte `0x1000`).
    pub fn protect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(packet.len() + self.rtp_overhead());
        self.protect_rtp_into(packet, &mut out)?;
        Ok(out)
    }

    /// [`protect_rtp`](Self::protect_rtp) into `out` (cleared first, left empty on error), so
    /// a reused buffer protects without allocating.
    ///
    /// # Errors
    ///
    /// As [`protect_rtp`](Self::protect_rtp).
    pub fn protect_rtp_into(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        out.clear();
        let h = parse_rtp(packet).ok_or(Error::Malformed)?;
        // One lookup per packet (the slot is updated at the end; new SSRCs are inserted there).
        let slot = self.rtp_out.get_mut(&h.ssrc);
        let roc = match &slot {
            Some(s) => estimate_roc(s.v, h.seq).ok_or(Error::IndexExhausted)?,
            None => 0,
        };
        let idx = index(roc, h.seq);
        if let Some(shift) = self.kdr_shift {
            let hdr = self.hdr_ids != [0; 4];
            let k = &mut self.keys[self.send];
            refresh(self.profile, k, Stream::Rtp, idx >> shift, hdr)?;
        }
        let k = &self.keys[self.send];
        let mki = &k.mki;
        if let Err(e) = seal_rtp(
            self.profile,
            &k.rtp,
            self.cryptex,
            &self.hdr_ids,
            mki,
            packet,
            h,
            roc,
            out,
        ) {
            out.clear();
            return Err(e);
        }
        self.tick += 1;
        let tick = self.tick;
        match slot {
            Some(s) => {
                s.used = tick;
                s.v = s.v.max(idx);
            }
            None => {
                evict(&mut self.rtp_out, self.max_ssrcs);
                self.rtp_out.insert(h.ssrc, Slot { used: tick, v: idx });
            }
        }
        Ok(())
    }

    /// Authenticates and decrypts an SRTP packet; returns the RTP packet. The master key is
    /// chosen by the MKI (if the context uses MKIs), the packet index estimated from the
    /// sequence number (RFC 3711 §3.3.1) and checked against the replay window, the tag
    /// verified before anything is decrypted, and only then are the replay window (and
    /// rollover counter) updated. The first packet of an SSRC starts with rollover counter 0.
    /// A cryptex packet comes back with its extension marked `0xBEDE` / `0x1000` again.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::UnknownMki`], [`Error::Replay`] (already received or
    /// too old) or [`Error::Authentication`].
    pub fn unprotect_rtp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(packet.len());
        self.unprotect_rtp_into(packet, &mut out)?;
        Ok(out)
    }

    /// [`unprotect_rtp`](Self::unprotect_rtp) into `out` (cleared first, left empty on
    /// error), so a reused buffer unprotects without allocating.
    ///
    /// # Errors
    ///
    /// As [`unprotect_rtp`](Self::unprotect_rtp).
    pub fn unprotect_rtp_into(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        out.clear();
        let h = parse_rtp(packet).ok_or(Error::Malformed)?;
        let tag_len = self.profile.rtp_tag_len();
        if packet.len() < h.len + tag_len + self.mki_len {
            return Err(Error::Malformed);
        }
        let ki = if self.mki_len == 0 {
            0
        } else {
            let at = if self.profile.is_aead() {
                packet.len() - self.mki_len
            } else {
                packet.len() - tag_len - self.mki_len
            };
            self.find_key(&packet[at..at + self.mki_len])
                .ok_or(Error::UnknownMki)?
        };
        let slot = self.rtp_in.get_mut(&h.ssrc);
        let roc = match &slot {
            Some(s) => {
                let roc = estimate_roc(s.v.max(), h.seq).ok_or(Error::Replay)?;
                s.v.check(index(roc, h.seq))?;
                roc
            }
            None => 0,
        };
        let idx = index(roc, h.seq);
        let r = self.kdr_shift.map_or(0, |s| idx >> s);
        let k = &self.keys[ki];
        // Keys at another `r` are derived into a box (rare; keeps this frame small) and replace
        // the cached ones only once the packet authenticated.
        let fresh = if r == k.rtp_r {
            None
        } else {
            Some(derive_boxed(
                self.profile,
                &k.master,
                Stream::Rtp,
                r,
                self.hdr_ids != [0; 4],
            )?)
        };
        let res = open_rtp(
            self.profile,
            fresh.as_deref().unwrap_or(&k.rtp),
            self.cryptex,
            &self.hdr_ids,
            self.mki_len,
            packet,
            h,
            roc,
            out,
        );
        if let Err(e) = res {
            out.clear();
            return Err(e);
        }
        if let Some(s) = fresh {
            install(&mut self.keys[ki], Stream::Rtp, s, r);
        }
        self.tick += 1;
        let tick = self.tick;
        match slot {
            Some(s) => {
                s.used = tick;
                s.v.accept(idx);
            }
            None => {
                evict(&mut self.rtp_in, self.max_ssrcs);
                let w = ReplayWindow::new(self.window_words, idx);
                self.rtp_in.insert(h.ssrc, Slot { used: tick, v: w });
            }
        }
        Ok(())
    }

    /// Encrypts and authenticates a (compound) RTCP packet: everything after the first 8
    /// bytes is encrypted, then the E flag and the 31-bit SRTCP index of the sender SSRC
    /// (bytes 4..8), the MKI (if any) and the tag (always 80 bits for the HMAC-SHA1
    /// profiles) are appended. With a NULL profile the E flag is clear.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for fewer than 8 bytes or a version other than 2,
    /// [`Error::IndexExhausted`] after 2^31 packets on one SSRC.
    pub fn protect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out =
            Vec::with_capacity(packet.len() + 4 + self.mki_len + self.profile.rtcp_tag_len());
        self.protect_rtcp_into(packet, &mut out)?;
        Ok(out)
    }

    /// [`protect_rtcp`](Self::protect_rtcp) into `out` (cleared first, left empty on error).
    ///
    /// # Errors
    ///
    /// As [`protect_rtcp`](Self::protect_rtcp).
    pub fn protect_rtcp_into(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        out.clear();
        let ssrc = rtcp_ssrc(packet)?;
        let slot = self.rtcp_out.get_mut(&ssrc);
        let idx = slot.as_ref().map_or(0, |s| s.v);
        if idx > MAX_SRTCP_INDEX {
            return Err(Error::IndexExhausted);
        }
        if let Some(shift) = self.kdr_shift {
            let k = &mut self.keys[self.send];
            refresh(
                self.profile,
                k,
                Stream::Rtcp,
                u64::from(idx) >> shift,
                false,
            )?;
        }
        let k = &self.keys[self.send];
        let s = &k.rtcp;
        let e = if self.profile.encrypts() { E_FLAG } else { 0 };
        let word = (e | idx).to_be_bytes();
        out.extend_from_slice(packet);
        if let Some(g) = s.gcm() {
            let iv = cipher::gcm_rtcp_iv(&s.salt, ssrc, idx);
            let mut aad = [0u8; 12];
            aad[..8].copy_from_slice(&packet[..8]);
            aad[8..].copy_from_slice(&word);
            let tag = g.encrypt_in_place_detached(&iv, &aad, &mut out[8..]);
            out.extend_from_slice(&tag);
            out.extend_from_slice(&word);
            out.extend_from_slice(&k.mki);
        } else {
            s.ctr_rtcp(&mut out[8..], ssrc, idx);
            out.extend_from_slice(&word);
            let mac = s.mac(out, &[]);
            out.extend_from_slice(&k.mki);
            out.extend_from_slice(&mac[..self.profile.rtcp_tag_len()]);
        }
        self.tick += 1;
        let tick = self.tick;
        match slot {
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
        Ok(())
    }

    /// Authenticates and decrypts an SRTCP packet; returns the compound RTCP packet. Packets
    /// with the E flag clear are authenticated but not decrypted. Replay protected per sender
    /// SSRC like [`unprotect_rtp`](Self::unprotect_rtp).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], [`Error::UnknownMki`], [`Error::Replay`] or
    /// [`Error::Authentication`].
    pub fn unprotect_rtcp(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(packet.len());
        self.unprotect_rtcp_into(packet, &mut out)?;
        Ok(out)
    }

    /// [`unprotect_rtcp`](Self::unprotect_rtcp) into `out` (cleared first, left empty on
    /// error).
    ///
    /// # Errors
    ///
    /// As [`unprotect_rtcp`](Self::unprotect_rtcp).
    pub fn unprotect_rtcp_into(&mut self, packet: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        out.clear();
        let ssrc = rtcp_ssrc(packet)?;
        let tag_len = self.profile.rtcp_tag_len();
        let m = self.mki_len;
        if packet.len() < 8 + 4 + tag_len + m {
            return Err(Error::Malformed);
        }
        let aead = self.profile.is_aead();
        // Layout: AEAD `data | tag | word | MKI`, HMAC `data | word | MKI | tag`.
        let (word_at, mki_at) = if aead {
            (packet.len() - m - 4, packet.len() - m)
        } else {
            (packet.len() - tag_len - m - 4, packet.len() - tag_len - m)
        };
        let ki = if m == 0 {
            0
        } else {
            self.find_key(&packet[mki_at..mki_at + m])
                .ok_or(Error::UnknownMki)?
        };
        let word = be32(packet, word_at).ok_or(Error::Malformed)?;
        let idx = word & !E_FLAG;
        let slot = self.rtcp_in.get_mut(&ssrc);
        if let Some(s) = &slot {
            s.v.check(u64::from(idx))?;
        }
        let r = self.kdr_shift.map_or(0, |s| u64::from(idx) >> s);
        let k = &self.keys[ki];
        let fresh = if r == k.rtcp_r {
            None
        } else {
            Some(derive_boxed(
                self.profile,
                &k.master,
                Stream::Rtcp,
                r,
                false,
            )?)
        };
        let s = fresh.as_deref().unwrap_or(&k.rtcp);
        let res = if let Some(g) = s.gcm() {
            let data_end = word_at - GCM_TAG;
            let tag = &packet[data_end..word_at];
            let iv = cipher::gcm_rtcp_iv(&s.salt, ssrc, idx);
            out.extend_from_slice(&packet[..data_end]);
            let opened = if word & E_FLAG != 0 {
                let mut aad = [0u8; 12];
                aad[..8].copy_from_slice(&packet[..8]);
                aad[8..].copy_from_slice(&word.to_be_bytes());
                g.decrypt_in_place_detached(&iv, &aad, &mut out[8..], tag)
            } else {
                // RFC 7714 §9.2: unencrypted SRTCP, the whole packet is AAD.
                out.extend_from_slice(&word.to_be_bytes());
                let opened = g.decrypt_in_place_detached(&iv, &out[..], &mut [], tag);
                out.truncate(data_end);
                opened
            };
            opened.map_err(|_| Error::Authentication)
        } else {
            let auth_end = word_at + 4;
            let mac = s.mac(&packet[..auth_end], &[]);
            if only_crypto::ct_eq(&mac[..tag_len], &packet[packet.len() - tag_len..]) {
                out.extend_from_slice(&packet[..word_at]);
                if word & E_FLAG != 0 {
                    s.ctr_rtcp(&mut out[8..], ssrc, idx);
                }
                Ok(())
            } else {
                Err(Error::Authentication)
            }
        };
        if let Err(e) = res {
            out.clear();
            return Err(e);
        }
        if let Some(s) = fresh {
            install(&mut self.keys[ki], Stream::Rtcp, s, r);
        }
        self.tick += 1;
        let tick = self.tick;
        match slot {
            Some(s) => {
                s.used = tick;
                s.v.accept(u64::from(idx));
            }
            None => {
                evict(&mut self.rtcp_in, self.max_ssrcs);
                let w = ReplayWindow::new(self.window_words, u64::from(idx));
                self.rtcp_in.insert(ssrc, Slot { used: tick, v: w });
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_next_rtcp_index(&mut self, ssrc: u32, index: u32) {
        self.rtcp_out.insert(ssrc, Slot { used: 0, v: index });
    }

    #[cfg(test)]
    pub(crate) fn set_send_index(&mut self, ssrc: u32, index: u64) {
        self.rtp_out.insert(ssrc, Slot { used: 0, v: index });
    }
}

/// Makes `k`'s `stream` session keys those of `r` (key derivation rate). Out of line: it is
/// rare, and its session temporary would bloat the callers' frames.
#[cold]
#[inline(never)]
fn refresh(profile: Profile, k: &mut Key, stream: Stream, r: u64, hdr: bool) -> Result<(), Error> {
    let (session, cur) = match stream {
        Stream::Rtp => (&mut k.rtp, &mut k.rtp_r),
        Stream::Rtcp => (&mut k.rtcp, &mut k.rtcp_r),
    };
    if r != *cur {
        *session = Session::derive(profile, &k.master, stream, r, hdr)?;
        *cur = r;
    }
    Ok(())
}

/// [`Session::derive`] into a box, out of line (the key derivation rate path).
#[cold]
#[inline(never)]
fn derive_boxed(
    profile: Profile,
    master: &Master,
    stream: Stream,
    r: u64,
    hdr: bool,
) -> Result<Box<Session>, Error> {
    Ok(Box::new(Session::derive(profile, master, stream, r, hdr)?))
}

/// Makes `s` (derived at `r`) the cached `stream` session keys of `k`.
#[cold]
#[inline(never)]
fn install(k: &mut Key, stream: Stream, s: Box<Session>, r: u64) {
    match stream {
        Stream::Rtp => {
            k.rtp = *s;
            k.rtp_r = r;
        }
        Stream::Rtcp => {
            k.rtcp = *s;
            k.rtcp_r = r;
        }
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
