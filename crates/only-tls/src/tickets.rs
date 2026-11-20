//! Session ticket keys that rotate (ADR-062): one key seals new tickets, the ones before it
//! still open the tickets they sealed, for a while.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use only_crypto::chacha::ChaCha20Poly1305;
use only_crypto::hash::Sha256;

use crate::proto::common::{now_secs, random};
use crate::proto::session::Session;

/// Keys a set holds at most: the one sealing and the ones before it that still open tickets.
pub const MAX_TICKET_KEYS: usize = 4;

/// One ticket key: `name(16) || key(32)`, the name going in front of every ticket it seals.
pub(crate) struct TicketKey {
    name: [u8; 16],
    key: ChaCha20Poly1305,
}

impl TicketKey {
    pub(crate) fn new(bytes: &[u8; 48]) -> TicketKey {
        let mut name = [0u8; 16];
        name.copy_from_slice(&bytes[..16]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[16..]);
        TicketKey {
            name,
            key: ChaCha20Poly1305::new(&key),
        }
    }

    /// Seals `s`: `name || nonce(12) || ChaCha20-Poly1305(session)`, the name as AAD.
    pub(crate) fn seal(&self, s: &Session) -> Option<Vec<u8>> {
        let nonce = random::<12>().ok()?;
        let mut out = self.name.to_vec();
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&self.key.encrypt(&nonce, &self.name, &s.encode()));
        Some(out)
    }

    /// Opens a ticket this key sealed (`None` for another key's or a forged one).
    pub(crate) fn open(&self, ticket: &[u8]) -> Option<Session> {
        if ticket.len() < 16 + 12 + 16 || ticket[..16] != self.name {
            return None;
        }
        let nonce: [u8; 12] = ticket[16..28].try_into().ok()?;
        let plain = self.key.decrypt(&nonce, &self.name, &ticket[28..]).ok()?;
        Session::decode(&plain)
    }
}

/// The keys in force: `keys[0]` seals, all open.
struct KeySet {
    /// The rotation period the set was made for (Unix seconds / period), for scheduled keys.
    epoch: u64,
    keys: Vec<TicketKey>,
}

enum Schedule {
    /// Rotated by the application ([`TicketKeys::rotate`], [`TicketKeys::set`]).
    Manual,
    /// A new random key every `period` seconds, the previous one still opening tickets.
    Random { period: u64 },
    /// Keys derived from a shared secret per `period` seconds: every server with the secret
    /// has the same keys at the same time.
    Derived { prk: [u8; 32], period: u64 },
}

struct Inner {
    schedule: Schedule,
    set: RwLock<KeySet>,
}

/// Session ticket keys that can rotate while servers run (ADR-062), for
/// [`ServerConfigBuilder::session_ticket_keys`](crate::ServerConfigBuilder::session_ticket_keys).
///
/// One key seals new tickets; up to [`MAX_TICKET_KEYS`] `- 1` earlier ones still open the
/// tickets they sealed, so rotating does not cost the clients holding them a full handshake.
/// Clones share the keys: give the same `TicketKeys` to several configurations (SNI variants,
/// TCP and QUIC) and they rotate together. Three ways to rotate:
///
/// - [`new`](Self::new), then [`rotate`](Self::rotate) / [`set`](Self::set) whenever the
///   application decides, e.g. with keys from a secret store pushed to every server (the
///   same keys on every server keeps the [`session_ticket_key`](crate::ServerConfigBuilder::session_ticket_key)
///   sharing: a ticket from one server resumes on the others, through the rotation);
/// - [`derived`](Self::derived): every period a key derived from a secret shared by the
///   servers (HKDF-SHA256 of the period number), so servers sharing tickets rotate in step
///   with nothing to coordinate but the secret and their clocks;
/// - [`random`](Self::random): a fresh random key every period, private to the process.
///
/// Scheduled keys change when a handshake needs them after the period ended (no thread).
/// Tickets advertise a lifetime of at most one period, the time they are sure to open.
#[derive(Clone)]
pub struct TicketKeys(Arc<Inner>);

impl fmt::Debug for TicketKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match self.0.schedule {
            Schedule::Manual => "manual",
            Schedule::Random { .. } => "random",
            Schedule::Derived { .. } => "derived",
        };
        f.debug_struct("TicketKeys")
            .field("mode", &mode)
            .field("period_secs", &self.period())
            .field("keys", &self.0.set.read().map_or(0, |s| s.keys.len()))
            .finish_non_exhaustive()
    }
}

/// The period in whole seconds, at least one.
fn secs(period: Duration) -> u64 {
    period.as_secs().max(1)
}

impl TicketKeys {
    /// Keys starting with `key` (16 bytes of key name, then a 32-byte ChaCha20-Poly1305 key;
    /// secret and random), rotated by the application.
    pub fn new(key: [u8; 48]) -> TicketKeys {
        TicketKeys::with(Schedule::Manual, 0, vec![TicketKey::new(&key)])
    }

    /// A random key every `period` (at least a second), the previous one still opening
    /// tickets for one more period. Private to this process: servers that share tickets use
    /// [`derived`](Self::derived) or [`new`](Self::new) with keys they share.
    pub fn random(period: Duration) -> std::io::Result<TicketKeys> {
        let period = secs(period);
        let epoch = now_secs() / period;
        let key = TicketKey::new(&random::<48>().map_err(std::io::Error::other)?);
        Ok(TicketKeys::with(
            Schedule::Random { period },
            epoch,
            vec![key],
        ))
    }

    /// Keys derived from `secret` (at least 32 random bytes, the same on every server that
    /// should accept the others' tickets): the key of period `n` (Unix time / `period`, at
    /// least a second) seals, the keys of periods `n - 1` and `n + 1` also open tickets (the
    /// previous period's tickets, and a server whose clock is ahead by less than a period).
    pub fn derived(secret: &[u8], period: Duration) -> TicketKeys {
        let period = secs(period);
        let prk = only_crypto::kdf::hkdf_extract::<Sha256>(b"only-tls ticket keys", secret);
        let mut p = [0u8; 32];
        p.copy_from_slice(prk.as_ref());
        let epoch = now_secs() / period;
        TicketKeys::with(
            Schedule::Derived { prk: p, period },
            epoch,
            derived_set(&p, epoch),
        )
    }

    fn with(schedule: Schedule, epoch: u64, keys: Vec<TicketKey>) -> TicketKeys {
        TicketKeys(Arc::new(Inner {
            schedule,
            set: RwLock::new(KeySet { epoch, keys }),
        }))
    }

    /// Makes `key` the one sealing new tickets; the previous ones keep opening theirs (the
    /// oldest is dropped beyond [`MAX_TICKET_KEYS`]). For keys made with [`new`](Self::new);
    /// scheduled keys ignore it.
    pub fn rotate(&self, key: [u8; 48]) {
        if !matches!(self.0.schedule, Schedule::Manual) {
            return;
        }
        if let Ok(mut s) = self.0.set.write() {
            s.keys.insert(0, TicketKey::new(&key));
            s.keys.truncate(MAX_TICKET_KEYS);
        }
    }

    /// Replaces the keys: `seal` seals new tickets, `seal` and `open_only` (at most
    /// [`MAX_TICKET_KEYS`] `- 1` of them; extra ones are ignored) open tickets. For keys made
    /// with [`new`](Self::new); scheduled keys ignore it.
    pub fn set(&self, seal: [u8; 48], open_only: &[[u8; 48]]) {
        if !matches!(self.0.schedule, Schedule::Manual) {
            return;
        }
        let mut keys = vec![TicketKey::new(&seal)];
        keys.extend(
            open_only
                .iter()
                .take(MAX_TICKET_KEYS - 1)
                .map(TicketKey::new),
        );
        if let Ok(mut s) = self.0.set.write() {
            s.keys = keys;
        }
    }

    /// The rotation period of scheduled keys.
    pub fn period(&self) -> Option<Duration> {
        match self.0.schedule {
            Schedule::Manual => None,
            Schedule::Random { period } | Schedule::Derived { period, .. } => {
                Some(Duration::from_secs(period))
            }
        }
    }

    /// Brings scheduled keys to the current period.
    fn tick(&self, now: u64) {
        let (period, derived) = match &self.0.schedule {
            Schedule::Manual => return,
            Schedule::Random { period } => (*period, None),
            Schedule::Derived { prk, period } => (*period, Some(prk)),
        };
        let epoch = now / period;
        if self.0.set.read().is_ok_and(|s| s.epoch == epoch) {
            return;
        }
        let Ok(mut s) = self.0.set.write() else {
            return;
        };
        if s.epoch == epoch {
            return;
        }
        match derived {
            Some(prk) => s.keys = derived_set(prk, epoch),
            None => {
                // The previous period's key opens tickets for one more period; older ones go.
                let fresh = epoch == s.epoch + 1;
                match random::<48>() {
                    Ok(k) => {
                        s.keys.truncate(usize::from(fresh));
                        s.keys.insert(0, TicketKey::new(&k));
                    }
                    // No randomness: keep sealing with the old key rather than none.
                    Err(_) => return,
                }
            }
        }
        s.epoch = epoch;
    }

    pub(crate) fn seal(&self, sess: &Session) -> Option<Vec<u8>> {
        self.tick(now_secs());
        self.0.set.read().ok()?.keys.first()?.seal(sess)
    }

    pub(crate) fn open(&self, ticket: &[u8]) -> Option<Session> {
        self.tick(now_secs());
        let s = self.0.set.read().ok()?;
        s.keys.iter().find_map(|k| k.open(ticket))
    }
}

/// The keys of a derived schedule at `epoch`: its own first, then the previous and the next
/// period's.
fn derived_set(prk: &[u8; 32], epoch: u64) -> Vec<TicketKey> {
    [Some(epoch), epoch.checked_sub(1), epoch.checked_add(1)]
        .into_iter()
        .flatten()
        .map(|e| {
            let mut k = [0u8; 48];
            let mut info = *b"epoch\0\0\0\0\0\0\0\0";
            info[5..].copy_from_slice(&e.to_be_bytes());
            // A 48-byte output is far below HKDF's limit: it cannot fail.
            let _ = only_crypto::kdf::hkdf_expand::<Sha256>(prk, &info, &mut k);
            TicketKey::new(&k)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(n: u8) -> Session {
        Session {
            version: 0x0304,
            suite: 0x1301,
            secret: vec![n; 32],
            ..Session::default()
        }
    }

    #[test]
    fn manual_rotation() {
        let keys = TicketKeys::new([1; 48]);
        let t1 = keys.seal(&session(1)).unwrap();
        assert_eq!(&t1[..16], &[1; 16]);
        assert_eq!(keys.open(&t1).unwrap().secret, vec![1; 32]);
        keys.rotate([2; 48]);
        let t2 = keys.seal(&session(2)).unwrap();
        assert_eq!(&t2[..16], &[2; 16], "the new key seals");
        assert!(keys.open(&t1).is_some(), "the old key still opens");
        assert!(keys.open(&t2).is_some());
        for k in 3..=5 {
            keys.rotate([k; 48]);
        }
        // Four keys at most: the first is gone.
        assert!(keys.open(&t1).is_none());
        assert!(keys.open(&t2).is_some());
        keys.set([9; 48], &[]);
        assert!(keys.open(&t2).is_none());
        assert_eq!(&keys.seal(&session(9)).unwrap()[..16], &[9; 16]);
        keys.set([8; 48], &[[9; 48], [7; 48], [6; 48], [5; 48]]);
        assert_eq!(keys.0.set.read().unwrap().keys.len(), MAX_TICKET_KEYS);
        // Tampered or unknown tickets open nowhere.
        let mut bad = keys.seal(&session(3)).unwrap();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(keys.open(&bad).is_none());
        assert!(keys.open(&[0; 20]).is_none());
        assert!(format!("{keys:?}").contains("manual"));
        assert_eq!(keys.period(), None);
    }

    #[test]
    fn derived_rotation() {
        let a = TicketKeys::derived(b"a shared secret of 32 bytes.....", Duration::from_secs(60));
        let b = TicketKeys::derived(b"a shared secret of 32 bytes.....", Duration::from_secs(60));
        let other =
            TicketKeys::derived(b"another secret of 32 bytes......", Duration::from_secs(60));
        let t = 1_000_000_020; // period 16_666_667
        a.tick(t);
        b.tick(t);
        other.tick(t);
        let ticket = a.0.set.read().unwrap().keys[0].seal(&session(1)).unwrap();
        let open = |k: &TicketKeys, now: u64| {
            k.tick(now);
            k.0.set
                .read()
                .unwrap()
                .keys
                .iter()
                .find_map(|x| x.open(&ticket))
        };
        // Another server with the secret opens it, also one period later or earlier
        // (clock skew), not two.
        assert!(open(&b, t).is_some());
        assert!(open(&b, t + 60).is_some());
        assert!(open(&b, t - 60).is_some());
        assert!(open(&b, t + 120).is_none());
        assert!(open(&other, t).is_none());
        // Periods seal with their own key.
        a.tick(t + 60);
        let next = a.0.set.read().unwrap().keys[0].seal(&session(2)).unwrap();
        assert_ne!(&next[..16], &ticket[..16]);
        assert_eq!(a.period(), Some(Duration::from_secs(60)));
        a.rotate([1; 48]);
        assert!(
            a.0.set.read().unwrap().keys.len() == 3,
            "scheduled keys ignore rotate"
        );
    }

    #[test]
    fn random_rotation() {
        let k = TicketKeys::random(Duration::from_secs(10)).unwrap();
        let e = k.0.set.read().unwrap().epoch;
        let t1 = k.0.set.read().unwrap().keys[0].seal(&session(1)).unwrap();
        let opens = |now: u64| {
            k.tick(now);
            k.0.set
                .read()
                .unwrap()
                .keys
                .iter()
                .any(|x| x.open(&t1).is_some())
        };
        assert!(opens(e * 10));
        // Next period: a new key seals, the old one still opens.
        assert!(opens(e * 10 + 10));
        assert_eq!(k.0.set.read().unwrap().keys.len(), 2);
        // Two periods on: gone.
        assert!(!opens(e * 10 + 20));
        // A jump of several periods keeps only the new key.
        assert!(!opens(e * 10 + 100));
        assert_eq!(k.0.set.read().unwrap().keys.len(), 1);
    }
}
