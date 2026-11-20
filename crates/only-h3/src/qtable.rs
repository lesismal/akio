//! The QPACK dynamic table (RFC 9204 §3.2, §4.3, §4.4): the decoder's copy fed by the peer's
//! encoder stream, and this side's encoder.
//!
//! The encoder is conservative: it inserts fields that repeat (the second time it sees them;
//! not paths, dates, lengths, validators or credentials), references entries the peer has not
//! acknowledged only within the blocked-streams budget the peer grants, duplicates entries
//! about to be evicted, and evicts only entries the peer has acknowledged that no
//! unacknowledged section references. Its table is bounded by the capacity the configuration
//! and the peer both allow (see [`Encoder`]).

use std::collections::{HashMap, VecDeque};

use crate::code;
use crate::qpack::{QpackError, put_int};
use crate::table::STATIC;

/// Per-entry overhead in the table size (RFC 9204 §3.2.1).
const OVERHEAD: u64 = 32;

/// Why encoder or decoder stream input stopped.
enum P {
    /// The instruction is not complete yet.
    More,
    /// Malformed.
    Bad,
}

fn int(b: &[u8], pos: &mut usize, prefix: u8) -> Result<u64, P> {
    let max = (1u64 << prefix) - 1;
    let first = *b.get(*pos).ok_or(P::More)?;
    *pos += 1;
    let mut v = u64::from(first) & max;
    if v < max {
        return Ok(v);
    }
    let mut shift = 0;
    loop {
        let byte = *b.get(*pos).ok_or(P::More)?;
        *pos += 1;
        if shift > 56 {
            return Err(P::Bad);
        }
        v = v
            .checked_add(u64::from(byte & 0x7f) << shift)
            .ok_or(P::Bad)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
}

/// A string whose length has a `prefix`-bit prefix (Huffman flag just above it), at most `max`
/// bytes on the wire; decoded into `out`.
fn string(b: &[u8], pos: &mut usize, prefix: u8, max: u64, out: &mut Vec<u8>) -> Result<(), P> {
    let huff = b.get(*pos).ok_or(P::More)? & (1 << prefix) != 0;
    let len = int(b, pos, prefix)?;
    if len > max {
        return Err(P::Bad);
    }
    let len = len as usize;
    let raw = b.get(*pos..*pos + len).ok_or(P::More)?;
    *pos += len;
    if huff {
        only_http::hpack::decode_huffman(raw, out).map_err(|_| P::Bad)
    } else {
        out.extend_from_slice(raw);
        Ok(())
    }
}

/// A table entry: name and value.
type Entry = (Box<[u8]>, Box<[u8]>);

/// Entries by absolute index: `entries[0]` has index `dropped`.
#[derive(Default)]
struct Ring {
    entries: VecDeque<Entry>,
    dropped: u64,
    size: u64,
}

impl Ring {
    const fn new() -> Ring {
        Ring {
            entries: VecDeque::new(),
            dropped: 0,
            size: 0,
        }
    }

    fn inserted(&self) -> u64 {
        self.dropped + self.entries.len() as u64
    }

    fn get(&self, abs: u64) -> Option<(&[u8], &[u8])> {
        let i = abs.checked_sub(self.dropped)?;
        self.entries
            .get(usize::try_from(i).ok()?)
            .map(|(n, v)| (&n[..], &v[..]))
    }

    fn evict(&mut self) -> Option<Entry> {
        let e = self.entries.pop_front()?;
        self.dropped += 1;
        self.size -= e.0.len() as u64 + e.1.len() as u64 + OVERHEAD;
        Some(e)
    }

    fn push(&mut self, n: Box<[u8]>, v: Box<[u8]>) {
        self.size += n.len() as u64 + v.len() as u64 + OVERHEAD;
        self.entries.push_back((n, v));
    }
}

/// The decoder's dynamic table, as the peer's encoder stream builds it.
pub(crate) struct DecTable {
    /// The capacity we advertised (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`).
    max_capacity: u64,
    capacity: u64,
    ring: Ring,
    /// The Insert Count the encoder knows we have (section acknowledgements and increments).
    acked: u64,
    /// Decoder stream bytes to send.
    pub(crate) out: Vec<u8>,
}

/// A decoder without a dynamic table (capacity 0): static references and literals only.
pub(crate) static NO_TABLE: DecTable = DecTable::new(0);

impl DecTable {
    pub(crate) const fn new(max_capacity: u64) -> DecTable {
        DecTable {
            max_capacity,
            capacity: 0,
            ring: Ring::new(),
            acked: 0,
            out: Vec::new(),
        }
    }

    /// The Insert Count: entries inserted so far.
    pub(crate) fn inserted(&self) -> u64 {
        self.ring.inserted()
    }

    /// The capacity we advertised.
    pub(crate) fn max_capacity(&self) -> u64 {
        self.max_capacity
    }

    /// Bytes of the table (names, values and per-entry overhead).
    #[cfg(test)]
    pub(crate) fn size(&self) -> u64 {
        self.ring.size
    }

    /// The entry with absolute index `abs`, unless evicted or not inserted.
    pub(crate) fn get(&self, abs: u64) -> Option<(&[u8], &[u8])> {
        self.ring.get(abs)
    }

    /// The Required Insert Count of an encoded one (RFC 9204 §4.5.1.1).
    pub(crate) fn required_insert_count(&self, enc: u64) -> Result<u64, QpackError> {
        if enc == 0 {
            return Ok(0);
        }
        let max_entries = self.max_capacity / OVERHEAD;
        let full = 2 * max_entries;
        if enc > full {
            return Err(QpackError::Decompression);
        }
        let max_value = self.inserted() + max_entries;
        let max_wrapped = (max_value / full) * full;
        let mut ric = max_wrapped + enc - 1;
        if ric > max_value {
            if ric <= full {
                return Err(QpackError::Decompression);
            }
            ric -= full;
        }
        if ric == 0 {
            return Err(QpackError::Decompression);
        }
        Ok(ric)
    }

    fn evict_to(&mut self, cap: u64) {
        while self.ring.size > cap {
            self.ring.evict();
        }
    }

    fn insert(&mut self, n: Vec<u8>, v: Vec<u8>) -> Result<(), u32> {
        let size = n.len() as u64 + v.len() as u64 + OVERHEAD;
        if size > self.capacity {
            return Err(code::QPACK_ENCODER_STREAM_ERROR);
        }
        self.evict_to(self.capacity - size);
        self.ring.push(n.into(), v.into());
        Ok(())
    }

    /// Applies the encoder stream instructions in `b`; the bytes taken (a trailing incomplete
    /// instruction is left), or `Err(code)`, a connection error.
    pub(crate) fn on_encoder_stream(&mut self, b: &[u8]) -> Result<usize, u32> {
        let mut pos = 0;
        loop {
            let start = pos;
            match self.instruction(b, &mut pos) {
                Ok(true) => {}
                Ok(false) => return Ok(pos),
                Err(P::More) => return Ok(start),
                Err(P::Bad) => return Err(code::QPACK_ENCODER_STREAM_ERROR),
            }
        }
    }

    /// One encoder instruction; `Ok(false)` when `b` is used up.
    fn instruction(&mut self, b: &[u8], pos: &mut usize) -> Result<bool, P> {
        let Some(&first) = b.get(*pos) else {
            return Ok(false);
        };
        // A string can be no longer than the table can hold.
        let max = self.capacity;
        if first & 0x80 != 0 {
            // Insert with name reference: 1 T index(6), value H len(7).
            let idx = int(b, pos, 6)?;
            let name = if first & 0x40 != 0 {
                STATIC
                    .get(idx as usize)
                    .ok_or(P::Bad)?
                    .0
                    .as_bytes()
                    .to_vec()
            } else {
                let abs = self.inserted().checked_sub(idx + 1).ok_or(P::Bad)?;
                self.get(abs).ok_or(P::Bad)?.0.to_vec()
            };
            let mut v = Vec::new();
            string(b, pos, 7, max, &mut v)?;
            self.insert(name, v).map_err(|_| P::Bad)?;
        } else if first & 0x40 != 0 {
            // Insert with literal name: 01 H len(5), value H len(7).
            let mut n = Vec::new();
            string(b, pos, 5, max, &mut n)?;
            let mut v = Vec::new();
            string(b, pos, 7, max, &mut v)?;
            self.insert(n, v).map_err(|_| P::Bad)?;
        } else if first & 0x20 != 0 {
            // Set dynamic table capacity: 001 capacity(5).
            let cap = int(b, pos, 5)?;
            if cap > self.max_capacity {
                return Err(P::Bad);
            }
            self.capacity = cap;
            self.evict_to(cap);
        } else {
            // Duplicate: 000 index(5).
            let idx = int(b, pos, 5)?;
            let abs = self.inserted().checked_sub(idx + 1).ok_or(P::Bad)?;
            let (n, v) = self.get(abs).ok_or(P::Bad)?;
            let (n, v) = (n.to_vec(), v.to_vec());
            self.insert(n, v).map_err(|_| P::Bad)?;
        }
        Ok(true)
    }

    /// Acknowledges a decoded section of `stream` whose Required Insert Count was `ric` (> 0).
    pub(crate) fn section_ack(&mut self, stream: u64, ric: u64) {
        put_int(&mut self.out, 0x80, 7, stream);
        self.acked = self.acked.max(ric);
    }

    /// Tells the encoder about inserts no section acknowledgement covered.
    pub(crate) fn increment(&mut self) {
        let n = self.inserted() - self.acked;
        if n > 0 {
            put_int(&mut self.out, 0, 6, n);
            self.acked = self.inserted();
        }
    }

    /// The stream was abandoned with a section that may reference the table (§4.4.2).
    pub(crate) fn cancel(&mut self, stream: u64) {
        if self.max_capacity > 0 {
            put_int(&mut self.out, 0x40, 6, stream);
        }
    }
}

/// Fields worth a table entry: ones that repeat across messages. Paths, dates, lengths,
/// validators and ranges change; credentials are not kept (RFC 9204 §7.1).
fn cacheable(n: &[u8]) -> bool {
    !matches!(
        n,
        b":path"
            | b"content-length"
            | b"date"
            | b"etag"
            | b"last-modified"
            | b"if-none-match"
            | b"if-modified-since"
            | b"content-range"
            | b"range"
            | b"age"
            | b"expires"
            | b"authorization"
            | b"proxy-authorization"
            | b"cookie"
            | b"set-cookie"
            | b"early-data"
    )
}

/// A field's key in the encoder's index: the name's length, the name, the value.
fn set_key(k: &mut Vec<u8>, n: &[u8], v: &[u8]) {
    k.clear();
    k.extend_from_slice(&(n.len() as u16).to_le_bytes());
    k.extend_from_slice(n);
    k.extend_from_slice(v);
}

fn key(n: &[u8], v: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(n.len() + v.len() + 2);
    set_key(&mut k, n, v);
    k
}

/// A field's fingerprint for the seen filter (FNV-1a over name, a separator and value).
fn fingerprint(n: &[u8], v: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in n.iter().chain(&[0xff]).chain(v) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Slots of the seen filter: fields are inserted on their second appearance.
const SEEN: usize = 256;

/// Unacknowledged sections tracked at most: past this, no more references (a peer that never
/// acknowledges cannot grow the encoder).
const MAX_UNACKED: usize = 1024;

/// Streams this encoder leaves blocked at most, whatever the peer allows.
const MAX_BLOCKING: u64 = 64;

/// What the encoder did, for tests and the fuzz harness.
#[cfg(any(test, feature = "fuzzing"))]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EncStats {
    pub(crate) inserts: u64,
    pub(crate) duplicates: u64,
    /// Inserts naming a dynamic entry.
    pub(crate) dyn_name_inserts: u64,
    /// Field lines with a dynamic name reference.
    pub(crate) dyn_name_lines: u64,
    /// Field lines with a post-base index or name reference.
    pub(crate) post_base: u64,
    /// Sections that may block the peer (they reference entries it was not known to have).
    pub(crate) blocking: u64,
}

/// This side's QPACK encoder with a dynamic table (RFC 9204 §2.1, §4.3, §4.5).
///
/// - **Inserts** go on the encoder stream with a static name reference, a dynamic name
///   reference or a literal name, for fields that are worth it ([`cacheable`]) the second time
///   they are seen, at most a quarter of the table each.
/// - **Duplicate**: a referenced entry in the oldest quarter of a full table ("draining") is
///   duplicated, so references move to the copy and the old one can be evicted.
/// - **References**: Base is the Insert Count when the section starts; entries inserted while
///   it is encoded get post-base indices. A section references entries the peer has not
///   acknowledged only within the peer's `SETTINGS_QPACK_BLOCKED_STREAMS` (streams with such a
///   section count once each, at most [`MAX_BLOCKING`]); otherwise it uses acknowledged entries
///   and literals.
/// - **Eviction** takes only entries the peer has acknowledged (Known Received Count) that no
///   unacknowledged section references.
pub(crate) struct Encoder {
    capacity: u64,
    /// The peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` / 32, for encoding Required Insert Counts.
    max_entries: u64,
    /// Streams the peer lets wait for inserts (`SETTINGS_QPACK_BLOCKED_STREAMS`), capped.
    max_blocked: u64,
    ring: Ring,
    /// Per entry (from the oldest), bytes inserted up to and including it since the start.
    ends: VecDeque<u64>,
    /// Bytes evicted since the start.
    evicted: u64,
    /// Entries the peer has (Known Received Count).
    known: u64,
    /// Field → absolute index of its newest entry.
    index: HashMap<Vec<u8>, u64>,
    /// Name → absolute index of the newest entry with it (for name references).
    names: HashMap<Box<[u8]>, u64>,
    /// Unacknowledged sections in the order they were encoded: (stream, Required Insert Count,
    /// lowest absolute index referenced). An acknowledgement takes its stream's oldest. Few are
    /// in flight, so a vector beats a map (no allocation per section).
    unacked: Vec<(u64, u64, u64)>,
    /// Fingerprints of fields seen once (direct mapped; 0 is empty).
    seen: Box<[u32; SEEN]>,
    /// A field's key in `index`, built here to look it up without allocating.
    key: Vec<u8>,
    /// Encoder stream bytes to send.
    pub(crate) out: Vec<u8>,
    /// Lines of the section being encoded.
    scratch: Vec<u8>,
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) stats: EncStats,
}

/// What one section referenced, while it is being encoded.
pub(crate) struct Section {
    /// Highest absolute index referenced + 1 (the Required Insert Count).
    ric: u64,
    /// Lowest absolute index referenced.
    min: u64,
    /// The Insert Count when the section started.
    base: u64,
    stream: u64,
    /// Whether it may reference entries the peer may not have yet; decided when first needed.
    block: Option<bool>,
}

impl Encoder {
    /// An encoder using `capacity` bytes of table (at most the peer's maximum,
    /// `peer_max_capacity`) that leaves at most `peer_blocked` streams waiting for inserts; the
    /// Set Dynamic Table Capacity instruction is queued.
    pub(crate) fn new(capacity: u64, peer_max_capacity: u64, peer_blocked: u64) -> Encoder {
        let capacity = capacity.min(peer_max_capacity);
        let mut out = Vec::new();
        put_int(&mut out, 0x20, 5, capacity);
        Encoder {
            capacity,
            max_entries: peer_max_capacity / OVERHEAD,
            max_blocked: peer_blocked.min(MAX_BLOCKING),
            ring: Ring::new(),
            ends: VecDeque::new(),
            evicted: 0,
            known: 0,
            index: HashMap::new(),
            names: HashMap::new(),
            unacked: Vec::new(),
            seen: Box::new([0; SEEN]),
            key: Vec::new(),
            out,
            scratch: Vec::new(),
            #[cfg(any(test, feature = "fuzzing"))]
            stats: EncStats::default(),
        }
    }

    /// Entries no unacknowledged section (nor `cur`, being encoded) references, and that the
    /// peer has, can be evicted: those below this index.
    fn floor(&self, cur: &Section) -> u64 {
        let mut f = self.known;
        if cur.ric > 0 {
            f = f.min(cur.min);
        }
        for &(_, _, min) in &self.unacked {
            f = f.min(min);
        }
        f
    }

    /// Whether entry `abs` is in the oldest quarter of a full table: about to be evicted.
    fn draining(&self, abs: u64) -> bool {
        let Some(&end) = abs
            .checked_sub(self.ring.dropped)
            .and_then(|i| self.ends.get(i as usize))
        else {
            return false;
        };
        end - self.evicted <= self.ring.size.saturating_sub(self.capacity / 4 * 3)
    }

    /// Evicts entries below `floor` until `size` bytes are free; `false` (nothing evicted) when
    /// that is not possible.
    fn make_room(&mut self, size: u64, floor: u64) -> bool {
        let mut free = self.capacity - self.ring.size;
        let mut abs = self.ring.dropped;
        while free < size {
            if abs >= floor {
                return false;
            }
            let Some((en, ev)) = self.ring.get(abs) else {
                return false;
            };
            free += en.len() as u64 + ev.len() as u64 + OVERHEAD;
            abs += 1;
        }
        while self.ring.dropped < abs {
            let at = self.ring.dropped;
            let Some((en, ev)) = self.ring.evict() else {
                break;
            };
            self.ends.pop_front();
            self.evicted += en.len() as u64 + ev.len() as u64 + OVERHEAD;
            let k = key(&en, &ev);
            if self.index.get(&k) == Some(&at) {
                self.index.remove(&k);
            }
            if self.names.get(&en) == Some(&at) {
                self.names.remove(&en);
            }
        }
        true
    }

    /// Adds an entry the encoder stream just inserted; its absolute index.
    fn push(&mut self, n: &[u8], v: &[u8]) -> u64 {
        let size = n.len() as u64 + v.len() as u64 + OVERHEAD;
        let end = self.ends.back().copied().unwrap_or(self.evicted) + size;
        self.ends.push_back(end);
        let at = self.ring.inserted();
        self.index.insert(key(n, v), at);
        self.names.insert(n.into(), at);
        self.ring.push(n.into(), v.into());
        at
    }

    /// Inserts `n: v` if it fits without evicting a needed entry; its absolute index.
    fn insert(&mut self, n: &[u8], v: &[u8], cur: &Section) -> Option<u64> {
        let size = n.len() as u64 + v.len() as u64 + OVERHEAD;
        if size > self.capacity / 4 {
            return None;
        }
        let stat = crate::qpack::static_name(n);
        // A dynamic name is referenced only if it stays (the RFC lets an insert name the entry
        // it evicts, but decoders need not be tested on that).
        let dyn_name = match stat {
            None => self.names.get(n).copied(),
            Some(_) => None,
        };
        let mut floor = self.floor(cur);
        if let Some(a) = dyn_name {
            floor = floor.min(a);
        }
        if !self.make_room(size, floor) {
            return None;
        }
        match (stat, dyn_name) {
            (Some(i), _) => put_int(&mut self.out, 0xc0, 6, u64::from(i)),
            (None, Some(a)) => {
                put_int(&mut self.out, 0x80, 6, self.ring.inserted() - 1 - a);
                #[cfg(any(test, feature = "fuzzing"))]
                {
                    self.stats.dyn_name_inserts += 1;
                }
            }
            (None, None) => {
                put_int(&mut self.out, 0x40, 5, n.len() as u64);
                self.out.extend_from_slice(n);
            }
        }
        put_int(&mut self.out, 0, 7, v.len() as u64);
        self.out.extend_from_slice(v);
        #[cfg(any(test, feature = "fuzzing"))]
        {
            self.stats.inserts += 1;
        }
        Some(self.push(n, v))
    }

    /// Duplicates entry `abs` (Duplicate instruction) if that evicts nothing still needed,
    /// `abs` included; the copy's absolute index.
    fn duplicate(&mut self, abs: u64, cur: &Section) -> Option<u64> {
        let (n, v) = self.ring.get(abs)?;
        let (n, v) = (Box::<[u8]>::from(n), Box::<[u8]>::from(v));
        let size = n.len() as u64 + v.len() as u64 + OVERHEAD;
        let floor = self.floor(cur).min(abs);
        if !self.make_room(size, floor) {
            return None;
        }
        put_int(&mut self.out, 0, 5, self.ring.inserted() - 1 - abs);
        #[cfg(any(test, feature = "fuzzing"))]
        {
            self.stats.duplicates += 1;
        }
        Some(self.push(&n, &v))
    }

    /// Whether `sec` may reference entries the peer may not have yet: within the peer's
    /// blocked-streams budget (a stream already blocking it costs nothing more).
    fn may_block(&self, sec: &mut Section) -> bool {
        if let Some(b) = sec.block {
            return b;
        }
        let b = self.max_blocked > 0
            && self.unacked.len() < MAX_UNACKED
            && self.blocking_ok(sec.stream);
        sec.block = Some(b);
        b
    }

    fn blocking_ok(&self, stream: u64) -> bool {
        let mut streams: Vec<u64> = Vec::new();
        for &(s, ric, _) in &self.unacked {
            if ric <= self.known {
                continue;
            }
            if s == stream {
                return true;
            }
            if !streams.contains(&s) {
                streams.push(s);
                if streams.len() as u64 >= self.max_blocked {
                    return false;
                }
            }
        }
        true
    }

    /// Whether `sec` may reference entry `abs`.
    fn usable(&self, abs: u64, sec: &mut Section) -> bool {
        self.unacked.len() < MAX_UNACKED && (abs < self.known || self.may_block(sec))
    }

    fn note(sec: &mut Section, abs: u64) {
        if sec.ric == 0 || abs < sec.min {
            sec.min = abs;
        }
        sec.ric = sec.ric.max(abs + 1);
    }

    /// An indexed field line for entry `abs` (relative to Base, or post-base).
    fn indexed(&mut self, lines: &mut Vec<u8>, sec: &mut Section, abs: u64) {
        if abs < sec.base {
            put_int(lines, 0x80, 6, sec.base - 1 - abs);
        } else {
            put_int(lines, 0x10, 4, abs - sec.base);
            #[cfg(any(test, feature = "fuzzing"))]
            {
                self.stats.post_base += 1;
            }
        }
        Self::note(sec, abs);
    }

    /// A literal field line: a static name reference, a dynamic one when usable, else a
    /// literal name.
    fn literal(&mut self, lines: &mut Vec<u8>, sec: &mut Section, n: &[u8], v: &[u8]) {
        if crate::qpack::static_name(n).is_none() {
            if let Some(&abs) = self.names.get(n) {
                if !self.draining(abs) && self.usable(abs, sec) {
                    if abs < sec.base {
                        put_int(lines, 0x40, 4, sec.base - 1 - abs);
                    } else {
                        put_int(lines, 0x00, 3, abs - sec.base);
                        #[cfg(any(test, feature = "fuzzing"))]
                        {
                            self.stats.post_base += 1;
                        }
                    }
                    put_int(lines, 0, 7, v.len() as u64);
                    lines.extend_from_slice(v);
                    Self::note(sec, abs);
                    #[cfg(any(test, feature = "fuzzing"))]
                    {
                        self.stats.dyn_name_lines += 1;
                    }
                    return;
                }
            }
        }
        crate::qpack::encode_line(lines, n, v);
    }

    /// Whether the field was seen before (and remembers it if not).
    fn seen_before(&mut self, n: &[u8], v: &[u8]) -> bool {
        let h = fingerprint(n, v);
        let slot = &mut self.seen[(h as usize) & (SEEN - 1)];
        let tag = (h >> 32) as u32 | 1;
        if *slot == tag {
            true
        } else {
            *slot = tag;
            false
        }
    }

    /// Starts a section for `stream`: lines go to an internal buffer until [`end`](Self::end).
    pub(crate) fn begin(&mut self, stream: u64) -> (Vec<u8>, Section) {
        let mut s = std::mem::take(&mut self.scratch);
        s.clear();
        let sec = Section {
            ric: 0,
            min: 0,
            base: self.ring.inserted(),
            stream,
            block: None,
        };
        (s, sec)
    }

    /// Appends a field line to `lines`: a static or dynamic reference when the field is in a
    /// table and the peer has it (or may wait for it), else a literal (inserting the field for
    /// next time when worth it). `n` is lowercase.
    pub(crate) fn line(&mut self, lines: &mut Vec<u8>, sec: &mut Section, n: &[u8], v: &[u8]) {
        if crate::qpack::static_exact(n, v).is_some() || !cacheable(n) {
            crate::qpack::encode_line(lines, n, v);
            return;
        }
        let mut k = std::mem::take(&mut self.key);
        set_key(&mut k, n, v);
        let found = self.index.get(&k[..]).copied();
        self.key = k;
        match found {
            Some(mut abs) => {
                if self.draining(abs) {
                    // References move to a fresh copy so the old entry can go.
                    if let Some(copy) = self.duplicate(abs, sec) {
                        if self.usable(copy, sec) {
                            abs = copy;
                        }
                    }
                }
                if self.usable(abs, sec) {
                    self.indexed(lines, sec, abs);
                } else {
                    self.literal(lines, sec, n, v);
                }
            }
            None => {
                if self.seen_before(n, v) {
                    if let Some(new) = self.insert(n, v, sec) {
                        if self.usable(new, sec) {
                            return self.indexed(lines, sec, new);
                        }
                    }
                }
                self.literal(lines, sec, n, v);
            }
        }
    }

    /// Ends the section started with [`begin`](Self::begin): appends its prefix and lines to
    /// `out`, and remembers it until the peer acknowledges it.
    pub(crate) fn end(&mut self, out: &mut Vec<u8>, lines: Vec<u8>, sec: Section) {
        if sec.ric == 0 {
            out.extend_from_slice(&crate::qpack::PREFIX);
        } else {
            put_int(out, 0, 8, sec.ric % (2 * self.max_entries) + 1);
            if sec.base >= sec.ric {
                put_int(out, 0, 7, sec.base - sec.ric);
            } else {
                put_int(out, 0x80, 7, sec.ric - sec.base - 1);
            }
            #[cfg(any(test, feature = "fuzzing"))]
            if sec.ric > self.known {
                self.stats.blocking += 1;
            }
            self.unacked.push((sec.stream, sec.ric, sec.min));
        }
        out.extend_from_slice(&lines);
        self.scratch = lines;
    }

    /// Applies decoder stream instructions; the bytes taken, or `Err(code)`.
    pub(crate) fn on_decoder_stream(&mut self, b: &[u8]) -> Result<usize, u32> {
        let mut pos = 0;
        while let Some(&first) = b.get(pos) {
            let start = pos;
            let r = if first & 0x80 != 0 {
                // Section acknowledgement: the stream's oldest unacknowledged section.
                int(b, &mut pos, 7).and_then(|id| {
                    let at = self.unacked.iter().position(|e| e.0 == id).ok_or(P::Bad)?;
                    let (_, ric, _) = self.unacked.remove(at);
                    self.known = self.known.max(ric);
                    Ok(())
                })
            } else if first & 0x40 != 0 {
                // Stream cancellation.
                int(b, &mut pos, 6).map(|id| self.unacked.retain(|e| e.0 != id))
            } else {
                // Insert count increment.
                int(b, &mut pos, 6).and_then(|inc| {
                    let k = self.known.checked_add(inc).ok_or(P::Bad)?;
                    if inc == 0 || k > self.ring.inserted() {
                        return Err(P::Bad);
                    }
                    self.known = k;
                    Ok(())
                })
            };
            match r {
                Ok(()) => {}
                Err(P::More) => return Ok(start),
                Err(P::Bad) => return Err(code::QPACK_DECODER_STREAM_ERROR),
            }
        }
        Ok(pos)
    }

    /// Bytes in the table.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn size(&self) -> u64 {
        self.ring.size
    }

    /// Entries inserted so far.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn inserted(&self) -> u64 {
        self.ring.inserted()
    }

    /// The Known Received Count.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn known(&self) -> u64 {
        self.known
    }

    /// The oldest entry still in the table.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn dropped(&self) -> u64 {
        self.ring.dropped
    }

    /// Streams with a section the peer may be blocked on.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn blocking_streams(&self) -> u64 {
        let mut s: Vec<u64> = self
            .unacked
            .iter()
            .filter(|e| e.1 > self.known)
            .map(|e| e.0)
            .collect();
        s.sort_unstable();
        s.dedup();
        s.len() as u64
    }

    /// The lowest absolute index an unacknowledged section references.
    #[cfg(any(test, feature = "fuzzing"))]
    pub(crate) fn min_referenced(&self) -> Option<u64> {
        self.unacked.iter().map(|e| e.2).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::{FieldBuf, SectionError, decode_section};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn fields(f: &FieldBuf) -> Vec<(String, String)> {
        f.iter()
            .map(|(n, v)| {
                (
                    String::from_utf8(n.to_vec()).unwrap(),
                    String::from_utf8(v.to_vec()).unwrap(),
                )
            })
            .collect()
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        p.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// RFC 9204 Appendix B.2 to B.5, decoder side: encoder stream instructions, field sections
    /// that reference them (one blocked until its insert arrives), and the decoder stream
    /// bytes the RFC shows.
    #[test]
    fn rfc9204_appendix_b() {
        let mut t = DecTable::new(220);
        let mut f = FieldBuf::default();
        // B.2: the section on stream 4 arrives before the inserts it needs: blocked.
        let sec = hex("0381 10 11");
        assert!(matches!(
            decode_section(&sec, 1 << 16, &t, &mut f),
            Err(SectionError::Blocked(2))
        ));
        let enc = hex("3fbd01 c00f7777772e6578616d706c652e636f6d c10c2f73616d706c652f70617468");
        assert_eq!(t.on_encoder_stream(&enc), Ok(enc.len()));
        assert_eq!((t.inserted(), t.size()), (2, 106));
        let ric = decode_section(&sec, 1 << 16, &t, &mut f).ok().unwrap();
        assert_eq!(ric, 2);
        assert_eq!(
            fields(&f),
            pairs(&[(":authority", "www.example.com"), (":path", "/sample/path")])
        );
        t.section_ack(4, ric);
        assert_eq!(t.out, hex("84"));
        t.out.clear();
        // B.3: an insert with a literal name, then an Insert Count Increment.
        let enc = hex("4a637573746f6d2d6b65790c637573746f6d2d76616c7565");
        assert_eq!(t.on_encoder_stream(&enc), Ok(enc.len()));
        t.increment();
        assert_eq!(t.out, hex("01"));
        t.out.clear();
        assert_eq!(t.size(), 160);
        // B.4: a duplicate, then a section on stream 8 using post-base and pre-base indices.
        let enc = hex("02");
        assert_eq!(t.on_encoder_stream(&enc), Ok(1));
        let sec = hex("0500 80 c1 81");
        let ric = decode_section(&sec, 1 << 16, &t, &mut f).ok().unwrap();
        assert_eq!(ric, 4);
        assert_eq!(
            fields(&f),
            pairs(&[
                (":authority", "www.example.com"),
                (":path", "/"),
                ("custom-key", "custom-value"),
            ])
        );
        t.section_ack(8, ric);
        assert_eq!(t.out, hex("88"));
        t.out.clear();
        // Stream 8 is then cancelled.
        t.cancel(8);
        assert_eq!(t.out, hex("48"));
        t.out.clear();
        // B.5: an insert that evicts the oldest entry; a section on stream 12.
        let enc = hex("810d637573746f6d2d76616c756532");
        assert_eq!(t.on_encoder_stream(&enc), Ok(enc.len()));
        assert_eq!((t.inserted(), t.size()), (5, 215));
        assert!(t.get(0).is_none());
        // The increment is not covered by the acknowledgement of stream 8 (RIC 4).
        t.increment();
        assert_eq!(t.out, hex("01"));
        // Base below the Required Insert Count: a static name reference, a post-base indexed
        // line and a post-base literal with a name reference.
        let sec = hex("0680 500161 10 000178");
        let ric = decode_section(&sec, 1 << 16, &t, &mut f).ok().unwrap();
        assert_eq!(ric, 5);
        assert_eq!(
            fields(&f),
            pairs(&[
                (":authority", "a"),
                ("custom-key", "custom-value2"),
                ("custom-key", "x"),
            ])
        );
        // The encoded Required Insert Count wraps around (2 x 6 entries): 18 is encoded 7.
        let mut t = DecTable::new(220);
        t.on_encoder_stream(&hex("3fbd01")).unwrap();
        for _ in 0..18 {
            t.on_encoder_stream(&hex("c00161")).unwrap();
        }
        assert_eq!(t.required_insert_count(7), Ok(18));
        assert_eq!(t.required_insert_count(13), Err(QpackError::Decompression));
    }

    #[test]
    fn decoder_errors() {
        let mut t = DecTable::new(100);
        let mut f = FieldBuf::default();
        // Capacity above the maximum; an entry larger than the capacity.
        assert!(t.on_encoder_stream(&hex("3f46")).is_err());
        let mut t = DecTable::new(100);
        assert_eq!(t.on_encoder_stream(&hex("3f21")), Ok(2)); // capacity 64
        let mut big = hex("4a637573746f6d2d6b65791d");
        big.extend_from_slice(&[b'v'; 29]);
        assert!(t.on_encoder_stream(&big).is_err());
        // A partial instruction waits; a reference beyond the inserts is refused.
        let mut t = DecTable::new(100);
        assert_eq!(t.on_encoder_stream(&hex("3f45 4a6375")), Ok(2));
        assert!(t.on_encoder_stream(&hex("05")).is_err());
        assert!(t.on_encoder_stream(&hex("80")).is_err());
        // Encoded Required Insert Count beyond the table's range, or 0 after wrapping.
        let t = DecTable::new(100);
        assert!(decode_section(&hex("0700"), 1000, &t, &mut f).is_err());
        assert!(matches!(
            decode_section(&hex("0200"), 1000, &t, &mut f),
            Err(SectionError::Blocked(1))
        ));
        // A section referencing an entry at or above its Required Insert Count.
        let mut t = DecTable::new(100);
        assert_eq!(t.on_encoder_stream(&hex("3f45 c0 0161 c0 0162")), Ok(8));
        assert!(decode_section(&hex("0200 80"), 1000, &t, &mut f).is_ok());
        assert!(decode_section(&hex("0280 10"), 1000, &t, &mut f).is_ok());
        assert!(decode_section(&hex("0280 11"), 1000, &t, &mut f).is_err());
        assert!(decode_section(&hex("0281 80"), 1000, &t, &mut f).is_err());
        // Without a table, any dynamic reference fails.
        assert!(decode_section(&hex("0000 80"), 1000, &NO_TABLE, &mut f).is_err());
        assert!(decode_section(&hex("0100"), 1000, &NO_TABLE, &mut f).is_err());
    }

    /// One field section through encoder `e` for `stream`; its bytes.
    fn encode(e: &mut Encoder, stream: u64, fields: &[(&str, &str)]) -> Vec<u8> {
        let (mut lines, mut sec) = e.begin(stream);
        for (n, v) in fields {
            e.line(&mut lines, &mut sec, n.as_bytes(), v.as_bytes());
        }
        let mut out = Vec::new();
        e.end(&mut out, lines, sec);
        out
    }

    /// Moves the encoder stream to the decoder.
    fn inserts(e: &mut Encoder, d: &mut DecTable) {
        let ins = std::mem::take(&mut e.out);
        assert_eq!(d.on_encoder_stream(&ins), Ok(ins.len()));
    }

    /// Moves the decoder stream to the encoder.
    fn acks(e: &mut Encoder, d: &mut DecTable) {
        let acks = std::mem::take(&mut d.out);
        assert_eq!(e.on_decoder_stream(&acks), Ok(acks.len()));
    }

    /// Decodes a section, checks it and acknowledges it.
    fn decode_ack(d: &mut DecTable, stream: u64, sec: &[u8], want: &[(&str, &str)]) -> u64 {
        let mut f = FieldBuf::default();
        let Ok(ric) = decode_section(sec, 1 << 16, d, &mut f) else {
            panic!("section of stream {stream} does not decode")
        };
        assert_eq!(fields(&f), pairs(want));
        if ric > 0 {
            d.section_ack(stream, ric);
        }
        ric
    }

    /// Without a blocked-streams budget the encoder references only what was acknowledged,
    /// keeps within its capacity and inserts fields the second time it sees them.
    #[test]
    fn encoder_roundtrip() {
        let mut e = Encoder::new(300, 4096, 0);
        let mut d = DecTable::new(4096);
        inserts(&mut e, &mut d);
        let mut wire_sizes = Vec::new();
        for round in 0..40u64 {
            let trace = format!("t{}", round % 3);
            let fields_in = [
                (":status", "200"),
                ("server", "only"),
                ("x-trace", trace.as_str()),
                ("content-type", "application/x-custom"),
                ("date", "Mon, 16 Nov 2026 00:00:00 GMT"),
            ];
            let out = encode(&mut e, round * 4, &fields_in);
            wire_sizes.push(out.len());
            assert!(e.size() <= 300);
            if round == 0 {
                // Seen once: nothing inserted yet.
                assert!(e.out.is_empty(), "{:?}", e.out);
            }
            // The decoder sees the encoder stream later: nothing blocks.
            let mut f = FieldBuf::default();
            assert!(decode_section(&out, 1 << 16, &d, &mut f).is_ok());
            inserts(&mut e, &mut d);
            decode_ack(&mut d, round * 4, &out, &fields_in);
            d.increment();
            acks(&mut e, &mut d);
        }
        assert_eq!((e.stats.blocking, e.stats.post_base), (0, 0));
        // Repeated fields shrink to one-byte references once acknowledged.
        assert!(wire_sizes[39] + 30 < wire_sizes[0], "{wire_sizes:?}");
        // Bad decoder stream input.
        let mut e = Encoder::new(300, 4096, 0);
        assert!(e.on_decoder_stream(&hex("84")).is_err());
        assert!(e.on_decoder_stream(&hex("00")).is_err());
        assert!(e.on_decoder_stream(&hex("01")).is_err());
        assert_eq!(e.on_decoder_stream(&hex("44")), Ok(1));
    }

    /// With a budget, a field is referenced (post-base) in the section whose encoding inserted
    /// it; that section blocks until the insert arrives. At most the peer's limit of streams
    /// block: further sections fall back to literals and acknowledged entries.
    #[test]
    fn encoder_blocking_post_base() {
        let mut e = Encoder::new(4096, 4096, 2);
        let mut d = DecTable::new(4096);
        let f1 = [(":status", "200"), ("x-a", "1"), ("server", "only")];
        // First sight: literals.
        let s0 = encode(&mut e, 0, &f1);
        assert_eq!(e.inserted(), 0);
        decode_ack(&mut d, 0, &s0, &f1);
        // Second sight: inserted and referenced after Base.
        let s4 = encode(&mut e, 4, &f1);
        assert_eq!(e.inserted(), 2);
        assert_eq!(e.stats.post_base, 2);
        assert_eq!(
            &s4[..3],
            &hex("03 81 d9")[..],
            "RIC 2, Base 0 (sign, delta 1)"
        );
        let mut f = FieldBuf::default();
        assert!(matches!(
            decode_section(&s4, 1 << 16, &d, &mut f),
            Err(SectionError::Blocked(2))
        ));
        assert_eq!(e.blocking_streams(), 1);
        // A second stream may block too (new fields, also referenced post-base).
        let f2 = [("x-b", "2"), ("x-a", "1")];
        encode(&mut e, 8, &[("x-b", "2")]);
        let s12 = encode(&mut e, 12, &f2);
        assert_eq!(e.blocking_streams(), 2);
        // A third may not: x-a is not acknowledged, so it is a literal with... a literal name
        // reference is not possible either (the name entry is not acknowledged).
        let f3 = [("x-a", "1"), ("x-c", "3")];
        encode(&mut e, 16, &f3);
        let s20 = encode(&mut e, 20, &f3);
        assert_eq!(e.blocking_streams(), 2);
        assert_eq!(&s20[..2], &crate::qpack::PREFIX[..]);
        // A stream already blocking may block again (its trailers, say).
        let t = encode(&mut e, 4, &[("x-b", "2")]);
        assert_ne!(&t[..2], &crate::qpack::PREFIX[..]);
        // The inserts arrive: everything decodes; acknowledgements clear the budget.
        inserts(&mut e, &mut d);
        decode_ack(&mut d, 4, &s4, &f1);
        decode_ack(&mut d, 12, &s12, &f2);
        decode_ack(&mut d, 20, &s20, &f3);
        decode_ack(&mut d, 4, &t, &[("x-b", "2")]);
        acks(&mut e, &mut d);
        assert_eq!(e.blocking_streams(), 0);
        // Now acknowledged entries are referenced before Base.
        let s24 = encode(&mut e, 24, &f3);
        assert_eq!(e.stats.post_base, 3);
        decode_ack(&mut d, 24, &s24, &f3);
        acks(&mut e, &mut d);
        // A cancelled stream frees its share of the budget.
        encode(&mut e, 28, &[("x-d", "4")]);
        encode(&mut e, 28, &[("x-d", "4")]);
        encode(&mut e, 32, &[("x-e", "5")]);
        encode(&mut e, 32, &[("x-e", "5")]);
        assert_eq!(e.blocking_streams(), 2);
        d.cancel(28);
        acks(&mut e, &mut d);
        assert_eq!(e.blocking_streams(), 1);
    }

    /// However many blocked streams the peer allows, at most `MAX_BLOCKING` are used.
    #[test]
    fn encoder_blocking_cap() {
        let mut e = Encoder::new(1 << 20, 1 << 20, 1000);
        let n = MAX_BLOCKING + 6;
        for i in 0..n {
            let v = i.to_string();
            encode(&mut e, 4 * i, &[("x-a", v.as_str())]);
            encode(&mut e, 4 * i, &[("x-a", v.as_str())]);
        }
        assert_eq!(e.blocking_streams(), MAX_BLOCKING);
        assert_eq!(e.inserted(), n);
        // Just under the cap a new stream may still block; at it, not.
        let mut e = Encoder::new(1 << 20, 1 << 20, 3);
        for i in 0..3u64 {
            let v = i.to_string();
            encode(&mut e, 4 * i, &[("x-a", v.as_str())]);
            encode(&mut e, 4 * i, &[("x-a", v.as_str())]);
            assert_eq!(e.blocking_streams(), i + 1);
        }
        encode(&mut e, 100, &[("x-z", "1")]);
        let s = encode(&mut e, 100, &[("x-z", "1")]);
        assert_eq!(&s[..2], &crate::qpack::PREFIX[..]);
        assert_eq!(e.blocking_streams(), 3);
    }

    /// A field whose entry is in the oldest quarter of a full table is duplicated; its
    /// references move to the copy and the old entry is evicted.
    #[test]
    fn encoder_duplicate() {
        // Entries of 36 bytes ("x-k" + 1 byte + 32); 10 fit in 360.
        let mut e = Encoder::new(360, 360, 0);
        let mut d = DecTable::new(360);
        let round = |e: &mut Encoder, d: &mut DecTable, stream: u64, f: &[(&str, &str)]| {
            let s = encode(e, stream, f);
            inserts(e, d);
            decode_ack(d, stream, &s, f);
            d.increment();
            acks(e, d);
        };
        let vals = ["0", "1", "2", "3", "4", "5", "6", "7", "8"];
        for (i, v) in vals.iter().enumerate() {
            round(&mut e, &mut d, 8 * i as u64, &[("x-k", v)]);
            round(&mut e, &mut d, 8 * i as u64 + 4, &[("x-k", v)]);
        }
        assert_eq!(e.inserted(), 9);
        assert_eq!(e.stats.duplicates, 0);
        // "0" is the oldest of a 9/10 full table: duplicated, then referenced.
        round(&mut e, &mut d, 100, &[("x-k", "0")]);
        assert_eq!(e.stats.duplicates, 1);
        assert_eq!(e.inserted(), 10);
        assert!(e.size() <= 360);
        // Inserting more evicts the old "0", not the copy.
        round(&mut e, &mut d, 104, &[("x-k", "a")]);
        round(&mut e, &mut d, 108, &[("x-k", "a")]);
        assert_eq!(e.dropped(), 1);
        round(&mut e, &mut d, 112, &[("x-k", "0")]);
        assert_eq!(e.stats.duplicates, 1);
        assert_eq!(e.size(), d.size());
    }

    /// Names in the table are referenced: an insert of a new value of a known custom name
    /// names its entry, and a literal line uses it.
    #[test]
    fn encoder_dynamic_names() {
        let mut e = Encoder::new(4096, 4096, 0);
        let mut d = DecTable::new(4096);
        let round = |e: &mut Encoder, d: &mut DecTable, stream: u64, f: &[(&str, &str)]| {
            let s = encode(e, stream, f);
            inserts(e, d);
            decode_ack(d, stream, &s, f);
            d.increment();
            acks(e, d);
            s
        };
        let name = "x-a-rather-long-custom-header-name";
        round(&mut e, &mut d, 0, &[(name, "1")]);
        round(&mut e, &mut d, 4, &[(name, "1")]);
        // A new value: a literal with a dynamic name reference.
        let s = round(&mut e, &mut d, 8, &[(name, "2")]);
        assert_eq!(e.stats.dyn_name_lines, 1);
        assert!(s.len() < 8, "{s:?}");
        // Seen again: inserted naming the entry.
        let before = e.out.len();
        round(&mut e, &mut d, 12, &[(name, "2")]);
        assert_eq!(e.stats.dyn_name_inserts, 1);
        assert!(before == 0);
        assert_eq!(e.inserted(), 2);
        assert_eq!(d.get(1), Some((name.as_bytes(), &b"2"[..])));
    }

    /// Entries referenced by unacknowledged sections are not evicted, even when the table is
    /// full; nothing is inserted then.
    #[test]
    fn encoder_eviction_floor() {
        let mut e = Encoder::new(200, 200, 0);
        let mut d = DecTable::new(200);
        let mut f = FieldBuf::default();
        let mut send = |e: &mut Encoder, d: &mut DecTable, v: &str, stream: u64| {
            let out = encode(e, stream, &[("x-a", v)]);
            inserts(e, d);
            decode_section(&out, 1000, d, &mut f).ok().unwrap()
        };
        // Insert "1" (36 bytes) and have it acknowledged.
        assert_eq!(send(&mut e, &mut d, "1", 0), 0);
        assert_eq!(send(&mut e, &mut d, "1", 0), 0);
        d.increment();
        acks(&mut e, &mut d);
        // Stream 4 references it and stays unacknowledged.
        assert_eq!(send(&mut e, &mut d, "1", 4), 1);
        // Fill the table: the referenced entry must survive.
        for (i, v) in ["2", "3", "4", "5", "6", "7"].iter().enumerate() {
            send(&mut e, &mut d, v, 8 + 4 * i as u64);
            send(&mut e, &mut d, v, 8 + 4 * i as u64);
            assert!(e.ring.get(0).is_some());
            assert!(d.get(0).is_some());
            d.increment();
            acks(&mut e, &mut d);
        }
        assert!(e.size() <= 200);
        // Unacknowledged inserts are not evicted either.
        assert!(e.dropped() <= e.known());
    }
}
