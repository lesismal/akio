//! The QPACK dynamic table (RFC 9204 §3.2, §4.3, §4.4): the decoder's copy fed by the peer's
//! encoder stream, and this side's encoder.
//!
//! The encoder is conservative: it only references entries the peer has acknowledged (Known
//! Received Count), so the peer never blocks on it and the blocked-streams budget the peer
//! grants is never used; its table is bounded by the capacity the configuration and the peer
//! both allow. It inserts fields that tend to repeat (not paths, dates, lengths, validators or
//! credentials), evicting only entries that no unacknowledged section references.

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

fn key(n: &[u8], v: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(n.len() + v.len() + 2);
    k.extend_from_slice(&(n.len() as u16).to_le_bytes());
    k.extend_from_slice(n);
    k.extend_from_slice(v);
    k
}

/// This side's QPACK encoder with a dynamic table.
pub(crate) struct Encoder {
    capacity: u64,
    /// The peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` / 32, for encoding Required Insert Counts.
    max_entries: u64,
    ring: Ring,
    /// Entries the peer has (Known Received Count).
    known: u64,
    /// Field → absolute index of its newest entry.
    index: HashMap<Vec<u8>, u64>,
    /// Per stream, its unacknowledged sections in order: (Required Insert Count, lowest
    /// absolute index referenced).
    unacked: HashMap<u64, VecDeque<(u64, u64)>>,
    /// Encoder stream bytes to send.
    pub(crate) out: Vec<u8>,
    /// Lines of the section being encoded.
    scratch: Vec<u8>,
    /// Sections in `unacked`: past [`MAX_UNACKED`], no more references (a peer that never
    /// acknowledges cannot grow this).
    pending: usize,
}

/// Unacknowledged sections tracked at most.
const MAX_UNACKED: usize = 1024;

/// What one section referenced, while it is being encoded.
#[derive(Default)]
pub(crate) struct Section {
    /// Highest absolute index referenced + 1 (the Required Insert Count).
    ric: u64,
    /// Lowest absolute index referenced.
    min: u64,
}

impl Encoder {
    /// An encoder using `capacity` bytes of table (at most the peer's maximum,
    /// `peer_max_capacity`); the Set Dynamic Table Capacity instruction is queued.
    pub(crate) fn new(capacity: u64, peer_max_capacity: u64) -> Encoder {
        let capacity = capacity.min(peer_max_capacity);
        let mut out = Vec::new();
        put_int(&mut out, 0x20, 5, capacity);
        Encoder {
            capacity,
            max_entries: peer_max_capacity / OVERHEAD,
            ring: Ring::new(),
            known: 0,
            index: HashMap::new(),
            unacked: HashMap::new(),
            out,
            scratch: Vec::new(),
            pending: 0,
        }
    }

    /// Entries no unacknowledged section (nor `cur`, being encoded) references, and that the
    /// peer has, can be evicted: those below this index.
    fn floor(&self, cur: &Section) -> u64 {
        let mut f = self.known;
        if cur.ric > 0 {
            f = f.min(cur.min);
        }
        for q in self.unacked.values() {
            for &(_, min) in q {
                f = f.min(min);
            }
        }
        f
    }

    /// Inserts `n: v` if it fits without evicting a needed entry.
    fn insert(&mut self, n: &[u8], v: &[u8], cur: &Section) {
        let size = n.len() as u64 + v.len() as u64 + OVERHEAD;
        if size > self.capacity / 4 {
            return;
        }
        // Room without evicting what is still needed?
        let floor = self.floor(cur);
        let mut free = self.capacity - self.ring.size;
        let mut abs = self.ring.dropped;
        while free < size {
            if abs >= floor {
                return;
            }
            let Some((en, ev)) = self.ring.get(abs) else {
                return;
            };
            free += en.len() as u64 + ev.len() as u64 + OVERHEAD;
            abs += 1;
        }
        while self.ring.dropped < abs {
            let at = self.ring.dropped;
            if let Some((en, ev)) = self.ring.evict() {
                let k = key(&en, &ev);
                if self.index.get(&k) == Some(&at) {
                    self.index.remove(&k);
                }
            }
        }
        // Insert with a static name reference, or with a literal name.
        match crate::qpack::static_name(n) {
            Some(i) => put_int(&mut self.out, 0xc0, 6, u64::from(i)),
            None => {
                put_int(&mut self.out, 0x40, 5, n.len() as u64);
                self.out.extend_from_slice(n);
            }
        }
        put_int(&mut self.out, 0, 7, v.len() as u64);
        self.out.extend_from_slice(v);
        let at = self.ring.inserted();
        self.index.insert(key(n, v), at);
        self.ring.push(n.into(), v.into());
    }

    /// Starts a section: lines go to an internal buffer until [`end`](Self::end).
    pub(crate) fn begin(&mut self) -> (Vec<u8>, Section) {
        let mut s = std::mem::take(&mut self.scratch);
        s.clear();
        (s, Section::default())
    }

    /// Appends a field line to `lines`: a static or acknowledged dynamic reference when the
    /// field is in a table, else a literal (inserting the field for next time when worth it).
    /// `n` is lowercase.
    pub(crate) fn line(&mut self, lines: &mut Vec<u8>, sec: &mut Section, n: &[u8], v: &[u8]) {
        if crate::qpack::static_exact(n, v).is_some() || !cacheable(n) {
            crate::qpack::encode_line(lines, n, v);
            return;
        }
        let k = key(n, v);
        match self.index.get(&k).copied() {
            Some(abs) if abs < self.known && self.pending < MAX_UNACKED => {
                // Relative to Base = Known Received Count (see `end`).
                put_int(lines, 0x80, 6, self.known - 1 - abs);
                if sec.ric == 0 || abs < sec.min {
                    sec.min = abs;
                }
                sec.ric = sec.ric.max(abs + 1);
            }
            Some(_) => crate::qpack::encode_line(lines, n, v),
            None => {
                crate::qpack::encode_line(lines, n, v);
                self.insert(n, v, sec);
            }
        }
    }

    /// Ends the section of `stream` started with [`begin`](Self::begin): appends its prefix and
    /// lines to `out`, and remembers it until the peer acknowledges it.
    pub(crate) fn end(&mut self, out: &mut Vec<u8>, lines: Vec<u8>, sec: Section, stream: u64) {
        if sec.ric == 0 {
            out.extend_from_slice(&crate::qpack::PREFIX);
        } else {
            // Base is the Known Received Count when the lines were encoded: ric <= base.
            put_int(out, 0, 8, sec.ric % (2 * self.max_entries) + 1);
            put_int(out, 0, 7, self.known - sec.ric);
            self.unacked
                .entry(stream)
                .or_default()
                .push_back((sec.ric, sec.min));
            self.pending += 1;
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
                    let q = self.unacked.get_mut(&id).ok_or(P::Bad)?;
                    let (ric, _) = q.pop_front().ok_or(P::Bad)?;
                    if q.is_empty() {
                        self.unacked.remove(&id);
                    }
                    self.pending -= 1;
                    self.known = self.known.max(ric);
                    Ok(())
                })
            } else if first & 0x40 != 0 {
                // Stream cancellation.
                int(b, &mut pos, 6).map(|id| {
                    if let Some(q) = self.unacked.remove(&id) {
                        self.pending -= q.len();
                    }
                })
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
    #[cfg(test)]
    pub(crate) fn size(&self) -> u64 {
        self.ring.size
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

    /// The encoder against the decoder: references only what was acknowledged, never blocks,
    /// keeps within its capacity and never evicts an entry an unacknowledged section needs.
    #[test]
    fn encoder_roundtrip() {
        let mut e = Encoder::new(300, 4096);
        let mut d = DecTable::new(4096);
        let mut f = FieldBuf::default();
        let mut wire_sizes = Vec::new();
        for round in 0..40u64 {
            let fields_in = [
                (":status", "200".to_string()),
                ("server", "only".to_string()),
                ("x-trace", format!("t{}", round % 3)),
                ("content-type", "application/x-custom".to_string()),
                ("date", "Mon, 16 Nov 2026 00:00:00 GMT".to_string()),
            ];
            let (mut lines, mut sec) = e.begin();
            for (n, v) in &fields_in {
                e.line(&mut lines, &mut sec, n.as_bytes(), v.as_bytes());
            }
            let mut out = Vec::new();
            let stream = round * 4;
            e.end(&mut out, lines, sec, stream);
            wire_sizes.push(out.len());
            assert!(e.size() <= 300);
            // The decoder sees the encoder stream first (any order works: no blocking).
            let ins = std::mem::take(&mut e.out);
            assert_eq!(d.on_encoder_stream(&ins), Ok(ins.len()));
            let Ok(ric) = decode_section(&out, 1 << 16, &d, &mut f) else {
                panic!("round {round}")
            };
            assert_eq!(
                fields(&f),
                fields_in
                    .iter()
                    .map(|(n, v)| (n.to_string(), v.clone()))
                    .collect::<Vec<_>>()
            );
            if ric > 0 {
                d.section_ack(stream, ric);
            }
            d.increment();
            let acks = std::mem::take(&mut d.out);
            assert_eq!(e.on_decoder_stream(&acks), Ok(acks.len()));
        }
        // Repeated fields shrink to one-byte references once acknowledged.
        assert!(wire_sizes[39] + 30 < wire_sizes[0], "{wire_sizes:?}");
        // Bad decoder stream input.
        let mut e = Encoder::new(300, 4096);
        assert!(e.on_decoder_stream(&hex("84")).is_err());
        assert!(e.on_decoder_stream(&hex("00")).is_err());
        assert!(e.on_decoder_stream(&hex("01")).is_err());
        assert_eq!(e.on_decoder_stream(&hex("44")), Ok(1));
    }

    /// Entries referenced by unacknowledged sections are not evicted, even when the table is
    /// full; nothing is inserted then.
    #[test]
    fn encoder_eviction_floor() {
        let mut e = Encoder::new(200, 200);
        let mut d = DecTable::new(200);
        let mut f = FieldBuf::default();
        let mut send = |e: &mut Encoder, d: &mut DecTable, v: &str, stream: u64| {
            let (mut lines, mut sec) = e.begin();
            e.line(&mut lines, &mut sec, b"x-a", v.as_bytes());
            let mut out = Vec::new();
            e.end(&mut out, lines, sec, stream);
            let ins = std::mem::take(&mut e.out);
            assert_eq!(d.on_encoder_stream(&ins), Ok(ins.len()));
            decode_section(&out, 1000, d, &mut f).ok().unwrap()
        };
        // Insert "1" (36 bytes) and have it acknowledged.
        assert_eq!(send(&mut e, &mut d, "1", 0), 0);
        d.increment();
        let acks = std::mem::take(&mut d.out);
        e.on_decoder_stream(&acks).unwrap();
        // Stream 4 references it and stays unacknowledged.
        assert_eq!(send(&mut e, &mut d, "1", 4), 1);
        // Fill the table: the referenced entry must survive.
        for (i, v) in ["2", "3", "4", "5", "6", "7"].iter().enumerate() {
            send(&mut e, &mut d, v, 8 + 4 * i as u64);
            assert!(e.ring.get(0).is_some());
            assert!(d.get(0).is_some());
        }
        assert!(e.size() <= 200);
    }
}
