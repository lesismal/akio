//! [`Bytes`]: a cheaply cloneable, sliceable byte buffer (reference counted), the type of stream
//! and datagram payloads in this crate's API. It has the shape of the `bytes` crate's `Bytes`
//! that the API used before (DEV-PLAN wave D removed that dependency).

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Bound, Deref, RangeBounds};
use std::sync::Arc;

/// Receive buffers kept for reuse per thread: a received datagram is copied into one, decrypted
/// in place, and its frames' payloads ([`Bytes`] slices) share it. A buffer is reused once every
/// slice of it has dropped (on any thread), so steady traffic allocates nothing per packet.
pub(crate) mod pool {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// Buffers kept per thread (about 1.5 KB each for full-size datagrams).
    const MAX: usize = 256;
    /// Buffers looked at for a free one before allocating (a slice still held elsewhere, an
    /// out-of-order stream fragment for example, keeps its buffer busy).
    const TRIES: usize = 8;

    thread_local! {
        static POOL: RefCell<VecDeque<Arc<Vec<u8>>>> = const { RefCell::new(VecDeque::new()) };
    }

    /// A buffer holding a copy of `data`, unshared.
    pub(crate) fn copy(data: &[u8]) -> Arc<Vec<u8>> {
        fill(data.len(), |v| v.extend_from_slice(data))
    }

    /// A buffer filled by `f` (from empty), unshared; `hint` sizes a new one.
    pub(crate) fn fill(hint: usize, f: impl FnOnce(&mut Vec<u8>)) -> Arc<Vec<u8>> {
        let mut b = POOL
            .try_with(|p| {
                let mut p = p.borrow_mut();
                for _ in 0..TRIES.min(p.len()) {
                    let mut b = p.pop_front()?;
                    if Arc::get_mut(&mut b).is_some() {
                        return Some(b);
                    }
                    p.push_back(b);
                }
                None
            })
            .ok()
            .flatten()
            .unwrap_or_else(|| Arc::new(Vec::with_capacity(hint)));
        if let Some(v) = Arc::get_mut(&mut b) {
            v.clear();
            f(v);
        }
        b
    }

    /// Done with a buffer (slices of it may live on): keep it for a later [`copy`].
    pub(crate) fn recycle(b: Arc<Vec<u8>>) {
        // Only buffers of ordinary datagram sizes are worth keeping.
        if b.capacity() > 1 << 16 {
            return;
        }
        // Not during thread teardown (the pool may be gone).
        let _ = POOL.try_with(|p| {
            let mut p = p.borrow_mut();
            if p.len() < MAX {
                p.push_back(b);
            }
        });
    }
}

#[derive(Clone)]
enum Repr {
    Static(&'static [u8]),
    Shared(Arc<Vec<u8>>),
    /// A range of the UDP receive slab the datagram arrived in (ADR-024): no copy at all.
    Chunk(only_buf::slab::Chunk),
}

/// A received packet being processed: a pooled buffer (see [`pool`]), or the datagram's own
/// range of the UDP receive slab (`only_buf::slab`, ADR-024), decrypted in place either way.
/// Its frames become [`Bytes`] slices of it ([`PktBuf::share`]).
#[derive(Default)]
pub(crate) enum PktBuf {
    Vec(Arc<Vec<u8>>),
    /// Exclusive, writable (not shared yet).
    Chunk(only_buf::slab::ChunkMut),
    /// Shared by `Bytes` slices: read-only.
    Frozen(only_buf::slab::Chunk),
    #[default]
    Empty,
}

impl PktBuf {
    /// The bytes, writable: a shared buffer is copied first (into the pool) and replaced by the
    /// copy, as `Arc::make_mut` does.
    pub(crate) fn make_mut(&mut self) -> &mut [u8] {
        if let PktBuf::Frozen(c) = self {
            *self = PktBuf::Vec(pool::copy(c));
        }
        match self {
            PktBuf::Vec(v) => Arc::make_mut(v).as_mut_slice(),
            PktBuf::Chunk(c) => c,
            PktBuf::Frozen(_) | PktBuf::Empty => &mut [],
        }
    }

    /// The whole buffer as a [`Bytes`] its holder can keep: a slab range is frozen (read-only
    /// from now on) and shared, not copied.
    pub(crate) fn share(&mut self) -> Bytes {
        if matches!(self, PktBuf::Chunk(_)) {
            if let PktBuf::Chunk(c) = std::mem::replace(self, PktBuf::Empty) {
                *self = PktBuf::Frozen(c.freeze());
            }
        }
        match self {
            PktBuf::Vec(v) => Bytes::from_shared(v.clone()),
            PktBuf::Frozen(c) => {
                let end = c.len();
                Bytes {
                    repr: Repr::Chunk(c.clone()),
                    start: 0,
                    end,
                }
            }
            PktBuf::Chunk(_) | PktBuf::Empty => Bytes::new(),
        }
    }

    /// Done with it (slices of it may live on): a pooled buffer goes back to the pool.
    pub(crate) fn recycle(self) {
        if let PktBuf::Vec(v) = self {
            pool::recycle(v);
        }
    }
}

impl Deref for PktBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            PktBuf::Vec(v) => v,
            PktBuf::Chunk(c) => c,
            PktBuf::Frozen(c) => c,
            PktBuf::Empty => &[],
        }
    }
}

impl From<Arc<Vec<u8>>> for PktBuf {
    fn from(v: Arc<Vec<u8>>) -> PktBuf {
        PktBuf::Vec(v)
    }
}

impl From<only_buf::slab::ChunkMut> for PktBuf {
    fn from(c: only_buf::slab::ChunkMut) -> PktBuf {
        PktBuf::Chunk(c)
    }
}

/// An immutable, reference-counted byte buffer: cloning and slicing share the bytes instead of
/// copying them. Received stream data and datagrams are slices of the decrypted packet.
#[derive(Clone)]
pub struct Bytes {
    repr: Repr,
    start: usize,
    end: usize,
}

impl Bytes {
    /// An empty buffer.
    pub const fn new() -> Bytes {
        Bytes {
            repr: Repr::Static(&[]),
            start: 0,
            end: 0,
        }
    }

    /// A buffer over static bytes (no allocation).
    pub const fn from_static(data: &'static [u8]) -> Bytes {
        Bytes {
            repr: Repr::Static(data),
            start: 0,
            end: data.len(),
        }
    }

    /// A buffer holding a copy of `data`.
    pub fn copy_from_slice(data: &[u8]) -> Bytes {
        Bytes::from(data.to_vec())
    }

    /// A buffer written by `f`, in storage reused from earlier buffers of this thread once
    /// every copy of them has dropped: steady traffic allocates nothing per buffer (a
    /// `Vec` turned into `Bytes` costs two allocations). For small, short-lived buffers such
    /// as HTTP/3 heads; `hint` sizes a fresh buffer.
    ///
    /// `#[doc(hidden)]`: for only-h3, not a public API; it may change in any release.
    #[doc(hidden)]
    pub fn pooled(hint: usize, f: impl FnOnce(&mut Vec<u8>)) -> Bytes {
        let b = pool::fill(hint, f);
        let out = Bytes::from_shared(b.clone());
        pool::recycle(b);
        out
    }

    /// The whole of a shared buffer (no copy, no allocation).
    pub(crate) fn from_shared(v: Arc<Vec<u8>>) -> Bytes {
        let end = v.len();
        Bytes {
            repr: Repr::Shared(v),
            start: 0,
            end,
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    fn whole(&self) -> &[u8] {
        match &self.repr {
            Repr::Static(s) => s,
            Repr::Shared(v) => v,
            Repr::Chunk(c) => c,
        }
    }

    /// The bytes in `range` (relative to this buffer), sharing the allocation.
    ///
    /// # Panics
    ///
    /// If the range is out of bounds.
    #[must_use]
    pub fn slice(&self, range: impl RangeBounds<usize>) -> Bytes {
        let len = self.len();
        let lo = match range.start_bound() {
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n + 1,
            Bound::Unbounded => 0,
        };
        let hi = match range.end_bound() {
            Bound::Included(&n) => n + 1,
            Bound::Excluded(&n) => n,
            Bound::Unbounded => len,
        };
        assert!(lo <= hi && hi <= len, "Bytes::slice out of bounds");
        Bytes {
            repr: self.repr.clone(),
            start: self.start + lo,
            end: self.start + hi,
        }
    }

    /// Splits off and returns the first `at` bytes; `self` keeps the rest.
    ///
    /// # Panics
    ///
    /// If `at > len()`.
    #[must_use]
    pub fn split_to(&mut self, at: usize) -> Bytes {
        assert!(at <= self.len(), "Bytes::split_to out of bounds");
        let head = Bytes {
            repr: self.repr.clone(),
            start: self.start,
            end: self.start + at,
        };
        self.start += at;
        head
    }

    /// Splits off and returns the bytes from `at` on; `self` keeps the first `at`.
    ///
    /// # Panics
    ///
    /// If `at > len()`.
    #[must_use]
    pub fn split_off(&mut self, at: usize) -> Bytes {
        assert!(at <= self.len(), "Bytes::split_off out of bounds");
        let tail = Bytes {
            repr: self.repr.clone(),
            start: self.start + at,
            end: self.end,
        };
        self.end = self.start + at;
        tail
    }

    /// Shortens the buffer to `len` bytes (no-op if it is shorter).
    pub fn truncate(&mut self, len: usize) {
        if len < self.len() {
            self.end = self.start + len;
        }
    }

    /// Drops the first `n` bytes.
    ///
    /// # Panics
    ///
    /// If `n > len()`.
    pub fn advance(&mut self, n: usize) {
        assert!(n <= self.len(), "Bytes::advance out of bounds");
        self.start += n;
    }

    /// Empties the buffer.
    pub fn clear(&mut self) {
        self.start = self.end;
    }
}

impl Default for Bytes {
    fn default() -> Bytes {
        Bytes::new()
    }
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.whole()[self.start..self.end]
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Borrow<[u8]> for Bytes {
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("b\"")?;
        for &b in &self[..] {
            match b {
                b'\n' => f.write_str("\\n")?,
                b'\r' => f.write_str("\\r")?,
                b'\t' => f.write_str("\\t")?,
                b'\\' | b'"' => write!(f, "\\{}", b as char)?,
                0x20..=0x7e => write!(f, "{}", b as char)?,
                _ => write!(f, "\\x{b:02x}")?,
            }
        }
        f.write_str("\"")
    }
}

impl PartialEq for Bytes {
    fn eq(&self, o: &Bytes) -> bool {
        self[..] == o[..]
    }
}
impl Eq for Bytes {}

impl PartialOrd for Bytes {
    fn partial_cmp(&self, o: &Bytes) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Bytes {
    fn cmp(&self, o: &Bytes) -> Ordering {
        self[..].cmp(&o[..])
    }
}

impl Hash for Bytes {
    fn hash<H: Hasher>(&self, h: &mut H) {
        self[..].hash(h);
    }
}

impl PartialEq<[u8]> for Bytes {
    fn eq(&self, o: &[u8]) -> bool {
        self[..] == *o
    }
}
impl PartialEq<&[u8]> for Bytes {
    fn eq(&self, o: &&[u8]) -> bool {
        self[..] == **o
    }
}
impl PartialEq<Vec<u8>> for Bytes {
    fn eq(&self, o: &Vec<u8>) -> bool {
        self[..] == o[..]
    }
}
impl PartialEq<str> for Bytes {
    fn eq(&self, o: &str) -> bool {
        self[..] == *o.as_bytes()
    }
}
impl PartialEq<&str> for Bytes {
    fn eq(&self, o: &&str) -> bool {
        self[..] == *o.as_bytes()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Bytes {
        let end = v.len();
        Bytes {
            repr: Repr::Shared(Arc::new(v)),
            start: 0,
            end,
        }
    }
}

impl From<Box<[u8]>> for Bytes {
    fn from(v: Box<[u8]>) -> Bytes {
        Bytes::from(v.into_vec())
    }
}

impl From<String> for Bytes {
    fn from(s: String) -> Bytes {
        Bytes::from(s.into_bytes())
    }
}

impl From<&'static [u8]> for Bytes {
    fn from(s: &'static [u8]) -> Bytes {
        Bytes::from_static(s)
    }
}

impl From<&'static str> for Bytes {
    fn from(s: &'static str) -> Bytes {
        Bytes::from_static(s.as_bytes())
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(b: Bytes) -> Vec<u8> {
        match b.repr {
            Repr::Shared(v) if b.start == 0 && b.end == v.len() => {
                Arc::try_unwrap(v).unwrap_or_else(|v| v.to_vec())
            }
            _ => b[..].to_vec(),
        }
    }
}

impl FromIterator<u8> for Bytes {
    fn from_iter<T: IntoIterator<Item = u8>>(it: T) -> Bytes {
        Bytes::from(it.into_iter().collect::<Vec<u8>>())
    }
}

impl<'a> IntoIterator for &'a Bytes {
    type Item = &'a u8;
    type IntoIter = std::slice::Iter<'a, u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_share_and_split() {
        let mut b = Bytes::from(b"hello world".to_vec());
        let c = b.clone();
        assert_eq!(b.slice(6..), Bytes::from_static(b"world"));
        assert_eq!(b.slice(..=4), "hello");
        let head = b.split_to(6);
        assert_eq!(head, &b"hello "[..]);
        assert_eq!(b, "world");
        let tail = b.split_off(2);
        assert_eq!((b.len(), tail.len()), (2, 3));
        assert_eq!(tail, b"rld".to_vec());
        let mut t = c.clone();
        t.truncate(4);
        t.advance(1);
        assert_eq!(t, "ell");
        t.clear();
        assert!(t.is_empty());
        assert_eq!(Vec::from(c.clone()), b"hello world".to_vec());
        assert_eq!(Vec::from(c.slice(1..3)), b"el".to_vec());
        assert_eq!(
            format!("{:?}", Bytes::from_static(b"a\"\n\x01")),
            "b\"a\\\"\\n\\x01\""
        );
        assert_eq!(Bytes::from(String::from("x")), Bytes::from("x"));
        assert_eq!(Bytes::default(), Bytes::new());
        assert!(Bytes::from_static(b"a") < Bytes::copy_from_slice(b"b"));
        let it: Bytes = (0u8..3).collect();
        assert_eq!((&it).into_iter().copied().sum::<u8>(), 3);
        assert_eq!(Bytes::from(vec![1u8].into_boxed_slice()).as_ref(), &[1]);
        let r: &[u8] = it.borrow();
        assert_eq!(r.len(), 3);
        let mut h = std::collections::hash_map::DefaultHasher::new();
        it.hash(&mut h);
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn slice_out_of_bounds_panics() {
        let _ = Bytes::from_static(b"ab").slice(1..3);
    }
}
