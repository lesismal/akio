//! An AEAD output buffer that may start uninitialised: [`Fill`] tracks which of its bytes were
//! written, and hands the buffer out as `&mut [u8]` only once every byte holds a value.
//! [`append`] runs a seal or open straight into the spare capacity of a `Vec<u8>` and extends it
//! afterwards, so the TLS record layer appends ciphertext and plaintext without zero-filling the
//! space first.
//!
//! One of the crate's `unsafe` modules (docs/unsafe-review.md), the only one that is not about
//! CPU instructions: `unsafe` for viewing an initialised `&mut [u8]` as `&mut [MaybeUninit<u8>]`
//! (never de-initialised: every write is a `u8`), for viewing the buffer as `&mut [u8]` once it
//! is all written, and for `Vec::set_len` after that. The vector kernels of `gcm::hw` and
//! `chacha::hw` write into the buffer through [`Fill::next_ptr`] and record what they wrote with
//! [`Fill::assume_written`].
#![allow(unsafe_code)]

use std::mem::MaybeUninit;

/// An output buffer written front to back, with an optional initialised suffix written first
/// (the TLS 1.3 inner content type after the record content): bytes `..pos` and `tail..` hold
/// values, and the buffer is complete when `pos >= tail`.
pub(crate) struct Fill<'a> {
    buf: &'a mut [MaybeUninit<u8>],
    pos: usize,
    tail: usize,
}

impl<'a> Fill<'a> {
    /// A buffer with nothing written yet.
    #[inline]
    pub(crate) fn uninit(buf: &'a mut [MaybeUninit<u8>]) -> Fill<'a> {
        let tail = buf.len();
        Fill { buf, pos: 0, tail }
    }

    /// An initialised buffer, written from the front (in place, or over the old bytes).
    #[inline]
    pub(crate) fn init(buf: &'a mut [u8]) -> Fill<'a> {
        let p = std::ptr::from_mut::<[u8]>(buf) as *mut [MaybeUninit<u8>];
        // SAFETY: `MaybeUninit<u8>` has the size, alignment and validity-superset of `u8`, and
        // `p` comes from a unique borrow that this one replaces for `'a`. The caller's bytes
        // stay initialised because `Fill` only ever stores `u8` values into the buffer (its
        // writers `push`, `push_xor`, `push_back` and the kernels behind `next_ptr` write
        // plain bytes), never `MaybeUninit::uninit()`.
        let buf = unsafe { &mut *p };
        Fill {
            buf,
            pos: 0,
            tail: 0,
        }
    }

    /// The buffer length.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Bytes written from the front.
    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Whether every byte holds a value.
    #[inline]
    pub(crate) fn is_full(&self) -> bool {
        self.pos >= self.tail
    }

    /// Writes `s` at the front cursor.
    ///
    /// # Panics
    ///
    /// If `s` does not fit.
    #[inline]
    pub(crate) fn push(&mut self, s: &[u8]) {
        let d = &mut self.buf[self.pos..self.pos + s.len()];
        for (d, s) in d.iter_mut().zip(s) {
            d.write(*s);
        }
        self.pos += s.len();
    }

    /// Writes `s ^ k` (of `s.len()` bytes; `k` at least as long) at the front cursor.
    #[inline]
    pub(crate) fn push_xor(&mut self, s: &[u8], k: &[u8]) {
        assert!(k.len() >= s.len());
        let d = &mut self.buf[self.pos..self.pos + s.len()];
        for ((d, s), k) in d.iter_mut().zip(s).zip(k) {
            d.write(s ^ k);
        }
        self.pos += s.len();
    }

    /// Writes `s` as the last bytes of the buffer, before anything is written from the front.
    ///
    /// # Panics
    ///
    /// If `s` is longer than the unwritten middle.
    #[inline]
    pub(crate) fn push_back(&mut self, s: &[u8]) {
        assert!(s.len() <= self.tail - self.pos, "Fill: no room");
        let at = self.tail - s.len();
        for (d, s) in self.buf[at..self.tail].iter_mut().zip(s) {
            d.write(*s);
        }
        self.tail = at;
    }

    /// Where the next `n` bytes go, for a kernel that writes them through a raw pointer and
    /// then calls [`assume_written`](Self::assume_written). The pointer is valid for writing
    /// `n` bytes until the next use of `self`; the bytes may be uninitialised, so the kernel
    /// must not read them.
    ///
    /// # Panics
    ///
    /// If fewer than `n` bytes are left.
    #[inline]
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) fn next_ptr(&mut self, n: usize) -> *mut u8 {
        self.buf[self.pos..self.pos + n].as_mut_ptr().cast::<u8>()
    }

    /// Records that the `n` bytes at [`next_ptr`](Self::next_ptr) were written.
    ///
    /// # Safety
    ///
    /// Every one of the `n` bytes after the front cursor holds a value written since the
    /// pointer was taken (or before), and `n` is at most the bytes left.
    #[inline]
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub(crate) unsafe fn assume_written(&mut self, n: usize) {
        debug_assert!(n <= self.buf.len() - self.pos);
        self.pos += n;
    }

    /// The whole buffer, every byte written.
    ///
    /// # Panics
    ///
    /// If a byte was not written ([`is_full`](Self::is_full) is false).
    #[inline]
    pub(crate) fn filled(&mut self) -> &mut [u8] {
        assert!(self.is_full(), "Fill: unwritten bytes");
        let len = self.buf.len();
        let p = self.buf.as_mut_ptr().cast::<u8>();
        // SAFETY: `pos >= tail` and bytes `..pos` and `tail..` were written (`push*`, or kernels
        // vouched for by `assume_written`'s contract, or initialised from the start by `init`),
        // so all `len` bytes at `p` are initialised `u8`s; `p` and `len` come from the live
        // unique slice `self.buf`, which the returned borrow of `self` keeps exclusive.
        unsafe { std::slice::from_raw_parts_mut(p, len) }
    }
}

/// Appends `n` bytes to `v`: `f` writes them into a [`Fill`] over `v`'s spare capacity and
/// returns a result and whether to keep them. Kept bytes extend `v`; otherwise (a failed open)
/// `v` keeps its length and the spare bytes `f` wrote are zeroed, so no unverified plaintext is
/// left behind even in the spare capacity.
///
/// # Panics
///
/// If `f` asks to keep bytes it did not write all of (before `v` is changed).
pub(crate) fn append<R>(
    v: &mut Vec<u8>,
    n: usize,
    f: impl FnOnce(&mut Fill<'_>) -> (R, bool),
) -> R {
    v.reserve(n);
    let at = v.len();
    let mut fill = Fill::uninit(&mut v.spare_capacity_mut()[..n]);
    let (r, keep) = f(&mut fill);
    if !keep {
        // Bytes the front cursor wrote (a fused open writes everything before the tag check).
        let pos = fill.pos;
        for b in &mut fill.buf[..pos] {
            b.write(0);
        }
        return r;
    }
    assert!(fill.is_full(), "Fill: unwritten bytes");
    // SAFETY: `fill` covered `v`'s spare bytes `at..at + n` (within the capacity `reserve`
    // made), and it is full, so all of them hold values; `fill`'s borrow of `v` ended above.
    unsafe { v.set_len(at + n) };
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Front and back writes, kept or dropped, over fresh and reused capacity (runs under Miri:
    /// `cargo miri test -p akio-crypto --lib -- fill`).
    #[test]
    fn fill_and_append() {
        let mut v = vec![9u8, 8];
        let r = append(&mut v, 5, |f| {
            f.push_back(&[7]);
            f.push(&[1, 2]);
            f.push_xor(&[3, 4], &[1, 1]);
            assert!(f.is_full());
            f.filled()[0] = 0;
            (f.len(), true)
        });
        assert_eq!((r, &v[..]), (5, &[9, 8, 0, 2, 2, 5, 7][..]));
        // Dropped: the length stays, whatever was written.
        let cap = v.capacity();
        append(&mut v, 3, |f| {
            f.push(&[5, 5, 5]);
            ((), false)
        });
        assert_eq!(v, [9, 8, 0, 2, 2, 5, 7]);
        assert!(v.capacity() >= cap);
        // Kept with nothing to write.
        append(&mut v, 0, |f| ((), f.is_full()));
        assert_eq!(v.len(), 7);
        // In place over initialised bytes.
        let mut b = [1u8, 2, 3];
        let mut f = Fill::init(&mut b);
        assert!(f.is_full());
        f.push(&[4]);
        f.filled()[2] = 6;
        assert_eq!(b, [4, 2, 6]);
    }

    #[test]
    #[should_panic(expected = "unwritten")]
    fn partial_fill_is_not_kept() {
        let mut v = Vec::new();
        append(&mut v, 4, |f| {
            f.push(&[1, 2, 3]);
            ((), true)
        });
    }
}
