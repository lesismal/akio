//! Constants of the DEFLATE format (RFC 1951, section 3.2.5).

/// Base match length of length symbols 257..=285.
pub(crate) const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// Extra bits of length symbols 257..=285.
pub(crate) const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// Base distance of distance symbols 0..=29.
pub(crate) const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// Extra bits of distance symbols 0..=29.
pub(crate) const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// Order in which the code length code lengths are sent.
pub(crate) const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Code lengths of the fixed literal/length code.
pub(crate) const fn fixed_lit_lens() -> [u8; 288] {
    let mut l = [0u8; 288];
    let mut i = 0;
    while i < 288 {
        l[i] = if i < 144 {
            8
        } else if i < 256 {
            9
        } else if i < 280 {
            7
        } else {
            8
        };
        i += 1;
    }
    l
}

/// Reverses the low `len` bits of `code` (DEFLATE sends Huffman codes most significant bit
/// first inside a least-significant-bit-first bit stream).
pub(crate) const fn reverse_bits(code: u32, len: u32) -> u32 {
    if len == 0 {
        0
    } else {
        code.reverse_bits() >> (32 - len)
    }
}

/// Counts of each code length (0..=15) in `lens`, with `count[0]` set to 0. Four interleaved
/// counters avoid the store-to-load stall of incrementing one counter for runs of equal
/// lengths.
#[inline]
pub(crate) fn length_counts(lens: &[u8]) -> [u16; 16] {
    let mut c = [[0u16; 16]; 4];
    let mut chunks = lens.chunks_exact(4);
    for q in &mut chunks {
        c[0][usize::from(q[0] & 15)] += 1;
        c[1][usize::from(q[1] & 15)] += 1;
        c[2][usize::from(q[2] & 15)] += 1;
        c[3][usize::from(q[3] & 15)] += 1;
    }
    for &l in chunks.remainder() {
        c[0][usize::from(l & 15)] += 1;
    }
    let mut count = [0u16; 16];
    for (i, n) in count.iter_mut().enumerate().skip(1) {
        *n = c[0][i] + c[1][i] + c[2][i] + c[3][i];
    }
    count
}
