//! Argon2id (RFC 9106), version 0x13, over BLAKE2b.
//!
//! Memory is `m' = 4·p·⌊m / 4p⌋` blocks of 1 KiB (`m` the memory in KiB, `p` the lanes), one
//! allocation made fallibly before any work. Each slice of each pass fills the lanes' segments
//! on threads of a scoped group (at most one per lane and per available CPU); the segments are
//! disjoint `&mut` borrows of that allocation and the blocks they read are shared borrows of the
//! rest, so the threads need no lock and no `unsafe`, and the result is the same as one lane
//! after another.

use crate::Error;
use crate::hash::Blake2b;

/// Words (u64) in a 1 KiB block.
const WORDS: usize = 128;
/// Slices of a pass (RFC 9106's `SL`).
const SYNC_POINTS: usize = 4;
/// Argon2 version 0x13.
const VERSION: u32 = 0x13;
/// Argon2id's type number `y`.
const TYPE_ID: u64 = 2;

#[derive(Clone, Copy)]
struct Block([u64; WORDS]);

impl Block {
    const ZERO: Block = Block([0; WORDS]);

    fn from_bytes(b: &[u8; 1024]) -> Block {
        let mut out = Block::ZERO;
        for (w, c) in out.0.iter_mut().zip(b.chunks_exact(8)) {
            *w = u64::from_le_bytes(c.try_into().unwrap_or_else(|_| unreachable!()));
        }
        out
    }

    fn to_bytes(self) -> [u8; 1024] {
        let mut out = [0u8; 1024];
        for (c, w) in out.chunks_exact_mut(8).zip(self.0) {
            c.copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// The parameters derived from the caller's, shared by every segment.
#[derive(Clone, Copy)]
struct Geometry {
    lanes: usize,
    lane_len: usize,
    seg_len: usize,
    /// `m'`, in blocks.
    blocks: u64,
    passes: u64,
}

/// Argon2id with a password, salt and costs, as Go's `argon2.IDKey` (no secret, no associated
/// data): fills `out` (4 bytes or more) from `password` and `salt` (8 bytes or more) after
/// `time` passes over `memory_kib` KiB of memory split into `lanes` lanes.
///
/// Fails, before allocating or computing anything, with [`Error::InvalidLength`] for a salt
/// shorter than 8 bytes, an output shorter than 4 bytes or an input longer than `u32::MAX`
/// bytes, and with [`Error::InvalidParameter`] for `time` or `lanes` of 0 or a `memory_kib`
/// below 8 per lane (RFC 9106's bounds); with [`Error::OutOfMemory`] when the memory cannot be
/// allocated. The memory is about `memory_kib` KiB (rounded down to a multiple of `4·lanes`), held
/// for the call only. The call takes time in proportion to `time × memory_kib` and is meant for
/// a thread that may block (a control thread or the logical pool, never an I/O thread); the
/// caller bounds both costs when they come from outside (a file header, a request).
///
/// Lanes are filled on up to `lanes` threads (no more than the CPUs available), and one after
/// another if a thread cannot be started; the output does not depend on it.
///
/// ```
/// use akio_crypto::kdf;
///
/// let mut key = [0u8; 32];
/// kdf::argon2id(b"password", b"somesalt", 1, 64, 2, &mut key).unwrap();
/// ```
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    time: u32,
    memory_kib: u32,
    lanes: u8,
    out: &mut [u8],
) -> Result<(), Error> {
    argon2id_full(
        password,
        salt,
        &[],
        &[],
        time,
        memory_kib,
        u32::from(lanes),
        out,
        std::thread::available_parallelism().map_or(1, usize::from),
    )
}

/// Argon2id with RFC 9106's optional secret `K` and associated data `X` (for the RFC's test
/// vector), on up to `threads` threads.
#[allow(clippy::too_many_arguments)]
pub(crate) fn argon2id_full(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    time: u32,
    memory_kib: u32,
    lanes: u32,
    out: &mut [u8],
    threads: usize,
) -> Result<(), Error> {
    let max = u32::MAX as usize;
    if salt.len() < 8
        || out.len() < 4
        || [
            password.len(),
            salt.len(),
            secret.len(),
            ad.len(),
            out.len(),
        ]
        .iter()
        .any(|&n| n > max)
    {
        return Err(Error::InvalidLength);
    }
    if time == 0
        || lanes == 0
        || lanes > 0x00ff_ffff
        || u64::from(memory_kib) < 8 * u64::from(lanes)
    {
        return Err(Error::InvalidParameter);
    }
    let lanes_n = lanes as usize;
    let threads = threads.clamp(1, lanes_n);
    let lane_len = memory_kib as usize / (SYNC_POINTS * lanes_n) * SYNC_POINTS;
    let g = Geometry {
        lanes: lanes_n,
        lane_len,
        seg_len: lane_len / SYNC_POINTS,
        blocks: (lane_len * lanes_n) as u64,
        passes: u64::from(time),
    };

    let mut mem: Vec<Block> = Vec::new();
    let total = lane_len.checked_mul(lanes_n).ok_or(Error::OutOfMemory)?;
    mem.try_reserve_exact(total)
        .map_err(|_| Error::OutOfMemory)?;
    mem.resize(total, Block::ZERO);

    // H0 (RFC 9106, section 3.2, step 1).
    let mut h = Blake2b::with_len(64);
    for v in [
        lanes,
        out.len() as u32,
        memory_kib,
        time,
        VERSION,
        TYPE_ID as u32,
    ] {
        h.update(&v.to_le_bytes());
    }
    for field in [password, salt, secret, ad] {
        h.update(&(field.len() as u32).to_le_bytes());
        h.update(field);
    }
    let mut h0 = [0u8; 64];
    h.finalize_into(&mut h0).unwrap_or_else(|_| unreachable!());

    // The first two blocks of each lane (steps 3 and 4).
    let mut buf = [0u8; 1024];
    for (lane, lm) in mem.chunks_mut(lane_len).enumerate() {
        for (col, b) in lm.iter_mut().take(2).enumerate() {
            hprime(
                &mut buf,
                &[
                    &h0,
                    &(col as u32).to_le_bytes(),
                    &(lane as u32).to_le_bytes(),
                ],
            );
            *b = Block::from_bytes(&buf);
        }
    }

    for pass in 0..time {
        for slice in 0..SYNC_POINTS {
            fill_slice(&mut mem, &g, u64::from(pass), slice, threads);
        }
    }

    // The XOR of each lane's last block, through H' (steps 7 and 8).
    let mut acc = mem[lane_len - 1];
    for lm in mem.chunks(lane_len).skip(1) {
        for (a, b) in acc.0.iter_mut().zip(lm[lane_len - 1].0) {
            *a ^= b;
        }
    }
    hprime(out, &[&acc.to_bytes()]);
    Ok(())
}

/// The variable-length hash H' (RFC 9106, section 3.3) of the concatenated `parts`, `out.len()`
/// bytes long (1 to `u32::MAX`).
fn hprime(out: &mut [u8], parts: &[&[u8]]) {
    let t = (out.len() as u32).to_le_bytes();
    if out.len() <= 64 {
        let mut h = Blake2b::with_len(out.len());
        h.update(&t);
        for p in parts {
            h.update(p);
        }
        h.finalize_into(out).unwrap_or_else(|_| unreachable!());
        return;
    }
    let mut v = [0u8; 64];
    let mut h = Blake2b::with_len(64);
    h.update(&t);
    for p in parts {
        h.update(p);
    }
    h.finalize_into(&mut v).unwrap_or_else(|_| unreachable!());
    out[..32].copy_from_slice(&v[..32]);
    let mut pos = 32;
    while out.len() - pos > 64 {
        let mut h = Blake2b::with_len(64);
        h.update(&v);
        h.finalize_into(&mut v).unwrap_or_else(|_| unreachable!());
        out[pos..pos + 32].copy_from_slice(&v[..32]);
        pos += 32;
    }
    let mut h = Blake2b::with_len(out.len() - pos);
    h.update(&v);
    h.finalize_into(&mut out[pos..])
        .unwrap_or_else(|_| unreachable!());
}

/// The blocks other segments of a slice may read: for each lane, the columns before the slice
/// and those after it.
struct Others<'a> {
    views: Vec<(&'a [Block], &'a [Block])>,
    seg_start: usize,
    seg_len: usize,
}

impl Others<'_> {
    fn get(&self, lane: usize, col: usize) -> &Block {
        let (before, after) = self.views[lane];
        if col < self.seg_start {
            &before[col]
        } else {
            &after[col - self.seg_start - self.seg_len]
        }
    }
}

/// Fills slice `slice` of pass `pass` in every lane, on up to `threads` threads.
fn fill_slice(mem: &mut [Block], g: &Geometry, pass: u64, slice: usize, threads: usize) {
    let seg_start = slice * g.seg_len;
    let mut segs: Vec<(usize, &mut [Block])> = Vec::with_capacity(g.lanes);
    let mut views = Vec::with_capacity(g.lanes);
    for (lane, lm) in mem.chunks_mut(g.lane_len).enumerate() {
        let (before, rest) = lm.split_at_mut(seg_start);
        let (seg, after) = rest.split_at_mut(g.seg_len);
        views.push((&*before, &*after));
        segs.push((lane, seg));
    }
    let others = Others {
        views,
        seg_start,
        seg_len: g.seg_len,
    };
    if threads <= 1 {
        for (lane, seg) in segs {
            fill_segment(g, pass, slice, lane, seg, &others);
        }
        return;
    }
    // Deal the segments out to `threads` groups; the last group runs on this thread.
    let mut groups: Vec<Vec<(usize, &mut [Block])>> = (0..threads).map(|_| Vec::new()).collect();
    for (i, s) in segs.into_iter().enumerate() {
        groups[i % threads].push(s);
    }
    let others = &others;
    std::thread::scope(|scope| {
        let mine = groups.pop().unwrap_or_default();
        for group in groups {
            // A group whose thread cannot start is filled here instead; `spawn_scoped` hands
            // the closure back only through its error, so the group goes in an `Option`.
            let cell = std::sync::Mutex::new(Some(group));
            let cell = std::sync::Arc::new(cell);
            let theirs = std::sync::Arc::clone(&cell);
            let spawned = std::thread::Builder::new()
                .name("akio-argon2".into())
                .spawn_scoped(scope, move || {
                    let group = theirs.lock().ok().and_then(|mut g| g.take());
                    for (lane, seg) in group.into_iter().flatten() {
                        fill_segment(g, pass, slice, lane, seg, others);
                    }
                });
            if spawned.is_err() {
                let group = cell.lock().ok().and_then(|mut g| g.take());
                for (lane, seg) in group.into_iter().flatten() {
                    fill_segment(g, pass, slice, lane, seg, others);
                }
            }
        }
        for (lane, seg) in mine {
            fill_segment(g, pass, slice, lane, seg, others);
        }
    });
}

/// RFC 9106's mapping of `J1` onto a column of the reference lane (section 3.4.2), for the
/// block at index `index` of the segment.
fn ref_column(
    g: &Geometry,
    pass: u64,
    slice: usize,
    index: usize,
    j1: u32,
    same_lane: bool,
) -> usize {
    let area = if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice * g.seg_len + index - 1
        } else {
            slice * g.seg_len - usize::from(index == 0)
        }
    } else if same_lane {
        g.lane_len - g.seg_len + index - 1
    } else {
        g.lane_len - g.seg_len - usize::from(index == 0)
    } as u64;
    let x = (u64::from(j1) * u64::from(j1)) >> 32;
    let rel = area - 1 - ((area * x) >> 32);
    let start = if pass == 0 || slice == SYNC_POINTS - 1 {
        0
    } else {
        (slice + 1) * g.seg_len
    };
    (start + rel as usize) % g.lane_len
}

/// Fills one lane's segment of a slice (RFC 9106, section 3.2, steps 5 and 6).
fn fill_segment(
    g: &Geometry,
    pass: u64,
    slice: usize,
    lane: usize,
    seg: &mut [Block],
    others: &Others<'_>,
) {
    let seg_start = slice * g.seg_len;
    // Argon2id: data-independent addressing (Argon2i) for the first half of the first pass.
    let indep = pass == 0 && slice < SYNC_POINTS / 2;
    let mut input = Block::ZERO;
    let mut addr = Block::ZERO;
    if indep {
        input.0[..6].copy_from_slice(&[
            pass,
            lane as u64,
            slice as u64,
            g.blocks,
            g.passes,
            TYPE_ID,
        ]);
    }
    let first = if pass == 0 && slice == 0 {
        if indep {
            next_addresses(&mut addr, &mut input);
        }
        2
    } else {
        0
    };
    for i in first..g.seg_len {
        let col = seg_start + i;
        let (done, rest) = seg.split_at_mut(i);
        let prev = if i > 0 {
            &done[i - 1]
        } else if col == 0 {
            others.get(lane, g.lane_len - 1)
        } else {
            others.get(lane, col - 1)
        };
        let rand = if indep {
            if i % WORDS == 0 {
                next_addresses(&mut addr, &mut input);
            }
            addr.0[i % WORDS]
        } else {
            prev.0[0]
        };
        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            ((rand >> 32) % g.lanes as u64) as usize
        };
        let same = ref_lane == lane;
        let ref_col = ref_column(g, pass, slice, i, rand as u32, same);
        let reference = if same && (seg_start..col).contains(&ref_col) {
            &done[ref_col - seg_start]
        } else {
            others.get(ref_lane, ref_col)
        };
        fill_block(prev, reference, &mut rest[0], pass > 0);
    }
}

/// The next block of pseudo-random addresses: `G(0, G(0, input))` after counting `input` up.
fn next_addresses(addr: &mut Block, input: &mut Block) {
    input.0[6] = input.0[6].wrapping_add(1);
    let mut a = Block::ZERO;
    fill_block(&Block::ZERO, input, &mut a, false);
    let first = a;
    fill_block(&Block::ZERO, &first, addr, false);
}

/// The compression function G (RFC 9106, section 3.5): `next = P(prev ⊕ ref) ⊕ prev ⊕ ref`,
/// XORed into the old `next` when `xor` (passes after the first, version 0x13).
fn fill_block(prev: &Block, reference: &Block, next: &mut Block, xor: bool) {
    let mut r = Block::ZERO;
    for ((r, a), b) in r.0.iter_mut().zip(prev.0).zip(reference.0) {
        *r = a ^ b;
    }
    let mut tmp = r;
    if xor {
        for (t, n) in tmp.0.iter_mut().zip(next.0) {
            *t ^= n;
        }
    }
    let v = &mut r.0;
    for row in 0..8 {
        let b = row * 16;
        round(
            v,
            [
                b,
                b + 1,
                b + 2,
                b + 3,
                b + 4,
                b + 5,
                b + 6,
                b + 7,
                b + 8,
                b + 9,
                b + 10,
                b + 11,
                b + 12,
                b + 13,
                b + 14,
                b + 15,
            ],
        );
    }
    for col in 0..8 {
        let b = col * 2;
        round(
            v,
            [
                b,
                b + 1,
                b + 16,
                b + 17,
                b + 32,
                b + 33,
                b + 48,
                b + 49,
                b + 64,
                b + 65,
                b + 80,
                b + 81,
                b + 96,
                b + 97,
                b + 112,
                b + 113,
            ],
        );
    }
    for ((n, t), r) in next.0.iter_mut().zip(tmp.0).zip(r.0) {
        *n = t ^ r;
    }
}

/// BLAKE2b's round without a message, on the multiply-hardened `GB` (RFC 9106, section 3.6),
/// over the sixteen words at `i`.
#[inline(always)]
fn round(v: &mut [u64; WORDS], i: [usize; 16]) {
    gb(v, i[0], i[4], i[8], i[12]);
    gb(v, i[1], i[5], i[9], i[13]);
    gb(v, i[2], i[6], i[10], i[14]);
    gb(v, i[3], i[7], i[11], i[15]);
    gb(v, i[0], i[5], i[10], i[15]);
    gb(v, i[1], i[6], i[11], i[12]);
    gb(v, i[2], i[7], i[8], i[13]);
    gb(v, i[3], i[4], i[9], i[14]);
}

#[inline(always)]
fn bla_mka(x: u64, y: u64) -> u64 {
    let m = u64::from(x as u32) * u64::from(y as u32);
    x.wrapping_add(y).wrapping_add(m.wrapping_mul(2))
}

#[inline(always)]
fn gb(v: &mut [u64; WORDS], a: usize, b: usize, c: usize, d: usize) {
    v[a] = bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = bla_mka(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = bla_mka(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hex;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9106_argon2id() {
        // RFC 9106, section 5.3.
        let mut out = [0u8; 32];
        argon2id_full(&[1; 32], &[2; 16], &[3; 8], &[4; 12], 3, 32, 4, &mut out, 4).unwrap();
        assert_eq!(
            hex(&out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// Outputs of Go's `golang.org/x/crypto/argon2.IDKey` (x/crypto v0.58.0, Go 1.27), the
    /// function fit's store calls; the first line is fit's setting (time 3, 64 MiB, 4 lanes).
    /// Made by a short Go program that prints `IDKey` for each line's inputs (recorded in
    /// docs/constant-time.md's Argon2id entry).
    const GO: &[(&str, &str, u32, u32, u8, &str)] = &[
        (
            "636f727265637420686f727365206261747465727920737461706c65",
            "000102030405060708090a0b0c0d0e0f",
            3,
            65536,
            4,
            "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e",
        ),
        (
            "70617373776f7264",
            "736f6d6573616c74",
            1,
            8,
            1,
            "f137f8e186a403a679ccd0606e5ab5dcdafe43c1640855ac8c6e33e9bd63eeb3",
        ),
        (
            "70617373776f7264",
            "736f6d6573616c74",
            2,
            64,
            2,
            "07f4fffda0aed64bd50549438340ef1346f45c95891c212db834702b8c37dc18\
             bf5a600612c76121855ec5974a6ddd78e428164a7d370d71d3babc97c7493185",
        ),
        ("", "030a11181f262d34", 1, 32, 4, "284991bc"),
    ];

    #[test]
    fn go_idkey() {
        for &(pw, salt, t, m, p, want) in GO {
            let want = unhex(&want.replace(' ', ""));
            let mut out = vec![0u8; want.len()];
            argon2id(&unhex(pw), &unhex(salt), t, m, p, &mut out).unwrap();
            assert_eq!(hex(&out), hex(&want), "t={t} m={m} p={p}");
        }
    }

    #[test]
    fn threads_do_not_change_the_result() {
        for lanes in [2, 3, 5] {
            let mut one = [0u8; 40];
            argon2id_full(
                b"pw",
                b"saltsalt",
                b"k",
                b"x",
                2,
                8 * lanes * 3,
                lanes,
                &mut one,
                1,
            )
            .unwrap();
            for threads in [2, 4, 16] {
                let mut many = [0u8; 40];
                argon2id_full(
                    b"pw",
                    b"saltsalt",
                    b"k",
                    b"x",
                    2,
                    8 * lanes * 3,
                    lanes,
                    &mut many,
                    threads,
                )
                .unwrap();
                assert_eq!(one, many, "lanes {lanes} threads {threads}");
            }
        }
    }

    #[test]
    fn bounds_are_errors() {
        let mut out = [0u8; 32];
        let e = |r: Result<(), Error>| r.err();
        assert_eq!(
            e(argon2id(b"p", b"short", 1, 64, 1, &mut out)),
            Some(Error::InvalidLength)
        );
        assert_eq!(
            e(argon2id(b"p", b"saltsalt", 1, 64, 1, &mut out[..3])),
            Some(Error::InvalidLength)
        );
        assert_eq!(
            e(argon2id(b"p", b"saltsalt", 0, 64, 1, &mut out)),
            Some(Error::InvalidParameter)
        );
        assert_eq!(
            e(argon2id(b"p", b"saltsalt", 1, 64, 0, &mut out)),
            Some(Error::InvalidParameter)
        );
        assert_eq!(
            e(argon2id(b"p", b"saltsalt", 1, 31, 4, &mut out)),
            Some(Error::InvalidParameter)
        );
        assert_eq!(e(argon2id(b"p", b"saltsalt", 1, 32, 4, &mut out)), None);
    }
}
