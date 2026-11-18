//! XXH64, the hash of Zstandard's content checksum (its low 32 bits).

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

fn merge(acc: u64, v: u64) -> u64 {
    (acc ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

fn le64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

fn le32(b: &[u8]) -> u64 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[..4]);
    u64::from(u32::from_le_bytes(a))
}

/// XXH64 of `data` with `seed`. Zstandard's Content_Checksum is the low 32 bits of
/// `xxh64(content, 0)`.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut rest = data;
    let mut h = if data.len() >= 32 {
        let mut v = [
            seed.wrapping_add(P1).wrapping_add(P2),
            seed.wrapping_add(P2),
            seed,
            seed.wrapping_sub(P1),
        ];
        let mut stripes = data.chunks_exact(32);
        for s in &mut stripes {
            for (i, v) in v.iter_mut().enumerate() {
                *v = round(*v, le64(&s[i * 8..]));
            }
        }
        rest = stripes.remainder();
        let mut h = v[0]
            .rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18));
        for v in v {
            h = merge(h, v);
        }
        h
    } else {
        seed.wrapping_add(P5)
    };
    h = h.wrapping_add(data.len() as u64);
    let mut words = rest.chunks_exact(8);
    for w in &mut words {
        h = (h ^ round(0, le64(w)))
            .rotate_left(27)
            .wrapping_mul(P1)
            .wrapping_add(P4);
    }
    let mut rest = words.remainder();
    if rest.len() >= 4 {
        h = (h ^ le32(rest).wrapping_mul(P1))
            .rotate_left(23)
            .wrapping_mul(P2)
            .wrapping_add(P3);
        rest = &rest[4..];
    }
    for &b in rest {
        h = (h ^ u64::from(b).wrapping_mul(P5))
            .rotate_left(11)
            .wrapping_mul(P1);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}

#[cfg(test)]
mod tests {
    use super::xxh64;

    #[test]
    fn known_answers() {
        // Reference values of the xxHash project (checked against xxhash.h).
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"a", 0), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
        assert_eq!(
            xxh64(b"Nobody inspects the spammish repetition", 0),
            0xFBCE_A83C_8A37_8BF1
        );
        // The sanity buffer of xxHash's sanity check (xsum_sanity_check.c): bytes of a
        // multiplicative generator, prime 2654435761.
        let mut buf = vec![0u8; 2367];
        let mut g: u64 = 2_654_435_761;
        for b in &mut buf {
            *b = (g >> 56) as u8;
            g = g.wrapping_mul(0x9E37_79B1_85EB_CA8D);
        }
        assert_eq!(xxh64(&buf[..0], 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(&buf[..0], 2_654_435_761), 0xAC75_FDA2_929B_17EF);
        assert_eq!(xxh64(&buf[..1], 0), 0xE934_A84A_DB05_2768);
        assert_eq!(xxh64(&buf[..1], 2_654_435_761), 0x5014_6076_43A9_B4C3);
        assert_eq!(xxh64(&buf[..14], 0), 0x8282_DCC4_994E_35C8);
        assert_eq!(xxh64(&buf[..14], 2_654_435_761), 0xC3BD_6BF6_3DEB_6DF0);
        assert_eq!(xxh64(&buf[..222], 0), 0xB641_AE8C_B691_C174);
        assert_eq!(xxh64(&buf[..222], 2_654_435_761), 0x20CB_8AB7_AE10_C14A);
        assert_eq!(xxh64(&buf, 0), 0xA824_18DD_EC0E_A581);
        assert_eq!(xxh64(&buf, 2_654_435_761), 0xA36A_93C1_8052_673A);
    }
}
