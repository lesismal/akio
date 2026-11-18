//! Constants of the format (RFC 8878 section 3.1.1.3.2).

pub(crate) const MAGIC: u32 = 0xFD2F_B528;
pub(crate) const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
pub(crate) const SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;
/// Largest block content (Block_Maximum_Size).
pub(crate) const BLOCK_MAX: usize = 128 << 10;

/// Largest literal length / match length / offset code.
pub(crate) const MAX_LL: usize = 35;
pub(crate) const MAX_ML: usize = 52;
pub(crate) const MAX_OF: usize = 31;
/// Largest accuracy log of the FSE tables of the sequences.
pub(crate) const LL_MAX_LOG: u32 = 9;
pub(crate) const ML_MAX_LOG: u32 = 9;
pub(crate) const OF_MAX_LOG: u32 = 8;

pub(crate) const LL_BASE: [u32; MAX_LL + 1] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000,
];
pub(crate) const LL_BITS: [u8; MAX_LL + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
pub(crate) const ML_BASE: [u32; MAX_ML + 1] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 0x83, 0x103, 0x203,
    0x403, 0x803, 0x1003, 0x2003, 0x4003, 0x8003, 0x10003,
];
pub(crate) const ML_BITS: [u8; MAX_ML + 1] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// Predefined distributions (accuracy logs 6, 6 and 5).
pub(crate) const LL_DEFAULT_NORM: [i16; MAX_LL + 1] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
pub(crate) const ML_DEFAULT_NORM: [i16; MAX_ML + 1] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
pub(crate) const OF_DEFAULT_NORM: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
pub(crate) const LL_DEFAULT_LOG: u32 = 6;
pub(crate) const ML_DEFAULT_LOG: u32 = 6;
pub(crate) const OF_DEFAULT_LOG: u32 = 5;

/// Index of the highest set bit (`x` > 0).
#[inline]
pub(crate) fn highbit(x: u32) -> u32 {
    31 - x.leading_zeros()
}

/// Literal length code of `ll`.
pub(crate) fn ll_code(ll: u32) -> u8 {
    if ll < 16 {
        ll as u8
    } else if ll < 64 {
        // Codes 16..=24 cover 16..64.
        let mut c = 16;
        while c + 1 < LL_BASE.len() && LL_BASE[c + 1] <= ll {
            c += 1;
        }
        c as u8
    } else {
        (highbit(ll) + 19) as u8
    }
}

/// Match length code of `ml` (at least 3).
pub(crate) fn ml_code(ml: u32) -> u8 {
    let base = ml - 3;
    if base < 32 {
        base as u8
    } else if base < 128 {
        let mut c = 32;
        while c + 1 < ML_BASE.len() && ML_BASE[c + 1] <= ml {
            c += 1;
        }
        c as u8
    } else {
        (highbit(base) + 36) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_tables() {
        for ll in 0..131_072u32 {
            let c = usize::from(ll_code(ll));
            assert!(
                LL_BASE[c] <= ll && ll < LL_BASE[c] + (1 << LL_BITS[c]),
                "ll {ll}"
            );
        }
        for ml in 3..131_075u32 {
            let c = usize::from(ml_code(ml));
            assert!(
                ML_BASE[c] <= ml && ml < ML_BASE[c] + (1 << ML_BITS[c]),
                "ml {ml}"
            );
        }
        assert_eq!(LL_DEFAULT_NORM.iter().map(|&n| n.abs()).sum::<i16>(), 64);
        assert_eq!(ML_DEFAULT_NORM.iter().map(|&n| n.abs()).sum::<i16>(), 64);
        assert_eq!(OF_DEFAULT_NORM.iter().map(|&n| n.abs()).sum::<i16>(), 32);
    }
}
