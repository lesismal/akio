//! Reed-Solomon over GF(2^8) with the matrix github.com/klauspost/reedsolomon builds (a
//! Vandermonde matrix times the inverse of its top square), so parity matches kcp-go's.

struct Gf {
    exp: [u8; 510],
    log: [u8; 256],
}

fn gf() -> &'static Gf {
    static G: std::sync::OnceLock<Gf> = std::sync::OnceLock::new();
    G.get_or_init(|| {
        let mut g = Gf {
            exp: [0; 510],
            log: [0; 256],
        };
        let mut x: u32 = 1;
        for i in 0..255 {
            g.exp[i] = x as u8;
            g.exp[i + 255] = x as u8;
            g.log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        g
    })
}

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let g = gf();
    g.exp[g.log[a as usize] as usize + g.log[b as usize] as usize]
}

fn inv(a: u8) -> u8 {
    let g = gf();
    g.exp[255 - g.log[a as usize] as usize]
}

fn pow(a: u8, n: usize) -> u8 {
    if n == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }
    let g = gf();
    g.exp[(g.log[a as usize] as usize * n) % 255]
}

type Matrix = Vec<Vec<u8>>;

fn matmul(a: &Matrix, b: &Matrix) -> Matrix {
    let mut out = vec![vec![0u8; b[0].len()]; a.len()];
    for r in 0..a.len() {
        for c in 0..b[0].len() {
            let mut v = 0;
            for (i, row) in b.iter().enumerate() {
                v ^= mul(a[r][i], row[c]);
            }
            out[r][c] = v;
        }
    }
    out
}

fn invert(m: &Matrix) -> Option<Matrix> {
    let n = m.len();
    let mut w: Matrix = m
        .iter()
        .enumerate()
        .map(|(r, row)| {
            let mut v = row.clone();
            v.resize(2 * n, 0);
            v[n + r] = 1;
            v
        })
        .collect();
    for r in 0..n {
        if w[r][r] == 0 {
            if let Some(below) = (r + 1..n).find(|&b| w[b][r] != 0) {
                w.swap(r, below);
            }
        }
        if w[r][r] == 0 {
            return None;
        }
        let d = w[r][r];
        if d != 1 {
            let i = inv(d);
            w[r].iter_mut().for_each(|x| *x = mul(*x, i));
        }
        for o in 0..n {
            if o == r || w[o][r] == 0 {
                continue;
            }
            let f = w[o][r];
            let pivot = w[r].clone();
            w[o].iter_mut()
                .zip(&pivot)
                .for_each(|(x, p)| *x ^= mul(f, *p));
        }
    }
    Some(w.into_iter().map(|row| row[n..].to_vec()).collect())
}

fn mul_add(c: u8, input: &[u8], out: &mut [u8]) {
    match c {
        0 => {}
        1 => out.iter_mut().zip(input).for_each(|(o, i)| *o ^= i),
        _ => out
            .iter_mut()
            .zip(input)
            .for_each(|(o, i)| *o ^= mul(c, *i)),
    }
}

/// An encoder/decoder for `data` + `parity` shards.
pub struct Rs {
    pub data: usize,
    pub parity: usize,
    m: Matrix,
}

impl Rs {
    /// 1..=255 data and parity shards, 256 at most in all.
    pub fn new(data: usize, parity: usize) -> Option<Rs> {
        if data == 0 || parity == 0 || data + parity > 256 {
            return None;
        }
        let total = data + parity;
        let vm: Matrix = (0..total)
            .map(|r| (0..data).map(|c| pow(r as u8, c)).collect())
            .collect();
        let top = invert(&vm[..data].to_vec())?;
        Some(Rs {
            data,
            parity,
            m: matmul(&vm, &top),
        })
    }

    /// Fills the parity shards (indices `data..`) from the data shards; all of equal length.
    pub fn encode(&self, shards: &mut [Vec<u8>]) {
        for p in 0..self.parity {
            let (dat, par) = shards.split_at_mut(self.data);
            let out = &mut par[p];
            out.iter_mut().for_each(|b| *b = 0);
            let row = &self.m[self.data + p];
            for (d, shard) in dat.iter().enumerate() {
                mul_add(row[d], shard, out);
            }
        }
    }

    /// Rebuilds the missing data shards (`None`) from any `data` present ones of `size` bytes.
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>], size: usize) -> bool {
        let rows: Vec<usize> = (0..shards.len())
            .filter(|&i| shards[i].is_some())
            .take(self.data)
            .collect();
        if rows.len() < self.data {
            return false;
        }
        let sub: Matrix = rows.iter().map(|&r| self.m[r].clone()).collect();
        let Some(dec) = invert(&sub) else {
            return false;
        };
        for d in 0..self.data {
            if shards[d].is_some() {
                continue;
            }
            let mut out = vec![0u8; size];
            for (i, &r) in rows.iter().enumerate() {
                mul_add(dec[d][i], shards[r].as_ref().expect("present"), &mut out);
            }
            shards[d] = Some(out);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_any_lost_data_shards() {
        let rs = Rs::new(10, 3).unwrap();
        let mut shards: Vec<Vec<u8>> = (0..13)
            .map(|i| (0..64).map(|j| (i * 31 + j * 7) as u8).collect())
            .collect();
        rs.encode(&mut shards);
        let original = shards.clone();
        for lost in [[0, 1, 2], [3, 9, 12], [0, 5, 10]] {
            let mut s: Vec<Option<Vec<u8>>> = original.iter().cloned().map(Some).collect();
            for &l in &lost {
                s[l] = None;
            }
            assert!(rs.reconstruct(&mut s, 64));
            for d in 0..10 {
                assert_eq!(s[d].as_ref().unwrap(), &original[d], "lost {lost:?}");
            }
        }
        // klauspost's matrix: the top square is the identity (systematic code).
        assert_eq!(rs.m[0][0], 1);
        assert_eq!(rs.m[0][1], 0);
    }
}
