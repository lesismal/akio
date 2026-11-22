//! Stable replay of the `crypto_ed448_dsa` fuzz target: its corpus under
//! `fuzz/corpus/crypto_ed448_dsa`, truncations and corruptions of it, and pseudorandom inputs.

use akio_crypto::rand::ChaChaRng;

#[path = "common/ed448_dsa.rs"]
mod ed448_dsa;

#[test]
fn replay_corpus() {
    let dir = format!(
        "{}/../../fuzz/corpus/crypto_ed448_dsa",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{dir}: {e}")) {
        let data = std::fs::read(e.unwrap().path()).unwrap();
        ed448_dsa::check(&data);
        for cut in [1, data.len() / 2] {
            ed448_dsa::check(&data[..cut.min(data.len())]);
        }
        for i in (0..data.len()).step_by(53) {
            let mut g = data.clone();
            g[i] ^= 0x41;
            ed448_dsa::check(&g);
        }
        n += 1;
    }
    assert!(n > 0);
}

#[test]
fn pseudorandom_inputs() {
    let mut rng = ChaChaRng::from_seed([44; 32]);
    for i in 0..64u32 {
        let len = 1 + (rng.next_u32() % 300) as usize;
        let mut d = vec![0u8; len];
        rng.fill(&mut d);
        d[0] = (i % 4) as u8;
        ed448_dsa::check(&d);
    }
}
