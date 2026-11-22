//! Stable replay of the `crypto_sig_verify` fuzz target: its corpus under
//! `fuzz/corpus/crypto_sig_verify` plus pseudorandom inputs, checked against ring.

mod common;

use akio_crypto::rand::ChaChaRng;

#[path = "common/sigdiff.rs"]
mod sigdiff;

#[test]
fn replay_corpus() {
    let dir = format!(
        "{}/../../fuzz/corpus/crypto_sig_verify",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut n = 0;
    for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{dir}: {e}")) {
        let data = std::fs::read(e.unwrap().path()).unwrap();
        sigdiff::check(&data);
        n += 1;
    }
    assert!(n > 0);
}

#[test]
fn pseudorandom_inputs() {
    let mut rng = ChaChaRng::from_seed([7; 32]);
    for i in 0..1500u32 {
        let len = 34 + (rng.next_u32() % 200) as usize;
        let mut d = vec![0u8; len];
        rng.fill(&mut d);
        // Small mutations are the interesting ones: keep most bytes zero in mode 1.
        if i % 3 == 0 {
            let start = 34 + usize::from(d[33]).min(len - 34);
            for (j, b) in d[start..].iter_mut().enumerate() {
                if j % 11 != 0 {
                    *b = 0;
                }
            }
        }
        sigdiff::check(&d);
    }
}
