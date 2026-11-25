#![no_main]

// akio-wasm's interpreter (ADR-125, sections 1 and 3) on valid modules that `wasm-smith`
// generates from the fuzzer's bytes, with section 2's features: every module loads (translation
// never refuses a valid module), and runs under small limits and budgets without a panic, each
// call returning its results or a trap that ends the store (`akio_wasm::fuzzing::exec`).

use libfuzzer_sys::arbitrary::Unstructured;

#[path = "wasm_smith_config.rs"]
mod wasm_smith_config;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(c) = wasm_smith_config::config(&mut u) else {
        return;
    };
    let Ok(module) = wasm_smith::Module::new(c, &mut u) else {
        return;
    };
    let bytes = module.to_bytes();
    if let Err(e) = akio_wasm::Module::new(&bytes, &akio_wasm::ModuleLimits::default()) {
        panic!("a valid module refused: {e}");
    }
    akio_wasm::fuzzing::exec(&bytes);
});
