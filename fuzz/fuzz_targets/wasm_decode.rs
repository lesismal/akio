#![no_main]

// akio-wasm's decoder and validator (ADR-125) on arbitrary bytes, under the default load limits
// and under small ones: never a panic, a module accepted under the small limits is inside each
// of them, the two runs agree on why a module is refused, and loading stays linear in the
// module's size (libFuzzer's -timeout catches a slow input).

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    akio_wasm::fuzzing::decode(data);
});
