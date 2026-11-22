#![no_main]
//! RFC 9841 shared brotli framing format containers: arbitrary bytes never panic the reader;
//! containers the writer makes from the input (resources, hidden dictionaries, resources
//! compressed with them) read back as written.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    only_brotli::fuzzing::container(data);
});
