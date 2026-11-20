#![no_main]
//! The `partial_success` of an OTLP answer (HTTP body or gRPC message), as the exporter reads
//! every response from the collector: any bytes, never a panic.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = only_export::fuzzing::otlp_response(data);
});
