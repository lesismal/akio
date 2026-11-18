#![no_main]
//! The OTLP/HTTP exporter's response reader: any bytes from the collector, never a panic.

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_export::fuzzing::http_response(data));
