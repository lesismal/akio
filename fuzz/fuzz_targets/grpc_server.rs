#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_grpc::fuzzing::grpc_server(data));
