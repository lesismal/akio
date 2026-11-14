#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| flash_grpc::fuzzing::grpc_server(data));
