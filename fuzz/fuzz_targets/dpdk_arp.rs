#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_dpdk::fuzzing::dpdk_arp(data));
