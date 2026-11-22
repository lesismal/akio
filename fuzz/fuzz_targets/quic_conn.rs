#![no_main]
//! akio-quic: a handshaken client/server pair fed a script of raw datagrams, 1-RTT packets with
//! arbitrary frames under valid keys (both directions), forged Initial packets to the server
//! endpoint, ECN codepoints chosen per path (kept, bleached, CE, ECT(1)) and time passing;
//! nothing panics (`akio_quic::fuzzing::connection`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| akio_quic::fuzzing::connection(data));
