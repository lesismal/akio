#![no_main]
//! only-rtp: arbitrary bytes as an RTP packet (every header extension mapped) and as a
//! compound RTCP packet never panic; parsed headers and RTCP re-write and re-parse
//! consistently, and what parsed drives a RecvStream, a SendStream and a TwccSender
//! (`only_rtp::fuzzing::rtp_rtcp`).

libfuzzer_sys::fuzz_target!(|data: &[u8]| only_rtp::fuzzing::rtp_rtcp(data));
