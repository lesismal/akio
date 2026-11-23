#![no_main]

//! akio-sys's ICMP error parser (macOS ICMP sockets): the first byte picks ICMPv6 (odd) or an
//! IPv4 packet carrying ICMPv4 (even); whatever parses keeps to what the parser promises.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&sel, msg)) = data.split_first() else {
        return;
    };
    let v6 = sel & 1 == 1;
    if let Some(p) = akio_sys::parse_icmp_error(msg, v6) {
        assert_eq!(p.v6, v6);
        assert_eq!(p.source.is_ipv6(), v6);
        assert_eq!(p.dest.is_ipv6(), v6);
        if v6 {
            assert!(matches!(p.icmp_type, 1..=4));
            assert!(p.icmp_type == 2 || p.mtu == 0);
        } else {
            assert!(matches!(p.icmp_type, 3 | 11 | 12));
            assert!((p.icmp_type == 3 && p.code == 4) || p.mtu == 0);
            assert!(p.mtu <= u32::from(u16::MAX));
        }
    }
});
