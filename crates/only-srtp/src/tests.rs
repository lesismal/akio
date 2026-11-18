//! Context tests: RFC 7714 vectors, pion/srtp v3.1.3 cross-check vectors, round trips,
//! replay, rollover, tampering and truncation.

use crate::{Context, Error, Profile};

pub(crate) fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rfc7714_ctx(profile: Profile, key: &[u8]) -> Context {
    Context::from_session_keys(profile, key, &hex("517569642070726f2071756f"), &[])
}

const RFC7714_RTP: &str = "8040f17b 8041f8d3 5501a0b2 47616c6c 69612065 7374206f 6d6e6973 20646976
    69736120 696e2070 61727465 73207472 6573";
const RFC7714_RTCP: &str = "81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61
    deadbeef deadbeef deadbeef deadbeef deadbeef";

/// RFC 7714 §16.1 (AEAD_AES_128_GCM) and §16.2 (AEAD_AES_256_GCM) for RTP, §17 for SRTCP
/// (encrypted, index 0x5d4) and §17 with the E flag clear (authentication only).
#[test]
fn rfc7714_vectors() {
    let cases = [
        (
            Profile::AeadAes128Gcm,
            hex("000102030405060708090a0b0c0d0e0f"),
            "8040f17b 8041f8d3 5501a0b2 f24de3a3 fb34de6c acba861c 9d7e4bca be633bd5
             0d294e6f 42a5f47a 51c7d19b 36de3adf 8833899d 7f27beb1 6a9152cf 765ee439 0cce",
            "81c8000d 4d617273 63e94885 dcdab67c a727d766 2f6b7e99 7ff5c0f7 6c06f32d
             c676a5f1 730d6fda 4ce09b46 86303ded 0bb9275b c84aa458 96cf4d2f c5abf872
             45d9eade 800005d4",
            "81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61
             deadbeef deadbeef deadbeef deadbeef deadbeef 841dd968 3dd78ec9 2ae58790
             125f62b3 000005d4",
        ),
        (
            Profile::AeadAes256Gcm,
            hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            "8040f17b 8041f8d3 5501a0b2 32b1de78 a822fe12 ef9f78fa 332e33aa b1801238
             9a58e2f3 b50b2a02 76ffae0f 1ba63799 b87b7aa3 db36dfff d6b0f9bb 7878d7a7 6c13",
            "81c8000d 4d617273 d50ae4d1 f5ce5d30 4ba297e4 7d470c28 2c3ece5d bffe0a50
             a2eaa5c1 110555be 8415f658 c61de047 6f1b6fad 1d1eb30c 4446839f 57ff6f6c
             b26ac3be 800005d4",
            "81c8000d 4d617273 4e545031 4e545032 52545020 0000042a 0000e930 4c756e61
             deadbeef deadbeef deadbeef deadbeef deadbeef 91db4afb feee5a97 8fab4393
             ed2615fe 000005d4",
        ),
    ];
    for (profile, key, srtp, srtcp, srtcp_auth_only) in cases {
        let mut tx = rfc7714_ctx(profile, &key);
        assert_eq!(tx.protect_rtp(&hex(RFC7714_RTP)).unwrap(), hex(srtp));
        tx.set_next_rtcp_index(0x4d61_7273, 0x5d4);
        assert_eq!(tx.protect_rtcp(&hex(RFC7714_RTCP)).unwrap(), hex(srtcp));

        let mut rx = rfc7714_ctx(profile, &key);
        assert_eq!(rx.unprotect_rtp(&hex(srtp)).unwrap(), hex(RFC7714_RTP));
        assert_eq!(rx.unprotect_rtcp(&hex(srtcp)).unwrap(), hex(RFC7714_RTCP));
        assert_eq!(rx.unprotect_rtcp(&hex(srtcp)), Err(Error::Replay));
        let mut rx = rfc7714_ctx(profile, &key);
        assert_eq!(
            rx.unprotect_rtcp(&hex(srtcp_auth_only)).unwrap(),
            hex(RFC7714_RTCP)
        );
        let mut bad = hex(srtcp_auth_only);
        bad[20] ^= 1;
        assert_eq!(
            rfc7714_ctx(profile, &key).unprotect_rtcp(&bad),
            Err(Error::Authentication)
        );
    }
}

const IN_RTP: [&str; 4] = [
    "9160fffe11223344cafebabe01020304bede000110aa000068656c6c6f207372747020776f726c64",
    "a0e0ffff11223345cafebabe0102030405000003",
    "8060000011223346cafebabe000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "8060000111223347cafebabe090909",
];
const IN_RTCP: [&str; 2] = [
    "80c80006cafebabe0102030405060708112233440000000a000003e8",
    "81c90007cafebabe000000010500000200010003000000040000000500000006",
];

/// Produced by pion/srtp v3.1.3 `Context.EncryptRTP` / `EncryptRTCP` with master key
/// `01 02 03 ...` and salt `a0 a1 a2 ...` (pion's SRTCP index starts at 1). The RTP packets
/// carry a CSRC, a header extension and padding, and cross the sequence number rollover.
const PION: [(Profile, [&str; 4], [&str; 2]); 4] = [
    (
        Profile::Aes128CmHmacSha1_80,
        [
            "9160fffe11223344cafebabe01020304bede000110aa000031834c760bbe44da59503d8f29db6a99b27356165a4ff3fbdcde",
            "a0e0ffff11223345cafebabe128fd80d2a4d198cfc65d7f5d22a98ef2ba4",
            "8060000011223346cafebabe1d25b0466714b0a0b06f4c017d215b202bbec25201d7c808aeef007ece1ba2344ef5fbebd9822ccfe9ae",
            "8060000111223347cafebabe60148c49e273a04890cf67f127",
        ],
        [
            "80c80006cafebabeeb2e9647a1ab2641d7d0421ba949596d3a7380888000000128dfe145f7718c6c8df1",
            "81c90007cafebabee9944798dbaa5d17fb77966e630a92c86c21aa316e1ce8cc80000002dcd6a64e1bb9895651ec",
        ],
    ),
    (
        Profile::Aes128CmHmacSha1_32,
        [
            "9160fffe11223344cafebabe01020304bede000110aa000031834c760bbe44da59503d8f29db6a99b2735616",
            "a0e0ffff11223345cafebabe128fd80d2a4d198cfc65d7f5",
            "8060000011223346cafebabe1d25b0466714b0a0b06f4c017d215b202bbec25201d7c808aeef007ece1ba2344ef5fbeb",
            "8060000111223347cafebabe60148c49e273a0",
        ],
        [
            "80c80006cafebabeeb2e9647a1ab2641d7d0421ba949596d3a7380888000000128dfe145f7718c6c8df1",
            "81c90007cafebabee9944798dbaa5d17fb77966e630a92c86c21aa316e1ce8cc80000002dcd6a64e1bb9895651ec",
        ],
    ),
    (
        Profile::AeadAes128Gcm,
        [
            "9160fffe11223344cafebabe01020304bede000110aa0000242f4a04d66a211f1947032a9d19404d68105ad061fcf734ab1e98d1145b579a",
            "a0e0ffff11223345cafebabe9402a5f38eadc366758e6473556c803bfb028f77b98ec164",
            "8060000011223346cafebabecce18179a6d4be6706a982a052e19f786e218a901e70fe446651fde007acd3ecd622a75654ad0c336280ae53ce96db79",
            "8060000111223347cafebabed8a9f32fb537cfcc5b583090771c5b70b0c808",
        ],
        [
            "80c80006cafebabe09d57ad65ef0651553db5339b335b3c8c45b09ebbf5d51d8784404a8234b585a8a2d5e6d80000001",
            "81c90007cafebabefc2f7d09f3bea5e05c61ed5a1f1a2d97623ff6f683bc5f6bf2308ce2a57f5858b12b6e3f19d32f9580000002",
        ],
    ),
    (
        Profile::AeadAes256Gcm,
        [
            "9160fffe11223344cafebabe01020304bede000110aa0000f83a620bb600f4d9f27c18d4fff662988583a5902fc748276964285b0d6d7f3b",
            "a0e0ffff11223345cafebabe1bb1c34595ab638e0ef5e2704b12b9e3f1b6011aa50e8122",
            "8060000011223346cafebabe603fd5248b536245c6bb9f883cc61de77e854a5ea11b61db03cfee67b969082d41e984704da4beef887b14390408f07b",
            "8060000111223347cafebabe40e328475973e40144e3bc56896fe1f2cbd2dc",
        ],
        [
            "80c80006cafebabe8182aa5f3d04ef385e262794226e57aeb3bced5cff8a56003dc54ae649b15a59813c438d80000001",
            "81c90007cafebabeeee0d042e47fa611eab2af67a2cc90180e816c863d148416a0bec017c42d7fcbcee4e5d364bf2efc80000002",
        ],
    ),
];

pub(crate) fn test_keys(profile: Profile) -> (Vec<u8>, Vec<u8>) {
    let key = (1..=profile.key_len()).map(|i| i as u8).collect();
    let salt = (0..profile.salt_len()).map(|i| 0xa0 + i as u8).collect();
    (key, salt)
}

#[test]
fn pion_cross_check() {
    for (profile, rtp, rtcp) in PION {
        let (key, salt) = test_keys(profile);
        let mut tx = Context::new(profile, &key, &salt).unwrap();
        let mut rx = Context::new(profile, &key, &salt).unwrap();
        for (input, want) in IN_RTP.iter().zip(rtp) {
            assert_eq!(
                tx.protect_rtp(&hex(input)).unwrap(),
                hex(want),
                "{profile:?}"
            );
            assert_eq!(rx.unprotect_rtp(&hex(want)).unwrap(), hex(input));
        }
        assert_eq!(tx.send_roc(0xcafe_babe), Some(1));
        assert_eq!(rx.recv_roc(0xcafe_babe), Some(1));
        tx.set_next_rtcp_index(0xcafe_babe, 1);
        for (input, want) in IN_RTCP.iter().zip(rtcp) {
            assert_eq!(
                tx.protect_rtcp(&hex(input)).unwrap(),
                hex(want),
                "{profile:?}"
            );
            assert_eq!(rx.unprotect_rtcp(&hex(want)).unwrap(), hex(input));
        }
    }
}

fn rtp(seq: u16, ssrc: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x80, 111];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&(u32::from(seq) * 960).to_be_bytes());
    p.extend_from_slice(&ssrc.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn pair(profile: Profile) -> (Context, Context) {
    let (key, salt) = test_keys(profile);
    (
        Context::new(profile, &key, &salt).unwrap(),
        Context::new(profile, &key, &salt).unwrap(),
    )
}

#[test]
fn replay_and_reorder() {
    for profile in Profile::ALL {
        let (mut tx, mut rx) = pair(profile);
        let pkts: Vec<_> = (0..200u16)
            .map(|s| tx.protect_rtp(&rtp(s, 1, b"media")).unwrap())
            .collect();
        assert_eq!(rx.unprotect_rtp(&pkts[10]).unwrap(), rtp(10, 1, b"media"));
        assert_eq!(rx.unprotect_rtp(&pkts[10]), Err(Error::Replay));
        // Reordered but inside the window.
        assert!(rx.unprotect_rtp(&pkts[5]).is_ok());
        assert_eq!(rx.unprotect_rtp(&pkts[5]), Err(Error::Replay));
        assert!(rx.unprotect_rtp(&pkts[150]).is_ok());
        // 150 - 80 >= 64: too old.
        assert_eq!(rx.unprotect_rtp(&pkts[80]), Err(Error::Replay));
        assert!(rx.unprotect_rtp(&pkts[100]).is_ok());
        // A bigger window accepts it.
        let (_, rx2) = pair(profile);
        let mut rx2 = rx2.with_replay_window(1000);
        assert!(rx2.unprotect_rtp(&pkts[150]).is_ok());
        assert!(rx2.unprotect_rtp(&pkts[0]).is_ok());
        // A failed authentication does not move the window.
        let mut bad = pkts[199].clone();
        let n = bad.len();
        bad[n - 1] ^= 0x80;
        assert_eq!(rx.unprotect_rtp(&bad), Err(Error::Authentication));
        assert!(rx.unprotect_rtp(&pkts[199]).is_ok());
    }
}

#[test]
fn rollover() {
    for profile in Profile::ALL {
        let (mut tx, mut rx) = pair(profile);
        let seqs: Vec<u16> = (65_500..=65_535).chain(0..40).collect();
        let pkts: Vec<_> = seqs
            .iter()
            .map(|&s| tx.protect_rtp(&rtp(s, 7, &[s as u8; 20])).unwrap())
            .collect();
        assert_eq!(tx.send_roc(7), Some(1));
        // Deliver with reordering across the rollover: swap neighbours.
        let mut order: Vec<usize> = (0..pkts.len()).collect();
        for c in order.chunks_mut(2) {
            c.reverse();
        }
        // and one late packet from before the wrap after many after it.
        order.retain(|&i| i != 30);
        order.push(30);
        for i in order {
            let got = rx.unprotect_rtp(&pkts[i]).unwrap();
            assert_eq!(got, rtp(seqs[i], 7, &[seqs[i] as u8; 20]));
        }
        assert_eq!(rx.recv_roc(7), Some(1));
        // A second wrap.
        for s in (40..=65_535).step_by(1000).chain([65_535, 0, 1]) {
            let p = tx.protect_rtp(&rtp(s, 7, b"x")).unwrap();
            assert!(rx.unprotect_rtp(&p).is_ok(), "seq {s}");
        }
        assert_eq!(rx.recv_roc(7), Some(2));
        assert_eq!(tx.send_roc(7), Some(2));
    }
}

#[test]
fn rtcp_round_trip_and_replay() {
    for profile in Profile::ALL {
        let (mut tx, mut rx) = pair(profile);
        let p = hex(IN_RTCP[1]);
        let a = tx.protect_rtcp(&p).unwrap();
        let b = tx.protect_rtcp(&p).unwrap();
        assert_eq!(a.len(), p.len() + 4 + profile.rtcp_tag_len());
        assert_ne!(a, b);
        assert_eq!(rx.unprotect_rtcp(&b).unwrap(), p);
        assert_eq!(rx.unprotect_rtcp(&a).unwrap(), p);
        assert_eq!(rx.unprotect_rtcp(&a), Err(Error::Replay));
        let mut t = b.clone();
        t[9] ^= 1;
        assert_eq!(rx.unprotect_rtcp(&t), Err(Error::Replay));
        let c = tx.protect_rtcp(&p).unwrap();
        let mut t = c.clone();
        t[9] ^= 1;
        assert_eq!(rx.unprotect_rtcp(&t), Err(Error::Authentication));
        assert!(rx.unprotect_rtcp(&c).is_ok());
        assert_eq!(tx.protect_rtcp(&[0x80, 200, 0]), Err(Error::Malformed));
    }
}

#[test]
fn tampering_and_truncation() {
    for profile in Profile::ALL {
        let (mut tx, mut rx) = pair(profile);
        let p = tx.protect_rtp(&hex(IN_RTP[0])).unwrap();
        for i in 0..p.len() {
            let mut t = p.clone();
            t[i] ^= 0x01;
            // Flipping the version bits makes it malformed; anything else fails auth (or,
            // for the SSRC / seq, still fails auth under a different ROC / state).
            assert!(rx.unprotect_rtp(&t).is_err(), "{profile:?} byte {i}");
        }
        for n in 0..p.len() {
            assert!(rx.unprotect_rtp(&p[..n]).is_err());
            let _ = rx.unprotect_rtcp(&p[..n]);
        }
        assert!(rx.unprotect_rtp(&p).is_ok());
        // Wrong key.
        let mut other =
            Context::new(profile, &vec![0; profile.key_len()], &test_keys(profile).1).unwrap();
        assert_eq!(
            other.unprotect_rtp(&tx.protect_rtp(&rtp(9, 9, b"q")).unwrap()),
            Err(Error::Authentication)
        );
        assert_eq!(tx.protect_rtp(&[0x80; 11]), Err(Error::Malformed));
    }
}

#[test]
fn ssrc_eviction() {
    let (tx, rx) = pair(Profile::AeadAes128Gcm);
    let (mut tx, mut rx) = (tx.with_max_ssrcs(4), rx.with_max_ssrcs(4));
    let first = tx.protect_rtp(&rtp(1, 100, b"a")).unwrap();
    assert!(rx.unprotect_rtp(&first).is_ok());
    for ssrc in 101..110 {
        let p = tx.protect_rtp(&rtp(1, ssrc, b"a")).unwrap();
        assert!(rx.unprotect_rtp(&p).is_ok());
    }
    assert_eq!(rx.recv_roc(100), None);
    assert_eq!(rx.recv_roc(109), Some(0));
    // The evicted SSRC's state is gone, so its old packet is accepted again.
    assert!(rx.unprotect_rtp(&first).is_ok());
    assert!(format!("{rx:?}").contains("AeadAes128Gcm"));
}

#[test]
fn wrong_key_length() {
    assert_eq!(
        Context::new(Profile::AeadAes128Gcm, &[0; 16], &[0; 14]).err(),
        Some(Error::KeyLength)
    );
    assert!(Error::Replay.to_string().contains("replay"));
}

/// The second master key of the MKI cross-checks (libsrtp.txt).
fn second_keys(profile: Profile) -> (Vec<u8>, Vec<u8>) {
    let key = (0..profile.key_len()).map(|i| 0x40 + i as u8).collect();
    let salt = (0..profile.salt_len()).map(|i| 0xc0 + i as u8).collect();
    (key, salt)
}

const MKI0: [u8; 4] = [1, 2, 3, 4];
const MKI1: [u8; 4] = [0x0a, 0x0b, 0x0c, 0x0d];

/// A context configured like the libsrtp cross-check case `case` (`kind:Profile`).
fn libsrtp_ctx(case: &str) -> (Profile, Context) {
    let (kind, name) = case.split_once(':').unwrap();
    let profile = Profile::ALL
        .into_iter()
        .find(|p| format!("{p:?}") == name)
        .unwrap();
    let (key, salt) = test_keys(profile);
    let ctx = if kind.contains("mki") {
        let mut c = Context::new_with_mki(profile, &MKI0, &key, &salt).unwrap();
        let (k1, s1) = second_keys(profile);
        c.add_master_key(&MKI1, &k1, &s1).unwrap();
        c
    } else {
        Context::new(profile, &key, &salt).unwrap()
    };
    let ctx = match kind {
        "hdrext" => ctx.with_encrypted_header_extensions(&[1, 3, 14]),
        k if k.starts_with("cryptex") => ctx.with_cryptex(true),
        _ => ctx,
    };
    (profile, ctx)
}

/// Byte-for-byte cross-check with libsrtp (testdata/libsrtp.txt, from tools/interop/srtp):
/// every profile without MKI and with two MKI keys (switching keys mid-stream), RFC 6904
/// header extension encryption with one- and two-byte extensions, and cryptex (also with an
/// MKI), protect and unprotect.
#[test]
fn libsrtp_cross_check() {
    let data = include_str!("../testdata/libsrtp.txt");
    type Packet<'a> = (&'a str, Vec<u8>, Vec<u8>);
    let mut cases: Vec<(&str, Vec<Packet<'_>>)> = Vec::new();
    for line in data
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split(' ').collect();
        let entry = (f[1], hex(f[2]), hex(f[3]));
        match cases.last_mut() {
            Some((c, v)) if *c == f[0] => v.push(entry),
            _ => cases.push((f[0], vec![entry])),
        }
    }
    assert_eq!(cases.len(), 50);
    let mut checked = 0;
    for (case, packets) in cases {
        let (profile, mut tx) = libsrtp_ctx(case);
        let (_, mut rx) = libsrtp_ctx(case);
        let rekey = case.starts_with("mki:");
        let (mut nrtp, mut nrtcp) = (0, 0);
        for (kind, input, want) in packets {
            if kind == "rtp" {
                if rekey {
                    tx.set_send_mki(if nrtp < 2 { &MKI0 } else { &MKI1 })
                        .unwrap();
                }
                nrtp += 1;
                assert_eq!(tx.protect_rtp(&input).unwrap(), want, "{case} rtp {nrtp}");
                assert_eq!(rx.unprotect_rtp(&want).unwrap(), input, "{case} rtp {nrtp}");
                if case.starts_with("cryptex") && input[0] == 0x92 && profile.encrypts() {
                    // libsrtp needs the empty extension spelt out; without it we add it.
                    let mut bare = input[..20].to_vec();
                    bare[0] = 0x82;
                    bare.extend_from_slice(&input[24..]);
                    let (_, mut tx2) = libsrtp_ctx(case);
                    assert_eq!(tx2.protect_rtp(&bare).unwrap(), want, "{case}");
                }
            } else {
                if rekey {
                    tx.set_send_mki(if nrtcp < 1 { &MKI0 } else { &MKI1 })
                        .unwrap();
                }
                nrtcp += 1;
                assert_eq!(
                    tx.protect_rtcp(&input).unwrap(),
                    want,
                    "{case} rtcp {nrtcp}"
                );
                assert_eq!(rx.unprotect_rtcp(&want).unwrap(), input, "{case} rtcp");
            }
            checked += 1;
        }
        if case.contains("mki") {
            assert_eq!(rx.mki_len(), 4);
            assert!(profile.rtp_tag_len() > 0);
        }
    }
    assert_eq!(checked, 230);
}

/// RFC 9335 Appendix A: cryptex with AES-CM (A.1) and AES-GCM (A.2), one- and two-byte
/// extensions, with and without CSRCs, empty extensions.
#[test]
fn rfc9335_vectors() {
    let rtp = [
        "900f1235 decafbad cafebabe bede0001 51000200 abababab abababab abababab abababab",
        "900f1236 decafbad cafebabe 10000001 05020002 abababab abababab abababab abababab",
        "920f1238 decafbad cafebabe 0001e240 0000b26e bede0001 51000200 abababab abababab
         abababab abababab",
        "920f1239 decafbad cafebabe 0001e240 0000b26e 10000001 05020002 abababab abababab
         abababab abababab",
        "920f123a decafbad cafebabe 0001e240 0000b26e bede0000 abababab abababab abababab
         abababab",
        "920f123b decafbad cafebabe 0001e240 0000b26e 10000000 abababab abababab abababab
         abababab",
    ];
    let cm = [
        "900f1235 decafbad cafebabe c0de0001 eb923652 51c3e036 f8de27e9 c27ee3e0 b4651d9f
         bc4218a7 0244522f 34a5",
        "900f1236 decafbad cafebabe c2de0001 4ed9cc4e 6a712b30 96c5ca77 339d4204 ce0d7739
         6cab6958 5fbce381 94a5",
        "920f1238 decafbad cafebabe 8bb6e12b 5cff16dd c0de0001 92838c8c 09e58393 e1de3a9a
         74734d67 45671338 c3acf11d a2df8423 bee0",
        "920f1239 decafbad cafebabe f70e513e b90b9b25 c2de0001 bbed4848 faa64466 5f3d7f34
         125914e9 f4d0ae92 3c6f479b 95a0f7b5 3133",
        "920f123a decafbad cafebabe 7130b6ab fe2ab0e3 c0de0000 e3d9f64b 25c9e74c b4cf8e43
         fb92e378 1c2c0cea b6b3a499 a14c",
        "920f123b decafbad cafebabe cbf24c12 4330e1c8 c2de0000 599dd45b c9d687b6 03e8b59d
         771fd38e 88b170e0 cd31e125 eabe",
    ];
    let gcm = [
        "900f1235 decafbad cafebabe c0de0001 39972dc9 572c4d99 e8fc355d e743fb2e 94f9d8ff
         54e72f41 93bbc5c7 4ffab0fa 9fa0fbeb",
        "900f1236 decafbad cafebabe c2de0001 bb75a4c5 45cd1f41 3bdb7daa 2b1e3263 de313667
         c9632490 81b35a65 f5cb6c88 b394235f",
        "920f1238 decafbad cafebabe 63bbccc4 a7f695c4 c0de0001 8ad7c71f ac70a80c 92866b4c
         6ba98546 ef913586 e95ffaaf fe956885 bb0647a8 bc094ac8",
        "920f1239 decafbad cafebabe 3680524f 8d312b00 c2de0001 c78d1200 38422bc1 11a7187a
         18246f98 0c059cc6 bc9df8b6 26394eca 344e4b05 d80fea83",
        "920f123a decafbad cafebabe 15b6bb43 37906fff c0de0000 b7b96453 7a2b03ab 7ba5389c
         e9331712 6b5d974d f30c6884 dcb651c5 e120c1da",
        "920f123b decafbad cafebabe dcb38c9e 48bf95f4 c2de0000 61ee432c f9203170 76613258
         d3ce4236 c06ac429 681ad084 13512dc9 8b5207d8",
    ];
    let suites = [
        (
            Profile::Aes128CmHmacSha1_80,
            "e1f97a0d3e018be0d64fa32c06de4139",
            "0ec675ad498afeebb6960b3aabe6",
            cm,
        ),
        (
            Profile::AeadAes128Gcm,
            "000102030405060708090a0b0c0d0e0f",
            "a0a1a2a3a4a5a6a7a8a9aaab",
            gcm,
        ),
    ];
    for (profile, key, salt, want) in suites {
        let mk = || {
            Context::new(profile, &hex(key), &hex(salt))
                .unwrap()
                .with_cryptex(true)
        };
        let (mut tx, mut rx) = (mk(), mk());
        for (input, want) in rtp.iter().zip(want) {
            assert_eq!(
                tx.protect_rtp(&hex(input)).unwrap(),
                hex(want),
                "{profile:?}"
            );
            assert_eq!(rx.unprotect_rtp(&hex(want)).unwrap(), hex(input));
        }
        // Without cryptex a receiver authenticates the packet but leaves it encrypted.
        let mut plain_rx = Context::new(profile, &hex(key), &hex(salt)).unwrap();
        if !profile.is_aead() {
            let got = plain_rx.unprotect_rtp(&hex(want[2])).unwrap();
            assert_ne!(got, hex(rtp[2]));
        }
    }
}

fn csrc_ext_packet(seq: u16) -> Vec<u8> {
    // X + 2 CSRCs, a one-byte extension (IDs 1, 2, 3; padding between 2 and 3), payload.
    let mut p = vec![0x92, 0x60];
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&hex("00000001 00c0ffee 11111111 22222222"));
    p.extend_from_slice(&hex("bede0003 10aa 21bbcc 00 32112233 00 00"));
    p.extend_from_slice(b"payload");
    p
}

#[test]
fn mki_rekeying() {
    for profile in Profile::ALL {
        let (k0, s0) = test_keys(profile);
        let (k1, s1) = second_keys(profile);
        let mut tx = Context::new_with_mki(profile, &MKI0, &k0, &s0).unwrap();
        let mut rx = Context::new_with_mki(profile, &MKI0, &k0, &s0).unwrap();
        assert_eq!(tx.send_mki(), Some(&MKI0[..]));
        let a = tx.protect_rtp(&rtp(1, 5, b"old key")).unwrap();
        assert_eq!(a.len(), 12 + 7 + 4 + profile.rtp_tag_len());
        assert_eq!(rx.unprotect_rtp(&a).unwrap(), rtp(1, 5, b"old key"));
        // The sender switches keys before the receiver knows the new one.
        tx.add_master_key(&MKI1, &k1, &s1).unwrap();
        tx.set_send_mki(&MKI1).unwrap();
        let b = tx.protect_rtp(&rtp(2, 5, b"new key")).unwrap();
        assert_eq!(rx.unprotect_rtp(&b), Err(Error::UnknownMki));
        rx.add_master_key(&MKI1, &k1, &s1).unwrap();
        assert_eq!(rx.unprotect_rtp(&b).unwrap(), rtp(2, 5, b"new key"));
        // Reordered packets under the old key still decrypt until it is removed.
        let c = {
            tx.set_send_mki(&MKI0).unwrap();
            tx.protect_rtcp(&hex(IN_RTCP[0])).unwrap()
        };
        tx.set_send_mki(&MKI1).unwrap();
        assert!(tx.remove_master_key(&MKI0));
        let d = tx.protect_rtcp(&hex(IN_RTCP[1])).unwrap();
        assert_eq!(rx.unprotect_rtcp(&d).unwrap(), hex(IN_RTCP[1]));
        assert!(!rx.remove_master_key(&MKI0), "rx sends with MKI0");
        rx.set_send_mki(&MKI1).unwrap();
        assert!(rx.remove_master_key(&MKI0));
        assert_eq!(rx.unprotect_rtcp(&c), Err(Error::UnknownMki));
        // Same index, other key: the MKI picks the key, so a forged MKI fails to authenticate.
        let mut e = tx.protect_rtp(&rtp(3, 5, b"x")).unwrap();
        rx.add_master_key(&MKI0, &k0, &s0).unwrap();
        let at = if profile.is_aead() {
            e.len() - 4
        } else {
            e.len() - 4 - profile.rtp_tag_len()
        };
        e[at..at + 4].copy_from_slice(&MKI0);
        assert_eq!(rx.unprotect_rtp(&e), Err(Error::Authentication));
        e[at..at + 4].copy_from_slice(&MKI1);
        assert!(rx.unprotect_rtp(&e).is_ok());
        assert!(format!("{rx:?}").contains("mki_len: 4"));
    }
}

#[test]
fn mki_config_errors() {
    let p = Profile::Aes128CmHmacSha1_80;
    let (k, s) = test_keys(p);
    assert_eq!(
        Context::new_with_mki(p, &[], &k, &s).err(),
        Some(Error::Config)
    );
    assert_eq!(
        Context::new_with_mki(p, &[0; 256], &k, &s).err(),
        Some(Error::Config)
    );
    assert!(Context::new_with_mki(p, &[7; 255], &k, &s).is_ok());
    assert_eq!(
        Context::new_with_mki(p, &MKI0, &k[..15], &s).err(),
        Some(Error::KeyLength)
    );
    let mut plain = Context::new(p, &k, &s).unwrap();
    assert_eq!(plain.send_mki(), None);
    assert_eq!(plain.add_master_key(&MKI1, &k, &s), Err(Error::Config));
    let mut c = Context::new_with_mki(p, &MKI0, &k, &s).unwrap();
    assert_eq!(c.add_master_key(&MKI0, &k, &s), Err(Error::Config));
    assert_eq!(c.add_master_key(&[1, 2, 3], &k, &s), Err(Error::Config));
    assert_eq!(c.add_master_key(&MKI1, &k, &s[..3]), Err(Error::KeyLength));
    assert_eq!(c.set_send_mki(&MKI1), Err(Error::UnknownMki));
    assert!(!c.remove_master_key(&MKI0), "the sending key stays");
    assert!(!c.remove_master_key(&MKI1));
    for i in 1..crate::MAX_MASTER_KEYS {
        c.add_master_key(&[0, 0, 0, i as u8], &k, &s).unwrap();
    }
    assert_eq!(c.add_master_key(&[9, 9, 9, 9], &k, &s), Err(Error::Config));
    // Removing a key before the sending one keeps the sending key.
    c.set_send_mki(&[0, 0, 0, 5]).unwrap();
    assert!(c.remove_master_key(&MKI0));
    assert_eq!(c.send_mki(), Some(&[0, 0, 0, 5][..]));
    // A packet too short for the MKI and tag.
    let mut rx = Context::new_with_mki(p, &MKI0, &k, &s).unwrap();
    assert_eq!(
        rx.unprotect_rtp(&rtp(1, 1, &[0; 13])),
        Err(Error::Malformed)
    );
    assert_eq!(
        rx.unprotect_rtcp(&hex(IN_RTCP[0])[..25]),
        Err(Error::Malformed)
    );
}

#[test]
fn key_derivation_rate() {
    let p = Profile::Aes128CmHmacSha1_80;
    let (k, s) = test_keys(p);
    for bad in [3, 6, (1 << 24) + 1, 1 << 25] {
        assert_eq!(
            Context::new(p, &k, &s)
                .unwrap()
                .with_key_derivation_rate(bad)
                .err(),
            Some(Error::Config)
        );
    }
    for profile in Profile::ALL {
        let (k, s) = test_keys(profile);
        let mk = |rate| {
            Context::new_with_mki(profile, &MKI0, &k, &s)
                .unwrap()
                .with_key_derivation_rate(rate)
                .unwrap()
                .with_encrypted_header_extensions(&[1, 3])
        };
        let (mut tx, mut rx) = (mk(16), mk(16));
        let mut ref0 = mk(0);
        let pkts: Vec<_> = (0..100u16)
            .map(|q| tx.protect_rtp(&csrc_ext_packet(q)).unwrap())
            .collect();
        // r = 0 keys are the rate-0 keys; later blocks differ.
        assert_eq!(ref0.unprotect_rtp(&pkts[3]).unwrap(), csrc_ext_packet(3));
        assert_eq!(ref0.unprotect_rtp(&pkts[40]), Err(Error::Authentication));
        // In order, then reordered across key blocks (old blocks derive their keys again).
        for i in (0..60).chain([75, 61, 99, 62, 63, 64, 70]) {
            assert_eq!(
                rx.unprotect_rtp(&pkts[i]).unwrap(),
                csrc_ext_packet(i as u16),
                "{i}"
            );
        }
        // SRTCP uses the SRTCP index.
        let rtcp: Vec<_> = (0..40)
            .map(|_| tx.protect_rtcp(&hex(IN_RTCP[1])).unwrap())
            .collect();
        for i in (0..40).rev() {
            assert_eq!(rx.unprotect_rtcp(&rtcp[i]).unwrap(), hex(IN_RTCP[1]));
        }
        let mut ref0 = mk(0);
        assert!(ref0.unprotect_rtcp(&rtcp[15]).is_ok());
        assert_eq!(ref0.unprotect_rtcp(&rtcp[16]), Err(Error::Authentication));
        // A large index (an r several bytes long; the PRF input is checked in cipher.rs).
        tx.set_send_index(9, (1 << 40) + 5);
        assert!(tx.protect_rtp(&rtp(6, 9, b"far")).is_ok());
        assert_eq!(tx.send_roc(9), Some(1 << 24));
        assert!(format!("{tx:?}").contains("key_derivation_rate: 16"));
    }
}

#[test]
fn header_extension_encryption() {
    for profile in Profile::ALL {
        let (k, s) = test_keys(profile);
        let mk = || {
            Context::new(profile, &k, &s)
                .unwrap()
                .with_encrypted_header_extensions(&[0, 1, 3, 200])
        };
        let (mut tx, mut rx) = (mk(), mk());
        let input = csrc_ext_packet(1);
        let out = tx.protect_rtp(&input).unwrap();
        // CSRCs, element headers, padding and ID 2 stay in the clear; 1 and 3 change.
        let ext = &out[24..36];
        assert_eq!(&out[..24], &input[..24]);
        assert_eq!(ext[0], 0x10);
        assert_eq!(&ext[2..5], &hex("21bbcc")[..]);
        assert_eq!(ext[5], 0x00);
        assert_eq!(ext[6], 0x32);
        assert_eq!(&ext[10..], &hex("0000")[..]);
        assert_eq!(ext[1] != 0xaa, profile.encrypts());
        assert_eq!(ext[7..10] != hex("112233")[..], profile.encrypts());
        assert_eq!(rx.unprotect_rtp(&out).unwrap(), input);
        // Two-byte extension: ID 200 (beyond the one-byte range) is encrypted.
        let mut two = rtp(2, 1, b"pl");
        two[0] |= 0x10;
        two.splice(12..12, hex("10000002 c803010203 0201ff 00"));
        let out = tx.protect_rtp(&two).unwrap();
        assert_eq!(&out[16..18], &hex("c803")[..]);
        assert_eq!(out[18..21] != hex("010203")[..], profile.encrypts());
        assert_eq!(&out[21..24], &hex("0201ff")[..]);
        assert_eq!(rx.unprotect_rtp(&out).unwrap(), two);
        // An element running past the extension.
        let mut bad = rtp(3, 1, b"pl");
        bad[0] |= 0x10;
        bad.splice(12..12, hex("bede0001 1f000000"));
        let mut buf = vec![1, 2, 3];
        let r = tx.protect_rtp_into(&bad, &mut buf);
        if profile.encrypts() {
            assert_eq!(r, Err(Error::Malformed));
            assert!(buf.is_empty());
        }
        // Turned off again.
        let mut off = mk().with_encrypted_header_extensions(&[]);
        let mut plain_rx = Context::new(profile, &k, &s).unwrap();
        assert_eq!(
            plain_rx
                .unprotect_rtp(&off.protect_rtp(&input).unwrap())
                .unwrap(),
            input
        );
    }
}

#[test]
fn cryptex_round_trips() {
    for profile in Profile::ALL {
        let (k, s) = test_keys(profile);
        let mk = || Context::new(profile, &k, &s).unwrap().with_cryptex(true);
        let (mut tx, mut rx) = (mk(), mk());
        let input = csrc_ext_packet(1);
        let out = tx.protect_rtp(&input).unwrap();
        assert_eq!(&out[..12], &input[..12]);
        let marker = if profile.encrypts() {
            hex("c0de0003")
        } else {
            hex("bede0003")
        };
        assert_eq!(&out[20..24], &marker[..]);
        assert_eq!(out[12..20] != input[12..20], profile.encrypts());
        assert_eq!(rx.unprotect_rtp(&out).unwrap(), input);
        // CSRCs only: an empty extension is added and kept.
        let mut csrc = rtp(2, 1, b"pl");
        csrc[0] |= 0x01;
        csrc.splice(12..12, hex("00c0ffee"));
        let out = tx.protect_rtp(&csrc).unwrap();
        let got = rx.unprotect_rtp(&out).unwrap();
        if profile.encrypts() {
            assert_eq!(&out[16..20], &hex("c0de0000")[..]);
            let mut want = csrc.clone();
            want[0] |= 0x10;
            want.splice(16..16, hex("bede0000"));
            assert_eq!(got, want);
        } else {
            assert_eq!(got, csrc);
        }
        // Neither: unchanged path; a non-cryptex packet is still accepted.
        let bare = rtp(3, 1, b"pl");
        assert_eq!(
            rx.unprotect_rtp(&tx.protect_rtp(&bare).unwrap()).unwrap(),
            bare
        );
        let mut plain_tx = Context::new(profile, &k, &s).unwrap();
        let p = plain_tx.protect_rtp(&csrc_ext_packet(4)).unwrap();
        assert_eq!(rx.unprotect_rtp(&p).unwrap(), csrc_ext_packet(4));
        // Extensions cryptex cannot carry.
        for prof in ["1001", "abcd"] {
            let mut odd = rtp(5, 1, b"pl");
            odd[0] |= 0x10;
            odd.splice(12..12, hex(&format!("{prof}0001 01020304")));
            let r = tx.protect_rtp(&odd);
            if profile.encrypts() {
                assert_eq!(r, Err(Error::Unsupported));
            } else {
                assert!(r.is_ok());
            }
        }
        // Tampering anywhere fails.
        let out = tx.protect_rtp(&csrc_ext_packet(6)).unwrap();
        for i in 0..out.len() {
            let mut t = out.clone();
            t[i] ^= 0x04;
            assert!(rx.unprotect_rtp(&t).is_err(), "{profile:?} byte {i}");
        }
    }
}

#[test]
fn into_buffers_are_reused() {
    for profile in Profile::ALL {
        let (mut tx, mut rx) = pair(profile);
        let (mut a, mut b) = (Vec::with_capacity(256), Vec::with_capacity(256));
        let (pa, pb) = (a.as_ptr(), b.as_ptr());
        for q in 0..50u16 {
            let p = rtp(q, 3, &[q as u8; 100]);
            tx.protect_rtp_into(&p, &mut a).unwrap();
            rx.unprotect_rtp_into(&a, &mut b).unwrap();
            assert_eq!(b, p);
            tx.protect_rtcp_into(&hex(IN_RTCP[1]), &mut a).unwrap();
            rx.unprotect_rtcp_into(&a, &mut b).unwrap();
            assert_eq!(b, hex(IN_RTCP[1]));
        }
        assert_eq!((a.as_ptr(), b.as_ptr()), (pa, pb), "no reallocation");
        assert_eq!(
            rx.unprotect_rtp_into(&[0x80; 30], &mut b),
            Err(Error::Authentication)
        );
        assert!(b.is_empty());
    }
}
