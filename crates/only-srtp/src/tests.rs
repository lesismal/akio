//! Context tests: RFC 7714 vectors, pion/srtp v3.1.3 cross-check vectors, round trips,
//! replay, rollover, tampering and truncation.

use crate::cipher::SessionKeys;
use crate::{Context, Error, Profile};

pub(crate) fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rfc7714_ctx(profile: Profile, key: &[u8]) -> Context {
    let salt = hex("517569642070726f2071756f");
    let keys = SessionKeys {
        rtp_key: key.to_vec(),
        rtp_salt: salt.clone(),
        rtp_auth: Vec::new(),
        rtcp_key: key.to_vec(),
        rtcp_salt: salt,
        rtcp_auth: Vec::new(),
    };
    Context::from_session_keys(profile, &keys)
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
