//! Kernel TLS offload: the exported keys open what the user-space record layer sealed (as the
//! kernel would), and the control records handled after the offload.

use super::*;
use crate::proto::{DirKeys, Offload, OffloadEvent};

const HEADER: usize = 5;

fn connect_keep(scfg: &ServerConfig, ccfg: &ClientConfig) -> (Connection, Connection) {
    let mut c = crate::__proto::client(ccfg, "localhost").unwrap();
    let mut s = crate::__proto::server(scfg);
    c.set_keep_keys(true);
    s.set_keep_keys(true);
    assert!(!c.offload_ready() && !s.offload_ready());
    shuttle(&mut c, &mut s, usize::MAX).unwrap();
    (c, s)
}

/// Opens one record with `k` the way the kernel does; returns the plaintext (TLS 1.3: the inner
/// content, type byte included).
fn open_with(o: &Offload, k: &DirKeys, rec: &[u8]) -> Vec<u8> {
    let aead = o.aead.key(&k.key);
    let mut nonce = k.iv;
    let body = &rec[HEADER..];
    let xor_seq = |n: &mut [u8; 12]| {
        for (a, b) in n[4..].iter_mut().zip(k.seq.to_be_bytes()) {
            *a ^= b;
        }
    };
    let (ct, aad): (&[u8], Vec<u8>) = if o.tls13 {
        xor_seq(&mut nonce);
        (body, rec[..HEADER].to_vec())
    } else {
        let ct = if o.aead == suites::AeadAlg::ChaCha20Poly1305 {
            xor_seq(&mut nonce);
            body
        } else {
            assert_eq!(
                body[..8],
                k.seq.to_be_bytes(),
                "explicit nonce = sequence number"
            );
            nonce[4..].copy_from_slice(&body[..8]);
            &body[8..]
        };
        let mut aad = k.seq.to_be_bytes().to_vec();
        aad.extend_from_slice(&[rec[0], 3, 3]);
        aad.extend_from_slice(&((ct.len() - 16) as u16).to_be_bytes());
        (ct, aad)
    };
    let (ct, tag) = ct.split_at(ct.len() - 16);
    let mut buf = ct.to_vec();
    aead.open(&nonce, &aad, &mut buf, tag)
        .expect("the exported keys open the record");
    buf
}

fn same(a: &DirKeys, b: &DirKeys) {
    assert_eq!(a.key, b.key);
    assert_eq!(a.iv, b.iv);
    assert_eq!(a.seq, b.seq);
}

#[test]
fn exported_keys_open_records_of_every_suite() {
    let p = pki(Kind::P256, &["localhost"]);
    for (suite, tls12) in [
        (0x1301u16, false),
        (0x1302, false),
        (0x1303, false),
        (0xc02b, true),
        (0xc02c, true),
        (0xcca9, true),
    ] {
        let s = server(&p).__suites(&[suite]).build().unwrap();
        let c = client(&p).__tls12_only(tls12).build().unwrap();
        let (mut c, mut s) = connect_keep(&s, &c);
        exchange(&mut c, &mut s);
        exchange(&mut c, &mut s);
        assert!(c.offload_ready() && s.offload_ready(), "{suite:#x}");
        let (co, so) = (c.offload_keys().unwrap(), s.offload_keys().unwrap());
        assert_eq!(co.tls13, !tls12);
        same(&co.tx, &so.rx);
        same(&co.rx, &so.tx);
        assert!(co.tx.seq > 0, "records were sent before the offload");
        let mut wire = Vec::new();
        c.seal(b"sealed in user space", &mut wire).unwrap();
        let mut plain = open_with(&co, &co.tx, &wire);
        if co.tls13 {
            assert_eq!(plain.pop(), Some(CT_APPLICATION_DATA));
        }
        assert_eq!(plain, b"sealed in user space", "{suite:#x}");
        c.commit_offload();
        assert!(c.offloaded() && !c.offload_ready() && c.offload_keys().is_none());
    }
}

#[test]
fn not_ready_with_a_partial_record_or_without_keep_keys() {
    let p = pki(Kind::P256, &["localhost"]);
    let (scfg, ccfg) = (server(&p).build().unwrap(), client(&p).build().unwrap());
    let (mut c, mut s) = connect(&scfg, &ccfg, "localhost").unwrap();
    assert!(!c.offload_ready() && c.offload_keys().is_none());
    exchange(&mut c, &mut s);
    let (mut c, mut s) = connect_keep(&scfg, &ccfg);
    let mut wire = Vec::new();
    c.seal(b"half a record", &mut wire).unwrap();
    s.recv(&wire[..7], &mut Vec::new(), &mut Vec::new())
        .unwrap();
    assert!(!s.offload_ready());
    s.recv(&wire[7..], &mut Vec::new(), &mut Vec::new())
        .unwrap();
    assert!(s.offload_ready());
    s.skip_offload();
    assert!(!s.offload_ready());
}

#[test]
fn key_update_after_the_offload() {
    let p = pki(Kind::P256, &["localhost"]);
    let (mut c, mut s) = connect_keep(&server(&p).build().unwrap(), &client(&p).build().unwrap());
    exchange(&mut c, &mut s);
    let (co, so) = (c.offload_keys().unwrap(), s.offload_keys().unwrap());
    c.commit_offload();
    s.commit_offload();
    // Ours: the KeyUpdate message (not requesting one back), then the new send keys.
    let mut ev = Vec::new();
    c.offloaded_key_update(&mut ev).unwrap();
    let [
        OffloadEvent::Send(CT_HANDSHAKE, msg),
        OffloadEvent::TxKeys(ctx),
    ] = &ev[..]
    else {
        panic!("{ev:?}");
    };
    assert_eq!(msg, &[24, 0, 0, 1, 0]);
    assert_eq!(ctx.seq, 0);
    assert_ne!(ctx.key, co.tx.key);
    // The peer installs matching receive keys and answers nothing.
    let mut ev2 = Vec::new();
    assert!(s.offloaded_record(CT_HANDSHAKE, msg, &mut ev2).unwrap());
    let [OffloadEvent::RxKeys(srx)] = &ev2[..] else {
        panic!("{ev2:?}");
    };
    same(ctx, srx);
    // update_requested: new receive keys, our KeyUpdate, new send keys.
    let mut ev3 = Vec::new();
    assert!(
        s.offloaded_record(CT_HANDSHAKE, &[24, 0, 0, 1, 1], &mut ev3)
            .unwrap()
    );
    let [
        OffloadEvent::RxKeys(_),
        OffloadEvent::Send(CT_HANDSHAKE, m),
        OffloadEvent::TxKeys(stx),
    ] = &ev3[..]
    else {
        panic!("{ev3:?}");
    };
    assert_eq!(m, &[24, 0, 0, 1, 0]);
    assert_ne!(stx.key, so.tx.key);
    // The client follows.
    let mut ev4 = Vec::new();
    c.offloaded_record(CT_HANDSHAKE, m, &mut ev4).unwrap();
    let [OffloadEvent::RxKeys(crx)] = &ev4[..] else {
        panic!("{ev4:?}");
    };
    same(stx, crx);
}

#[test]
fn alerts_and_close_notify_after_the_offload() {
    let p = pki(Kind::P256, &["localhost"]);
    let (scfg, ccfg) = (server(&p).build().unwrap(), client(&p).build().unwrap());
    let (_c, mut s) = connect_keep(&scfg, &ccfg);
    s.commit_offload();
    let mut ev = Vec::new();
    assert!(!s.offloaded_record(CT_ALERT, &[1, 0], &mut ev).unwrap());
    assert!(s.received_close_notify() && ev.is_empty());
    // After close_notify everything else is ignored.
    assert!(!s.offloaded_record(CT_ALERT, &[2, 10], &mut ev).unwrap());
    let Some(OffloadEvent::Send(CT_ALERT, a)) = s.offloaded_close() else {
        panic!("close_notify");
    };
    assert_eq!(a, [1, 0]);
    assert!(s.offloaded_close().is_none());

    // A fatal alert from the peer: an error, nothing sent back.
    let (_c, mut s) = connect_keep(&scfg, &ccfg);
    s.commit_offload();
    let e = s.offloaded_record(CT_ALERT, &[2, 80], &mut ev).unwrap_err();
    assert!(e.from_peer && ev.is_empty());
    assert!(s.offloaded_close().is_none());

    // Garbage: a fatal alert to send, then the connection stays failed.
    let (_c, mut s) = connect_keep(&scfg, &ccfg);
    s.commit_offload();
    let e = s
        .offloaded_record(CT_HANDSHAKE, &[99, 0, 0, 0], &mut ev)
        .unwrap_err();
    assert_eq!(e.alert, Alert::UnexpectedMessage);
    let [OffloadEvent::Send(CT_ALERT, a)] = &ev[..] else {
        panic!("{ev:?}");
    };
    assert_eq!(a, &[2, 10]);
    assert!(
        s.offloaded_record(CT_ALERT, &[1, 0], &mut Vec::new())
            .is_err()
    );
    // A malformed alert and an unknown record type.
    let (_c, mut s) = connect_keep(&scfg, &ccfg);
    s.commit_offload();
    assert!(
        s.offloaded_record(CT_ALERT, &[1, 2, 3], &mut Vec::new())
            .is_err()
    );
    let (_c, mut s) = connect_keep(&scfg, &ccfg);
    s.commit_offload();
    assert!(s.offloaded_record(99, &[0], &mut Vec::new()).is_err());
    // TLS 1.2 has no KeyUpdate.
    let (mut c, _s) = connect_keep(&scfg, &client(&p).__tls12_only(true).build().unwrap());
    c.commit_offload();
    assert!(c.offloaded_key_update(&mut Vec::new()).is_err());
}
