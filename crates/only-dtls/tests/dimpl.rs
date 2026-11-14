//! Interop with str0m's `dimpl` (the DTLS stack only-webrtc uses today), both roles, in
//! memory: handshake, DTLS-SRTP keying material, application data.

use std::sync::Arc;
use std::time::{Duration, Instant};

use only_dtls::{Config, Connection, Event, Identity, PeerVerifier, SrtpProfile};

fn dimpl_endpoint(id: &Identity, active: bool, now: Instant) -> dimpl::Dtls {
    let cert = dimpl::DtlsCertificate {
        certificate: id.certificate().to_vec(),
        private_key: id.private_key().to_pkcs8_der(),
    };
    let config = Arc::new(dimpl::Config::builder().build().expect("dimpl config"));
    let mut d = dimpl::Dtls::new_12(config, cert, now);
    d.set_active(active);
    d
}

#[derive(Default)]
struct DimplOut {
    packets: Vec<Vec<u8>>,
    connected: bool,
    peer_cert: Option<Vec<u8>>,
    material: Option<(Vec<u8>, String)>,
    data: Vec<Vec<u8>>,
    timeout: Option<Instant>,
}

fn drain(d: &mut dimpl::Dtls, out: &mut DimplOut) {
    let mut buf = vec![0u8; 4096];
    loop {
        match d.poll_output(&mut buf) {
            dimpl::Output::Packet(p) => out.packets.push(p.to_vec()),
            dimpl::Output::Timeout(t) => {
                out.timeout = Some(t);
                break;
            }
            dimpl::Output::Connected => out.connected = true,
            dimpl::Output::PeerCert(c) => out.peer_cert = Some(c.to_vec()),
            dimpl::Output::KeyingMaterial(m, p) => {
                out.material = Some((m.to_vec(), format!("{p:?}")));
            }
            dimpl::Output::ApplicationData(a) => out.data.push(a.to_vec()),
            dimpl::Output::BufferTooSmall { needed } => buf.resize(needed, 0),
            _ => {}
        }
    }
}

fn run(ours: &mut Connection, theirs: &mut dimpl::Dtls, start: Instant) -> DimplOut {
    let mut out = DimplOut::default();
    let mut now = start;
    theirs.handle_timeout(now).unwrap();
    for _ in 0..200 {
        drain(theirs, &mut out);
        for p in std::mem::take(&mut out.packets) {
            ours.handle_datagram(now, &p).unwrap();
        }
        let mut sent = false;
        while let Some(d) = ours.poll_transmit() {
            theirs.handle_packet(&d).unwrap();
            sent = true;
        }
        if !sent && out.packets.is_empty() {
            now += Duration::from_millis(50);
            theirs.handle_timeout(now).unwrap();
            ours.handle_timeout(now).unwrap();
        }
        if ours.is_connected() && out.connected && out.material.is_some() {
            break;
        }
    }
    drain(theirs, &mut out);
    out
}

fn check(ours: &mut Connection, theirs: &mut dimpl::Dtls, out: &mut DimplOut, peer: &Identity) {
    assert!(ours.is_connected() && out.connected);
    let info = ours.handshake_info().unwrap().clone();
    assert_eq!(info.peer_fingerprint, Some(peer.fingerprint()));
    let keys = info.srtp_keys.expect("srtp");
    let (material, profile) = out.material.clone().expect("dimpl keying material");
    let n = 2 * (keys.profile.master_key_len() + keys.profile.master_salt_len());
    assert_eq!(
        material,
        ours.export_keying_material(only_dtls::SRTP_EXPORTER_LABEL, None, n)
            .unwrap()
    );
    eprintln!(
        "dimpl profile {profile}, ours {:?}, suite {}",
        keys.profile, info.cipher_suite
    );
    // Application data both ways.
    let now = Instant::now();
    ours.send_application_data(b"from only").unwrap();
    while let Some(d) = ours.poll_transmit() {
        theirs.handle_packet(&d).unwrap();
    }
    theirs.send_application_data(b"from dimpl").unwrap();
    drain(theirs, out);
    assert_eq!(out.data, vec![b"from only".to_vec()]);
    for p in std::mem::take(&mut out.packets) {
        ours.handle_datagram(now, &p).unwrap();
    }
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| ours.poll_event())
        .filter_map(|e| match e {
            Event::ApplicationData(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(got, vec![b"from dimpl".to_vec()]);
}

#[test]
fn only_client_dimpl_server() {
    let now = Instant::now();
    let ours_id = Identity::generate_self_signed().unwrap();
    let theirs_id = Identity::generate_self_signed().unwrap();
    for profile in [SrtpProfile::AeadAes128Gcm, SrtpProfile::Aes128CmHmacSha1_80] {
        let cfg = Config::webrtc(
            ours_id.clone(),
            PeerVerifier::Fingerprints(vec![theirs_id.fingerprint()]),
        )
        .with_srtp_profiles(vec![profile]);
        let mut ours = Connection::client(Arc::new(cfg), now).unwrap();
        let mut theirs = dimpl_endpoint(&theirs_id, false, now);
        let mut out = run(&mut ours, &mut theirs, now);
        assert_eq!(out.peer_cert.as_deref(), Some(ours_id.certificate()));
        check(&mut ours, &mut theirs, &mut out, &theirs_id);
    }
}

#[test]
fn dimpl_client_only_server() {
    let now = Instant::now();
    let ours_id = Identity::generate_self_signed().unwrap();
    let theirs_id = Identity::generate_self_signed().unwrap();
    for hello_verify in [false, true] {
        let cfg = Config::webrtc(
            ours_id.clone(),
            PeerVerifier::Fingerprints(vec![theirs_id.fingerprint()]),
        )
        .with_hello_verify(hello_verify)
        .with_srtp_profiles(SrtpProfile::ALL.to_vec());
        let mut ours = Connection::server(Arc::new(cfg), now, b"dimpl").unwrap();
        let mut theirs = dimpl_endpoint(&theirs_id, true, now);
        let mut out = run(&mut ours, &mut theirs, now);
        assert_eq!(out.peer_cert.as_deref(), Some(ours_id.certificate()));
        check(&mut ours, &mut theirs, &mut out, &theirs_id);
    }
}
