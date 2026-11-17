//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::handshake::{self as hs, ClientHello, ServerHello, ServerKeyExchange};
use crate::{Config, Connection, Identity, PeerVerifier, Psk, Role, Version, record};

/// `dtls_record`: arbitrary bytes as a datagram: record splitting (DTLS 1.2 headers,
/// RFC 9146 `tls12_cid` records and DTLS 1.3 unified headers, with several CID lengths),
/// sequence number reconstruction, handshake fragments and every message parser of both
/// versions. Never panics; parsed hellos re-encode to what they parsed from.
pub fn record(data: &[u8]) {
    for (_, payload) in record::split(data) {
        let Ok(frags) = hs::parse_fragments(payload) else {
            continue;
        };
        for f in frags {
            parse_message(f.msg_type, f.body);
        }
    }
    for cid_len in [0, 1, 4, 8] {
        let _ = record::connection_id(data, cid_len);
        for w in record::split_cid(data, cid_len) {
            match w {
                record::Wire::Plain { fragment, .. } => {
                    let _ = hs::parse_ack(fragment);
                }
                record::Wire::Unified(u) => {
                    assert!(u.header.len() <= data.len() && u.seq_len <= 2);
                    let low = u
                        .header
                        .get(u.seq_at..u.seq_at + u.seq_len)
                        .map_or(0, |b| b.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)));
                    let n = record::reconstruct_seq(
                        u64::from(u.epoch_bits) << 20,
                        low,
                        8 * u.seq_len as u32,
                    );
                    assert_eq!(n & ((1 << (8 * u.seq_len)) - 1), low);
                }
            }
        }
    }
    // The whole input as each message body, too.
    for t in [
        hs::CLIENT_HELLO,
        hs::SERVER_HELLO,
        hs::HELLO_VERIFY_REQUEST,
        hs::CERTIFICATE,
        hs::SERVER_KEY_EXCHANGE,
        hs::CERTIFICATE_REQUEST,
        hs::CERTIFICATE_VERIFY,
        hs::CLIENT_KEY_EXCHANGE,
        hs::NEW_SESSION_TICKET,
        hs::ENCRYPTED_EXTENSIONS,
        hs::KEY_UPDATE,
    ] {
        parse_message(t, data);
    }
    let _ = hs::parse_certificate13(data);
    let _ = hs::parse_certificate_request13(data);
    let _ = hs::parse_ack(data);
}

fn parse_message(t: u8, body: &[u8]) {
    match t {
        hs::CLIENT_HELLO => {
            if let Ok(mut ch) = ClientHello::parse(body) {
                // Unknown extensions are recorded by type only and not re-encoded.
                ch.extensions.unknown.clear();
                assert!(ClientHello::parse(&ch.encode()).ok().as_ref() == Some(&ch));
            }
        }
        hs::SERVER_HELLO => {
            if let Ok(mut sh) = ServerHello::parse(body) {
                sh.extensions.unknown.clear();
                assert!(ServerHello::parse(&sh.encode()).ok().as_ref() == Some(&sh));
            }
        }
        hs::HELLO_VERIFY_REQUEST => {
            let _ = hs::parse_hello_verify(body);
        }
        hs::CERTIFICATE => {
            let _ = hs::parse_certificate(body);
        }
        hs::SERVER_KEY_EXCHANGE => {
            if let Ok(s) = ServerKeyExchange::parse(body) {
                assert!(ServerKeyExchange::parse(&s.encode()).ok().as_ref() == Some(&s));
            }
        }
        hs::CERTIFICATE_REQUEST => {
            let _ = hs::parse_certificate_request(body);
        }
        hs::CERTIFICATE_VERIFY => {
            let _ = hs::parse_signed(body);
        }
        hs::CLIENT_KEY_EXCHANGE => {
            let _ = hs::parse_client_key_exchange(body);
        }
        hs::NEW_SESSION_TICKET => {
            let _ = hs::parse_ticket12(body);
            if let Ok(t) = hs::Ticket13::parse(body) {
                assert!(hs::Ticket13::parse(&t.encode()).ok().as_ref() == Some(&t));
            }
        }
        hs::ENCRYPTED_EXTENSIONS => {
            if let Ok(mut e) = hs::parse_encrypted_extensions(body) {
                e.unknown.clear();
                let again = hs::encode_encrypted_extensions(&e);
                assert!(hs::parse_encrypted_extensions(&again).ok().as_ref() == Some(&e));
            }
        }
        hs::KEY_UPDATE => {
            let _ = hs::parse_key_update(body);
        }
        _ => {}
    }
}

fn identities() -> &'static (Identity, Identity) {
    static IDS: OnceLock<(Identity, Identity)> = OnceLock::new();
    IDS.get_or_init(|| {
        let a = Identity::generate_self_signed().expect("identity");
        let b = Identity::generate_self_signed().expect("identity");
        (a, b)
    })
}

/// Splits fuzz input into datagrams: a 2-byte big-endian length before each.
fn datagrams(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while rest.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        out.push(&rest[2..2 + n]);
        rest = &rest[2 + n..];
    }
    out
}

/// `dtls_handshake`: arbitrary datagrams (2-byte length prefixes) fed to a client and a server
/// (with and without cookies), interleaved with timer expiries, then to both ends of a
/// completed handshake. Never panics.
pub fn handshake(data: &[u8]) {
    let (a, b) = identities();
    let start = Instant::now();
    let mut now = start;
    let server_cfg = |hv: bool| {
        Arc::new(
            Config::new(a.clone())
                .with_verifier(PeerVerifier::AcceptAny)
                .with_hello_verify(hv)
                .with_srtp_profiles(crate::SrtpProfile::ALL.to_vec())
                .with_mtu(256),
        )
    };
    let client_cfg = Arc::new(
        Config::new(b.clone())
            .with_srtp_profiles(crate::SrtpProfile::ALL.to_vec())
            .with_mtu(256),
    );
    let Ok(mut client) = Connection::client(client_cfg.clone(), now) else {
        return;
    };
    let psk = Psk::new("fuzz", vec![7; 16]).ok();
    // DTLS 1.3 (offering 1.2 too), with CIDs, PSKs and resumption.
    let v13 = |c: Config| {
        c.with_versions(vec![Version::Dtls13, Version::Dtls12])
            .with_connection_id(Some(4))
            .with_session_resumption(true)
            .with_psks(psk.iter().cloned().collect())
    };
    let mut clients = vec![client];
    if let Ok(c) = Connection::client(Arc::new(v13((*client_cfg).clone())), now) {
        clients.push(c);
    }
    let mut servers = Vec::new();
    for hv in [false, true] {
        if let Ok(s) = Connection::new(server_cfg(hv), Role::Server, now, b"peer") {
            servers.push(s);
        }
        let cfg = Arc::new(v13((*server_cfg(hv)).clone()));
        if let Ok(s) = Connection::new(cfg, Role::Server, now, b"peer") {
            servers.push(s);
        }
    }
    for (i, d) in datagrams(data).into_iter().enumerate() {
        now += Duration::from_millis(300);
        for client in &mut clients {
            let _ = client.handle_datagram(now, d);
            while client.poll_transmit().is_some() {}
            while client.poll_event().is_some() {}
            if i % 4 == 3 {
                let _ = client.handle_timeout(now);
            }
            let _ = client.poll_timeout();
            let _ = client.export_keying_material("EXPERIMENTAL", None, 16);
        }
        for s in &mut servers {
            let _ = s.handle_datagram(now, d);
            while s.poll_transmit().is_some() {}
            while s.poll_event().is_some() {}
            if i % 4 == 3 {
                let _ = s.handle_timeout(now);
            }
        }
    }

    // Real handshakes (DTLS 1.2, DTLS 1.3 with CIDs), then the same input against both
    // connected ends.
    for (cc, sc) in [
        (client_cfg.clone(), server_cfg(false)),
        (
            Arc::new(v13((*client_cfg).clone())),
            Arc::new(v13((*server_cfg(false)).clone())),
        ),
    ] {
        let Ok(mut c) = Connection::client(cc, start) else {
            return;
        };
        let Ok(mut s) = Connection::new(sc, Role::Server, start, b"peer") else {
            return;
        };
        for _ in 0..8 {
            while let Some(d) = c.poll_transmit() {
                let _ = s.handle_datagram(start, &d);
            }
            while let Some(d) = s.poll_transmit() {
                let _ = c.handle_datagram(start, &d);
            }
        }
        assert!(c.is_connected() && s.is_connected());
        let _ = c.update_keys(true);
        for d in datagrams(data) {
            let _ = c.handle_datagram(start, d);
            let _ = s.handle_datagram(start, d);
            while c.poll_transmit().is_some() {}
            while s.poll_transmit().is_some() {}
        }
        let _ = c.send_application_data(data);
    }
}

#[cfg(test)]
mod tests {
    fn corpus(target: &str) -> Vec<Vec<u8>> {
        let dir = format!("{}/../../fuzz/corpus/{target}", env!("CARGO_MANIFEST_DIR"));
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|e| std::fs::read(e.path()).ok())
            .collect()
    }

    fn replay(target: &str, f: fn(&[u8])) {
        let files = corpus(target);
        assert!(!files.is_empty(), "fuzz/corpus/{target} is empty");
        for d in files {
            f(&d);
            for cut in [1, d.len() / 2, d.len().saturating_sub(1)] {
                f(&d[..cut.min(d.len())]);
            }
            for i in (0..d.len()).step_by(61) {
                let mut g = d.clone();
                g[i] ^= 0x5a;
                f(&g);
            }
        }
    }

    /// Regenerates the seed corpora from real handshakes (cookies on, MTU 256, SRTP):
    /// `cargo test -p only-dtls --features fuzzing -- --ignored generate_corpus`.
    #[test]
    #[ignore = "writes fuzz/corpus"]
    fn generate_corpus() {
        use std::sync::Arc;
        use std::time::Instant;

        use crate::{Config, Connection, PeerVerifier, Role, SrtpProfile, Version};

        let (a, b) = super::identities();
        let now = Instant::now();
        let dir = format!("{}/../../fuzz/corpus", env!("CARGO_MANIFEST_DIR"));
        let rec = format!("{dir}/dtls_record");
        let hs = format!("{dir}/dtls_handshake");
        std::fs::create_dir_all(&rec).unwrap();
        std::fs::create_dir_all(&hs).unwrap();
        let framed = |ds: &[Vec<u8>]| {
            let mut out = Vec::new();
            for d in ds {
                out.extend_from_slice(&(d.len() as u16).to_be_bytes());
                out.extend_from_slice(d);
            }
            out
        };
        // DTLS 1.2; DTLS 1.3 with connection IDs, a PSK and resumption.
        for (tag, versions) in [("", vec![Version::Dtls12]), ("13_", vec![Version::Dtls13])] {
            let extra = |c: Config| {
                if tag.is_empty() {
                    c
                } else {
                    c.with_versions(versions.clone())
                        .with_connection_id(Some(4))
                        .with_session_resumption(true)
                }
            };
            let sc = extra(
                Config::new(a.clone())
                    .with_verifier(PeerVerifier::AcceptAny)
                    .with_srtp_profiles(SrtpProfile::ALL.to_vec())
                    .with_mtu(256),
            );
            let cc = extra(
                Config::new(b.clone())
                    .with_srtp_profiles(SrtpProfile::ALL.to_vec())
                    .with_mtu(256),
            );
            let mut c = Connection::client(Arc::new(cc), now).unwrap();
            let mut s = Connection::new(Arc::new(sc), Role::Server, now, b"peer").unwrap();
            let (mut to_server, mut to_client) = (Vec::new(), Vec::new());
            for _ in 0..8 {
                while let Some(d) = c.poll_transmit() {
                    s.handle_datagram(now, &d).unwrap();
                    to_server.push(d);
                }
                while let Some(d) = s.poll_transmit() {
                    c.handle_datagram(now, &d).unwrap();
                    to_client.push(d);
                }
            }
            assert!(c.is_connected() && s.is_connected());
            if !tag.is_empty() {
                c.update_keys(true).unwrap();
                to_server.extend(std::iter::from_fn(|| c.poll_transmit()));
            }
            c.send_application_data(b"data").unwrap();
            to_server.push(c.poll_transmit().unwrap());
            c.close();
            to_server.push(c.poll_transmit().unwrap());
            for (i, d) in to_server.iter().chain(&to_client).enumerate() {
                std::fs::write(format!("{rec}/datagram_{tag}{i:02}"), d).unwrap();
            }
            std::fs::write(format!("{hs}/client_flights{tag}"), framed(&to_server)).unwrap();
            std::fs::write(format!("{hs}/server_flights{tag}"), framed(&to_client)).unwrap();
            let mut mixed = Vec::new();
            for (x, y) in to_server.iter().zip(&to_client) {
                mixed.push(x.clone());
                mixed.push(y.clone());
            }
            std::fs::write(format!("{hs}/interleaved{tag}"), framed(&mixed)).unwrap();
            std::fs::write(format!("{hs}/client_hello{tag}"), framed(&to_server[..1])).unwrap();
        }
    }

    #[test]
    fn replay_dtls_record() {
        replay("dtls_record", super::record);
    }

    #[test]
    fn replay_dtls_handshake() {
        replay("dtls_handshake", super::handshake);
    }
}
