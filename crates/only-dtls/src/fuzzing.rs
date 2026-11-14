//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use crate::handshake::{self as hs, ClientHello, ServerHello, ServerKeyExchange};
use crate::{Config, Connection, Identity, PeerVerifier, Role, record};

/// `dtls_record`: arbitrary bytes as a datagram: record splitting, handshake fragments and
/// every message parser. Never panics; parsed hellos re-encode to what they parsed from.
pub fn record(data: &[u8]) {
    for (_, payload) in record::split(data) {
        let Ok(frags) = hs::parse_fragments(payload) else {
            continue;
        };
        for f in frags {
            parse_message(f.msg_type, f.body);
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
    ] {
        parse_message(t, data);
    }
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
    let mut servers = Vec::new();
    for hv in [false, true] {
        if let Ok(s) = Connection::new(server_cfg(hv), Role::Server, now, b"peer") {
            servers.push(s);
        }
    }
    for (i, d) in datagrams(data).into_iter().enumerate() {
        now += Duration::from_millis(300);
        let _ = client.handle_datagram(now, d);
        for s in &mut servers {
            let _ = s.handle_datagram(now, d);
            while s.poll_transmit().is_some() {}
            while s.poll_event().is_some() {}
            if i % 4 == 3 {
                let _ = s.handle_timeout(now);
            }
        }
        while client.poll_transmit().is_some() {}
        while client.poll_event().is_some() {}
        if i % 4 == 3 {
            let _ = client.handle_timeout(now);
        }
        let _ = client.poll_timeout();
        let _ = client.export_keying_material("EXPERIMENTAL", None, 16);
    }

    // A real handshake, then the same input against both connected ends.
    let Ok(mut c) = Connection::client(client_cfg, start) else {
        return;
    };
    let Ok(mut s) = Connection::new(server_cfg(false), Role::Server, start, b"peer") else {
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
    for d in datagrams(data) {
        let _ = c.handle_datagram(start, d);
        let _ = s.handle_datagram(start, d);
    }
    let _ = c.send_application_data(data);
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

        use crate::{Config, Connection, PeerVerifier, Role, SrtpProfile};

        let (a, b) = super::identities();
        let now = Instant::now();
        let sc = Config::new(a.clone())
            .with_verifier(PeerVerifier::AcceptAny)
            .with_srtp_profiles(SrtpProfile::ALL.to_vec())
            .with_mtu(256);
        let cc = Config::new(b.clone())
            .with_srtp_profiles(SrtpProfile::ALL.to_vec())
            .with_mtu(256);
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
        c.send_application_data(b"data").unwrap();
        to_server.push(c.poll_transmit().unwrap());
        c.close();
        to_server.push(c.poll_transmit().unwrap());
        let dir = format!("{}/../../fuzz/corpus", env!("CARGO_MANIFEST_DIR"));
        let rec = format!("{dir}/dtls_record");
        let hs = format!("{dir}/dtls_handshake");
        std::fs::create_dir_all(&rec).unwrap();
        std::fs::create_dir_all(&hs).unwrap();
        for (i, d) in to_server.iter().chain(&to_client).enumerate() {
            std::fs::write(format!("{rec}/datagram_{i:02}"), d).unwrap();
        }
        let framed = |ds: &[Vec<u8>]| {
            let mut out = Vec::new();
            for d in ds {
                out.extend_from_slice(&(d.len() as u16).to_be_bytes());
                out.extend_from_slice(d);
            }
            out
        };
        std::fs::write(format!("{hs}/client_flights"), framed(&to_server)).unwrap();
        std::fs::write(format!("{hs}/server_flights"), framed(&to_client)).unwrap();
        let mut mixed = Vec::new();
        for (x, y) in to_server.iter().zip(&to_client) {
            mixed.push(x.clone());
            mixed.push(y.clone());
        }
        std::fs::write(format!("{hs}/interleaved"), framed(&mixed)).unwrap();
        std::fs::write(format!("{hs}/client_hello"), framed(&to_server[..1])).unwrap();
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
