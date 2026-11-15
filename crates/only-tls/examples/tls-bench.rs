//! TLS 1.3 in memory, only-tls against rustls 0.23 + ring (a dev-dependency):
//!
//! ```text
//! cargo run --release -p only-tls --example tls-bench [handshakes|records|all] [SECS]
//! ```
//!
//! - `handshakes`: full handshakes per second with X25519 and secp256r1, both ends on this
//!   thread, the same self-signed ECDSA P-256 certificate verified by the client, no tickets.
//! - `records`: application data sealed by the client and opened by the server, MB/s of
//!   plaintext, for writes of 1 KiB, 16 KiB and 64 KiB with each TLS 1.3 cipher suite.
//!
//! Each case runs for `SECS` (default 1) after a warm-up; the ratio is only / rustls.
#![allow(missing_docs)]

use std::hint::black_box;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_tls::__proto::{self, Connection};
use only_tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig};
use rustls::crypto::ring as rring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

const X25519: u16 = 0x001d;
const SECP256R1: u16 = 0x0017;
const AES128: u16 = 0x1301;
const AES256: u16 = 0x1302;
const CHACHA: u16 = 0x1303;

struct Cert {
    der: Vec<u8>,
    key: Vec<u8>,
}

fn cert() -> Cert {
    let (c, k) = only_x509::generate_simple_self_signed(["localhost"]).expect("certificate");
    Cert {
        der: c.as_der().to_vec(),
        key: k.to_pkcs8_der(),
    }
}

fn rate(secs: f64, mut f: impl FnMut() -> u64) -> f64 {
    for _ in 0..3 {
        f();
    }
    let start = Instant::now();
    let mut n = 0u64;
    while start.elapsed() < Duration::from_secs_f64(secs) {
        n += f();
    }
    n as f64 / start.elapsed().as_secs_f64()
}

// ---- only-tls ----

fn only_configs(c: &Cert, group: u16, suite: u16) -> (ServerConfig, ClientConfig) {
    let s = ServerConfig::builder(
        vec![Certificate::from_der(c.der.clone())],
        PrivateKey::from_pkcs8_der(c.key.clone()),
    )
    .tls13_only(true)
    .session_tickets(false)
    .__tickets13(0)
    .__groups(&[group])
    .__suites(&[suite])
    .build()
    .expect("server config");
    let mut roots = RootCerts::empty();
    roots
        .add(&Certificate::from_der(c.der.clone()))
        .expect("root");
    let cl = ClientConfig::builder()
        .roots(roots)
        .tls13_only(true)
        .resumption(false)
        .__groups(&[group])
        .__suites(&[suite])
        .build()
        .expect("client config");
    (s, cl)
}

/// Runs both ends until neither has anything to say.
fn only_pump(cl: &mut Connection, sv: &mut Connection) {
    let (mut a, mut b, mut plain) = (Vec::new(), Vec::new(), Vec::new());
    cl.recv(&[], &mut plain, &mut a).expect("client start");
    for _ in 0..16 {
        if a.is_empty() && !cl.handshaking() && !sv.handshaking() {
            return;
        }
        b.clear();
        sv.recv(&a, &mut plain, &mut b).expect("server recv");
        a.clear();
        cl.recv(&b, &mut plain, &mut a).expect("client recv");
    }
    panic!("only-tls handshake did not finish");
}

fn only_pair(s: &ServerConfig, c: &ClientConfig) -> (Connection, Connection) {
    let mut cl = __proto::client(c, "localhost").expect("client");
    let mut sv = __proto::server(s);
    only_pump(&mut cl, &mut sv);
    (cl, sv)
}

fn only_records(cl: &mut Connection, sv: &mut Connection, data: &[u8]) -> u64 {
    let (mut wire, mut plain, mut back) = (Vec::new(), Vec::new(), Vec::new());
    cl.seal(data, &mut wire).expect("seal");
    sv.recv(&wire, &mut plain, &mut back).expect("open");
    assert_eq!(plain.len(), data.len());
    black_box(&plain);
    data.len() as u64
}

// ---- rustls ----

fn rustls_configs(
    c: &Cert,
    group: u16,
    suite: u16,
) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let mut p = rring::default_provider();
    p.kx_groups = vec![match group {
        X25519 => rring::kx_group::X25519,
        _ => rring::kx_group::SECP256R1,
    }];
    p.cipher_suites = vec![match suite {
        AES128 => rring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        AES256 => rring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        _ => rring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    }];
    let p = Arc::new(p);
    let der = CertificateDer::from(c.der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(c.key.clone()));
    let mut s = rustls::ServerConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .expect("server config");
    s.send_tls13_tickets = 0;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).expect("root");
    let mut cl = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cl.resumption = rustls::client::Resumption::disabled();
    (Arc::new(s), Arc::new(cl))
}

/// Moves everything `from` has to send into `to`.
fn transfer(from: &mut impl RustlsConn, to: &mut impl RustlsConn, wire: &mut Vec<u8>) {
    wire.clear();
    while from.wants_write() {
        from.write_tls(wire);
    }
    let mut rd = &wire[..];
    while !rd.is_empty() {
        to.read_tls(&mut rd);
        to.process();
    }
}

trait RustlsConn {
    fn wants_write(&self) -> bool;
    fn write_tls(&mut self, w: &mut Vec<u8>);
    fn read_tls(&mut self, r: &mut &[u8]);
    fn process(&mut self);
    fn handshaking(&self) -> bool;
}

macro_rules! rustls_conn {
    ($t:ty) => {
        impl RustlsConn for $t {
            fn wants_write(&self) -> bool {
                (**self).wants_write()
            }
            fn write_tls(&mut self, w: &mut Vec<u8>) {
                (**self).write_tls(w).expect("write_tls");
            }
            fn read_tls(&mut self, r: &mut &[u8]) {
                (**self).read_tls(r).expect("read_tls");
            }
            fn process(&mut self) {
                (**self).process_new_packets().expect("process");
            }
            fn handshaking(&self) -> bool {
                (**self).is_handshaking()
            }
        }
    };
}
rustls_conn!(rustls::ClientConnection);
rustls_conn!(rustls::ServerConnection);

fn rustls_pair(
    s: &Arc<rustls::ServerConfig>,
    c: &Arc<rustls::ClientConfig>,
) -> (rustls::ClientConnection, rustls::ServerConnection) {
    let name = ServerName::try_from("localhost").expect("name");
    let mut cl = rustls::ClientConnection::new(c.clone(), name).expect("client");
    let mut sv = rustls::ServerConnection::new(s.clone()).expect("server");
    let mut wire = Vec::new();
    for _ in 0..16 {
        if !cl.handshaking() && !sv.handshaking() && !cl.wants_write() && !sv.wants_write() {
            return (cl, sv);
        }
        transfer(&mut cl, &mut sv, &mut wire);
        transfer(&mut sv, &mut cl, &mut wire);
    }
    panic!("rustls handshake did not finish");
}

fn rustls_records(
    cl: &mut rustls::ClientConnection,
    sv: &mut rustls::ServerConnection,
    data: &[u8],
    wire: &mut Vec<u8>,
    plain: &mut [u8],
) -> u64 {
    cl.writer().write_all(data).expect("write");
    wire.clear();
    while cl.wants_write() {
        RustlsConn::write_tls(cl, wire);
    }
    // rustls buffers at most 16 KiB of received plaintext: read it out as it comes.
    let mut rd = &wire[..];
    let mut got = 0;
    while !rd.is_empty() {
        RustlsConn::read_tls(sv, &mut rd);
        sv.process_new_packets().expect("process");
        loop {
            match sv.reader().read(plain) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("read: {e}"),
            }
        }
    }
    assert_eq!(got, data.len());
    black_box(&plain);
    data.len() as u64
}

fn row(name: &str, unit: &str, ours: f64, theirs: f64) {
    println!(
        "{name:<44} {ours:>10.0} {theirs:>10.0} {unit:<4} {:>6.2}x",
        ours / theirs
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let what = args.get(1).map_or("all", String::as_str);
    let secs: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let c = cert();
    println!("{:<44} {:>10} {:>10}", "", "only-tls", "rustls");
    if matches!(what, "handshakes" | "all") {
        for (name, g) in [("X25519", X25519), ("secp256r1", SECP256R1)] {
            let (os, oc) = only_configs(&c, g, AES128);
            let (rs, rc) = rustls_configs(&c, g, AES128);
            let ours = rate(secs, || {
                black_box(only_pair(&os, &oc));
                1
            });
            let theirs = rate(secs, || {
                black_box(rustls_pair(&rs, &rc));
                1
            });
            row(&format!("full handshakes, {name}"), "/s", ours, theirs);
        }
    }
    if matches!(what, "records" | "all") {
        for (name, s) in [
            ("AES-128-GCM", AES128),
            ("AES-256-GCM", AES256),
            ("ChaCha20-Poly1305", CHACHA),
        ] {
            let (os, oc) = only_configs(&c, X25519, s);
            let (rs, rc) = rustls_configs(&c, X25519, s);
            for size in [1024usize, 16 * 1024, 64 * 1024] {
                let data = vec![0x5au8; size];
                let (mut ocl, mut osv) = only_pair(&os, &oc);
                let ours = rate(secs, || only_records(&mut ocl, &mut osv, &data));
                let (mut rcl, mut rsv) = rustls_pair(&rs, &rc);
                let (mut wire, mut plain) = (Vec::new(), vec![0u8; 64 * 1024]);
                let theirs = rate(secs, || {
                    rustls_records(&mut rcl, &mut rsv, &data, &mut wire, &mut plain)
                });
                row(
                    &format!("seal + open {} KiB, {name}", size / 1024),
                    "MB/s",
                    ours / 1e6,
                    theirs / 1e6,
                );
            }
        }
    }
}
