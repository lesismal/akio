//! A DTLS 1.2 client or server over UDP for interop checks (tools/interop/dtls/run.sh).
//!
//! ```text
//! dtls-interop client <host:port> [options]   # sends --message, expects it echoed
//! dtls-interop server <bind:port> [options]   # one connection, echoes application data
//!   --cert FILE --key FILE        PEM identity (default: a fresh self-signed P-256 one)
//!   --fingerprint 'sha-256 AB:..' pin the peer certificate (default: accept any)
//!   --srtp NAME[,NAME]            SRTP profiles (OpenSSL names, e.g. SRTP_AES128_CM_SHA1_80)
//!   --suite NAME[,NAME]           cipher suites (IANA names)
//!   --export LABEL:LEN            print exporter output as `EXPORT <hex>`
//!   --mtu N                       handshake datagram size
//!   --no-cookie                   server: no HelloVerifyRequest
//!   --no-client-cert              server: do not require a client certificate
//!   --message TEXT                client: what to send (default "hello from only-dtls")
//!   --close                       client: send close_notify at the end
//!   --oneway                      client: send --message, close, do not wait for an echo
//! ```
//!
//! Prints `CONNECTED suite=.. srtp=.. peer=<fingerprint>`, `SRTP_MATERIAL <hex>` (the
//! `EXTRACTOR-dtls_srtp` export, as OpenSSL's `-keymatexport` prints it), `RECV <text>`.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_dtls::{
    CipherSuite, Config, Connection, Event, Fingerprint, Identity, PeerVerifier, Role, SrtpProfile,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn srtp_by_name(n: &str) -> SrtpProfile {
    match n {
        "SRTP_AES128_CM_SHA1_80" | "SRTP_AES128_CM_HMAC_SHA1_80" => {
            SrtpProfile::Aes128CmHmacSha1_80
        }
        "SRTP_AES128_CM_SHA1_32" | "SRTP_AES128_CM_HMAC_SHA1_32" => {
            SrtpProfile::Aes128CmHmacSha1_32
        }
        "SRTP_AEAD_AES_128_GCM" => SrtpProfile::AeadAes128Gcm,
        "SRTP_AEAD_AES_256_GCM" => SrtpProfile::AeadAes256Gcm,
        _ => panic!("unknown SRTP profile {n}"),
    }
}

fn suite_by_name(n: &str) -> CipherSuite {
    CipherSuite::ALL
        .into_iter()
        .find(|s| s.to_string() == n)
        .unwrap_or_else(|| panic!("unknown cipher suite {n}"))
}

struct Opts {
    config: Config,
    export: Option<(String, usize)>,
    message: String,
    close: bool,
    oneway: bool,
}

fn parse(args: &[String]) -> Opts {
    let mut cert = None;
    let mut key = None;
    let mut fingerprint = None;
    let mut srtp = Vec::new();
    let mut suites = Vec::new();
    let mut export = None;
    let mut mtu = None;
    let mut cookie = true;
    let mut client_cert = true;
    let mut message = "hello from only-dtls".to_string();
    let mut close = false;
    let mut oneway = false;
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--cert" => cert = Some(std::fs::read(&v).expect("cert file")),
            "--key" => key = Some(std::fs::read(&v).expect("key file")),
            "--fingerprint" => fingerprint = Some(Fingerprint::parse(&v).expect("fingerprint")),
            "--srtp" => srtp = v.split(',').map(srtp_by_name).collect(),
            "--suite" => suites = v.split(',').map(suite_by_name).collect(),
            "--export" => {
                let (l, n) = v.rsplit_once(':').expect("LABEL:LEN");
                export = Some((l.to_string(), n.parse().expect("length")));
            }
            "--mtu" => mtu = Some(v.parse().expect("mtu")),
            "--message" => message = v,
            "--no-cookie" => {
                cookie = false;
                i -= 1;
            }
            "--no-client-cert" => {
                client_cert = false;
                i -= 1;
            }
            "--close" => {
                close = true;
                i -= 1;
            }
            "--oneway" => {
                oneway = true;
                i -= 1;
            }
            o => panic!("unknown option {o}"),
        }
        i += 2;
    }
    let identity = match (cert, key) {
        (Some(c), Some(k)) => Identity::from_pem(&c, &k).expect("identity"),
        _ => Identity::generate_self_signed().expect("identity"),
    };
    eprintln!("local fingerprint: {}", identity.fingerprint());
    let mut config = Config::new(identity)
        .with_srtp_profiles(srtp)
        .with_hello_verify(cookie)
        .with_require_client_certificate(client_cert)
        .with_verifier(match fingerprint {
            Some(f) => PeerVerifier::Fingerprints(vec![f]),
            None => PeerVerifier::AcceptAny,
        })
        .with_retransmit(Duration::from_millis(500), Duration::from_secs(4))
        .with_handshake_timeout(Duration::from_secs(15));
    if !suites.is_empty() {
        config = config.with_cipher_suites(suites);
    }
    if let Some(m) = mtu {
        config = config.with_mtu(m);
    }
    Opts {
        config,
        export,
        message,
        close,
        oneway,
    }
}

fn on_connected(conn: &Connection, opts: &Opts, info: &only_dtls::HandshakeInfo) {
    println!(
        "CONNECTED suite={} srtp={:?} peer={}",
        info.cipher_suite,
        info.srtp_profile,
        info.peer_fingerprint
            .as_ref()
            .map_or_else(|| "-".to_string(), ToString::to_string)
    );
    if let Some(p) = info.srtp_profile {
        let n = 2 * (p.master_key_len() + p.master_salt_len());
        let m = conn
            .export_keying_material(only_dtls::SRTP_EXPORTER_LABEL, None, n)
            .expect("export");
        println!("SRTP_MATERIAL {}", hex(&m));
    }
    if let Some((label, len)) = &opts.export {
        let m = conn
            .export_keying_material(label, None, *len)
            .expect("export");
        println!("EXPORT {}", hex(&m));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, addr) = (args[0].as_str(), args[1].as_str());
    let opts = parse(&args[2..]);
    let config = Arc::new(opts.config.clone());
    let role = if mode == "client" {
        Role::Client
    } else {
        Role::Server
    };
    let sock = match role {
        Role::Client => {
            let s = UdpSocket::bind("0.0.0.0:0").expect("bind");
            s.connect(addr).expect("connect");
            s
        }
        Role::Server => UdpSocket::bind(addr).expect("bind"),
    };
    let mut buf = vec![0u8; 65536];
    let mut peer: Option<SocketAddr> = None;
    let mut conn = match role {
        Role::Client => Connection::client(config, Instant::now()).expect("client"),
        Role::Server => {
            sock.set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            let (n, from) = sock.recv_from(&mut buf).expect("first datagram");
            peer = Some(from);
            sock.connect(from).expect("connect");
            let mut c = Connection::server(config, Instant::now(), from.to_string().as_bytes())
                .expect("server");
            c.handle_datagram(Instant::now(), &buf[..n])
                .expect("first datagram");
            c
        }
    };
    let _ = peer;
    let mut sent_message = false;
    let mut idle_deadline = None;
    loop {
        while let Some(d) = conn.poll_transmit() {
            let _ = sock.send(&d);
        }
        while let Some(e) = conn.poll_event() {
            match e {
                Event::Connected(info) => {
                    on_connected(&conn, &opts, &info);
                    if role == Role::Client && !sent_message {
                        conn.send_application_data(opts.message.as_bytes())
                            .expect("send");
                        sent_message = true;
                        if opts.oneway {
                            while let Some(d) = conn.poll_transmit() {
                                let _ = sock.send(&d);
                            }
                            std::thread::sleep(Duration::from_millis(300));
                            conn.close();
                            while let Some(d) = conn.poll_transmit() {
                                let _ = sock.send(&d);
                            }
                            println!("DONE");
                            return;
                        }
                    }
                    idle_deadline = Some(Instant::now() + Duration::from_secs(10));
                }
                Event::ApplicationData(d) => {
                    let text = String::from_utf8_lossy(&d).trim_end().to_string();
                    println!("RECV {text}");
                    if role == Role::Server {
                        conn.send_application_data(&d).expect("echo");
                    } else if text == opts.message.trim_end() {
                        if opts.close {
                            conn.close();
                            while let Some(d) = conn.poll_transmit() {
                                let _ = sock.send(&d);
                            }
                        }
                        println!("DONE");
                        return;
                    }
                }
                Event::Closed => {
                    println!("CLOSED");
                    return;
                }
                _ => {}
            }
        }
        while let Some(d) = conn.poll_transmit() {
            let _ = sock.send(&d);
        }
        if conn.is_closed() {
            return;
        }
        let now = Instant::now();
        if idle_deadline.is_some_and(|t| now >= t) {
            eprintln!("idle timeout");
            std::process::exit(i32::from(role != Role::Server));
        }
        let wait = conn
            .poll_timeout()
            .map_or(Duration::from_millis(200), |t| {
                t.saturating_duration_since(now)
            })
            .clamp(Duration::from_millis(1), Duration::from_millis(200));
        sock.set_read_timeout(Some(wait)).expect("timeout");
        match sock.recv(&mut buf) {
            Ok(n) => {
                if let Err(e) = conn.handle_datagram(Instant::now(), &buf[..n]) {
                    while let Some(d) = conn.poll_transmit() {
                        let _ = sock.send(&d);
                    }
                    eprintln!("ERROR {e}");
                    std::process::exit(1);
                }
            }
            Err(_) => {
                if let Err(e) = conn.handle_timeout(Instant::now()) {
                    eprintln!("ERROR {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
