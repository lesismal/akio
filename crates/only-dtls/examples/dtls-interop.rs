//! A DTLS client or server over UDP for interop checks (tools/interop/dtls/run.sh).
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
//!   --versions 1.3,1.2            protocol versions (default 1.2)
//!   --cid N                       connection IDs: ask the peer for an N-byte CID
//!   --psk IDENTITY:HEXKEY         an external PSK (no certificate needed)
//!   --resumption                  issue (server) / accept (client) session tickets
//!   --resume                      client: connect, then reconnect resuming the session
//!   --key-update                  client: after the echo, KeyUpdate (asking the peer's) and
//!                                 send the message again
//!   --accept N                    server: serve N connections one after the other
//!   --early-data N                DTLS 1.3 0-RTT: server accepts N bytes; client (with
//!                                 --resume) sends `early: <message>` before the handshake
//!   --pha                         client: offer post-handshake authentication
//!   --request-cert                server: ask for the client's certificate before the first
//!                                 echo (prints `CLIENT_CERT <fingerprint>`)
//!   --rotate-cid                  client: after the echo, RequestConnectionId, switch to a
//!                                 new CID and send the message again
//! ```
//!
//! Prints `CONNECTED suite=.. srtp=.. peer=<fingerprint>`, `INFO version=.. resumed=..
//! psk=.. local_cid=.. peer_cid=..`, `EARLY accepted=..` (DTLS 1.3), `EARLY_RECV <text>`,
//! `SRTP_MATERIAL <hex>` (the `EXTRACTOR-dtls_srtp` export,
//! as OpenSSL's `-keymatexport` prints it), `RECV <text>`.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only_dtls::{
    CipherSuite, Config, Connection, Event, Fingerprint, Identity, PeerVerifier, Psk, Role,
    Session, SrtpProfile, Version,
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn suite_by_name(n: &str) -> CipherSuite {
    CipherSuite::ALL
        .into_iter()
        .chain(CipherSuite::PSK)
        .chain(CipherSuite::TLS13)
        .find(|s| s.to_string() == n)
        .unwrap_or_else(|| panic!("unknown cipher suite {n}"))
}

struct Opts {
    config: Config,
    export: Option<(String, usize)>,
    message: String,
    close: bool,
    oneway: bool,
    resume: bool,
    key_update: bool,
    accept: usize,
    early: bool,
    request_cert: bool,
    rotate_cid: bool,
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
    let mut versions = vec![Version::Dtls12];
    let mut cid = None;
    let mut psks = Vec::new();
    let mut resumption = false;
    let mut resume = false;
    let mut key_update = false;
    let mut accept = 1;
    let mut early = 0;
    let mut pha = false;
    let mut request_cert = false;
    let mut rotate_cid = false;
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
            "--versions" => {
                versions = v
                    .split(',')
                    .map(|x| match x {
                        "1.3" => Version::Dtls13,
                        "1.2" => Version::Dtls12,
                        o => panic!("unknown version {o}"),
                    })
                    .collect();
            }
            "--cid" => cid = Some(v.parse().expect("cid length")),
            "--psk" => {
                let (id, key) = v.split_once(':').expect("IDENTITY:HEXKEY");
                psks.push(Psk::new(id.as_bytes(), unhex(key)).expect("psk"));
            }
            "--accept" => accept = v.parse().expect("count"),
            "--resumption" => {
                resumption = true;
                i -= 1;
            }
            "--resume" => {
                resume = true;
                resumption = true;
                i -= 1;
            }
            "--key-update" => {
                key_update = true;
                i -= 1;
            }
            "--early-data" => early = v.parse().expect("bytes"),
            "--pha" => {
                pha = true;
                i -= 1;
            }
            "--request-cert" => {
                request_cert = true;
                i -= 1;
            }
            "--rotate-cid" => {
                rotate_cid = true;
                i -= 1;
            }
            o => panic!("unknown option {o}"),
        }
        i += 2;
    }
    let identity = match (cert, key) {
        (Some(c), Some(k)) => Some(Identity::from_pem(&c, &k).expect("identity")),
        _ if !psks.is_empty() => None,
        _ => Some(Identity::generate_self_signed().expect("identity")),
    };
    let base = match identity {
        Some(id) => {
            eprintln!("local fingerprint: {}", id.fingerprint());
            Config::new(id)
        }
        None => Config::without_identity(),
    };
    let mut config = base
        .with_versions(versions)
        .with_connection_id(cid)
        .with_psks(psks)
        .with_session_resumption(resumption)
        .with_srtp_profiles(srtp)
        .with_hello_verify(cookie)
        .with_require_client_certificate(client_cert)
        .with_verifier(match fingerprint {
            Some(f) => PeerVerifier::Fingerprints(vec![f]),
            None => PeerVerifier::AcceptAny,
        })
        .with_early_data(early)
        .with_post_handshake_auth(pha)
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
        resume,
        key_update,
        accept,
        early: early > 0,
        request_cert,
        rotate_cid,
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
    println!(
        "INFO version={} resumed={} psk={} local_cid={} peer_cid={}",
        match info.version {
            Version::Dtls13 => "1.3",
            _ => "1.2",
        },
        info.resumed,
        info.psk_identity.as_deref().map_or_else(
            || "-".to_string(),
            |p| String::from_utf8_lossy(p).into_owned()
        ),
        info.local_connection_id
            .as_deref()
            .map_or_else(|| "-".to_string(), hex),
        info.peer_connection_id
            .as_deref()
            .map_or_else(|| "-".to_string(), hex),
    );
    if info.version == Version::Dtls13 {
        println!("EARLY accepted={}", info.early_data);
    }
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
    let mut buf = vec![0u8; 65536];
    if mode == "client" {
        // Unconnected sockets: `send_to` on a connected one fails on macOS.
        let peer: SocketAddr = addr
            .to_socket_addrs()
            .expect("address")
            .next()
            .expect("address");
        let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
        let mut conn = Connection::client(config.clone(), Instant::now()).expect("client");
        let session = run(&sock, peer, &mut conn, &opts, &mut buf);
        if opts.resume {
            let session = session.unwrap_or_else(|| {
                eprintln!("ERROR no resumable session");
                std::process::exit(1)
            });
            println!("RESUMING");
            std::thread::sleep(Duration::from_millis(300));
            let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
            let mut conn =
                Connection::client_resume(config, Instant::now(), &session).expect("client");
            if opts.early {
                println!("EARLY max={}", session.max_early_data());
                match conn.send_early_data(format!("early: {}", opts.message).as_bytes()) {
                    Ok(()) => println!("EARLY_SENT"),
                    Err(e) => println!("EARLY_NOT_SENT {e}"),
                }
            }
            run(&sock, peer, &mut conn, &opts, &mut buf);
        }
        return;
    }
    let sock = UdpSocket::bind(addr).expect("bind");
    for _ in 0..opts.accept {
        sock.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (n, from) = sock.recv_from(&mut buf).expect("first datagram");
        let mut c = Connection::server(config.clone(), Instant::now(), from.to_string().as_bytes())
            .expect("server");
        if let Err(e) = c.handle_datagram(Instant::now(), &buf[..n]) {
            eprintln!("ERROR {e}");
            std::process::exit(1);
        }
        run(&sock, from, &mut c, &opts, &mut buf);
    }
}

fn flush(sock: &UdpSocket, peer: SocketAddr, conn: &mut Connection) {
    while let Some(d) = conn.poll_transmit() {
        let _ = sock.send_to(&d, peer);
    }
}

/// Runs one connection to its end; the client returns the last resumable session.
fn run(
    sock: &UdpSocket,
    peer: SocketAddr,
    conn: &mut Connection,
    opts: &Opts,
    buf: &mut [u8],
) -> Option<Session> {
    let role = conn.role();
    let mut sent_message = false;
    let mut idle_deadline = None;
    let mut session = None;
    // Client: when to send the message again after a KeyUpdate, and when to finish (after
    // the echo, or a linger for NewSessionTickets).
    let mut resend_at: Option<Instant> = None;
    let mut done_at: Option<Instant> = None;
    // Server: the certificate request after the first echo; client: CID rotation steps.
    let mut asked_cert = false;
    let mut rotate_step = 0;
    let linger = Duration::from_millis(match (opts.resume, opts.key_update || opts.rotate_cid) {
        (_, true) => 1500,
        (true, _) => 700,
        _ if opts.request_cert => 1000,
        _ => 300,
    });
    loop {
        flush(sock, peer, conn);
        if resend_at.is_some_and(|t| Instant::now() >= t) {
            resend_at = None;
            if rotate_step == 1 {
                // The spare CIDs arrived (or not): switch and send on the new one.
                rotate_step = 2;
                let rotated = conn.rotate_connection_id().expect("rotate");
                println!(
                    "ROTATED {rotated} peer_cid={}",
                    conn.peer_connection_id()
                        .map_or_else(|| "-".to_string(), hex)
                );
            }
            conn.send_application_data(opts.message.as_bytes())
                .expect("send");
            println!("SENT_AFTER_UPDATE");
        }
        while let Some(e) = conn.poll_event() {
            match e {
                Event::Connected(info) => {
                    on_connected(conn, opts, &info);
                    if role == Role::Client && !sent_message {
                        conn.send_application_data(opts.message.as_bytes())
                            .expect("send");
                        sent_message = true;
                        if opts.key_update {
                            // Ask for the peer's update too; send again on the new keys.
                            conn.update_keys(true).expect("key update");
                            println!("KEY_UPDATE");
                            resend_at = Some(Instant::now() + Duration::from_millis(500));
                        }
                        if opts.oneway {
                            done_at = Some(Instant::now() + linger);
                        }
                    }
                    idle_deadline = Some(Instant::now() + Duration::from_secs(10));
                }
                Event::ApplicationData(d) => {
                    let text = String::from_utf8_lossy(&d).trim_end().to_string();
                    println!("RECV {text}");
                    if role == Role::Server {
                        if opts.request_cert && !asked_cert {
                            // Before the echo: a client waiting for it processes the request
                            // first.
                            asked_cert = true;
                            conn.request_client_certificate()
                                .expect("request certificate");
                            println!("REQUESTED_CERT");
                        }
                        conn.send_application_data(&d).expect("echo");
                    } else if opts.rotate_cid && rotate_step == 0 {
                        rotate_step = 1;
                        conn.request_connection_ids(2).expect("request CIDs");
                        println!("REQUESTED_CIDS");
                        resend_at = Some(Instant::now() + Duration::from_millis(500));
                    } else if done_at.is_none() {
                        let wait = if opts.key_update || opts.resume {
                            linger
                        } else {
                            Duration::ZERO
                        };
                        done_at = Some(Instant::now() + wait);
                    }
                }
                Event::NewSession(s) => {
                    println!("NEW_SESSION ticket={}", s.has_ticket());
                    session = Some(*s);
                }
                Event::Closed => {
                    println!("CLOSED");
                    return session;
                }
                Event::EarlyData(d) => {
                    println!("EARLY_RECV {}", String::from_utf8_lossy(&d).trim_end());
                }
                Event::ClientCertificate(chain) => {
                    println!(
                        "CLIENT_CERT {}",
                        chain.first().map_or_else(
                            || "-".to_string(),
                            |c| Fingerprint::of(only_dtls::FingerprintAlgorithm::Sha256, c)
                                .to_string()
                        )
                    );
                }
                Event::LocalConnectionIds(ids) => {
                    let ids: Vec<String> = ids.iter().map(|c| hex(c)).collect();
                    println!("LOCAL_CIDS {}", ids.join(","));
                }
                _ => {}
            }
        }
        flush(sock, peer, conn);
        if conn.is_closed() {
            return session;
        }
        let now = Instant::now();
        if done_at.is_some_and(|t| now >= t) {
            if opts.close || opts.resume || opts.oneway {
                conn.close();
                flush(sock, peer, conn);
            }
            println!("DONE");
            return session;
        }
        if idle_deadline.is_some_and(|t| now >= t) {
            eprintln!("idle timeout");
            if role == Role::Server {
                return None;
            }
            std::process::exit(1);
        }
        let wait = conn
            .poll_timeout()
            .map_or(Duration::from_millis(200), |t| {
                t.saturating_duration_since(now)
            })
            .clamp(Duration::from_millis(1), Duration::from_millis(200));
        sock.set_read_timeout(Some(wait)).expect("timeout");
        match sock.recv_from(buf) {
            Ok((n, from)) if from == peer => {
                if let Err(e) = conn.handle_datagram(Instant::now(), &buf[..n]) {
                    flush(sock, peer, conn);
                    eprintln!("ERROR {e}");
                    std::process::exit(1);
                }
            }
            Ok(_) => {}
            Err(_) => {
                if let Err(e) = conn.handle_timeout(Instant::now()) {
                    eprintln!("ERROR {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
