//! Interop driver for only-tls: a blocking client or server over TCP, for runs against
//! `openssl s_client` / `s_server`, Go's `crypto/tls` and others (`tools/interop/tls`).
//!
//! ```text
//! tls-interop server <addr> --cert c.pem --key k.pem [--ca ca.pem [--require]] [--alpn h2,..]
//!                           [--http-server]
//!                           [--tls12|--tls13] [--suites 0x1301,..] [--groups 0x1d,..]
//!                           [--tickets] [--count N] [--hrr] [--early-data [--early-max N]]
//! tls-interop client <addr> <name> [--ca ca.pem | --insecure] [--cert c.pem --key k.pem]
//!                           [--alpn ..] [--tls12|--tls13] [--suites ..] [--groups ..]
//!                           [--count N] [--expect-resume] [--key-update] [--bytes N] [--http]
//!                           [--early-data] [--expect-early accepted|rejected]
//! ```
//!
//! The server echoes what it reads (`--count` connections, then exits); the client sends a line,
//! checks the echo and prints what was negotiated, one line per connection. With
//! `--early-data` the client sends its line (or HTTP request) before the handshake, as TLS 1.3
//! early data when it resumes with a ticket allowing it; `--expect-early` checks what the
//! server did with it from the second connection on.
//!
//! `--ktls` (or `ONLY_INTEROP_KTLS=1` in the environment, `=require` to fail when the kernel
//! refuses; needs Linux and the `experimental-ktls` feature) moves the record layer into the Linux kernel after the handshake (kernel TLS,
//! evaluation only: docs/BENCHMARKS.md); `--key-update` then rekeys through the kernel.
#![allow(missing_docs)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use only_tls::stream::Stream;
use only_tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig};

struct Opts {
    pos: Vec<String>,
    cert: Option<String>,
    key: Option<String>,
    ca: Option<String>,
    require: bool,
    insecure: bool,
    alpn: Vec<String>,
    tls12: bool,
    tls13: bool,
    suites: Vec<u16>,
    groups: Vec<u16>,
    tickets: bool,
    count: usize,
    expect_resume: bool,
    key_update: bool,
    hrr: bool,
    bytes: usize,
    http: bool,
    http_server: bool,
    ktls: bool,
    ktls_required: bool,
    early_data: Option<u32>,
    expect_early: Option<String>,
}

fn hex_list(s: &str) -> Vec<u16> {
    s.split(',')
        .map(|x| u16::from_str_radix(x.trim_start_matches("0x"), 16).expect("hex id"))
        .collect()
}

fn parse() -> Opts {
    let mut o = Opts {
        pos: Vec::new(),
        cert: None,
        key: None,
        ca: None,
        require: false,
        insecure: false,
        alpn: Vec::new(),
        tls12: false,
        tls13: false,
        suites: Vec::new(),
        groups: Vec::new(),
        tickets: false,
        count: 1,
        expect_resume: false,
        key_update: false,
        hrr: false,
        bytes: 0,
        http: false,
        http_server: false,
        ktls: false,
        ktls_required: false,
        early_data: None,
        expect_early: None,
    };
    match std::env::var("ONLY_INTEROP_KTLS").as_deref() {
        Ok("1") => o.ktls = true,
        Ok("require") => (o.ktls, o.ktls_required) = (true, true),
        _ => {}
    }
    let mut a = std::env::args().skip(1);
    while let Some(x) = a.next() {
        let mut val = || a.next().expect("missing value");
        match x.as_str() {
            "--cert" => o.cert = Some(val()),
            "--key" => o.key = Some(val()),
            "--ca" => o.ca = Some(val()),
            "--require" => o.require = true,
            "--insecure" => o.insecure = true,
            "--alpn" => o.alpn = val().split(',').map(str::to_owned).collect(),
            "--tls12" => o.tls12 = true,
            "--tls13" => o.tls13 = true,
            "--suites" => o.suites = hex_list(&val()),
            "--groups" => o.groups = hex_list(&val()),
            "--tickets" => o.tickets = true,
            "--count" => o.count = val().parse().expect("count"),
            "--expect-resume" => o.expect_resume = true,
            "--key-update" => o.key_update = true,
            "--hrr" => o.hrr = true,
            "--bytes" => o.bytes = val().parse().expect("bytes"),
            "--http" => o.http = true,
            "--http-server" => o.http_server = true,
            "--ktls" => o.ktls = true,
            // Server: accept up to 16384 bytes (or `--early-max`); client: send early.
            "--early-data" => o.early_data = Some(o.early_data.unwrap_or(16384)),
            "--early-max" => o.early_data = Some(val().parse().expect("early-max")),
            "--expect-early" => o.expect_early = Some(val()),
            _ => o.pos.push(x),
        }
    }
    o
}

fn read(p: &str) -> Vec<u8> {
    std::fs::read(p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn roots(p: &str) -> RootCerts {
    let mut r = RootCerts::empty();
    r.add_pem(&read(p)).expect("roots");
    r
}

fn describe(c: &only_tls::__proto::Connection) -> String {
    format!(
        "version={} suite={} alpn={} resumed={} sni={} peer_certs={} early={:?}/{}",
        c.version_name().unwrap_or("-"),
        c.suite().map_or("-", |s| s.name),
        c.alpn().map_or_else(
            || "-".to_owned(),
            |a| String::from_utf8_lossy(a).into_owned()
        ),
        c.resumed(),
        c.server_name().unwrap_or("-"),
        c.peer_certificates().len(),
        c.early_data(),
        c.early_data_len(),
    )
}

/// Asks for kernel TLS before the handshake (Linux).
#[cfg_attr(
    not(all(target_os = "linux", feature = "experimental-ktls")),
    allow(clippy::needless_pass_by_ref_mut)
)]
fn want_ktls<S: Read + Write + std::os::fd::AsRawFd>(o: &Opts, s: &mut Stream<S>) {
    #[cfg(all(target_os = "linux", feature = "experimental-ktls"))]
    if o.ktls {
        s.want_ktls();
    }
    let _ = (o, s);
}

/// Moves the record layer into the kernel after the handshake; " ktls=on|off" for the report.
#[cfg_attr(
    not(all(target_os = "linux", feature = "experimental-ktls")),
    allow(clippy::needless_pass_by_ref_mut)
)]
fn offload<S: Read + Write + std::os::fd::AsRawFd>(o: &Opts, s: &mut Stream<S>) -> &'static str {
    if !o.ktls {
        return "";
    }
    #[cfg(all(target_os = "linux", feature = "experimental-ktls"))]
    match s.offload() {
        Ok(true) => return " ktls=on",
        Ok(false) => {}
        Err(e) => {
            println!("kTLS offload failed: {e}");
            std::process::exit(1);
        }
    }
    let _ = s;
    if o.ktls_required {
        println!("kTLS required but unavailable");
        std::process::exit(1);
    }
    " ktls=off"
}

fn server(o: &Opts) {
    let chain = Certificate::from_pem(&read(o.cert.as_deref().expect("--cert"))).expect("cert");
    let key = PrivateKey::from_pem(&read(o.key.as_deref().expect("--key"))).expect("key");
    let mut b = ServerConfig::builder(chain, key)
        .alpn(&o.alpn)
        .session_tickets(o.tickets)
        .tls13_only(o.tls13)
        .__tls12_only(o.tls12)
        .__force_hello_retry(o.hrr)
        .early_data(o.early_data.unwrap_or(0));
    if let Some(ca) = &o.ca {
        b = if o.require {
            b.client_auth_required(roots(ca))
        } else {
            b.client_auth_optional(roots(ca))
        };
    }
    if !o.suites.is_empty() {
        b = b.__suites(&o.suites);
    }
    if !o.groups.is_empty() {
        b = b.__groups(&o.groups);
    }
    let cfg = b.build().expect("server config");
    let l = TcpListener::bind(&o.pos[1]).expect("bind");
    println!("listening {}", l.local_addr().expect("addr"));
    for _ in 0..o.count {
        let (tcp, _) = l.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
        let mut s = Stream::server(&cfg, tcp);
        want_ktls(o, &mut s);
        if let Err(e) = s.handshake() {
            println!("handshake failed: {e}");
            continue;
        }
        let k = offload(o, &mut s);
        println!("server: {}{k}", describe(s.conn()));
        let mut buf = vec![0u8; 64 * 1024];
        let mut req = Vec::new();
        loop {
            match s.read(&mut buf) {
                Ok(0) => break,
                Ok(n) if o.http_server => {
                    // One response per request head (tlsfuzzer expects an HTTP server).
                    req.extend_from_slice(&buf[..n]);
                    while let Some((end, n)) = req
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|e| (e, 4))
                        .or_else(|| req.windows(2).position(|w| w == b"\n\n").map(|e| (e, 2)))
                    {
                        req.drain(..end + n);
                        let r = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
                        if s.write_all(r).is_err() {
                            break;
                        }
                    }
                }
                Ok(n) => {
                    if s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    println!("read: {e}");
                    break;
                }
            }
        }
        let _ = s.close();
    }
}

fn client(o: &Opts) {
    let mut b = ClientConfig::builder()
        .alpn(&o.alpn)
        .tls13_only(o.tls13)
        .__tls12_only(o.tls12)
        .early_data(o.early_data.is_some());
    if o.insecure {
        b = b.insecure_skip_verify();
    } else if let Some(ca) = &o.ca {
        b = b.roots(roots(ca));
    }
    if let (Some(c), Some(k)) = (&o.cert, &o.key) {
        b = b.client_cert(
            Certificate::from_pem(&read(c)).expect("cert"),
            PrivateKey::from_pem(&read(k)).expect("key"),
        );
    }
    if !o.suites.is_empty() {
        b = b.__suites(&o.suites);
    }
    if !o.groups.is_empty() {
        b = b.__groups(&o.groups);
    }
    let cfg = b.build().expect("client config");
    let mut failed = false;
    for i in 0..o.count {
        let tcp = TcpStream::connect(&o.pos[1]).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
        let mut s = Stream::client(&cfg, &o.pos[2], tcp).expect("client");
        want_ktls(o, &mut s);
        let pad = "x".repeat(o.bytes);
        let req = format!("GET / HTTP/1.0\r\nX-Pad: {pad}\r\n\r\n").into_bytes();
        let mut msg = format!("hello from only-tls {i}\n").into_bytes();
        msg.resize(msg.len().max(o.bytes), b'x');
        if o.early_data.is_some() {
            // Everything before the handshake: early data if the ticket allows it.
            let first = if o.http { &req } else { &msg };
            if let Err(e) = s.write_early(first) {
                println!("early write: {e}");
                std::process::exit(1);
            }
        }
        if let Err(e) = s.handshake() {
            println!("handshake failed: {e}");
            std::process::exit(1);
        }
        let k = offload(o, &mut s);
        println!("client[{i}]: {}{k}", describe(s.conn()));
        if o.expect_resume && i > 0 && !s.conn().resumed() {
            println!("expected a resumed session");
            failed = true;
        }
        if let (Some(want), true) = (&o.expect_early, i > 0) {
            let got = format!("{:?}", s.conn().early_data()).to_ascii_lowercase();
            if got != *want || (want == "accepted" && s.conn().early_data_len() == 0) {
                println!("expected early data {want}, got {got}");
                failed = true;
            }
        }
        if o.key_update && !s.offloaded() {
            s.conn_mut().set_key_update_after(1);
        }
        // Through the kernel: one KeyUpdate before each write.
        let ktls_key_update = o.key_update && s.offloaded();
        if o.http {
            // `openssl s_server -www` answers a GET with a status page, then closes.
            let chunks: [&[u8]; 2] = if o.early_data.is_some() {
                [&[], &[]]
            } else {
                [&req[..req.len() / 2], &req[req.len() / 2..]]
            };
            for chunk in chunks {
                if ktls_key_update {
                    key_update(&mut s);
                }
                s.write_all(chunk).expect("write");
            }
            let mut resp = Vec::new();
            if let Err(e) = s.read_to_end(&mut resp) {
                println!("read: {e}");
                std::process::exit(1);
            }
            if !resp.starts_with(b"HTTP/1.0 200") {
                println!("unexpected response: {}", String::from_utf8_lossy(&resp));
                std::process::exit(1);
            }
            continue;
        }
        let chunks: [&[u8]; 2] = if o.early_data.is_some() {
            [&[], &[]]
        } else {
            [&msg[..msg.len() / 2], &msg[msg.len() / 2..]]
        };
        for chunk in chunks {
            if ktls_key_update {
                key_update(&mut s);
            }
            s.write_all(chunk).expect("write");
        }
        let mut got = vec![0u8; msg.len()];
        if let Err(e) = s.read_exact(&mut got) {
            println!("read: {e}");
            std::process::exit(1);
        }
        if got != msg {
            println!("echo mismatch");
            std::process::exit(1);
        }
        let _ = s.close();
    }
    if failed {
        std::process::exit(2);
    }
    println!("ok");
}

#[cfg_attr(
    not(all(target_os = "linux", feature = "experimental-ktls")),
    allow(clippy::needless_pass_by_ref_mut)
)]
fn key_update<S: Read + Write>(s: &mut Stream<S>) {
    #[cfg(all(target_os = "linux", feature = "experimental-ktls"))]
    if let Err(e) = s.key_update() {
        println!("kTLS KeyUpdate failed: {e}");
        std::process::exit(1);
    }
    let _ = s;
}

fn main() {
    let o = parse();
    match o.pos.first().map(String::as_str) {
        Some("server") if o.pos.len() >= 2 => server(&o),
        Some("client") if o.pos.len() >= 3 => client(&o),
        _ => {
            eprintln!("usage: tls-interop server <addr> ... | client <addr> <name> ...");
            std::process::exit(2);
        }
    }
}
