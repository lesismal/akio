//! Kernel TLS offload over real loopback sockets (Linux, `experimental-ktls`): every suite of
//! TLS 1.3 and 1.2, KeyUpdate through the kernel in both directions, alerts, close_notify,
//! `sendfile` of encrypted records, and a user-space peer. Skipped (with a note) where the
//! kernel has no `tls` module, as in most containers.
#![cfg(all(target_os = "linux", feature = "ktls"))]
#![allow(missing_docs, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::Duration;

use only_tls::stream::Stream;
use only_tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig};

struct Pki {
    chain: Vec<Certificate>,
    key: PrivateKey,
    roots: RootCerts,
}

fn pki() -> Pki {
    let (c, k) = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = Certificate::from_der(c.as_der().to_vec());
    let mut roots = RootCerts::empty();
    roots.add(&cert).unwrap();
    Pki {
        chain: vec![cert],
        key: PrivateKey::from_pkcs8_der(k.to_pkcs8_der()),
        roots,
    }
}

/// Whether this kernel can offload at all (the `tls` module and TLS 1.3 rekeying).
fn available() -> bool {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let ok = only_sys::ktls::ktls_attach(c.as_raw_fd()).is_ok()
        && only_sys::ktls::ktls_rekey_supported();
    if !ok {
        eprintln!("kernel TLS unavailable here (no `tls` module or a kernel before 6.14): skipped");
    }
    ok
}

#[derive(Clone, Copy)]
struct Case {
    suite: u16,
    tls12: bool,
    client_ktls: bool,
    key_update: bool,
    file: bool,
}

/// Server: echoes until close_notify, then answers it; with `file`, first sends a file with
/// `sendfile(2)`. Client: sends data (with KeyUpdates), checks the echo, closes.
fn run(p: &Pki, case: Case) {
    let scfg = ServerConfig::builder(p.chain.clone(), p.key.clone())
        .__suites(&[case.suite])
        .build()
        .unwrap();
    let ccfg = ClientConfig::builder()
        .roots(p.roots.clone())
        .__tls12_only(case.tls12)
        .build()
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let file_data: Vec<u8> = (0..300_000u32).map(|i| (i * 7) as u8).collect();
    let path =
        std::env::temp_dir().join(format!("only-ktls-{}-{:x}", std::process::id(), case.suite));
    std::fs::write(&path, &file_data).unwrap();
    let srv_path = path.clone();
    let srv = std::thread::spawn(move || {
        let (tcp, _) = l.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut s = Stream::server(&scfg, tcp);
        s.want_ktls();
        s.handshake().unwrap();
        assert!(s.offload().unwrap(), "server offload");
        if case.file {
            let f = std::fs::File::open(&srv_path).unwrap();
            let len = f.metadata().unwrap().len();
            let mut off = 0;
            while off < len {
                let n = only_sys::sendfile(
                    s.get_ref().as_raw_fd(),
                    f.as_raw_fd(),
                    off,
                    (len - off) as usize,
                )
                .unwrap();
                off += n as u64;
            }
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        let mut reads = 0u32;
        loop {
            let n = s.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            total += n;
            reads += 1;
            if case.key_update && !case.tls12 && reads % 2 == 0 {
                s.key_update().unwrap();
            }
            s.write_all(&buf[..n]).unwrap();
        }
        assert!(
            s.conn().received_close_notify(),
            "close_notify reached the server"
        );
        s.close().unwrap();
        total
    });
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut c = Stream::client(&ccfg, "localhost", tcp).unwrap();
    if case.client_ktls {
        c.want_ktls();
    }
    c.handshake().unwrap();
    assert_eq!(c.conn().suite().unwrap().id, case.suite);
    if case.client_ktls {
        assert!(c.offload().unwrap(), "client offload");
    }
    if case.file {
        let mut got = vec![0u8; file_data.len()];
        c.read_exact(&mut got).unwrap();
        assert!(got == file_data, "sendfile data");
    }
    let mut sent = 0;
    for i in 0..20u32 {
        if case.key_update && !case.tls12 {
            if c.offloaded() {
                c.key_update().unwrap();
            } else {
                c.conn_mut().set_key_update_after(1);
            }
        }
        let msg: Vec<u8> = (0..(1000 + i * 4099)).map(|j| (i + j) as u8).collect();
        c.write_all(&msg).unwrap();
        let mut got = vec![0u8; msg.len()];
        c.read_exact(&mut got).unwrap();
        assert!(got == msg, "echo {i}");
        sent += msg.len();
    }
    c.close().unwrap();
    let mut rest = Vec::new();
    assert_eq!(c.read_to_end(&mut rest).unwrap(), 0);
    assert!(
        c.conn().received_close_notify(),
        "close_notify reached the client"
    );
    assert_eq!(srv.join().unwrap(), sent);
    let _ = std::fs::remove_file(path);
}

#[test]
fn every_suite_both_versions() {
    if !available() {
        return;
    }
    let p = pki();
    for (suite, tls12) in [
        (0x1301, false),
        (0x1302, false),
        (0x1303, false),
        (0xc02b, true),
        (0xc02c, true),
        (0xcca9, true),
    ] {
        for client_ktls in [true, false] {
            run(
                &p,
                Case {
                    suite,
                    tls12,
                    client_ktls,
                    key_update: false,
                    file: true,
                },
            );
        }
    }
}

#[test]
fn key_update_through_the_kernel() {
    if !available() {
        return;
    }
    let p = pki();
    for suite in [0x1301, 0x1302, 0x1303] {
        for client_ktls in [true, false] {
            run(
                &p,
                Case {
                    suite,
                    tls12: false,
                    client_ktls,
                    key_update: true,
                    file: false,
                },
            );
        }
    }
}

/// A fatal alert sent through the kernel fails the peer's read; garbage in a handshake record
/// draws an unexpected_message alert back.
#[test]
fn alerts_through_the_kernel() {
    if !available() {
        return;
    }
    let p = pki();
    let scfg = ServerConfig::builder(p.chain, p.key).build().unwrap();
    let ccfg = ClientConfig::builder().roots(p.roots).build().unwrap();
    for garbage in [false, true] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let scfg = scfg.clone();
        let srv = std::thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut s = Stream::server(&scfg, tcp);
            s.want_ktls();
            s.handshake().unwrap();
            assert!(s.offload().unwrap());
            let mut buf = [0u8; 100];
            s.read(&mut buf).map(|_| ()).map_err(|e| e.to_string())
        });
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut c = Stream::client(&ccfg, "localhost", tcp).unwrap();
        c.want_ktls();
        c.handshake().unwrap();
        assert!(c.offload().unwrap());
        let fd = c.get_ref().as_raw_fd();
        if garbage {
            only_sys::ktls::ktls_send_record(fd, 22, &[99, 0, 0, 0]).unwrap();
            let e = srv.join().unwrap().unwrap_err();
            assert!(e.contains("unexpected"), "{e}");
            // The server answered with a fatal unexpected_message alert.
            let mut buf = [0u8; 100];
            let e = c.read(&mut buf).unwrap_err().to_string();
            assert!(e.to_lowercase().contains("unexpected"), "{e}");
        } else {
            only_sys::ktls::ktls_send_record(fd, 21, &[2, 80]).unwrap();
            let e = srv.join().unwrap().unwrap_err();
            assert!(e.to_lowercase().contains("internal"), "{e}");
        }
    }
}
