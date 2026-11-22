//! Kernel TLS on engine connections (ADR-067, `ktls` feature, Linux with the `tls` module): a
//! rustls client (and an `akio` client) against `akio` servers whose record layer moves into
//! the kernel after the handshake. Runs on epoll and, with `AKIO_TEST_BACKEND=uring`, io_uring.

#![allow(missing_docs)]
#![cfg(all(target_os = "linux", feature = "ktls"))]

mod common;

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{
    Config, Conn, Engine, Handler, Listener, fn_acceptor,
    tls::{self as ftls, Ktls, KtlsPath, Tls, TlsInfo, tls_info},
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};

struct Pki {
    cert: CertificateDer<'static>,
    key: Vec<u8>,
}

fn pki() -> Pki {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    Pki {
        cert: CertificateDer::from(ck.0.as_der().to_vec()),
        key: ck.1.to_pkcs8_der(),
    }
}

fn server_cfg(p: &Pki, mode: Ktls, key_update_after: Option<u64>) -> ftls::ServerConfig {
    let mut b = ftls::ServerConfig::builder(
        vec![ftls::Certificate::from_der(p.cert.to_vec())],
        ftls::PrivateKey::from_pkcs8_der(p.key.clone()),
    )
    .ktls(mode);
    if let Some(n) = key_update_after {
        b = b.__key_update_after(n);
    }
    b.build().unwrap()
}

/// Whether the kernel has the `tls` module: otherwise the tests check that nothing moved.
fn kernel_tls() -> bool {
    std::path::Path::new("/proc/net/tls_stat").exists() || load_tls_module()
}

/// Attaching the ULP once loads the module if the system allows it.
fn load_tls_module() -> bool {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let _ = l.accept();
    use std::os::fd::AsRawFd;
    let _ = akio_sys::ktls::ktls_attach(c.as_raw_fd());
    std::path::Path::new("/proc/net/tls_stat").exists()
}

/// TLS 1.3 also needs the kernel to follow key updates (Linux 6.14).
fn rekey_ok() -> bool {
    kernel_tls() && akio_sys::ktls::ktls_rekey_supported()
}

fn rustls_client(trust: &CertificateDer<'static>, tls12: bool, chacha: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trust.clone()).unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    if chacha {
        provider
            .cipher_suites
            .retain(|s| format!("{:?}", s.suite()).contains("CHACHA20"));
    }
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12 {
        &[&rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let c = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(c)
}

fn connect(addr: SocketAddr, cfg: Arc<ClientConfig>) -> StreamOwned<ClientConnection, TcpStream> {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let conn = ClientConnection::new(cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    StreamOwned::new(conn, tcp)
}

fn quick() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(300);
    v
}

/// Echoes, and keeps the server's latest `tls_info`.
struct Echo(Arc<Mutex<Option<TlsInfo>>>);
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        *self.0.lock().unwrap() = tls_info(c);
        if data == b"FILE" {
            let f = std::fs::File::open(file_path()).unwrap();
            let len = f.metadata().unwrap().len();
            let part = akio::Part::File {
                file: Arc::new(f),
                offset: 0,
                len,
            };
            c.reserve_response().unwrap().fill_parts(vec![part], false);
            return;
        }
        let _ = c.send(data);
    }
}

fn file_path() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("akio-ktls-{}.bin", std::process::id()));
    if !p.exists() {
        let data: Vec<u8> = (0..FILE_LEN).map(|i| (i * 7 % 253) as u8).collect();
        std::fs::write(&p, data).unwrap();
    }
    p
}

const FILE_LEN: usize = 5 << 20;

struct Server {
    e: Engine,
    info: Arc<Mutex<Option<TlsInfo>>>,
    stats: ftls::TlsStats,
}

impl Server {
    fn addr(&self) -> SocketAddr {
        self.e.local_addrs()[0]
    }
    fn info(&self) -> TlsInfo {
        self.info.lock().unwrap().clone().expect("no data seen")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.e.shutdown();
        self.e.wait();
    }
}

fn server(p: &Pki, mode: Ktls, key_update_after: Option<u64>) -> Server {
    let info = Arc::new(Mutex::new(None));
    let i2 = info.clone();
    let tls = Tls::server(
        server_cfg(p, mode, key_update_after),
        fn_acceptor(move |_c: &Conn<Echo>| Echo(i2.clone())),
    );
    let stats = tls.stats();
    let e = Engine::builder()
        .config(quick())
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .backend(common::backend())
                .threads(2)
                .serve(tls),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    Server { e, info, stats }
}

/// Writes `data` and reads its echo back, interleaved so neither side stalls.
fn echo_bulk(c: &mut StreamOwned<ClientConnection, TcpStream>, data: &[u8]) {
    let mut got = Vec::with_capacity(data.len());
    let mut sent = 0;
    let mut buf = vec![0u8; 64 << 10];
    while got.len() < data.len() {
        if sent < data.len() && sent - got.len() < 256 << 10 {
            let n = (data.len() - sent).min(48 << 10);
            c.write_all(&data[sent..sent + n]).unwrap();
            sent += n;
            continue;
        }
        let n = common::read_retry(c, &mut buf).unwrap();
        assert!(n > 0, "eof after {} of {} bytes", got.len(), data.len());
        got.extend_from_slice(&buf[..n]);
    }
    assert!(got == data, "echo differs");
}

fn echo_small(c: &mut StreamOwned<ClientConnection, TcpStream>, msg: &[u8]) {
    c.write_all(msg).unwrap();
    let mut b = vec![0u8; msg.len()];
    c.read_exact(&mut b).unwrap();
    assert_eq!(b, msg);
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

/// The paths the server should report under `mode`.
fn expected(mode: Ktls, tls13: bool) -> (Option<KtlsPath>, Option<KtlsPath>) {
    let able = if tls13 { rekey_ok() } else { kernel_tls() };
    match mode {
        _ if !able => (None, None),
        Ktls::Software => (Some(KtlsPath::Software), Some(KtlsPath::Software)),
        Ktls::SoftwareTx => (Some(KtlsPath::Software), None),
        _ => (None, None),
    }
}

/// The receive direction moves once a read ends on a record boundary: after a small echo.
fn settle(
    s: &Server,
    c: &mut StreamOwned<ClientConnection, TcpStream>,
    want: (Option<KtlsPath>, Option<KtlsPath>),
) {
    let t = Instant::now();
    loop {
        echo_small(c, b"sync");
        let i = s.info();
        if (i.ktls_tx, i.ktls_rx) == want {
            return;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "ktls {:?} != {want:?}",
            (i.ktls_tx, i.ktls_rx)
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn software_both_directions_echo_and_bulk() {
    for (tls12, chacha) in [(false, false), (false, true), (true, false), (true, true)] {
        let p = pki();
        let s = server(&p, Ktls::Software, None);
        let mut c = connect(s.addr(), rustls_client(&p.cert, tls12, chacha));
        echo_small(&mut c, b"hello ktls");
        let want = expected(Ktls::Software, !tls12);
        settle(&s, &mut c, want);
        echo_bulk(&mut c, &pattern(6 << 20));
        echo_small(&mut c, b"after bulk");
        let n = s.stats.counts();
        assert_eq!(
            n.ktls_tx_software,
            u64::from(want.0.is_some()),
            "tls12={tls12} chacha={chacha}"
        );
        assert_eq!(n.ktls_rx_software, u64::from(want.1.is_some()));
        assert_eq!(n.ktls_tx_hardware + n.ktls_rx_hardware, 0);
    }
}

#[test]
fn software_tx_only() {
    let p = pki();
    let s = server(&p, Ktls::SoftwareTx, None);
    let mut c = connect(s.addr(), rustls_client(&p.cert, false, false));
    echo_small(&mut c, b"x");
    settle(&s, &mut c, expected(Ktls::SoftwareTx, true));
    echo_bulk(&mut c, &pattern(3 << 20));
}

#[test]
fn hardware_without_a_nic_and_off_stay_in_user_space() {
    for mode in [Ktls::Hardware, Ktls::Off] {
        let p = pki();
        let s = server(&p, mode, None);
        let mut c = connect(s.addr(), rustls_client(&p.cert, false, false));
        echo_small(&mut c, b"x");
        echo_bulk(&mut c, &pattern(1 << 20));
        let i = s.info();
        // Loopback offloads nothing.
        assert_eq!((i.ktls_tx, i.ktls_rx), (None, None), "{mode:?}");
        let n = s.stats.counts();
        assert_eq!(n.ktls_tx_software + n.ktls_rx_software, 0);
    }
}

#[test]
fn peer_key_update_requests_are_answered() {
    let p = pki();
    let s = server(&p, Ktls::Software, None);
    let mut c = connect(s.addr(), rustls_client(&p.cert, false, false));
    echo_small(&mut c, b"x");
    settle(&s, &mut c, expected(Ktls::Software, true));
    for i in 0..20 {
        // KeyUpdate(update_requested): the server installs new receive keys in the kernel,
        // answers with its own KeyUpdate and installs new send keys.
        c.conn.refresh_traffic_keys().unwrap();
        echo_small(&mut c, format!("after key update {i}").as_bytes());
    }
    echo_bulk(&mut c, &pattern(2 << 20));
}

#[test]
fn server_initiated_key_updates() {
    let p = pki();
    // A key update every 16 records sent.
    let s = server(&p, Ktls::Software, Some(16));
    let mut c = connect(s.addr(), rustls_client(&p.cert, false, false));
    echo_small(&mut c, b"x");
    settle(&s, &mut c, expected(Ktls::Software, true));
    for i in 0..100 {
        echo_small(&mut c, format!("message {i}").as_bytes());
    }
    echo_bulk(&mut c, &pattern(4 << 20));
}

#[test]
fn send_file_goes_through_the_kernel() {
    for mode in [Ktls::Software, Ktls::Off] {
        let p = pki();
        let s = server(&p, mode, None);
        let mut c = connect(s.addr(), rustls_client(&p.cert, false, false));
        echo_small(&mut c, b"x");
        settle(&s, &mut c, expected(mode, true));
        for _ in 0..3 {
            c.write_all(b"FILE").unwrap();
            let mut got = vec![0u8; FILE_LEN];
            c.read_exact(&mut got).unwrap();
            assert!(
                got == std::fs::read(file_path()).unwrap(),
                "{mode:?}: file differs"
            );
        }
    }
}

#[test]
fn close_notify_both_ways() {
    let p = pki();
    let s = server(&p, Ktls::Software, None);
    let mut c = connect(s.addr(), rustls_client(&p.cert, false, false));
    echo_small(&mut c, b"x");
    settle(&s, &mut c, expected(Ktls::Software, true));
    // The client closes: the server reads close_notify (a control record through the kernel
    // when the receive direction moved) and the FIN, and answers with its own close_notify.
    c.conn.send_close_notify();
    c.flush().unwrap();
    c.sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut b = [0u8; 16];
    // rustls reports a clean close (close_notify received) as Ok(0), a bare EOF as an error.
    assert_eq!(c.read(&mut b).unwrap(), 0);
}

#[test]
fn akio_client_with_ktls_dials_only_server() {
    let p = pki();
    let s = server(&p, Ktls::Software, None);
    struct Client(Arc<Mutex<Vec<u8>>>, Arc<Mutex<Option<TlsInfo>>>);
    impl Handler for Client {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            *self.1.lock().unwrap() = tls_info(c);
            self.0.lock().unwrap().extend_from_slice(data);
        }
    }
    struct Acc(Arc<Mutex<Vec<u8>>>, Arc<Mutex<Option<TlsInfo>>>, Vec<u8>);
    impl akio::Acceptor for Acc {
        type Handler = Client;
        fn on_open(&self, c: &Conn<Client>) -> Client {
            c.send(&self.2).unwrap();
            Client(self.0.clone(), self.1.clone())
        }
    }
    let mut roots = ftls::RootCerts::empty();
    roots
        .add(&ftls::Certificate::from_der(p.cert.to_vec()))
        .unwrap();
    let cfg = ftls::ClientConfig::builder()
        .roots(roots)
        .ktls(Ktls::Software)
        .build()
        .unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let info = Arc::new(Mutex::new(None));
    let data = pattern(2 << 20);
    let client = Engine::builder()
        .config(quick())
        .client_threads(1)
        .build()
        .unwrap();
    client.start().unwrap();
    let acc = Acc(got.clone(), info.clone(), data.clone());
    client.dial(s.addr(), Tls::client(cfg, "localhost", acc).unwrap(), |e| {
        panic!("dial failed: {e}")
    });
    let t = Instant::now();
    while got.lock().unwrap().len() < data.len() {
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "no echo through kTLS"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(*got.lock().unwrap() == data);
    // The client's send direction moved (its data went out after the handshake).
    let i = info.lock().unwrap().clone().unwrap();
    assert_eq!(i.ktls_tx, expected(Ktls::Software, true).0);
    client.shutdown();
    client.wait();
}
