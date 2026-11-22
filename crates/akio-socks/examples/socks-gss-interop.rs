//! GSS-API (RFC 1961) interop with MIT Kerberos, for `tools/interop/socks/gssapi.sh`: the
//! security context is a test-only shim process (`tools/interop/socks/gss_shim.py`, over
//! python3-gssapi) behind the `GssContext` trait, so the workspace links no GSS-API library.
//!
//! ```text
//! socks-gss-interop server <listen> <lowest level> [highest level, default confidentiality]
//! socks-gss-interop client <proxy> <service@host> <none|integrity|confidentiality> [bytes]
//! socks-gss-interop udp <proxy> <service@host> <none|integrity|confidentiality>
//! ```
//!
//! The client relays `bytes` (default 1 MiB) through the proxy to an echo server of its own
//! and checks them, on the engine; with `none` it also tries the blocking helper. `udp` makes
//! a UDP association (on the engine, then blocking) and checks datagrams echoed by a UDP echo
//! server of its own; with protection they are wrapped (RFC 1961 §5). The server accepts
//! `UDP ASSOCIATE`.

use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, UdpSocket},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Conn, Engine, EngineRef, Handler, Listener};
use akio_socks::{
    Dest, Destinations, Socks, SocksClient, Version,
    gssapi::{GssContext, GssStep, Protection},
};

/// One context in the shim process.
struct Shim {
    _child: Child,
    tx: ChildStdin,
    rx: ChildStdout,
    /// The peer's principal, asked once established.
    peer: Option<String>,
}

impl Shim {
    fn spawn(args: &[&str]) -> io::Result<Shim> {
        let path = std::env::var("AKIO_GSS_SHIM")
            .unwrap_or_else(|_| "tools/interop/socks/gss_shim.py".into());
        let mut child = Command::new("python3")
            .arg(path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let tx = child.stdin.take().expect("piped");
        let rx = child.stdout.take().expect("piped");
        Ok(Shim {
            _child: child,
            tx,
            rx,
            peer: None,
        })
    }

    fn call(&mut self, op: u8, payload: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        let mut m = vec![op];
        m.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        m.extend_from_slice(payload);
        self.tx.write_all(&m)?;
        let mut h = [0u8; 5];
        self.rx.read_exact(&mut h)?;
        let mut b = vec![0u8; u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize];
        self.rx.read_exact(&mut b)?;
        if h[0] == b'E' {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                String::from_utf8_lossy(&b).into_owned(),
            ));
        }
        Ok((h[0], b))
    }
}

impl GssContext for Shim {
    fn step(&mut self, token: &[u8]) -> io::Result<GssStep> {
        match self.call(b'S', token)? {
            (b'C', t) => Ok(GssStep::Continue(t)),
            (_, t) => {
                let name = self.call(b'N', &[])?.1;
                self.peer = Some(String::from_utf8_lossy(&name).into_owned());
                Ok(GssStep::Complete(t))
            }
        }
    }
    fn wrap(&mut self, confidential: bool, msg: &[u8]) -> io::Result<Vec<u8>> {
        let mut p = vec![u8::from(confidential)];
        p.extend_from_slice(msg);
        Ok(self.call(b'W', &p)?.1)
    }
    fn unwrap(&mut self, token: &[u8]) -> io::Result<Vec<u8>> {
        Ok(self.call(b'U', token)?.1)
    }
    fn peer_name(&self) -> Option<String> {
        self.peer.clone()
    }
}

fn protection(s: &str) -> Protection {
    match s {
        "none" => Protection::None,
        "integrity" => Protection::Integrity,
        "confidentiality" => Protection::Confidentiality,
        _ => panic!("protection: none, integrity or confidentiality"),
    }
}

fn server(addr: SocketAddr, levels: std::ops::RangeInclusive<Protection>) -> io::Result<()> {
    let er = EngineRef::new();
    let socks = Socks::new(er.clone())
        .destinations(Destinations::Any)
        .udp_associate(true)
        .allow(|r| {
            println!("request from {:?}", r.user());
            true
        })
        .gssapi(
            || Ok(Box::new(Shim::spawn(&["accept"])?) as Box<dyn GssContext>),
            levels,
        );
    let e = Arc::new(
        Engine::builder()
            .listen(Listener::tcp(addr).serve(socks))
            .udp_client_threads(1)
            .build()?,
    );
    er.set(&e);
    e.start()?;
    println!("listening on {}", e.local_addrs()[0]);
    e.wait();
    Ok(())
}

/// An echo server on 127.0.0.1.
fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            thread::spawn(move || {
                let mut b = vec![0u8; 64 << 10];
                while let Ok(n) = s.read(&mut b) {
                    if n == 0 || s.write_all(&b[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    a
}

struct Check {
    want: Vec<u8>,
    got: Vec<u8>,
    done: Option<mpsc::Sender<bool>>,
}

impl Handler for Check {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.got.extend_from_slice(data);
        if self.got.len() >= self.want.len() {
            if let Some(tx) = self.done.take() {
                let _ = tx.send(self.got == self.want);
            }
            c.close();
        }
    }
    fn on_close(&mut self, _c: &Conn<Self>, _e: Option<akio::Error>) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(false);
        }
    }
}

fn client(proxy: SocketAddr, service: String, p: Protection, n: usize) -> io::Result<()> {
    let target = echo();
    let svc = service;
    let c = SocksClient::new(Version::Socks5, proxy).gssapi(
        move |_host: &str| Ok(Box::new(Shim::spawn(&["initiate", &svc])?) as Box<dyn GssContext>),
        p,
    );
    let e = Arc::new(Engine::builder().client_threads(1).build()?);
    e.start()?;
    let d2: Vec<u8> = (0..n).map(|i| (i * 13 % 251) as u8).collect();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let (etx, erx) = mpsc::channel();
    c.dial(
        &e,
        target.into(),
        akio::fn_acceptor(move |c: &Conn<Check>| {
            c.send(&d2).expect("send");
            Check {
                want: d2.clone(),
                got: Vec::new(),
                done: Some(tx.lock().expect("lock").clone()),
            }
        }),
        move |err| {
            let _ = etx.send(err);
        },
    );
    let ok = rx.recv_timeout(Duration::from_secs(30)).unwrap_or(false);
    if !ok {
        let why = erx.try_recv().map_or_else(
            |_| "bytes differ or tunnel closed".into(),
            |e| e.to_string(),
        );
        return Err(io::Error::other(format!("engine tunnel ({p:?}): {why}")));
    }
    println!("engine tunnel ok ({p:?}, {n} bytes)");
    if p == Protection::None {
        match c.dial_blocking(&target.into()) {
            Ok(mut s) => {
                s.write_all(b"blocking ping")?;
                let mut b = [0u8; 13];
                s.read_exact(&mut b)?;
                assert_eq!(&b, b"blocking ping");
                println!("blocking tunnel ok");
            }
            // The proxy granted more protection than asked for.
            Err(e) if e.kind() == io::ErrorKind::Unsupported => println!("blocking refused: {e}"),
            Err(e) => return Err(e),
        }
    }
    e.shutdown();
    Ok(())
}

/// A UDP echo server on 127.0.0.1.
fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let a = s.local_addr().expect("addr");
    thread::spawn(move || {
        let mut b = vec![0u8; 65_536];
        while let Ok((n, from)) = s.recv_from(&mut b) {
            let _ = s.send_to(&b[..n], from);
        }
    });
    a
}

/// Datagram sizes checked (whole datagrams: Dante does not take fragments).
const SIZES: [usize; 3] = [1, 500, 1400];

fn udp(proxy: SocketAddr, service: String, p: Protection) -> io::Result<()> {
    let target = udp_echo();
    let svc = service;
    let c = SocksClient::new(Version::Socks5, proxy).gssapi(
        move |_host: &str| Ok(Box::new(Shim::spawn(&["initiate", &svc])?) as Box<dyn GssContext>),
        p,
    );
    let e = Arc::new(
        Engine::builder()
            .client_threads(1)
            .udp_client_threads(1)
            .build()?,
    );
    e.start()?;
    let (dtx, drx) = mpsc::channel::<(Dest, Vec<u8>)>();
    let dtx = Mutex::new(dtx);
    let (tx, rx) = mpsc::channel();
    c.udp_associate(
        &e,
        move |_, from, d| {
            let _ = dtx.lock().expect("lock").send((from, d.to_vec()));
        },
        move |r| {
            let _ = tx.send(r);
        },
    );
    let a = rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| io::Error::other("no association"))??;
    for n in SIZES {
        let d: Vec<u8> = (0..n).map(|i| (i * 7 % 251) as u8).collect();
        a.send_to(&d, &target.into())?;
        let (from, got) = drx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| io::Error::other(format!("engine: no echo of {n} bytes ({p:?})")))?;
        if from != Dest::from(target) || got != d {
            return Err(io::Error::other(format!("engine: {n}-byte echo differs")));
        }
    }
    a.close();
    println!("engine association ok ({p:?})");
    let u = c.udp_associate_blocking()?;
    u.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut b = vec![0u8; 4096];
    for n in SIZES {
        let d: Vec<u8> = (0..n).map(|i| (i * 11 % 251) as u8).collect();
        u.send_to(&d, &target.into())?;
        let (k, from) = u.recv_from(&mut b)?;
        if from != Dest::from(target) || b[..k] != d[..] {
            return Err(io::Error::other(format!("blocking: {n}-byte echo differs")));
        }
    }
    println!("blocking association ok ({p:?})");
    e.shutdown();
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("server") => server(
            args[1].parse().expect("listen address"),
            protection(&args[2])
                ..=protection(args.get(3).map_or("confidentiality", String::as_str)),
        ),
        Some("client") => client(
            args[1].parse().expect("proxy address"),
            args[2].clone(),
            protection(&args[3]),
            args.get(4).map_or(1 << 20, |n| n.parse().expect("bytes")),
        ),
        Some("udp") => udp(
            args[1].parse().expect("proxy address"),
            args[2].clone(),
            protection(&args[3]),
        ),
        _ => {
            eprintln!("usage: socks-gss-interop server|client ...");
            std::process::exit(2);
        }
    }
}
