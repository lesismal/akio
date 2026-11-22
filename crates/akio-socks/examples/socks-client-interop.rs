//! akio-socks' SOCKS client against a SOCKS server, for `tools/interop/socks/run.sh` (run
//! against Dante, the reference server, and against akio-socks' own server).
//!
//! `cargo run -p akio-socks --example socks-client-interop -- PROXY [user:pass] [--no-socks4]
//! [--no-socks4a-names]`
//!
//! Starts its own TCP and UDP echo servers on 127.0.0.1 and plays the BIND peer itself, then
//! checks, blocking and on the engine: SOCKS5 CONNECT to an address and to a name, BIND and
//! UDP ASSOCIATE; SOCKS4 and SOCKS4a CONNECT and BIND (unless `--no-socks4`; SOCKS4a without
//! host names with `--no-socks4a-names`: Dante 1.4 refuses them, curl's `--socks4a` too). Prints
//! one line per check; exits non-zero if any failed.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use akio::{Conn, Engine, Handler};
use akio_socks::{Dest, SocksClient, Version};

fn echo_tcp() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let a = l.local_addr().expect("addr");
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            thread::spawn(move || echo_stream(s));
        }
    });
    a
}

fn echo_stream(mut s: TcpStream) {
    let mut b = vec![0u8; 64 << 10];
    loop {
        match s.read(&mut b) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if s.write_all(&b[..n]).is_err() {
                    return;
                }
            }
        }
    }
}

fn echo_udp() -> SocketAddr {
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

fn roundtrip(s: &mut TcpStream, n: usize) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
    let mut w = s.try_clone()?;
    let d2 = data.clone();
    let t = thread::spawn(move || w.write_all(&d2));
    let mut got = vec![0; n];
    s.read_exact(&mut got)?;
    t.join().expect("writer")?;
    if got != data {
        return Err(std::io::Error::other("relayed bytes differ"));
    }
    Ok(())
}

struct Collect {
    got: Vec<u8>,
    done: Option<mpsc::Sender<Vec<u8>>>,
}

impl Handler for Collect {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.got.extend_from_slice(data);
        if self.got.ends_with(b"\n") {
            if let Some(tx) = self.done.take() {
                let _ = tx.send(std::mem::take(&mut self.got));
            }
            c.close();
        }
    }
}

fn collect(
    msg: &'static [u8],
) -> (
    impl akio::Acceptor<Handler = Collect>,
    mpsc::Receiver<Vec<u8>>,
) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let a = akio::fn_acceptor(move |c: &Conn<Collect>| {
        let _ = c.send(msg);
        Collect {
            got: Vec::new(),
            done: Some(tx.lock().unwrap_or_else(|p| p.into_inner()).clone()),
        }
    });
    (a, rx)
}

type Check = Box<dyn FnOnce() -> std::io::Result<()>>;

fn main() {
    let mut args = std::env::args().skip(1);
    let proxy: SocketAddr = args
        .next()
        .expect("PROXY address")
        .parse()
        .expect("PROXY address");
    let mut auth = None;
    let mut socks4 = true;
    let mut socks4a_names = true;
    for a in args {
        if a == "--no-socks4" {
            socks4 = false;
        } else if a == "--no-socks4a-names" {
            socks4a_names = false;
        } else if let Some((u, p)) = a.split_once(':') {
            auth = Some((u.to_owned(), p.to_owned()));
        }
    }
    let tcp = echo_tcp();
    let udp = echo_udp();
    let engine = Arc::new(
        Engine::builder()
            .client_threads(1)
            .udp_client_threads(1)
            .build()
            .expect("engine"),
    );
    engine.start().expect("start");
    let client = |v: Version| {
        let c = SocksClient::new(v, proxy);
        match &auth {
            Some((u, p)) => c.auth(u, p),
            None => c,
        }
    };
    let any: Dest = "0.0.0.0:0".parse::<SocketAddr>().expect("addr").into();
    let mut versions = vec![Version::Socks5];
    if socks4 {
        versions.extend([Version::Socks4, Version::Socks4a]);
    }
    let mut checks: Vec<(String, Check)> = Vec::new();
    for v in versions {
        let c = client(v);
        checks.push((
            format!("{v:?} CONNECT blocking (address, 1 MiB)"),
            Box::new(move || roundtrip(&mut c.dial_blocking(&Dest::Addr(tcp))?, 1 << 20)),
        ));
        let c = client(v);
        if v == Version::Socks4a && !socks4a_names {
            println!("skip  {v:?} CONNECT blocking (name): the server has no SOCKS4a names");
        } else {
            checks.push((
                format!("{v:?} CONNECT blocking (name)"),
                Box::new(move || {
                    roundtrip(
                        &mut c.dial_blocking(&Dest::Name("localhost".into(), tcp.port()))?,
                        1000,
                    )
                }),
            ));
        }
        let (c, e) = (client(v), engine.clone());
        checks.push((
            format!("{v:?} CONNECT on the engine"),
            Box::new(move || {
                let (a, rx) = collect(b"through the engine\n");
                let (etx, erx) = mpsc::channel();
                c.dial(&e, Dest::Addr(tcp), a, move |err| {
                    let _ = etx.send(err);
                });
                match rx.recv_timeout(Duration::from_secs(10)) {
                    Ok(got) if got == b"through the engine\n" => Ok(()),
                    Ok(got) => Err(std::io::Error::other(format!("got {got:?}"))),
                    Err(_) => Err(erx
                        .try_recv()
                        .unwrap_or_else(|_| std::io::Error::other("no answer"))),
                }
            }),
        ));
        let (c, any2) = (client(v), any.clone());
        checks.push((
            format!("{v:?} BIND blocking"),
            Box::new(move || {
                let b = c.bind_blocking(&any2)?;
                let bound = b.bound_addr();
                thread::spawn(move || {
                    if let Ok(p) = TcpStream::connect(bound) {
                        echo_stream(p);
                    }
                });
                let (mut s, _peer) = b.accept()?;
                roundtrip(&mut s, 256 << 10)
            }),
        ));
        let (c, e, any2) = (client(v), engine.clone(), any.clone());
        checks.push((
            format!("{v:?} BIND on the engine"),
            Box::new(move || {
                let (a, rx) = collect(b"bound\n");
                let (etx, erx) = mpsc::channel();
                let on_bound = |bound: SocketAddr| {
                    thread::spawn(move || {
                        if let Ok(p) = TcpStream::connect(bound) {
                            echo_stream(p);
                        }
                    });
                };
                c.bind(&e, any2, on_bound, a, move |err| {
                    let _ = etx.send(err);
                });
                match rx.recv_timeout(Duration::from_secs(10)) {
                    Ok(got) if got == b"bound\n" => Ok(()),
                    Ok(got) => Err(std::io::Error::other(format!("got {got:?}"))),
                    Err(_) => Err(erx
                        .try_recv()
                        .unwrap_or_else(|_| std::io::Error::other("no answer"))),
                }
            }),
        ));
    }
    let c = client(Version::Socks5);
    checks.push((
        "Socks5 UDP ASSOCIATE blocking (1..8000 bytes)".into(),
        Box::new(move || {
            let u = c.udp_associate_blocking()?;
            u.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut b = vec![0u8; 65_536];
            for size in [1usize, 512, 1400, 8000] {
                let payload: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
                u.send_to(&payload, &Dest::Addr(udp))?;
                let (n, from) = u.recv_from(&mut b)?;
                if b[..n] != payload[..] || from != Dest::Addr(udp) {
                    return Err(std::io::Error::other(format!("{size} bytes from {from}")));
                }
            }
            Ok(())
        }),
    ));
    let (c, e) = (client(Version::Socks5), engine.clone());
    checks.push((
        "Socks5 UDP ASSOCIATE on the engine".into(),
        Box::new(move || {
            let (tx, rx) = mpsc::channel();
            let tx = Mutex::new(tx);
            let (dtx, drx) = mpsc::channel();
            c.udp_associate(
                &e,
                move |_a, _from, p| {
                    let _ = tx
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .send(p.to_vec());
                },
                move |r| {
                    let _ = dtx.send(r);
                },
            );
            let a = drx
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| std::io::Error::other("no association"))??;
            a.send_to(b"ping", &Dest::Addr(udp))?;
            let got = rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| std::io::Error::other("no echo"))?;
            a.close();
            if got == b"ping" {
                Ok(())
            } else {
                Err(std::io::Error::other(format!("got {got:?}")))
            }
        }),
    ));
    let mut failed = 0;
    for (name, f) in checks {
        match f() {
            Ok(()) => println!("  ok  {name}"),
            Err(e) => {
                failed += 1;
                println!("FAIL  {name}: {e}");
            }
        }
    }
    engine.shutdown();
    std::process::exit(i32::from(failed > 0));
}
