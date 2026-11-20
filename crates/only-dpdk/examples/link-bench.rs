//! The userspace stack over a real link (AF_PACKET or AF_XDP on one end of a veth pair) against
//! kernel clients on the other end: UDP and TCP request/response rates, TCP connection rate
//! and TCP echo throughput. `tools/bench/afxdp.sh` runs both links alternately on the same
//! veth pair (ADR-063). Linux, privileged.
//!
//! ```text
//! link-bench serve <af_packet|af_xdp|af_xdp_generic> <iface> <ip>   # until stdin closes
//! link-bench client <ip> <secs> <threads>                            # prints one result line
//! ```
#![allow(missing_docs)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("link-bench is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("serve") if args.len() == 4 => linux::serve(&args[1], &args[2], &args[3]),
        Some("client") if args.len() == 4 => linux::client(
            &args[1],
            args[2].parse().expect("secs"),
            args[3].parse().expect("threads"),
        ),
        _ => {
            eprintln!(
                "usage: link-bench serve <af_packet|af_xdp|af_xdp_generic> <iface> <ip> | \
                 client <ip> <secs> <threads>"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("link-bench: {e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        io::{self, BufRead, Read, Write},
        net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::{Duration, Instant},
    };

    use only::{
        Backend, Config, Conn, Engine, Handler, Listener,
        dpdk::{AfXdpConfig, Device, DpdkConfig, XdpMode},
        fn_acceptor,
    };

    struct Echo;
    impl Handler for Echo {
        fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
            let _ = c.send(data);
        }
    }

    pub(super) fn serve(link: &str, iface: &str, ip: &str) -> io::Result<()> {
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let device = match link {
            "af_packet" => Device::AfPacket(iface.to_owned()),
            "af_xdp" | "af_xdp_generic" => {
                let mut c = AfXdpConfig::new(iface);
                if link == "af_xdp_generic" {
                    c.mode = XdpMode::Generic;
                }
                Device::AfXdp(c)
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown link {other}"),
                ));
            }
        };
        let mut d = DpdkConfig::new(device, ip);
        d.tcp_buffer = 1 << 20;
        let backend = Backend::Dpdk(d);
        let mut cfg = Config::default();
        cfg.shutdown_timeout = Duration::from_millis(500);
        let engine = Engine::builder()
            .config(cfg)
            .listen(
                Listener::udp(SocketAddr::from((ip, 7000)))
                    .backend(backend.clone())
                    .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
            )
            .listen(
                Listener::tcp(SocketAddr::from((ip, 7001)))
                    .backend(backend)
                    .serve(fn_acceptor(|_c: &Conn<Echo>| Echo)),
            )
            .build()?;
        engine.start()?;
        if link.starts_with("af_xdp") {
            eprintln!("{iface}: {:?}", only::dpdk::af_xdp_info(iface));
        }
        println!("ready");
        io::stdout().flush()?;
        // Serve until stdin closes.
        let mut line = String::new();
        while io::stdin().lock().read_line(&mut line)? > 0 {
            line.clear();
        }
        engine.shutdown();
        engine.wait();
        Ok(())
    }

    /// Runs `f` on `threads` threads for `secs` seconds; operations per second in total.
    fn rate(
        threads: usize,
        secs: f64,
        f: impl Fn(usize, &AtomicBool) -> io::Result<u64> + Send + Sync + 'static,
    ) -> io::Result<f64> {
        let stop = Arc::new(AtomicBool::new(false));
        let total = Arc::new(AtomicU64::new(0));
        let f = Arc::new(f);
        let t0 = Instant::now();
        let hs: Vec<_> = (0..threads)
            .map(|i| {
                let (stop, total, f) = (stop.clone(), total.clone(), f.clone());
                std::thread::spawn(move || {
                    let n = f(i, &stop)?;
                    total.fetch_add(n, Ordering::Relaxed);
                    Ok::<(), io::Error>(())
                })
            })
            .collect();
        std::thread::sleep(Duration::from_secs_f64(secs));
        stop.store(true, Ordering::Relaxed);
        for h in hs {
            h.join()
                .map_err(|_| io::Error::other("bench thread panicked"))??;
        }
        Ok(total.load(Ordering::Relaxed) as f64 / t0.elapsed().as_secs_f64())
    }

    pub(super) fn client(ip: &str, secs: f64, threads: usize) -> io::Result<()> {
        let ip: Ipv4Addr = ip
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let udp = SocketAddr::from((ip, 7000));
        let tcp = SocketAddr::from((ip, 7001));
        // Warm up: ARP both ways and the first handshake.
        {
            let u = UdpSocket::bind("0.0.0.0:0")?;
            u.set_read_timeout(Some(Duration::from_millis(200)))?;
            let mut b = [0u8; 64];
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                u.send_to(b"warm", udp)?;
                if u.recv(&mut b).is_ok() {
                    break;
                }
                if Instant::now() > deadline {
                    return Err(io::Error::other("no UDP echo"));
                }
            }
        }
        let udp_rr = rate(threads, secs, move |_, stop| {
            let u = UdpSocket::bind("0.0.0.0:0")?;
            u.connect(udp)?;
            u.set_read_timeout(Some(Duration::from_millis(100)))?;
            let msg = [7u8; 64];
            let mut b = [0u8; 2048];
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                u.send(&msg)?;
                // A lost datagram is a timeout, not an error.
                if matches!(u.recv(&mut b), Ok(64)) {
                    n += 1;
                }
            }
            Ok(n)
        })?;
        let tcp_rr = rate(threads, secs, move |_, stop| {
            let mut s = TcpStream::connect_timeout(&tcp, Duration::from_secs(5))?;
            s.set_nodelay(true)?;
            s.set_read_timeout(Some(Duration::from_secs(5)))?;
            let msg = [9u8; 64];
            let mut b = [0u8; 64];
            let mut n = 0;
            while !stop.load(Ordering::Relaxed) {
                s.write_all(&msg)?;
                s.read_exact(&mut b)?;
                n += 1;
            }
            Ok(n)
        })?;
        let tcp_cps = rate(threads, secs, move |_, stop| {
            let mut n = 0;
            let mut b = [0u8; 8];
            while !stop.load(Ordering::Relaxed) {
                let mut s = TcpStream::connect_timeout(&tcp, Duration::from_secs(5))?;
                s.set_read_timeout(Some(Duration::from_secs(5)))?;
                s.write_all(b"8 bytes!")?;
                s.read_exact(&mut b)?;
                n += 1;
            }
            Ok(n)
        })?;
        // One connection, written and read concurrently.
        let tcp_bulk = {
            let mut s = TcpStream::connect_timeout(&tcp, Duration::from_secs(5))?;
            s.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut w = s.try_clone()?;
            let stop = Arc::new(AtomicBool::new(false));
            let st = stop.clone();
            let writer = std::thread::spawn(move || {
                let chunk = vec![5u8; 64 << 10];
                let mut sent = 0u64;
                while !st.load(Ordering::Relaxed) {
                    if w.write_all(&chunk).is_err() {
                        break;
                    }
                    sent += chunk.len() as u64;
                }
                let _ = w.shutdown(std::net::Shutdown::Write);
                sent
            });
            let t0 = Instant::now();
            let mut got = 0u64;
            let mut b = vec![0u8; 256 << 10];
            let deadline = t0 + Duration::from_secs_f64(secs);
            let mut measured = None;
            loop {
                if measured.is_none() && Instant::now() >= deadline {
                    measured = Some((got, t0.elapsed()));
                    stop.store(true, Ordering::Relaxed);
                }
                match s.read(&mut b) {
                    Ok(0) => break,
                    Ok(k) => got += k as u64,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            let sent = writer
                .join()
                .map_err(|_| io::Error::other("writer panicked"))?;
            if got != sent {
                return Err(io::Error::other(format!("echoed {got} of {sent} bytes")));
            }
            let (bytes, took) = measured.unwrap_or_else(|| (got, t0.elapsed()));
            bytes as f64 / took.as_secs_f64() / 1e6
        };
        println!(
            "udp_rr={udp_rr:.0} tcp_rr={tcp_rr:.0} tcp_cps={tcp_cps:.0} tcp_mbps={tcp_bulk:.1}"
        );
        Ok(())
    }
}
