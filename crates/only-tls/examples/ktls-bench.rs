//! Kernel TLS against only-tls's own record layer (Linux): a thread-per-connection HTTP/1.1
//! server over TLS whose record layer is either user space (`user`) or the kernel (`ktls`),
//! for `h2load --h1` (docs/BENCHMARKS.md, kTLS section).
//!
//! ```text
//! ktls-bench <addr> user|ktls [--file PATH] [--tls12] [--suite 0x1301]
//! ```
//!
//! `GET /<n>` answers `n` bytes from memory; `GET /file` answers the file: `ktls` sends it with
//! `sendfile(2)` (the kernel encrypts from the page cache), `user` reads it in 64 KiB chunks and
//! seals them. The handshake is only-tls in both modes (a self-signed ECDSA P-256 certificate,
//! session tickets off). At exit (SIGTERM is not caught: read the counters from `/proc`) nothing
//! is printed; per-connection setup time of the offload is printed every 4096 connections.
#![allow(missing_docs)]

#[cfg(target_os = "linux")]
fn main() {
    imp::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ktls-bench needs Linux");
}

#[cfg(target_os = "linux")]
mod imp {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    use only_tls::stream::Stream;
    use only_tls::{Certificate, PrivateKey, ServerConfig};

    static OFFLOADS: AtomicU64 = AtomicU64::new(0);
    static OFFLOAD_NS: AtomicU64 = AtomicU64::new(0);
    static FALLBACKS: AtomicU64 = AtomicU64::new(0);

    struct Opts {
        ktls: bool,
        file: Option<Arc<File>>,
        cfg: ServerConfig,
    }

    pub(super) fn main() {
        let args: Vec<String> = std::env::args().collect();
        if args.len() < 3 {
            eprintln!(
                "usage: ktls-bench <addr> user|ktls [--file PATH] [--tls12] [--suite 0xNNNN]"
            );
            std::process::exit(2);
        }
        let mut file = None;
        let mut tls12 = false;
        let mut suites = Vec::new();
        let mut i = 3;
        while i < args.len() {
            match args[i].as_str() {
                "--file" => {
                    i += 1;
                    file = Some(Arc::new(File::open(&args[i]).expect("file")));
                }
                "--tls12" => tls12 = true,
                "--suite" => {
                    i += 1;
                    let s = args[i].trim_start_matches("0x");
                    suites.push(u16::from_str_radix(s, 16).expect("suite"));
                }
                a => panic!("unknown option {a}"),
            }
            i += 1;
        }
        let (c, k) = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
        let mut b = ServerConfig::builder(
            vec![Certificate::from_der(c.as_der().to_vec())],
            PrivateKey::from_pkcs8_der(k.to_pkcs8_der()),
        )
        .session_tickets(false)
        .__tls12_only(tls12);
        if !suites.is_empty() {
            b = b.__suites(&suites);
        }
        let o = Arc::new(Opts {
            ktls: args[2] == "ktls",
            file,
            cfg: b.build().expect("config"),
        });
        let l = TcpListener::bind(&args[1]).expect("bind");
        eprintln!("listening {} ({})", l.local_addr().expect("addr"), args[2]);
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            let o = o.clone();
            std::thread::spawn(move || {
                let _ = serve(&o, s);
            });
        }
    }

    fn serve(o: &Opts, tcp: TcpStream) -> std::io::Result<()> {
        tcp.set_nodelay(true)?;
        let mut s = Stream::server(&o.cfg, tcp);
        if o.ktls {
            s.want_ktls();
        }
        s.handshake()?;
        if o.ktls {
            let t = Instant::now();
            if s.offload()? {
                OFFLOAD_NS.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
                let n = OFFLOADS.fetch_add(1, Ordering::Relaxed) + 1;
                if n.is_power_of_two() || n % 4096 == 0 {
                    eprintln!(
                        "offloads {n} ({}, {}), avg {} ns, fallbacks {}",
                        s.conn().version_name().unwrap_or("?"),
                        s.conn().suite().map_or("?", |s| s.name),
                        OFFLOAD_NS.load(Ordering::Relaxed) / n,
                        FALLBACKS.load(Ordering::Relaxed)
                    );
                }
            } else {
                FALLBACKS.fetch_add(1, Ordering::Relaxed);
            }
        }
        let mut bodies: HashMap<usize, Vec<u8>> = HashMap::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut req = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let n = s.read(&mut buf)?;
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
            while let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                let path = req
                    .split(|&b| b == b' ')
                    .nth(1)
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .unwrap_or_default();
                req.drain(..end + 4);
                if path == "/file" {
                    let Some(f) = &o.file else { return Ok(()) };
                    let len = f.metadata()?.len();
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
                    if s.offloaded() {
                        s.write_all(head.as_bytes())?;
                        let fd = s.get_ref().as_raw_fd();
                        let mut off = 0u64;
                        while off < len {
                            let n = only_sys::sendfile(
                                fd,
                                f.as_raw_fd(),
                                off,
                                (len - off).min(1 << 30) as usize,
                            )?;
                            if n == 0 {
                                return Ok(());
                            }
                            off += n as u64;
                        }
                    } else {
                        s.write_all(head.as_bytes())?;
                        let mut off = 0u64;
                        while off < len {
                            let want = (len - off).min(chunk.len() as u64) as usize;
                            let n = f.read_at(&mut chunk[..want], off)?;
                            if n == 0 {
                                return Ok(());
                            }
                            s.write_all(&chunk[..n])?;
                            off += n as u64;
                        }
                    }
                    continue;
                }
                let size: usize = path.trim_start_matches('/').parse().unwrap_or(13);
                let resp = bodies.entry(size).or_insert_with(|| {
                    let mut r =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").into_bytes();
                    r.resize(r.len() + size, b'x');
                    r
                });
                s.write_all(resp)?;
            }
        }
        let _ = s.close();
        Ok(())
    }
}
