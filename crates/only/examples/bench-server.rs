//! Server for the benchmarks (see docs/BENCHMARKS.md):
//!
//! `bench-server <tcp|tls|udp|udp-dgram> <addr> <threads> <epoll|uring> [echo|block-inline|block-pool [ms]]`
//!
//! `udp` serves one connection per peer (`Listener::udp(..).serve`); `udp-dgram` echoes with a
//! connectionless `DatagramsHandler` (`serve_datagrams`, ADR-065) and only takes `echo`.
//!
//! * `echo`: reply with what was received.
//! * `block-inline`: sleep `ms` (default 5) inside `on_data`, then reply. This is the mistake
//!   `only` is designed to make visible: it blocks the I/O thread.
//! * `block-pool`: do the same sleep on the logical pool with `spawn_blocking` and reply from
//!   the completion callback.
//!
//! `ONLY_ACCEL=cpu|cpu-pin|hash` attaches `SO_REUSEPORT` steering (`Accel::Ebpf`; `cpu-pin` also
//! pins I/O thread `i` to the CPUs `c % threads == i`), for the eBPF benchmark.
//!
//! `ONLY_KTLS=off|hardware|software|software-tx` sets `tls`'s kernel TLS mode (`Ktls`; takes
//! effect with the `ktls` feature on Linux), for the kernel TLS benchmark.

use std::{thread, time::Duration};

use only::{
    Accel, Acceptor, Backend, Conn, DatagramSender, Datagrams, DatagramsHandler, EbpfConfig,
    Engine, Handler, Listener, PoolConfig, Replies, ebpf, fn_acceptor,
    tls::{Certificate, PrivateKey, ServerConfig, Tls},
};

/// `ONLY_KTLS`, see the module documentation.
fn ktls_mode() -> only::tls::Ktls {
    match std::env::var("ONLY_KTLS").as_deref() {
        Ok("hardware") => only::tls::Ktls::Hardware,
        Ok("software") => only::tls::Ktls::Software,
        Ok("software-tx") => only::tls::Ktls::SoftwareTx,
        _ => only::tls::Ktls::Off,
    }
}

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
    }
}

/// Connectionless echo: every datagram of a batch back to its sender.
struct DgramEcho;
impl DatagramsHandler for DgramEcho {
    fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies) {
        for (peer, data) in batch {
            let _ = out.send_to(data, peer);
        }
    }
}

struct Inline(Duration);
impl Handler for Inline {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        thread::sleep(self.0);
        let _ = c.send(data);
    }
}

struct Pooled(Duration);
impl Handler for Pooled {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let (d, req) = (self.0, data.to_vec());
        let _ = c.spawn_blocking(
            move || {
                thread::sleep(d);
                req
            },
            |_me: &mut Pooled, c, req| {
                let _ = c.send_owned(req);
            },
        );
    }
}

fn serve<A: Acceptor>(
    l: Listener,
    a: A,
    tls: Option<ServerConfig>,
    pool_threads: usize,
) -> std::io::Result<()> {
    let l = match tls {
        Some(cfg) => l.serve(Tls::server(cfg, a)),
        None => l.serve(a),
    };
    let engine = Engine::builder()
        .pool({
            let mut v = PoolConfig::default();
            v.max_threads = pool_threads;
            v
        })
        .listen(l)
        .build()?;
    println!("listening on {:?}", engine.local_addrs());
    for s in engine.accel_status() {
        eprintln!("accel: {s:?}");
    }
    engine.run()
}

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 4 {
        eprintln!(
            "usage: bench-server <tcp|tls|udp|udp-dgram> <addr> <threads> <epoll|uring> [echo|block-inline|block-pool [ms]]"
        );
        std::process::exit(2);
    }
    let addr = a[1].parse().expect("address");
    let threads: usize = a[2].parse().expect("threads");
    let backend = match a[3].as_str() {
        "uring" => Backend::IoUring(Default::default()),
        _ => Backend::Epoll,
    };
    let ms: u64 = a.get(5).and_then(|s| s.parse().ok()).unwrap_or(5);
    let d = Duration::from_millis(ms);

    let tls = (a[0] == "tls")
        .then(|| {
            let ck = only_x509::generate_simple_self_signed(["localhost"])
                .map_err(std::io::Error::other)?;
            ServerConfig::builder(
                vec![Certificate::from_der(ck.0.as_der().to_vec())],
                PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der()),
            )
            .ktls(ktls_mode())
            .build()
            .map_err(std::io::Error::from)
        })
        .transpose()?;
    let l = if a[0] == "udp" {
        Listener::udp(addr)
    } else if a[0] == "udp-dgram" {
        Listener::udp(addr).backend(backend)
    } else {
        Listener::tcp(addr).backend(backend)
    }
    .threads(threads);
    let l = match std::env::var("ONLY_ACCEL").as_deref() {
        Ok(mode @ ("cpu" | "cpu-pin" | "hash")) => l.accel(Accel::Ebpf({
            let mut v = EbpfConfig::default();
            v.steering = if mode == "hash" {
                ebpf::Steering::Hash(ebpf::HashKey::SrcIpPort)
            } else {
                ebpf::Steering::Cpu
            };
            v.pin_threads = mode == "cpu-pin";
            v.strict = true;
            v
        })),
        _ => l,
    };

    if a[0] == "udp-dgram" {
        let engine = Engine::builder()
            .listen(l.serve_datagrams(|_: &DatagramSender| DgramEcho))
            .build()?;
        println!("listening on {:?}", engine.local_addrs());
        return engine.run();
    }
    match a.get(4).map_or("echo", String::as_str) {
        "echo" => serve(l, fn_acceptor(|_c: &Conn<Echo>| Echo), tls, 64),
        "block-inline" => serve(l, fn_acceptor(move |_c: &Conn<Inline>| Inline(d)), tls, 64),
        "block-pool" => serve(
            l,
            fn_acceptor(move |_c: &Conn<Pooled>| Pooled(d)),
            tls,
            4096,
        ),
        other => {
            eprintln!("unknown handler {other}");
            std::process::exit(2)
        }
    }
}
