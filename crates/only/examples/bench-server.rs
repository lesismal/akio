//! Server for the benchmarks (see docs/BENCHMARKS.md):
//!
//! `bench-server <tcp|tls|udp> <addr> <threads> <epoll|uring> [echo|block-inline|block-pool [ms]]`
//!
//! * `echo`: reply with what was received.
//! * `block-inline`: sleep `ms` (default 5) inside `on_data`, then reply. This is the mistake
//!   `only` is designed to make visible: it blocks the I/O thread.
//! * `block-pool`: do the same sleep on the logical pool with `spawn_blocking` and reply from
//!   the completion callback.

use std::{thread, time::Duration};

use only::{
    Acceptor, Backend, Conn, Engine, Handler, Listener, PoolConfig, fn_acceptor,
    tls::{Certificate, PrivateKey, ServerConfig, Tls},
};

struct Echo;
impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data);
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
    engine.run()
}

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 4 {
        eprintln!(
            "usage: bench-server <tcp|tls|udp> <addr> <threads> <epoll|uring> [echo|block-inline|block-pool [ms]]"
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
            .build()
            .map_err(std::io::Error::from)
        })
        .transpose()?;
    let l = if a[0] == "udp" {
        Listener::udp(addr)
    } else {
        Listener::tcp(addr).backend(backend)
    }
    .threads(threads);

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
