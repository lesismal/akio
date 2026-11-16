//! A SOCKS5/4/4a server with BIND and UDP ASSOCIATE enabled, for `tools/interop/socks/run.sh`
//! (curl, PySocks and hand-written clients against it; Dante as the reference server).
//!
//! `cargo run -p only-socks --example socks-interop -- 127.0.0.1:1080 [user:pass]`

use std::{net::SocketAddr, sync::Arc, time::Duration};

use only::{Engine, EngineRef, Listener};
use only_socks::Socks;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:1080".into())
        .parse()
        .expect("listen address");
    let er = EngineRef::new();
    let mut socks = Socks::new(er.clone())
        .bind(true)
        .bind_timeout(Duration::from_secs(10))
        .udp_associate(true)
        .udp_idle_timeout(Duration::from_secs(30));
    if let Some(cred) = args.next() {
        let (u, p) = cred.split_once(':').expect("user:pass");
        let (u, p) = (u.to_owned(), p.to_owned());
        socks = socks.auth(move |a, b| a == u && b == p);
    }
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
