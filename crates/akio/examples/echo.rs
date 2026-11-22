//! TCP echo server: `cargo run --release -p akio --example echo -- 127.0.0.1:7000 [threads] [uring]`

use akio::{Backend, Conn, Engine, Handler, Listener, fn_acceptor};

struct Echo;

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let _ = c.send(data); // non-blocking, inline on the I/O thread
    }
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let addr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:7000".into())
        .parse()
        .expect("address");
    let mut l = Listener::tcp(addr).serve(fn_acceptor(|_c: &Conn<Echo>| Echo));
    if let Some(n) = args.next() {
        l = l.threads(n.parse().expect("threads"));
    }
    if args.next().as_deref() == Some("uring") {
        l = l.backend(Backend::IoUring(Default::default()));
    }
    let engine = Engine::builder().listen(l).build()?;
    println!("echo listening on {:?}", engine.local_addrs());
    engine.run()
}
