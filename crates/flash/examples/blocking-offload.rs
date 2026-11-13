//! Blocking work off the I/O thread: `cargo run --release -p flash --example blocking-offload`.
//!
//! The server answers each byte-request after a (simulated) 100 ms database call. The call runs
//! on the logical pool; the reply is written from the completion callback on the I/O thread, and
//! `reserve_response` keeps pipelined replies in request order.

use std::{thread, time::Duration};

use flash::{Conn, Engine, Handler, Listener, fn_acceptor};

struct Server {
    served: u64,
}

impl Handler for Server {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        for &req in data {
            let Ok(slot) = c.reserve_response() else {
                return;
            };
            let _ = c.spawn_blocking(
                move || {
                    thread::sleep(Duration::from_millis(100)); // the "database"
                    format!("result-for-{req}\n").into_bytes()
                },
                move |me: &mut Server, _c, reply| {
                    me.served += 1; // exclusive access to the handler on the I/O thread
                    slot.fill(reply);
                },
            );
        }
    }
}

fn main() -> std::io::Result<()> {
    let addr = "127.0.0.1:7001".parse().expect("address");
    let engine = Engine::builder()
        .listen(Listener::tcp(addr).serve(fn_acceptor(|_c: &Conn<Server>| Server { served: 0 })))
        .build()?;
    println!(
        "try: printf 'abc' | nc 127.0.0.1 7001   (listening on {:?})",
        engine.local_addrs()
    );
    engine.run()
}
