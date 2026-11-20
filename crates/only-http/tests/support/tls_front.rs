//! TLS in front of a plain TCP server (the test proxy), so that the clients see an `https://`
//! proxy: each TLS connection is relayed to `to` over its own TCP connection.
#![allow(dead_code)]

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

use only::{Conn, Engine, Handler, Listener, fn_acceptor, tls::Tls};

pub(crate) struct Front {
    up: TcpStream,
}

impl Handler for Front {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        // Loopback, small test traffic: a blocking write is fine here.
        let _ = self.up.write_all(data);
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<only::Error>) {
        let _ = self.up.shutdown(Shutdown::Both);
    }
}

/// Serves TLS with `cfg` on 127.0.0.1 and relays the plaintext to `to`; also returns how many
/// connections it took.
pub(crate) fn start(
    cfg: only::tls::ServerConfig,
    to: SocketAddr,
) -> (Arc<Engine>, SocketAddr, Arc<AtomicUsize>) {
    let opened = Arc::new(AtomicUsize::new(0));
    let o2 = opened.clone();
    let acceptor = fn_acceptor(move |c: &Conn<Front>| {
        o2.fetch_add(1, Ordering::SeqCst);
        let up = TcpStream::connect(to).expect("upstream");
        let mut down = up.try_clone().expect("clone");
        let c = c.clone();
        thread::spawn(move || {
            let mut b = [0u8; 16384];
            loop {
                match down.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if c.send(&b[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            c.close();
        });
        Front { up }
    });
    let e = Arc::new(
        Engine::builder()
            .config({
                let mut v = only::Config::default();
                v.shutdown_timeout = std::time::Duration::from_millis(300);
                v
            })
            .listen(
                Listener::tcp("127.0.0.1:0".parse().unwrap())
                    .threads(1)
                    .serve(Tls::server(cfg, acceptor)),
            )
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    (e, addr, opened)
}
