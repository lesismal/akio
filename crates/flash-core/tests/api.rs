//! Compile-time checks of the M0 API prototype (ADR-003). Nothing here runs the engine.
#![allow(dead_code, missing_docs)]

use std::cell::Cell;

use flash_core::{Backend, Conn, Engine, Handler, Listener, fn_acceptor};

fn assert_send_sync<T: Send + Sync>() {}

/// `Cell` makes this handler `Send` but not `Sync`: no lock needed, no `Sync` bound required.
struct Echo {
    seen: Cell<u64>,
}

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.seen.set(self.seen.get() + data.len() as u64);
        let _ = c.send(data); // non-blocking, inline on the I/O thread
    }
}

/// Blocking work is offloaded explicitly; `done` gets `&mut Self` on the I/O thread.
struct Db;

impl Handler for Db {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let req = data.to_vec();
        let _ = c.spawn_blocking(
            move || req.len(), // runs on the logical pool
            |_me: &mut Db, c, n| {
                let _ = c.send_owned(n.to_string().into_bytes());
            },
        );
    }
}

#[test]
fn conn_is_send_sync_for_any_handler() {
    assert_send_sync::<Conn<Echo>>();
    assert_send_sync::<Conn<Db>>();
}

#[test]
fn builder_api_shape() {
    // Not executed: only checks that the intended configuration type-checks.
    fn _shape() -> flash_core::Result<()> {
        let e = Engine::builder()
            .listen(
                Listener::tcp("0.0.0.0:8080".parse().unwrap())
                    .backend(Backend::Epoll)
                    .serve(fn_acceptor(|_c: &Conn<Echo>| Echo { seen: Cell::new(0) })),
            )
            .listen(
                Listener::tcp("0.0.0.0:9000".parse().unwrap())
                    .serve(fn_acceptor(|_c: &Conn<Db>| Db)),
            )
            .build()?;
        e.run()
    }
}
