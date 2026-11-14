//! Compile-time checks of the handler API (ADR-003).
#![allow(dead_code, missing_docs)]

use std::cell::Cell;

use only_core::{Conn, Handler};

fn assert_send_sync<T: Send + Sync>() {}

/// `Cell` makes this handler `Send` but not `Sync`: no lock needed, no `Sync` bound required.
struct Echo {
    seen: Cell<u64>,
}

impl Handler for Echo {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        self.seen.set(self.seen.get() + data.len() as u64);
        let _ = c.send(data);
    }
}

/// Blocking work is offloaded explicitly; `done` gets `&mut Self` on the I/O thread.
struct Db;

impl Handler for Db {
    fn on_data(&mut self, c: &Conn<Self>, data: &[u8]) {
        let req = data.to_vec();
        let _ = c.spawn_blocking(
            move || req.len(),
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
