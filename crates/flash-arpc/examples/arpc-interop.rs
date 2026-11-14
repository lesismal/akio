//! The flash side of the Go interop check (tools/interop/arpc/run.sh):
//! `arpc-interop server <addr>` serves what the Go client expects;
//! `arpc-interop client <addr>` calls a Go server and checks the answers.

use std::{sync::Arc, time::Duration};

use flash::{Engine, Listener};
use flash_arpc::{CallError, Routes, Server, StreamEvent, dial_blocking};

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let addr = a[1].parse().expect("address");
    if a[0] == "server" {
        let routes = Routes::new()
            .handle("/echo", |ctx| {
                let b = ctx.body().to_vec();
                ctx.write(&b);
            })
            .handle("/fail", |ctx| ctx.error("rust failed"))
            .handle("/note", |ctx| {
                println!("notify: {}", String::from_utf8_lossy(ctx.body()));
            })
            .handle_stream("/upper", |_s| {
                |s: &flash_arpc::Stream, ev: StreamEvent<'_>| match ev {
                    StreamEvent::Message(m) => {
                        s.send(&m.to_ascii_uppercase());
                    }
                    StreamEvent::Eof => {
                        s.close_send();
                    }
                }
            });
        let e = Engine::builder()
            .listen(Listener::tcp(addr).serve(Server::new(Arc::new(routes))))
            .build()?;
        println!("ready");
        return e.run();
    }
    let e = Arc::new(Engine::builder().client_threads(1).build()?);
    e.start()?;
    let p = dial_blocking(&e, addr, Arc::new(Routes::new()))?;
    let t = Some(Duration::from_secs(5));
    assert_eq!(
        p.call("/echo", b"from rust", t).wait().unwrap(),
        b"from rust"
    );
    assert_eq!(
        p.call("/echo", &vec![b'q'; 1 << 20], t)
            .wait()
            .unwrap()
            .len(),
        1 << 20
    );
    assert_eq!(
        p.call("/fail", b"", t).wait(),
        Err(CallError::Remote("go failed".into()))
    );
    assert_eq!(
        p.call("/missing", b"", t).wait(),
        Err(CallError::Remote("method not found".into()))
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let s = p.new_stream("/upper", move |_s, ev| {
        if let StreamEvent::Message(m) = ev {
            let _ = tx.send(m.to_vec());
        }
    });
    for w in ["one", "two"] {
        s.send(w.as_bytes());
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            w.to_uppercase().as_bytes()
        );
    }
    s.close_send();
    println!("OK");
    Ok(())
}
