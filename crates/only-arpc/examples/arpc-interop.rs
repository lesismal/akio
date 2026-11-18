//! The `only` side of the Go interop check (tools/interop/arpc/run.sh):
//! `arpc-interop server <addr>` serves what the Go client expects;
//! `arpc-interop client <addr>` calls a Go server and checks the answers;
//! `arpc-interop server-coded <addr>` / `client-coded <addr>` do the same with the gzip and
//! trace-value coders, middleware that needs the value, and a pool of connections.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use only::{Engine, Listener};
use only_arpc::{
    CallError, Pool, Routes, Server, StreamEvent, Values,
    coder::{Appender, Coder, CoderError, FLAG_BIT_GZIP, FLAG_BIT_TRACING, Gzip, flag_bit},
    dial_blocking,
};

/// Gzip that counts the compressed frames it inflated.
struct Counting(Gzip, Arc<AtomicUsize>);

impl Coder for Counting {
    fn encode(&self, frame: &mut Vec<u8>, values: &Values) {
        self.0.encode(frame, values);
    }
    fn decode(&self, f: &mut Vec<u8>, v: &mut Values, max: usize) -> Result<(), CoderError> {
        if flag_bit(f, FLAG_BIT_GZIP) {
            self.1.fetch_add(1, Ordering::Relaxed);
        }
        self.0.decode(f, v, max)
    }
}

/// The chain of the Go side: values, then gzip over 256 bytes.
fn coded(r: Routes, inflated: &Arc<AtomicUsize>) -> Routes {
    r.coder(Appender::new("trace", FLAG_BIT_TRACING))
        .coder(Counting(Gzip::new(256), inflated.clone()))
}

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let addr = a[1].parse().expect("address");
    match a[0].as_str() {
        "server-coded" => return serve_coded(addr),
        "client-coded" => return client_coded(addr),
        _ => {}
    }
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
            .handle_stream("/upper", upper());
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

fn upper() -> impl Fn(&only_arpc::Stream) -> fn(&only_arpc::Stream, StreamEvent<'_>) {
    |_s| {
        |s: &only_arpc::Stream, ev: StreamEvent<'_>| match ev {
            StreamEvent::Message(m) => {
                s.send(&m.to_ascii_uppercase());
            }
            StreamEvent::Eof => {
                s.close_send();
            }
        }
    }
}

fn serve_coded(addr: std::net::SocketAddr) -> std::io::Result<()> {
    let inflated = Arc::new(AtomicUsize::new(0));
    let n = inflated.clone();
    let routes = coded(Routes::new(), &inflated)
        .middleware(|ctx, next| {
            // The Go client's appended value, seen before the handler.
            if ctx.values().get("trace").is_none() && !ctx.is_notify() {
                return ctx.error("no trace");
            }
            next.run(ctx);
        })
        .handle("/echo", |ctx| {
            let mut b = ctx.values().get("trace").unwrap_or_default().to_vec();
            b.push(b'|');
            b.extend_from_slice(ctx.body());
            ctx.values_mut().set("trace", "answered by only");
            ctx.write(&b);
        })
        .handle("/gzipped", move |ctx| {
            ctx.write(n.load(Ordering::Relaxed).to_string().as_bytes());
        })
        .handle("/note", |ctx| {
            println!(
                "coded notify: {} bytes, trace {:?}",
                ctx.body().len(),
                ctx.values().get("trace").map(String::from_utf8_lossy)
            );
        })
        .handle_stream("/upper", upper());
    let e = Engine::builder()
        .listen(Listener::tcp(addr).serve(Server::new(Arc::new(routes))))
        .build()?;
    println!("ready");
    e.run()
}

fn client_coded(addr: std::net::SocketAddr) -> std::io::Result<()> {
    let e = Arc::new(Engine::builder().client_threads(1).build()?);
    e.start()?;
    let inflated = Arc::new(AtomicUsize::new(0));
    let pool = Pool::builder()
        .size(3)
        .dial(&e, addr, Arc::new(coded(Routes::new(), &inflated)))?;
    let t = Some(Duration::from_secs(5));
    let v = Values::new().with("trace", "from only");
    let big = vec![b'z'; 1 << 20];
    for _ in 0..6 {
        assert_eq!(
            pool.call_with("/echo", b"x", t, &v).wait().unwrap(),
            b"from only|x"
        );
        let r = pool.call_with("/echo", &big, t, &v).wait().unwrap();
        assert_eq!((&r[..10], &r[10..]), (&b"from only|"[..], &big[..]));
        // The Go side's middleware refuses calls without the value and aborts the chain.
        assert_eq!(
            pool.call("/echo", b"x", t).wait(),
            Err(CallError::Remote("no trace".into()))
        );
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let s = pool.peer().new_stream("/upper", move |_s, ev| {
        if let StreamEvent::Message(m) = ev {
            let _ = tx.send(m.to_vec());
        }
    });
    let w = "one".repeat(200);
    s.send(w.as_bytes());
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        w.to_uppercase().as_bytes()
    );
    s.close_send();
    let go_inflated: usize =
        String::from_utf8(pool.call_with("/gzipped", b"", t, &v).wait().unwrap())
            .unwrap()
            .parse()
            .unwrap();
    let ours = inflated.load(Ordering::Relaxed);
    assert!(go_inflated > 0 && ours > 0, "go {go_inflated} only {ours}");
    println!("OK coded, go inflated {go_inflated}, only inflated {ours}");
    pool.close();
    Ok(())
}
