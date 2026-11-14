//! The `only` side of the grpc-go interop check (tools/interop/grpc/run.sh):
//! `grpc-interop server <addr> [tls]` / `grpc-interop client <addr> [tls]` (`tls`: HTTP/2 over
//! only-tls with ALPN `h2`, a self-signed certificate, the client skipping verification).

use std::{sync::Arc, time::Duration};

use only::{Engine, Listener};
use only_grpc::{CallOptions, Code, GrpcClient, GrpcServer, Status};
use only_http::h2client::{H2Client, H2Options};

fn main() -> std::io::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let addr = a[1].parse().expect("address");
    let tls = a.get(2).is_some_and(|t| t == "tls");
    if a[0] == "server" {
        // Responses are gzip-compressed for clients that accept it (grpc-go does once its
        // gzip compressor is registered).
        let s = GrpcServer::new()
            .compress(true)
            .unary("/test.Echo/Unary", |md, req, sink| {
                if let Some(u) = md.get("x-user") {
                    println!("metadata x-user={u}");
                }
                sink.send(&req);
                sink.finish(Status::ok());
            })
            .unary("/test.Echo/Fail", |_md, _r, sink| {
                sink.finish(Status::new(Code::InvalidArgument, "only says no"));
            })
            .server_stream("/test.Echo/Count", |_md, req, sink| {
                let n: usize = String::from_utf8_lossy(&req).parse().unwrap_or(0);
                for i in 0..n {
                    sink.send(i.to_string().as_bytes());
                }
                sink.finish(Status::ok());
            })
            .bidi("/test.Echo/Chat", |_md, sink| {
                Box::new(move |m| match m {
                    Some(m) => {
                        sink.send(&[b"re:".as_slice(), &m].concat());
                    }
                    None => sink.finish(Status::ok()),
                })
            });
        let l = Listener::tcp(addr);
        let l = if tls {
            let (cert, key) = only_x509::generate_simple_self_signed(["localhost"]).expect("cert");
            let cfg = only::tls::ServerConfig::builder(
                vec![only::tls::Certificate::from_der(cert.as_der().to_vec())],
                only::tls::PrivateKey::from_pkcs8_der(key.to_pkcs8_der()),
            )
            .alpn(["h2"])
            .build()
            .expect("tls config");
            l.serve(only::tls::Tls::server(cfg, only_http::serve(s)))
        } else {
            l.serve(only_http::serve(s))
        };
        let e = Engine::builder().listen(l).build()?;
        println!("ready");
        return e.run();
    }
    let e = Arc::new(Engine::builder().client_threads(1).build()?);
    e.start()?;
    let tls_cfg = tls.then(|| {
        only::tls::ClientConfig::builder()
            .insecure_skip_verify()
            .alpn(["h2"])
            .build()
            .expect("tls config")
    });
    let dial = || {
        H2Client::dial_blocking(
            &e,
            addr,
            tls_cfg.clone().map(|c| (c, "localhost")),
            H2Options::default(),
        )
    };
    let scheme = if tls { "https" } else { "http" };
    let h2 = dial()?;
    let c = GrpcClient::new(h2, &format!("{scheme}://{addr}"));
    let o = || {
        let mut v = CallOptions::default();
        v.timeout = Some(Duration::from_secs(10));
        v
    };
    assert_eq!(
        c.unary("/test.Echo/Unary", b"from rust", o()).unwrap(),
        b"from rust"
    );
    let big = vec![7u8; 3 << 20];
    assert_eq!(
        c.unary("/test.Echo/Unary", &big, o()).unwrap().len(),
        big.len()
    );
    let err = c.unary("/test.Echo/Unary", b"fail", o()).unwrap_err();
    assert_eq!(
        (err.code, err.message.as_str()),
        (Code::InvalidArgument, "go says no")
    );
    assert_eq!(
        c.unary("/test.Echo/Nope", b"x", o()).unwrap_err().code,
        Code::Unimplemented
    );
    let (msgs, st) = c.collect("/test.Echo/Count", vec![b"50".to_vec()], o());
    assert_eq!((st.code, msgs.len()), (Code::Ok, 50));
    let (msgs, st) = c.collect("/test.Echo/Chat", vec![b"x".to_vec(), b"y".to_vec()], o());
    assert_eq!(st.code, Code::Ok);
    assert_eq!(msgs, [b"re:x".to_vec(), b"re:y".to_vec()]);
    // gzip both ways: only compresses the requests, grpc-go answers in kind.
    let h2z = dial()?;
    let cz = GrpcClient::new(h2z, &format!("{scheme}://{addr}")).compress(true);
    let text = b"gzip me, grpc-go! ".repeat(50_000);
    assert_eq!(cz.unary("/test.Echo/Unary", &text, o()).unwrap(), text);
    let (msgs, st) = cz.collect("/test.Echo/Chat", vec![b"zz".to_vec(), text.clone()], o());
    assert_eq!(st.code, Code::Ok);
    assert_eq!(
        msgs,
        [b"re:zz".to_vec(), [b"re:".as_slice(), &text].concat()]
    );
    println!("gzip OK");
    println!("OK");
    Ok(())
}
