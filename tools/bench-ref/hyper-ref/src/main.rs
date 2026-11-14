//! hyper reference server: `hyper-ref <addr> <threads>`
//!
//! Same routes as flash's `http-bench`: `GET /plaintext` and `GET /json`. HTTP/1.1 and HTTP/2
//! (prior knowledge, h2c) on one port via `hyper_util::server::conn::auto`.

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, header, service::service_fn, Request, Response, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::net::TcpListener;

#[derive(serde::Serialize)]
struct Message {
    message: &'static str,
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let r = match req.uri().path() {
        "/plaintext" => Response::builder()
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"Hello, World!"))),
        "/json" => {
            let body = serde_json::to_vec(&Message {
                message: "Hello, World!",
            })
            .unwrap();
            Response::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body)))
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new())),
    };
    Ok(r.unwrap())
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let addr = a.first().cloned().unwrap_or_else(|| "127.0.0.1:8080".into());
    let threads: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let l = TcpListener::bind(&addr).await.unwrap();
        println!("listening on {addr}");
        loop {
            let (s, _) = l.accept().await.unwrap();
            s.set_nodelay(true).ok();
            tokio::spawn(async move {
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(s), service_fn(handle))
                    .await;
            });
        }
    });
}
