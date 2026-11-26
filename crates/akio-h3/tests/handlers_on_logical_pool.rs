//! `H3Config::handlers_on_logical_pool`: the requests of one connection served at the same time
//! on the logical pool.
#![allow(missing_docs)]

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use akio::{Engine, Listener};
use akio_h3::{H3Client, H3Config};
use akio_http::{Context, Router};

const T: Duration = Duration::from_secs(10);

fn setup(on: bool) -> (Arc<Engine>, H3Client) {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = akio::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = akio::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let app = Router::new().get("/block/:ms", |ctx: &mut Context| {
        // Blocks where it runs: only fine on the pool.
        let ms: u64 = ctx.param("ms").unwrap().parse().unwrap();
        thread::sleep(Duration::from_millis(ms));
        let pooled = thread::current().name() == Some("akio-pool");
        ctx.text(200, format!("{ms} pool={pooled}"));
    });
    let mut cfg = H3Config::default();
    cfg.handlers_on_logical_pool = on;
    let quic = akio_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(akio_h3::serve_with(quic, cfg, app)),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = akio_quic::client_config_insecure(&[b"h3"]).unwrap();
    let client = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    (Arc::new(e), client)
}

#[test]
fn requests_of_one_connection_run_at_once_on_the_pool() {
    for on in [true, false] {
        let (e, c) = setup(on);
        let t = Instant::now();
        let calls: Vec<_> = (0..8)
            .map(|_| {
                let c = c.clone();
                thread::spawn(move || c.get("/block/150", T).unwrap())
            })
            .collect();
        for h in calls {
            let r = h.join().unwrap();
            assert_eq!(r.status, 200);
            assert_eq!(r.body, format!("150 pool={on}").into_bytes());
        }
        let took = t.elapsed();
        if on {
            // On the I/O thread they take 8 x 150 ms.
            assert!(took < Duration::from_millis(800), "took {took:?}");
        } else {
            assert!(took >= Duration::from_millis(1200), "took {took:?}");
        }
        e.shutdown();
        e.wait();
    }
}
