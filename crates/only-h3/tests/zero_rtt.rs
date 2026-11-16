//! HTTP/3 over 0-RTT: a resuming client's requests go out before the handshake, the server
//! marks them `Early-Data: 1` (RFC 8470) and the application can answer `425 Too Early`.

use std::time::Duration;

use only::tls::EarlyData;
use only::{Engine, Listener};
use only_h3::H3Client;
use only_http::message::{Headers, Method};
use only_http::{Context, Router};

const T: Duration = Duration::from_secs(10);

#[test]
fn early_requests_are_marked() {
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = only::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let app = Router::new()
        .get("/", |ctx: &mut Context| {
            let early = ctx.header("early-data").unwrap_or("-").to_owned();
            ctx.text(200, format!("early={early}"));
        })
        .post("/pay", |ctx: &mut Context| {
            // Not safe to repeat: refused in 0-RTT (RFC 8470 section 5.2).
            if ctx.header("early-data") == Some("1") {
                ctx.text(425, "too early");
            } else {
                ctx.text(200, "paid");
            }
        });
    let quic = only_h3::server_config(vec![cert], key)
        .unwrap()
        .zero_rtt(true);
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(only_h3::serve(quic, app)))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    let cc = only_quic::client_config_insecure(&[b"h3"])
        .unwrap()
        .zero_rtt(true);
    // First connection: a full handshake, nothing early.
    let c = H3Client::dial(&e, addr, "localhost", cc.clone()).unwrap();
    assert_eq!(c.get("/", T).unwrap().body, b"early=-");
    std::thread::sleep(Duration::from_millis(200));
    c.close();
    // Resumed: the GET goes in 0-RTT and is marked; the POST is refused with 425.
    let c = H3Client::dial(&e, addr, "localhost", cc.clone()).unwrap();
    let r = c.get("/", T).unwrap();
    assert_eq!(r.body, b"early=1");
    assert_eq!(c.connection().early_data(), EarlyData::Accepted);
    c.close();
    std::thread::sleep(Duration::from_millis(100));
    let c = H3Client::dial(&e, addr, "localhost", cc).unwrap();
    let r = c
        .request_blocking(Method::Post, "/pay", &Headers::new(), b"1".to_vec(), T)
        .unwrap();
    assert_eq!(r.status, 425);
    // After the handshake the same request goes through.
    let r = c
        .request_blocking(Method::Post, "/pay", &Headers::new(), b"1".to_vec(), T)
        .unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"paid"[..]));
    c.close();
}
