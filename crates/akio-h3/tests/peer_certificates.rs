//! The client's verified certificate chain on each HTTP/3 request (`Request::peer_certificates`,
//! ADR-109), with a QUIC server asking for client certificates; absent without one.

use std::time::Duration;

use akio::{
    Engine, Listener,
    tls::{Certificate, ClientConfig, PrivateKey, RootCerts, ServerConfig},
};
use akio_h3::{H3Client, H3Config};
use akio_http::{Context, Router};
use akio_x509::{CertificateParams, generate_simple_self_signed};

const T: Duration = Duration::from_secs(10);

#[test]
fn h3_requests_carry_the_clients_verified_chain() {
    let (_, ca_key) = generate_simple_self_signed(["ca"]).unwrap();
    let ca = CertificateParams::ca("test ca")
        .self_signed(&ca_key)
        .unwrap();
    let issue = |name: &str| {
        let (throwaway, key) = generate_simple_self_signed(["x"]).unwrap();
        let cert = CertificateParams::new([name])
            .signed_by(&throwaway.public_key().unwrap(), &ca, &ca_key)
            .unwrap();
        (
            vec![Certificate::from_der(cert.as_der().to_vec())],
            PrivateKey::from_pkcs8_der(key.to_pkcs8_der()),
        )
    };
    let mut roots = RootCerts::empty();
    roots
        .add(&Certificate::from_der(ca.as_der().to_vec()))
        .unwrap();
    let (server_chain, server_key) = issue("localhost");
    let (client_chain, client_key) = issue("alice");
    let want = client_chain[0].as_der().to_vec();
    let app = Router::new().get("/who", move |ctx: &mut Context| {
        let body = match &ctx.req().peer_certificates {
            None => "none".to_owned(),
            Some(chain) => format!("certs={} leaf={}", chain.len(), chain[0] == want),
        };
        ctx.text(200, body);
    });
    let tls = ServerConfig::builder(server_chain, server_key)
        .alpn(["h3"])
        .tls13_only(true)
        .client_auth_optional(roots.clone())
        .build()
        .unwrap();
    let quic = akio_quic::server_config_from(&tls).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve_with(
                quic,
                H3Config::default(),
                app,
            )),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let addr = e.local_addrs()[0];
    for (cert, want) in [(true, "certs=1 leaf=true"), (false, "none")] {
        let mut b = ClientConfig::builder()
            .roots(roots.clone())
            .alpn(["h3"])
            .tls13_only(true);
        if cert {
            b = b.client_cert(client_chain.clone(), client_key.clone());
        }
        let cc = akio_quic::client_config_from(&b.build().unwrap()).unwrap();
        let client = H3Client::dial(&e, addr, "localhost", cc).unwrap();
        for _ in 0..2 {
            let r = client.get("/who", T).unwrap();
            assert_eq!(String::from_utf8(r.body).unwrap(), want, "cert={cert}");
        }
    }
    e.shutdown();
    e.wait();
}
