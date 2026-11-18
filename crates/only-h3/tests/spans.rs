//! Request and connection spans over HTTP/3 (only-log spans, `only_http::trace`).

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use only::{
    Engine, Listener,
    log::{
        LevelFilter,
        span::{self, FieldValue, SpanData, Tracer},
    },
};
use only_h3::{H3Client, H3Config};
use only_http::{Context, Router};

const T: Duration = Duration::from_secs(10);

struct Capture(Mutex<Vec<SpanData>>);

impl Tracer for Capture {
    fn on_end(&self, span: SpanData) {
        self.0.lock().unwrap().push(span);
    }
}

static CAP: Capture = Capture(Mutex::new(Vec::new()));

#[test]
fn h3_request_and_connection_spans() {
    span::set_tracer(&CAP).unwrap();
    span::set_max_span_level(LevelFilter::Debug);
    let ck = only_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = only::tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = only::tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
    let app = Router::new().get("/user/:id", |ctx: &mut Context| ctx.text(200, "u"));
    let quic = only_h3::server_config(vec![cert], key).unwrap();
    let e = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap()).serve(only_h3::serve_with(
                quic,
                H3Config::default(),
                app,
            )),
        )
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let cc = only_quic::client_config_insecure(&[b"h3"]).unwrap();
    let c = H3Client::dial(&e, e.local_addrs()[0], "localhost", cc).unwrap();
    assert_eq!(c.get("/user/1", T).unwrap().status, 200);
    c.close();
    let t0 = Instant::now();
    let done = || {
        let v = CAP.0.lock().unwrap();
        v.iter().any(|s| s.target == "only_http::connection")
            && v.iter().any(|s| s.target == "only_http::request")
    };
    while !done() && t0.elapsed() < T {
        std::thread::sleep(Duration::from_millis(10));
    }
    let v = CAP.0.lock().unwrap().clone();
    let req = v
        .iter()
        .find(|s| s.target == "only_http::request")
        .expect("request span");
    assert_eq!(req.name, "GET /user/:id");
    assert_eq!(
        req.field("network.protocol.version"),
        Some(&FieldValue::Str("3".into()))
    );
    assert_eq!(
        req.field("http.response.status_code"),
        Some(&FieldValue::U64(200))
    );
    let conn = v
        .iter()
        .find(|s| s.target == "only_http::connection")
        .expect("connection span");
    assert_eq!(
        conn.field("network.protocol.version"),
        Some(&FieldValue::Str("3".into()))
    );
    e.shutdown();
}
