//! OTLP/gRPC and OTLP/HTTPS against in-process receivers (akio-grpc's server, akio-http's
//! router, both behind akio-tls with a private CA and client certificates required): traces
//! with events and links, logs correlated with spans, metrics with exemplars; retries after
//! retryable failures, partial success, permanent failures, and TLS that must fail.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use akio::{
    Config, Engine, Listener,
    log::{LevelFilter, info, info_span, span::FieldValue},
    metrics::Registry,
    tls::{Certificate, PrivateKey, RootCerts, ServerConfig, Tls},
};
use akio_export::{Encoding, Exporter};
use akio_grpc::{Code, GrpcServer, Status};
use akio_http::{Context, Router, serve};
use akio_protobuf::encoding::{Reader, WireType};
use akio_x509::{CertificateParams, generate_simple_self_signed};

type X509Key = akio_crypto::pkey::PrivateKey;

// ---- certificates ---------------------------------------------------------------------------

struct Pki {
    ca: Certificate,
    server: (Vec<Certificate>, PrivateKey),
    client: (Vec<Certificate>, PrivateKey),
}

fn issue(names: &[&str], ca: &(akio_x509::Certificate, X509Key)) -> (Vec<Certificate>, PrivateKey) {
    let (throwaway, key) = generate_simple_self_signed(["x"]).unwrap();
    let cert = CertificateParams::new(names.iter().copied())
        .signed_by(&throwaway.public_key().unwrap(), &ca.0, &ca.1)
        .unwrap();
    (
        vec![Certificate::from_der(cert.as_der().to_vec())],
        PrivateKey::from_pkcs8_der(key.to_pkcs8_der()),
    )
}

fn make_pki(name: &str) -> Pki {
    let (_, ca_key) = generate_simple_self_signed(["ca"]).unwrap();
    let ca_cert = CertificateParams::ca(name).self_signed(&ca_key).unwrap();
    let ca = (ca_cert, ca_key);
    Pki {
        ca: Certificate::from_der(ca.0.as_der().to_vec()),
        server: issue(&["localhost", "127.0.0.1"], &ca),
        client: issue(&["exporter"], &ca),
    }
}

fn roots(c: &Certificate) -> RootCerts {
    let mut r = RootCerts::empty();
    r.add(c).unwrap();
    r
}

// ---- protobuf reading -----------------------------------------------------------------------

/// Every length-delimited field `num` of the message `buf`.
fn fields(buf: &[u8], num: u32) -> Vec<&[u8]> {
    let mut r = Reader::new(buf);
    let mut out = Vec::new();
    while !r.is_empty() {
        let (f, wt) = r.read_tag().unwrap();
        if wt == WireType::Len {
            let b = r.read_bytes().unwrap();
            if f == num {
                out.push(b);
            }
        } else {
            r.skip_field(f, wt).unwrap();
        }
    }
    out
}

/// Follows a path of message fields, collecting the leaves.
fn path<'a>(buf: &'a [u8], nums: &[u32]) -> Vec<&'a [u8]> {
    match nums.split_first() {
        None => vec![buf],
        Some((n, rest)) => fields(buf, *n)
            .into_iter()
            .flat_map(|b| path(b, rest))
            .collect(),
    }
}

fn strs(v: Vec<&[u8]>) -> Vec<String> {
    v.into_iter()
        .map(|b| String::from_utf8(b.to_vec()).unwrap())
        .collect()
}

/// An `Export*ServiceResponse` with a partial success rejecting `n`.
fn partial(n: u64) -> Vec<u8> {
    let mut inner = vec![0x08];
    let mut v = n;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            inner.push(b);
            break;
        }
        inner.push(b | 0x80);
    }
    let mut out = vec![0x0a, inner.len() as u8];
    out.extend(inner);
    out
}

// ---- receivers ------------------------------------------------------------------------------

#[derive(Default)]
struct Got {
    /// (method or path, metadata `authorization`, body)
    calls: Mutex<Vec<(String, String, Vec<u8>)>>,
    /// Answer the next calls with this status (Unavailable / InvalidArgument), then OK (over
    /// gRPC: only the trace service's calls).
    fail: Mutex<Vec<Code>>,
    /// Reject this many items in the next OK answer (gRPC: of the trace service).
    reject: AtomicUsize,
}

impl Got {
    fn bodies(&self, suffix: &str) -> Vec<Vec<u8>> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _, _)| m.ends_with(suffix))
            .map(|(_, _, b)| b.clone())
            .collect()
    }
}

fn grpc_collector(got: Arc<Got>) -> GrpcServer {
    let mut s = GrpcServer::new();
    for svc in [
        "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export",
        "/opentelemetry.proto.collector.trace.v1.TraceService/Export",
        "/opentelemetry.proto.collector.logs.v1.LogsService/Export",
    ] {
        let got = got.clone();
        let name = svc.to_owned();
        s = s.unary(svc, move |md, req, sink| {
            let auth = md.get("authorization").unwrap_or("").to_owned();
            got.calls.lock().unwrap().push((name.clone(), auth, req));
            let fail = if !name.contains("trace") {
                None
            } else {
                let mut f = got.fail.lock().unwrap();
                (!f.is_empty()).then(|| f.remove(0))
            };
            if let Some(code) = fail {
                return sink.finish(Status::new(code, "injected"));
            }
            let n = if name.contains("trace") {
                got.reject.swap(0, Ordering::Relaxed)
            } else {
                0
            };
            sink.send(&if n > 0 { partial(n as u64) } else { Vec::new() });
            sink.finish(Status::ok());
        });
    }
    s
}

fn http_collector(got: Arc<Got>) -> Router {
    let mut r = Router::new();
    for p in ["/v1/metrics", "/v1/traces", "/v1/logs"] {
        let got = got.clone();
        r = r.post(p, move |ctx: &mut Context| {
            let ct = ctx
                .req()
                .headers
                .get("content-type")
                .unwrap_or("")
                .to_owned();
            got.calls.lock().unwrap().push((
                ctx.req().path().to_owned(),
                ct,
                ctx.req().body.clone(),
            ));
            let fail = {
                let mut f = got.fail.lock().unwrap();
                (!f.is_empty()).then(|| f.remove(0))
            };
            if fail.is_some() {
                let mut resp = akio_http::Response::text(503, "busy");
                resp.headers.set("retry-after", "0");
                return ctx.respond(resp);
            }
            ctx.text(200, "");
        });
    }
    r
}

fn tls_engine(pki: &Pki, alpn: &str, acceptor: impl akio::Acceptor) -> Engine {
    let scfg = ServerConfig::builder(pki.server.0.clone(), pki.server.1.clone())
        .alpn([alpn])
        .client_auth_required(roots(&pki.ca))
        .build()
        .unwrap();
    let mut cfg = Config::default();
    cfg.shutdown_timeout = Duration::from_millis(300);
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::tcp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(Tls::server(scfg, acceptor)),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(15), "timed out: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn grpc_and_https_with_mutual_tls() {
    let pki = make_pki("akio test CA");
    let got = Arc::new(Got::default());
    let grpc = tls_engine(&pki, "h2", serve(grpc_collector(got.clone())));
    let endpoint = format!("https://localhost:{}", grpc.local_addrs()[0].port());

    let reg = Registry::new();
    let lat = reg.histogram_with_exemplars("job_seconds", "Job time.", &[], &[0.1, 1.0]);
    let ex = Exporter::builder()
        .service_name("grpc-e2e")
        .collector(Arc::new(reg.clone()))
        .interval(Duration::from_secs(3600))
        .span_interval(Duration::from_secs(3600))
        .otlp_grpc_with(&endpoint, &[("authorization", "Bearer t0k")])
        .tls_roots(roots(&pki.ca))
        .tls_client_cert(pki.client.0.clone(), pki.client.1.clone())
        .retry(
            Duration::from_millis(20),
            Duration::from_millis(50),
            Duration::from_secs(30),
        )
        .traces(LevelFilter::Info)
        // New traces are not recorded (the receivers' own request spans would be): the spans
        // of this test are children of a sampled remote parent, entered on this thread.
        .sample_ratio(0.0)
        .logs(LevelFilter::Info)
        .start()
        .unwrap();
    let remote = akio::log::span::SpanContext::new(0x0123, 0x4567, true, true).unwrap();
    let _parent = akio::log::span::enter_context(remote);

    // A span with an event and a link, a record and an observation inside it.
    let linked = akio::log::span::SpanContext::new(0xfeed, 0xbeef, true, true).unwrap();
    let mut s = akio::log::span::SpanBuilder::new(akio::log::Level::Info, "app", "batch")
        .link(akio::log::span::SpanLink::new(linked).field("why", "fan-in"))
        .start();
    let ctx = s.context().unwrap();
    s.add_event("retry", &[("attempt", FieldValue::U64(2))]);
    s.in_scope(|| {
        info!(target: "app", rows = 3u64; "loaded {} rows", 3);
        lat.observe(0.5);
    });
    drop(s);
    info!(target: "app", "outside any span");
    ex.flush();

    let s = ex.stats();
    assert_eq!(
        (s.otlp_traces_ok, s.otlp_logs_ok, s.otlp_metrics_ok),
        (1, 1, 1),
        "{s:?}"
    );
    assert_eq!((s.spans_exported, s.logs_exported), (1, 2), "{s:?}");
    assert!(
        got.calls
            .lock()
            .unwrap()
            .iter()
            .all(|(_, auth, _)| auth == "Bearer t0k"),
        "metadata on every call"
    );
    let traces = got.bodies("TraceService/Export");
    let span = path(&traces[0], &[1, 2, 2])[0];
    assert_eq!(strs(path(span, &[5])), ["batch"]);
    assert_eq!(strs(path(span, &[11, 2])), ["retry"], "the event");
    assert_eq!(
        path(span, &[13, 1])[0],
        0xfeed_u128.to_be_bytes(),
        "the link"
    );
    assert_eq!(strs(path(span, &[13, 4, 1])), ["why"]);
    let logs = got.bodies("LogsService/Export");
    let records = path(&logs[0], &[1, 2, 2]);
    assert_eq!(records.len(), 2);
    let inside = records
        .iter()
        .find(|r| strs(path(r, &[5, 1])) == ["loaded 3 rows"])
        .expect("the record logged in the span");
    assert_eq!(path(inside, &[9])[0], ctx.trace_id().to_be_bytes());
    assert_eq!(path(inside, &[10])[0], ctx.span_id().to_be_bytes());
    assert!(strs(path(inside, &[6, 1])).contains(&"rows".to_owned()));
    let outside = records
        .iter()
        .find(|r| strs(path(r, &[5, 1])) == ["outside any span"])
        .unwrap();
    // Outside the batch span, the record carries the context entered on the thread.
    assert_eq!(path(outside, &[9])[0], remote.trace_id().to_be_bytes());
    assert_eq!(path(outside, &[10])[0], remote.span_id().to_be_bytes());
    let metrics = got.bodies("MetricsService/Export");
    let exemplar = path(&metrics[0], &[1, 2, 2, 9, 1, 8])[0];
    assert_eq!(path(exemplar, &[5])[0], ctx.trace_id().to_be_bytes());
    assert_eq!(path(exemplar, &[4])[0], ctx.span_id().to_be_bytes());

    // UNAVAILABLE twice: the batch is kept and sent again after the backoff.
    got.fail
        .lock()
        .unwrap()
        .extend([Code::Unavailable, Code::Unavailable]);
    drop(info_span!("retried"));
    ex.flush();
    wait_until("the retried span", || ex.stats().spans_exported == 2);
    let s = ex.stats();
    assert_eq!(s.otlp_traces_failed, 2, "{s:?}");
    assert!(s.otlp_retried >= 2, "{s:?}");
    assert_eq!(s.spans_dropped, 0);

    // A partial success is counted.
    got.reject.store(1, Ordering::Relaxed);
    drop(info_span!("a"));
    drop(info_span!("b"));
    ex.flush();
    let s = ex.stats();
    assert_eq!((s.spans_exported, s.spans_rejected), (3, 1), "{s:?}");

    // INVALID_ARGUMENT: dropped at once, no retry.
    got.fail.lock().unwrap().push(Code::InvalidArgument);
    drop(info_span!("refused"));
    ex.flush();
    let s = ex.stats();
    assert_eq!(
        (s.spans_dropped, s.spans_queued, s.otlp_traces_failed),
        (1, 0, 3),
        "{s:?}"
    );
    ex.shutdown();

    // OTLP/HTTP over TLS (ALPN http/1.1), JSON, with the client certificate; a 503 with
    // Retry-After is retried.
    let hgot = Arc::new(Got::default());
    let https = tls_engine(&pki, "http/1.1", serve(http_collector(hgot.clone())));
    let hendpoint = format!("https://127.0.0.1:{}", https.local_addrs()[0].port());
    hgot.fail.lock().unwrap().push(Code::Unavailable);
    let hex = Exporter::builder()
        .service_name("https-e2e")
        .collector(Arc::new(reg.clone()))
        .interval(Duration::from_secs(3600))
        .otlp_http_with(&hendpoint, Encoding::Json, &[])
        .tls_roots(roots(&pki.ca))
        .tls_client_cert(pki.client.0.clone(), pki.client.1.clone())
        .retry(
            Duration::from_millis(20),
            Duration::from_millis(50),
            Duration::from_secs(30),
        )
        .start()
        .unwrap();
    hex.flush();
    wait_until("metrics after the 503", || hex.stats().otlp_metrics_ok == 1);
    assert_eq!(hex.stats().otlp_metrics_failed, 1);
    let calls = hgot.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].0, "/v1/metrics");
    assert_eq!(calls[1].1, "application/json");
    let json = String::from_utf8(calls[1].2.clone()).unwrap();
    assert!(json.contains("\"exemplars\":[{\"timeUnixNano\""), "{json}");
    assert!(
        json.contains(&format!("\"traceId\":\"{:032x}\"", ctx.trace_id())),
        "{json}"
    );
    hex.shutdown();

    // TLS that must fail: no client certificate, a server name the certificate lacks, another
    // CA. Each push fails (retryable: the collector may get fixed) and nothing is accepted.
    let other = make_pki("another CA");
    for b in [
        Exporter::builder().tls_roots(roots(&pki.ca)),
        Exporter::builder()
            .tls_roots(roots(&pki.ca))
            .tls_client_cert(pki.client.0.clone(), pki.client.1.clone())
            .tls_server_name("collector.example"),
        Exporter::builder()
            .tls_roots(roots(&other.ca))
            .tls_client_cert(pki.client.0.clone(), pki.client.1.clone()),
    ] {
        let before = hgot.calls.lock().unwrap().len();
        let bad = b
            .collector(Arc::new(reg.clone()))
            .interval(Duration::from_secs(3600))
            .timeout(Duration::from_secs(2))
            .otlp_http(&hendpoint)
            .start()
            .unwrap();
        bad.flush();
        let s = bad.stats();
        assert_eq!((s.otlp_metrics_ok, s.otlp_metrics_failed), (0, 1), "{s:?}");
        bad.shutdown();
        assert_eq!(
            hgot.calls.lock().unwrap().len(),
            before,
            "nothing got through"
        );
    }
    for e in [grpc, https] {
        e.shutdown();
        e.wait();
    }
}
