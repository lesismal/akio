//! End to end against the OpenTelemetry Collector over OTLP/gRPC (plain and TLS) and OTLP/HTTP
//! over TLS, with client certificates: run with `tools/otel/e2e.sh`, which makes a private CA,
//! starts the collector in Docker and sets `AKIO_OTEL_GRPC`, `AKIO_OTEL_GRPCS`,
//! `AKIO_OTEL_HTTPS`, `AKIO_OTEL_CERTS` (ca.pem, client.pem, client.key) and `AKIO_OTEL_OUT`.
//! Without them the test returns at once.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use akio::{
    log::{LevelFilter, info, info_span, span::FieldValue},
    metrics::Registry,
    tls::{Certificate, PrivateKey, RootCerts},
};
use akio_export::Exporter;

fn wait_for(dir: &str, name: &str, needles: &[&str]) {
    let path = format!("{dir}/{name}");
    let t0 = Instant::now();
    loop {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let missing: Vec<&&str> = needles.iter().filter(|n| !text.contains(**n)).collect();
        if missing.is_empty() {
            return;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "{path} lacks {missing:?}; it has:\n{}",
            &text[text.len().saturating_sub(4000)..]
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn grpc_and_tls_into_the_collector() {
    let (Ok(grpc), Ok(grpcs), Ok(https), Ok(certs), Ok(out)) = (
        std::env::var("AKIO_OTEL_GRPC"),
        std::env::var("AKIO_OTEL_GRPCS"),
        std::env::var("AKIO_OTEL_HTTPS"),
        std::env::var("AKIO_OTEL_CERTS"),
        std::env::var("AKIO_OTEL_OUT"),
    ) else {
        eprintln!("AKIO_OTEL_GRPC / _GRPCS / _HTTPS / _CERTS / _OUT not set: skipped");
        return;
    };
    let read = |f: &str| std::fs::read(format!("{certs}/{f}")).unwrap();
    let mut roots = RootCerts::empty();
    roots.add_pem(&read("ca.pem")).unwrap();
    let chain = Certificate::from_pem(&read("client.pem")).unwrap();
    let key = PrivateKey::from_pem(&read("client.key")).unwrap();

    let reg = Registry::new();
    let jobs = reg.counter("e2e_jobs_total", "Jobs.", &[]);
    let lat = reg.histogram_with_exemplars("e2e_job_seconds", "Job time.", &[], &[0.1, 1.0]);

    // gRPC over TLS with a client certificate: traces and metrics.
    let grpc_tls = Exporter::builder()
        .service_name("akio-grpcs-e2e")
        .collector(Arc::new(reg.clone()))
        .interval(Duration::from_secs(3600))
        .span_interval(Duration::from_millis(100))
        .otlp_grpc(&grpcs)
        .tls_roots(roots.clone())
        .tls_client_cert(chain.clone(), key.clone())
        .traces(LevelFilter::Info)
        .start()
        .unwrap();
    // HTTP/protobuf over TLS with a client certificate: logs and metrics.
    let https_ex = Exporter::builder()
        .service_name("akio-https-e2e")
        .collector(Arc::new(reg.clone()))
        .interval(Duration::from_secs(3600))
        .span_interval(Duration::from_millis(100))
        .otlp_http(&https)
        .tls_roots(roots.clone())
        .tls_client_cert(chain, key)
        .logs(LevelFilter::Info)
        .start()
        .unwrap();
    // Plain gRPC (h2c): metrics.
    let plain = Exporter::builder()
        .service_name("akio-grpc-e2e")
        .collector(Arc::new(reg.clone()))
        .interval(Duration::from_secs(3600))
        .otlp_grpc(&grpc)
        .start()
        .unwrap();

    let ctx;
    {
        let mut s = info_span!(target: "e2e", "grpc job", n = 1u64);
        ctx = s.context().unwrap();
        s.add_event("checkpoint", &[("step", FieldValue::from(2u64))]);
        s.in_scope(|| {
            info!(target: "e2e", job = 1u64; "job over TLS");
            jobs.inc();
            lat.observe(0.5);
        });
    }
    for e in [&grpc_tls, &https_ex, &plain] {
        e.flush();
    }
    let trace_id = format!("\"traceId\":\"{:032x}\"", ctx.trace_id());
    wait_for(
        &out,
        "traces.jsonl",
        &[
            "\"stringValue\":\"akio-grpcs-e2e\"",
            "\"name\":\"grpc job\"",
            "\"name\":\"checkpoint\"",
            &trace_id,
        ],
    );
    wait_for(
        &out,
        "logs.jsonl",
        &[
            "\"stringValue\":\"akio-https-e2e\"",
            "\"body\":{\"stringValue\":\"job over TLS\"}",
            &trace_id,
        ],
    );
    wait_for(
        &out,
        "metrics.jsonl",
        &[
            "\"stringValue\":\"akio-grpcs-e2e\"",
            "\"stringValue\":\"akio-https-e2e\"",
            "\"stringValue\":\"akio-grpc-e2e\"",
            "\"name\":\"e2e_jobs_total\"",
            "\"name\":\"e2e_job_seconds\"",
            "\"exemplars\":[{",
        ],
    );
    for (name, e) in [("grpcs", &grpc_tls), ("https", &https_ex), ("grpc", &plain)] {
        let s = e.stats();
        assert_eq!(
            (
                s.otlp_metrics_failed,
                s.otlp_traces_failed,
                s.otlp_logs_failed,
                s.metric_points_rejected,
                s.spans_rejected,
                s.logs_rejected
            ),
            (0, 0, 0, 0, 0, 0),
            "{name}: {s:?}"
        );
        assert!(s.otlp_metrics_ok >= 1, "{name}: {s:?}");
    }
    assert!(grpc_tls.stats().spans_exported >= 1);
    assert!(https_ex.stats().logs_exported >= 1);

    // Without the client certificate the collector refuses the handshake.
    let refused = Exporter::builder()
        .collector(Arc::new(reg))
        .interval(Duration::from_secs(3600))
        .otlp_grpc(&grpcs)
        .tls_roots(roots)
        .start()
        .unwrap();
    refused.flush();
    let s = refused.stats();
    assert_eq!((s.otlp_metrics_ok, s.otlp_metrics_failed), (0, 1), "{s:?}");
    for e in [refused, grpc_tls, https_ex, plain] {
        e.shutdown();
    }
}
