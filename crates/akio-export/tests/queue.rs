//! The span and log queues are bounded, a failed batch is retried after a backoff until its
//! age limit and then dropped and counted; bad configurations fail at start.
#![allow(missing_docs)]

use std::{
    net::TcpListener,
    time::{Duration, Instant},
};

use akio::log::{LevelFilter, info, info_span, span};
use akio_export::Exporter;

#[test]
fn bounded_queues_retry_then_drop() {
    // A port with nothing listening.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ex = Exporter::builder()
        .otlp_http(&format!("http://127.0.0.1:{port}"))
        .otlp_traces_only()
        .timeout(Duration::from_millis(200))
        .interval(Duration::from_secs(3600))
        .span_interval(Duration::from_secs(3600))
        .span_queue(16, 1000)
        .log_queue(8, 1000)
        .retry(
            Duration::from_millis(20),
            Duration::from_millis(40),
            Duration::from_millis(600),
        )
        .traces(LevelFilter::Info)
        .logs(LevelFilter::Info)
        .start()
        .unwrap();
    // A second tracer or logger cannot be installed.
    for b in [
        Exporter::builder()
            .otlp_http("http://127.0.0.1:1")
            .traces(LevelFilter::Info),
        Exporter::builder()
            .otlp_http("http://127.0.0.1:1")
            .logs(LevelFilter::Info),
    ] {
        assert_eq!(
            b.start().unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }
    assert_eq!(span::max_span_level(), LevelFilter::Info);
    assert_eq!(akio::log::max_level(), LevelFilter::Info);

    for i in 0..100u32 {
        drop(info_span!("work", i = i));
    }
    for i in 0..50u32 {
        info!(i = i; "record {i}");
    }
    let s = ex.stats();
    assert_eq!((s.spans_queued, s.spans_dropped), (16, 84), "{s:?}");
    assert_eq!((s.logs_queued, s.logs_dropped), (8, 42), "{s:?}");

    // The flush fails on the first signal and stops there: the batch waits to be retried.
    ex.flush();
    let s = ex.stats();
    assert_eq!(
        (s.spans_queued, s.spans_exported, s.spans_dropped),
        (16, 0, 84),
        "{s:?}"
    );
    assert_eq!((s.otlp_traces_failed, s.otlp_retried), (1, 1), "{s:?}");
    assert_eq!((s.otlp_logs_failed, s.logs_queued), (0, 8), "{s:?}");
    assert_eq!(s.otlp_metrics_failed, 0, "metrics do not go to OTLP");

    // The thread retries by itself after each backoff, then drops the batch once it is older
    // than the limit.
    let t0 = Instant::now();
    loop {
        let s = ex.stats();
        if s.spans_dropped == 100 {
            assert!(s.otlp_traces_failed >= 3, "{s:?}");
            assert_eq!(s.spans_queued, 0);
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "{s:?}");
        std::thread::sleep(Duration::from_millis(20));
    }
    // Nothing is retried for ever: once both batches are gone the counters settle.
    let t0 = Instant::now();
    loop {
        let s = ex.stats();
        if s.logs_dropped == 50 {
            assert_eq!(s.logs_queued, 0, "{s:?}");
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "{s:?}");
        // The log batch is drained by a flush (its interval is an hour).
        ex.flush();
        std::thread::sleep(Duration::from_millis(50));
    }
    ex.shutdown();
    // After shutdown nothing is queued any more.
    drop(info_span!("late"));
    info!("late");
    let s = ex.stats();
    assert_eq!((s.spans_queued, s.logs_queued), (0, 0));

    // Bad configurations fail at start.
    let ca = akio::tls::RootCerts::empty();
    for b in [
        Exporter::builder().otlp_http("collector:4318"),
        Exporter::builder().otlp_grpc("http://collector:4317/prefix"),
        Exporter::builder()
            .otlp_http("http://collector:4318")
            .tls_roots(ca.clone()),
        Exporter::builder().tls_server_name("x"),
        Exporter::builder().traces(LevelFilter::Info),
        Exporter::builder().logs(LevelFilter::Info),
    ] {
        assert_eq!(
            b.start().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
    // An https endpoint is accepted (nothing is dialled before the first push).
    let tls = Exporter::builder()
        .otlp_grpc("https://collector.invalid:4317")
        .tls_roots(ca)
        .start()
        .unwrap();
    tls.shutdown();
}
