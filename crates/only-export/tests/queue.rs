//! The span queue is bounded and failures are counted, never retried without limit.
#![allow(missing_docs)]

use std::{net::TcpListener, time::Duration};

use only::log::{LevelFilter, info_span, span};
use only_export::Exporter;

#[test]
fn full_queue_drops_and_dead_endpoint_counts() {
    // A port with nothing listening.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let ex = Exporter::builder()
        .otlp_http(&format!("http://127.0.0.1:{port}"))
        .timeout(Duration::from_millis(200))
        .interval(Duration::from_secs(3600))
        .span_interval(Duration::from_secs(3600))
        .span_queue(16, 1000)
        .traces(LevelFilter::Info)
        .start()
        .unwrap();
    // A second tracer cannot be installed.
    let again = Exporter::builder()
        .otlp_http("http://127.0.0.1:1")
        .traces(LevelFilter::Info)
        .start();
    assert_eq!(again.unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(span::max_span_level(), LevelFilter::Info);

    for i in 0..100u32 {
        drop(info_span!("work", i = i));
    }
    let s = ex.stats();
    assert_eq!(s.spans_queued, 16, "{s:?}");
    assert_eq!(s.spans_dropped, 84);
    ex.flush();
    let s = ex.stats();
    assert_eq!(
        (s.spans_queued, s.spans_exported, s.spans_dropped),
        (0, 0, 100)
    );
    assert_eq!(s.otlp_traces_failed, 1);
    assert_eq!(s.otlp_metrics_failed, 1);
    ex.shutdown();
    // After shutdown spans are not queued any more.
    drop(info_span!("late"));
    assert_eq!(ex.stats().spans_queued, 0);

    // Bad configurations fail at start.
    for b in [
        Exporter::builder().otlp_http("https://collector:4318"),
        Exporter::builder().otlp_http("collector:4318"),
        Exporter::builder().traces(LevelFilter::Info),
    ] {
        assert_eq!(
            b.start().unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }
}
