//! OTLP/gRPC: unary `Export` calls with only-grpc's client over an HTTP/2 connection (h2c, or
//! TLS with ALPN `h2`) of a private engine with one client I/O thread, started on first use.
//! The exporter thread waits for each answer (with the timeout); the I/O thread only runs the
//! connection's callbacks.

use std::{io, sync::mpsc, time::Duration};

use only::Engine;
use only_grpc::{CallOptions, Code, GrpcClient};
use only_http::h2client::{H2Client, H2Options};
use only_tls::ClientConfig;

use crate::{http::Endpoint, logs::suppress_this_thread};

/// Largest `Export*ServiceResponse` accepted.
const MAX_RESPONSE: usize = 1 << 20;

/// The outcome of one call.
pub(crate) enum Answer {
    /// The response message (an `Export*ServiceResponse`).
    Ok(Vec<u8>),
    /// A status worth retrying (unavailable, deadline, resource exhausted ...).
    Retry,
    /// A status that will not change on retry (invalid argument, unauthenticated ...).
    Fail,
}

pub(crate) struct Client {
    ep: Endpoint,
    timeout: Duration,
    metadata: Vec<(String, String)>,
    tls: Option<(ClientConfig, String)>,
    engine: Option<Engine>,
    client: Option<GrpcClient>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("grpc::Client")
            .field("ep", &self.ep)
            .field("connected", &self.client.is_some())
            .finish_non_exhaustive()
    }
}

/// Whether a status is retryable (OTLP specification, "Failures": the codes that may succeed
/// later; `RESOURCE_EXHAUSTED` too, as the collector's memory limiter answers it).
pub(crate) fn retryable(c: Code) -> bool {
    matches!(
        c,
        Code::Cancelled
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::OutOfRange
            | Code::Unavailable
            | Code::DataLoss
    )
}

impl Client {
    pub(crate) fn new(
        ep: Endpoint,
        timeout: Duration,
        metadata: Vec<(String, String)>,
        tls: Option<(ClientConfig, String)>,
    ) -> Client {
        Client {
            ep,
            timeout,
            metadata,
            tls,
            engine: None,
            client: None,
        }
    }

    fn connect(&mut self) -> io::Result<GrpcClient> {
        if self.engine.is_none() {
            let mut cfg = only::Config::default();
            // Closing the exporter closes its connection at once.
            cfg.shutdown_timeout = Duration::from_millis(200);
            let e = Engine::builder().config(cfg).client_threads(1).build()?;
            e.start()?;
            self.engine = Some(e);
        }
        let engine = self.engine.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
        for addr in self.ep.addrs()? {
            let (tx, rx) = mpsc::channel();
            H2Client::dial(
                engine,
                addr,
                self.tls.as_ref().map(|(c, n)| (c.clone(), n.as_str())),
                H2Options::default(),
                move |r| {
                    if r.is_ok() {
                        // The connection's I/O thread: its records are not exported.
                        suppress_this_thread();
                    }
                    let _ = tx.send(r);
                },
            );
            match rx.recv_timeout(self.timeout) {
                Ok(Ok(h2)) => {
                    // Export responses are tiny: bound them like the HTTP path's (1 MiB).
                    return Ok(GrpcClient::new(h2, &self.ep.origin())
                        .max_message_bytes(MAX_RESPONSE)
                        .max_collect_bytes(MAX_RESPONSE));
                }
                Ok(Err(e)) => last = e,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    last = io::Error::new(io::ErrorKind::TimedOut, "gRPC connect timed out");
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    last = io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed before HTTP/2 started (TLS handshake failed?)",
                    );
                }
            }
        }
        Err(last)
    }

    /// One `Export` call with `body` (an `Export*ServiceRequest` in protobuf).
    pub(crate) fn export(&mut self, path: &str, body: &[u8]) -> Answer {
        let client = match &self.client {
            Some(c) => c.clone(),
            None => match self.connect() {
                Ok(c) => {
                    self.client = Some(c.clone());
                    c
                }
                Err(_) => return Answer::Retry,
            },
        };
        let mut opts = CallOptions::default();
        opts.timeout = Some(self.timeout);
        opts.metadata.clone_from(&self.metadata);
        match client.unary(path, body, opts) {
            Ok(resp) => Answer::Ok(resp),
            Err(s) => {
                if matches!(
                    s.code,
                    Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled
                ) {
                    // The connection may be gone: dial again next time.
                    self.client = None;
                }
                if retryable(s.code) {
                    Answer::Retry
                } else {
                    Answer::Fail
                }
            }
        }
    }

    /// Stops the private engine.
    pub(crate) fn close(&mut self) {
        self.client = None;
        if let Some(e) = self.engine.take() {
            e.shutdown();
            e.wait();
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}
