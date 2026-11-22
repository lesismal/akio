//! HTTP/3 over 0-RTT: a resuming client's requests go out before the handshake, the server
//! marks them `Early-Data: 1` (RFC 8470) and the application can answer `425 Too Early`.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use akio::tls::{self, EarlyData};
use akio::{Engine, Listener};
use akio_h3::{H3Client, H3Error};
use akio_http::message::{Headers, Method, Response};
use akio_http::{Context, Router};

const T: Duration = Duration::from_secs(10);

#[test]
fn early_requests_are_marked() {
    let ck = akio_x509::generate_simple_self_signed(["localhost"]).unwrap();
    let cert = tls::Certificate::from_der(ck.0.as_der().to_vec());
    let key = tls::PrivateKey::from_pkcs8_der(ck.1.to_pkcs8_der());
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
    let quic = akio_h3::server_config(vec![cert], key)
        .unwrap()
        .zero_rtt(true);
    let e = Engine::builder()
        .listen(Listener::udp("127.0.0.1:0".parse().unwrap()).serve(akio_h3::serve(quic, app)))
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    let server = e.local_addrs()[0];
    // The TLS configuration is kept to see the session tickets the connections leave in it
    // (QUIC client configurations share it).
    let tcfg = tls::ClientConfig::builder()
        .insecure_skip_verify()
        .alpn([b"h3"])
        .tls13_only(true)
        .build()
        .unwrap();
    let cc = akio_quic::client_config_from(&tcfg).unwrap().zero_rtt(true);

    // First connection: a full handshake, nothing early.
    let relay = Relay::new(server, false);
    let c = H3Client::dial(&e, relay.addr, "localhost", cc.clone()).unwrap();
    assert_eq!(c.get("/", T).unwrap().body, b"early=-");
    wait_ticket(&tcfg);
    c.close();

    // Resumed: the GET goes in 0-RTT and is marked. The server's handshake flight is held
    // until the request is sent, so it cannot complete the handshake first (the request
    // would then go, correctly, in 1-RTT packets).
    let relay = Relay::new(server, true);
    let c = H3Client::dial(&e, relay.addr, "localhost", cc.clone()).unwrap();
    assert_eq!(c.connection().early_data(), EarlyData::Pending);
    let r = early(&c, &relay, Method::Get, "/", b"");
    assert_eq!(r.body, b"early=1");
    assert_eq!(c.connection().early_data(), EarlyData::Accepted);
    wait_ticket(&tcfg);
    c.close();

    // The POST in 0-RTT is refused with 425.
    let relay = Relay::new(server, true);
    let c = H3Client::dial(&e, relay.addr, "localhost", cc).unwrap();
    assert_eq!(c.connection().early_data(), EarlyData::Pending);
    let r = early(&c, &relay, Method::Post, "/pay", b"1");
    assert_eq!(r.status, 425);
    // After the handshake the same request goes through.
    assert_eq!(c.connection().early_data(), EarlyData::Accepted);
    let r = c
        .request_blocking(Method::Post, "/pay", &Headers::new(), b"1".to_vec(), T)
        .unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"paid"[..]));
    c.close();
}

/// Sends a request (written to the connection before `request` returns, in 0-RTT packets
/// while the handshake is held), then lets the handshake go on and waits for the answer.
fn early(c: &H3Client, relay: &Relay, method: Method, path: &str, body: &[u8]) -> Response {
    let (tx, rx) = mpsc::channel::<Result<Response, H3Error>>();
    c.request(method, path, &Headers::new(), body.to_vec(), move |r| {
        let _ = tx.send(r);
    });
    relay.release();
    rx.recv_timeout(T).unwrap().unwrap()
}

/// Waits until `cfg` holds a session ticket for the server (it comes after the handshake).
fn wait_ticket(cfg: &tls::ClientConfig) {
    let end = Instant::now() + T;
    while tls::quic::ticket_version(cfg, "localhost").is_none() {
        assert!(Instant::now() < end, "no session ticket");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A UDP relay between one client and the server that can hold the server's datagrams.
struct Relay {
    addr: SocketAddr,
    sock: Arc<UdpSocket>,
    st: Arc<Mutex<Held>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

struct Held {
    hold: bool,
    queue: Vec<Vec<u8>>,
    client: Option<SocketAddr>,
}

impl Relay {
    fn new(server: SocketAddr, hold: bool) -> Relay {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").unwrap());
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let st = Arc::new(Mutex::new(Held {
            hold,
            queue: Vec::new(),
            client: None,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (sock, st, stop) = (sock.clone(), st.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((n, from)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    let d = &buf[..n];
                    if from == server {
                        let mut g = st.lock().unwrap();
                        match g.client {
                            Some(to) if !g.hold => {
                                let _ = sock.send_to(d, to);
                            }
                            _ => g.queue.push(d.to_vec()),
                        }
                    } else {
                        st.lock().unwrap().client = Some(from);
                        let _ = sock.send_to(d, server);
                    }
                }
            })
        };
        Relay {
            addr: sock.local_addr().unwrap(),
            sock,
            st,
            stop,
            thread: Some(thread),
        }
    }

    /// Stops holding: the held datagrams go to the client, in order, then the rest.
    fn release(&self) {
        let mut g = self.st.lock().unwrap();
        g.hold = false;
        // Nothing is held before the client's first datagram (its socket may come up after
        // `dial` returns): the request then leaves with it, before any answer.
        if let Some(to) = g.client {
            for d in g.queue.drain(..) {
                let _ = self.sock.send_to(&d, to);
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
