//! TrackerClient against TrackerServer over real sockets, HTTP and UDP, announce and scrape.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use only::{Engine, Listener};
use only_bittorrent::metainfo::InfoHash;
use only_bittorrent::tracker::{
    AnnounceRequest, TrackerClient, TrackerConfig, TrackerError, TrackerServer,
};

#[test]
fn announce_and_scrape_over_http_and_udp() {
    let t = TrackerServer::new(TrackerConfig::default());
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let server = Engine::builder()
        .listen(
            Listener::tcp(addr)
                .threads(1)
                .serve(only_http::serve(t.http())),
        )
        .listen(Listener::udp(addr).threads(1).serve(t.udp()))
        .build()
        .unwrap();
    server.start().unwrap();
    let engine = Arc::new(
        Engine::builder()
            .client_threads(1)
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let c = TrackerClient::new(engine, Duration::from_millis(300), 2);
    let ih = InfoHash([5; 20]);
    for (i, url) in [
        format!("http://{addr}/announce"),
        format!("udp://{addr}/announce"),
    ]
    .iter()
    .enumerate()
    {
        let (tx, rx) = mpsc::channel();
        let req = AnnounceRequest::new(
            ih,
            [i as u8 + 1; 20],
            6000 + i as u16,
            if i == 0 { 0 } else { 10 },
        );
        c.announce(url, &req, move |r| tx.send(r).unwrap());
        let r = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        if i == 1 {
            // The second (a leecher) sees the first (a seeder).
            assert_eq!(
                r.peers,
                vec![std::net::SocketAddr::from(([127, 0, 0, 1], 6000))],
                "{url}"
            );
            assert_eq!((r.seeders, r.leechers), (Some(1), Some(1)));
        }
        let (tx, rx) = mpsc::channel();
        c.scrape(url, &[ih], move |r| tx.send(r).unwrap());
        let s = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!(s[&ih].complete, 1, "{url}");
    }
    // Nobody at a UDP port: a timeout after the retransmissions.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (tx, rx) = mpsc::channel();
    let req = AnnounceRequest::new(ih, [9; 20], 1, 1);
    c.announce(
        &format!("udp://{}", dead.local_addr().unwrap()),
        &req,
        move |r| tx.send(r).unwrap(),
    );
    let e = rx
        .recv_timeout(Duration::from_secs(10))
        .unwrap()
        .unwrap_err();
    assert_eq!(e, TrackerError::Timeout);
}

/// A tracker given by host name is resolved on the client's resolver threads, never on the
/// caller's: `announce` returns at once and the outcome arrives from a resolver thread.
#[test]
fn host_names_resolve_off_the_calling_thread() {
    let engine = Arc::new(
        Engine::builder()
            .client_threads(1)
            .udp_client_threads(1)
            .build()
            .unwrap(),
    );
    engine.start().unwrap();
    let c = TrackerClient::new(engine.clone(), Duration::from_millis(200), 0);
    let req = AnnounceRequest::new(InfoHash([1; 20]), [1; 20], 1, 1);
    for url in [
        "udp://does-not-exist.invalid:6969/announce",
        "http://does-not-exist.invalid:80/announce",
    ] {
        let (tx, rx) = mpsc::channel();
        let t0 = std::time::Instant::now();
        c.announce(url, &req, move |r| {
            let name = std::thread::current().name().map(str::to_owned);
            tx.send((r, name)).unwrap();
        });
        assert!(
            t0.elapsed() < Duration::from_millis(50),
            "announce returned at once"
        );
        let (r, name) = rx.recv_timeout(Duration::from_secs(30)).unwrap();
        assert!(r.is_err(), "{url}");
        assert!(
            name.as_deref()
                .is_some_and(|n| n.starts_with("only-bt-dns")),
            "{url}: done ran on {name:?}"
        );
    }
    engine.shutdown();
    engine.wait();
}
