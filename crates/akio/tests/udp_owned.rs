//! UDP datagrams handed to the handler as owned receive-slab ranges (`Handler::OWNED_DATA`,
//! ADR-024): kept past later receives, written in place, split from GRO batches, truncated at
//! `read_buffer` like borrowed ones.
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akio::{Acceptor, Config, Conn, Engine, Handler, Listener, fn_acceptor};
use akio_buf::slab::{Chunk, ChunkMut};

type Kept = Arc<Mutex<Vec<Chunk>>>;

fn cfg() -> Config {
    let mut v = Config::default();
    v.shutdown_timeout = Duration::from_millis(500);
    v
}

fn client(server: SocketAddr) -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.connect(server).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

fn stop(e: &Engine) {
    e.shutdown();
    e.wait();
}

fn wait_for(what: &str, c: impl Fn() -> bool) {
    let t = Instant::now();
    while !c() {
        assert!(t.elapsed() < Duration::from_secs(10), "timed out: {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn pattern(seq: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| (seq * 31 + i) as u8).collect()
}

/// Keeps every datagram (after flipping its first byte in place) and, if `.1`, acknowledges it
/// with one byte; `on_data` must never be called for it.
struct Keep(Kept, bool);
impl Handler for Keep {
    fn on_data(&mut self, _c: &Conn<Self>, _data: &[u8]) {
        panic!("an owned-data handler got a borrowed datagram");
    }
    const OWNED_DATA: bool = true;
    fn on_data_owned(&mut self, c: &Conn<Self>, mut data: ChunkMut) {
        if let Some(b) = data.first_mut() {
            *b ^= 0xff;
        }
        self.0.lock().unwrap().push(data.freeze());
        if self.1 {
            let _ = c.send(&[1]);
        }
    }
}

fn unflip(c: &Chunk) -> Vec<u8> {
    let mut v = c.to_vec();
    if let Some(b) = v.first_mut() {
        *b ^= 0xff;
    }
    v
}

fn keep_server(cfg: Config, kept: &Kept) -> Engine {
    let k = kept.clone();
    let e = Engine::builder()
        .config(cfg)
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<Keep>| Keep(k.clone(), true))),
        )
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

#[test]
fn owned_datagrams_outlive_later_receives() {
    let kept: Kept = Arc::default();
    let e = keep_server(cfg(), &kept);
    let c = client(e.local_addrs()[0]);
    let max = if cfg!(target_os = "linux") {
        9000
    } else {
        8000
    };
    let mut ack = [0u8; 4];
    // Which datagram each kept one is (acknowledged one by one, so they arrive in order).
    let mut seqs = Vec::new();
    for seq in 0..1500 {
        let len = 1 + (seq * 389) % max;
        c.send(&pattern(seq, len)).unwrap();
        assert_eq!(c.recv(&mut ack).unwrap(), 1, "ack {seq}");
        seqs.push(seq);
        // Drop every other one now and then: their slabs come back once their neighbours go
        // too, while the rest stay held across the receives that follow.
        if seq % 100 == 99 {
            let mut k = kept.lock().unwrap();
            assert_eq!(k.len(), seqs.len());
            let mut i = 0;
            k.retain(|_| {
                i += 1;
                i % 2 == 1
            });
            let mut j = 0;
            seqs.retain(|_| {
                j += 1;
                j % 2 == 1
            });
        }
    }
    let k = kept.lock().unwrap();
    assert_eq!(k.len(), seqs.len());
    for (d, &seq) in k.iter().zip(&seqs) {
        let len = 1 + (seq * 389) % max;
        assert_eq!(unflip(d), pattern(seq, len), "datagram {seq}");
    }
    drop(k);
    stop(&e);
}

#[test]
fn owned_datagrams_are_truncated_like_borrowed_ones() {
    let kept: Kept = Arc::default();
    let mut v = cfg();
    // Below 64 KiB GRO stays off; longer datagrams are cut at `read_buffer`.
    v.read_buffer = 2048;
    let e = keep_server(v, &kept);
    let c = client(e.local_addrs()[0]);
    let big = pattern(3, 3000);
    let mut ack = [0u8; 4];
    for d in [&big[..], &[9u8; 100][..], &big[..]] {
        c.send(d).unwrap();
        assert_eq!(c.recv(&mut ack).unwrap(), 1);
    }
    let k = kept.lock().unwrap();
    let got: Vec<Vec<u8>> = k.iter().map(unflip).collect();
    assert_eq!(
        got,
        vec![big[..2048].to_vec(), vec![9; 100], big[..2048].to_vec()]
    );
    drop(k);
    stop(&e);
}

/// Sends 5 datagrams of 1000 bytes and one of 300 with `send_segments` on open.
struct Segs;
impl Handler for Segs {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
}

fn segments(base: u8) -> Vec<Vec<u8>> {
    (0..6u8)
        .map(|i| vec![base.wrapping_add(i); if i == 5 { 300 } else { 1000 }])
        .collect()
}

#[test]
fn coalesced_receives_are_split_into_owned_datagrams() {
    // The client sends with GSO; the listener has GRO on (Linux, the default): the kernel may
    // hand it one coalesced buffer, which must still arrive as six owned datagrams.
    struct Dial;
    impl Acceptor for Dial {
        type Handler = Segs;
        fn on_open(&self, c: &Conn<Segs>) -> Segs {
            c.send_segments(segments(50).concat(), 1000).unwrap();
            Segs
        }
    }
    let kept: Kept = Arc::default();
    let server = keep_server(cfg(), &kept);
    let client = Engine::builder()
        .config(cfg())
        .udp_client_threads(1)
        .build()
        .unwrap();
    client.start().unwrap();
    client.dial_udp(server.local_addrs()[0], Dial, |e| panic!("{e}"));
    wait_for("six datagrams", || kept.lock().unwrap().len() >= 6);
    thread::sleep(Duration::from_millis(50));
    let got: Vec<Vec<u8>> = kept.lock().unwrap().iter().map(unflip).collect();
    assert_eq!(got, segments(50));
    stop(&client);
    stop(&server);
}

#[test]
fn dialed_connections_get_owned_datagrams_too() {
    // A plain echo server answers with GSO segments; the dialed owned handler keeps them.
    struct SegEcho;
    impl Handler for SegEcho {
        fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
            c.send_segments(segments(d[0]).concat(), 1000).unwrap();
        }
    }
    struct Dial(Kept);
    impl Acceptor for Dial {
        type Handler = Keep;
        fn on_open(&self, c: &Conn<Keep>) -> Keep {
            c.send(&[70]).unwrap();
            Keep(self.0.clone(), false)
        }
    }
    let server = Engine::builder()
        .config(cfg())
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .serve(fn_acceptor(|_c: &Conn<SegEcho>| SegEcho)),
        )
        .build()
        .unwrap();
    server.start().unwrap();
    let kept: Kept = Arc::default();
    let client = Engine::builder()
        .config(cfg())
        .udp_client_threads(1)
        .build()
        .unwrap();
    client.start().unwrap();
    client.dial_udp(server.local_addrs()[0], Dial(kept.clone()), |e| {
        panic!("{e}")
    });
    // The handler acknowledges each datagram to the server, which answers each with six more:
    // wait for the first six, then compare that prefix.
    wait_for("six datagrams", || kept.lock().unwrap().len() >= 6);
    let got: Vec<Vec<u8>> = kept.lock().unwrap()[..6].iter().map(unflip).collect();
    assert_eq!(got, segments(70));
    stop(&client);
    stop(&server);
}
