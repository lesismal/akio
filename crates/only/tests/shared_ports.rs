//! Sockets that share a port: `Engine::dial_from` (TCP connections from one bound local port,
//! as TCP simultaneous open needs) and `Engine::bind_udp_multicast` (a multicast group's port
//! shared with other members on the host, as mDNS needs).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use only::{Conn, Engine, Handler, fn_acceptor};

fn engine() -> Engine {
    let e = Engine::builder()
        .client_threads(1)
        .udp_client_threads(1)
        .build()
        .unwrap();
    e.start().unwrap();
    e
}

struct Hello;
impl Handler for Hello {
    fn on_data(&mut self, _c: &Conn<Self>, _d: &[u8]) {}
}

/// A free local port (for TCP and UDP alike, unused right now).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn dial_from_one_local_port_to_two_listeners() {
    let e = engine();
    let local: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let l1 = TcpListener::bind("127.0.0.1:0").unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").unwrap();
    for l in [&l1, &l2] {
        e.dial_from(
            local,
            l.local_addr().unwrap(),
            fn_acceptor(|c: &Conn<Hello>| {
                let _ = c.send(b"hi");
                Hello
            }),
            |err| panic!("dial_from: {err}"),
        );
    }
    for l in [&l1, &l2] {
        let (mut s, from) = l.accept().unwrap();
        assert_eq!(from, local, "both connections leave from the bound port");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut b = [0u8; 2];
        s.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hi");
        s.write_all(b"ok").unwrap();
    }
    // A refused connect reports through on_error.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let (tx, rx) = channel();
    e.dial_from(
        "127.0.0.1:0".parse().unwrap(),
        closed,
        fn_acceptor(|_c: &Conn<Hello>| Hello),
        move |err| {
            let _ = tx.send(err.kind());
        },
    );
    assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
    e.shutdown();
}

struct Rx(Mutex<Sender<(SocketAddr, Vec<u8>)>>);
impl Handler for Rx {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        let _ = self.0.lock().unwrap().send((c.peer_addr(), d.to_vec()));
    }
}

#[test]
fn multicast_group_shared_by_two_bindings() {
    let e = engine();
    let group: SocketAddr = format!("239.255.42.99:{}", free_port()).parse().unwrap();
    let (tx, rx) = channel();
    let tx = Arc::new(Mutex::new(tx));
    let bind = || {
        let tx = tx.clone();
        e.bind_udp_multicast(
            group,
            fn_acceptor(move |_c: &Conn<Rx>| Rx(Mutex::new(tx.lock().unwrap().clone()))),
        )
    };
    let a = bind().unwrap();
    let b = bind().unwrap();
    assert_eq!(a.local_addr().port(), group.port());
    assert_eq!(b.local_addr().port(), group.port());
    // A plain socket sends to the group: both bindings get it (multicast looped back).
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    if let Err(err) = s.send_to(b"to the group", group) {
        eprintln!("skipped: no multicast route here ({err})");
        e.shutdown();
        return;
    }
    let mut got = Vec::new();
    while got.len() < 2 {
        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok((_, d)) => got.push(d),
            Err(_) => break,
        }
    }
    if got.is_empty() {
        eprintln!("skipped: multicast not looped back on this host");
        e.shutdown();
        return;
    }
    assert_eq!(got, vec![b"to the group".to_vec(); 2]);
    // Not a group address.
    let err = e
        .bind_udp_multicast(
            "127.0.0.1:5000".parse().unwrap(),
            fn_acceptor(|_c: &Conn<Hello>| Hello),
        )
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    a.close();
    b.close();
    e.shutdown();
}
