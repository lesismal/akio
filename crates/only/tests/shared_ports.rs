//! Sockets that share a port: `Engine::dial_from` (TCP connections from one bound local port,
//! as TCP simultaneous open needs) and `Engine::bind_udp_multicast` / `bind_udp_multicast_on`
//! (a multicast group's port shared with other members on the host, joined per interface for
//! link-scoped IPv6 groups, as mDNS needs).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, UdpSocket};
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
    // A host without IPv4 multicast (an IPv6-only link) refuses the join.
    let a = match bind() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("skipped: no IPv4 multicast here ({err})");
            e.shutdown();
            return;
        }
    };
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

#[test]
fn multicast_on_checks_its_arguments() {
    let e = engine();
    let v4: SocketAddr = format!("239.255.42.98:{}", free_port()).parse().unwrap();
    let v6: SocketAddr = format!("[ff02::4242]:{}", free_port()).parse().unwrap();
    let acc = || fn_acceptor(|_c: &Conn<Hello>| Hello);
    let kind = |r: std::io::Result<only::UdpBinding>| r.map(|b| b.close()).unwrap_err().kind();
    // IPv4 groups join the default interface only.
    for bad in [&[1u32][..], &[0, 1], &[]] {
        assert_eq!(
            kind(e.bind_udp_multicast_on(v4, bad, acc())),
            std::io::ErrorKind::InvalidInput,
            "{bad:?}"
        );
    }
    // No interface at all, or not a group.
    assert_eq!(
        kind(e.bind_udp_multicast_on(v6, &[], acc())),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        kind(e.bind_udp_multicast_on("[::1]:5000".parse().unwrap(), &[0], acc())),
        std::io::ErrorKind::InvalidInput
    );
    // `&[0]` is what bind_udp_multicast does (unless this host has no IPv4 multicast).
    match e.bind_udp_multicast_on(v4, &[0], acc()) {
        Ok(b) => {
            assert_eq!(b.local_addr().port(), v4.port());
            b.close();
        }
        Err(err) => eprintln!("skipped: no IPv4 multicast here ({err})"),
    }
    // An interface index no host has: the join fails, so does the binding.
    if e.bind_udp_multicast_on(v6, &[0], acc())
        .map(|b| b.close())
        .is_ok()
    {
        assert!(e.bind_udp_multicast_on(v6, &[999_999], acc()).is_err());
    }
    e.shutdown();
}

/// The interfaces with an IPv6 link-local address, and that address.
fn link_local_interfaces() -> Vec<(u32, Ipv6Addr)> {
    (1..=64)
        .filter_map(|i| {
            let s = UdpSocket::bind("[::]:0").ok()?;
            s.connect(SocketAddrV6::new("ff02::1".parse().unwrap(), 9, 0, i))
                .ok()?;
            match s.local_addr().ok()? {
                SocketAddr::V6(a) if a.ip().segments()[0] == 0xfe80 && a.scope_id() == i => {
                    Some((i, *a.ip()))
                }
                _ => None,
            }
        })
        .collect()
}

#[test]
fn ipv6_group_joined_per_interface() {
    let ifs = link_local_interfaces();
    if ifs.is_empty() {
        eprintln!("skipped: no interface with an IPv6 link-local address");
        return;
    }
    let e = engine();
    let port = free_port();
    let group: Ipv6Addr = "ff02::4243".parse().unwrap();
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    // Every interface, plus one that does not exist (skipped).
    let mut list: Vec<u32> = ifs.iter().map(|(i, _)| *i).collect();
    list.push(999_999);
    let b = e
        .bind_udp_multicast_on(
            SocketAddr::V6(SocketAddrV6::new(group, port, 0, 0)),
            &list,
            fn_acceptor(move |_c: &Conn<Rx>| Rx(Mutex::new(tx.lock().unwrap().clone()))),
        )
        .unwrap();
    assert_eq!(b.local_addr().port(), port);
    // A datagram to the group on each link reaches the binding (looped back), from a source
    // on that link.
    let s = UdpSocket::bind("[::]:0").unwrap();
    let mut reached = 0;
    for &(i, _) in &ifs {
        let to = SocketAddrV6::new(group, port, 0, i);
        if s.send_to(format!("link {i}").as_bytes(), to).is_err() {
            continue;
        }
        let want = format!("link {i}").into_bytes();
        while let Ok((src, d)) = rx.recv_timeout(Duration::from_secs(2)) {
            if d == want {
                if let SocketAddr::V6(a) = src {
                    // Link-local sources carry the link's scope id.
                    if a.ip().segments()[0] == 0xfe80 {
                        assert_eq!(a.scope_id(), i, "{src}");
                    }
                }
                reached += 1;
                break;
            }
        }
    }
    if reached == 0 {
        eprintln!("skipped: IPv6 multicast not looped back on this host");
    }
    b.close();
    e.shutdown();
}
