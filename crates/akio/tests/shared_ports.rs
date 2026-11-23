//! Sockets that share a port: `Engine::dial_from` (TCP connections from one bound local port,
//! as TCP simultaneous open needs) and `Engine::bind_udp_multicast` / `bind_udp_multicast_on`
//! (a multicast group's port shared with other members on the host, joined per interface, as
//! mDNS needs) with `UdpBinding::send_to_on` (out of a given interface).
#![allow(missing_docs)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, UdpSocket};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use akio::{Conn, Engine, Handler, fn_acceptor};

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
    let kind = |r: std::io::Result<akio::UdpBinding>| r.map(|b| b.close()).unwrap_err().kind();
    // No interface at all, or not a group.
    for g in [v4, v6] {
        assert_eq!(
            kind(e.bind_udp_multicast_on(g, &[], acc())),
            std::io::ErrorKind::InvalidInput
        );
    }
    // An IPv4 group on an interface that does not exist (or has no IPv4 address) only.
    assert_eq!(
        kind(e.bind_udp_multicast_on(v4, &[999_999], acc())),
        std::io::ErrorKind::AddrNotAvailable
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

/// `UdpBinding::set_unicast_hops` (the TTL / hop limit of unicast datagrams, 255 for mDNS
/// answers): 0..=255 taken on both families, 256 refused, datagrams still delivered.
#[test]
fn unicast_hops_set_on_bindings() {
    let e = engine();
    let acc = || fn_acceptor(|_c: &Conn<Hello>| Hello);
    for any in ["127.0.0.1:0", "[::1]:0"] {
        let Ok(b) = e.bind_udp(any.parse().unwrap(), acc()) else {
            eprintln!("skipped: cannot bind {any}");
            continue;
        };
        for ok in [255, 1, 64] {
            b.set_unicast_hops(ok).unwrap();
        }
        assert_eq!(
            b.set_unicast_hops(256).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        b.set_unicast_hops(255).unwrap();
        let peer = UdpSocket::bind(SocketAddr::new(b.local_addr().ip(), 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b.send_to(b"ttl 255", peer.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ttl 255");
        b.close();
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

/// The interfaces that are up, multicast-capable and have an IPv4 address (not loopback: Linux
/// does not mark it multicast-capable, macOS does).
fn ipv4_multicast_interfaces() -> Vec<akio_sys::Interface> {
    akio_sys::interfaces()
        .unwrap()
        .into_iter()
        .filter(|i| i.flags.is_up() && i.flags.is_multicast() && i.ipv4().is_some())
        .collect()
}

/// An IPv4 group joined on every interface (by index, `bind_udp_multicast_on`), and a datagram
/// sent to it out of each one (`send_to_on`): looped back from that interface's address, which
/// a datagram sent out of the default interface would not be.
#[test]
fn ipv4_group_joined_and_sent_per_interface() {
    let ifs = ipv4_multicast_interfaces();
    if ifs.is_empty() {
        eprintln!("skipped: no multicast interface with an IPv4 address");
        return;
    }
    let e = engine();
    let port = free_port();
    let group: SocketAddr = format!("239.255.42.97:{port}").parse().unwrap();
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    let mut list: Vec<u32> = ifs.iter().map(|i| i.index).collect();
    list.push(999_999);
    let b = match e.bind_udp_multicast_on(
        group,
        &list,
        fn_acceptor(move |_c: &Conn<Rx>| Rx(Mutex::new(tx.lock().unwrap().clone()))),
    ) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("skipped: no IPv4 multicast here ({err})");
            e.shutdown();
            return;
        }
    };
    assert_eq!(b.local_addr().port(), port);
    let mut reached = 0;
    for i in &ifs {
        let msg = format!("out of {}", i.name).into_bytes();
        if let Err(err) = b.send_to_on(&msg, group, i.index) {
            eprintln!("{}: not sent ({err})", i.name);
            continue;
        }
        while let Ok((src, d)) = rx.recv_timeout(Duration::from_secs(2)) {
            if d == msg {
                assert!(i.has_addr(src.ip()), "{} sent from {src}: {i:?}", i.name);
                reached += 1;
                break;
            }
        }
    }
    eprintln!("{reached} of {} interfaces looped back", ifs.len());
    if ifs.len() >= 2 {
        assert!(
            reached >= 2,
            "datagrams out of two interfaces at least: {ifs:?}"
        );
    }
    // Interface 0 is a plain send_to.
    b.send_to_on(b"default", group, 0).unwrap();
    b.close();
    e.shutdown();
}

/// A group joined on one interface at bind time, then on a second one through the binding
/// (`UdpBinding::join_multicast`, what an interface that appears later needs): a datagram out
/// of the second interface is received only while that membership exists; joining twice is
/// not an error, and `leave_multicast` ends it.
#[test]
fn ipv4_group_joined_and_left_on_a_bound_socket() {
    let ifs = ipv4_multicast_interfaces();
    let [first, second, ..] = &ifs[..] else {
        eprintln!("skipped: fewer than two multicast interfaces with an IPv4 address");
        return;
    };
    let e = engine();
    let port = free_port();
    let group: SocketAddr = format!("239.255.42.98:{port}").parse().unwrap();
    let (tx, rx) = channel();
    let tx = Mutex::new(tx);
    let b = match e.bind_udp_multicast_on(
        group,
        &[first.index],
        fn_acceptor(move |_c: &Conn<Rx>| Rx(Mutex::new(tx.lock().unwrap().clone()))),
    ) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("skipped: no IPv4 multicast here ({err})");
            e.shutdown();
            return;
        }
    };
    let got = |msg: &[u8]| -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(700);
        while let Ok((_, d)) =
            rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
        {
            if d == msg {
                return true;
            }
        }
        false
    };
    let out = |msg: &[u8]| {
        if let Err(err) = b.send_to_on(msg, group, second.index) {
            panic!("{}: not sent ({err})", second.name);
        }
    };
    out(b"before");
    assert!(
        !got(b"before"),
        "received out of {} before joining it",
        second.name
    );
    b.join_multicast(group.ip(), second.index).unwrap();
    b.join_multicast(group.ip(), second.index).unwrap();
    out(b"joined");
    assert!(
        got(b"joined"),
        "nothing out of {} after joining it",
        second.name
    );
    b.leave_multicast(group.ip(), second.index).unwrap();
    out(b"left");
    assert!(
        !got(b"left"),
        "received out of {} after leaving it",
        second.name
    );
    // An interface that does not exist is refused.
    assert!(b.join_multicast(group.ip(), 999_999).is_err());
    eprintln!(
        "joined and left on {} after binding on {}",
        second.name, first.name
    );
    b.close();
    e.shutdown();
}
