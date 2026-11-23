//! mDNS candidates: endpoints conceal their host addresses behind `.local` names and resolve
//! the other side's names over the local network's mDNS (multicast looped back on this host).
#![allow(missing_docs)]

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use akio::Engine;
use akio_webrtc::{ChannelId, Endpoint, Peer, PeerHandler};

fn engine() -> Arc<Engine> {
    let e = Arc::new(
        Engine::builder()
            .udp_client_threads(1)
            .client_threads(1)
            .build()
            .unwrap(),
    );
    e.start().unwrap();
    e
}

struct Echo;
impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary);
    }
}

struct Probe(Mutex<Sender<Vec<u8>>>);
impl PeerHandler for Probe {
    fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
        let _ = self.0.lock().unwrap().send(b"open".to_vec());
    }
    fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, data: &[u8], _b: bool) {
        let _ = self.0.lock().unwrap().send(data.to_vec());
    }
}

fn wait(rx: &Receiver<Vec<u8>>, want: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let g = rx.recv_timeout(left).unwrap_or_else(|_| {
            panic!("timed out waiting for {:?}", String::from_utf8_lossy(want))
        });
        if g == want {
            return;
        }
    }
}

/// An endpoint on loopback that resolves mDNS names and conceals its own address, or `None`
/// when this host has no shared mDNS port (the test is then skipped).
fn concealing(e: &Engine) -> Option<Endpoint> {
    let ep = Endpoint::bind(e, "127.0.0.1:0".parse().unwrap()).unwrap();
    ep.resolve_mdns(e, Duration::from_secs(5)).unwrap();
    assert!(ep.resolve_mdns(e, Duration::from_secs(5)).is_err());
    match ep.conceal_host_candidates() {
        Ok(()) => Some(ep),
        Err(err) => {
            eprintln!("skipped: {err}");
            None
        }
    }
}

fn host_lines(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter(|l| l.starts_with("a=candidate"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn concealed_endpoints_resolve_each_other() {
    let e = engine();
    let (Some(a), Some(b)) = (concealing(&e), concealing(&e)) else {
        return;
    };
    // Without resolution neither side could check the other: both conceal.
    for trickle in [false, true] {
        let (tx, rx) = channel();
        let mut ch = None;
        let (pa, offer) = a
            .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
            .unwrap();
        let lines = host_lines(&offer);
        assert!(!lines.is_empty());
        for l in &lines {
            assert!(l.contains(".local ") && !l.contains("127.0.0.1"), "{l}");
        }
        let offer_sent = if trickle {
            offer
                .lines()
                .filter(|l| !l.starts_with("a=candidate") && !l.starts_with("a=end-of-candidates"))
                .map(|l| format!("{l}\r\n"))
                .collect()
        } else {
            offer
        };
        let (pb, answer) = b.accept_offer(&offer_sent, Echo).unwrap();
        assert!(host_lines(&answer).iter().all(|l| l.contains(".local ")));
        if trickle {
            for l in &lines {
                pb.add_remote_candidate(l).unwrap();
            }
        }
        pa.accept_answer(&answer).unwrap();
        wait(&rx, b"open");
        pa.send(ch.unwrap(), b"over mdns", true).unwrap();
        wait(&rx, b"over mdns");
        pa.close();
        pb.close();
    }
    a.close();
    b.close();
    e.shutdown();
}

#[test]
fn without_resolution_mdns_candidates_are_refused() {
    let e = engine();
    let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(ep.conceal_host_candidates().is_err());
    let (p, _offer) = ep
        .create_offer(Echo, |api| {
            api.add_channel("c");
        })
        .unwrap();
    let line =
        "candidate:1 1 udp 2122260223 0a1b2c3d-1111-4222-8333-444455556666.local 5000 typ host";
    assert!(p.add_remote_candidate(line).is_err());
    p.close();
    ep.close();
    e.shutdown();
}

// ---- IPv6 (ff02::fb) ----

use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};

use akio_ice::mdns::{GROUP_V6, Message, PORT, Record, TYPE_AAAA};

/// The interfaces with an IPv6 link-local address (as the endpoint finds them).
fn ifaces() -> Vec<u32> {
    if let Ok(t) = std::fs::read_to_string("/proc/net/if_inet6") {
        let mut v: Vec<u32> = t
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_ascii_whitespace().collect();
                (f.len() >= 6 && f[3] == "20").then(|| u32::from_str_radix(f[1], 16).ok())?
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        return v;
    }
    (1..=64)
        .filter(|&i| {
            let s = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).unwrap();
            s.connect(v6_group(i)).is_ok()
                && matches!(s.local_addr(), Ok(SocketAddr::V6(a)) if a.ip().segments()[0] == 0xfe80)
        })
        .collect()
}

/// A raw socket on the shared IPv6 mDNS port, member of `ff02::fb` on every interface, or
/// `None` (the test is skipped) when this host has no IPv6 multicast.
fn raw_v6() -> Option<(UdpSocket, Vec<u32>)> {
    let ifs = ifaces();
    let s = akio_sys::listen_udp((Ipv6Addr::UNSPECIFIED, PORT).into(), true).and_then(|s| {
        let mut ok = false;
        for &i in &ifs {
            ok |= s.join_multicast_v6(&GROUP_V6, i).is_ok();
        }
        if ok {
            s.set_nonblocking(false).map(|()| s)
        } else {
            Err(std::io::Error::other("no interface takes ff02::fb"))
        }
    });
    match s {
        Ok(s) => {
            s.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            Some((s, ifs))
        }
        Err(e) => {
            eprintln!("skipped: no IPv6 multicast ({e})");
            None
        }
    }
}

/// Sends `m` to `ff02::fb` on every interface.
fn multicast_v6(s: &UdpSocket, ifs: &[u32], m: &[u8]) {
    let mut sent = false;
    for &i in ifs {
        sent |= s.send_to(m, v6_group(i)).is_ok();
    }
    assert!(sent, "no interface sends to ff02::fb");
}

/// Reads mDNS messages that arrived over IPv6 (not IPv4-mapped) until `f` takes one.
fn recv_v6<T>(s: &UdpSocket, mut f: impl FnMut(SocketAddr, Message) -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buf = [0u8; 9000];
    while Instant::now() < deadline {
        let Ok((n, src)) = s.recv_from(&mut buf) else {
            continue;
        };
        let SocketAddr::V6(a) = src else { continue };
        if a.ip().to_ipv4_mapped().is_some() {
            continue;
        }
        if let Ok(m) = Message::parse(&buf[..n]) {
            if let Some(t) = f(src, m) {
                return Some(t);
            }
        }
    }
    None
}

fn v6_group(scope: u32) -> SocketAddr {
    SocketAddr::V6(std::net::SocketAddrV6::new(GROUP_V6, PORT, 0, scope))
}

fn bind_v6(e: &Engine) -> Option<Endpoint> {
    match Endpoint::bind(e, "[::1]:0".parse().unwrap()) {
        Ok(ep) => Some(ep),
        Err(err) => {
            eprintln!("skipped: no IPv6 loopback ({err})");
            None
        }
    }
}

/// The endpoint answers an AAAA query that arrives over IPv6 for its concealed `::1`, by
/// IPv6 multicast to the link the query came from.
#[test]
fn answers_aaaa_queries_over_ipv6_multicast() {
    let Some((raw, ifs)) = raw_v6() else { return };
    let e = engine();
    let Some(ep) = bind_v6(&e) else { return };
    ep.resolve_mdns(&e, Duration::from_secs(5)).unwrap();
    if let Err(err) = ep.conceal_host_candidates() {
        eprintln!("skipped: {err}");
        return;
    }
    let (p, offer) = ep
        .create_offer(Echo, |api| {
            api.add_channel("c");
        })
        .unwrap();
    let line = host_lines(&offer)
        .into_iter()
        .next()
        .expect("a host candidate");
    assert!(!line.contains("::1"), "{line}");
    let name = line.split_whitespace().nth(4).unwrap().to_owned();
    let q = Message::query(&name, TYPE_AAAA, false).unwrap();
    multicast_v6(&raw, &ifs, &q);
    let answer = recv_v6(&raw, |_src, m| {
        (m.response && m.records.iter().any(|r| r.name == name)).then_some(m)
    })
    .expect("no AAAA answer over IPv6");
    let r = answer.records.iter().find(|r| r.name == name).unwrap();
    assert_eq!(r.addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert!(r.ttl > 0 && r.cache_flush);
    p.close();
    ep.close();
    e.shutdown();
}

/// A name only an IPv6 responder knows: the endpoint queries `ff02::fb`, the answer over IPv6
/// resolves it, and the peers connect through the resolved `::1` candidate.
#[test]
fn resolves_names_over_ipv6_multicast() {
    let Some((raw, ifs)) = raw_v6() else { return };
    let e = engine();
    let (Some(a), Some(b)) = (bind_v6(&e), bind_v6(&e)) else {
        return;
    };
    a.resolve_mdns(&e, Duration::from_secs(10)).unwrap();
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    let (pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    // b's candidates replaced by one under a name of ours.
    let name = "0a1b2c3d-1111-4222-8333-444455556666.local";
    let port = b.local_addr().unwrap().port();
    let answer: String = answer
        .lines()
        .filter(|l| !l.starts_with("a=candidate"))
        .map(|l| format!("{l}\r\n"))
        .collect();
    pa.accept_answer(&answer).unwrap();
    let cand = format!("candidate:1 1 udp 2122260223 {name} {port} typ host");
    pa.add_remote_candidate(&cand).unwrap();
    // The query arrives over IPv6; answer it there.
    recv_v6(&raw, |_src, m| {
        (!m.response
            && m.questions
                .iter()
                .any(|q| q.name == name && q.qtype == TYPE_AAAA))
        .then_some(())
    })
    .expect("no AAAA query over IPv6");
    let rec = Record {
        name: name.to_owned(),
        addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
        ttl: 120,
        cache_flush: true,
    };
    multicast_v6(&raw, &ifs, &Message::response(0, &[], &[rec]));
    wait(&rx, b"open");
    pa.send(ch.unwrap(), b"over mdns6", true).unwrap();
    wait(&rx, b"over mdns6");
    pa.close();
    pb.close();
    a.close();
    b.close();
    e.shutdown();
}

/// Two endpoints on `::1` conceal and resolve each other (AAAA records).
#[test]
fn concealed_ipv6_endpoints_resolve_each_other() {
    let e = engine();
    let (Some(a), Some(b)) = (bind_v6(&e), bind_v6(&e)) else {
        return;
    };
    for ep in [&a, &b] {
        ep.resolve_mdns(&e, Duration::from_secs(5)).unwrap();
        if let Err(err) = ep.conceal_host_candidates() {
            eprintln!("skipped: {err}");
            return;
        }
    }
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    assert!(
        host_lines(&offer)
            .iter()
            .all(|l| l.contains(".local ") && !l.contains("::1"))
    );
    let (pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    pa.accept_answer(&answer).unwrap();
    wait(&rx, b"open");
    pa.send(ch.unwrap(), b"v6", true).unwrap();
    wait(&rx, b"v6");
    pa.close();
    pb.close();
    a.close();
    b.close();
    e.shutdown();
}

/// Endpoints bound to a link-local IPv6 address: the SDP carries no scope id, the endpoint
/// puts the link's back on what it sends (and strips it from what it receives).
#[test]
fn link_local_ipv6_endpoints_connect() {
    let addr = ifaces().into_iter().find_map(|i| {
        let s = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
        s.connect(v6_group(i)).ok()?;
        match s.local_addr().ok()? {
            SocketAddr::V6(mut a) if a.ip().segments()[0] == 0xfe80 && a.scope_id() == i => {
                a.set_port(0);
                Some(SocketAddr::V6(a))
            }
            _ => None,
        }
    });
    let Some(addr) = addr else {
        eprintln!("skipped: no link-local IPv6 address");
        return;
    };
    let e = engine();
    let (Ok(a), Ok(b)) = (Endpoint::bind(&e, addr), Endpoint::bind(&e, addr)) else {
        eprintln!("skipped: cannot bind {addr}");
        return;
    };
    let (tx, rx) = channel();
    let mut ch = None;
    let (pa, offer) = a
        .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
        .unwrap();
    assert!(!offer.contains('%'), "{offer}");
    let (pb, answer) = b.accept_offer(&offer, Echo).unwrap();
    pa.accept_answer(&answer).unwrap();
    wait(&rx, b"open");
    pa.send(ch.unwrap(), b"link-local", true).unwrap();
    wait(&rx, b"link-local");
    pa.close();
    pb.close();
    a.close();
    b.close();
    e.shutdown();
}

// ---- Claiming our names (RFC 6762 §8, §9, §10.1) ----

use akio_ice::mdns::TYPE_ANY;

/// Like [`recv_v6`] for at most `within`.
fn recv_v6_within<T>(
    s: &UdpSocket,
    within: Duration,
    mut f: impl FnMut(SocketAddr, Message) -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + within;
    let mut buf = [0u8; 9000];
    while Instant::now() < deadline {
        let Ok((n, src)) = s.recv_from(&mut buf) else {
            continue;
        };
        if matches!(src, SocketAddr::V6(a) if a.ip().to_ipv4_mapped().is_none()) {
            if let Ok(m) = Message::parse(&buf[..n]) {
                if let Some(t) = f(src, m) {
                    return Some(t);
                }
            }
        }
    }
    None
}

/// An endpoint on `::1` that conceals, and the name of its host candidate in a new offer.
fn concealing_v6(e: &Engine) -> Option<Endpoint> {
    let ep = bind_v6(e)?;
    ep.resolve_mdns(e, Duration::from_secs(5)).unwrap();
    match ep.conceal_host_candidates() {
        Ok(()) => Some(ep),
        Err(err) => {
            eprintln!("skipped: {err}");
            None
        }
    }
}

fn offered_name(ep: &Endpoint) -> String {
    let (p, offer) = ep
        .create_offer(Echo, |api| {
            api.add_channel("c");
        })
        .unwrap();
    p.close();
    let line = host_lines(&offer)
        .into_iter()
        .next()
        .expect("a host candidate");
    line.split_whitespace().nth(4).unwrap().to_owned()
}

#[derive(Debug, PartialEq)]
enum Seen {
    Probe,
    Announcement,
    Goodbye,
    Answer,
}

/// What a message says about our name `name` (for `::1`).
fn seen(name: &str, m: &Message) -> Option<Seen> {
    if !m.response {
        let probe = m
            .questions
            .iter()
            .any(|q| q.name == name && q.qtype == TYPE_ANY && q.unicast_response)
            && m.authority
                .iter()
                .any(|r| r.name == name && r.addr == IpAddr::V6(Ipv6Addr::LOCALHOST));
        return probe.then_some(Seen::Probe);
    }
    let r = m.records.iter().find(|r| r.name == name)?;
    assert_eq!(r.addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    Some(match (r.ttl, r.cache_flush) {
        (0, _) => Seen::Goodbye,
        (_, true) => Seen::Announcement,
        _ => Seen::Answer,
    })
}

/// A new concealed name is probed three times 250 ms apart, then announced twice 1 s apart,
/// its own probes are not answered, and closing the endpoint says goodbye.
#[test]
fn names_are_probed_announced_and_withdrawn() {
    let Some((raw, _ifs)) = raw_v6() else { return };
    let e = engine();
    let Some(ep) = concealing_v6(&e) else { return };
    let name = offered_name(&ep);
    // Each message may arrive once per interface: copies within 100 ms count once.
    let mut events: Vec<(Seen, Instant)> = Vec::new();
    let _ = recv_v6_within(&raw, Duration::from_secs(4), |_src, m| {
        if let Some(s) = seen(&name, &m) {
            let now = Instant::now();
            let dup = events
                .iter()
                .any(|(k, t)| *k == s && now.duration_since(*t) < Duration::from_millis(100));
            if !dup {
                events.push((s, now));
            }
        }
        None::<()>
    });
    let kinds: Vec<&Seen> = events.iter().map(|(k, _)| k).collect();
    assert_eq!(
        kinds,
        [
            &Seen::Probe,
            &Seen::Probe,
            &Seen::Probe,
            &Seen::Announcement,
            &Seen::Announcement
        ],
        "{events:?}"
    );
    let gap = |i: usize| events[i + 1].1.duration_since(events[i].1);
    for i in 0..2 {
        assert!(
            gap(i) >= Duration::from_millis(200),
            "probe gap {:?}",
            gap(i)
        );
    }
    assert!(
        gap(2) >= Duration::from_millis(200),
        "claimed too early: {:?}",
        gap(2)
    );
    assert!(
        gap(3) >= Duration::from_millis(900),
        "announcement gap {:?}",
        gap(3)
    );
    ep.close();
    let bye = recv_v6_within(&raw, Duration::from_secs(3), |_src, m| {
        (seen(&name, &m) == Some(Seen::Goodbye)).then_some(())
    });
    assert!(bye.is_some(), "no goodbye for {name}");
    e.shutdown();
}

/// Another host answering our name with another address takes it: the endpoint stops
/// answering it and conceals its address under a new name.
#[test]
fn a_conflicting_answer_gives_the_name_up() {
    let Some((raw, ifs)) = raw_v6() else { return };
    let e = engine();
    let Some(ep) = concealing_v6(&e) else { return };
    let name = offered_name(&ep);
    let theirs = Record {
        name: name.clone(),
        addr: "fd00::99".parse().unwrap(),
        ttl: 120,
        cache_flush: true,
    };
    multicast_v6(&raw, &ifs, &Message::response(0, &[], &[theirs]));
    let again = (0..50)
        .map(|_| {
            std::thread::sleep(Duration::from_millis(50));
            offered_name(&ep)
        })
        .find(|n| *n != name);
    assert!(again.is_some(), "{name} kept after a conflict");
    // Past any announcement already under way, a query for it gets no answer from us.
    std::thread::sleep(Duration::from_millis(2200));
    multicast_v6(
        &raw,
        &ifs,
        &Message::query(&name, TYPE_AAAA, false).unwrap(),
    );
    let answered = recv_v6_within(&raw, Duration::from_millis(1500), |_src, m| {
        (m.response
            && m.records
                .iter()
                .any(|r| r.name == name && r.addr == IpAddr::V6(Ipv6Addr::LOCALHOST)))
        .then_some(())
    });
    assert!(answered.is_none(), "{name} still answered");
    ep.close();
    e.shutdown();
}

/// A probe for our name from another host while ours is being probed: the greater record
/// wins (RFC 6762 §8.2). An `AAAA fd00::…` beats our `AAAA ::1`; an `A` record loses to it.
#[test]
fn simultaneous_probes_are_settled_by_the_tiebreak() {
    let Some((raw, ifs)) = raw_v6() else { return };
    let e = engine();
    for (addr, we_keep) in [("10.0.0.1", true), ("fd00::99", false)] {
        let Some(ep) = concealing_v6(&e) else { return };
        let name = offered_name(&ep);
        let theirs = Record {
            name: name.clone(),
            addr: addr.parse().unwrap(),
            ttl: 120,
            cache_flush: false,
        };
        multicast_v6(&raw, &ifs, &Message::probe(&name, &[theirs]).unwrap());
        std::thread::sleep(Duration::from_millis(300));
        let now = offered_name(&ep);
        assert_eq!(now == name, we_keep, "probe with {addr}: {name} -> {now}");
        ep.close();
    }
    e.shutdown();
}

/// A link-local address is claimed and answered on its own link only (RFC 6762 §6.2): its
/// probes and announcements leave from that interface alone (their source is its link-local
/// address; sent on another link they would carry that link's), a query from another link
/// gets no answer (unless the two links are wired together, as a veth pair is), one from its
/// link does.
#[test]
fn link_local_names_stay_on_their_link() {
    let Some((raw, ifs)) = raw_v6() else { return };
    let addr = ifaces().into_iter().find_map(|i| {
        let s = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).ok()?;
        s.connect(v6_group(i)).ok()?;
        match s.local_addr().ok()? {
            SocketAddr::V6(mut a) if a.ip().segments()[0] == 0xfe80 && a.scope_id() == i => {
                a.set_port(0);
                Some(a)
            }
            _ => None,
        }
    });
    let Some(addr) = addr else {
        eprintln!("skipped: no link-local IPv6 address");
        return;
    };
    let link = addr.scope_id();
    let Some(&other) = ifs.iter().find(|&&i| i != link) else {
        eprintln!("skipped: one link only");
        return;
    };
    let e = engine();
    let Ok(ep) = Endpoint::bind(&e, SocketAddr::V6(addr)) else {
        eprintln!("skipped: cannot bind {addr}");
        return;
    };
    ep.resolve_mdns(&e, Duration::from_secs(5)).unwrap();
    if let Err(err) = ep.conceal_host_candidates() {
        eprintln!("skipped: {err}");
        return;
    }
    let name = offered_name(&ep);
    let mine = IpAddr::V6(*addr.ip());
    let about_us = |m: &Message| {
        m.records
            .iter()
            .chain(&m.authority)
            .any(|r| r.name == name && r.addr == mine)
    };
    // Probes and announcements, for 2.5 s: every copy left from the address's link.
    let mut seen = 0;
    let _ = recv_v6_within(&raw, Duration::from_millis(2500), |src, m| {
        if about_us(&m) {
            assert_eq!(src.ip(), mine, "{name} sent on another link ({src})");
            seen += 1;
        }
        None::<()>
    });
    assert!(seen >= 5, "{seen} probes and announcements");
    let q = Message::query(&name, TYPE_AAAA, false).unwrap();
    // From another link: no answer, unless our own query also reaches the address's link (the
    // two links are one wire, as a veth pair's ends are: the endpoint then rightly answers).
    raw.send_to(&q, v6_group(other)).unwrap();
    let (mut wired, mut answered) = (false, false);
    let _ = recv_v6_within(&raw, Duration::from_millis(1000), |src, m| {
        let SocketAddr::V6(s) = src else { return None };
        if !m.response && m.questions.iter().any(|x| x.name == name) && s.scope_id() == link {
            wired = true;
        }
        answered |= m.response && about_us(&m);
        None::<()>
    });
    if wired {
        eprintln!("links {other} and {link} are connected: the other-link check does not apply");
    } else {
        assert!(!answered, "answered on link {other}");
    }
    // From its own link: answered there.
    raw.send_to(&q, v6_group(link)).unwrap();
    let answered = recv_v6_within(&raw, Duration::from_secs(3), |src, m| {
        (m.response && about_us(&m)).then_some(src)
    });
    match answered {
        Some(src) => assert_eq!(src.ip(), mine, "answered from another link"),
        None => panic!("no answer on link {link}"),
    }
    ep.close();
    e.shutdown();
}

// ---- IPv4 on every interface (ADR-078 update 3) ----

use std::net::Ipv4Addr;

use akio_ice::mdns::{GROUP_V4, MULTICAST_V4, TYPE_A};

/// The interfaces the endpoint joins `224.0.0.251` on: up, multicast-capable, not loopback,
/// with an IPv4 address (and that address).
fn ipv4_ifaces() -> Vec<(u32, Ipv4Addr)> {
    akio_sys::interfaces()
        .unwrap()
        .into_iter()
        .filter(|i| i.flags.is_up() && i.flags.is_multicast() && !i.flags.is_loopback())
        .filter_map(|i| Some((i.index, i.ipv4()?)))
        .collect()
}

/// A raw socket on the shared IPv4 mDNS port, member of `224.0.0.251` on each of `ifs`.
fn raw_v4(ifs: &[(u32, Ipv4Addr)]) -> Option<UdpSocket> {
    let s = akio_sys::listen_udp((Ipv4Addr::UNSPECIFIED, PORT).into(), true).ok()?;
    let mut ok = false;
    for (_, a) in ifs {
        ok |= s.join_multicast_v4(&GROUP_V4, a).is_ok();
    }
    s.set_nonblocking(false).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(100))).ok()?;
    ok.then_some(s)
}

/// Like [`recv_v6_within`], for the IPv4 messages.
fn recv_v4_within(s: &UdpSocket, within: Duration, mut f: impl FnMut(SocketAddr, Message)) {
    let deadline = Instant::now() + within;
    let mut buf = [0u8; 9000];
    while Instant::now() < deadline {
        let Ok((n, src)) = s.recv_from(&mut buf) else {
            continue;
        };
        if let Ok(m) = Message::parse(&buf[..n]) {
            f(src, m);
        }
    }
}

/// An IPv4 address is claimed and answered on the interface that holds it only (RFC 6762
/// §6.2), now that IPv4 runs on every interface: its probes and announcements over IPv4 leave
/// from that interface alone (their source is its address; sent out of another they would
/// carry that one's), a query from another interface's subnet gets no answer, one from its own
/// is answered, out of that interface. Needs two IPv4 multicast interfaces.
#[test]
fn ipv4_names_stay_on_their_interface() {
    let ifs = ipv4_ifaces();
    let [first, second, ..] = ifs[..] else {
        eprintln!("skipped: fewer than two IPv4 multicast interfaces ({ifs:?})");
        return;
    };
    let Some(raw) = raw_v4(&ifs) else {
        eprintln!("skipped: no IPv4 multicast");
        return;
    };
    let e = engine();
    // The address on each of the two interfaces in turn: one of them is not the default
    // interface, which a single IPv4 group membership would be limited to.
    for ((link, mine), (other, theirs)) in [(first, second), (second, first)] {
        let ep = Endpoint::bind(&e, SocketAddr::new(mine.into(), 0)).unwrap();
        ep.resolve_mdns(&e, Duration::from_secs(5)).unwrap();
        if let Err(err) = ep.conceal_host_candidates() {
            eprintln!("skipped: {err}");
            return;
        }
        let name = offered_name(&ep);
        let about_us = |m: &Message| {
            m.records
                .iter()
                .chain(&m.authority)
                .any(|r| r.name == name && r.addr == IpAddr::V4(mine))
        };
        // Probes and announcements, for 2.5 s: every IPv4 copy left from the address's
        // interface.
        let mut seen = 0;
        recv_v4_within(&raw, Duration::from_millis(2500), |src, m| {
            if about_us(&m) {
                assert_eq!(
                    src.ip(),
                    IpAddr::V4(mine),
                    "{name} sent on another interface"
                );
                seen += 1;
            }
        });
        assert!(
            seen >= 5,
            "{seen} probes and announcements over IPv4 for {mine}"
        );
        let q = Message::query(&name, TYPE_A, false).unwrap();
        // From the other interface (the query's source is in its subnet): no answer.
        akio_sys::send_to_on(&raw, &q, MULTICAST_V4, other).unwrap();
        let mut answered = None;
        recv_v4_within(&raw, Duration::from_millis(1000), |src, m| {
            if m.response && about_us(&m) {
                answered = Some(src);
            }
        });
        assert_eq!(answered, None, "{mine}: answered a query from {theirs}");
        // From its own interface: answered, out of it.
        akio_sys::send_to_on(&raw, &q, MULTICAST_V4, link).unwrap();
        recv_v4_within(&raw, Duration::from_secs(2), |src, m| {
            if m.response && about_us(&m) {
                answered = Some(src);
            }
        });
        assert_eq!(
            answered.map(|a| a.ip()),
            Some(IpAddr::V4(mine)),
            "{mine}: no answer out of interface {link}"
        );
        ep.close();
    }
    e.shutdown();
}
