//! ICE-TCP: an `Endpoint` with a passive TCP candidate, reached by an active ICE agent over a
//! real TCP connection with RFC 4571 framing.
#![allow(missing_docs)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use only::Engine;
use only_ice::tcp::{FrameReader, frame};
use only_ice::{Candidate, Credentials, IceAgent, IceConfig, IceState, TcpType};
use only_webrtc::{Endpoint, Peer, PeerHandler};

struct Nop;
impl PeerHandler for Nop {}

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

fn attr<'a>(sdp: &'a str, key: &str) -> &'a str {
    sdp.lines()
        .find_map(|l| l.strip_prefix(&format!("a={key}:")))
        .unwrap_or_else(|| panic!("no a={key} in {sdp}"))
        .trim()
}

/// A minimal answer from an agent that only does ICE (no DTLS follows).
fn answer(c: &Credentials) -> String {
    let fp = (0..32).map(|_| "AB").collect::<Vec<_>>().join(":");
    format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n\
         m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n\
         a=ice-ufrag:{}\r\na=ice-pwd:{}\r\na=fingerprint:sha-256 {fp}\r\na=setup:active\r\n\
         a=mid:0\r\na=sctp-port:5000\r\n",
        c.ufrag, c.pwd
    )
}

/// Runs the active agent over the stream until it completes.
fn run_active(s: &mut TcpStream, agent: &mut IceAgent, local: SocketAddr, remote: SocketAddr) {
    let mut r = FrameReader::new();
    let mut buf = [0u8; 4096];
    let end = Instant::now() + Duration::from_secs(10);
    while agent.state() != IceState::Completed {
        assert!(Instant::now() < end, "state {:?}", agent.state());
        let now = Instant::now();
        agent.handle_timeout(now);
        while let Some(t) = agent.poll_transmit() {
            assert_eq!((t.source, t.destination), (local, remote));
            s.write_all(&frame(&t.contents).unwrap()).unwrap();
        }
        match s.read(&mut buf) {
            Ok(0) => panic!("closed"),
            Ok(n) => r.push(&buf[..n], |f| {
                agent.handle_receive(Instant::now(), remote, local, f);
                true
            }),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("{e}"),
        }
    }
}

#[test]
fn passive_candidate_reached_by_an_active_agent() {
    let e = engine();
    let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let passive = ep.listen_tcp(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    assert_ne!(passive.port(), ep.local_addr().unwrap().port());
    assert!(ep.listen_tcp(&e, "127.0.0.1:0".parse().unwrap()).is_err());
    let (peer, offer): (Peer, String) = ep
        .create_offer(Nop, |api| {
            api.add_channel("c");
        })
        .unwrap();
    let line = offer
        .lines()
        .find(|l| l.contains(" tcp ") && l.contains("tcptype passive"))
        .unwrap_or_else(|| panic!("{offer}"));
    let remote = Candidate::parse(line).unwrap();
    assert_eq!(remote.addr(), passive);

    let mut s = TcpStream::connect(passive).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let local = s.local_addr().unwrap();
    let mut agent = IceAgent::new(IceConfig::new(false, false), Instant::now());
    agent.add_local_candidate(Candidate::host_tcp(local, TcpType::Active));
    agent.set_remote_credentials(Credentials::new(
        attr(&offer, "ice-ufrag"),
        attr(&offer, "ice-pwd"),
    ));
    agent.add_remote_candidate(remote);
    peer.accept_answer(&answer(agent.local_credentials()))
        .unwrap();
    run_active(&mut s, &mut agent, local, passive);
    assert_eq!(agent.selected_pair(), Some((local, passive)));
    // Closing the peer closes its connections.
    peer.close();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0u8; 256];
    loop {
        match s.read(&mut b) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    ep.close();
    e.shutdown();
}

#[test]
fn unidentified_connections_are_closed() {
    let e = engine();
    let ep = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let passive = ep.listen_tcp(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
    let read_eof = |s: &mut TcpStream| {
        s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        matches!(s.read(&mut [0u8; 16]), Ok(0) | Err(_))
    };
    // A first frame that is not a check for a known ufrag.
    let mut s = TcpStream::connect(passive).unwrap();
    s.write_all(&frame(b"\x16\x03\x01 hello").unwrap()).unwrap();
    assert!(read_eof(&mut s));
    // Silence: closed after the first-check timeout.
    let mut s = TcpStream::connect(passive).unwrap();
    let t = Instant::now();
    assert!(read_eof(&mut s));
    let waited = t.elapsed();
    assert!(
        waited >= Duration::from_secs(9) && waited < Duration::from_secs(14),
        "{waited:?}"
    );
    ep.close();
    // The listener is gone with the endpoint.
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        TcpStream::connect_timeout(&passive, Duration::from_secs(1))
            .map_or(true, |mut s| read_eof(&mut s))
    );
    e.shutdown();
}

mod dc {
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, Sender, channel};

    use only::Listener;
    use only_webrtc::{ChannelId, RtcServer};

    use super::*;

    struct Echo;
    impl PeerHandler for Echo {
        fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
            let _ = p.send(id, data, binary);
        }
    }

    #[derive(Debug)]
    pub(super) enum Got {
        Open,
        Data(Vec<u8>),
    }

    struct Probe(Mutex<Sender<Got>>);
    impl PeerHandler for Probe {
        fn on_channel_open(&mut self, _p: &Peer, _id: ChannelId, _label: &str) {
            let _ = self.0.lock().unwrap().send(Got::Open);
        }
        fn on_channel_data(&mut self, _p: &Peer, _id: ChannelId, data: &[u8], _b: bool) {
            let _ = self.0.lock().unwrap().send(Got::Data(data.to_vec()));
        }
    }

    fn wait(rx: &Receiver<Got>, what: &str, f: impl Fn(&Got) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let g = rx
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
            if f(&g) {
                return;
            }
        }
    }

    fn tcp_only(sdp: &str) -> String {
        sdp.lines()
            .filter(|l| !l.starts_with("a=candidate") || l.contains(" tcp "))
            .map(|l| format!("{l}\r\n"))
            .collect()
    }

    /// `a` (active TCP candidate) offers to `answer`, both signalling TCP candidates only.
    fn echo_over_tcp(a: &Endpoint, answer: impl FnOnce(&str) -> String) -> Peer {
        echo_over(a, " 9 typ host tcptype active", answer)
    }

    /// `a` offers to `answer`, both signalling TCP candidates only; the offer has `want`.
    fn echo_over(a: &Endpoint, want: &str, answer: impl FnOnce(&str) -> String) -> Peer {
        let (tx, rx) = channel();
        let mut ch = None;
        let (pa, offer) = a
            .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("c")))
            .unwrap();
        let offer = tcp_only(&offer);
        assert!(offer.contains(want), "{offer}");
        pa.accept_answer(&tcp_only(&answer(&offer))).unwrap();
        wait(&rx, "open", |g| matches!(g, Got::Open));
        for i in 0..50u16 {
            // Up to 60 kB messages: several frames each.
            let m = vec![i as u8; 1200 * usize::from(i + 1)];
            pa.send(ch.unwrap(), &m, true).unwrap();
            wait(&rx, "echo", |g| matches!(g, Got::Data(d) if *d == m));
        }
        pa
    }

    #[test]
    fn active_endpoint_to_passive_endpoint() {
        let e = engine();
        let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        assert_eq!(a.dial_tcp(&e).unwrap(), "127.0.0.1:9".parse().unwrap());
        assert!(a.dial_tcp(&e).is_err());
        b.listen_tcp(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        let pa = echo_over_tcp(&a, |offer| b.accept_offer(offer, Echo).unwrap().1);
        // Closing the peer closes its connection: the other side's peer goes too.
        pa.close();
        let t = Instant::now();
        while b.peers() != 0 {
            assert!(t.elapsed() < Duration::from_secs(40), "b still has a peer");
            std::thread::sleep(Duration::from_millis(50));
        }
        a.close();
        b.close();
        e.shutdown();
    }

    #[test]
    fn simultaneous_open_endpoints() {
        // Both sides have only `so` candidates: whichever connect wins (crossing connects,
        // or one side's listener accepting the other's), checks, DTLS and SCTP run over it.
        for round in 0..3 {
            let e = engine();
            let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
            let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
            let sa = a.listen_tcp_so(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
            assert_ne!(sa.port(), a.local_addr().unwrap().port());
            assert!(a.listen_tcp_so(&e, "127.0.0.1:0".parse().unwrap()).is_err());
            b.listen_tcp_so(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
            let want = format!("{} {} typ host tcptype so", sa.ip(), sa.port());
            let pa = echo_over(&a, &want, |offer| {
                let answer = b.accept_offer(offer, Echo).unwrap().1;
                assert!(answer.contains("tcptype so"), "{answer}");
                answer
            });
            // ICE on both sides, not only DTLS over the connection's address.
            let t = Instant::now();
            while !pa.is_connected() {
                assert!(t.elapsed() < Duration::from_secs(10), "round {round}");
                std::thread::sleep(Duration::from_millis(10));
            }
            pa.close();
            a.close();
            b.close();
            e.shutdown();
        }
    }

    #[test]
    fn active_endpoint_to_ice_lite_server_over_tcp() {
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // Ports first, so that the candidates name them: TCP and UDP on the same port, so
        // that the server's TCP and UDP candidates share one address.
        let (udp, tcp) = loop {
            let t = std::net::TcpListener::bind(any)
                .unwrap()
                .local_addr()
                .unwrap();
            if std::net::UdpSocket::bind(t).is_ok() {
                break (t, t);
            }
        };
        let server =
            RtcServer::new(vec![udp]).tcp_candidates(vec![tcp, "0.0.0.0:0".parse().unwrap()]);
        let se = Engine::builder()
            .listen(Listener::udp(udp).threads(1).serve(server.clone()))
            .listen(Listener::tcp(tcp).threads(1).serve(server.tcp()))
            .build()
            .unwrap();
        se.start().unwrap();
        let e = engine();
        let a = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        a.dial_tcp(&e).unwrap();
        let _p = echo_over_tcp(&a, |offer| {
            let answer = server.accept_offer(offer, Echo).unwrap().1;
            assert!(
                answer.contains(" tcp ")
                    && answer.contains(&format!(
                        "{} {} typ host tcptype passive",
                        tcp.ip(),
                        tcp.port()
                    )),
                "{answer}"
            );
            assert_eq!(answer.matches("tcptype passive").count(), 1, "{answer}");
            answer
        });
        assert_eq!(server.peers(), 1);
        // A UDP peer of the same server is not taken for a TCP one.
        let b = Endpoint::bind(&e, "127.0.0.1:0".parse().unwrap()).unwrap();
        let (tx, rx) = channel();
        let mut ch = None;
        let (pb, offer) = b
            .create_offer(Probe(Mutex::new(tx)), |api| ch = Some(api.add_channel("u")))
            .unwrap();
        let answer = server.accept_offer(&offer, Echo).unwrap().1;
        pb.accept_answer(&answer).unwrap();
        wait(&rx, "udp open", |g| matches!(g, Got::Open));
        pb.send(ch.unwrap(), b"over udp", true).unwrap();
        wait(
            &rx,
            "udp echo",
            |g| matches!(g, Got::Data(d) if d == b"over udp"),
        );
        assert_eq!(server.peers(), 2);
        b.close();
        server.close_all();
        a.close();
        e.shutdown();
        se.shutdown();
    }
}
