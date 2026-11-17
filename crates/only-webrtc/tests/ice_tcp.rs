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
