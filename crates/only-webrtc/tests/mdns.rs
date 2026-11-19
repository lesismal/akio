//! mDNS candidates: endpoints conceal their host addresses behind `.local` names and resolve
//! the other side's names over the local network's mDNS (multicast looped back on this host).
#![allow(missing_docs)]

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use only::Engine;
use only_webrtc::{ChannelId, Endpoint, Peer, PeerHandler};

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
