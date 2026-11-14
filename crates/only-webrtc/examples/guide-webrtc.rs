//! Companion of the book's "WebRTC, STUN and TURN" chapter: an ICE-lite WebRTC server, a TURN
//! server (which also answers STUN), and a full-ICE client `Endpoint` that learns its
//! server-reflexive address and talks to the server over a data channel, all on one engine.
//!
//! `cargo run -p only-webrtc --example guide-webrtc`

use std::sync::{Arc, mpsc};
use std::time::Duration;

use only::{Engine, Listener};
use only_turn::{TurnConfig, TurnServer, static_auth};
use only_webrtc::{ChannelId, Endpoint, Peer, PeerHandler, RtcServer};

// ANCHOR: handler
/// Server side: one handler per peer; callbacks run one at a time and must not block.
struct Echo;

impl PeerHandler for Echo {
    fn on_channel_data(&mut self, p: &Peer, id: ChannelId, data: &[u8], binary: bool) {
        let _ = p.send(id, data, binary); // sends work from any thread, callbacks included
    }
}
// ANCHOR_END: handler

// ANCHOR: client
/// Client side: say hello when the channel opens, report the echo.
struct Hello(mpsc::Sender<String>);

impl PeerHandler for Hello {
    fn on_channel_open(&mut self, p: &Peer, id: ChannelId, label: &str) {
        let _ = p.send(id, format!("hello on {label}").as_bytes(), false);
    }
    fn on_channel_data(&mut self, p: &Peer, _id: ChannelId, data: &[u8], _binary: bool) {
        let _ = self.0.send(String::from_utf8_lossy(data).into_owned());
        p.close();
    }
}
// ANCHOR_END: client

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ANCHOR: engine
    // The address peers reach the WebRTC listener at is its host candidate.
    let rtc_addr = "127.0.0.1:3479".parse()?;
    let server = RtcServer::new(vec![rtc_addr]);

    let auth = static_auth("example.org", [("alice", "secret")]);
    let turn = TurnServer::new(TurnConfig::new("example.org", auth, "127.0.0.1".parse()?));

    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::udp(rtc_addr).serve(server.clone()))
            .listen(Listener::udp("127.0.0.1:3478".parse()?).serve(turn.clone()))
            .udp_client_threads(1) // Endpoint::bind needs UDP I/O threads
            .build()?,
    );
    turn.set_engine(&engine); // relay sockets are bound on the engine
    engine.start()?;
    // ANCHOR_END: engine

    // ANCHOR: endpoint
    let ep = Endpoint::bind(&engine, "127.0.0.1:0".parse()?)?;
    // The TURN server answers STUN Binding requests too.
    let public = ep.gather_srflx("127.0.0.1:3478".parse()?, Duration::from_secs(3))?;
    println!("server-reflexive address: {public}");

    let (tx, rx) = mpsc::channel();
    let (peer, offer) = ep.create_offer(Hello(tx), |sdp| {
        sdp.add_channel("chat");
    })?;
    // Signalling: in a real application the offer travels over HTTP (WHIP/WHEP), a WebSocket ...
    let (_server_peer, answer) = server.accept_offer(&offer, Echo)?;
    peer.accept_answer(&answer)?;
    println!("echo: {}", rx.recv_timeout(Duration::from_secs(10))?);
    // ANCHOR_END: endpoint

    engine.shutdown();
    engine.wait();
    Ok(())
}
