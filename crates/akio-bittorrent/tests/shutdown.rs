//! A client's peer connections at its engine's graceful shutdown (a follow-up of akit's A301):
//! one still in its handshake does not hold `Client::close` (the engine's `wait`) until the
//! shutdown timeout, whichever side opened it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use akio_bittorrent::client::{AddOptions, Client, ClientConfig, MemoryStorage};
use akio_bittorrent::metainfo::{Builder, MetaInfo};
use akio_bittorrent::mse::{CRYPTO_PLAINTEXT, CRYPTO_RC4, Initiator, Policy};
use akio_bittorrent::wire::{HANDSHAKE_LEN, Handshake, new_peer_id};

/// Well under the engine's default `shutdown_timeout` (10 s), which the client keeps.
const BOUND: Duration = Duration::from_secs(5);

fn cfg(enc: Policy) -> ClientConfig {
    let mut c = ClientConfig::default();
    c.listen = "127.0.0.1:0".parse().unwrap();
    c.utp = false;
    c.encryption = enc;
    c.dht = false;
    c.lsd = false;
    c.trackers = false;
    c
}

fn torrent() -> MetaInfo {
    let mi = Builder::new("shutdown.bin")
        .piece_length(16 * 1024)
        .build_bytes(&vec![7u8; 64 * 1024])
        .unwrap();
    MetaInfo::parse(&mi.to_bytes()).unwrap()
}

/// A connection the client dialed, to a peer that took its handshake and never answered.
#[test]
fn a_dialed_peer_that_never_answers_does_not_hold_close() {
    let peer = TcpListener::bind("127.0.0.1:0").unwrap();
    let mi = torrent();
    let client = Client::new(cfg(Policy::Disabled)).unwrap();
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::new(mi.info.total_length)));
    o.peers = vec![peer.local_addr().unwrap()];
    client.add_torrent(mi.clone(), o).unwrap();
    let (mut s, _) = peer.accept().unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut hs = [0u8; HANDSHAKE_LEN];
    s.read_exact(&mut hs).unwrap();
    assert_eq!(Handshake::parse(&hs).unwrap().info_hash, mi.info_hash);
    let t0 = Instant::now();
    client.close();
    assert!(t0.elapsed() < BOUND, "{:?}", t0.elapsed());
    // The connection was closed, not left behind.
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).unwrap(), 0);
}

/// A connection the client accepted, in the middle of its MSE handshake.
#[test]
fn an_accepted_peer_in_its_handshake_does_not_hold_close() {
    let mi = torrent();
    let client = Client::new(cfg(Policy::Prefer)).unwrap();
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::new(mi.info.total_length)));
    client.add_torrent(mi.clone(), o).unwrap();
    let mut s = TcpStream::connect(client.listen_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let hs = Handshake::new(mi.info_hash, new_peer_id())
        .encode()
        .to_vec();
    let (_i, first) = Initiator::new(mi.info_hash, CRYPTO_RC4 | CRYPTO_PLAINTEXT, hs);
    s.write_all(&first).unwrap();
    // The client's public key: the connection is up, waiting for the rest of the handshake.
    let mut yb = [0u8; 96];
    s.read_exact(&mut yb).unwrap();
    let t0 = Instant::now();
    client.close();
    assert!(t0.elapsed() < BOUND, "{:?}", t0.elapsed());
    // The connection was closed: what is left of the client's padding, then the end.
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).unwrap();
}

/// A peer connection past its handshake, when the engine is shut down without
/// `Client::close` (which would have taken the torrent's peers off first).
#[test]
fn a_peer_of_a_torrent_ends_at_the_engine_shutdown() {
    let payload = vec![7u8; 64 * 1024];
    let mi = torrent();
    let client = Client::new(cfg(Policy::Prefer)).unwrap();
    let mut o = AddOptions::default();
    o.storage = Some(Arc::new(MemoryStorage::with_data(payload)));
    let t = client.add_torrent(mi.clone(), o).unwrap();
    assert!(t.wait_complete(Duration::from_secs(10)));
    let mut s = TcpStream::connect(client.listen_addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(&Handshake::new(mi.info_hash, new_peer_id()).encode())
        .unwrap();
    // The client's handshake: the connection is the torrent's peer now.
    let mut hs = [0u8; HANDSHAKE_LEN];
    s.read_exact(&mut hs).unwrap();
    assert_eq!(Handshake::parse(&hs).unwrap().info_hash, mi.info_hash);
    let t0 = Instant::now();
    client.engine().shutdown();
    client.engine().wait();
    assert!(t0.elapsed() < BOUND, "{:?}", t0.elapsed());
    // What the client had queued (its bitfield and so on), then the end.
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).unwrap();
    client.close();
}
