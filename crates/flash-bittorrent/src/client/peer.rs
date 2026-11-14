//! Peer connections up to the handshake, over TCP (flash `Conn`s) and uTP (the [`UdpPort`]'s
//! streams): MSE or plaintext, the BitTorrent handshake, then the messages, handed to the
//! torrent the handshake named.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use flash_core::{Acceptor, Conn, Handler};

use super::ClientInner;
use super::torrent::{Dial, Link, TorrentShared};
use crate::mse::{self, CRYPTO_PLAINTEXT, CRYPTO_RC4, Initiator, Policy, Rc4, Receiver};
use crate::port::{StreamHandler, UtpStream};
use crate::wire::{HANDSHAKE_LEN, Handshake, PROTOCOL, Parser};

enum Phase {
    /// Incoming: not yet known whether MSE or plaintext.
    Detect,
    MseInit(Box<Initiator>),
    MseRecv(Box<Receiver>),
    Handshake,
    Messages,
    Dead,
}

/// One peer connection's protocol, the same over TCP and uTP.
pub(crate) struct Session {
    client: Weak<ClientInner>,
    link: Option<Link>,
    addr: SocketAddr,
    dial: Option<(Dial, Weak<TorrentShared>)>,
    phase: Phase,
    enc: Option<Rc4>,
    dec: Option<Rc4>,
    encrypted: bool,
    sent_handshake: bool,
    expected: Option<crate::metainfo::InfoHash>,
    buf: Vec<u8>,
    parser: Parser,
    torrent: Option<(Arc<TorrentShared>, u64)>,
    got_bytes: bool,
}

impl Session {
    fn new(
        client: Weak<ClientInner>,
        addr: SocketAddr,
        dial: Option<(Dial, Weak<TorrentShared>)>,
    ) -> Session {
        Session {
            client,
            link: None,
            addr,
            dial,
            phase: Phase::Detect,
            enc: None,
            dec: None,
            encrypted: false,
            sent_handshake: false,
            expected: None,
            buf: Vec::new(),
            parser: Parser::default(),
            torrent: None,
            got_bytes: false,
        }
    }

    fn write(&mut self, mut b: Vec<u8>) {
        if let Some(e) = &mut self.enc {
            e.apply(&mut b);
        }
        if let Some(l) = &self.link {
            l.write(b);
        }
    }

    fn raw_write(&self, b: Vec<u8>) {
        if let Some(l) = &self.link {
            l.write(b);
        }
    }

    fn fail(&mut self) {
        self.phase = Phase::Dead;
        if let Some(l) = &self.link {
            l.close();
        }
    }

    /// The link is up: an outgoing connection starts its handshake.
    fn start(&mut self, link: Link) {
        self.link = Some(link);
        let Some(client) = self.client.upgrade() else {
            return self.fail();
        };
        let Some((d, _)) = self.dial.as_ref().map(|(d, t)| (*d, t.clone())) else {
            return; // incoming: wait for the peer
        };
        let Some(t) = self.dial.as_ref().and_then(|(_, t)| t.upgrade()) else {
            return self.fail();
        };
        let hs = Handshake::new(t.info_hash, client.peer_id)
            .encode()
            .to_vec();
        self.expected = Some(t.info_hash);
        self.sent_handshake = true;
        if d.mse {
            let provide = if client.cfg.encryption == Policy::Require {
                CRYPTO_RC4
            } else {
                CRYPTO_RC4 | CRYPTO_PLAINTEXT
            };
            let (i, first) = Initiator::new(t.info_hash, provide, hs);
            self.raw_write(first);
            self.phase = Phase::MseInit(Box::new(i));
        } else {
            self.raw_write(hs);
            self.phase = Phase::Handshake;
        }
    }

    fn on_bytes(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.got_bytes = true;
        }
        match &mut self.phase {
            Phase::Dead => {}
            Phase::Detect => {
                self.buf.extend_from_slice(data);
                let n = self.buf.len().min(PROTOCOL.len());
                if self.buf[..n] == PROTOCOL[..n] {
                    if n < PROTOCOL.len() {
                        return;
                    }
                    let require = self
                        .client
                        .upgrade()
                        .is_some_and(|c| c.cfg.encryption == Policy::Require);
                    if require {
                        return self.fail();
                    }
                    self.phase = Phase::Handshake;
                    let b = std::mem::take(&mut self.buf);
                    self.on_handshake_bytes(&b);
                } else {
                    let accept = match self.client.upgrade().map(|c| c.cfg.encryption) {
                        Some(Policy::Require) => CRYPTO_RC4,
                        _ => CRYPTO_RC4 | CRYPTO_PLAINTEXT,
                    };
                    self.phase = Phase::MseRecv(Box::new(Receiver::new(accept)));
                    let b = std::mem::take(&mut self.buf);
                    self.on_bytes(&b);
                }
            }
            Phase::MseInit(i) => match i.feed(data) {
                Ok(p) => {
                    self.raw_write(p.send);
                    if let Some(done) = p.done {
                        self.encrypted = done.cipher.is_some();
                        if let Some((e, d)) = done.cipher {
                            self.enc = Some(e);
                            self.dec = Some(d);
                        }
                        self.phase = Phase::Handshake;
                        // Already decrypted.
                        self.handshake_plain(&done.data);
                    }
                }
                Err(_) => self.fail(),
            },
            Phase::MseRecv(r) => {
                let Some(client) = self.client.upgrade() else {
                    return self.fail();
                };
                let lookup = |h: &[u8; 20]| client.lookup_req2(h);
                match r.feed(data, &lookup) {
                    Ok(p) => {
                        self.raw_write(p.send);
                        if let Some(done) = p.done {
                            self.encrypted = done.cipher.is_some();
                            if let Some((e, d)) = done.cipher {
                                self.enc = Some(e);
                                self.dec = Some(d);
                            }
                            self.expected = Some(done.info_hash);
                            self.phase = Phase::Handshake;
                            self.handshake_plain(&done.data);
                        }
                    }
                    Err(_) => self.fail(),
                }
            }
            Phase::Handshake => self.on_handshake_bytes(data),
            Phase::Messages => self.on_message_bytes(data),
        }
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut b = data.to_vec();
        if let Some(d) = &mut self.dec {
            d.apply(&mut b);
        }
        b
    }

    fn on_handshake_bytes(&mut self, data: &[u8]) {
        let b = self.decrypt(data);
        self.handshake_plain(&b);
    }

    /// Handshake bytes, already decrypted.
    fn handshake_plain(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
        if self.buf.len() < HANDSHAKE_LEN {
            return;
        }
        let Some(hs) = Handshake::parse(&self.buf) else {
            return self.fail();
        };
        let Some(client) = self.client.upgrade() else {
            return self.fail();
        };
        if self.expected.is_some_and(|e| e != hs.info_hash) {
            return self.fail();
        }
        let Some(t) = client.torrent(&hs.info_hash) else {
            return self.fail();
        };
        if !self.sent_handshake {
            self.sent_handshake = true;
            let ours = Handshake::new(hs.info_hash, client.peer_id)
                .encode()
                .to_vec();
            self.write(ours);
        }
        let Some(link) = self.link.clone() else {
            return self.fail();
        };
        let rest = self.buf.split_off(HANDSHAKE_LEN);
        self.buf.clear();
        let enc = self.enc.take();
        let outgoing = self.dial.is_some();
        let addr = self.dial.as_ref().map_or(self.addr, |(d, _)| d.addr);
        let encrypted = self.encrypted;
        let key = t.with(|st, cx| st.add_peer(link, enc, &hs, addr, outgoing, encrypted, cx));
        let Some(key) = key else { return self.fail() };
        self.torrent = Some((t, key));
        self.phase = Phase::Messages;
        if !rest.is_empty() {
            self.parser.feed(&rest);
            self.drain_messages();
        }
    }

    fn on_message_bytes(&mut self, data: &[u8]) {
        let b = self.decrypt(data);
        self.parser.feed(&b);
        self.drain_messages();
    }

    fn drain_messages(&mut self) {
        let mut msgs = Vec::new();
        loop {
            match self.parser.next_message() {
                Ok(Some(m)) => msgs.push(m),
                Ok(None) => break,
                Err(_) => {
                    self.deliver(msgs);
                    return self.fail();
                }
            }
        }
        self.deliver(msgs);
    }

    fn deliver(&self, msgs: Vec<crate::wire::Message>) {
        if msgs.is_empty() {
            return;
        }
        if let Some((t, key)) = &self.torrent {
            let key = *key;
            t.with(|st, cx| {
                for m in msgs {
                    st.on_message(key, m, cx);
                }
            });
        }
    }

    fn on_close(&mut self) {
        self.phase = Phase::Dead;
        if let Some((t, key)) = self.torrent.take() {
            t.with(|st, cx| st.remove_peer(key, cx));
            return;
        }
        if let Some((d, t)) = &self.dial {
            if let Some(t) = t.upgrade() {
                let mut d = *d;
                // An MSE attempt the peer hung up on is retried in plaintext; uTP falls back to
                // TCP only when nothing came back at all.
                if d.utp && self.got_bytes {
                    d.utp = false;
                }
                t.with(|st, cx| st.dial_failed(d, cx));
            }
        }
    }
}

/// The acceptor of the client's TCP listener.
pub(crate) struct TcpAcceptor {
    pub(crate) client: Arc<std::sync::OnceLock<Weak<ClientInner>>>,
}

/// One TCP peer connection.
pub(crate) struct TcpPeer {
    s: Session,
}

impl Acceptor for TcpAcceptor {
    type Handler = TcpPeer;
    fn on_open(&self, c: &Conn<TcpPeer>) -> TcpPeer {
        let client = self.client.get().cloned().unwrap_or_default();
        let mut s = Session::new(client, c.peer_addr(), None);
        s.start(Link::Tcp(c.inner().clone()));
        TcpPeer { s }
    }
}

impl Handler for TcpPeer {
    fn on_data(&mut self, _c: &Conn<Self>, data: &[u8]) {
        self.s.on_bytes(data);
    }

    fn on_close(&mut self, _c: &Conn<Self>, _err: Option<flash_core::Error>) {
        self.s.on_close();
    }
}

struct DialAcceptor {
    client: Weak<ClientInner>,
    dial: Dial,
    torrent: Weak<TorrentShared>,
}

impl Acceptor for DialAcceptor {
    type Handler = TcpPeer;
    fn on_open(&self, c: &Conn<TcpPeer>) -> TcpPeer {
        let mut s = Session::new(
            self.client.clone(),
            self.dial.addr,
            Some((self.dial, self.torrent.clone())),
        );
        s.start(Link::Tcp(c.inner().clone()));
        TcpPeer { s }
    }
}

/// One uTP peer connection.
pub(crate) struct UtpPeer {
    s: Session,
}

impl UtpPeer {
    pub(crate) fn incoming(client: Weak<ClientInner>, addr: SocketAddr) -> UtpPeer {
        UtpPeer {
            s: Session::new(client, addr, None),
        }
    }
}

impl StreamHandler for UtpPeer {
    fn on_connect(&mut self, s: &UtpStream) {
        self.s.start(Link::Utp(s.clone()));
    }

    fn on_data(&mut self, _s: &UtpStream, data: &[u8]) {
        self.s.on_bytes(data);
    }

    fn on_close(&mut self, _s: &UtpStream, _err: Option<io::ErrorKind>) {
        self.s.on_close();
    }
}

/// Starts a connection a torrent asked for.
pub(crate) fn dial(client: &Arc<ClientInner>, t: &Arc<TorrentShared>, d: Dial) {
    let weak_t = Arc::downgrade(t);
    if d.utp {
        let h = UtpPeer {
            s: Session::new(Arc::downgrade(client), d.addr, Some((d, weak_t))),
        };
        client.port.connect(d.addr, h);
        return;
    }
    let acc = DialAcceptor {
        client: Arc::downgrade(client),
        dial: d,
        torrent: weak_t.clone(),
    };
    client.engine.dial(d.addr, acc, move |_e| {
        // Never inline under the torrent's lock: dials are made after it is released.
        if let Some(t) = weak_t.upgrade() {
            t.with(|st, cx| st.dial_failed(Dial { mse: false, ..d }, cx));
        }
    });
}

/// `HASH('req2', info_hash)`, for a client's lookup table.
pub(crate) fn req2(ih: &crate::metainfo::InfoHash) -> [u8; 20] {
    mse::req2_hash(ih)
}
