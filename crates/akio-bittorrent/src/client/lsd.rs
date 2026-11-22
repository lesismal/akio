//! Local Service Discovery for the client (BEP 14): a thread of its own (never an I/O thread)
//! with a UDP socket on port 6771 joined to the multicast group (IPv4; also IPv6 when the
//! client listens dual-stack). It announces every running public torrent when it is added and
//! then every five minutes, and hands the peers it hears to their torrents.
//!
//! Bounded: announcements are read at most [`MAX_RECV_PER_SEC`] a second (the rest are
//! dropped), each carries at most [`lsd::MAX_INFO_HASHES`](crate::lsd::MAX_INFO_HASHES) hashes,
//! and a torrent is announced at most once a minute.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Weak;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::ClientInner;
use crate::lsd::{Announce, MAX_INFO_HASHES, MAX_MESSAGE, MULTICAST_V4, MULTICAST_V6};
use crate::metainfo::InfoHash;

/// Announce interval per torrent.
pub(crate) const INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Least time between two announcements of one torrent.
pub(crate) const MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Announcements read per second at most.
pub(crate) const MAX_RECV_PER_SEC: u32 = 50;

fn open4() -> io::Result<UdpSocket> {
    let s = akio_sys::listen_udp(SocketAddr::from(([0, 0, 0, 0], MULTICAST_V4.port())), true)?;
    let IpAddr::V4(g) = MULTICAST_V4.ip() else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    s.join_multicast_v4(&g, &Ipv4Addr::UNSPECIFIED)?;
    s.set_multicast_loop_v4(true)?;
    s.set_nonblocking(false)?;
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(s)
}

fn open6() -> io::Result<UdpSocket> {
    let s = akio_sys::listen_udp(
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, MULTICAST_V6.port())),
        true,
    )?;
    let IpAddr::V6(g) = MULTICAST_V6.ip() else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    s.join_multicast_v6(&g, 0)?;
    s.set_multicast_loop_v6(true)?;
    s.set_nonblocking(false)?;
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(s)
}

/// Opens the sockets; `None` (and LSD off) if not even the IPv4 one works.
pub(crate) fn open(v6: bool) -> Option<Vec<UdpSocket>> {
    let mut socks = Vec::new();
    match open4() {
        Ok(s) => socks.push(s),
        Err(_) => return None,
    }
    if v6 {
        if let Ok(s) = open6() {
            socks.push(s);
        }
    }
    Some(socks)
}

/// The thread's loop: runs until the client closes.
pub(crate) fn run(weak: &Weak<ClientInner>, socks: Vec<UdpSocket>) {
    let mut cookie = [0u8; 4];
    crate::rand_fill(&mut cookie);
    let cookie = crate::metainfo::hex(&cookie);
    let groups: Vec<SocketAddr> = socks
        .iter()
        .map(|s| match s.local_addr() {
            Ok(a) if a.is_ipv6() => MULTICAST_V6,
            _ => MULTICAST_V4,
        })
        .collect();
    let mut buf = vec![0u8; MAX_MESSAGE + 1];
    let mut window = Instant::now();
    let mut received = 0u32;
    loop {
        let Some(client) = weak.upgrade() else { return };
        if client.closed.load(Ordering::Relaxed) {
            return;
        }
        // Announce what is due.
        let now = Instant::now();
        let mut due: Vec<InfoHash> = Vec::new();
        for t in client.all() {
            let mut st = t.lock();
            if st.private || !st.running() || !st.lsd_wanted {
                continue;
            }
            let at = st.last_lsd;
            if at.is_none_or(|a| now.duration_since(a) >= INTERVAL)
                || (st.lsd_now && at.is_none_or(|a| now.duration_since(a) >= MIN_INTERVAL))
            {
                st.last_lsd = Some(now);
                st.lsd_now = false;
                due.extend(st.hashes.iter().copied());
            }
        }
        let port = client.listen.port();
        for chunk in due.chunks(MAX_INFO_HASHES) {
            let mut a = Announce::new(port, chunk.to_vec());
            a.cookie = Some(cookie.clone());
            for (s, g) in socks.iter().zip(&groups) {
                let _ = s.send_to(&a.encode(&g.to_string()), g);
            }
        }
        drop(client);
        // Listen, a slice of time on each socket.
        for s in &socks {
            let Ok((n, from)) = s.recv_from(&mut buf) else {
                continue;
            };
            let now = Instant::now();
            if now.duration_since(window) >= Duration::from_secs(1) {
                window = now;
                received = 0;
            }
            received += 1;
            if received > MAX_RECV_PER_SEC {
                continue;
            }
            let Some(a) = Announce::parse(&buf[..n]) else {
                continue;
            };
            if a.cookie.as_deref() == Some(cookie.as_str()) {
                continue; // our own
            }
            let peer = SocketAddr::new(from.ip().to_canonical(), a.port);
            let Some(client) = weak.upgrade() else { return };
            for ih in a.info_hashes {
                if let Some(t) = client.torrent(&ih) {
                    let public = {
                        let st = t.lock();
                        !st.private && st.running() && st.lsd_wanted
                    };
                    if public {
                        t.with(|st, cx| st.add_peers(&[peer], cx));
                    }
                }
            }
        }
    }
}
