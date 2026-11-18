//! Fuzz entry points (feature `fuzzing`; not a public API). The `fuzz/` cargo-fuzz project
//! calls them; the unit tests below replay `fuzz/corpus/<target>` on stable.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::tcp::FrameReader;
use crate::{Candidate, Credentials, IceAgent, IceConfig, TcpType};

/// Local credentials of the fuzzed agents (the seeds' requests authenticate against them).
const LOCAL: (&str, &str) = ("fuzz", "fuzzfuzzfuzzfuzzfuzzfuzz");
/// Remote credentials of the fuzzed agents.
const REMOTE: (&str, &str) = ("peer", "peerpeerpeerpeerpeerpeer");
const LOCAL_ADDR: &str = "10.0.0.1:1000";
const REMOTE_ADDR: &str = "10.0.0.2:2000";

fn addr(s: &str) -> SocketAddr {
    s.parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
}

fn agent(lite: bool, controlling: bool, now: Instant) -> IceAgent {
    let mut c = IceConfig::new(lite, controlling);
    c.local = Credentials::new(LOCAL.0, LOCAL.1);
    let mut a = IceAgent::new(c, now);
    a.add_local_candidate(Candidate::host(addr(LOCAL_ADDR)));
    a.set_remote_credentials(Credentials::new(REMOTE.0, REMOTE.1));
    a.add_remote_candidate(Candidate::host(addr(REMOTE_ADDR)));
    a
}

/// `ice_stun`: arbitrary bytes as a datagram into full controlling, full controlled and lite
/// agents (remote credentials set, one check in flight), from the known remote address and
/// from an unknown one, then timers far into the future; and every line of the input (if
/// UTF-8) through [`Candidate::parse`], whose results must survive an SDP round trip.
pub fn stun(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        for line in s.lines() {
            if let Ok(c) = Candidate::parse(line) {
                let again = Candidate::parse(&c.to_sdp());
                assert!(again.is_ok_and(|d| d.addr() == c.addr()
                    && d.priority() == c.priority()
                    && d.kind() == c.kind()
                    && d.foundation() == c.foundation()));
            }
        }
    }
    let now = Instant::now();
    for (lite, controlling) in [(false, true), (false, false), (true, false)] {
        let mut a = agent(lite, controlling, now);
        a.handle_timeout(now);
        for src in [REMOTE_ADDR, "10.0.0.3:3000", "[2001:db8::3]:3000"] {
            let _ = a.handle_receive(now, addr(src), addr(LOCAL_ADDR), data);
        }
        for secs in [1, 10, 40, 100] {
            a.handle_timeout(now + Duration::from_secs(secs));
            let _ = a.poll_timeout();
            while a.poll_transmit().is_some() {}
            while a.poll_event().is_some() {}
        }
        let _ = a.send_pair();
        a.restart(Credentials::new("fuz2", LOCAL.1), true);
        let _ = a.handle_receive(now, addr(REMOTE_ADDR), addr(LOCAL_ADDR), data);
        while a.poll_transmit().is_some() {}
    }
}

const PASSIVE_ADDR: &str = "10.0.0.1:1001";
const ACTIVE_ADDR: &str = "10.0.0.2:50000";

fn tcp_agent(controlling: bool, now: Instant) -> IceAgent {
    let mut c = IceConfig::new(false, controlling);
    c.local = Credentials::new(LOCAL.0, LOCAL.1);
    let mut a = IceAgent::new(c, now);
    a.add_local_candidate(Candidate::host(addr(LOCAL_ADDR)));
    a.add_local_candidate(Candidate::host_tcp(addr(PASSIVE_ADDR), TcpType::Passive));
    a.set_remote_credentials(Credentials::new(REMOTE.0, REMOTE.1));
    a
}

/// `ice_tcp`: an ICE-TCP connection's bytes (the first byte picks the role and a split
/// step), cut into RFC 4571 frames that go to an agent with a passive candidate as if they
/// arrived over that connection; its answers are framed back.
pub fn ice_tcp(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let now = Instant::now();
    let mut a = tcp_agent(sel & 1 == 1, now);
    let mut r = FrameReader::new();
    let step = usize::from(sel >> 1).max(1);
    let mut t = now;
    for chunk in rest.chunks(step) {
        r.push(chunk, |f| {
            let _ = a.handle_receive(t, addr(ACTIVE_ADDR), addr(PASSIVE_ADDR), f);
            true
        });
        assert!(r.buffered() < 2 + crate::tcp::MAX_FRAME);
        t += Duration::from_millis(5);
        a.handle_timeout(t);
        while let Some(x) = a.poll_transmit() {
            // Nothing leaves a passive candidate but answers and triggered checks to the
            // connection's remote end.
            if x.source == addr(PASSIVE_ADDR) {
                assert_eq!(x.destination, addr(ACTIVE_ADDR));
            }
            let _ = crate::tcp::frame(&x.contents);
        }
    }
}

#[cfg(test)]
mod seeds {
    use super::*;

    /// Real check requests a peer sends to the fuzzed agents, the agents' responses and
    /// requests, and a few candidate lines.
    pub(super) fn ice_stun() -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        for (lite, controlling) in [(false, true), (false, false), (true, false)] {
            let mut me = agent(lite, controlling, now);
            let mut pc = IceConfig::new(false, !controlling || lite);
            pc.local = Credentials::new(REMOTE.0, REMOTE.1);
            let mut peer = IceAgent::new(pc, now);
            if lite {
                peer.set_remote_lite(true);
            }
            peer.add_local_candidate(Candidate::host(addr(REMOTE_ADDR)));
            peer.set_remote_credentials(Credentials::new(LOCAL.0, LOCAL.1));
            peer.add_remote_candidate(Candidate::host(addr(LOCAL_ADDR)));
            let mut t = now;
            for _ in 0..60 {
                me.handle_timeout(t);
                peer.handle_timeout(t);
                while let Some(x) = peer.poll_transmit() {
                    out.push(x.contents.clone());
                    me.handle_receive(t, x.source, x.destination, &x.contents);
                }
                while let Some(x) = me.poll_transmit() {
                    out.push(x.contents.clone());
                    peer.handle_receive(t, x.source, x.destination, &x.contents);
                }
                t += Duration::from_millis(20);
            }
        }
        out.sort();
        out.dedup();
        for line in [
            "candidate:842163049 1 udp 1677729535 203.0.113.7 61665 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag EsAw network-id 1 network-cost 10",
            "a=candidate:1 1 UDP 2122260223 2001:db8::1 5000 typ host",
            "candidate:2 1 udp 41885439 198.51.100.9 3478 typ relay raddr 203.0.113.7 rport 61665",
            "candidate:3 1 tcp 1518280447 192.168.1.2 9 typ host tcptype active",
            "candidate:4 1 udp 2122260223 4c1f-ab.local 5000 typ host",
        ] {
            out.push(line.as_bytes().to_vec());
        }
        out
    }

    /// A real active agent's checks over the connection, framed, both roles.
    pub(super) fn ice_tcp() -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut out = Vec::new();
        for controlling in [false, true] {
            let mut me = tcp_agent(controlling, now);
            let mut pc = IceConfig::new(false, !controlling);
            pc.local = Credentials::new(REMOTE.0, REMOTE.1);
            let mut peer = IceAgent::new(pc, now);
            peer.add_local_candidate(Candidate::host_tcp(addr(ACTIVE_ADDR), TcpType::Active));
            peer.set_remote_credentials(Credentials::new(LOCAL.0, LOCAL.1));
            peer.add_remote_candidate(Candidate::host_tcp(addr(PASSIVE_ADDR), TcpType::Passive));
            let mut stream = Vec::new();
            let mut t = now;
            for _ in 0..40 {
                me.handle_timeout(t);
                peer.handle_timeout(t);
                while let Some(x) = peer.poll_transmit() {
                    stream.extend(crate::tcp::frame(&x.contents).unwrap_or_default());
                    me.handle_receive(t, x.source, x.destination, &x.contents);
                }
                while let Some(x) = me.poll_transmit() {
                    peer.handle_receive(t, x.source, x.destination, &x.contents);
                }
                t += Duration::from_millis(5);
            }
            for step in [1u8, 7, 255] {
                let sel = (step << 1) | u8::from(controlling);
                out.push([&[sel][..], &stream].concat());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "ice_stun", stun) > 0);
        assert!(replay(DIR, "ice_tcp", ice_tcp) > 0);
    }

    #[test]
    fn tcp_seeds_run_clean() {
        for s in &seeds::ice_tcp() {
            ice_tcp(s);
            ice_tcp(&s[..s.len() / 2]);
        }
    }

    #[test]
    fn seeds_run_clean() {
        let seeds = seeds::ice_stun();
        assert!(seeds.len() > 10);
        for s in &seeds {
            stun(s);
        }
        // Truncations and bit flips of every seed.
        for s in &seeds {
            for n in [0, 1, 19, 20, 21, s.len() / 2, s.len().saturating_sub(4)] {
                stun(&s[..n.min(s.len())]);
            }
            for i in (0..s.len()).step_by(3) {
                let mut m = s.clone();
                m[i] ^= 0x41;
                stun(&m);
            }
        }
    }

    /// Regenerates the seed files: `cargo test -p only-ice --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "ice_stun", &seeds::ice_stun());
        write_target_seeds(DIR, "ice_tcp", &seeds::ice_tcp());
    }
}
