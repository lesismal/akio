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

/// Whether a candidate read back from its own SDP has the same address: an active TCP
/// candidate's port is always written as 9 (RFC 6544 §4.5), whatever the line said.
fn same_addr(a: &Candidate, b: &Candidate) -> bool {
    a.addr() == b.addr()
        || (a.tcp_type() == Some(TcpType::Active) && a.addr().ip() == b.addr().ip())
}

fn addr(s: &str) -> SocketAddr {
    s.parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
}

#[cfg(test)]
fn agent(lite: bool, controlling: bool, now: Instant) -> IceAgent {
    agent_with(lite, controlling, false, false, now)
}

/// Component 2 (RTCP without rtcp-mux) of the two-component agents.
const LOCAL_ADDR2: &str = "10.0.0.1:1001";
const REMOTE_ADDR2: &str = "10.0.0.2:2001";

/// `nominating`: aggressive nomination and renomination (both sides) on. `two`: a stream of
/// two components (RTP on the usual addresses, RTCP on the ones above).
fn agent_with(
    lite: bool,
    controlling: bool,
    nominating: bool,
    two: bool,
    now: Instant,
) -> IceAgent {
    let mut c = IceConfig::new(lite, controlling);
    c.local = Credentials::new(LOCAL.0, LOCAL.1);
    c.aggressive_nomination = nominating;
    c.renomination = nominating;
    c.components = if two { 2 } else { 1 };
    let mut a = IceAgent::new(c, now);
    a.set_remote_renomination(nominating);
    a.add_local_candidate(Candidate::host(addr(LOCAL_ADDR)));
    a.set_remote_credentials(Credentials::new(REMOTE.0, REMOTE.1));
    a.add_remote_candidate(Candidate::host(addr(REMOTE_ADDR)));
    if two {
        a.add_local_candidate(Candidate::host(addr(LOCAL_ADDR2)).with_component(2));
        a.add_remote_candidate(Candidate::host(addr(REMOTE_ADDR2)).with_component(2));
    }
    a
}

/// `ice_stun`: arbitrary bytes as a datagram into full controlling, full controlled and lite
/// agents, full ones with aggressive nomination and renomination, and agents of two
/// components (on both components' addresses; remote credentials set, one check in flight),
/// from the known remote addresses and
/// from an unknown one, then timers far into the future; and every line of the input (if
/// UTF-8) through [`Candidate::parse`], whose results must survive an SDP round trip.
pub fn stun(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        for line in s.lines() {
            if let Ok(c) = Candidate::parse(line) {
                let again = Candidate::parse(&c.to_sdp());
                assert!(again.is_ok_and(|d| same_addr(&d, &c)
                    && d.priority() == c.priority()
                    && d.kind() == c.kind()
                    && d.foundation() == c.foundation()));
            }
        }
    }
    let now = Instant::now();
    for (lite, controlling, nominating, two) in [
        (false, true, false, false),
        (false, false, false, false),
        (true, false, false, false),
        (false, true, true, false),
        (false, false, true, false),
        (false, true, false, true),
        (false, false, true, true),
        (true, false, false, true),
    ] {
        let mut a = agent_with(lite, controlling, nominating, two, now);
        a.handle_timeout(now);
        let locals: &[&str] = if two {
            &[LOCAL_ADDR, LOCAL_ADDR2]
        } else {
            &[LOCAL_ADDR]
        };
        for local in locals {
            for src in [
                REMOTE_ADDR,
                REMOTE_ADDR2,
                "10.0.0.3:3000",
                "[2001:db8::3]:3000",
            ] {
                let _ = a.handle_receive(now, addr(src), addr(local), data);
                // RFC 6679's ECN-CHECK echo (ADR-086).
                let _ = a.handle_receive_ecn(now, addr(src), addr(local), data, 1);
            }
        }
        let _ = a.check_ecn(now, 1);
        let _ = a.handle_receive_ecn(now, addr(REMOTE_ADDR), addr(LOCAL_ADDR), data, 3);
        for secs in [1, 10, 40, 100] {
            a.handle_timeout(now + Duration::from_secs(secs));
            let _ = a.poll_timeout();
            while a.poll_transmit_ecn().is_some() {}
            while a.poll_event().is_some() {}
        }
        let _ = (a.send_pair(), a.send_pair_of(2), a.selected_pair_of(2));
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

/// `ice_mdns`: arbitrary bytes as an mDNS message ([`crate::mdns::Message::parse`]): what
/// parses must survive being rebuilt as a response and parsed again (the records and
/// questions whose names can be written), and its authority records as a probe
/// ([`crate::mdns::Message::probe`]) for their first name; and every line (if UTF-8) through
/// [`Candidate::parse_resolved`] with a resolver, whose results must survive an SDP round trip
/// (the name kept).
pub fn mdns(data: &[u8]) {
    use crate::mdns::{MAX_QUESTIONS, MAX_RECORDS, Message, valid_name};
    if let Ok(m) = Message::parse(data) {
        assert!(m.questions.len() <= MAX_QUESTIONS && m.records.len() <= MAX_RECORDS);
        assert!(m.authority.len() <= MAX_RECORDS);
        if let Some(first) = m.authority.first().filter(|r| valid_name(&r.name)) {
            let proposed: Vec<_> = m
                .authority
                .iter()
                .filter(|r| r.name == first.name)
                .cloned()
                .collect();
            let p = Message::probe(&first.name, &proposed).expect("probe of valid records");
            let again = Message::parse(&p).unwrap_or_else(|e| panic!("rebuilt probe refused: {e}"));
            assert!(!again.response && again.records.is_empty());
            assert_eq!(again.questions.len(), 1);
            assert_eq!(again.authority.len(), proposed.len());
            for (a, b) in again.authority.iter().zip(&proposed) {
                assert_eq!((&a.name, a.addr, a.ttl), (&b.name, b.addr, b.ttl));
                assert!(!a.cache_flush);
                let _ = a.tiebreak(b);
            }
        }
        let qs: Vec<_> = m
            .questions
            .iter()
            .filter(|q| valid_name(&q.name))
            .cloned()
            .collect();
        let rs: Vec<_> = m
            .records
            .iter()
            .filter(|r| valid_name(&r.name))
            .cloned()
            .collect();
        let again = Message::parse(&Message::response(m.id, &qs, &rs));
        let again = again.unwrap_or_else(|e| panic!("rebuilt message refused: {e}"));
        assert_eq!(again.id, m.id);
        assert!(again.response);
        assert_eq!(again.records.len(), rs.len());
        assert_eq!(again.questions.len(), qs.len());
        for (a, b) in again.records.iter().zip(&rs) {
            assert_eq!(
                (a.addr, a.ttl, a.cache_flush),
                (b.addr, b.ttl, b.cache_flush)
            );
        }
        for q in &qs {
            let _ = Message::query(&q.name, q.qtype, q.unicast_response);
        }
    }
    if let Ok(s) = std::str::from_utf8(data) {
        for line in s.lines() {
            let ip = std::net::IpAddr::from([192, 168, 7, 9]);
            if let Ok(c) = Candidate::parse_resolved(line, |_| Some(ip)) {
                if let Some(h) = c.hostname() {
                    assert_eq!(c.addr().ip(), ip);
                    let again = Candidate::parse_resolved(&c.to_sdp(), |n| (n == h).then_some(ip));
                    assert!(again.is_ok_and(|d| same_addr(&d, &c) && d.hostname() == Some(h)));
                }
            }
        }
        let _ = crate::mdns::is_mdns_name(s);
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
            // RFC 6679 ECN checks both ways and their echoes (ADR-086).
            let _ = peer.check_ecn(t, 1);
            let _ = me.check_ecn(t, 2);
            for _ in 0..10 {
                while let Some((x, e)) = peer.poll_transmit_ecn() {
                    out.push(x.contents.clone());
                    me.handle_receive_ecn(t, x.source, x.destination, &x.contents, e);
                }
                while let Some((x, e)) = me.poll_transmit_ecn() {
                    out.push(x.contents.clone());
                    peer.handle_receive_ecn(t, x.source, x.destination, &x.contents, e);
                }
                t += Duration::from_millis(100);
                me.handle_timeout(t);
                peer.handle_timeout(t);
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
            "candidate:5 2 udp 2122260222 10.0.0.2 2001 typ host",
        ] {
            out.push(line.as_bytes().to_vec());
        }
        out
    }

    /// Queries and responses as resolvers and responders send them (one question, two,
    /// compressed names, legacy unicast, goodbyes) and mDNS candidate lines.
    pub(super) fn ice_mdns() -> Vec<Vec<u8>> {
        use crate::mdns::{Message, Question, Record, TYPE_A, TYPE_AAAA};
        let name = "4c1fab2e-0d4a-4c11-9e2f-5a6b7c8d9e0f.local";
        let rec = |addr: &str, ttl: u32, cache_flush: bool| Record {
            name: name.to_owned(),
            addr: addr.parse().unwrap_or_else(|_| [0, 0, 0, 0].into()),
            ttl,
            cache_flush,
        };
        let q = |qtype: u16, unicast_response: bool| Question {
            name: name.to_owned(),
            qtype,
            unicast_response,
        };
        let mut out = vec![
            Message::query(name, TYPE_A, false).unwrap_or_default(),
            Message::query(name, TYPE_AAAA, true).unwrap_or_default(),
            Message::response(0, &[], &[rec("192.168.1.20", 120, true)]),
            Message::response(
                0,
                &[],
                &[rec("fe80::1", 120, true), rec("10.0.0.7", 0, false)],
            ),
            Message::response(
                0x4242,
                &[q(TYPE_A, false)],
                &[rec("192.168.1.20", 10, false)],
            ),
            Message::probe(
                name,
                &[rec("192.168.1.20", 120, false), rec("fd00::7", 120, false)],
            )
            .unwrap_or_default(),
        ];
        // As a browser's responder writes it: the name once, then a compression pointer.
        let mut c = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 1];
        for label in name.split('.') {
            c.push(label.len() as u8);
            c.extend_from_slice(label.as_bytes());
        }
        c.push(0);
        c.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 20]);
        c.extend_from_slice(&[0xc0, 12, 0, 28, 0x80, 1, 0, 0, 0, 120, 0, 16]);
        c.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        c.extend_from_slice(&[0xc0, 12, 0, 47, 0x80, 1, 0, 0, 0, 120, 0, 2, 0xc0, 12]);
        out.push(c);
        out.push(
            format!(
                "candidate:1 1 udp 2113937151 {name} 54321 typ host generation 0 ufrag X network-cost 999\n\
                 candidate:2 1 tcp 1518280447 {} 9 typ host tcptype active",
                name.to_uppercase()
            )
            .into_bytes(),
        );
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
    use akio_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "ice_stun", stun) > 0);
        assert!(replay(DIR, "ice_tcp", ice_tcp) > 0);
        assert!(replay(DIR, "ice_mdns", mdns) > 0);
    }

    #[test]
    fn mdns_seeds_run_clean() {
        for s in &seeds::ice_mdns() {
            mdns(s);
            for n in [0, 1, 11, 12, 13, s.len() / 2] {
                mdns(&s[..n.min(s.len())]);
            }
            for i in 0..s.len() {
                let mut m = s.clone();
                m[i] ^= 0x41;
                mdns(&m);
            }
        }
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

    /// Regenerates the seed files: `cargo test -p akio-ice --lib write_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_fuzz_seeds() {
        write_target_seeds(DIR, "ice_stun", &seeds::ice_stun());
        write_target_seeds(DIR, "ice_tcp", &seeds::ice_tcp());
        write_target_seeds(DIR, "ice_mdns", &seeds::ice_mdns());
    }
}
