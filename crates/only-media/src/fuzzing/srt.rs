//! SRT and MPEG-TS fuzz entry points.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use only_core::fuzzing::split;

use crate::{
    mpegts::demux::{Demuxer, Event},
    srt::{Config, Conn, Event as SrtEvent, Listener, StreamId},
};

/// `mpegts_demux`: the MPEG-TS demuxer fed in pieces (`data[0]` seeds the piece sizes, see
/// `only_core::fuzzing::split`). Checks that packets only come after tracks and index them.
pub fn mpegts_demux(data: &[u8]) {
    let mut d = Demuxer::new();
    let mut tracks = 0usize;
    let mut emit = |e: Event| match e {
        Event::Tracks(t) => tracks = t.len(),
        Event::Packet(p) => assert!(p.track < tracks, "packet before or outside its tracks"),
    };
    for p in split(data) {
        let _ = d.feed(p, &mut emit);
    }
    d.flush(&mut emit);
}

/// Datagrams of a fuzz input: 2-byte big-endian length prefixes (a short last one takes the
/// rest).
fn datagrams(mut b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while b.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([b[0], b[1]])).min(b.len() - 2);
        out.push(&b[2..2 + n]);
        b = &b[2 + n..];
    }
    out
}

const PASS: &str = "fuzz-passphrase";

/// `srt_listener`: the listener's handshake parsing (induction, cookie, conclusion with its
/// HSREQ, KMREQ and stream ID extensions), then the accepted connection fed the remaining
/// datagrams. `data[0]` bit 0 requires a passphrase; the rest is length-prefixed datagrams.
/// The cookie is checked, so conclusions only get through in seeds that start with an
/// induction... which a fuzzer cannot complete: the cookie answer is replayed for it, by
/// patching the conclusion's cookie field with the one the induction got.
pub fn srt_listener(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let mut l = Listener::new();
    let from: SocketAddr = "192.0.2.1:9000"
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0; 4], 0)));
    let now = Instant::now();
    let mut cookie = None;
    let mut conn: Option<Conn> = None;
    for (i, d) in datagrams(rest).into_iter().enumerate() {
        let t = now + Duration::from_millis(i as u64 * 7);
        if let Some(c) = conn.as_mut() {
            c.handle(d, t);
            c.handle_timeout(t + Duration::from_millis(20));
            let _ = c.take_output();
            while c.poll_event().is_some() {}
            continue;
        }
        let mut d = d.to_vec();
        if let Some(ck) = cookie {
            if d.len() >= 16 + 32 {
                d[16 + 28..16 + 32].copy_from_slice(&u32::to_be_bytes(ck));
            }
        }
        let mut out = Vec::new();
        conn = l.handle(&d, from, t, &mut out, |req| {
            let _ = StreamId::parse(&req.stream_id);
            let mut c = Config::default();
            if cfg & 1 == 1 {
                c.passphrase = Some(PASS.into());
            }
            Ok(c)
        });
        for o in out {
            // The induction response carries the cookie at offset 16 + 28.
            if o.len() >= 48 + 16 && o[16 + 20..16 + 24] == [0, 0, 0, 1] {
                cookie = Some(u32::from_be_bytes([o[44], o[45], o[46], o[47]]));
            }
        }
    }
}

/// `srt_conn`: a connected listener-side connection (set up by a real in-memory handshake,
/// encrypted when `data[0]` bit 0 is set) fed length-prefixed datagrams whose destination
/// socket ID is patched to its own, so data, ACK, NAK, ACKACK, DROPREQ, SHUTDOWN and key
/// refresh packets all reach their handlers; timers run between them.
pub fn srt_conn(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let now = Instant::now();
    let mut cc = Config::default().stream_id("live/s");
    if cfg & 1 == 1 {
        cc.passphrase = Some(PASS.into());
    }
    let Ok(mut caller) = Conn::caller(cc, now) else {
        return;
    };
    let mut l = Listener::new();
    let from: SocketAddr = "192.0.2.1:9000"
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0; 4], 0)));
    let mut server = None;
    for _ in 0..4 {
        for d in caller.take_output() {
            let mut out = Vec::new();
            if let Some(c) = l.handle(&d, from, now, &mut out, |_| {
                let mut c = Config::default();
                if cfg & 1 == 1 {
                    c.passphrase = Some(PASS.into());
                }
                Ok(c)
            }) {
                server = Some(c);
            }
            for o in out {
                caller.handle(&o, now);
            }
        }
    }
    let Some(mut s) = server else { return };
    let id = s.socket_id.to_be_bytes();
    for (i, d) in datagrams(rest).into_iter().enumerate() {
        let t = now + Duration::from_millis(i as u64 * 3);
        let mut d = d.to_vec();
        if d.len() >= 16 {
            d[12..16].copy_from_slice(&id);
        }
        s.handle(&d, t);
        if i % 4 == 3 {
            s.handle_timeout(t + Duration::from_millis(15));
        }
        let _ = s.write(&d, t);
        for o in s.take_output() {
            caller.handle(&o, t);
        }
        while let Some(e) = s.poll_event() {
            if matches!(e, SrtEvent::Closed(_)) {
                return;
            }
        }
    }
}

/// The rendezvous cookies of [`srt_rendezvous`]: the fuzzed side's (initiator or responder
/// against the recorded peer's [`RDV_PEER_COOKIE`]).
const RDV_COOKIES: [u32; 2] = [0x0000_ffff, 0xffff_0000];
/// The cookie of the peer whose datagrams the seeds recorded.
#[cfg(test)]
const RDV_PEER_COOKIE: u32 = 0x8000_0000;

/// `srt_rendezvous`: a rendezvous connection fed length-prefixed datagrams from its peer:
/// waves, conclusions (HSREQ / HSRSP, KMREQ / KMRSP), agreements, rejections and, once
/// connected, everything else (their destination socket ID patched to its own). `data[0]` bit
/// 0 sets a passphrase, bit 1 picks the cookie that makes this side the initiator (against
/// the seeds' peer). Timers run between datagrams and the side writes a payload after each.
pub fn srt_rendezvous(data: &[u8]) {
    let Some((&cfg, rest)) = data.split_first() else {
        return;
    };
    let now = Instant::now();
    let mut c = Config::default();
    if cfg & 1 == 1 {
        c.passphrase = Some(PASS.into());
    }
    let peer: SocketAddr = "192.0.2.1:9000"
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0; 4], 0)));
    let Ok(mut s) = Conn::rendezvous(c, peer, now) else {
        return;
    };
    s.set_rendezvous_cookie(RDV_COOKIES[usize::from(cfg >> 1 & 1)]);
    let id = s.socket_id.to_be_bytes();
    for (i, d) in datagrams(rest).into_iter().enumerate() {
        let t = now + Duration::from_millis(i as u64 * 3);
        let mut d = d.to_vec();
        // Control packets other than handshakes, and data, get our socket ID.
        let handshake = d.len() >= 4 && d[0] & 0x80 != 0 && d[1] == 0 && d[0] & 0x7f == 0;
        if d.len() >= 16 && !handshake {
            d[12..16].copy_from_slice(&id);
        }
        s.handle(&d, t);
        if i % 3 == 2 {
            s.handle_timeout(t + Duration::from_millis(260));
        }
        let _ = s.write(&[i as u8; 64], t);
        let _ = s.take_output();
        while let Some(e) = s.poll_event() {
            if matches!(e, SrtEvent::Closed(_)) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::fuzzing::{replay, write_target_seeds};

    const DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn lp(ds: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        for d in ds {
            v.extend_from_slice(&(d.len() as u16).to_be_bytes());
            v.extend_from_slice(d);
        }
        v
    }

    /// Real datagrams of a caller-listener exchange with data and a loss, both directions.
    fn exchange(pass: bool) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let now = Instant::now();
        let mut cc = Config::default().stream_id("#!::r=live/s,m=publish");
        if pass {
            cc.passphrase = Some(PASS.into());
        }
        let mut caller = Conn::caller(cc, now).unwrap();
        let mut l = Listener::new();
        let from: SocketAddr = "192.0.2.1:9000".parse().unwrap();
        let mut to_server = Vec::new();
        let mut to_caller = Vec::new();
        let mut server = None;
        for _ in 0..3 {
            for d in caller.take_output() {
                to_server.push(d.clone());
                let mut out = Vec::new();
                if let Some(c) = l.handle(&d, from, now, &mut out, |_| {
                    let mut c = Config::default();
                    if pass {
                        c.passphrase = Some(PASS.into());
                    }
                    Ok(c)
                }) {
                    server = Some(c);
                }
                for o in out {
                    to_caller.push(o.clone());
                    caller.handle(&o, now);
                }
            }
        }
        let mut s = server.unwrap();
        for i in 0..20u8 {
            let t = now + Duration::from_millis(u64::from(i) * 5);
            caller.write(&[i; 188], t).unwrap();
            for d in caller.take_output() {
                to_server.push(d.clone());
                if i != 7 {
                    s.handle(&d, t);
                }
            }
            s.handle_timeout(t + Duration::from_millis(11));
            for d in s.take_output() {
                to_caller.push(d.clone());
                caller.handle(&d, t);
            }
        }
        caller.close(now + Duration::from_millis(200));
        to_server.extend(caller.take_output());
        (to_server, to_caller)
    }

    /// AV1 + Opus muxed into MPEG-TS (the start-code format) from the sample FLV.
    fn av1_ts() -> Vec<u8> {
        use crate::flv::{Decoder, Demuxer as FlvDemuxer, Event as FlvEvent};
        let data = std::fs::read(format!("{DIR}/testdata/av1_opus.flv")).unwrap();
        let mut dec = Decoder::new();
        let (mut tracks, mut pkts) = (None, Vec::new());
        for t in FlvDemuxer::new().feed(&data).unwrap() {
            for e in dec.write(t.tag_type, t.ts, &t.body) {
                match e {
                    FlvEvent::Tracks(t) => tracks = Some(t),
                    FlvEvent::Packet(p) => pkts.push(p),
                }
            }
        }
        let mut m = crate::mpegts::Muxer::new(&tracks.unwrap());
        let mut ts = Vec::new();
        m.write_tables(&mut ts);
        for p in &pkts {
            m.write_packet(p, &mut ts);
        }
        ts
    }

    fn ts_seeds() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        let mut files = Vec::new();
        for f in ["h264_aac.ts", "h265_opus.ts"] {
            files.push(std::fs::read(format!("{DIR}/testdata/{f}")).unwrap());
        }
        files.push(av1_ts());
        for b in files {
            for (seed, len) in [(0u8, 188 * 60), (97, 188 * 40), (200, 188 * 25)] {
                let mut s = vec![seed];
                s.extend_from_slice(&b[..len.min(b.len())]);
                v.push(s);
            }
        }
        v
    }

    /// The peer's datagrams of a rendezvous with the fuzzed side (role `initiator`), and data
    /// after it.
    fn rendezvous_seed(pass: bool, initiator: bool) -> Vec<u8> {
        let now = Instant::now();
        let mk = || {
            let mut c = Config::default();
            if pass {
                c.passphrase = Some(PASS.into());
            }
            c
        };
        let addr: SocketAddr = "192.0.2.1:9000".parse().unwrap();
        let mut a = Conn::rendezvous(mk(), addr, now).unwrap();
        a.set_rendezvous_cookie(RDV_COOKIES[usize::from(initiator)]);
        let mut b = Conn::rendezvous(mk(), addr, now).unwrap();
        b.set_rendezvous_cookie(RDV_PEER_COOKIE);
        let mut to_a = Vec::new();
        for i in 0..40u8 {
            let t = now + Duration::from_millis(u64::from(i) * 5);
            for d in a.take_output() {
                b.handle(&d, t);
            }
            for d in b.take_output() {
                to_a.push(d.clone());
                a.handle(&d, t);
            }
            if b.state() == crate::srt::State::Connected && i % 2 == 0 {
                let _ = b.write(&[i; 100], t);
            }
            a.handle_timeout(t);
            b.handle_timeout(t);
        }
        assert_eq!(a.state(), crate::srt::State::Connected);
        assert!(!a.is_rendezvous());
        let mut s = vec![u8::from(pass) | u8::from(initiator) << 1];
        s.extend(lp(&to_a));
        s
    }

    fn rendezvous_seeds() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for pass in [false, true] {
            for initiator in [false, true] {
                v.push(rendezvous_seed(pass, initiator));
            }
        }
        v
    }

    fn listener_seeds() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for pass in [false, true] {
            let (to_server, _) = exchange(pass);
            let mut s = vec![u8::from(pass)];
            s.extend(lp(&to_server[..to_server.len().min(12)]));
            v.push(s);
        }
        v
    }

    fn conn_seeds() -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for pass in [false, true] {
            let (to_server, to_caller) = exchange(pass);
            let mut s = vec![u8::from(pass)];
            s.extend(lp(&to_server[2..]));
            v.push(s);
            let mut s = vec![u8::from(pass)];
            s.extend(lp(&to_caller[2..]));
            v.push(s);
        }
        v
    }

    #[test]
    fn replay_corpora() {
        assert!(replay(DIR, "mpegts_demux", mpegts_demux) > 0);
        assert!(replay(DIR, "srt_listener", srt_listener) > 0);
        assert!(replay(DIR, "srt_conn", srt_conn) > 0);
        assert!(replay(DIR, "srt_rendezvous", srt_rendezvous) > 0);
    }

    #[test]
    fn seeds_run_clean() {
        for s in ts_seeds() {
            mpegts_demux(&s);
        }
        for s in listener_seeds() {
            srt_listener(&s);
        }
        for s in conn_seeds() {
            srt_conn(&s);
        }
        for s in rendezvous_seeds() {
            srt_rendezvous(&s);
        }
        srt_rendezvous(&[3, 0, 1]);
        srt_conn(&[]);
        srt_listener(&[1, 0]);
        mpegts_demux(&[3, 0x47, 0x40]);
    }

    /// Regenerates the seed files: `cargo test -p only-media --lib write_srt_fuzz_seeds -- --ignored`.
    #[test]
    #[ignore]
    fn write_srt_fuzz_seeds() {
        write_target_seeds(DIR, "mpegts_demux", &ts_seeds());
        write_target_seeds(DIR, "srt_listener", &listener_seeds());
        write_target_seeds(DIR, "srt_conn", &conn_seeds());
        write_target_seeds(DIR, "srt_rendezvous", &rendezvous_seeds());
    }
}
