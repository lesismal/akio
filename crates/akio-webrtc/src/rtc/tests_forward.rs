//! An SFU's peers in simulated time (ADR-187): the ICE consent timeouts.

use super::*;
use crate::SdpChanges;

const TICK: Duration = Duration::from_millis(5);

struct Node {
    rtc: Rtc,
    addr: SocketAddr,
    events: Vec<RtcEvent>,
    wake: Instant,
}

type DropFn = Box<dyn FnMut(SocketAddr, SocketAddr, &[u8]) -> bool>;

/// Peers on one simulated network: every datagram takes 10 ms unless `drop` takes it.
struct World {
    nodes: Vec<Node>,
    queue: Vec<(Instant, SocketAddr, SocketAddr, Vec<u8>)>,
    now: Instant,
    drop: DropFn,
}

impl World {
    fn new() -> World {
        World {
            nodes: Vec::new(),
            queue: Vec::new(),
            now: Instant::now(),
            drop: Box::new(|_, _, _| false),
        }
    }

    fn add(&mut self, rtc: Rtc) -> usize {
        let n = self.nodes.len();
        let addr = SocketAddr::from(([10, 0, 0, n as u8 + 1], 1000));
        self.nodes.push(Node {
            rtc,
            addr,
            events: Vec::new(),
            wake: self.now,
        });
        n
    }

    /// An offerer (full ICE) with `off` and an ICE-lite answerer with `ans`; the offer made
    /// by `f` and edited by `edit`.
    fn link<R>(
        &mut self,
        off: ConfigInner,
        ans: ConfigInner,
        f: impl FnOnce(&mut SdpChanges<'_, '_>) -> R,
        edit: impl Fn(String) -> String,
    ) -> (usize, usize, R) {
        let now = self.now;
        let mut a = Rtc::new(off, false, now).unwrap();
        let mut b = Rtc::new(ans, true, now).unwrap();
        let (ia, ib) = (self.add_placeholder(), self.add_placeholder());
        a.add_local_candidate(IceCandidate::host(self.nodes[ia].addr));
        b.add_local_candidate(IceCandidate::host(self.nodes[ib].addr));
        let mut ch = a.changes();
        let r = f(&mut SdpChanges(&mut ch));
        let offer = edit(a.apply(now, ch).unwrap().unwrap());
        let answer = b.accept_offer(now, &offer).unwrap();
        a.accept_answer(now, &answer).unwrap();
        self.nodes[ia].rtc = a;
        self.nodes[ib].rtc = b;
        (ia, ib, r)
    }

    fn add_placeholder(&mut self) -> usize {
        let rtc = Rtc::new(ConfigInner::default(), true, self.now).unwrap();
        self.add(rtc)
    }

    fn step(&mut self) {
        self.now += TICK;
        let now = self.now;
        let (due, keep): (Vec<_>, Vec<_>) = self.queue.drain(..).partition(|x| x.0 <= now);
        self.queue = keep;
        for (_, from, to, d) in due {
            if let Some(n) = self.nodes.iter_mut().find(|n| n.addr == to) {
                n.rtc.handle_receive(now, from, to, &d);
            }
        }
        for i in 0..self.nodes.len() {
            if self.nodes[i].wake <= now {
                self.nodes[i].rtc.handle_timeout(now);
            }
            self.drain(i);
        }
    }

    fn drain(&mut self, i: usize) {
        let now = self.now;
        loop {
            let n = &mut self.nodes[i];
            match n.rtc.poll_output(now) {
                Output::Timeout(t) => {
                    n.wake = t;
                    break;
                }
                Output::Transmit(_, to, d, _) => {
                    let from = n.addr;
                    if !(self.drop)(from, to, &d) {
                        self.queue
                            .push((now + Duration::from_millis(10), from, to, d));
                    }
                }
                Output::Event(e) => n.events.push(e),
            }
        }
    }

    fn take(&mut self, i: usize) -> Vec<RtcEvent> {
        std::mem::take(&mut self.nodes[i].events)
    }

    fn until(&mut self, what: &str, mut f: impl FnMut(&World) -> bool) {
        let start = self.now;
        while !f(self) {
            self.step();
            assert!(self.now - start < Duration::from_secs(30), "{what}");
        }
    }
}

fn consent_world(timeouts: Option<(Duration, Duration)>) -> (World, usize, usize) {
    let mut w = World::new();
    // Both sides: the full agent then checks consent often enough for the timeouts.
    let cfg = || ConfigInner {
        ice_timeouts: timeouts,
        ..ConfigInner::default()
    };
    let (a, b, ()) = w.link(
        cfg(),
        cfg(),
        |api| {
            api.add_channel("c");
        },
        |o| o,
    );
    w.until("connected", |w| {
        w.nodes.iter().all(|n| n.rtc.is_connected())
    });
    w.take(b);
    (w, a, b)
}

fn ice_states(
    w: &mut World,
    b: usize,
    at: &mut Vec<(IceConnectionState, Duration)>,
    from: Instant,
) {
    for e in w.take(b) {
        if let RtcEvent::IceState(s) = e {
            at.push((s, w.now - from));
        }
    }
}

#[test]
fn consent_lost_is_disconnected_then_failed() {
    let (mut w, _a, b) = consent_world(Some((Duration::from_secs(2), Duration::from_secs(5))));
    assert!(w.nodes[b].rtc.fails_after_disconnect());
    // The remote goes silent.
    w.drop = Box::new(|_, _, _| true);
    let cut = w.now;
    let mut states = Vec::new();
    while w.now - cut < Duration::from_secs(8) {
        w.step();
        ice_states(&mut w, b, &mut states, cut);
    }
    let kinds: Vec<IceConnectionState> = states.iter().map(|s| s.0).collect();
    assert_eq!(
        kinds,
        [IceConnectionState::Disconnected, IceConnectionState::Failed]
    );
    // Disconnected 2 s after the last check (which came up to the full agent's interval
    // before the cut), Failed 3 s after that.
    assert!(states[0].1 <= Duration::from_secs(2) + TICK, "{states:?}");
    let wait = states[1].1.saturating_sub(states[0].1);
    assert!(
        wait >= Duration::from_secs(3) && wait <= Duration::from_secs(3) + TICK,
        "{states:?}"
    );
}

#[test]
fn consent_back_before_failed() {
    let (mut w, _a, b) = consent_world(Some((Duration::from_secs(2), Duration::from_secs(20))));
    w.drop = Box::new(|_, _, _| true);
    let cut = w.now;
    let mut states = Vec::new();
    w.until("disconnected", |w| {
        w.nodes[b]
            .events
            .iter()
            .any(|e| matches!(e, RtcEvent::IceState(IceConnectionState::Disconnected)))
    });
    ice_states(&mut w, b, &mut states, cut);
    w.drop = Box::new(|_, _, _| false);
    while w.now - cut < Duration::from_secs(25) {
        w.step();
        ice_states(&mut w, b, &mut states, cut);
    }
    let kinds: Vec<IceConnectionState> = states.iter().map(|s| s.0).collect();
    assert_eq!(kinds[0], IceConnectionState::Disconnected);
    assert!(
        kinds[1..].iter().all(|k| matches!(
            k,
            IceConnectionState::Connected | IceConnectionState::Completed
        )),
        "{kinds:?}"
    );
    assert!(kinds.len() >= 2);
}

#[test]
fn consent_without_failed_timeout_is_disconnected_only() {
    // A failed timeout not past the disconnected one: Disconnected, as without the setting.
    let (mut w, _a, b) = consent_world(Some((Duration::from_secs(2), Duration::from_secs(2))));
    assert!(!w.nodes[b].rtc.fails_after_disconnect());
    w.drop = Box::new(|_, _, _| true);
    let cut = w.now;
    let mut states = Vec::new();
    while w.now - cut < Duration::from_secs(6) {
        w.step();
        ice_states(&mut w, b, &mut states, cut);
    }
    let kinds: Vec<IceConnectionState> = states.iter().map(|s| s.0).collect();
    assert_eq!(kinds, [IceConnectionState::Disconnected]);
}

#[test]
fn receive_cap_told_as_remb() {
    let mut w = World::new();
    let (p, s, (audio, video)) = w.link(
        ConfigInner::default(),
        ConfigInner::default(),
        |api| {
            (
                api.add_media(MediaKind::Audio, Direction::SendOnly, None, None),
                api.add_media(MediaKind::Video, Direction::SendOnly, None, None),
            )
        },
        |o| o,
    );
    w.until("connected", |w| {
        w.nodes.iter().all(|n| n.rtc.is_connected())
    });
    let ssrc = |mid: Mid| {
        w.nodes[p]
            .rtc
            .media
            .iter()
            .find(|l| l.mid == mid)
            .unwrap()
            .send
            .ssrc()
    };
    let (sa, sv) = (ssrc(audio), ssrc(video));
    let opus = w.nodes[p].rtc.payload_type(audio, Codec::Opus).unwrap();
    let vp8 = w.nodes[p].rtc.payload_type(video, Codec::Vp8).unwrap();
    let mut rembs: Vec<(Duration, u64, Vec<u32>)> = Vec::new();
    let start = w.now;
    let run = |w: &mut World, secs: u64, rembs: &mut Vec<(Duration, u64, Vec<u32>)>| {
        let until = w.now + Duration::from_secs(secs);
        let mut i = 0u64;
        while w.now < until {
            let now = w.now;
            let t = MediaTime::new(i * 960, Frequency::FORTY_EIGHT_KHZ);
            w.nodes[p]
                .rtc
                .write_media(now, audio, None, opus, t, &[0xfc, 1, 2])
                .unwrap();
            let t = MediaTime::new(i * 1800, Frequency::NINETY_KHZ);
            w.nodes[p]
                .rtc
                .write_media(now, video, None, vp8, t, &[0x10, 0, 0, 1])
                .unwrap();
            i += 1;
            for _ in 0..4 {
                w.step();
            }
            for e in w.take(p) {
                if let RtcEvent::Other(Other::RemoteBitrateEstimate { bitrate, ssrcs }) = e {
                    rembs.push((w.now - start, bitrate, ssrcs));
                }
            }
        }
    };
    run(&mut w, 1, &mut rembs);
    assert!(rembs.is_empty(), "no cap, no REMB: {rembs:?}");
    // The cap goes out at once, then once a second, about both streams received.
    w.nodes[s].rtc.set_receive_bitrate_cap(Some(250_000));
    let set = w.now - start;
    run(&mut w, 3, &mut rembs);
    assert!(rembs.len() >= 3, "{rembs:?}");
    assert!(
        rembs[0].0.saturating_sub(set) <= Duration::from_millis(30),
        "at once: {rembs:?}"
    );
    for (_, b, ssrcs) in &rembs {
        assert_eq!(*b, 250_000);
        assert_eq!(ssrcs, &{
            let mut v = vec![sa, sv];
            v.sort_unstable();
            v
        });
    }
    // None: no more.
    w.nodes[s].rtc.set_receive_bitrate_cap(None);
    rembs.clear();
    run(&mut w, 2, &mut rembs);
    assert!(
        rembs.len() <= 1,
        "at most one already on its way: {rembs:?}"
    );
}
