//! Interop with libnice over real loopback UDP sockets with a stream of two components (RTP
//! and RTCP without rtcp-mux; ignored by default).
//!
//! Needs the libnice peer of `tools/interop/ice/nicepeer.c` (one stream of two components,
//! a line protocol on stdin/stdout described there), given by `ONLY_ICE_NICE_PEER`;
//! `tools/interop/ice/run.sh` builds it in a Debian container and runs these tests:
//!
//! ```text
//! ONLY_ICE_NICE_PEER=/path/to/nicepeer cargo test -p only-ice --test libnice -- --ignored
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use only_ice::{Candidate, Credentials, IceAgent, IceConfig, IceEvent, IceState};

#[derive(Clone, Copy)]
struct Setup {
    we_lite: bool,
    we_controlling: bool,
    nice_lite: bool,
    /// libnice controlling with regular nomination (its default is aggressive).
    nice_regular: bool,
}

fn session(s: Setup) {
    let Ok(peer) = std::env::var("ONLY_ICE_NICE_PEER") else {
        eprintln!("ONLY_ICE_NICE_PEER not set: skipped");
        return;
    };
    let mut cmd = Command::new(peer);
    if !s.we_controlling && !s.nice_lite {
        cmd.arg("-controlling");
    }
    if s.nice_lite {
        cmd.arg("-lite");
    }
    if s.nice_regular {
        cmd.arg("-regular");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn libnice peer");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            eprintln!("nice: {line}");
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut creds = None;
    let mut cands = Vec::new();
    loop {
        let line = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("libnice output");
        if let Some(c) = line.strip_prefix("CRED ") {
            let f: Vec<&str> = c.split_whitespace().collect();
            creds = Some(Credentials::new(f[0], f[1]));
        } else if let Some(c) = line.strip_prefix("CAND ") {
            cands.push(Candidate::parse(c).expect("libnice candidate parses"));
        } else if line == "GATHERED" {
            break;
        }
    }
    assert!(cands.iter().any(|c| c.component() == 2), "{cands:?}");
    // One socket per component.
    let socks = [
        UdpSocket::bind("127.0.0.1:0").unwrap(),
        UdpSocket::bind("127.0.0.1:0").unwrap(),
    ];
    let locals: Vec<SocketAddr> = socks.iter().map(|s| s.local_addr().unwrap()).collect();
    for s in &socks {
        s.set_nonblocking(true).unwrap();
    }
    let start = Instant::now();
    let mut config = IceConfig::new(s.we_lite, s.we_controlling);
    config.components = 2;
    let mut agent = IceAgent::new(config, start);
    if s.nice_lite {
        agent.set_remote_lite(true);
    }
    for (c, l) in [1u16, 2].into_iter().zip(&locals) {
        assert!(agent.add_local_candidate(Candidate::host(*l).with_component(c)));
    }
    let mine = agent.local_credentials().clone();
    writeln!(stdin, "CRED {} {}", mine.ufrag, mine.pwd).unwrap();
    for c in agent.local_candidates() {
        writeln!(stdin, "CAND {}", c.to_sdp()).unwrap();
    }
    writeln!(stdin, "GO").unwrap();
    agent.set_remote_credentials(creds.expect("libnice credentials"));
    for c in cands {
        agent.add_remote_candidate(c);
    }
    agent.end_of_remote_candidates();

    let mut buf = [0u8; 2048];
    // Application data received per component.
    let mut app: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    let mut nice: Vec<String> = Vec::new();
    let mut states = Vec::new();
    let mut pinged = [false; 2];
    let deadline = start + Duration::from_secs(16);
    while Instant::now() < deadline {
        let now = Instant::now();
        agent.handle_timeout(now);
        while let Some(t) = agent.poll_transmit() {
            let i = locals
                .iter()
                .position(|l| *l == t.source)
                .expect("our socket");
            socks[i].send_to(&t.contents, t.destination).unwrap();
        }
        while let Some(e) = agent.poll_event() {
            eprintln!("only: {e:?}");
            if let IceEvent::StateChanged(s) = e {
                states.push(s);
            }
        }
        for c in [1u16, 2] {
            let i = usize::from(c - 1);
            if !pinged[i] {
                if let Some((src, dst)) = agent.send_pair_of(c) {
                    assert_eq!(src, locals[i]);
                    socks[i]
                        .send_to(format!("ping-{c}").as_bytes(), dst)
                        .unwrap();
                    pinged[i] = true;
                }
            }
        }
        while let Ok(l) = rx.try_recv() {
            nice.push(l);
        }
        let mut got = false;
        for (i, sock) in socks.iter().enumerate() {
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                got = true;
                if !agent.handle_receive(Instant::now(), from, locals[i], &buf[..n]) {
                    app[i].push(String::from_utf8_lossy(&buf[..n]).into_owned());
                }
            }
        }
        if !got {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    writeln!(stdin, "QUIT").ok();
    let _ = child.wait();
    eprintln!("states {states:?} app {app:?}");
    assert!(matches!(
        agent.state(),
        IceState::Completed | IceState::Connected
    ));
    assert!(!states.contains(&IceState::Disconnected));
    assert!(!states.contains(&IceState::Failed));
    for c in [1u16, 2] {
        let i = usize::from(c - 1);
        let (l, _) = agent.selected_pair_of(c).expect("selected");
        assert_eq!(l, locals[i]);
        assert!(app[i].contains(&format!("hello-{c}")), "{app:?}");
        assert!(app[i].contains(&format!("echo:ping-{c}")), "{app:?}");
        assert!(nice.contains(&format!("STATE {c} ready")), "{nice:?}");
        assert!(nice.contains(&format!("RECV {c} ping-{c}")), "{nice:?}");
        // libnice selected the same pair (its local port is our remote's).
        let (_, r) = agent.selected_pair_of(c).unwrap();
        assert!(
            nice.iter()
                .any(|x| *x == format!("SELECTED {c} {} {}", r.port(), l.port())),
            "{nice:?}"
        );
    }
    assert!(!nice.iter().any(|l| l.starts_with("ERR")), "{nice:?}");
}

#[test]
#[ignore]
fn nice_controlling_aggressive() {
    session(Setup {
        we_lite: false,
        we_controlling: false,
        nice_lite: false,
        nice_regular: false,
    });
}

#[test]
#[ignore]
fn nice_controlling_regular() {
    session(Setup {
        we_lite: false,
        we_controlling: false,
        nice_lite: false,
        nice_regular: true,
    });
}

#[test]
#[ignore]
fn nice_controlled() {
    session(Setup {
        we_lite: false,
        we_controlling: true,
        nice_lite: false,
        nice_regular: false,
    });
}

#[test]
#[ignore]
fn nice_lite() {
    session(Setup {
        we_lite: false,
        we_controlling: true,
        nice_lite: true,
        nice_regular: false,
    });
}

#[test]
#[ignore]
fn we_lite_nice_controlling() {
    session(Setup {
        we_lite: true,
        we_controlling: false,
        nice_lite: false,
        nice_regular: true,
    });
}
