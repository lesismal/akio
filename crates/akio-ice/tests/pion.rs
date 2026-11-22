//! Interop with pion/ice over real loopback UDP sockets (ignored by default).
//!
//! Needs a pion peer program speaking a small line protocol on stdin/stdout (`CRED u p`,
//! `CAND <candidate>`, `GATHERED`, `GO`, `CONNECTED`, `RECV <data>`, `STATE <s>`, `QUIT`; it
//! writes `hello-from-pion` once connected and echoes what it receives prefixed with `echo:`),
//! given by `AKIO_ICE_PION_PEER`:
//!
//! ```text
//! AKIO_ICE_PION_PEER=/path/to/pionpeer cargo test -p akio-ice --test pion -- --ignored
//! ```

use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use akio_ice::{Candidate, Credentials, IceAgent, IceConfig, IceEvent, IceState};

fn session(we_lite: bool, we_controlling: bool, pion_lite: bool) {
    let Ok(peer) = std::env::var("AKIO_ICE_PION_PEER") else {
        eprintln!("AKIO_ICE_PION_PEER not set: skipped");
        return;
    };
    let mut cmd = Command::new(peer);
    if !we_controlling {
        cmd.arg("-controlling");
    }
    if pion_lite {
        cmd.arg("-lite");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn pion peer");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            eprintln!("pion: {line}");
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
            .expect("pion output");
        if let Some(c) = line.strip_prefix("CRED ") {
            let f: Vec<&str> = c.split_whitespace().collect();
            creds = Some(Credentials::new(f[0], f[1]));
        } else if let Some(c) = line.strip_prefix("CAND ") {
            let line = if c.starts_with("candidate:") {
                c.to_owned()
            } else {
                format!("candidate:{c}")
            };
            cands.push(Candidate::parse(&line).expect("pion candidate parses"));
        } else if line == "GATHERED" {
            break;
        }
    }
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = sock.local_addr().unwrap();
    let start = Instant::now();
    let mut agent = IceAgent::new(IceConfig::new(we_lite, we_controlling), start);
    if pion_lite {
        agent.set_remote_lite(true);
    }
    agent.add_local_candidate(Candidate::host(local));
    let mine = agent.local_credentials().clone();
    writeln!(stdin, "CRED {} {}", mine.ufrag, mine.pwd).unwrap();
    writeln!(stdin, "CAND {}", agent.local_candidates()[0].to_sdp()).unwrap();
    writeln!(stdin, "GO").unwrap();
    agent.set_remote_credentials(creds.expect("pion credentials"));
    for c in cands {
        agent.add_remote_candidate(c);
    }
    agent.end_of_remote_candidates();

    let mut buf = [0u8; 2048];
    let mut app: Vec<String> = Vec::new();
    let mut pion: Vec<String> = Vec::new();
    let mut states = Vec::new();
    let mut pinged = false;
    let deadline = start + Duration::from_secs(16);
    while Instant::now() < deadline {
        let now = Instant::now();
        agent.handle_timeout(now);
        while let Some(t) = agent.poll_transmit() {
            assert_eq!(t.source, local);
            sock.send_to(&t.contents, t.destination).unwrap();
        }
        while let Some(e) = agent.poll_event() {
            eprintln!("akio: {e:?}");
            if let IceEvent::StateChanged(s) = e {
                states.push(s);
            }
        }
        if !pinged {
            if let Some((_, dst)) = agent.send_pair() {
                sock.send_to(b"ping-from-only", dst).unwrap();
                pinged = true;
            }
        }
        while let Ok(l) = rx.try_recv() {
            pion.push(l);
        }
        let wait = agent
            .poll_timeout()
            .map_or(Duration::from_millis(50), |t| {
                t.saturating_duration_since(now)
            })
            .clamp(Duration::from_millis(1), Duration::from_millis(50));
        sock.set_read_timeout(Some(wait)).unwrap();
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if !agent.handle_receive(Instant::now(), from, local, &buf[..n]) {
                app.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            }
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
    assert!(agent.selected_pair().is_some());
    assert!(app.iter().any(|m| m == "hello-from-pion"), "{app:?}");
    assert!(app.iter().any(|m| m == "echo:ping-from-only"), "{app:?}");
    assert!(pion.iter().any(|l| l == "CONNECTED"), "{pion:?}");
    assert!(pion.iter().any(|l| l == "RECV ping-from-only"), "{pion:?}");
    assert!(!pion.iter().any(|l| l.starts_with("ERR")), "{pion:?}");
}

#[test]
#[ignore]
fn pion_controlled() {
    session(false, true, false);
}

#[test]
#[ignore]
fn pion_controlling() {
    session(false, false, false);
}

#[test]
#[ignore]
fn pion_lite() {
    session(false, true, true);
}

#[test]
#[ignore]
fn we_lite_pion_controlling() {
    session(true, false, false);
}
