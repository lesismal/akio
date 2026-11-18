//! Drives an [`only_sctp::Association`] over plain UDP (no DTLS) against another SCTP data
//! channel implementation, for interop checks (for example a small pion/sctp +
//! pion/datachannel program that echoes messages and opens channels of its own).
//!
//! ```text
//! cargo run -p only-sctp --example udp_peer -- connect 127.0.0.1:6000 127.0.0.1:6001
//! cargo run -p only-sctp --example udp_peer -- accept  127.0.0.1:6000 127.0.0.1:6001
//! ```
//!
//! It opens "from-rust" (ordered) and "rust-unordered", sends messages of many sizes
//! (including 100 kB and empty ones) and expects them echoed back; it reads every channel the
//! peer opens and closes "from-pion" after a "pion-end" message; then it closes its own
//! channels, waits for both directions to be reset and shuts the association down.
//!
//! Plain UDP has no DTLS, so zero checksums (RFC 9653) are off unless `SCTP_ZERO_CHECKSUM=1`
//! (to check the negotiation against a peer that offers them too).

use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use only_sctp::{Association, ChannelOptions, Config, Event};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: udp_peer connect|accept LOCAL REMOTE [loss-every-n]");
        return ExitCode::FAILURE;
    }
    let active = args[1] == "connect";
    let loss: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
    match run(active, &args[2], &args[3], loss) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rust: FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

fn expected(i: usize) -> (Vec<u8>, bool) {
    let len = match i {
        0 => 0,
        1 => 100_000,
        2 => 1,
        i if i % 10 == 0 => 5_000 + i * 31,
        i => i * 7,
    };
    ((0..len).map(|j| (i * 3 + j) as u8).collect(), i % 2 == 0)
}

#[allow(clippy::too_many_lines)]
fn run(active: bool, local: &str, remote: &str, loss: u64) -> Result<(), String> {
    let sock = UdpSocket::bind(local).map_err(|e| e.to_string())?;
    sock.connect(remote).map_err(|e| e.to_string())?;
    let start = Instant::now();
    let zero = std::env::var("SCTP_ZERO_CHECKSUM").is_ok_and(|v| v == "1");
    let mut a = Association::new(Config::new(active).with_zero_checksum(zero), start);
    if active {
        a.connect(start);
    }
    let n = 100;
    let opts = ChannelOptions::new("from-rust").with_protocol("r1");
    let ordered = a.open_channel(start, opts).map_err(|e| e.to_string())?;
    let unordered = a
        .open_channel(
            start,
            ChannelOptions::new("rust-unordered").with_ordered(false),
        )
        .map_err(|e| e.to_string())?;
    for i in 0..n {
        let (m, bin) = expected(i);
        a.send(start, ordered, &m, bin).map_err(|e| e.to_string())?;
        a.send(start, unordered, &m, bin)
            .map_err(|e| e.to_string())?;
    }
    let mut echoes: BTreeMap<u16, Vec<(Vec<u8>, bool)>> = BTreeMap::new();
    let mut labels: BTreeMap<u16, String> = BTreeMap::new();
    let mut closed: Vec<u16> = Vec::new();
    let mut closing_own = false;
    let mut shut = false;
    let mut sent_pkts = 0u64;
    let mut buf = vec![0u8; 65536];
    loop {
        let now = Instant::now();
        if now.duration_since(start) > Duration::from_secs(60) {
            return Err(format!(
                "timeout; echoes {:?}, closed {closed:?}",
                echoes
                    .iter()
                    .map(|(k, v)| (*k, v.len()))
                    .collect::<Vec<_>>()
            ));
        }
        while let Some(p) = a.poll_transmit(now) {
            sent_pkts += 1;
            if loss > 0 && sent_pkts % loss == 0 {
                continue;
            }
            let _ = sock.send(&p);
        }
        while let Some(ev) = a.poll_event() {
            match ev {
                Event::Connected => {
                    println!("rust: connected (zero checksum: {})", a.zero_checksum());
                }
                Event::ChannelOpen {
                    stream,
                    label,
                    protocol,
                } => {
                    println!(
                        "rust: open {stream} {label:?} {protocol:?} {:?}",
                        a.channel(stream)
                    );
                    labels.insert(stream, label);
                }
                Event::ChannelData {
                    stream,
                    data,
                    binary,
                } => {
                    if labels.get(&stream).map(String::as_str) == Some("from-pion")
                        && data == b"pion-end"
                    {
                        println!("rust: closing from-pion");
                        a.close_channel(now, stream);
                    }
                    echoes.entry(stream).or_default().push((data, binary));
                }
                Event::ChannelClose { stream } => {
                    println!("rust: channel {stream} closed");
                    closed.push(stream);
                }
                Event::BufferedAmountLow { .. } => {}
                Event::Restarted => return Err("peer restarted".into()),
                Event::Closed => {
                    println!(
                        "rust: association closed after {:?}",
                        now.duration_since(start)
                    );
                    return check(&echoes, &labels, &closed, ordered, unordered, n);
                }
                _ => {}
            }
        }
        let got = |s: u16| echoes.get(&s).map_or(0, Vec::len);
        if !closing_own && got(ordered) == n && got(unordered) == n {
            println!("rust: all echoes back, closing own channels");
            a.close_channel(now, ordered);
            a.close_channel(now, unordered);
            closing_own = true;
        }
        if closing_own && !shut && closed.len() >= 4 {
            println!("rust: shutting down");
            a.shutdown(now);
            shut = true;
        }
        let wait = a
            .poll_timeout()
            .map_or(Duration::from_millis(20), |t| {
                t.saturating_duration_since(now)
            })
            .clamp(Duration::from_millis(1), Duration::from_millis(20));
        sock.set_read_timeout(Some(wait))
            .map_err(|e| e.to_string())?;
        if let Ok(len) = sock.recv(&mut buf) {
            a.handle_packet(Instant::now(), &buf[..len]);
        }
        a.handle_timeout(Instant::now());
    }
}

fn check(
    echoes: &BTreeMap<u16, Vec<(Vec<u8>, bool)>>,
    labels: &BTreeMap<u16, String>,
    closed: &[u16],
    ordered: u16,
    unordered: u16,
    n: usize,
) -> Result<(), String> {
    let want: Vec<(Vec<u8>, bool)> = (0..n).map(expected).collect();
    if echoes.get(&ordered) != Some(&want) {
        return Err("ordered echoes differ".into());
    }
    let mut got = echoes.get(&unordered).cloned().unwrap_or_default();
    got.sort();
    let mut w = want;
    w.sort();
    if got != w {
        return Err("unordered echoes differ".into());
    }
    for (s, l) in labels {
        let msgs = echoes.get(s).map_or(0, Vec::len);
        println!("rust: channel {s} {l:?}: {msgs} messages");
        if l == "from-pion" {
            let m = &echoes[s];
            if m.len() != 53 || m[50] != (vec![0xab; 70000], true) || m[51] != (vec![], false) {
                return Err("from-pion messages differ".into());
            }
        }
    }
    println!("rust: closed channels {closed:?}");
    if closed.len() < 4 {
        return Err("not every channel closed".into());
    }
    println!("rust: OK");
    Ok(())
}
