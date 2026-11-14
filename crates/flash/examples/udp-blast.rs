//! Sender-side cost of bursts of datagrams to one peer, three ways (Linux is where it matters):
//!
//! `cargo run --release -p flash --example udp-blast [rounds=5000] [burst=40] [size=1200]`
//!
//! Each round the client asks for a burst and reads it all (closed loop, so the receiver never
//! overflows and every datagram is paid for in full). The server replies with:
//!
//! * `sendto`: one syscall per datagram (what flash did before batching);
//! * `sendmmsg`: `Conn::send` per datagram inside `on_data`; the loop flushes the burst at the end
//!   of the receive batch in one `sendmmsg` (equal-size runs to one peer become GSO sends where
//!   the kernel has it; `FLASH_UDP_GSO=0` turns that off);
//! * `segments`: one `Conn::send_segments` for the burst (GSO, else one `sendmmsg`).
//!
//! It prints the server thread's CPU time per datagram (from `/proc`, Linux only).

use std::{
    net::UdpSocket,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use flash::{Conn, Engine, Handler, Listener, fn_acceptor};

struct Blast {
    burst: usize,
    size: usize,
    cpu: Arc<Mutex<Option<u64>>>,
}

/// CPU time of the calling thread in clock ticks (0 where unavailable).
fn thread_ticks() -> u64 {
    std::fs::read_to_string("/proc/thread-self/stat")
        .ok()
        .and_then(|s| {
            let rest = s.rsplit_once(')')?.1.to_string();
            let f: Vec<&str> = rest.split_whitespace().collect();
            Some(f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?)
        })
        .unwrap_or(0)
}

impl Handler for Blast {
    fn on_data(&mut self, c: &Conn<Self>, d: &[u8]) {
        if d == b"cpu" {
            *self.cpu.lock().unwrap() = Some(thread_ticks());
            return;
        }
        let dgram = vec![0x5au8; self.size];
        match d {
            b"sendto" => {
                let _ = c.flush(); // uncorked: every send below is a direct sendto
                for _ in 0..self.burst {
                    let _ = c.send(&dgram);
                }
            }
            b"sendmmsg" => {
                for _ in 0..self.burst {
                    let _ = c.send(&dgram);
                }
            }
            _ => {
                let _ = c.send_segments(dgram.repeat(self.burst), self.size);
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let mut a = std::env::args().skip(1);
    let rounds: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(5000);
    let burst: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(40);
    let size: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(1200);
    let cpu = Arc::new(Mutex::new(None));
    let c2 = cpu.clone();
    let engine = Engine::builder()
        .listen(
            Listener::udp("127.0.0.1:0".parse().unwrap())
                .threads(1)
                .serve(fn_acceptor(move |_c: &Conn<Blast>| Blast {
                    burst,
                    size,
                    cpu: c2.clone(),
                })),
        )
        .build()?;
    engine.start()?;
    let addr = engine.local_addrs()[0];
    let rx = UdpSocket::bind("127.0.0.1:0")?;
    rx.connect(addr)?;
    rx.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut buf = vec![0u8; 65536];
    let ticks = |rx: &UdpSocket| {
        *cpu.lock().unwrap() = None;
        rx.send(b"cpu").unwrap();
        loop {
            let taken = *cpu.lock().unwrap();
            if let Some(t) = taken {
                return t;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    for mode in ["sendto", "sendmmsg", "segments"] {
        let t0 = ticks(&rx);
        let start = Instant::now();
        let (mut got, mut lost) = (0usize, 0usize);
        for _ in 0..rounds {
            rx.send(mode.as_bytes())?;
            for _ in 0..burst {
                match rx.recv(&mut buf) {
                    Ok(_) => got += 1,
                    Err(_) => {
                        lost += 1;
                        break;
                    }
                }
            }
        }
        let wall = start.elapsed();
        let t1 = ticks(&rx);
        // A clock tick is 10 ms.
        let ns = (t1 - t0) as f64 * 1e7 / got.max(1) as f64;
        let rate = got as f64 / wall.as_secs_f64() / 1e6;
        println!(
            "{mode:9} {burst} x {size} B bursts: server CPU {ns:6.0} ns/datagram, \
             {rate:5.2} M datagrams/s, received {got} (short bursts {lost})"
        );
    }
    engine.shutdown();
    engine.wait();
    Ok(())
}
