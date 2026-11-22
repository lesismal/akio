//! A tiny DNS-style responder on a connectionless UDP listener (`serve_datagrams`, ADR-065):
//! `cargo run --release -p akio --example udp-dns`, then `dig @127.0.0.1 -p 5353 hello.test`.
//!
//! Every query for an `A` record under `.test` (RFC 6761) is answered with `127.0.0.1`; other
//! names get `REFUSED`, malformed datagrams are ignored. The handler keeps no state per client:
//! one handler per I/O thread sees each receive batch and queues the answers, which leave
//! together when it returns (one `sendmmsg` on Linux). A second thread holds a `DatagramSender`
//! (sending works from any thread) and prints the counters every ten seconds.

use std::{net::SocketAddr, time::Duration};

use akio::{DatagramSender, Datagrams, DatagramsHandler, Engine, Listener, Replies};

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

struct Dns {
    /// Reused for each answer: no allocation per query.
    buf: Vec<u8>,
}

/// The question of a standard query: the name (labels, lowercase, dot-joined), its type and
/// where the question ends. `None` for anything else.
fn question(q: &[u8]) -> Option<(String, u16, usize)> {
    // Header: id, flags (QR = 0, opcode 0), QDCOUNT = 1.
    if q.len() < 12 || q[2] & 0xf8 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let (mut i, mut name) = (12, String::new());
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 || name.len() + len > 253 {
            return None; // also refuses compression pointers, never in a question
        }
        let label = std::str::from_utf8(q.get(i..i + len)?).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&label.to_ascii_lowercase());
        i += len;
    }
    let ty = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    let class = u16::from_be_bytes([*q.get(i + 2)?, *q.get(i + 3)?]);
    (class == CLASS_IN).then_some((name, ty, i + 4))
}

impl Dns {
    /// The answer to query `q` in `self.buf`, or `false` to ignore it.
    fn answer(&mut self, q: &[u8]) -> bool {
        let Some((name, ty, end)) = question(q) else {
            return false;
        };
        let ours = name == "test" || name.ends_with(".test");
        let b = &mut self.buf;
        b.clear();
        b.extend_from_slice(&q[..2]); // id
        let rd = q[2] & 0x01;
        // QR, AA, RD copied; RCODE 0 (NOERROR) or 5 (REFUSED).
        b.extend_from_slice(&[0x84 | rd, if ours { 0 } else { 5 }]);
        let answers = u16::from(ours && ty == TYPE_A);
        b.extend_from_slice(&[0, 1]); // QDCOUNT
        b.extend_from_slice(&answers.to_be_bytes()); // ANCOUNT
        b.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
        b.extend_from_slice(&q[12..end]); // the question, echoed
        if answers == 1 {
            // A pointer to the name in the question, A, IN, TTL 60, 127.0.0.1.
            b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
        }
        true
    }
}

// ANCHOR: handler
impl DatagramsHandler for Dns {
    /// One receive batch: every datagram of one `recvmmsg` (up to 32).
    fn on_datagrams(&mut self, batch: &Datagrams<'_>, out: &mut Replies) {
        for (peer, query) in batch {
            if self.answer(query) {
                // Dropped (with an error) only if the reply queue is full: the client retries.
                let _ = out.send_to(&self.buf, peer);
            }
        }
    }
}
// ANCHOR_END: handler

fn main() -> std::io::Result<()> {
    let addr: SocketAddr = "127.0.0.1:5353".parse().expect("address");
    // ANCHOR: listener
    let engine = Engine::builder()
        .listen(
            // The factory runs once per I/O thread.
            Listener::udp(addr).serve_datagrams(|_tx: &DatagramSender| Dns {
                buf: Vec::with_capacity(512),
            }),
        )
        .build()?;
    // ANCHOR_END: listener
    engine.start()?;
    let local = engine.local_addrs()[0];
    println!("DNS-style responder on {local}: dig @127.0.0.1 -p 5353 hello.test");
    let engine = std::sync::Arc::new(engine);
    // Any thread can send from the listener's socket (a NOTIFY to a secondary server, say);
    // this one only reports the counters.
    let (e, tx) = (engine.clone(), engine.datagram_sender(local)?);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(10));
            let m = e.metrics().total;
            println!(
                "{}: queries {} answers {} send calls {}",
                tx.local_addr(),
                m.datagrams_in,
                m.datagrams_out,
                m.writes
            );
        }
    });
    engine.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, ty: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&ty.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn answers_test_names_and_refuses_others() {
        let mut d = Dns { buf: Vec::new() };
        let q = query("Hello.TEST", TYPE_A);
        assert!(d.answer(&q));
        assert_eq!(&d.buf[..4], &[0x12, 0x34, 0x85, 0]);
        assert_eq!(&d.buf[6..8], &[0, 1]); // one answer
        assert_eq!(&d.buf[d.buf.len() - 4..], &[127, 0, 0, 1]);
        assert!(d.answer(&query("example.com", TYPE_A)));
        assert_eq!(d.buf[3], 5); // REFUSED
        assert!(!d.answer(b"junk"));
    }
}
