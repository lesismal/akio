//! This side's QPACK encoder over stdin/stdout, for checking it against another decoder
//! (`tools/interop/h3/nghttp3-qpack.py` uses libnghttp3's). Not an API example.
//!
//! ```text
//! qpack-pipe CAPACITY PEER_MAX_CAPACITY PEER_BLOCKED_STREAMS
//! > enc STREAM NAME_HEX=VALUE_HEX ...   < ok ENCODER_STREAM_HEX SECTION_HEX
//! > dec DECODER_STREAM_HEX              < ok BYTES_TAKEN | err CODE
//! > stats                               < ok INSERTS DUPLICATES DYN_NAME_INSERTS
//!                                          DYN_NAME_LINES POST_BASE BLOCKING KNOWN INSERTED
//! ```
//! The Set Dynamic Table Capacity instruction comes with the first `enc` answer.

use std::io::{BufRead, Write};

use akio_h3::fuzzing::InteropEncoder;

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn main() {
    let a: Vec<u64> = std::env::args()
        .skip(1)
        .map(|x| x.parse().expect("number"))
        .collect();
    let mut e = InteropEncoder::new(a[0], a[1], a[2]);
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let mut w = line.split_whitespace();
        let reply = match w.next() {
            Some("enc") => {
                let stream: u64 = w.next().expect("stream").parse().expect("stream");
                let fields: Vec<(Vec<u8>, Vec<u8>)> = w
                    .map(|f| {
                        let (n, v) = f.split_once('=').expect("name=value");
                        (unhex(n), unhex(v))
                    })
                    .collect();
                let sec = e.encode(stream, &fields);
                format!("ok {} {}", hex(&e.take_encoder_stream()), hex(&sec))
            }
            Some("dec") => match e.on_decoder_stream(&unhex(w.next().unwrap_or("-"))) {
                Ok(n) => format!("ok {n}"),
                Err(c) => format!("err {c}"),
            },
            Some("stats") => {
                let s = e.stats().map(|x| x.to_string());
                format!("ok {}", s.join(" "))
            }
            _ => "err bad command".into(),
        };
        writeln!(out, "{reply}").expect("stdout");
        out.flush().expect("stdout");
    }
}
