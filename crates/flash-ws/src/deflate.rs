//! permessage-deflate (RFC 7692): raw deflate per message, with optional context takeover.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

/// What went wrong inflating a message.
#[derive(Debug, PartialEq, Eq)]
pub enum InflateError {
    /// The decompressed size exceeds the message limit.
    TooBig,
    /// The data is not valid deflate.
    Corrupt,
}

/// Decompresses messages.
pub struct Inflater {
    d: Decompress,
    reset_each_message: bool,
}

const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

impl Inflater {
    /// `no_context_takeover`: forget the history after every message.
    pub fn new(no_context_takeover: bool) -> Inflater {
        Inflater {
            d: Decompress::new(false),
            reset_each_message: no_context_takeover,
        }
    }

    /// Inflates one message (the trailing `00 00 ff ff` is added here). Fails with `TooBig` as
    /// soon as the output passes `max` bytes, so a small bomb cannot balloon in memory.
    pub fn inflate(&mut self, data: &[u8], max: usize) -> Result<Vec<u8>, InflateError> {
        if data.is_empty() {
            return Ok(Vec::new()); // lenient: an empty compressed payload is an empty message
        }
        let mut input = Vec::with_capacity(data.len() + 4);
        input.extend_from_slice(data);
        input.extend_from_slice(&TAIL);
        let mut out: Vec<u8> = Vec::with_capacity((data.len() * 3).clamp(256, max.max(256)));
        let mut consumed = 0;
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.len().max(4096));
            }
            let (in0, out0) = (self.d.total_in(), self.d.total_out());
            let st = self
                .d
                .decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync)
                .map_err(|_| InflateError::Corrupt)?;
            consumed += (self.d.total_in() - in0) as usize;
            if out.len() > max {
                return Err(InflateError::TooBig);
            }
            if st == Status::StreamEnd {
                break;
            }
            if consumed >= input.len() && out.len() < out.capacity() {
                break;
            }
            if self.d.total_in() == in0 && self.d.total_out() == out0 && out.len() < out.capacity()
            {
                return Err(InflateError::Corrupt);
            }
        }
        if self.reset_each_message {
            self.d.reset(false);
        }
        Ok(out)
    }
}

/// Compresses messages.
pub struct Deflater {
    c: Compress,
    reset_each_message: bool,
}

impl Deflater {
    /// `no_context_takeover`: forget the history after every message. `window_bits`: 9..=15,
    /// the LZ77 window the peer agreed to inflate with (15 when nothing was negotiated).
    pub fn new(no_context_takeover: bool, window_bits: u8) -> Deflater {
        Deflater {
            c: Compress::new_with_window_bits(
                Compression::default(),
                false,
                window_bits.clamp(9, 15),
            ),
            reset_each_message: no_context_takeover,
        }
    }

    /// Compresses one message, returning the payload without the trailing `00 00 ff ff`.
    pub fn deflate(&mut self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            // RFC 7692 7.2.3.6: an empty message is the single octet 0x00 (an empty stored block
            // once the tail is appended); a sync flush of nothing would emit no bytes at all.
            return vec![0x00];
        }
        let mut out: Vec<u8> = Vec::with_capacity(data.len() / 2 + 64);
        let mut consumed = 0;
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.len().max(256));
            }
            let in0 = self.c.total_in();
            let _ = self
                .c
                .compress_vec(&data[consumed..], &mut out, FlushCompress::Sync);
            consumed += (self.c.total_in() - in0) as usize;
            // Done when all input was taken and the flush marker had room to be written.
            if consumed >= data.len() && out.len() < out.capacity() {
                break;
            }
        }
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - 4);
        }
        if self.reset_each_message {
            self.c.reset();
        }
        out
    }
}

/// Parameters agreed in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmdParams {
    /// The server compresses without history.
    pub server_no_context_takeover: bool,
    /// The client compresses without history.
    pub client_no_context_takeover: bool,
    /// Window the server compresses with (9..=15); echoed in the response when below 15.
    pub server_max_window_bits: u8,
}

impl Default for PmdParams {
    fn default() -> Self {
        PmdParams {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
        }
    }
}

/// Picks the first acceptable `permessage-deflate` offer among the `Sec-WebSocket-Extensions`
/// header values. Returns the agreed parameters and the response header value. An offer is
/// declined when it asks for something this implementation cannot do (a server window of 8 bits,
/// which zlib cannot produce for raw deflate, or unknown parameters).
pub fn negotiate<'a>(
    header_values: impl IntoIterator<Item = &'a str>,
) -> Option<(PmdParams, String)> {
    for value in header_values {
        'offers: for offer in value.split(',') {
            let mut parts = offer.split(';').map(str::trim);
            if parts.next() != Some("permessage-deflate") {
                continue;
            }
            let mut p = PmdParams::default();
            for param in parts {
                let (name, val) = match param.split_once('=') {
                    Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
                    None => (param, None),
                };
                match (name, val) {
                    ("server_no_context_takeover", None) => p.server_no_context_takeover = true,
                    ("client_no_context_takeover", None) => p.client_no_context_takeover = true,
                    // We inflate with a full window, so any client window is fine; not echoed.
                    ("client_max_window_bits", _) => {}
                    ("server_max_window_bits", Some(v)) => match v.parse::<u8>() {
                        Ok(b @ 9..=15) => p.server_max_window_bits = b,
                        _ => continue 'offers,
                    },
                    _ => continue 'offers,
                }
            }
            let mut resp = String::from("permessage-deflate");
            if p.server_no_context_takeover {
                resp.push_str("; server_no_context_takeover");
            }
            if p.client_no_context_takeover {
                resp.push_str("; client_no_context_takeover");
            }
            if p.server_max_window_bits < 15 {
                resp.push_str(&format!(
                    "; server_max_window_bits={}",
                    p.server_max_window_bits
                ));
            }
            return Some((p, resp));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_with_and_without_context_takeover() {
        let msgs: Vec<Vec<u8>> = vec![
            b"hello hello hello hello".to_vec(),
            vec![b'a'; 100_000],
            (0..5000u32).flat_map(|i| i.to_le_bytes()).collect(),
            Vec::new(),
            b"x".to_vec(),
        ];
        for nct in [false, true] {
            let (mut d, mut i) = (Deflater::new(nct, 15), Inflater::new(nct));
            for m in &msgs {
                let c = d.deflate(m);
                assert_eq!(
                    &i.inflate(&c, 1 << 20).unwrap(),
                    m,
                    "nct={nct} len={}",
                    m.len()
                );
            }
        }
        // Context takeover really shrinks a repeated message.
        let mut d = Deflater::new(false, 15);
        let first = d.deflate(&msgs[0]).len();
        let second = d.deflate(&msgs[0]).len();
        assert!(second < first, "{second} !< {first}");
    }

    /// Incompressible data makes the compressed output larger than the input and forces the
    /// output buffers to grow mid-message (Autobahn 12.2.9 caught this).
    #[test]
    fn roundtrip_incompressible_data_around_buffer_boundaries() {
        let mut x = 0x2545F4914F6CDD1Du64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for len in [
            1000usize, 32_768, 32_832, 65_535, 65_536, 65_537, 70_000, 200_000,
        ] {
            let data: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            for nct in [false, true] {
                let (mut d, mut i) = (Deflater::new(nct, 15), Inflater::new(nct));
                for round in 0..3 {
                    let c = d.deflate(&data);
                    let back = i.inflate(&c, 1 << 22).unwrap();
                    assert_eq!(back.len(), len, "len {len} nct {nct} round {round}");
                    assert!(back == data, "content differs, len {len} nct {nct}");
                }
            }
        }
    }

    /// Autobahn 12.2.9 failed at message 41 with miniz_oxide (a message came back 180 bytes short).
    /// A long run of low-entropy 64 KiB messages with context takeover keeps that class covered.
    #[test]
    fn many_large_messages_with_context_takeover_and_small_windows() {
        let mut x = 0x9E3779B97F4A7C15u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for bits in [15u8, 9, 12] {
            let (mut d, mut i) = (Deflater::new(false, bits), Inflater::new(false));
            for n in 0..60 {
                let alphabet = 2 + (n % 7) * 30;
                let data: Vec<u8> = (0..65_536)
                    .map(|_| (rnd() % alphabet as u64) as u8)
                    .collect();
                let c = d.deflate(&data);
                let back = i.inflate(&c, 1 << 20).unwrap();
                assert!(
                    back == data,
                    "bits {bits} message {n}: {} of {}",
                    back.len(),
                    data.len()
                );
            }
        }
    }

    #[test]
    fn limits_and_corruption() {
        let mut d = Deflater::new(false, 15);
        let c = d.deflate(&vec![0u8; 1 << 20]);
        assert!(c.len() < 5000, "highly compressible");
        assert_eq!(
            Inflater::new(false).inflate(&c, 1000),
            Err(InflateError::TooBig)
        );
        assert_eq!(
            Inflater::new(false).inflate(&[0xff, 0xff, 0xff, 0xff, 0xff], 1000),
            Err(InflateError::Corrupt)
        );
    }

    #[test]
    fn negotiation() {
        let (p, r) = negotiate(["permessage-deflate"]).unwrap();
        assert_eq!(p, PmdParams::default());
        assert_eq!(r, "permessage-deflate");
        let (p, r) =
            negotiate(["permessage-deflate; client_max_window_bits; server_no_context_takeover"])
                .unwrap();
        assert!(p.server_no_context_takeover && !p.client_no_context_takeover);
        assert_eq!(r, "permessage-deflate; server_no_context_takeover");
        // A smaller server window is honoured and echoed; 8 bits cannot be produced: declined.
        let (p, r) = negotiate(["permessage-deflate; server_max_window_bits=10"]).unwrap();
        assert_eq!(p.server_max_window_bits, 10);
        assert_eq!(r, "permessage-deflate; server_max_window_bits=10");
        let (_, r) = negotiate(["permessage-deflate; server_max_window_bits=8, permessage-deflate; client_no_context_takeover"]).unwrap();
        assert_eq!(r, "permessage-deflate; client_no_context_takeover");
        assert!(negotiate(["permessage-deflate; server_max_window_bits=8"]).is_none());
        assert!(negotiate(["x-webkit-deflate-frame"]).is_none());
        assert!(negotiate(["permessage-deflate; bogus"]).is_none());
        assert!(negotiate(std::iter::empty()).is_none());
    }
}
