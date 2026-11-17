//! permessage-deflate (RFC 7692): raw deflate per message, with optional context takeover.

use only_deflate::{Flush, Format, Level};

/// What went wrong inflating a message.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InflateError {
    /// The decompressed size exceeds the message limit.
    TooBig,
    /// The data is not valid deflate.
    Corrupt,
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InflateError::TooBig => "inflated message too big",
            InflateError::Corrupt => "corrupt deflate data",
        })
    }
}

impl std::error::Error for InflateError {}

/// Decompresses messages.
#[derive(Debug)]
pub struct Inflater {
    // Boxed: the codec state is ~0.6 KB inline, and `Option<Inflater>` sits in every
    // connection's decoder, compressed or not.
    d: Box<only_deflate::Inflater>,
    reset_each_message: bool,
}

const TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

impl Inflater {
    /// `no_context_takeover`: forget the history after every message.
    pub fn new(no_context_takeover: bool) -> Inflater {
        Inflater {
            d: Box::new(only_deflate::Inflater::new(Format::Raw)),
            reset_each_message: no_context_takeover,
        }
    }

    /// Inflates one message (the trailing `00 00 ff ff` is added here). Fails with `TooBig` as
    /// soon as the output passes `max` bytes, so a small bomb cannot balloon in memory.
    pub fn inflate(&mut self, data: &[u8], max: usize) -> Result<Vec<u8>, InflateError> {
        if data.is_empty() {
            return Ok(Vec::new()); // lenient: an empty compressed payload is an empty message
        }
        let limit = max.saturating_add(1);
        let mut out: Vec<u8> = Vec::with_capacity((data.len() * 3).clamp(256, max.max(256)));
        let mut done = false;
        for part in [data, &TAIL[..]] {
            if done {
                break; // the message ended with a final block: the tail is not needed
            }
            let p = self
                .d
                .decompress_vec(part, &mut out, limit)
                .map_err(|_| InflateError::Corrupt)?;
            if out.len() > max {
                return Err(InflateError::TooBig);
            }
            done = p.done;
        }
        if self.reset_each_message {
            self.d.reset();
        } else if done {
            // A final block ends the deflate stream, not the history: the next message may
            // still refer back into this one.
            self.d.reset_keep_window();
        }
        Ok(out)
    }
}

/// Compresses messages.
#[derive(Debug)]
pub struct Deflater {
    // Boxed for the same reason (~1.4 KB inline, in every connection's sender).
    c: Box<only_deflate::Deflater>,
    reset_each_message: bool,
}

impl Deflater {
    /// `no_context_takeover`: forget the history after every message. `window_bits`: 8..=15,
    /// the LZ77 window the peer agreed to inflate with (15 when nothing was negotiated).
    pub fn new(no_context_takeover: bool, window_bits: u8) -> Deflater {
        Deflater {
            c: Box::new(only_deflate::Deflater::with_window_bits(
                Format::Raw,
                Level::DEFAULT,
                window_bits.clamp(8, 15),
            )),
            reset_each_message: no_context_takeover,
        }
    }

    /// Compresses one message, returning the payload without the trailing `00 00 ff ff`.
    pub fn deflate(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(data.len() / 2 + 64);
        self.deflate_into(data, &mut out);
        out
    }

    /// [`deflate`](Self::deflate) into `out` (cleared first), so a sender can reuse one buffer.
    pub(crate) fn deflate_into(&mut self, data: &[u8], out: &mut Vec<u8>) {
        out.clear();
        if data.is_empty() {
            // RFC 7692 7.2.3.6: an empty message is the single octet 0x00 (an empty stored block
            // once the tail is appended); a sync flush of nothing would emit no bytes at all.
            out.push(0x00);
            return;
        }
        out.reserve(data.len() / 2 + 64);
        self.c.compress(data, out, Flush::Sync);
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - 4);
        }
        if self.reset_each_message {
            self.c.reset();
        }
    }
}

/// Parameters agreed in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PmdParams {
    /// The server compresses without history.
    pub server_no_context_takeover: bool,
    /// The client compresses without history.
    pub client_no_context_takeover: bool,
    /// Window the server compresses with (8..=15); echoed in the response when below 15.
    pub server_max_window_bits: u8,
    /// Window the client compresses with (8..=15). A server ignores it (it inflates with a full
    /// window).
    pub client_max_window_bits: u8,
}

impl Default for PmdParams {
    fn default() -> Self {
        PmdParams {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            server_max_window_bits: 15,
            client_max_window_bits: 15,
        }
    }
}

/// What a client puts in its `permessage-deflate` offer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PmdOffer {
    /// Promise not to use context takeover when compressing (`client_no_context_takeover`):
    /// less memory on the server, worse compression.
    pub client_no_context_takeover: bool,
    /// Ask the server to compress without context takeover (`server_no_context_takeover`).
    pub server_no_context_takeover: bool,
    /// Ask the server to compress with a smaller window (`server_max_window_bits`, 8..=15).
    pub server_max_window_bits: Option<u8>,
}

impl PmdOffer {
    /// The `Sec-WebSocket-Extensions` value of the offer. `client_max_window_bits` is always
    /// offered: this side can compress with any window the server picks.
    pub fn header(&self) -> String {
        let mut h = String::from("permessage-deflate; client_max_window_bits");
        if self.client_no_context_takeover {
            h.push_str("; client_no_context_takeover");
        }
        if self.server_no_context_takeover {
            h.push_str("; server_no_context_takeover");
        }
        if let Some(b) = self.server_max_window_bits {
            h.push_str(&format!("; server_max_window_bits={}", b.clamp(8, 15)));
        }
        h
    }

    /// Checks the server's `Sec-WebSocket-Extensions` answer to this offer. `Ok(None)`: the
    /// server declined compression. Fails when the answer is not a valid acceptance: an
    /// extension that was not offered, an unknown or repeated parameter, a bad window size, or a
    /// request of the offer that the server ignored.
    pub fn accept_response<'a>(
        &self,
        header_values: impl IntoIterator<Item = &'a str>,
    ) -> Result<Option<PmdParams>, &'static str> {
        let mut found: Option<PmdParams> = None;
        for value in header_values {
            for ext in value.split(',').map(str::trim).filter(|e| !e.is_empty()) {
                let mut parts = ext.split(';').map(str::trim);
                if parts.next() != Some("permessage-deflate") {
                    return Err("server accepted an extension that was not offered");
                }
                if found.is_some() {
                    return Err("permessage-deflate accepted twice");
                }
                let mut p = PmdParams::default();
                let mut seen = [false; 4];
                for param in parts {
                    let (name, val) = match param.split_once('=') {
                        Some((n, v)) => (n.trim(), Some(v.trim().trim_matches('"'))),
                        None => (param, None),
                    };
                    let idx = match name {
                        "server_no_context_takeover" => 0,
                        "client_no_context_takeover" => 1,
                        "server_max_window_bits" => 2,
                        "client_max_window_bits" => 3,
                        _ => return Err("unknown permessage-deflate parameter"),
                    };
                    if std::mem::replace(&mut seen[idx], true) {
                        return Err("repeated permessage-deflate parameter");
                    }
                    let bits = |v: Option<&str>| match v.map(str::parse::<u8>) {
                        Some(Ok(b @ 8..=15)) => Ok(b),
                        _ => Err("bad permessage-deflate window size"),
                    };
                    match (idx, val) {
                        (0, None) => p.server_no_context_takeover = true,
                        (1, None) => p.client_no_context_takeover = true,
                        (2, v) => p.server_max_window_bits = bits(v)?,
                        (3, v) => p.client_max_window_bits = bits(v)?,
                        _ => return Err("bad permessage-deflate parameter value"),
                    }
                }
                if self.server_no_context_takeover && !p.server_no_context_takeover {
                    return Err("server ignored server_no_context_takeover");
                }
                if let Some(b) = self.server_max_window_bits {
                    if p.server_max_window_bits > b.clamp(8, 15) {
                        return Err("server window larger than requested");
                    }
                }
                // The offer promised it: compress without history whatever the server said.
                p.client_no_context_takeover |= self.client_no_context_takeover;
                found = Some(p);
            }
        }
        Ok(found)
    }
}

/// Picks the first acceptable `permessage-deflate` offer among the `Sec-WebSocket-Extensions`
/// header values. Returns the agreed parameters and the response header value. An offer is
/// declined when it has unknown parameters or bad values.
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
                        Ok(b @ 8..=15) => p.server_max_window_bits = b,
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
    fn codec_state_is_not_inline() {
        // Every connection carries an `Option<Inflater>` and an `Option<Deflater>`, mostly `None`;
        // the codec state inline (~2 KB) cost ~1.8 KB per WebSocket connection.
        assert!(size_of::<Option<Inflater>>() <= 16);
        assert!(size_of::<Option<Deflater>>() <= 16);
    }

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
        // A smaller server window is honoured and echoed, down to 8 bits.
        let (p, r) = negotiate(["permessage-deflate; server_max_window_bits=10"]).unwrap();
        assert_eq!(p.server_max_window_bits, 10);
        assert_eq!(r, "permessage-deflate; server_max_window_bits=10");
        let (p, r) = negotiate(["permessage-deflate; server_max_window_bits=8, permessage-deflate; client_no_context_takeover"]).unwrap();
        assert_eq!(p.server_max_window_bits, 8);
        assert_eq!(r, "permessage-deflate; server_max_window_bits=8");
        let (_, r) = negotiate(["permessage-deflate; server_max_window_bits=7, permessage-deflate; client_no_context_takeover"]).unwrap();
        assert_eq!(r, "permessage-deflate; client_no_context_takeover");
        assert!(negotiate(["permessage-deflate; server_max_window_bits=16"]).is_none());
        assert!(negotiate(["x-webkit-deflate-frame"]).is_none());
        assert!(negotiate(["permessage-deflate; bogus"]).is_none());
        assert!(negotiate(std::iter::empty()).is_none());
    }

    #[test]
    fn client_offer_and_response() {
        let o = PmdOffer::default();
        assert_eq!(o.header(), "permessage-deflate; client_max_window_bits");
        let full = PmdOffer {
            client_no_context_takeover: true,
            server_no_context_takeover: true,
            server_max_window_bits: Some(10),
        };
        assert_eq!(
            full.header(),
            "permessage-deflate; client_max_window_bits; client_no_context_takeover; \
             server_no_context_takeover; server_max_window_bits=10"
        );
        assert_eq!(o.accept_response(std::iter::empty()), Ok(None));
        assert_eq!(
            o.accept_response(["permessage-deflate"]),
            Ok(Some(PmdParams::default()))
        );
        let p = o
            .accept_response([
                "permessage-deflate; client_max_window_bits=9; server_no_context_takeover",
            ])
            .unwrap()
            .unwrap();
        assert_eq!(p.client_max_window_bits, 9);
        assert!(p.server_no_context_takeover && !p.client_no_context_takeover);
        let p = full
            .accept_response([
                "permessage-deflate; server_no_context_takeover; server_max_window_bits=9",
            ])
            .unwrap()
            .unwrap();
        assert!(p.client_no_context_takeover, "promised in the offer");
        assert_eq!(p.server_max_window_bits, 9);
        for bad in [
            "x-webkit-deflate-frame",
            "permessage-deflate; bogus",
            "permessage-deflate; client_max_window_bits=16",
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
            "permessage-deflate, permessage-deflate",
        ] {
            assert!(o.accept_response([bad]).is_err(), "{bad}");
        }
        // The server must honour what the offer asked of it.
        assert!(full.accept_response(["permessage-deflate"]).is_err());
        assert!(
            full.accept_response(["permessage-deflate; server_no_context_takeover"])
                .is_err(),
            "window 15 > 10"
        );
    }
}
