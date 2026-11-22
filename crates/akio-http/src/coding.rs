//! Content codings of streamed responses: the encoder a [`BodyStream`](crate::BodyStream)
//! runs its writes through when the `compress` middleware chose a coding for it (ADR-074).

/// The coding of a streamed response, chosen by the `compress` middleware when the head goes
/// out (small and `Copy`, so a [`Response`](crate::Response) carries it at no cost).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamCoding {
    /// `gzip` at a zlib level.
    Gzip(u8),
    /// `deflate` (the zlib format) at a zlib level.
    Deflate(u8),
    /// `br` at a quality, with a window of `2^window_bits` bytes.
    Br { quality: u8, window_bits: u8 },
    /// `zstd` at a level, with a window of `2^window_log` bytes.
    Zstd { level: u8, window_log: u8 },
}

#[allow(clippy::large_enum_variant, reason = "boxed whole in the stream")]
enum Enc {
    Deflate(akio_deflate::Deflater),
    Br(akio_brotli::Compressor),
    Zstd(akio_zstd::Compressor),
}

/// One stream's encoder and the buffer its output goes through.
pub(crate) struct StreamEncoder {
    enc: Enc,
    out: Vec<u8>,
}

/// Output buffers larger than this are not kept between writes: an idle stream (server-sent
/// events) holds its encoder's window and tables, not the largest write it ever saw.
const KEEP_OUT: usize = 64 << 10;

impl StreamEncoder {
    pub(crate) fn new(c: StreamCoding) -> StreamEncoder {
        let enc = match c {
            StreamCoding::Gzip(l) => Enc::Deflate(akio_deflate::Deflater::new(
                akio_deflate::Format::Gzip,
                akio_deflate::Level::new(u32::from(l)),
            )),
            StreamCoding::Deflate(l) => Enc::Deflate(akio_deflate::Deflater::new(
                akio_deflate::Format::Zlib,
                akio_deflate::Level::new(u32::from(l)),
            )),
            StreamCoding::Br {
                quality,
                window_bits,
            } => Enc::Br(
                akio_brotli::Compressor::new(akio_brotli::Level::new(u32::from(quality)))
                    .window_bits(u32::from(window_bits)),
            ),
            StreamCoding::Zstd { level, window_log } => Enc::Zstd(
                akio_zstd::Compressor::new(akio_zstd::Level::new(u32::from(level)))
                    .window_log(u32::from(window_log)),
            ),
        };
        StreamEncoder {
            enc,
            out: Vec::new(),
        }
    }

    /// Compresses `data` and flushes, so that everything written so far can be decoded from
    /// the output (a sync flush for gzip and deflate, the end of a block or meta-block for zstd
    /// and brotli); `last` ends the stream instead. The output is valid until the next call.
    pub(crate) fn encode(&mut self, data: &[u8], last: bool) -> &[u8] {
        self.out.clear();
        if self.out.capacity() > KEEP_OUT {
            self.out = Vec::new();
        }
        match &mut self.enc {
            Enc::Deflate(d) => d.compress(
                data,
                &mut self.out,
                if last {
                    akio_deflate::Flush::Finish
                } else {
                    akio_deflate::Flush::Sync
                },
            ),
            Enc::Br(c) => c.compress(
                data,
                &mut self.out,
                if last {
                    akio_brotli::Flush::Finish
                } else {
                    akio_brotli::Flush::Flush
                },
            ),
            Enc::Zstd(c) => c.compress(
                data,
                &mut self.out,
                if last {
                    akio_zstd::Flush::Finish
                } else {
                    akio_zstd::Flush::Flush
                },
            ),
        }
        &self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(c: StreamCoding, decode: fn(&[u8]) -> Vec<u8>) {
        let mut e = StreamEncoder::new(c);
        let mut wire = Vec::new();
        let mut want = Vec::new();
        for i in 0..200 {
            let ev = format!("event: tick\ndata: {{\"seq\":{i}}}\n\n");
            want.extend_from_slice(ev.as_bytes());
            wire.extend_from_slice(e.encode(ev.as_bytes(), false));
            // Everything so far decodes from what was written so far.
            if i % 50 == 0 {
                assert_eq!(decode(&wire), want, "{c:?} after event {i}");
            }
        }
        // A large write that compresses poorly, then the end.
        let mut x = 1u32;
        let big: Vec<u8> = (0..300_000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 24) as u8
            })
            .collect();
        want.extend_from_slice(&big);
        wire.extend_from_slice(e.encode(&big, false));
        assert!(e.out.capacity() > KEEP_OUT);
        wire.extend_from_slice(e.encode(&[], true));
        assert!(e.out.capacity() <= KEEP_OUT, "large buffers are not kept");
        assert_eq!(decode_full(c, &wire), want, "{c:?}");
    }

    fn decode_full(c: StreamCoding, wire: &[u8]) -> Vec<u8> {
        match c {
            StreamCoding::Gzip(_) => {
                akio_deflate::decompress(akio_deflate::Format::Gzip, wire, 1 << 24).unwrap()
            }
            StreamCoding::Deflate(_) => {
                akio_deflate::decompress(akio_deflate::Format::Zlib, wire, 1 << 24).unwrap()
            }
            StreamCoding::Br { .. } => akio_brotli::decompress(wire, 1 << 24).unwrap(),
            StreamCoding::Zstd { .. } => akio_zstd::decompress(wire, 1 << 24).unwrap(),
        }
    }

    fn partial_inflate(format: akio_deflate::Format, wire: &[u8]) -> Vec<u8> {
        let mut d = akio_deflate::Inflater::new(format);
        let mut out = Vec::new();
        d.decompress_vec(wire, &mut out, 1 << 24).unwrap();
        out
    }

    #[test]
    fn the_coding_fits_in_a_response_padding() {
        // With the status (2 bytes) and the streaming flag (1), within one 8-byte slot.
        assert_eq!(size_of::<Option<StreamCoding>>(), 3);
    }

    #[test]
    fn every_write_is_decodable_and_the_end_completes_the_stream() {
        roundtrip(StreamCoding::Gzip(1), |w| {
            partial_inflate(akio_deflate::Format::Gzip, w)
        });
        roundtrip(StreamCoding::Deflate(6), |w| {
            partial_inflate(akio_deflate::Format::Zlib, w)
        });
        roundtrip(
            StreamCoding::Br {
                quality: 4,
                window_bits: 18,
            },
            |w| {
                let mut d = akio_brotli::Decompressor::new();
                let mut out = Vec::new();
                d.decompress_vec(w, &mut out, 1 << 24).unwrap();
                out
            },
        );
        roundtrip(
            StreamCoding::Zstd {
                level: 1,
                window_log: 17,
            },
            |w| {
                let mut d = akio_zstd::Decompressor::new();
                let mut out = Vec::new();
                d.decompress_vec(w, &mut out, 1 << 24).unwrap();
                out
            },
        );
    }
}
