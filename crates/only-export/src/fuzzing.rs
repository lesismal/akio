//! Fuzz entry points (`fuzz/fuzz_targets/export_*.rs`); not a public API.

use std::{
    borrow::Cow,
    time::{Duration, UNIX_EPOCH},
};

use only_core::metrics::Families;
use only_log::{
    Level,
    span::{FieldValue, SpanContext, SpanData, SpanKind, SpanStatus},
};

/// Parses `data` as an OTLP/HTTP response (status line, headers, a body framed by
/// `Content-Length`, chunked or the close). Must never panic or read past its limits.
pub fn http_response(data: &[u8]) {
    let _ = crate::http::read_response(&mut &data[..]);
}

fn span(name: &str, key: &str, value: &str) -> SpanData {
    let ctx = SpanContext::new(1, 2, true, false).unwrap_or_else(|| unreachable!());
    let mut d = SpanData::__fuzz(ctx);
    d.name = Cow::Owned(name.to_owned());
    d.fields = vec![(
        Cow::Owned(key.to_owned()),
        FieldValue::Str(Cow::Owned(value.to_owned())),
    )];
    d.status = SpanStatus::Error(Cow::Owned(value.to_owned()));
    d.kind = SpanKind::Server;
    d.level = Level::Info;
    d.start = UNIX_EPOCH + Duration::from_secs(1);
    d.end = d.start;
    d
}

/// An `ExportTraceServiceRequest` with one span carrying these strings, as OTLP/JSON.
pub fn otlp_span_json(name: &str, key: &str, value: &str) -> String {
    let req = crate::otlp::traces_request(&[span(name, key, value)], &[(key.into(), value.into())]);
    String::from_utf8(crate::Encoding::Json.encode(req)).unwrap_or_default()
}

/// The same request in protobuf.
pub fn otlp_span_protobuf(name: &str, key: &str, value: &str) -> Vec<u8> {
    let req = crate::otlp::traces_request(&[span(name, key, value)], &[]);
    crate::Encoding::Protobuf.encode(req)
}

/// StatsD lines (both flavors) of a counter, a gauge and a histogram labelled `label=value`.
pub fn statsd_lines(name: &str, label: &str, value: &str) -> Vec<String> {
    let mut f = Families::new();
    f.counter(name, "", &[(label, value)], 1.0);
    f.gauge("g", "", &[(label, value)], -1.0);
    let mut out = Vec::new();
    for flavor in [crate::Flavor::Statsd, crate::Flavor::DogStatsd] {
        let mut r = crate::statsd::Renderer::new(flavor, value.to_owned(), 10);
        out.extend(r.render(&f));
    }
    out
}

#[cfg(test)]
mod tests {
    //! The fuzz targets' invariants over seeded random inputs (cargo-fuzz runs them longer).
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, seed: &[u8], alphabet: &[u8]) -> Vec<u8> {
            let mut v = seed.to_vec();
            for _ in 0..(self.next() % 8) {
                let r = self.next() as usize;
                let b = alphabet[r % alphabet.len()];
                match r % 3 {
                    0 if !v.is_empty() => {
                        let i = (r >> 8) % v.len();
                        v[i] = b;
                    }
                    1 if !v.is_empty() => {
                        v.remove((r >> 8) % v.len());
                    }
                    _ => v.insert((r >> 8) % (v.len() + 1), b),
                }
            }
            v
        }
    }

    /// Undoes `tree::json_str` (with its quotes).
    fn unjson(s: &str) -> String {
        let inner = &s[1..s.len() - 1];
        let mut out = String::new();
        let mut it = inner.chars();
        while let Some(c) = it.next() {
            if c != '\\' {
                assert!(c != '"' && (c as u32) >= 0x20, "unescaped {c:?} in {s}");
                out.push(c);
                continue;
            }
            match it.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    let h: String = it.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&h, 16).unwrap()).unwrap());
                }
                Some(c) => out.push(c),
                None => panic!("dangling escape in {s}"),
            }
        }
        out
    }

    #[test]
    fn random_responses_never_panic() {
        let seeds: [&[u8]; 3] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.0 503 Busy\r\nConnection: close\r\n\r\nretry",
        ];
        let mut r = Rng(0x9e37_79b9_7f4a_7c15);
        for i in 0..200_000 {
            let v = r.bytes(seeds[i % 3], b"0123456789abcdefHTP/: \r\n;-\xff");
            http_response(&v);
        }
    }

    #[test]
    fn random_strings_keep_json_protobuf_and_statsd_framing() {
        let mut r = Rng(42);
        for _ in 0..20_000 {
            let raw = r.bytes(b"GET /a", b"a\"\\\n\r\t\x01\x1f|#,:@ /\xc3\xa9");
            let s = String::from_utf8_lossy(&raw).into_owned();
            let mut js = String::new();
            crate::tree::json_str(&mut js, &s);
            assert_eq!(unjson(&js), s);
            let pb = otlp_span_protobuf(&s, "k", "v");
            let needle = s.as_bytes();
            assert!(pb.windows(needle.len().max(1)).any(|w| w == needle) || needle.is_empty());
            for line in statsd_lines("m", "l", &s) {
                assert!(!line.contains('\n'), "{line:?}");
                let pipes = line.matches('|').count();
                assert!(pipes == 1 || pipes == 2, "{line:?}");
            }
        }
    }
}
