//! QPACK (RFC 9204) without a dynamic table: we advertise a table capacity of 0, so a peer may
//! only use static references and literals; we encode with the same. Huffman-coded strings
//! from the peer are decoded (with HPACK's code, which QPACK shares).

use std::sync::OnceLock;

use crate::table::STATIC;

/// A decoded field section: (name, value) pairs in order.
pub type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// A field section that cannot be decoded (`QPACK_DECOMPRESSION_FAILED`) or is too large.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QpackError {
    /// Malformed, or refers to a dynamic table we do not have.
    Decompression,
    /// Over the configured field section size.
    TooLarge,
}

impl std::fmt::Display for QpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            QpackError::Decompression => "QPACK decompression failed",
            QpackError::TooLarge => "field section too large",
        })
    }
}

impl std::error::Error for QpackError {}

/// Appends a prefixed integer (RFC 7541 §5.1) after `flags`.
#[inline(always)]
pub(crate) fn put_int(out: &mut Vec<u8>, flags: u8, prefix: u8, v: u64) {
    let max = (1u64 << prefix) - 1;
    if v < max {
        out.push(flags | v as u8);
    } else {
        put_int_more(out, flags | max as u8, v - max);
    }
}

fn put_int_more(out: &mut Vec<u8>, first: u8, mut v: u64) {
    out.push(first);
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Reads a prefixed integer at `pos` (the one-byte case inline, the rest out of line).
#[inline(always)]
fn get_int(b: &[u8], pos: &mut usize, prefix: u8) -> Result<u64, QpackError> {
    let max = (1u64 << prefix) - 1;
    let first = *b.get(*pos).ok_or(QpackError::Decompression)?;
    *pos += 1;
    let v = u64::from(first) & max;
    if v < max {
        return Ok(v);
    }
    get_int_more(b, pos, v)
}

fn get_int_more(b: &[u8], pos: &mut usize, mut v: u64) -> Result<u64, QpackError> {
    let mut shift = 0;
    loop {
        let byte = *b.get(*pos).ok_or(QpackError::Decompression)?;
        *pos += 1;
        if shift > 56 {
            return Err(QpackError::Decompression);
        }
        v += u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
}

/// Appends a string literal whose length has a `prefix`-bit prefix and whose Huffman flag is
/// the bit just above it.
fn get_str(b: &[u8], pos: &mut usize, prefix: u8, out: &mut Vec<u8>) -> Result<(), QpackError> {
    let huff = b.get(*pos).ok_or(QpackError::Decompression)? & (1 << prefix) != 0;
    let len = get_int(b, pos, prefix)? as usize;
    let raw = b
        .get(*pos..pos.checked_add(len).ok_or(QpackError::Decompression)?)
        .ok_or(QpackError::Decompression)?;
    *pos += len;
    if huff {
        only_http::hpack::decode_huffman(raw, out).map_err(|_| QpackError::Decompression)
    } else {
        out.extend_from_slice(raw);
        Ok(())
    }
}

fn static_entry(i: u64) -> Result<(&'static str, &'static str), QpackError> {
    STATIC
        .get(i as usize)
        .copied()
        .ok_or(QpackError::Decompression)
}

/// A decoded field section, flat: every name and value in one buffer that is reused from one
/// section to the next (a `Vec` per name and per value cost two allocations per field).
#[derive(Default)]
pub(crate) struct FieldBuf {
    buf: Vec<u8>,
    /// Per field: name at `buf[.0...1]`, value at `buf[.1...2]`.
    spans: Vec<(usize, usize, usize)>,
}

impl FieldBuf {
    /// Fields in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.spans
            .iter()
            .map(|&(a, b, c)| (&self.buf[a..b], &self.buf[b..c]))
    }

    /// Fields as text; `None` if any name or value is not UTF-8. One validation pass over the
    /// whole buffer (plus a char-boundary check per field) instead of one per name and value.
    pub(crate) fn strs(&self) -> Option<impl Iterator<Item = (&str, &str)>> {
        let s = std::str::from_utf8(&self.buf).ok()?;
        if !self
            .spans
            .iter()
            .all(|&(a, b, _)| s.is_char_boundary(a) && s.is_char_boundary(b))
        {
            return None;
        }
        // The last field ends at the end of the buffer, so every boundary is checked.
        Some(
            self.spans
                .iter()
                .map(move |&(a, b, c)| (&s[a..b], &s[b..c])),
        )
    }

    /// Number of fields.
    pub(crate) fn len(&self) -> usize {
        self.spans.len()
    }

    /// Number of fields that are not pseudo-header fields.
    pub(crate) fn regular(&self) -> usize {
        self.spans
            .iter()
            .filter(|&&(a, b, _)| a == b || self.buf[a] != b':')
            .count()
    }

    /// Bytes of names and values.
    pub(crate) fn bytes(&self) -> usize {
        self.buf.len()
    }
}

/// Decodes a field section into `out` (cleared first); `max` bounds the sum of name + value +
/// 32 per field (RFC 9114 `SETTINGS_MAX_FIELD_SECTION_SIZE`).
pub(crate) fn decode_into(b: &[u8], max: usize, out: &mut FieldBuf) -> Result<(), QpackError> {
    out.buf.clear();
    out.spans.clear();
    let mut pos = 0;
    let ric = get_int(b, &mut pos, 8)?;
    if ric != 0 {
        return Err(QpackError::Decompression);
    }
    let _delta_base = get_int(b, &mut pos, 7)?;
    let mut size = 0usize;
    while pos < b.len() {
        let first = b[pos];
        let a = out.buf.len();
        let mid;
        if first & 0x80 != 0 {
            // Indexed field line: 1 T index(6).
            if first & 0x40 == 0 {
                return Err(QpackError::Decompression);
            }
            let (n, v) = static_entry(get_int(b, &mut pos, 6)?)?;
            out.buf.extend_from_slice(n.as_bytes());
            mid = out.buf.len();
            out.buf.extend_from_slice(v.as_bytes());
        } else if first & 0x40 != 0 {
            // Literal with name reference: 01 N T index(4).
            if first & 0x10 == 0 {
                return Err(QpackError::Decompression);
            }
            let (n, _) = static_entry(get_int(b, &mut pos, 4)?)?;
            out.buf.extend_from_slice(n.as_bytes());
            mid = out.buf.len();
            get_str(b, &mut pos, 7, &mut out.buf)?;
        } else if first & 0x20 != 0 {
            // Literal with literal name: 001 N H len(3).
            get_str(b, &mut pos, 3, &mut out.buf)?;
            mid = out.buf.len();
            get_str(b, &mut pos, 7, &mut out.buf)?;
        } else {
            // Post-base forms refer to the dynamic table.
            return Err(QpackError::Decompression);
        }
        size += out.buf.len() - a + 32;
        if size > max {
            return Err(QpackError::TooLarge);
        }
        out.spans.push((a, mid, out.buf.len()));
    }
    Ok(())
}

/// Decodes a field section; `max` bounds the sum of name + value + 32 per field (RFC 9114
/// `SETTINGS_MAX_FIELD_SECTION_SIZE`).
pub fn decode(b: &[u8], max: usize) -> Result<Fields, QpackError> {
    let mut f = FieldBuf::default();
    decode_into(b, max, &mut f)?;
    Ok(f.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect())
}

/// The static table by name length: for each name, its entries' indices (the first one is the
/// name reference). Lookups compare a few names of the same length instead of hashing.
type ByLen = Vec<Vec<(&'static [u8], Vec<u8>)>>;

fn by_len() -> &'static ByLen {
    static I: OnceLock<ByLen> = OnceLock::new();
    I.get_or_init(|| {
        let mut t: ByLen = Vec::new();
        for (i, &(n, _)) in STATIC.iter().enumerate() {
            let n = n.as_bytes();
            if t.len() <= n.len() {
                t.resize_with(n.len() + 1, Vec::new);
            }
            let row = &mut t[n.len()];
            match row.iter_mut().find(|(m, _)| *m == n) {
                Some((_, ix)) => ix.push(i as u8),
                None => row.push((n, vec![i as u8])),
            }
        }
        t
    })
}

/// Appends one field line: an indexed line when the static table has the field, a literal with
/// a name reference when it has the name, else a literal with a literal name. `n` must already
/// be lowercase.
pub(crate) fn encode_line(out: &mut Vec<u8>, n: &[u8], v: &[u8]) {
    let ix = by_len()
        .get(n.len())
        .and_then(|row| row.iter().find(|(m, _)| *m == n))
        .map(|(_, ix)| ix.as_slice());
    if let Some(ix) = ix {
        if let Some(&i) = ix
            .iter()
            .find(|&&i| STATIC[usize::from(i)].1.as_bytes() == v)
        {
            put_int(out, 0xc0, 6, u64::from(i));
            return;
        }
        put_int(out, 0x50, 4, u64::from(ix[0]));
    } else {
        put_int(out, 0x20, 3, n.len() as u64);
        out.extend_from_slice(n);
    }
    put_int(out, 0, 7, v.len() as u64);
    out.extend_from_slice(v);
}

/// Static table indices of `:status` lines (RFC 9204 Appendix A).
fn status_index(status: u16) -> Option<u8> {
    Some(match status {
        103 => 24,
        200 => 25,
        304 => 26,
        404 => 27,
        503 => 28,
        100 => 63,
        204 => 64,
        206 => 65,
        302 => 66,
        400 => 67,
        403 => 68,
        421 => 69,
        425 => 70,
        500 => 71,
        _ => return None,
    })
}

/// Appends a `:status` line without a table search: an indexed line for the codes the static
/// table has, else a literal with the name reference.
pub(crate) fn encode_status(out: &mut Vec<u8>, status: u16) {
    match status_index(status) {
        Some(i) => put_int(out, 0xc0, 6, u64::from(i)),
        None => {
            let mut b = [0; 20];
            let v = crate::digits(&mut b, u64::from(status));
            put_int(out, 0x50, 4, 24);
            put_int(out, 0, 7, v.len() as u64);
            out.extend_from_slice(v);
        }
    }
}

/// Appends a `content-length` line without a table search.
pub(crate) fn encode_content_length(out: &mut Vec<u8>, len: u64) {
    if len == 0 {
        put_int(out, 0xc0, 6, 4);
    } else {
        let mut b = [0; 20];
        let v = crate::digits(&mut b, len);
        put_int(out, 0x50, 4, 4);
        put_int(out, 0, 7, v.len() as u64);
        out.extend_from_slice(v);
    }
}

/// The field section prefix: no dynamic table references (Required Insert Count 0, Base 0).
pub(crate) const PREFIX: [u8; 2] = [0, 0];

/// Encodes a field section with static references and plain literals. Names must already be
/// lowercase.
pub fn encode<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>, out: &mut Vec<u8>) {
    out.extend_from_slice(&PREFIX);
    for (n, v) in fields {
        encode_line(out, n.as_bytes(), v.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rfc_examples() {
        let fields = [
            (":method", "GET"),
            (":path", "/index.html"),
            (":authority", "example.com"),
            ("x-custom", "v"),
            ("content-type", "text/css"),
        ];
        let mut b = Vec::new();
        encode(fields.iter().copied(), &mut b);
        let d = decode(&b, 1 << 16).unwrap();
        let got: Vec<(String, String)> = d
            .into_iter()
            .map(|(n, v)| (String::from_utf8(n).unwrap(), String::from_utf8(v).unwrap()))
            .collect();
        let want: Vec<(String, String)> = fields
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(got, want);
        // RFC 9204 B.1: literal with name reference to :path, value "/index.html".
        let rfc = [
            0x00, 0x00, 0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm',
            b'l',
        ];
        assert_eq!(
            decode(&rfc, 1000).unwrap(),
            vec![(b":path".to_vec(), b"/index.html".to_vec())]
        );
        // Huffman value: "www.example.com" (RFC 7541 C.4.1).
        let mut h = vec![0, 0, 0x50, 0x8c];
        h.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        assert_eq!(decode(&h, 1000).unwrap()[0].1, b"www.example.com");
        // Dynamic references are refused.
        assert_eq!(
            decode(&[0x02, 0x00, 0x80], 1000),
            Err(QpackError::Decompression)
        );
        assert_eq!(
            decode(&[0x00, 0x00, 0x10], 1000),
            Err(QpackError::Decompression)
        );
        assert_eq!(decode(&b, 10), Err(QpackError::TooLarge));
        // Text: valid fields, a value that is not UTF-8, and a name and value that are only
        // UTF-8 together (a character split between them).
        let text = |n: &[u8], v: &[u8]| {
            let mut b = vec![0, 0, 0x20 | n.len() as u8];
            b.extend_from_slice(n);
            b.push(v.len() as u8);
            b.extend_from_slice(v);
            let mut f = FieldBuf::default();
            decode_into(&b, 1000, &mut f).unwrap();
            f.strs()
                .map(|i| i.map(|(n, v)| format!("{n}={v}")).collect::<Vec<_>>())
        };
        assert_eq!(
            text(b"x-a", "é".as_bytes()),
            Some(vec!["x-a=é".to_string()])
        );
        assert_eq!(text(b"x-a", &[0xff]), None);
        assert_eq!(text(&[b'x', 0xc3], &[0xa9]), None);
        // The fast paths encode what the table search does.
        for status in [100u16, 103, 200, 204, 299, 304, 404, 500, 503, 999, 1000] {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            encode_status(&mut a, status);
            encode_line(&mut b, b":status", status.to_string().as_bytes());
            assert_eq!(a, b, "{status}");
        }
        for len in [0u64, 1, 9, 10, 1234, u64::MAX] {
            let (mut a, mut b) = (Vec::new(), Vec::new());
            encode_content_length(&mut a, len);
            encode_line(&mut b, b"content-length", len.to_string().as_bytes());
            assert_eq!(a, b, "{len}");
        }
        // Large integers.
        let mut big = Vec::new();
        put_int(&mut big, 0, 7, 1_000_000);
        let mut p = 0;
        assert_eq!(get_int(&big, &mut p, 7).unwrap(), 1_000_000);
    }
}
