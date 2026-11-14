//! QPACK (RFC 9204) without a dynamic table: we advertise a table capacity of 0, so a peer may
//! only use static references and literals; we encode with the same. Huffman-coded strings
//! from the peer are decoded (with HPACK's code, which QPACK shares).

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::table::STATIC;

/// A decoded field section: (name, value) pairs in order.
pub type Fields = Vec<(Vec<u8>, Vec<u8>)>;

/// A field section that cannot be decoded (`QPACK_DECOMPRESSION_FAILED`) or is too large.
#[derive(Debug, PartialEq, Eq)]
pub enum QpackError {
    /// Malformed, or refers to a dynamic table we do not have.
    Decompression,
    /// Over the configured field section size.
    TooLarge,
}

pub(crate) fn put_int(out: &mut Vec<u8>, flags: u8, prefix: u8, mut v: u64) {
    let max = (1u64 << prefix) - 1;
    if v < max {
        out.push(flags | v as u8);
        return;
    }
    out.push(flags | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_int(b: &[u8], pos: &mut usize, prefix: u8) -> Result<u64, QpackError> {
    let max = (1u64 << prefix) - 1;
    let first = *b.get(*pos).ok_or(QpackError::Decompression)?;
    *pos += 1;
    let mut v = u64::from(first) & max;
    if v < max {
        return Ok(v);
    }
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

/// A string literal whose length has a `prefix`-bit prefix and whose Huffman flag is the bit
/// just above it.
fn get_str(b: &[u8], pos: &mut usize, prefix: u8) -> Result<Vec<u8>, QpackError> {
    let huff = b.get(*pos).ok_or(QpackError::Decompression)? & (1 << prefix) != 0;
    let len = get_int(b, pos, prefix)? as usize;
    let raw = b
        .get(*pos..pos.checked_add(len).ok_or(QpackError::Decompression)?)
        .ok_or(QpackError::Decompression)?;
    *pos += len;
    if huff {
        let mut out = Vec::with_capacity(raw.len() + raw.len() / 2);
        flash_http::hpack::decode_huffman(raw, &mut out).map_err(|_| QpackError::Decompression)?;
        Ok(out)
    } else {
        Ok(raw.to_vec())
    }
}

fn static_entry(i: u64) -> Result<(&'static str, &'static str), QpackError> {
    STATIC
        .get(i as usize)
        .copied()
        .ok_or(QpackError::Decompression)
}

/// Decodes a field section; `max` bounds the sum of name + value + 32 per field (RFC 9114
/// `SETTINGS_MAX_FIELD_SECTION_SIZE`).
pub fn decode(b: &[u8], max: usize) -> Result<Fields, QpackError> {
    let mut pos = 0;
    let ric = get_int(b, &mut pos, 8)?;
    if ric != 0 {
        return Err(QpackError::Decompression);
    }
    let _delta_base = get_int(b, &mut pos, 7)?;
    let mut out = Vec::new();
    let mut size = 0usize;
    while pos < b.len() {
        let first = b[pos];
        let (n, v) = if first & 0x80 != 0 {
            // Indexed field line: 1 T index(6).
            if first & 0x40 == 0 {
                return Err(QpackError::Decompression);
            }
            let (n, v) = static_entry(get_int(b, &mut pos, 6)?)?;
            (n.as_bytes().to_vec(), v.as_bytes().to_vec())
        } else if first & 0x40 != 0 {
            // Literal with name reference: 01 N T index(4).
            if first & 0x10 == 0 {
                return Err(QpackError::Decompression);
            }
            let (n, _) = static_entry(get_int(b, &mut pos, 4)?)?;
            (n.as_bytes().to_vec(), get_str(b, &mut pos, 7)?)
        } else if first & 0x20 != 0 {
            // Literal with literal name: 001 N H len(3).
            let n = get_str(b, &mut pos, 3)?;
            (n, get_str(b, &mut pos, 7)?)
        } else {
            // Post-base forms refer to the dynamic table.
            return Err(QpackError::Decompression);
        };
        size += n.len() + v.len() + 32;
        if size > max {
            return Err(QpackError::TooLarge);
        }
        out.push((n, v));
    }
    Ok(out)
}

struct Index {
    full: HashMap<(&'static str, &'static str), usize>,
    name: HashMap<&'static str, usize>,
}

fn index() -> &'static Index {
    static I: OnceLock<Index> = OnceLock::new();
    I.get_or_init(|| {
        let mut full = HashMap::new();
        let mut name = HashMap::new();
        for (i, &(n, v)) in STATIC.iter().enumerate() {
            full.entry((n, v)).or_insert(i);
            name.entry(n).or_insert(i);
        }
        Index { full, name }
    })
}

/// Encodes a field section with static references and plain literals. Names must already be
/// lowercase.
pub fn encode<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0, 0]);
    let ix = index();
    for (n, v) in fields {
        if let Some(&i) = ix.full.get(&(n, v)) {
            put_int(out, 0xc0, 6, i as u64);
        } else if let Some(&i) = ix.name.get(n) {
            put_int(out, 0x50, 4, i as u64);
            put_int(out, 0, 7, v.len() as u64);
            out.extend_from_slice(v.as_bytes());
        } else {
            put_int(out, 0x20, 3, n.len() as u64);
            out.extend_from_slice(n.as_bytes());
            put_int(out, 0, 7, v.len() as u64);
            out.extend_from_slice(v.as_bytes());
        }
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
        // Large integers.
        let mut big = Vec::new();
        put_int(&mut big, 0, 7, 1_000_000);
        let mut p = 0;
        assert_eq!(get_int(&big, &mut p, 7).unwrap(), 1_000_000);
    }
}
