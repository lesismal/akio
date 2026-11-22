//! AMF0 (read and write) and AMF3 (read) values, as RTMP commands and FLV script data carry
//! them (Adobe "Action Message Format" AMF0 and AMF3 specifications).

use std::fmt;

/// An AMF value. AMF3 values decode into the same variants (integers as numbers, byte arrays
/// and XML as strings or bytes).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// A double.
    Number(f64),
    /// A boolean.
    Bool(bool),
    /// A string (short or long).
    String(String),
    /// An anonymous or typed object, keys in order.
    Object(Vec<(String, Value)>),
    /// `null`.
    Null,
    /// `undefined`.
    Undefined,
    /// An ECMA (associative) array, keys in order.
    EcmaArray(Vec<(String, Value)>),
    /// A strict (dense) array.
    Array(Vec<Value>),
    /// A date: milliseconds since the epoch.
    Date(f64),
    /// An AMF3 byte array.
    Bytes(Vec<u8>),
}

impl Value {
    /// The number, if this is one.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The properties of an object or ECMA array.
    pub fn props(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Object(p) | Value::EcmaArray(p) => Some(p),
            _ => None,
        }
    }

    /// The property `key` of an object or ECMA array.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.props()?.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// An object from `(key, value)` pairs.
    pub fn object<K: Into<String>>(props: impl IntoIterator<Item = (K, Value)>) -> Value {
        Value::Object(props.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(s.to_owned())
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Value {
        Value::Number(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}

/// Malformed AMF data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AmfError {
    /// The data ended inside a value.
    Short,
    /// An unknown or unsupported type marker.
    Marker(u8),
    /// Nesting deeper than the limit, a bad reference or invalid UTF-8.
    Invalid,
}

impl fmt::Display for AmfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmfError::Short => f.write_str("AMF data too short"),
            AmfError::Marker(m) => write!(f, "unsupported AMF marker {m:#04x}"),
            AmfError::Invalid => f.write_str("malformed AMF data"),
        }
    }
}

impl std::error::Error for AmfError {}

const MAX_DEPTH: usize = 64;

/// Reads AMF0 values one after the other.
#[derive(Debug)]
pub struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `b`.
    pub fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, p: 0 }
    }

    /// Whether every byte was read.
    pub fn is_empty(&self) -> bool {
        self.p >= self.b.len()
    }

    /// The bytes not read yet.
    pub fn rest(&self) -> &'a [u8] {
        &self.b[self.p.min(self.b.len())..]
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AmfError> {
        let s = self
            .b
            .get(self.p..self.p.checked_add(n).ok_or(AmfError::Short)?);
        let s = s.ok_or(AmfError::Short)?;
        self.p += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, AmfError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AmfError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32, AmfError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn f64(&mut self) -> Result<f64, AmfError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(f64::from_be_bytes(a))
    }

    fn str_n(&mut self, n: usize) -> Result<String, AmfError> {
        let s = self.take(n)?;
        Ok(String::from_utf8_lossy(s).into_owned())
    }

    fn short_str(&mut self) -> Result<String, AmfError> {
        let n = usize::from(self.u16()?);
        self.str_n(n)
    }

    /// Reads one AMF0 value (switching to AMF3 at the `avmplus` marker).
    pub fn read(&mut self) -> Result<Value, AmfError> {
        self.read_depth(0)
    }

    /// Reads every remaining value.
    pub fn read_all(&mut self) -> Result<Vec<Value>, AmfError> {
        let mut v = Vec::new();
        while !self.is_empty() {
            v.push(self.read()?);
        }
        Ok(v)
    }

    fn props(&mut self, depth: usize) -> Result<Vec<(String, Value)>, AmfError> {
        let mut props = Vec::new();
        loop {
            let k = self.short_str()?;
            if k.is_empty() {
                // The object-end marker; tolerate its absence at the end of the data.
                if self.is_empty() {
                    return Ok(props);
                }
                let m = self.u8()?;
                if m == 0x09 {
                    return Ok(props);
                }
                self.p -= 1;
            }
            let v = self.read_depth(depth + 1)?;
            props.push((k, v));
        }
    }

    fn read_depth(&mut self, depth: usize) -> Result<Value, AmfError> {
        if depth > MAX_DEPTH {
            return Err(AmfError::Invalid);
        }
        let m = self.u8()?;
        Ok(match m {
            0x00 => Value::Number(self.f64()?),
            0x01 => Value::Bool(self.u8()? != 0),
            0x02 => Value::String(self.short_str()?),
            0x03 => Value::Object(self.props(depth)?),
            0x05 => Value::Null,
            0x06 => Value::Undefined,
            0x07 => {
                self.u16()?; // reference: not resolved
                Value::Undefined
            }
            0x08 => {
                self.u32()?; // count hint, often wrong
                Value::EcmaArray(self.props(depth)?)
            }
            0x0a => {
                let n = self.u32()? as usize;
                let mut v = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    v.push(self.read_depth(depth + 1)?);
                }
                Value::Array(v)
            }
            0x0b => {
                let ms = self.f64()?;
                self.u16()?; // time zone
                Value::Date(ms)
            }
            0x0c | 0x0f => {
                let n = self.u32()? as usize;
                Value::String(self.str_n(n)?)
            }
            0x0d => Value::Undefined, // unsupported
            0x10 => {
                self.short_str()?; // class name
                Value::Object(self.props(depth)?)
            }
            0x11 => {
                let mut r3 = Amf3::default();
                let mut rd = Amf3Reader {
                    r: self,
                    t: &mut r3,
                };
                rd.value(depth + 1)?
            }
            m => return Err(AmfError::Marker(m)),
        })
    }
}

/// Reads AMF0 values from `b`: a command message or script tag body.
pub fn decode_all(b: &[u8]) -> Result<Vec<Value>, AmfError> {
    Reader::new(b).read_all()
}

/// Reads AMF3 values from `b` (the body of an AMF3 data message after its format byte).
pub fn decode_amf3_all(b: &[u8]) -> Result<Vec<Value>, AmfError> {
    let mut r = Reader::new(b);
    let mut t = Amf3::default();
    let mut v = Vec::new();
    while !r.is_empty() {
        let mut rd = Amf3Reader {
            r: &mut r,
            t: &mut t,
        };
        v.push(rd.value(0)?);
    }
    Ok(v)
}

#[derive(Default)]
struct Amf3 {
    strings: Vec<String>,
    objects: Vec<Value>,
    traits: Vec<(Vec<String>, bool)>,
}

struct Amf3Reader<'r, 'a> {
    r: &'r mut Reader<'a>,
    t: &'r mut Amf3,
}

impl Amf3Reader<'_, '_> {
    fn u29(&mut self) -> Result<u32, AmfError> {
        let mut v = 0u32;
        for i in 0..4 {
            let b = self.r.u8()?;
            if i == 3 {
                return Ok((v << 8) | u32::from(b));
            }
            v = (v << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, AmfError> {
        let h = self.u29()?;
        if h & 1 == 0 {
            return self
                .t
                .strings
                .get((h >> 1) as usize)
                .cloned()
                .ok_or(AmfError::Invalid);
        }
        let s = self.r.str_n((h >> 1) as usize)?;
        if !s.is_empty() {
            self.t.strings.push(s.clone());
        }
        Ok(s)
    }

    fn obj_ref(&self, h: u32) -> Result<Value, AmfError> {
        self.t
            .objects
            .get((h >> 1) as usize)
            .cloned()
            .ok_or(AmfError::Invalid)
    }

    fn value(&mut self, depth: usize) -> Result<Value, AmfError> {
        if depth > MAX_DEPTH {
            return Err(AmfError::Invalid);
        }
        let m = self.r.u8()?;
        Ok(match m {
            0x00 => Value::Undefined,
            0x01 => Value::Null,
            0x02 => Value::Bool(false),
            0x03 => Value::Bool(true),
            0x04 => {
                let v = self.u29()?;
                // Sign-extend the 29-bit integer.
                let i = ((v << 3) as i32) >> 3;
                Value::Number(f64::from(i))
            }
            0x05 => Value::Number(self.r.f64()?),
            0x06 => Value::String(self.string()?),
            0x07 | 0x0b => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return self.obj_ref(h);
                }
                let v = Value::String(self.r.str_n((h >> 1) as usize)?);
                self.t.objects.push(v.clone());
                v
            }
            0x08 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return self.obj_ref(h);
                }
                let v = Value::Date(self.r.f64()?);
                self.t.objects.push(v.clone());
                v
            }
            0x09 => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return self.obj_ref(h);
                }
                let n = (h >> 1) as usize;
                let mut assoc = Vec::new();
                loop {
                    let k = self.string()?;
                    if k.is_empty() {
                        break;
                    }
                    assoc.push((k, self.value(depth + 1)?));
                }
                let mut dense = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    dense.push(self.value(depth + 1)?);
                }
                let v = if assoc.is_empty() {
                    Value::Array(dense)
                } else {
                    Value::EcmaArray(assoc)
                };
                self.t.objects.push(v.clone());
                v
            }
            0x0a => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return self.obj_ref(h);
                }
                let (names, dynamic) = if h & 2 == 0 {
                    self.t
                        .traits
                        .get((h >> 2) as usize)
                        .cloned()
                        .ok_or(AmfError::Invalid)?
                } else {
                    if h & 4 != 0 {
                        return Err(AmfError::Marker(0x0a)); // externalizable
                    }
                    let dynamic = h & 8 != 0;
                    let n = (h >> 4) as usize;
                    self.string()?; // class name
                    let mut names = Vec::with_capacity(n.min(256));
                    for _ in 0..n {
                        names.push(self.string()?);
                    }
                    self.t.traits.push((names.clone(), dynamic));
                    (names, dynamic)
                };
                let mut props = Vec::new();
                for k in names {
                    props.push((k, self.value(depth + 1)?));
                }
                if dynamic {
                    loop {
                        let k = self.string()?;
                        if k.is_empty() {
                            break;
                        }
                        props.push((k, self.value(depth + 1)?));
                    }
                }
                let v = Value::Object(props);
                self.t.objects.push(v.clone());
                v
            }
            0x0c => {
                let h = self.u29()?;
                if h & 1 == 0 {
                    return self.obj_ref(h);
                }
                let v = Value::Bytes(self.r.take((h >> 1) as usize)?.to_vec());
                self.t.objects.push(v.clone());
                v
            }
            m => return Err(AmfError::Marker(m)),
        })
    }
}

/// Appends the AMF0 encoding of `v`.
pub fn write(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Number(n) => {
            out.push(0x00);
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Bool(b) => out.extend_from_slice(&[0x01, u8::from(*b)]),
        Value::String(s) => write_string(out, s),
        Value::Object(p) => {
            out.push(0x03);
            write_props(out, p);
        }
        Value::Null => out.push(0x05),
        Value::Undefined => out.push(0x06),
        Value::EcmaArray(p) => {
            out.push(0x08);
            out.extend_from_slice(&(p.len() as u32).to_be_bytes());
            write_props(out, p);
        }
        Value::Array(a) => {
            out.push(0x0a);
            out.extend_from_slice(&(a.len() as u32).to_be_bytes());
            for v in a {
                write(out, v);
            }
        }
        Value::Date(ms) => {
            out.push(0x0b);
            out.extend_from_slice(&ms.to_be_bytes());
            out.extend_from_slice(&[0, 0]);
        }
        Value::Bytes(b) => write_string(out, &String::from_utf8_lossy(b)),
    }
}

/// Appends a string value (long string when over 65535 bytes).
pub fn write_string(out: &mut Vec<u8>, s: &str) {
    if s.len() > 0xffff {
        out.push(0x0c);
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    } else {
        out.push(0x02);
        out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(s.as_bytes());
}

fn write_props(out: &mut Vec<u8>, p: &[(String, Value)]) {
    for (k, v) in p {
        let k = &k.as_bytes()[..k.len().min(0xffff)];
        out.extend_from_slice(&(k.len() as u16).to_be_bytes());
        out.extend_from_slice(k);
        write(out, v);
    }
    out.extend_from_slice(&[0, 0, 0x09]);
}

/// Encodes values one after the other.
pub fn encode(values: &[Value]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        write(&mut out, v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amf0_round_trip() {
        let vals = vec![
            Value::from("connect"),
            Value::Number(1.0),
            Value::object([
                ("app", Value::from("live")),
                ("tcUrl", Value::from("rtmp://h/live")),
                ("fpad", Value::Bool(false)),
                ("nested", Value::object([("x", Value::Null)])),
            ]),
            Value::Null,
            Value::Undefined,
            Value::EcmaArray(vec![("duration".into(), Value::Number(0.0))]),
            Value::Array(vec![Value::Number(1.0), Value::from("a")]),
            Value::Date(1000.0),
            Value::String("x".repeat(70000)),
        ];
        let b = encode(&vals);
        let back = decode_all(&b).unwrap();
        assert_eq!(back, vals);
        assert_eq!(back[2].get("app").and_then(Value::as_str), Some("live"));
        for cut in 0..b.len().min(200) {
            let _ = decode_all(&b[..cut]);
        }
        assert_eq!(decode_all(&[0x42]), Err(AmfError::Marker(0x42)));
        // Deep nesting is refused, not a stack overflow.
        let deep = [0x0a, 0, 0, 0, 1].repeat(1000);
        assert_eq!(decode_all(&deep), Err(AmfError::Invalid));
    }

    #[test]
    fn amf3_values() {
        // integer 5, string "ab", the same string by reference, true, double 1.5,
        // dynamic anonymous object {k: 7}, dense array [null], byte array [1,2].
        let b = [
            0x04, 0x05, 0x06, 0x05, b'a', b'b', 0x06, 0x00, 0x03, 0x05, 0x3f, 0xf8, 0, 0, 0, 0, 0,
            0, 0x0a, 0x0b, 0x01, 0x03, b'k', 0x04, 0x07, 0x01, 0x09, 0x03, 0x01, 0x01, 0x0c, 0x05,
            1, 2,
        ];
        let v = decode_amf3_all(&b).unwrap();
        assert_eq!(
            v,
            vec![
                Value::Number(5.0),
                Value::from("ab"),
                Value::from("ab"),
                Value::Bool(true),
                Value::Number(1.5),
                Value::object([("k", Value::Number(7.0))]),
                Value::Array(vec![Value::Null]),
                Value::Bytes(vec![1, 2]),
            ]
        );
        // Negative 29-bit integer.
        assert_eq!(
            decode_amf3_all(&[0x04, 0xff, 0xff, 0xff, 0xff]).unwrap(),
            vec![Value::Number(-1.0)]
        );
        // AMF0 switching to AMF3.
        assert_eq!(decode_all(&[0x11, 0x03]).unwrap(), vec![Value::Bool(true)]);
        assert!(decode_amf3_all(&[0x06, 0x02]).is_err());
    }
}
