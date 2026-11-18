//! A small message tree serialized as protobuf (the OTLP wire format) or as OTLP/JSON, so both
//! encodings come from one description of each message.

use only_protobuf::encoding::{WireType, put_bytes, put_tag, put_varint};

/// One value of a message field.
#[derive(Debug, Clone)]
pub(crate) enum Node {
    Msg(Vec<Field>),
    Str(String),
    /// Trace and span ids: bytes in protobuf, lower-case hex in JSON.
    Id(Vec<u8>),
    /// `fixed64` (timestamps, counts): a decimal string in JSON.
    Fixed64(u64),
    /// `fixed32` (span flags).
    Fixed32(u32),
    /// `int64`: a decimal string in JSON.
    I64(i64),
    /// `uint32` or an enum value.
    U32(u32),
    Double(f64),
    Bool(bool),
    /// `repeated fixed64`, packed.
    PackedFixed64(Vec<u64>),
    /// `repeated double`, packed.
    PackedDouble(Vec<f64>),
}

#[derive(Debug, Clone)]
pub(crate) struct Field {
    pub(crate) num: u32,
    pub(crate) name: &'static str,
    /// A repeated field: a JSON array even with one element.
    pub(crate) repeated: bool,
    pub(crate) val: Node,
}

/// Builds the fields of one message.
#[derive(Default, Debug)]
pub(crate) struct Msg(pub(crate) Vec<Field>);

impl Msg {
    pub(crate) fn new() -> Msg {
        Msg(Vec::new())
    }

    pub(crate) fn set(&mut self, num: u32, name: &'static str, val: Node) -> &mut Msg {
        self.0.push(Field {
            num,
            name,
            repeated: false,
            val,
        });
        self
    }

    pub(crate) fn push(&mut self, num: u32, name: &'static str, val: Node) -> &mut Msg {
        self.0.push(Field {
            num,
            name,
            repeated: true,
            val,
        });
        self
    }

    pub(crate) fn str(&mut self, num: u32, name: &'static str, v: impl Into<String>) -> &mut Msg {
        self.set(num, name, Node::Str(v.into()))
    }

    pub(crate) fn msg(&mut self, num: u32, name: &'static str, m: Msg) -> &mut Msg {
        self.set(num, name, Node::Msg(m.0))
    }

    pub(crate) fn push_msg(&mut self, num: u32, name: &'static str, m: Msg) -> &mut Msg {
        self.push(num, name, Node::Msg(m.0))
    }
}

// ---- protobuf --------------------------------------------------------------------------------

pub(crate) fn to_protobuf(fields: &[Field], out: &mut Vec<u8>) {
    for f in fields {
        match &f.val {
            Node::Msg(m) => {
                let mut inner = Vec::new();
                to_protobuf(m, &mut inner);
                put_tag(out, f.num, WireType::Len);
                put_bytes(out, &inner);
            }
            Node::Str(s) => {
                put_tag(out, f.num, WireType::Len);
                put_bytes(out, s.as_bytes());
            }
            Node::Id(b) => {
                put_tag(out, f.num, WireType::Len);
                put_bytes(out, b);
            }
            Node::Fixed64(v) => {
                put_tag(out, f.num, WireType::Fixed64);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Node::Fixed32(v) => {
                put_tag(out, f.num, WireType::Fixed32);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Node::I64(v) => {
                put_tag(out, f.num, WireType::Varint);
                put_varint(out, *v as u64);
            }
            Node::U32(v) => {
                put_tag(out, f.num, WireType::Varint);
                put_varint(out, u64::from(*v));
            }
            Node::Double(v) => {
                put_tag(out, f.num, WireType::Fixed64);
                out.extend_from_slice(&v.to_bits().to_le_bytes());
            }
            Node::Bool(v) => {
                put_tag(out, f.num, WireType::Varint);
                put_varint(out, u64::from(*v));
            }
            Node::PackedFixed64(v) => {
                put_tag(out, f.num, WireType::Len);
                put_varint(out, (v.len() * 8) as u64);
                for x in v {
                    out.extend_from_slice(&x.to_le_bytes());
                }
            }
            Node::PackedDouble(v) => {
                put_tag(out, f.num, WireType::Len);
                put_varint(out, (v.len() * 8) as u64);
                for x in v {
                    out.extend_from_slice(&x.to_bits().to_le_bytes());
                }
            }
        }
    }
}

// ---- JSON (OTLP/JSON: lowerCamelCase names, hex ids, 64-bit integers as strings) ------------

pub(crate) fn to_json(fields: &[Field], out: &mut String) {
    out.push('{');
    let mut first = true;
    let mut done = vec![false; fields.len()];
    for i in 0..fields.len() {
        if done[i] {
            continue;
        }
        let f = &fields[i];
        if !first {
            out.push(',');
        }
        first = false;
        json_str(out, f.name);
        out.push(':');
        if f.repeated {
            out.push('[');
            let mut n = 0;
            for j in i..fields.len() {
                if fields[j].repeated && fields[j].name == f.name {
                    done[j] = true;
                    if n > 0 {
                        out.push(',');
                    }
                    n += 1;
                    json_val(&fields[j].val, out);
                }
            }
            out.push(']');
        } else {
            json_val(&f.val, out);
        }
    }
    out.push('}');
}

fn json_double(v: f64, out: &mut String) {
    if v.is_nan() {
        out.push_str("\"NaN\"");
    } else if v.is_infinite() {
        out.push_str(if v > 0.0 {
            "\"Infinity\""
        } else {
            "\"-Infinity\""
        });
    } else {
        out.push_str(&format!("{v:?}"));
    }
}

fn json_val(v: &Node, out: &mut String) {
    match v {
        Node::Msg(m) => to_json(m, out),
        Node::Str(s) => json_str(out, s),
        Node::Id(b) => {
            out.push('"');
            for x in b {
                out.push_str(&format!("{x:02x}"));
            }
            out.push('"');
        }
        Node::Fixed64(v) => out.push_str(&format!("\"{v}\"")),
        Node::I64(v) => out.push_str(&format!("\"{v}\"")),
        Node::Fixed32(v) | Node::U32(v) => out.push_str(&v.to_string()),
        Node::Double(v) => json_double(*v, out),
        Node::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
        Node::PackedFixed64(v) => {
            out.push('[');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&format!("\"{x}\""));
            }
            out.push(']');
        }
        Node::PackedDouble(v) => {
            out.push('[');
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_double(*x, out);
            }
            out.push(']');
        }
    }
}

pub(crate) fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_and_json_of_one_tree() {
        let mut inner = Msg::new();
        inner
            .str(1, "key", "a\"b")
            .set(3, "intValue", Node::I64(-1));
        let mut m = Msg::new();
        m.push_msg(1, "items", inner)
            .set(2, "id", Node::Id(vec![0xab, 0x01]))
            .set(3, "time", Node::Fixed64(5))
            .set(4, "flag", Node::Bool(true))
            .set(5, "ratio", Node::Double(0.5))
            .set(6, "counts", Node::PackedFixed64(vec![1, 2]))
            .set(7, "kind", Node::U32(2));
        let mut pb = Vec::new();
        to_protobuf(&m.0, &mut pb);
        // items: tag 0x0a, len, { key: 0x0a 03 'a"b', intValue: 0x18 ff..01 }
        assert_eq!(&pb[..2], &[0x0a, 0x10]);
        assert_eq!(&pb[2..7], &[0x0a, 0x03, b'a', b'"', b'b']);
        assert_eq!(pb[7], 0x18);
        assert_eq!(
            &pb[8..18],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
        assert_eq!(&pb[18..22], &[0x12, 0x02, 0xab, 0x01]);
        assert_eq!(&pb[22..31], &[0x19, 5, 0, 0, 0, 0, 0, 0, 0]);
        let mut js = String::new();
        to_json(&m.0, &mut js);
        assert_eq!(
            js,
            r#"{"items":[{"key":"a\"b","intValue":"-1"}],"id":"ab01","time":"5","flag":true,"ratio":0.5,"counts":["1","2"],"kind":2}"#
        );
    }
}
