//! `FileDescriptorProto`s from the parsed (and resolved) files, as protoc writes them: map entry
//! types, synthetic oneofs, JSON names, canonical default values, and options encoded against
//! `descriptor.proto` (custom options and text-format aggregates included).

use std::collections::{HashMap, HashSet};

use only_protobuf::{
    Message,
    encoding::{self, WireType},
    well_known::{
        DescriptorProto, Edition as PbEdition, EnumDescriptorProto, EnumValueDescriptorProto,
        FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet, MethodDescriptorProto,
        OneofDescriptorProto, ServiceDescriptorProto, SymbolVisibility, descriptor_proto,
        enum_descriptor_proto, field_descriptor_proto as fdp,
    },
};

use crate::parse::{
    Constant, Edition, EnumDef, Field, File, Label, MessageDef, Nested, OptionDef, Options as _,
    Presence, Scalar, TypeRef, json_name, parse_int,
};

type DResult<T> = Result<T, String>;

/// Every message, enum and extension of the loaded files, by full name (leading dot).
pub(crate) struct Index<'a> {
    msgs: HashMap<String, &'a MessageDef>,
    enums: HashMap<String, &'a EnumDef>,
    exts: HashMap<String, &'a Field>,
}

impl<'a> Index<'a> {
    pub(crate) fn new(files: &'a [File]) -> Index<'a> {
        let mut ix = Index {
            msgs: HashMap::new(),
            enums: HashMap::new(),
            exts: HashMap::new(),
        };
        fn walk<'a>(m: &'a MessageDef, prefix: &str, ix: &mut Index<'a>) {
            let name = format!("{prefix}.{}", m.name);
            for e in &m.enums {
                ix.enums.insert(format!("{name}.{}", e.name), e);
            }
            for x in &m.extensions {
                ix.exts.insert(format!("{name}.{}", x.name), x);
            }
            for n in &m.messages {
                walk(n, &name, ix);
            }
            ix.msgs.insert(name, m);
        }
        for f in files {
            let prefix = pkg_prefix(&f.package);
            for m in &f.messages {
                walk(m, &prefix, &mut ix);
            }
            for e in &f.enums {
                ix.enums.insert(format!("{prefix}.{}", e.name), e);
            }
            for x in &f.extensions {
                ix.exts.insert(format!("{prefix}.{}", x.name), x);
            }
        }
        ix
    }

    /// Resolves an extension name from `scope` (protobuf scoping: innermost first).
    fn extension(&self, name: &str, scope: &str) -> Option<(String, &'a Field)> {
        if let Some(abs) = name.strip_prefix('.') {
            let k = format!(".{abs}");
            return self.exts.get(&k).map(|f| (k, *f));
        }
        let mut scope = scope.to_owned();
        loop {
            let k = format!("{scope}.{name}");
            if let Some(f) = self.exts.get(&k) {
                return Some((k, *f));
            }
            let i = scope.rfind('.')?;
            scope.truncate(i);
        }
    }
}

fn pkg_prefix(pkg: &str) -> String {
    if pkg.is_empty() {
        String::new()
    } else {
        format!(".{pkg}")
    }
}

/// A FileDescriptorSet of `names` and everything they import (dependencies first).
pub(crate) fn file_descriptor_set(
    files: &[File],
    protos: &HashMap<&str, FileDescriptorProto>,
    names: &[&str],
) -> Vec<u8> {
    let by_name: HashMap<&str, &File> = files.iter().map(|f| (f.name.as_str(), f)).collect();
    let mut order = Vec::new();
    let mut seen = HashSet::new();
    fn visit<'a>(
        n: &'a str,
        by_name: &HashMap<&str, &'a File>,
        seen: &mut HashSet<&'a str>,
        order: &mut Vec<&'a str>,
    ) {
        if !seen.insert(n) {
            return;
        }
        if let Some(f) = by_name.get(n) {
            for i in &f.imports {
                visit(i, by_name, seen, order);
            }
        }
        order.push(n);
    }
    for n in names {
        if let Some(f) = by_name.get(n) {
            visit(f.name.as_str(), &by_name, &mut seen, &mut order);
        }
    }
    let set = FileDescriptorSet {
        file: order
            .into_iter()
            .filter_map(|n| protos.get(n).cloned())
            .collect(),
        ..Default::default()
    };
    set.encode_to_vec()
}

/// Builds the descriptor of `f`, without options of `retention = RETENTION_SOURCE` (as protoc
/// writes descriptor sets and embeds descriptors in generated code).
pub(crate) fn file_descriptor(f: &File, ix: &Index<'_>) -> DResult<FileDescriptorProto> {
    let b = Builder { ix, file: f };
    let prefix = pkg_prefix(&f.package);
    let mut d = FileDescriptorProto {
        name: Some(f.name.clone()),
        package: (!f.package.is_empty()).then(|| f.package.clone()),
        ..Default::default()
    };
    for (i, (name, kind)) in f.imports.iter().zip(&f.import_kinds).enumerate() {
        use crate::parse::ImportKind;
        let _ = i;
        match kind {
            ImportKind::Option => d.option_dependency.push(name.clone()),
            _ => {
                let idx = d.dependency.len() as i32;
                d.dependency.push(name.clone());
                match kind {
                    ImportKind::Public => d.public_dependency.push(idx),
                    ImportKind::Weak => d.weak_dependency.push(idx),
                    _ => {}
                }
            }
        }
    }
    for m in &f.messages {
        d.message_type.push(b.message(m, &prefix)?);
    }
    for e in &f.enums {
        d.enum_type.push(b.enumeration(e, &prefix)?);
    }
    for s in &f.services {
        let mut sd = ServiceDescriptorProto {
            name: Some(s.name.clone()),
            options: b.options(".google.protobuf.ServiceOptions", &s.options, &prefix)?,
            ..Default::default()
        };
        for m in &s.methods {
            let ty = |t: &TypeRef| match t {
                TypeRef::Message(n) | TypeRef::Enum(n) | TypeRef::Named(n) => n.clone(),
                TypeRef::Scalar(_) => String::new(),
            };
            sd.method.push(MethodDescriptorProto {
                name: Some(m.name.clone()),
                input_type: Some(ty(&m.input)),
                output_type: Some(ty(&m.output)),
                options: match b.options(".google.protobuf.MethodOptions", &m.options, &prefix)? {
                    None if m.body => Some(Default::default()),
                    o => o,
                },
                client_streaming: m.client_streaming.then_some(true),
                server_streaming: m.server_streaming.then_some(true),
            });
        }
        d.service.push(sd);
    }
    for x in &f.extensions {
        d.extension.push(b.field(x, &prefix, None, &prefix)?);
    }
    d.options = b.options(".google.protobuf.FileOptions", &f.options, &prefix)?;
    match f.edition {
        Edition::Proto2 => {}
        Edition::Proto3 => d.syntax = Some("proto3".into()),
        e => {
            d.syntax = Some("editions".into());
            d.edition = Some(PbEdition(e.number()));
        }
    }
    Ok(d)
}

struct Builder<'a> {
    ix: &'a Index<'a>,
    file: &'a File,
}

impl Builder<'_> {
    fn message(&self, m: &MessageDef, scope: &str) -> DResult<DescriptorProto> {
        let name = format!("{scope}.{}", m.name);
        let mut d = DescriptorProto {
            name: Some(m.name.clone()),
            ..Default::default()
        };
        for o in &m.oneofs {
            d.oneof_decl.push(OneofDescriptorProto {
                name: Some(o.name.clone()),
                options: self.options(".google.protobuf.OneofOptions", &o.options, &name)?,
            });
        }
        // proto3 `optional`: a synthetic oneof per field, after the real ones, named `_<field>`
        // (prefixed with `X` until unique).
        let mut taken: HashSet<String> = m
            .fields
            .iter()
            .map(|f| f.name.clone())
            .chain(m.oneofs.iter().map(|o| o.name.clone()))
            .collect();
        for f in &m.fields {
            let synthetic = self.file.edition == Edition::Proto3
                && f.label == Label::Optional
                && f.oneof.is_none();
            let oneof = if synthetic {
                let mut n = format!("_{}", f.name);
                while taken.contains(&n) {
                    n.insert(0, 'X');
                }
                taken.insert(n.clone());
                d.oneof_decl.push(OneofDescriptorProto {
                    name: Some(n),
                    ..Default::default()
                });
                Some(d.oneof_decl.len() - 1)
            } else {
                f.oneof
            };
            let mut fd = self.field(f, &name, oneof, &name)?;
            if synthetic {
                fd.proto3_optional = Some(true);
            }
            d.field.push(fd);
        }
        for x in &m.extensions {
            d.extension.push(self.field(x, &name, None, &name)?);
        }
        for n in &m.nested_order {
            match *n {
                Nested::Message(i) => d.nested_type.push(self.message(&m.messages[i], &name)?),
                Nested::MapEntry(i) => d.nested_type.push(self.map_entry(&m.fields[i], &name)?),
            }
        }
        for e in &m.enums {
            d.enum_type.push(self.enumeration(e, &name)?);
        }
        for r in &m.extension_ranges {
            d.extension_range.push(descriptor_proto::ExtensionRange {
                start: Some(r.start as i32),
                end: Some(r.end as i32 + 1),
                options: self.options(
                    ".google.protobuf.ExtensionRangeOptions",
                    &r.options,
                    &name,
                )?,
            });
        }
        for r in &m.reserved_ranges {
            d.reserved_range.push(descriptor_proto::ReservedRange {
                start: Some(r.start as i32),
                end: Some(r.end as i32 + 1),
            });
        }
        d.reserved_name = m.reserved_names.clone();
        d.options = self.options(".google.protobuf.MessageOptions", &m.options, &name)?;
        d.visibility = m.visibility.map(visibility);
        Ok(d)
    }

    /// The `<Field>Entry` type of a map field.
    fn map_entry(&self, f: &Field, scope: &str) -> DResult<DescriptorProto> {
        let key = FieldDescriptorProto {
            name: Some("key".into()),
            number: Some(1),
            label: Some(fdp::Label::OPTIONAL),
            r#type: f.map_key.map(|k| fdp::Type(k.type_number())),
            json_name: Some("key".into()),
            ..Default::default()
        };
        let (ty, type_name) = type_of(&f.ty, false);
        let value = FieldDescriptorProto {
            name: Some("value".into()),
            number: Some(2),
            label: Some(fdp::Label::OPTIONAL),
            r#type: Some(ty),
            type_name,
            json_name: Some("value".into()),
            ..Default::default()
        };
        let mut opts = Vec::new();
        encode_varint_field(&mut opts, 7, 1); // map_entry = true
        Ok(DescriptorProto {
            name: Some(map_entry_name(&f.name)),
            field: vec![key, value],
            options: Some(decode_opts(&opts, scope)?),
            ..Default::default()
        })
    }

    fn field(
        &self,
        f: &Field,
        scope: &str,
        oneof: Option<usize>,
        option_scope: &str,
    ) -> DResult<FieldDescriptorProto> {
        let label = if f.label == Label::Repeated {
            fdp::Label::REPEATED
        } else if f.label == Label::Required
            || (self.file.edition.is_editions()
                && f.resolved.presence == Presence::Required
                && false)
        {
            fdp::Label::REQUIRED
        } else {
            fdp::Label::OPTIONAL
        };
        let (ty, mut type_name) = type_of(&f.ty, f.group);
        if f.map_key.is_some() {
            type_name = Some(format!("{scope}.{}", map_entry_name(&f.name)));
        }
        let opts: Vec<OptionDef> = f
            .options
            .iter()
            .filter(|o| o.name != "default" && o.name != "json_name")
            .cloned()
            .collect();
        Ok(FieldDescriptorProto {
            name: Some(f.name.clone()),
            number: Some(f.number as i32),
            label: Some(label),
            r#type: Some(if f.map_key.is_some() {
                fdp::Type::MESSAGE
            } else {
                ty
            }),
            type_name,
            extendee: match &f.extendee {
                Some(TypeRef::Message(e)) => Some(e.clone()),
                _ => None,
            },
            default_value: f.default.as_ref().map(|d| default_text(f, d)),
            oneof_index: oneof.map(|i| i as i32),
            json_name: if f.extendee.is_some() {
                // protoc sets JSON names of extensions to their name in descriptors.
                Some(f.json_name.clone().unwrap_or_else(|| json_name(&f.name)))
            } else {
                Some(f.json_name.clone().unwrap_or_else(|| json_name(&f.name)))
            },
            options: self.options(".google.protobuf.FieldOptions", &opts, option_scope)?,
            proto3_optional: None,
        })
    }

    fn enumeration(&self, e: &EnumDef, scope: &str) -> DResult<EnumDescriptorProto> {
        let name = format!("{scope}.{}", e.name);
        let mut d = EnumDescriptorProto {
            name: Some(e.name.clone()),
            options: self.options(".google.protobuf.EnumOptions", &e.options, scope)?,
            reserved_name: e.reserved_names.clone(),
            visibility: e.visibility.map(visibility),
            ..Default::default()
        };
        for v in &e.values {
            d.value.push(EnumValueDescriptorProto {
                name: Some(v.name.clone()),
                number: Some(v.number),
                options: self.options(".google.protobuf.EnumValueOptions", &v.options, &name)?,
            });
        }
        for &(a, b) in &e.reserved_ranges {
            d.reserved_range
                .push(enum_descriptor_proto::EnumReservedRange {
                    start: Some(a),
                    end: Some(b),
                });
        }
        Ok(d)
    }

    /// Encodes `options` as the options message `target` (`.google.protobuf.FieldOptions` ...),
    /// `None` when there are none. Custom option names resolve from `scope`.
    fn options<M: Message>(
        &self,
        target: &str,
        options: &[OptionDef],
        scope: &str,
    ) -> DResult<Option<M>> {
        if options.is_empty() {
            return Ok(None);
        }
        let mut buf = Vec::new();
        for o in options {
            let path = split_option_name(&o.name);
            self.encode_path(target, &path, &o.value, scope, &mut buf)
                .map_err(|e| format!("{}: option {}: {e}", self.file.name, o.name))?;
        }
        if buf.is_empty() {
            return Ok(None);
        }
        let buf = self
            .canonical(target, &buf)
            .map_err(|e| format!("{scope}: options: {e}"))?;
        decode_opts(&buf, scope).map(Some)
    }

    /// The field `number` of message `msg` (declared, or an extension of it).
    fn field_by_number(&self, msg: &str, number: u32) -> Option<&Field> {
        if let Some(f) = self
            .ix
            .msgs
            .get(msg)
            .and_then(|m| m.fields.iter().find(|f| f.number == number))
        {
            return Some(f);
        }
        self.ix.exts.values().copied().find(|f| {
            f.number == number && matches!(&f.extendee, Some(TypeRef::Message(e)) if e == msg)
        })
    }

    /// Merges the option records the way protoc's parsed options serialize: field-number order,
    /// one record per singular field (messages merged recursively, the last scalar wins).
    fn canonical(&self, msg: &str, buf: &[u8]) -> DResult<Vec<u8>> {
        let mut recs: Vec<(u32, WireType, &[u8])> = Vec::new();
        let mut r = encoding::Reader::new(buf);
        while !r.is_empty() {
            let (n, wt) = r.read_tag().map_err(|e| e.to_string())?;
            let raw = r.skip_field(n, wt).map_err(|e| e.to_string())?;
            recs.push((n, wt, raw));
        }
        recs.sort_by_key(|&(n, _, _)| n);
        let mut out = Vec::new();
        let mut i = 0;
        while i < recs.len() {
            let n = recs[i].0;
            let j = recs[i..]
                .iter()
                .position(|r| r.0 != n)
                .map_or(recs.len(), |k| i + k);
            let group = &recs[i..j];
            match self.field_by_number(msg, n) {
                Some(f) if f.label != Label::Repeated => {
                    if let TypeRef::Message(sub) = &f.ty {
                        let mut inner = Vec::new();
                        for &(_, wt, raw) in group {
                            match wt {
                                WireType::Len => {
                                    let mut rr = encoding::Reader::new(raw);
                                    inner.extend_from_slice(
                                        rr.read_bytes().map_err(|e| e.to_string())?,
                                    );
                                }
                                WireType::StartGroup => {
                                    // raw = fields + end tag
                                    let end = encoding::tag_len(n);
                                    inner.extend_from_slice(&raw[..raw.len() - end]);
                                }
                                _ => return Err(format!("field {n} is not a message")),
                            }
                        }
                        let inner = self.canonical(sub, &inner)?;
                        wrap(f, &inner, &mut out);
                    } else if let Some(&(_, wt, raw)) = group.last() {
                        encoding::put_tag(&mut out, n, wt);
                        out.extend_from_slice(raw);
                    }
                }
                _ => {
                    for &(_, wt, raw) in group {
                        encoding::put_tag(&mut out, n, wt);
                        out.extend_from_slice(raw);
                    }
                }
            }
            i = j;
        }
        Ok(out)
    }

    /// The field `part` of message `msg`: a plain name or a `(extension)`.
    fn lookup(&self, msg: &str, part: &str, scope: &str) -> DResult<(String, &Field)> {
        if let Some(ext) = part.strip_prefix('(').and_then(|p| p.strip_suffix(')')) {
            let (full, f) = self
                .ix
                .extension(ext, scope)
                .ok_or_else(|| format!("unknown extension {ext}"))?;
            match &f.extendee {
                Some(TypeRef::Message(e)) if e == msg => Ok((full, f)),
                _ => Err(format!("{ext} does not extend {}", &msg[1..])),
            }
        } else {
            let m = self
                .ix
                .msgs
                .get(msg)
                .ok_or_else(|| format!("unknown message {msg}"))?;
            let f = m
                .fields
                .iter()
                .find(|f| f.name == part)
                .ok_or_else(|| format!("{} has no field {part}", &msg[1..]))?;
            Ok((format!("{msg}.{part}"), f))
        }
    }

    fn source_only(&self, f: &Field) -> bool {
        matches!(f.options.get_opt("retention"), Some(Constant::Ident(r)) if r == "RETENTION_SOURCE")
    }

    /// Encodes `value` at field path `path` of message `msg` into `out`.
    fn encode_path(
        &self,
        msg: &str,
        path: &[String],
        value: &Constant,
        scope: &str,
        out: &mut Vec<u8>,
    ) -> DResult<()> {
        let (_, f) = self.lookup(msg, &path[0], scope)?;
        if self.source_only(f) {
            return Ok(());
        }
        if path.len() == 1 {
            return self.encode_field(f, value, scope, out);
        }
        let TypeRef::Message(sub) = &f.ty else {
            return Err(format!("{} is not a message", path[0]));
        };
        let mut inner = Vec::new();
        self.encode_path(sub, &path[1..], value, scope, &mut inner)?;
        wrap(f, &inner, out);
        Ok(())
    }

    /// Encodes one value (or each item of a list) of field `f`.
    fn encode_field(
        &self,
        f: &Field,
        value: &Constant,
        scope: &str,
        out: &mut Vec<u8>,
    ) -> DResult<()> {
        if let Constant::List(items) = value {
            if f.label != Label::Repeated {
                return Err(format!("{} is not repeated", f.name));
            }
            for v in items {
                self.encode_field(f, v, scope, out)?;
            }
            return Ok(());
        }
        let n = f.number;
        match (&f.ty, value) {
            (TypeRef::Message(m), Constant::Aggregate(fields)) => {
                let mut inner = Vec::new();
                for (name, v) in fields {
                    let part = match name.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                        Some(ext) => format!("({ext})"),
                        None => name.clone(),
                    };
                    let (_, sf) = self.lookup(m, &part, scope)?;
                    if self.source_only(sf) {
                        continue;
                    }
                    self.encode_field(sf, v, scope, &mut inner)?;
                }
                wrap(f, &inner, out);
            }
            (TypeRef::Message(_), _) => return Err(format!("{} takes a message", f.name)),
            (TypeRef::Enum(e), Constant::Ident(v)) => {
                let en = self
                    .ix
                    .enums
                    .get(e)
                    .ok_or_else(|| format!("unknown enum {e}"))?;
                let num = en
                    .values
                    .iter()
                    .find(|x| &x.name == v)
                    .map(|x| x.number)
                    .ok_or_else(|| format!("{} has no value {v}", &e[1..]))?;
                encode_varint_field(out, n, i64::from(num) as u64);
            }
            (TypeRef::Enum(_), Constant::Int(t)) => {
                let v = int_value(t).ok_or("integer out of range")?;
                encode_varint_field(out, n, v as u64);
            }
            (TypeRef::Scalar(s), v) => encode_scalar(*s, n, v, out)?,
            _ => return Err(format!("invalid value for {}", f.name)),
        }
        Ok(())
    }
}

/// Writes a message-typed field holding `inner` (a group for proto2 groups / delimited fields).
fn wrap(f: &Field, inner: &[u8], out: &mut Vec<u8>) {
    if f.resolved.delimited {
        encoding::put_tag(out, f.number, WireType::StartGroup);
        out.extend_from_slice(inner);
        encoding::put_tag(out, f.number, WireType::EndGroup);
    } else {
        encoding::put_tag(out, f.number, WireType::Len);
        encoding::put_bytes(out, inner);
    }
}

fn encode_varint_field(out: &mut Vec<u8>, n: u32, v: u64) {
    encoding::put_tag(out, n, WireType::Varint);
    encoding::put_varint(out, v);
}

fn int_value(t: &str) -> Option<i128> {
    let (neg, body) = t.strip_prefix('-').map_or((false, t), |b| (true, b));
    let v = i128::from(parse_int(body)?);
    Some(if neg { -v } else { v })
}

fn float_value(t: &str) -> Option<f64> {
    let (neg, body) = t.strip_prefix('-').map_or((false, t), |b| (true, b));
    let v = match body {
        "inf" | "infinity" => f64::INFINITY,
        "nan" => f64::NAN,
        b if b.starts_with("0x") || b.starts_with("0X") => parse_int(b)? as f64,
        b => b.parse().ok()?,
    };
    Some(if neg { -v } else { v })
}

fn encode_scalar(s: Scalar, n: u32, v: &Constant, out: &mut Vec<u8>) -> DResult<()> {
    let bad = || format!("invalid {s:?} value");
    let int = |lo: i128, hi: i128| -> DResult<i128> {
        match v {
            Constant::Int(t) => int_value(t)
                .filter(|x| (lo..=hi).contains(x))
                .ok_or_else(bad),
            _ => Err(bad()),
        }
    };
    match s {
        Scalar::Int32 => {
            encode_varint_field(out, n, int(i32::MIN.into(), i32::MAX.into())? as i64 as u64)
        }
        Scalar::Int64 => {
            encode_varint_field(out, n, int(i64::MIN.into(), i64::MAX.into())? as i64 as u64)
        }
        Scalar::Uint32 => encode_varint_field(out, n, int(0, u32::MAX.into())? as u64),
        Scalar::Uint64 => encode_varint_field(out, n, int(0, u64::MAX.into())? as u64),
        Scalar::Sint32 => encode_varint_field(
            out,
            n,
            u64::from(encoding::zigzag32(
                int(i32::MIN.into(), i32::MAX.into())? as i32
            )),
        ),
        Scalar::Sint64 => encode_varint_field(
            out,
            n,
            encoding::zigzag64(int(i64::MIN.into(), i64::MAX.into())? as i64),
        ),
        Scalar::Fixed32 | Scalar::Sfixed32 => {
            let v = if s == Scalar::Fixed32 {
                int(0, u32::MAX.into())? as u32
            } else {
                int(i32::MIN.into(), i32::MAX.into())? as i32 as u32
            };
            encoding::put_tag(out, n, WireType::Fixed32);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Scalar::Fixed64 | Scalar::Sfixed64 => {
            let v = if s == Scalar::Fixed64 {
                int(0, u64::MAX.into())? as u64
            } else {
                int(i64::MIN.into(), i64::MAX.into())? as i64 as u64
            };
            encoding::put_tag(out, n, WireType::Fixed64);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Scalar::Bool => {
            let b = match v {
                Constant::Ident(t) if t == "true" || t == "True" || t == "t" => true,
                Constant::Ident(t) if t == "false" || t == "False" || t == "f" => false,
                Constant::Int(t) if t == "1" => true,
                Constant::Int(t) if t == "0" => false,
                _ => return Err(bad()),
            };
            encode_varint_field(out, n, u64::from(b));
        }
        Scalar::Float | Scalar::Double => {
            let x = match v {
                Constant::Float(t) | Constant::Int(t) => float_value(t).ok_or_else(bad)?,
                Constant::Ident(t) if t == "inf" || t == "nan" || t == "infinity" => {
                    float_value(t).ok_or_else(bad)?
                }
                _ => return Err(bad()),
            };
            if s == Scalar::Float {
                encoding::put_tag(out, n, WireType::Fixed32);
                out.extend_from_slice(&(x as f32).to_le_bytes());
            } else {
                encoding::put_tag(out, n, WireType::Fixed64);
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        Scalar::String | Scalar::Bytes => {
            let Constant::Str(b) = v else {
                return Err(bad());
            };
            if s == Scalar::String && std::str::from_utf8(b).is_err() {
                return Err("string option is not UTF-8".into());
            }
            encoding::put_tag(out, n, WireType::Len);
            encoding::put_bytes(out, b);
        }
    }
    Ok(())
}

fn decode_opts<M: Message>(buf: &[u8], scope: &str) -> DResult<M> {
    M::decode(buf).map_err(|e| format!("{scope}: options do not decode: {e}"))
}

/// Splits `(a.b).c.d` into `(a.b)`, `c`, `d`.
fn split_option_name(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0;
    for c in name.chars() {
        match c {
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth -= 1;
                cur.push(c);
            }
            '.' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn visibility(export: bool) -> SymbolVisibility {
    if export {
        SymbolVisibility::VISIBILITY_EXPORT
    } else {
        SymbolVisibility::VISIBILITY_LOCAL
    }
}

/// The descriptor type and type name of a field type.
fn type_of(t: &TypeRef, group: bool) -> (fdp::Type, Option<String>) {
    match t {
        TypeRef::Scalar(s) => (fdp::Type(s.type_number()), None),
        TypeRef::Message(n) if group => (fdp::Type::GROUP, Some(n.clone())),
        TypeRef::Message(n) => (fdp::Type::MESSAGE, Some(n.clone())),
        TypeRef::Enum(n) => (fdp::Type::ENUM, Some(n.clone())),
        TypeRef::Named(n) => (fdp::Type::MESSAGE, Some(n.clone())),
    }
}

/// protoc's map entry name: `my_map` -> `MyMapEntry`.
pub(crate) fn map_entry_name(field: &str) -> String {
    let mut out = String::new();
    let mut up = true;
    for c in field.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.push(c.to_ascii_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out.push_str("Entry");
    out
}

/// A default value as protoc writes it in `default_value`.
fn default_text(f: &Field, d: &Constant) -> String {
    match (&f.ty, d) {
        (TypeRef::Scalar(Scalar::String | Scalar::Bytes), Constant::Str(b)) => {
            if matches!(f.ty, TypeRef::Scalar(Scalar::String)) {
                String::from_utf8_lossy(b).into_owned()
            } else {
                c_escape(b)
            }
        }
        (TypeRef::Scalar(Scalar::Float), Constant::Float(t) | Constant::Int(t)) => {
            float_text(float_value(t).unwrap_or(0.0), true)
        }
        (TypeRef::Scalar(Scalar::Double), Constant::Float(t) | Constant::Int(t)) => {
            float_text(float_value(t).unwrap_or(0.0), false)
        }
        (TypeRef::Scalar(_), Constant::Int(t)) => int_value(t).unwrap_or(0).to_string(),
        (_, Constant::Ident(v)) => v.clone(),
        (_, Constant::Float(t) | Constant::Int(t)) => t.clone(),
        _ => String::new(),
    }
}

/// protoc's `CEscape`: printable ASCII as is (`\\`, `"`, `'` escaped), `\n` `\r` `\t`, other
/// bytes as three octal digits.
fn c_escape(b: &[u8]) -> String {
    let mut s = String::new();
    for &c in b {
        match c {
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            b'"' => s.push_str("\\\""),
            b'\'' => s.push_str("\\'"),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\{c:03o}")),
        }
    }
    s
}

/// protoc's `SimpleDtoa` / `SimpleFtoa`: `%.15g` (`%.6g` for floats), or `%.17g` (`%.9g`) when
/// that does not round-trip; `inf`, `-inf`, `nan`.
fn float_text(v: f64, single: bool) -> String {
    if v.is_nan() {
        return "nan".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "inf" } else { "-inf" }.into();
    }
    let (short, long) = if single { (6, 9) } else { (15, 17) };
    let s = format_g(v, short);
    let back: f64 = s.parse().unwrap_or(f64::NAN);
    let ok = if single {
        back as f32 == v as f32
    } else {
        back == v
    };
    if ok { s } else { format_g(v, long) }
}

/// C's `%.<p>g`.
fn format_g(v: f64, p: usize) -> String {
    if v == 0.0 {
        return if v.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let e = format!("{:.*e}", p - 1, v);
    let (mant, exp) = e.split_once('e').unwrap_or((&e, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let strip = |s: &str| -> String {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_owned()
        } else {
            s.to_owned()
        }
    };
    if exp < -4 || exp >= p as i32 {
        let sign = if exp < 0 { '-' } else { '+' };
        format!("{}e{sign}{:02}", strip(mant), exp.abs())
    } else {
        let decimals = (p as i32 - 1 - exp).max(0) as usize;
        strip(&format!("{v:.decimals$}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_protoc() {
        assert_eq!(float_text(9e9, true), "9e+09");
        assert_eq!(float_text(7e22, false), "7e+22");
        assert_eq!(float_text(1.5, false), "1.5");
        assert_eq!(float_text(0.1, false), "0.1");
        assert_eq!(float_text(-0.0001, false), "-0.0001");
        assert_eq!(float_text(1e-5, false), "1e-05");
        assert_eq!(float_text(123456.0, true), "123456");
        assert_eq!(c_escape(b"jo\x01\"\xff"), "jo\\001\\\"\\377");
        assert_eq!(map_entry_name("map_string_string"), "MapStringStringEntry");
        assert_eq!(
            split_option_name("(a.b).c.d"),
            ["(a.b)", "c", "d"].map(String::from)
        );
    }
}
