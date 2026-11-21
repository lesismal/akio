//! Name resolution and Rust code generation.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
};

use crate::{
    Config, descriptor, features,
    parse::{
        Constant, EnumDef, Field, File, Label, MessageDef, Options as _, Presence, Scalar, Service,
        TypeRef,
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Message,
    Enum,
}

#[derive(Clone, Debug)]
struct Sym {
    kind: Kind,
    package: String,
    /// Proto names from the outermost message to the type itself.
    nesting: Vec<String>,
    /// The file declaring it.
    file: String,
    /// 2024 visibility: not usable from other files.
    local: bool,
}

type GResult<T> = Result<T, String>;

/// A generated file: its name and its Rust source.
type Output = (String, String);

pub(crate) fn generate(cfg: &Config, files: Vec<File>) -> GResult<Vec<(String, String)>> {
    generate_all(cfg, files).map(|(code, _)| code)
}

/// The code per package, and the `FileDescriptorSet` of every file (for
/// `Config::file_descriptor_set_path`).
pub(crate) fn generate_all(cfg: &Config, mut files: Vec<File>) -> GResult<(Vec<Output>, Vec<u8>)> {
    // Symbols.
    let mut syms: HashMap<String, Sym> = HashMap::new();
    for f in &files {
        let ff = features::file_features(f)?;
        let mut add = |fqn: String, s: Sym| -> GResult<()> {
            if syms.insert(fqn.clone(), s).is_some() {
                return Err(format!("{}: {} is defined twice", f.name, &fqn[1..]));
            }
            Ok(())
        };
        struct W<'a> {
            pkg: &'a str,
            file: &'a str,
            ff: features::Features,
        }
        fn walk(
            w: &W<'_>,
            m: &MessageDef,
            nesting: &mut Vec<String>,
            add: &mut dyn FnMut(String, Sym) -> GResult<()>,
        ) -> GResult<()> {
            let nested = !nesting.is_empty();
            nesting.push(m.name.clone());
            add(
                fqn(w.pkg, nesting),
                Sym {
                    kind: Kind::Message,
                    package: w.pkg.to_owned(),
                    nesting: nesting.clone(),
                    file: w.file.to_owned(),
                    local: features::is_local(w.ff, m.visibility, nested),
                },
            )?;
            for e in &m.enums {
                nesting.push(e.name.clone());
                add(
                    fqn(w.pkg, nesting),
                    Sym {
                        kind: Kind::Enum,
                        package: w.pkg.to_owned(),
                        nesting: nesting.clone(),
                        file: w.file.to_owned(),
                        local: features::is_local(w.ff, e.visibility, true),
                    },
                )?;
                nesting.pop();
            }
            for n in &m.messages {
                walk(w, n, nesting, add)?;
            }
            nesting.pop();
            Ok(())
        }
        let w = W {
            pkg: &f.package,
            file: &f.name,
            ff,
        };
        for m in &f.messages {
            walk(&w, m, &mut Vec::new(), &mut add)?;
        }
        for e in &f.enums {
            add(
                fqn(&f.package, std::slice::from_ref(&e.name)),
                Sym {
                    kind: Kind::Enum,
                    package: f.package.clone(),
                    nesting: vec![e.name.clone()],
                    file: f.name.clone(),
                    local: features::is_local(ff, e.visibility, false),
                },
            )?;
        }
    }

    // Resolution.
    for f in &mut files {
        let fname = f.name.clone();
        let pkg_scope = if f.package.is_empty() {
            String::new()
        } else {
            format!(".{}", f.package)
        };
        fn field(
            fl: &mut Field,
            scope: &str,
            syms: &HashMap<String, Sym>,
            file: &str,
        ) -> GResult<()> {
            if let TypeRef::Named(n) = &fl.ty {
                fl.ty = resolve(n, scope, syms)
                    .ok_or_else(|| format!("{file}:{}: unknown type {n}", fl.line))?;
                visible(&fl.ty, syms, file).map_err(|e| format!("{file}:{}: {e}", fl.line))?;
            }
            if let Some(TypeRef::Named(n)) = &fl.extendee {
                match resolve(n, scope, syms) {
                    Some(t @ TypeRef::Message(_)) => {
                        visible(&t, syms, file).map_err(|e| format!("{file}:{}: {e}", fl.line))?;
                        fl.extendee = Some(t);
                    }
                    _ => return Err(format!("{file}:{}: {n} is not a message", fl.line)),
                }
            }
            if fl.packed == Some(true) && matches!(fl.ty, TypeRef::Message(_)) {
                return Err(format!(
                    "{file}:{}: [packed = true] on a message field",
                    fl.line
                ));
            }
            Ok(())
        }
        fn walk(
            m: &mut MessageDef,
            scope: &str,
            syms: &HashMap<String, Sym>,
            file: &str,
        ) -> GResult<()> {
            let scope = format!("{scope}.{}", m.name);
            for fl in m.fields.iter_mut().chain(&mut m.extensions) {
                field(fl, &scope, syms, file)?;
            }
            for n in &mut m.messages {
                walk(n, &scope, syms, file)?;
            }
            Ok(())
        }
        for m in &mut f.messages {
            walk(m, &pkg_scope, &syms, &fname)?;
        }
        for fl in &mut f.extensions {
            field(fl, &pkg_scope, &syms, &fname)?;
        }
        for s in &mut f.services {
            for m in &mut s.methods {
                for t in [&mut m.input, &mut m.output] {
                    if let TypeRef::Named(n) = t {
                        match resolve(n, &pkg_scope, &syms) {
                            Some(r @ TypeRef::Message(_)) => {
                                visible(&r, &syms, &fname)
                                    .map_err(|e| format!("{fname}: {}.{}: {e}", s.name, m.name))?;
                                *t = r;
                            }
                            _ => {
                                return Err(format!(
                                    "{fname}: {}.{}: {n} is not a message",
                                    s.name, m.name
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Features: enums first (whether each is closed), then fields.
    let mut closed: HashMap<String, bool> = HashMap::new();
    for f in &mut files {
        features::resolve_file(f, &mut |_| None)?;
        let prefix = if f.package.is_empty() {
            String::new()
        } else {
            format!(".{}", f.package)
        };
        fn walk(m: &MessageDef, prefix: &str, out: &mut HashMap<String, bool>) {
            let name = format!("{prefix}.{}", m.name);
            for e in &m.enums {
                out.insert(format!("{name}.{}", e.name), e.closed);
            }
            for n in &m.messages {
                walk(n, &name, out);
            }
        }
        for m in &f.messages {
            walk(m, &prefix, &mut closed);
        }
        for e in &f.enums {
            closed.insert(format!("{prefix}.{}", e.name), e.closed);
        }
    }
    for f in &mut files {
        features::resolve_file(f, &mut |e| closed.get(e).copied())?;
    }

    let mut externs = cfg.extern_paths.clone();
    if !cfg.compile_well_known_types {
        externs.push((
            ".google.protobuf".into(),
            "::only_protobuf::well_known".into(),
        ));
    }
    let mut msgs: HashMap<String, &MessageDef> = HashMap::new();
    let mut enums: HashMap<String, &EnumDef> = HashMap::new();
    for f in &files {
        fn walk<'a>(
            m: &'a MessageDef,
            prefix: &str,
            out: &mut HashMap<String, &'a MessageDef>,
            enums: &mut HashMap<String, &'a EnumDef>,
        ) {
            let name = format!("{prefix}.{}", m.name);
            for n in &m.messages {
                walk(n, &name, out, enums);
            }
            for e in &m.enums {
                enums.insert(format!("{name}.{}", e.name), e);
            }
            out.insert(name, m);
        }
        let prefix = if f.package.is_empty() {
            String::new()
        } else {
            format!(".{}", f.package)
        };
        for m in &f.messages {
            walk(m, &prefix, &mut msgs, &mut enums);
        }
        for e in &f.enums {
            enums.insert(format!("{prefix}.{}", e.name), e);
        }
    }
    // Extensions must use a number of one of the extendee's extension ranges.
    for f in &files {
        let all = f
            .extensions
            .iter()
            .chain(f.messages.iter().flat_map(all_extensions));
        for x in all {
            let Some(TypeRef::Message(e)) = &x.extendee else {
                continue;
            };
            let ok = msgs.get(e).is_some_and(|m| {
                m.extension_ranges
                    .iter()
                    .any(|r| (r.start..=r.end).contains(&x.number))
            });
            if !ok {
                return Err(format!(
                    "{}:{}: {} = {} is not in an extension range of {}",
                    f.name,
                    x.line,
                    x.name,
                    x.number,
                    &e[1..]
                ));
            }
        }
    }
    // Descriptors (source-retention options stripped, as protoc does).
    let index = descriptor::Index::new(&files);
    let mut protos = HashMap::new();
    for f in files.iter().filter(|f| !f.implicit) {
        protos.insert(f.name.as_str(), descriptor::file_descriptor(f, &index)?);
    }
    let all_names: Vec<&str> = files
        .iter()
        .filter(|f| !f.implicit)
        .map(|f| f.name.as_str())
        .collect();
    let full_set = if cfg.descriptor_set_path.is_some() {
        descriptor::file_descriptor_set(&files, &protos, &all_names)
    } else {
        Vec::new()
    };

    let gen_files: Vec<&File> = files
        .iter()
        .filter(|f| !f.implicit)
        .filter(|f| {
            let p = format!(".{}", f.package);
            !externs.iter().any(|(e, _)| covers(e, &p))
        })
        .collect();
    let grpc = cfg
        .grpc
        .unwrap_or_else(|| gen_files.iter().any(|f| !f.services.is_empty()));
    let mut utf8_exts: HashMap<String, Vec<u32>> = HashMap::new();
    for f in &files {
        for x in f
            .extensions
            .iter()
            .chain(f.messages.iter().flat_map(all_extensions))
        {
            if let (Some(TypeRef::Message(e)), TypeRef::Scalar(Scalar::String)) =
                (&x.extendee, &x.ty)
            {
                if x.resolved.verify_utf8 {
                    utf8_exts.entry(e.clone()).or_default().push(x.number);
                }
            }
        }
    }
    let g = Gen {
        cfg,
        syms: &syms,
        msgs,
        enums,
        externs,
        grpc,
        utf8_exts,
    };
    let mut by_pkg: BTreeMap<String, (Vec<String>, String)> = BTreeMap::new();
    let mut sorted = gen_files;
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for f in sorted {
        let module: Vec<String> = if f.package.is_empty() {
            Vec::new()
        } else {
            f.package.split('.').map(ident).collect()
        };
        let entry = by_pkg.entry(f.package.clone()).or_default();
        entry.0.push(f.name.clone());
        let out = &mut entry.1;
        let prefix = if f.package.is_empty() {
            String::new()
        } else {
            format!(".{}", f.package)
        };
        for m in &f.messages {
            g.message(out, m, &format!("{prefix}.{}", m.name), &module)?;
        }
        for e in &f.enums {
            g.enumeration(out, e);
        }
        g.extensions(out, &f.extensions, &f.package, &module);
        if g.grpc {
            for s in &f.services {
                g.service(out, s, &f.package, &module);
            }
        }
    }
    let code = by_pkg
        .into_iter()
        .map(|(pkg, (names, mut code))| {
            if cfg.descriptors {
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                let set = descriptor::file_descriptor_set(&files, &protos, &refs);
                code.push_str(&descriptor_items(&set));
            }
            let file = if pkg.is_empty() {
                "_.rs".to_owned()
            } else {
                format!("{pkg}.rs")
            };
            let head = format!(
                "// @generated by only-protobuf-build from {}. Do not edit.\n\n",
                names.join(", ")
            );
            (file, head + code.trim_end() + "\n")
        })
        .collect();
    Ok((code, full_set))
}

/// The package-level descriptor items: the encoded set as a byte string, split in lines, and
/// the pool built from it.
fn descriptor_items(set: &[u8]) -> String {
    let mut out = String::from(
        "/// The descriptor pool of this package's files and the files they import (built from\n/// [`FILE_DESCRIPTOR_SET`] on first use).\npub fn descriptor_pool() -> &'static ::only_protobuf::reflect::DescriptorPool {\n    static POOL: ::std::sync::OnceLock<::only_protobuf::reflect::DescriptorPool> =\n        ::std::sync::OnceLock::new();\n    POOL.get_or_init(|| {\n        ::only_protobuf::reflect::DescriptorPool::decode(FILE_DESCRIPTOR_SET)\n            .unwrap_or_else(|e| ::core::panic!(\"{e}\"))\n    })\n}\n\n",
    );
    out.push_str(
        "/// The descriptors of this package's files and of the files they import: an encoded\n/// `google.protobuf.FileDescriptorSet`.\npub const FILE_DESCRIPTOR_SET: &[u8] = b\"\\\n",
    );
    for chunk in set.chunks(48) {
        out.push_str("    ");
        for (i, &b) in chunk.iter().enumerate() {
            match b {
                b' ' if i == 0 => out.push_str("\\x20"),
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                0x20..=0x7e => out.push(b as char),
                _ => {
                    let _ = write!(out, "\\x{b:02x}");
                }
            }
        }
        out.push_str("\\\n");
    }
    out.push_str("\";\n\n");
    out
}

/// The extensions declared in `m` and its nested messages.
fn all_extensions(m: &MessageDef) -> Vec<&Field> {
    let mut v: Vec<&Field> = m.extensions.iter().collect();
    for n in &m.messages {
        v.extend(all_extensions(n));
    }
    v
}

/// Fails when `t` is a 2024 `local` type of another file.
fn visible(t: &TypeRef, syms: &HashMap<String, Sym>, file: &str) -> Result<(), String> {
    if let TypeRef::Message(n) | TypeRef::Enum(n) = t {
        if let Some(s) = syms.get(n) {
            if s.local && s.file != file {
                return Err(format!("{} is local to {} (not exported)", &n[1..], s.file));
            }
        }
    }
    Ok(())
}

fn fqn(pkg: &str, nesting: &[String]) -> String {
    if pkg.is_empty() {
        format!(".{}", nesting.join("."))
    } else {
        format!(".{pkg}.{}", nesting.join("."))
    }
}

/// Whether the proto prefix `prefix` (`.a.b`) covers `name` (`.a.b` or `.a.b.C`).
fn covers(prefix: &str, name: &str) -> bool {
    name == prefix
        || name
            .strip_prefix(prefix)
            .is_some_and(|r| r.starts_with('.'))
}

/// Resolves `name` from `scope` (both with a leading dot) per protobuf's scoping rules: the
/// innermost scope first.
fn resolve(name: &str, scope: &str, syms: &HashMap<String, Sym>) -> Option<TypeRef> {
    let found = |full: &str| {
        syms.get(full).map(|s| match s.kind {
            Kind::Message => TypeRef::Message(full.to_owned()),
            Kind::Enum => TypeRef::Enum(full.to_owned()),
        })
    };
    if name.starts_with('.') {
        return found(name);
    }
    let mut scope = scope.to_owned();
    loop {
        if let Some(t) = found(&format!("{scope}.{name}")) {
            return Some(t);
        }
        let i = scope.rfind('.')?;
        scope.truncate(i);
        if scope.is_empty() {
            return found(&format!(".{name}"));
        }
    }
}

// ---- names -----------------------------------------------------------------------------------

/// Splits an identifier into words at `_` and case changes (`HTTPRequest` -> `HTTP`, `Request`;
/// `int32Value` -> `int32`, `Value`).
fn words(s: &str) -> Vec<String> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    for i in 0..c.len() {
        let ch = c[i];
        if !ch.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if ch.is_ascii_uppercase() && !cur.is_empty() {
            let prev = c[i - 1];
            let next_lower = c.get(i + 1).is_some_and(char::is_ascii_lowercase);
            if prev.is_ascii_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_ascii_uppercase() && next_lower)
            {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn snake(s: &str) -> String {
    words(s)
        .iter()
        .map(|w| w.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("_")
}

fn screaming(s: &str) -> String {
    words(s)
        .iter()
        .map(|w| w.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join("_")
}

fn camel(s: &str) -> String {
    let mut out = String::new();
    for w in words(s) {
        let mut ch = w.chars();
        if let Some(f) = ch.next() {
            out.push(f.to_ascii_uppercase());
            out.push_str(&ch.as_str().to_ascii_lowercase());
        }
    }
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    ident(&out)
}

const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "enum", "extern", "false", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static",
    "struct", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn",
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try", "gen",
];

/// Escapes a Rust keyword (`r#type`; `self_` for the ones that cannot be raw).
fn ident(s: &str) -> String {
    if matches!(s, "self" | "super" | "crate" | "Self") {
        format!("{s}_")
    } else if KEYWORDS.contains(&s) {
        format!("r#{s}")
    } else if s.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{s}")
    } else {
        s.to_owned()
    }
}

/// The path to `name` in module `to`, written from module `from`.
fn rel(from: &[String], to: &[String], name: &str) -> String {
    let common = from.iter().zip(to).take_while(|(a, b)| a == b).count();
    let mut p = String::new();
    for _ in common..from.len() {
        p.push_str("super::");
    }
    for m in &to[common..] {
        p.push_str(m);
        p.push_str("::");
    }
    p.push_str(name);
    p
}

/// Writes a doc comment: `text` (from the `.proto` file, made safe for rustdoc) or `fallback`.
fn doc(out: &mut String, indent: &str, text: &str, fallback: &str) {
    let text = text.trim();
    let text = if text.is_empty() { fallback } else { text };
    let mut fence = false;
    for line in text.lines() {
        let line = line.trim();
        out.push_str(indent);
        out.push_str("///");
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        out.push(' ');
        if line.starts_with("```") {
            out.push_str(if !fence && line == "```" {
                "```text"
            } else {
                line
            });
            fence = !fence;
        } else if fence {
            out.push_str(line);
        } else {
            out.push_str(&markdown_safe(line));
        }
        out.push('\n');
    }
}

/// Escapes `[`, `]`, `<`, `>` outside code spans (no broken links or HTML tags) and wraps URLs
/// in `<...>` (no bare-URL warnings).
fn markdown_safe(line: &str) -> String {
    let mut out = String::new();
    for (i, part) in line.split('`').enumerate() {
        if i > 0 {
            out.push('`');
        }
        if i % 2 == 1 {
            out.push_str(part);
            continue;
        }
        for (j, w) in part.split(' ').enumerate() {
            if j > 0 {
                out.push(' ');
            }
            let url_at = w.find("https://").or_else(|| w.find("http://"));
            let (text, url) = url_at.map_or((w, ""), |k| w.split_at(k));
            escape_md(&mut out, text);
            if !url.is_empty() {
                let end = url.trim_end_matches(['.', ',', ')', ';', ':', '"', '\'', ']', '>']);
                out.push('<');
                out.push_str(end);
                out.push('>');
                escape_md(&mut out, &url[end.len()..]);
            }
        }
    }
    out
}

fn escape_md(out: &mut String, s: &str) {
    for ch in s.chars() {
        if matches!(ch, '[' | ']' | '<' | '>') {
            out.push('\\');
        }
        out.push(ch);
    }
}

fn indent(code: &str) -> String {
    let mut out = String::new();
    for l in code.lines() {
        if !l.is_empty() {
            out.push_str("    ");
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

// ---- generator -------------------------------------------------------------------------------

struct Gen<'a> {
    cfg: &'a Config,
    syms: &'a HashMap<String, Sym>,
    msgs: HashMap<String, &'a MessageDef>,
    enums: HashMap<String, &'a EnumDef>,
    externs: Vec<(String, String)>,
    grpc: bool,
    /// String extensions that must be UTF-8, by extendee: their numbers.
    utf8_exts: HashMap<String, Vec<u32>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Shape {
    Implicit,
    Required,
    Optional { boxed: bool },
    Repeated { packed: bool },
    Map,
    Oneof { boxed: bool },
}

struct Plan<'f> {
    f: &'f Field,
    name: String,
    shape: Shape,
    codec: String,
    ty: String,
    key: Option<(String, String)>,
    /// A closed enum (or a map of them): unknown numbers go to the unknown fields.
    closed: bool,
}

fn scalar_ty(s: Scalar) -> (&'static str, &'static str) {
    match s {
        Scalar::Double => ("f64", "Double"),
        Scalar::Float => ("f32", "Float"),
        Scalar::Int32 => ("i32", "Int32"),
        Scalar::Int64 => ("i64", "Int64"),
        Scalar::Uint32 => ("u32", "Uint32"),
        Scalar::Uint64 => ("u64", "Uint64"),
        Scalar::Sint32 => ("i32", "Sint32"),
        Scalar::Sint64 => ("i64", "Sint64"),
        Scalar::Fixed32 => ("u32", "Fixed32"),
        Scalar::Fixed64 => ("u64", "Fixed64"),
        Scalar::Sfixed32 => ("i32", "Sfixed32"),
        Scalar::Sfixed64 => ("i64", "Sfixed64"),
        Scalar::Bool => ("bool", "Bool"),
        Scalar::String => ("::std::string::String", "StringCodec"),
        Scalar::Bytes => ("::std::vec::Vec<u8>", "BytesCodec"),
    }
}

impl Gen<'_> {
    fn extern_path(&self, fqn: &str) -> Option<String> {
        let (prefix, rust) = self
            .externs
            .iter()
            .filter(|(p, _)| covers(p, fqn))
            .max_by_key(|(p, _)| p.len())?;
        if prefix == fqn {
            return Some(rust.clone());
        }
        let sym = &self.syms[fqn];
        let pkg: Vec<&str> = if sym.package.is_empty() {
            Vec::new()
        } else {
            sym.package.split('.').collect()
        };
        let k = prefix.matches('.').count();
        let mut p = rust.clone();
        if k <= pkg.len() {
            for m in &pkg[k..] {
                p.push_str("::");
                p.push_str(&ident(m));
            }
            for m in &sym.nesting[..sym.nesting.len() - 1] {
                p.push_str("::");
                p.push_str(&ident(&snake(m)));
            }
        } else {
            // A type mapped to an extern type: its nested types live in a module next to it.
            let skip = k - pkg.len();
            let (base, last) = p.rsplit_once("::").map_or_else(
                || (String::new(), p.clone()),
                |(b, l)| (b.to_owned(), l.to_owned()),
            );
            p = base;
            if !p.is_empty() || rust.starts_with("::") {
                p.push_str("::");
            }
            p.push_str(&snake(&last));
            for m in &sym.nesting[skip..sym.nesting.len() - 1] {
                p.push_str("::");
                p.push_str(&ident(&snake(m)));
            }
        }
        p.push_str("::");
        p.push_str(&camel(sym.nesting.last().map_or("", String::as_str)));
        Some(p)
    }

    /// The module a symbol's Rust type lives in, and its name.
    fn location(&self, fqn: &str) -> (Vec<String>, String) {
        let sym = &self.syms[fqn];
        let mut m: Vec<String> = if sym.package.is_empty() {
            Vec::new()
        } else {
            sym.package.split('.').map(ident).collect()
        };
        for n in &sym.nesting[..sym.nesting.len() - 1] {
            m.push(ident(&snake(n)));
        }
        (m, camel(sym.nesting.last().map_or("", String::as_str)))
    }

    fn type_path(&self, fqn: &str, from: &[String]) -> String {
        if let Some(p) = self.extern_path(fqn) {
            return p;
        }
        let (m, n) = self.location(fqn);
        rel(from, &m, &n)
    }

    /// The Rust type and codec of one value of `t`, seen from module `from`.
    fn value(&self, t: &TypeRef, from: &[String]) -> (String, String) {
        match t {
            TypeRef::Scalar(s) => {
                let (ty, c) = scalar_ty(*s);
                (ty.to_owned(), format!("__pb::{c}"))
            }
            TypeRef::Message(f) => {
                let p = self.type_path(f, from);
                (p.clone(), format!("__pb::MessageCodec<{p}>"))
            }
            TypeRef::Enum(f) => {
                let p = self.type_path(f, from);
                (p.clone(), format!("__pb::EnumCodec<{p}>"))
            }
            TypeRef::Named(n) => (n.clone(), String::new()),
        }
    }

    /// Messages directly contained (not through `Vec` or a map) in `fqn`.
    fn direct(&self, fqn: &str) -> Vec<&str> {
        self.msgs.get(fqn).map_or_else(Vec::new, |m| {
            m.fields
                .iter()
                .filter(|f| f.map_key.is_none() && f.label != Label::Repeated)
                .filter_map(|f| match &f.ty {
                    TypeRef::Message(t) => Some(t.as_str()),
                    _ => None,
                })
                .collect()
        })
    }

    /// A field of `from` with message type `to` must be boxed when `to` contains `from`.
    fn needs_box(&self, from: &str, to: &str) -> bool {
        let mut seen = HashSet::new();
        let mut stack = vec![to];
        while let Some(m) = stack.pop() {
            if m == from {
                return true;
            }
            if seen.insert(m) {
                stack.extend(self.direct(m));
            }
        }
        false
    }

    /// Whether `fqn` can derive `Eq` (no floats anywhere inside).
    fn eq_able(&self, fqn: &str, visiting: &mut HashSet<String>) -> bool {
        if self.extern_path(fqn).is_some() {
            // Well-known types: only the ones without floats.
            return !matches!(
                fqn,
                ".google.protobuf.DoubleValue"
                    | ".google.protobuf.FloatValue"
                    | ".google.protobuf.Value"
                    | ".google.protobuf.Struct"
                    | ".google.protobuf.ListValue"
            ) && fqn.starts_with(".google.protobuf.");
        }
        if !visiting.insert(fqn.to_owned()) {
            return true;
        }
        let Some(m) = self.msgs.get(fqn) else {
            return false;
        };
        m.fields.iter().all(|f| match &f.ty {
            TypeRef::Scalar(Scalar::Float | Scalar::Double) => false,
            TypeRef::Message(t) => self.eq_able(t, visiting),
            _ => true,
        })
    }

    /// Whether the `string` values (or keys) of `f` are `ProtoString`s: `utf8_validation =
    /// NONE` in an editions file, or proto2 with `Config::proto2_unchecked_strings`.
    fn unchecked(&self, f: &Field) -> bool {
        f.resolved.utf8_none || (self.cfg.proto2_unchecked_strings && !f.resolved.verify_utf8)
    }

    /// Whether `f` is a `string` field whose values are `ProtoString`s.
    fn unchecked_string(&self, f: &Field) -> bool {
        matches!(f.ty, TypeRef::Scalar(Scalar::String)) && self.unchecked(f)
    }

    /// The Rust type and codec of a field's values, seen from module `from` (a delimited message
    /// field uses the group codec).
    fn field_value(&self, f: &Field, from: &[String]) -> (String, String) {
        if self.unchecked_string(f) {
            return (
                "::only_protobuf::ProtoString".to_owned(),
                "__pb::ProtoStringCodec".to_owned(),
            );
        }
        let (ty, codec) = self.value(&f.ty, from);
        if f.resolved.delimited {
            let codec = format!("__pb::GroupCodec<{ty}, {}>", f.number);
            return (ty, codec);
        }
        (ty, codec)
    }

    fn is_closed(&self, t: &TypeRef) -> bool {
        matches!(t, TypeRef::Enum(e) if self.enums.get(e).is_some_and(|e| e.closed))
    }

    fn plans<'f>(&self, m: &'f MessageDef, fqn: &str, module: &[String]) -> Vec<Plan<'f>> {
        m.fields
            .iter()
            .map(|f| {
                let (ty, codec) = self.field_value(f, module);
                let msg = match &f.ty {
                    TypeRef::Message(t) => Some(t.as_str()),
                    _ => None,
                };
                let boxed = msg.is_some_and(|t| self.needs_box(fqn, t));
                let shape = if f.map_key.is_some() {
                    Shape::Map
                } else if f.oneof.is_some() {
                    Shape::Oneof { boxed }
                } else if f.label == Label::Repeated {
                    Shape::Repeated {
                        packed: f.resolved.packed,
                    }
                } else if msg.is_some() {
                    Shape::Optional { boxed }
                } else {
                    match f.resolved.presence {
                        Presence::Explicit => Shape::Optional { boxed },
                        Presence::Required => Shape::Required,
                        Presence::Implicit => Shape::Implicit,
                    }
                };
                let key = f.map_key.map(|k| {
                    if k == Scalar::String && self.unchecked(f) {
                        return (
                            "__pb::ProtoStringCodec".to_owned(),
                            "::only_protobuf::ProtoString".to_owned(),
                        );
                    }
                    let (t, c) = scalar_ty(k);
                    (format!("__pb::{c}"), t.to_owned())
                });
                Plan {
                    f,
                    name: ident(&snake(&f.name)),
                    shape,
                    codec,
                    ty,
                    key,
                    closed: self.is_closed(&f.ty),
                }
            })
            .collect()
    }

    fn map_type(&self) -> &'static str {
        if self.cfg.btree_maps {
            "::std::collections::BTreeMap"
        } else {
            "::std::collections::HashMap"
        }
    }

    fn message(
        &self,
        out: &mut String,
        m: &MessageDef,
        fqn: &str,
        module: &[String],
    ) -> GResult<()> {
        let name = camel(&m.name);
        let inner_mod = ident(&snake(&m.name));
        let mut inner: Vec<String> = module.to_vec();
        inner.push(inner_mod.clone());
        let plans = self.plans(m, fqn, module);
        if self.cfg.unknown_fields && plans.iter().any(|p| p.name == "unknown_fields") {
            return Err(format!(
                "{}: a field named unknown_fields clashes with the unknown-field member; turn \
                 Config::unknown_fields off",
                &fqn[1..]
            ));
        }
        let extendable = !m.extension_ranges.is_empty();
        if extendable && plans.iter().any(|p| p.name == "extensions") {
            return Err(format!(
                "{}: a field named extensions clashes with the extension member",
                &fqn[1..]
            ));
        }
        let eq = self.eq_able(fqn, &mut HashSet::new());
        let manual_default = plans
            .iter()
            .any(|p| p.shape == Shape::Required && p.f.default.is_some());

        // The struct.
        doc(out, "", &m.doc, &format!("The `{}` message.", &fqn[1..]));
        let _ = writeln!(
            out,
            "#[derive(Clone, PartialEq{}, Debug{})]",
            if eq { ", Eq" } else { "" },
            if manual_default { "" } else { ", Default" }
        );
        let _ = writeln!(out, "pub struct {name} {{");
        for p in plans.iter().filter(|p| p.f.oneof.is_none()) {
            doc(
                out,
                "    ",
                &p.f.doc,
                &format!("Field {}: `{}`.", p.f.number, p.f.name),
            );
            let ty = match p.shape {
                Shape::Implicit | Shape::Required => p.ty.clone(),
                Shape::Optional { boxed: false } => format!("::core::option::Option<{}>", p.ty),
                Shape::Optional { boxed: true } => {
                    format!("::core::option::Option<::std::boxed::Box<{}>>", p.ty)
                }
                Shape::Repeated { .. } => format!("::std::vec::Vec<{}>", p.ty),
                Shape::Map => format!(
                    "{}<{}, {}>",
                    self.map_type(),
                    p.key.as_ref().map_or("", |k| k.1.as_str()),
                    p.ty
                ),
                Shape::Oneof { .. } => unreachable!("oneof members are filtered out"),
            };
            let _ = writeln!(out, "    pub {}: {ty},", p.name);
        }
        for (i, o) in m.oneofs.iter().enumerate() {
            let members: Vec<String> = plans
                .iter()
                .filter(|p| p.f.oneof == Some(i))
                .map(|p| format!("`{}`", p.f.name))
                .collect();
            doc(
                out,
                "    ",
                &o.doc,
                &format!("The `{}` oneof: one of {}.", o.name, members.join(", ")),
            );
            let _ = writeln!(
                out,
                "    pub {}: ::core::option::Option<{inner_mod}::{}>,",
                ident(&snake(&o.name)),
                camel(&o.name)
            );
        }
        if extendable {
            out.push_str("    /// Extension fields (see `only_protobuf::Extendable`).\n");
            out.push_str("    pub extensions: ::only_protobuf::ExtensionSet,\n");
        }
        if self.cfg.unknown_fields {
            out.push_str("    /// Fields this version does not know, kept to be written back.\n");
            out.push_str("    pub unknown_fields: ::only_protobuf::UnknownFields,\n");
        }
        out.push_str("}\n\n");

        if manual_default {
            let _ = writeln!(out, "impl ::core::default::Default for {name} {{");
            let _ = writeln!(out, "    fn default() -> Self {{");
            let _ = writeln!(out, "        {name} {{");
            for p in plans.iter().filter(|p| p.f.oneof.is_none()) {
                let v = match (&p.shape, &p.f.default) {
                    (Shape::Required, Some(d)) => self.default_value(p, d, module, true),
                    _ => "::core::default::Default::default()".to_owned(),
                };
                let _ = writeln!(out, "            {}: {v},", p.name);
            }
            for o in &m.oneofs {
                let _ = writeln!(
                    out,
                    "            {}: ::core::option::Option::None,",
                    ident(&snake(&o.name))
                );
            }
            if extendable {
                out.push_str("            extensions: ::only_protobuf::ExtensionSet::new(),\n");
            }
            if self.cfg.unknown_fields {
                out.push_str(
                    "            unknown_fields: ::only_protobuf::UnknownFields::new(),\n",
                );
            }
            out.push_str("        }\n    }\n}\n\n");
        }

        // Getters for optional scalars (the default when unset).
        let reserved = [
            "encode_raw",
            "encoded_len",
            "merge_field",
            "merge_from",
            "encode",
            "encode_to_vec",
            "encode_length_delimited",
            "decode",
            "decode_length_delimited",
            "merge",
            "clear",
            "type_url",
            "encode_to",
            "decode_from",
        ];
        let getters: Vec<&Plan<'_>> = plans
            .iter()
            .filter(|p| {
                matches!(p.shape, Shape::Optional { .. })
                    && !matches!(p.f.ty, TypeRef::Message(_))
                    && !reserved.contains(&p.name.as_str())
            })
            .collect();
        if !getters.is_empty() {
            let _ = writeln!(out, "impl {name} {{");
            for p in getters {
                let d = match &p.f.default {
                    Some(d) => self.default_value(p, d, module, false),
                    None => match &p.f.ty {
                        TypeRef::Scalar(Scalar::String) if self.unchecked(p.f) => "&[]".to_owned(),
                        TypeRef::Scalar(Scalar::String) => "\"\"".to_owned(),
                        TypeRef::Scalar(Scalar::Bytes) => "&[]".to_owned(),
                        _ => "::core::default::Default::default()".to_owned(),
                    },
                };
                let _ = writeln!(
                    out,
                    "    /// `{}`, or its default ({}) when unset.",
                    p.f.name,
                    match &p.f.default {
                        Some(_) => "declared in the `.proto` file",
                        None => "the type's default",
                    }
                );
                match &p.f.ty {
                    TypeRef::Scalar(Scalar::String) if self.unchecked(p.f) => {
                        let _ = writeln!(
                            out,
                            "    pub fn {}(&self) -> &[u8] {{\n        self.{}.as_ref().map_or({d}, |v| v.as_bytes())\n    }}",
                            p.name, p.name
                        );
                    }
                    TypeRef::Scalar(Scalar::String) => {
                        let _ = writeln!(
                            out,
                            "    pub fn {}(&self) -> &str {{\n        self.{}.as_deref().unwrap_or({d})\n    }}",
                            p.name, p.name
                        );
                    }
                    TypeRef::Scalar(Scalar::Bytes) => {
                        let _ = writeln!(
                            out,
                            "    pub fn {}(&self) -> &[u8] {{\n        self.{}.as_deref().unwrap_or({d})\n    }}",
                            p.name, p.name
                        );
                    }
                    _ => {
                        let unwrap = if d.starts_with("::core::default") {
                            "unwrap_or_default()".to_owned()
                        } else {
                            format!("unwrap_or({d})")
                        };
                        let _ = writeln!(
                            out,
                            "    pub fn {}(&self) -> {} {{\n        self.{}.{unwrap}\n    }}",
                            p.name, p.ty, p.name
                        );
                    }
                }
            }
            out.push_str("}\n\n");
        }

        self.message_impl(out, m, fqn, &name, &inner_mod, &plans);
        if extendable {
            let _ = writeln!(
                out,
                "impl ::only_protobuf::Extendable for {name} {{
    fn extension_set(&self) -> &::only_protobuf::ExtensionSet {{
        &self.extensions
    }}
    fn extension_set_mut(&mut self) -> &mut ::only_protobuf::ExtensionSet {{
        &mut self.extensions
    }}
}}
"
            );
        }
        let _ = writeln!(
            out,
            "impl ::only_protobuf::Name for {name} {{\n    const FULL_NAME: &'static str = \"{}\";\n}}\n",
            &fqn[1..]
        );
        if self.cfg.descriptors {
            let sym = &self.syms[fqn];
            let pkg: Vec<String> = if sym.package.is_empty() {
                Vec::new()
            } else {
                sym.package.split('.').map(ident).collect()
            };
            let pool = rel(module, &pkg, "descriptor_pool");
            let _ = writeln!(
                out,
                "impl ::only_protobuf::reflect::ReflectMessage for {name} {{
    fn descriptor() -> ::only_protobuf::reflect::MessageDescriptor {{
        {pool}()
            .get_message_by_name(<Self as ::only_protobuf::Name>::FULL_NAME)
            .unwrap_or_else(|| ::core::panic!(\"{} is not in the descriptor pool\"))
    }}
}}
",
                &fqn[1..]
            );
        }
        if self.grpc {
            let _ = writeln!(
                out,
                "impl ::only_grpc::codec::Message for {name} {{
    fn encode_to(&self, buf: &mut ::std::vec::Vec<u8>) {{
        ::only_protobuf::Message::encode(self, buf);
    }}
    fn decode_from(bytes: &[u8]) -> ::core::result::Result<Self, ::only_grpc::Status> {{
        <Self as ::only_protobuf::Message>::decode(bytes)
            .map_err(|e| ::only_grpc::Status::new(::only_grpc::Code::InvalidArgument, e.to_string()))
    }}
}}
"
            );
        }

        // Nested types and oneof enums.
        if !m.messages.is_empty()
            || !m.enums.is_empty()
            || !m.oneofs.is_empty()
            || !m.extensions.is_empty()
        {
            let mut body = String::new();
            for (i, o) in m.oneofs.iter().enumerate() {
                let members: Vec<&Plan<'_>> =
                    plans.iter().filter(|p| p.f.oneof == Some(i)).collect();
                let eq = members.iter().all(|p| match &p.f.ty {
                    TypeRef::Scalar(Scalar::Float | Scalar::Double) => false,
                    TypeRef::Message(t) => self.eq_able(t, &mut HashSet::new()),
                    _ => true,
                });
                doc(
                    &mut body,
                    "",
                    &o.doc,
                    &format!("The `{}` oneof of `{}`.", o.name, &fqn[1..]),
                );
                let _ = writeln!(
                    body,
                    "#[derive(Clone, PartialEq{}, Debug)]\n#[allow(clippy::large_enum_variant, clippy::enum_variant_names)]\npub enum {} {{",
                    if eq { ", Eq" } else { "" },
                    camel(&o.name)
                );
                for p in members {
                    let (ty, _) = self.field_value(p.f, &inner);
                    let ty = if matches!(p.shape, Shape::Oneof { boxed: true }) {
                        format!("::std::boxed::Box<{ty}>")
                    } else {
                        ty
                    };
                    doc(
                        &mut body,
                        "    ",
                        &p.f.doc,
                        &format!("Field {}: `{}`.", p.f.number, p.f.name),
                    );
                    let _ = writeln!(body, "    {}({ty}),", camel(&p.f.name));
                }
                body.push_str("}\n\n");
            }
            for n in &m.messages {
                self.message(&mut body, n, &format!("{fqn}.{}", n.name), &inner)?;
            }
            for e in &m.enums {
                self.enumeration(&mut body, e);
            }
            self.extensions(&mut body, &m.extensions, &fqn[1..], &inner);
            let _ = writeln!(
                out,
                "/// Nested types of `{}`.\npub mod {inner_mod} {{",
                &fqn[1..]
            );
            out.push_str(&indent(body.trim_end()));
            out.push_str("}\n\n");
        }
        Ok(())
    }

    fn message_impl(
        &self,
        out: &mut String,
        m: &MessageDef,
        fqn: &str,
        name: &str,
        inner_mod: &str,
        plans: &[Plan<'_>],
    ) {
        let mut sorted: Vec<&Plan<'_>> = plans.iter().collect();
        sorted.sort_by_key(|p| p.f.number);
        let mut ranges: Vec<(u32, u32)> = m
            .extension_ranges
            .iter()
            .map(|r| (r.start, r.end))
            .collect();
        ranges.sort_unstable();
        let uf = self.cfg.unknown_fields;
        let ext = !ranges.is_empty();
        let message_set = m.options.flag("message_set_wire_format") == Some(true);
        let use_pb = "        use ::only_protobuf::encoding as __pb;\n";
        let _ = writeln!(out, "impl ::only_protobuf::Message for {name} {{");

        // encode_raw
        let _ = writeln!(
            out,
            "    fn encode_raw(&self, {}: &mut ::std::vec::Vec<u8>) {{",
            if plans.is_empty() && !uf && !ext {
                "_buf"
            } else {
                "buf"
            }
        );
        if !plans.is_empty() {
            out.push_str(use_pb);
        }
        let mut next_range = 0;
        for p in &sorted {
            while next_range < ranges.len() && ranges[next_range].0 < p.f.number {
                let (a, b) = ranges[next_range];
                let _ = writeln!(out, "        self.extensions.encode_range({a}, {b}, buf);");
                next_range += 1;
            }
            let (n, c, f) = (p.f.number, &p.codec, &p.name);
            let line = match p.shape {
                Shape::Implicit => format!("__pb::encode_implicit::<{c}>({n}, &self.{f}, buf);"),
                Shape::Required => format!("__pb::encode_required::<{c}>({n}, &self.{f}, buf);"),
                Shape::Optional { boxed } => format!(
                    "__pb::encode_optional::<{c}>({n}, self.{f}.{}(), buf);",
                    if boxed { "as_deref" } else { "as_ref" }
                ),
                Shape::Repeated { packed: true } => {
                    format!("__pb::encode_packed::<{c}>({n}, &self.{f}, buf);")
                }
                Shape::Repeated { packed: false } => {
                    format!("__pb::encode_repeated::<{c}>({n}, &self.{f}, buf);")
                }
                Shape::Map => format!(
                    "__pb::encode_map::<{}, {c}>({n}, &self.{f}, buf);",
                    p.key.as_ref().map_or("", |k| k.0.as_str())
                ),
                Shape::Oneof { boxed } => {
                    let o = &m.oneofs[p.f.oneof.unwrap_or(0)];
                    format!(
                        "if let ::core::option::Option::Some({inner_mod}::{}::{}(v)) = &self.{} {{\n            __pb::encode_required::<{c}>({n}, {}, buf);\n        }}",
                        camel(&o.name),
                        camel(&p.f.name),
                        ident(&snake(&o.name)),
                        if boxed { "&**v" } else { "v" }
                    )
                }
            };
            let _ = writeln!(out, "        {line}");
        }
        for &(a, b) in &ranges[next_range..] {
            if message_set {
                out.push_str("        self.extensions.encode_message_set(buf);\n");
            } else {
                let _ = writeln!(out, "        self.extensions.encode_range({a}, {b}, buf);");
            }
        }
        if uf {
            out.push_str("        self.unknown_fields.encode(buf);\n");
        }
        out.push_str("    }\n\n");

        // encoded_len
        out.push_str("    fn encoded_len(&self) -> usize {\n");
        if !plans.is_empty() {
            out.push_str(use_pb);
        }
        let mut terms = Vec::new();
        for p in plans.iter().filter(|p| p.f.oneof.is_none()) {
            let (n, c, f) = (p.f.number, &p.codec, &p.name);
            terms.push(match p.shape {
                Shape::Implicit => format!("__pb::implicit_len::<{c}>({n}, &self.{f})"),
                Shape::Required => format!("__pb::required_len::<{c}>({n}, &self.{f})"),
                Shape::Optional { boxed } => format!(
                    "__pb::optional_len::<{c}>({n}, self.{f}.{}())",
                    if boxed { "as_deref" } else { "as_ref" }
                ),
                Shape::Repeated { packed: true } => {
                    format!("__pb::packed_len::<{c}>({n}, &self.{f})")
                }
                Shape::Repeated { packed: false } => {
                    format!("__pb::repeated_len::<{c}>({n}, &self.{f})")
                }
                Shape::Map => format!(
                    "__pb::map_len::<{}, {c}>({n}, &self.{f})",
                    p.key.as_ref().map_or("", |k| k.0.as_str())
                ),
                Shape::Oneof { .. } => unreachable!("filtered"),
            });
        }
        for (i, o) in m.oneofs.iter().enumerate() {
            let mut t = format!("match &self.{} {{\n", ident(&snake(&o.name)));
            for p in plans.iter().filter(|p| p.f.oneof == Some(i)) {
                let boxed = matches!(p.shape, Shape::Oneof { boxed: true });
                let _ = writeln!(
                    t,
                    "            ::core::option::Option::Some({inner_mod}::{}::{}(v)) => __pb::required_len::<{}>({}, {}),",
                    camel(&o.name),
                    camel(&p.f.name),
                    p.codec,
                    p.f.number,
                    if boxed { "&**v" } else { "v" }
                );
            }
            t.push_str("            ::core::option::Option::None => 0,\n        }");
            terms.push(t);
        }
        if ext {
            terms.push(if message_set {
                "self.extensions.message_set_len()".into()
            } else {
                "self.extensions.encoded_len()".into()
            });
        }
        if uf {
            terms.push("self.unknown_fields.encoded_len()".into());
        }
        if terms.is_empty() {
            terms.push("0".into());
        }
        if terms.len() > 1 && terms[0].starts_with("match") {
            // A leading `match` would be a statement, not the sum's first operand.
            terms[0] = format!("({})", terms[0]);
        }
        let _ = writeln!(out, "        {}", terms.join("\n            + "));
        out.push_str("    }\n\n");

        // merge_field
        out.push_str(
            "    fn merge_field(
        &mut self,
        field: u32,
        wire_type: ::only_protobuf::encoding::WireType,
        r: &mut ::only_protobuf::encoding::Reader<'_>,
    ) -> ::core::result::Result<(), ::only_protobuf::DecodeError> {\n",
        );
        let fallback = if uf {
            "self.unknown_fields.merge_field(field, wire_type, r)"
        } else {
            "r.skip_field(field, wire_type).map(drop)"
        };
        let unknown = if uf {
            "&mut self.unknown_fields"
        } else {
            "&mut ::only_protobuf::UnknownFields::new()"
        };
        if message_set {
            // MessageSet: extensions travel as `repeated group Item = 1 { type_id = 2; message = 3 }`.
            let _ = writeln!(
                out,
                "        match field {{\n            1 if wire_type == ::only_protobuf::encoding::WireType::StartGroup => self.extensions.merge_message_set_item(r),"
            );
            // Extensions encoded as plain submessages are accepted too.
            let _ = writeln!(
                out,
                "            2..={} => self.extensions.merge_field(field, wire_type, r),\n            _ => {fallback},\n        }}",
                (1u32 << 29) - 1
            );
        } else if plans.is_empty() && !ext {
            let _ = writeln!(out, "        {fallback}");
        } else {
            if !plans.is_empty() {
                out.push_str(use_pb);
            }
            out.push_str("        match field {\n");
            for p in &sorted {
                let (n, c, f) = (p.f.number, &p.codec, &p.name);
                if p.closed {
                    let (arm, guard) = self.closed_arm(m, p, inner_mod, unknown);
                    let _ = writeln!(out, "            {n} if {guard} => {arm},");
                    continue;
                }
                let arm = match p.shape {
                    Shape::Implicit | Shape::Required => {
                        format!("__pb::merge_value::<{c}>({n}, wire_type, r, &mut self.{f})")
                    }
                    Shape::Optional { boxed: false } => {
                        format!("__pb::merge_optional::<{c}>({n}, wire_type, r, &mut self.{f})")
                    }
                    Shape::Optional { boxed: true } => {
                        format!("__pb::merge_boxed::<{c}>({n}, wire_type, r, &mut self.{f})")
                    }
                    Shape::Repeated { .. } => {
                        format!("__pb::merge_repeated::<{c}>({n}, wire_type, r, &mut self.{f})")
                    }
                    Shape::Map => format!(
                        "__pb::merge_map::<{}, {c}>({n}, wire_type, r, &mut self.{f})",
                        p.key.as_ref().map_or("", |k| k.0.as_str())
                    ),
                    Shape::Oneof { boxed } => {
                        let o = &m.oneofs[p.f.oneof.unwrap_or(0)];
                        let var = format!("{inner_mod}::{}::{}", camel(&o.name), camel(&p.f.name));
                        let of = ident(&snake(&o.name));
                        format!(
                            "match &mut self.{of} {{
                ::core::option::Option::Some({var}(v)) => __pb::merge_value::<{c}>({n}, wire_type, r, {}),
                _ => {{
                    let mut v = ::core::default::Default::default();
                    __pb::merge_value::<{c}>({n}, wire_type, r, &mut v)?;
                    self.{of} = ::core::option::Option::Some({var}({}));
                    ::core::result::Result::Ok(())
                }}
            }}",
                            if boxed { "&mut **v" } else { "v" },
                            if boxed { "::std::boxed::Box::new(v)" } else { "v" }
                        )
                    }
                };
                // A field with another wire type is an unknown field (as in C++ and Go).
                let guard = match p.shape {
                    Shape::Repeated { .. } => format!("__pb::accepts_repeated::<{c}>(wire_type)"),
                    Shape::Map => "wire_type == __pb::WireType::Len".to_owned(),
                    _ => format!("__pb::accepts::<{c}>(wire_type)"),
                };
                let _ = writeln!(out, "            {n} if {guard} => {arm},");
            }
            if let Some(nums) = self.utf8_exts.get(fqn) {
                for n in nums {
                    let _ = writeln!(
                        out,
                        "            {n} if wire_type == __pb::WireType::Len => self.extensions.merge_utf8_field(field, wire_type, r),"
                    );
                }
            }
            for &(a, b) in &ranges {
                let _ = writeln!(
                    out,
                    "            {a}..={b} => self.extensions.merge_field(field, wire_type, r),"
                );
            }
            let _ = writeln!(out, "            _ => {fallback},");
            out.push_str("        }\n");
        }
        out.push_str("    }\n}\n\n");
    }

    /// The merge arm and its guard for a closed enum field.
    fn closed_arm(
        &self,
        m: &MessageDef,
        p: &Plan<'_>,
        inner_mod: &str,
        unknown: &str,
    ) -> (String, String) {
        let (n, f, e) = (p.f.number, &p.name, &p.ty);
        let read = format!("__pb::read_closed_enum::<{e}>({n}, wire_type, r, {unknown})?");
        let single = format!("__pb::accepts::<{}>(wire_type)", p.codec);
        match p.shape {
            Shape::Implicit | Shape::Required => (
                format!(
                    "{{\n                if let ::core::option::Option::Some(v) = {read} {{\n                    self.{f} = v;\n                }}\n                ::core::result::Result::Ok(())\n            }}"
                ),
                single,
            ),
            Shape::Optional { .. } => (
                format!(
                    "{{\n                if let ::core::option::Option::Some(v) = {read} {{\n                    self.{f} = ::core::option::Option::Some(v);\n                }}\n                ::core::result::Result::Ok(())\n            }}"
                ),
                single,
            ),
            Shape::Repeated { .. } => (
                format!(
                    "__pb::merge_closed_enum_repeated::<{e}>({n}, wire_type, r, &mut self.{f}, {unknown})"
                ),
                format!("__pb::accepts_repeated::<{}>(wire_type)", p.codec),
            ),
            Shape::Map => (
                format!(
                    "__pb::merge_closed_enum_map::<{}, {e}>({n}, wire_type, r, &mut self.{f}, {unknown})",
                    p.key.as_ref().map_or("", |k| k.0.as_str())
                ),
                "wire_type == __pb::WireType::Len".to_owned(),
            ),
            Shape::Oneof { .. } => {
                let o = &m.oneofs[p.f.oneof.unwrap_or(0)];
                (
                    format!(
                        "{{\n                if let ::core::option::Option::Some(v) = {read} {{\n                    self.{} = ::core::option::Option::Some({inner_mod}::{}::{}(v));\n                }}\n                ::core::result::Result::Ok(())\n            }}",
                        ident(&snake(&o.name)),
                        camel(&o.name),
                        camel(&p.f.name)
                    ),
                    single,
                )
            }
        }
    }

    /// Constants for the extensions declared in one scope (`scope`: the package or the message's
    /// full name, for the names).
    fn extensions(&self, out: &mut String, exts: &[Field], scope: &str, module: &[String]) {
        for x in exts {
            let Some(TypeRef::Message(e)) = &x.extendee else {
                continue;
            };
            let extendee = self.type_path(e, module);
            let (_, codec) = self.field_value(x, module);
            let codec = codec.replace("__pb::", "::only_protobuf::encoding::");
            let full = if scope.is_empty() {
                x.name.clone()
            } else {
                format!("{scope}.{}", x.name)
            };
            doc(
                out,
                "",
                &x.doc,
                &format!("Extension `{full}` of `{}` (field {}).", &e[1..], x.number),
            );
            let cname = ident(&screaming(&x.name));
            if x.label == Label::Repeated {
                let _ = writeln!(
                    out,
                    "pub const {cname}: ::only_protobuf::RepeatedExtension<{extendee}, {codec}> =\n    ::only_protobuf::RepeatedExtension::new({}, {full:?}, {});\n",
                    x.number, x.resolved.packed
                );
            } else {
                let _ = writeln!(
                    out,
                    "pub const {cname}: ::only_protobuf::Extension<{extendee}, {codec}> =\n    ::only_protobuf::Extension::new({}, {full:?});\n",
                    x.number
                );
            }
        }
    }

    /// A Rust expression for a declared `[default = ...]`; `owned` for a struct field value
    /// (`String`, `Vec<u8>`), otherwise a getter's (`&str`, `&[u8]`, a copy).
    fn default_value(&self, p: &Plan<'_>, d: &Constant, from: &[String], owned: bool) -> String {
        match (&p.f.ty, d) {
            (TypeRef::Scalar(Scalar::String), Constant::Str(s)) if self.unchecked(p.f) => {
                let items: Vec<String> = s.iter().map(u8::to_string).collect();
                if owned {
                    format!(
                        "::only_protobuf::ProtoString::from(::std::vec![{}])",
                        items.join(", ")
                    )
                } else {
                    format!("&[{}]", items.join(", "))
                }
            }
            (TypeRef::Scalar(Scalar::String), Constant::Str(s)) => {
                let lit = format!("{:?}", String::from_utf8_lossy(s));
                if owned {
                    format!("::std::string::String::from({lit})")
                } else {
                    lit
                }
            }
            (TypeRef::Scalar(Scalar::Bytes), Constant::Str(s)) => {
                let items: Vec<String> = s.iter().map(u8::to_string).collect();
                if owned {
                    format!("::std::vec![{}]", items.join(", "))
                } else {
                    format!("&[{}]", items.join(", "))
                }
            }
            (TypeRef::Scalar(Scalar::Bool), Constant::Ident(b)) => (b == "true").to_string(),
            (
                TypeRef::Scalar(s @ (Scalar::Float | Scalar::Double)),
                Constant::Float(t) | Constant::Int(t),
            ) => {
                let ty = if *s == Scalar::Float { "f32" } else { "f64" };
                let (neg, body) = t
                    .strip_prefix('-')
                    .map_or((false, t.as_str()), |b| (true, b));
                let v = match body {
                    "inf" => format!("{ty}::INFINITY"),
                    "nan" => format!("{ty}::NAN"),
                    b if b.contains(['.', 'e', 'E']) => {
                        let b = if b.starts_with('.') {
                            format!("0{b}")
                        } else {
                            b.to_owned()
                        };
                        let b = if b.ends_with('.') { format!("{b}0") } else { b };
                        format!("{b}_{ty}")
                    }
                    b => format!("{}.0_{ty}", crate::parse::parse_int(b).unwrap_or(0)),
                };
                if neg { format!("-{v}") } else { v }
            }
            (TypeRef::Scalar(_), Constant::Int(t)) => {
                let (neg, body) = t
                    .strip_prefix('-')
                    .map_or((false, t.as_str()), |b| (true, b));
                let v = crate::parse::parse_int(body).unwrap_or(0);
                if neg { format!("-{v}") } else { v.to_string() }
            }
            (TypeRef::Enum(e), Constant::Ident(v)) => {
                let path = self.type_path(e, from);
                format!("{path}::{}", self.enum_const_name(e, v))
            }
            _ => "::core::default::Default::default()".to_owned(),
        }
    }

    /// The Rust constant name of enum value `value` of the enum `fqn`.
    fn enum_const_name(&self, fqn: &str, value: &str) -> String {
        match self.enums.get(fqn) {
            Some(e) => const_names(e)
                .into_iter()
                .zip(&e.values)
                .find(|(_, v)| v.name == value)
                .map_or_else(|| screaming(value), |(n, _)| n),
            None => screaming(value),
        }
    }

    fn enumeration(&self, out: &mut String, e: &EnumDef) {
        let name = camel(&e.name);
        let consts = const_names(e);
        doc(out, "", &e.doc, &format!("The `{}` enum.", e.name));
        let _ = writeln!(
            out,
            "#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]\npub struct {name}(pub i32);\n"
        );
        let _ = writeln!(out, "impl {name} {{");
        for (c, v) in consts.iter().zip(&e.values) {
            doc(
                out,
                "    ",
                &v.doc,
                &format!("`{}` = {}.", v.name, v.number),
            );
            if c.chars().any(|ch| ch.is_ascii_lowercase()) {
                out.push_str("    #[allow(non_upper_case_globals)]\n");
            }
            let _ = writeln!(out, "    pub const {c}: {name} = {name}({});", v.number);
        }
        out.push_str("\n    /// The value with this name in the `.proto` file.\n");
        let _ = writeln!(
            out,
            "    pub fn from_name(name: &str) -> ::core::option::Option<{name}> {{\n        match name {{"
        );
        for (c, v) in consts.iter().zip(&e.values) {
            let _ = writeln!(
                out,
                "            {:?} => ::core::option::Option::Some({name}::{c}),",
                v.name
            );
        }
        out.push_str("            _ => ::core::option::Option::None,\n        }\n    }\n}\n\n");
        let first = &consts[0];
        let _ = writeln!(
            out,
            "impl ::core::default::Default for {name} {{\n    fn default() -> Self {{\n        {name}::{first}\n    }}\n}}\n"
        );
        let _ = writeln!(out, "impl ::only_protobuf::Enumeration for {name} {{");
        let _ = writeln!(
            out,
            "    fn from_i32(v: i32) -> Self {{\n        {name}(v)\n    }}"
        );
        let _ = writeln!(out, "    fn value(self) -> i32 {{\n        self.0\n    }}");
        let _ = writeln!(
            out,
            "    fn name(self) -> ::core::option::Option<&'static str> {{\n        match self.0 {{"
        );
        let mut seen = HashSet::new();
        for v in &e.values {
            if seen.insert(v.number) {
                let _ = writeln!(
                    out,
                    "            {} => ::core::option::Option::Some({:?}),",
                    v.number, v.name
                );
            }
        }
        out.push_str("            _ => ::core::option::Option::None,\n        }\n    }\n}\n\n");
        let _ = writeln!(
            out,
            "impl ::core::fmt::Debug for {name} {{
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {{
        match ::only_protobuf::Enumeration::name(*self) {{
            ::core::option::Option::Some(n) => f.write_str(n),
            ::core::option::Option::None => ::core::fmt::Debug::fmt(&self.0, f),
        }}
    }}
}}

impl ::core::convert::From<i32> for {name} {{
    fn from(v: i32) -> Self {{
        {name}(v)
    }}
}}

impl ::core::convert::From<{name}> for i32 {{
    fn from(v: {name}) -> Self {{
        v.0
    }}
}}
"
        );
    }

    fn service(&self, out: &mut String, s: &Service, package: &str, module: &[String]) {
        let full = if package.is_empty() {
            s.name.clone()
        } else {
            format!("{package}.{}", s.name)
        };
        let trait_name = camel(&s.name);
        let snake_name = snake(&s.name);
        let server_mod = format!("{snake_name}_server");
        let client_mod = format!("{snake_name}_client");
        let mut smod = module.to_vec();
        smod.push(server_mod.clone());
        let mut cmod = module.to_vec();
        cmod.push(client_mod.clone());
        let ty = |t: &TypeRef, from: &[String]| match t {
            TypeRef::Message(f) => self.type_path(f, from),
            _ => String::new(),
        };
        let md = "&::only_grpc::Metadata";
        let st = "::only_grpc::Status";
        let res = |t: &str| format!("::core::result::Result<{t}, {st}>");

        // Server.
        let mut b = String::new();
        doc(
            &mut b,
            "",
            &s.doc,
            &format!("The `{full}` service. Implement it and add it to a server with `register`."),
        );
        let _ = writeln!(
            b,
            "pub trait {trait_name}: ::core::marker::Send + ::core::marker::Sync + 'static {{"
        );
        for m in &s.methods {
            let (i, o) = (ty(&m.input, &smod), ty(&m.output, &smod));
            let kind = match (m.client_streaming, m.server_streaming) {
                (false, false) => "Unary: answer with the response or a status.",
                (false, true) => {
                    "Server streaming: send responses with `sink.send_message`, then `sink.finish`; the sink works from any thread."
                }
                (true, false) => {
                    "Client streaming: every request message, once the client has finished sending."
                }
                (true, true) => {
                    "Bidirectional streaming: return the function that receives each request (then `None` at the client's half-close); answer through the sink."
                }
            };
            doc(&mut b, "    ", &format!("{}\n\n{kind}", m.doc.trim()), kind);
            let fname = ident(&snake(&m.name));
            let sig = match (m.client_streaming, m.server_streaming) {
                (false, false) => {
                    format!("fn {fname}(&self, md: {md}, request: {i}) -> {};", res(&o))
                }
                (false, true) => {
                    format!("fn {fname}(&self, md: {md}, request: {i}, sink: ::only_grpc::Sink);")
                }
                (true, false) => {
                    format!(
                        "fn {fname}(&self, md: {md}, requests: ::std::vec::Vec<{i}>) -> {};",
                        res(&o)
                    )
                }
                (true, true) => format!(
                    "fn {fname}(\n        &self,\n        md: {md},\n        sink: ::only_grpc::Sink,\n    ) -> ::std::boxed::Box<dyn ::core::ops::FnMut(::core::option::Option<{i}>) + ::core::marker::Send>;"
                ),
            };
            let _ = writeln!(b, "    {sig}");
        }
        b.push_str("}\n\n");
        let _ = writeln!(
            b,
            "/// Registers every method of `service` on `server` (paths `/{full}/<Method>`)."
        );
        if s.methods.is_empty() {
            let _ = writeln!(
                b,
                "pub fn register<S: {trait_name}>(server: ::only_grpc::GrpcServer, _service: S) -> ::only_grpc::GrpcServer {{\n    server\n}}"
            );
        } else {
            let _ = writeln!(
                b,
                "pub fn register<S: {trait_name}>(server: ::only_grpc::GrpcServer, service: S) -> ::only_grpc::GrpcServer {{"
            );
            b.push_str("    let service = ::std::sync::Arc::new(service);\n");
            let reply = format!(
                "match r {{
                ::core::result::Result::Ok(reply) => {{
                    sink.send_message(&reply);
                    sink.finish({st}::ok());
                }}
                ::core::result::Result::Err(status) => sink.finish(status),
            }}"
            );
            for (idx, m) in s.methods.iter().enumerate() {
                let (i, _) = (ty(&m.input, &smod), ty(&m.output, &smod));
                let fname = ident(&snake(&m.name));
                let path = format!("/{full}/{}", m.name);
                let s_var = if idx + 1 == s.methods.len() {
                    "    let s = service;\n".to_owned()
                } else {
                    "    let s = service.clone();\n".to_owned()
                };
                b.push_str(&s_var);
                let body = match (m.client_streaming, m.server_streaming) {
                    (false, false) => format!(
                        "    let server = server.unary({path:?}, move |md, request, sink| {{
        match ::only_grpc::codec::decode::<{i}>(&request) {{
            ::core::result::Result::Ok(request) => {{
                let r = s.{fname}(md, request);
                {}
            }}
            ::core::result::Result::Err(status) => sink.finish(status),
        }}
    }});\n",
                        reply.replace('\n', "\n    ")
                    ),
                    (false, true) => format!(
                        "    let server = server.server_stream({path:?}, move |md, request, sink| {{
        match ::only_grpc::codec::decode::<{i}>(&request) {{
            ::core::result::Result::Ok(request) => s.{fname}(md, request, sink),
            ::core::result::Result::Err(status) => sink.finish(status),
        }}
    }});\n"
                    ),
                    (true, false) => format!(
                        "    let server = server.client_stream({path:?}, move |md, requests, sink| {{
        let mut decoded = ::std::vec::Vec::with_capacity(requests.len());
        for m in &requests {{
            match ::only_grpc::codec::decode::<{i}>(m) {{
                ::core::result::Result::Ok(m) => decoded.push(m),
                ::core::result::Result::Err(status) => return sink.finish(status),
            }}
        }}
        let r = s.{fname}(md, decoded);
        {}
    }});\n",
                        reply.replace("\n    ", "\n")
                    ),
                    (true, true) => format!(
                        "    let server = server.bidi({path:?}, move |md, sink| {{
        let mut on_message = s.{fname}(md, sink.clone());
        ::std::boxed::Box::new(move |m: ::core::option::Option<::std::vec::Vec<u8>>| match m {{
            ::core::option::Option::Some(b) => match ::only_grpc::codec::decode::<{i}>(&b) {{
                ::core::result::Result::Ok(v) => on_message(::core::option::Option::Some(v)),
                ::core::result::Result::Err(status) => sink.finish(status),
            }},
            ::core::option::Option::None => on_message(::core::option::Option::None),
        }})
    }});\n"
                    ),
                };
                if idx + 1 == s.methods.len() {
                    let body = body.replacen("    let server = server.", "    server.", 1);
                    b.push_str(body.strip_suffix(";\n").unwrap_or(&body));
                    b.push_str("\n}\n");
                } else {
                    b.push_str(&body);
                }
            }
        }
        let _ = writeln!(
            out,
            "/// Server side of the `{full}` service.\npub mod {server_mod} {{"
        );
        out.push_str(&indent(b.trim_end()));
        out.push_str("}\n\n");

        // Client.
        let client = format!("{trait_name}Client");
        let mut b = String::new();
        let _ = writeln!(
            b,
            "/// A client of the `{full}` service on an `only_grpc::GrpcClient`. The calls returning a\n/// result block the calling thread (not an I/O thread); the streaming-both-ways call does not.\n#[derive(Clone, Debug)]\npub struct {client} {{\n    inner: ::only_grpc::GrpcClient,\n}}\n"
        );
        let _ = writeln!(b, "impl {client} {{");
        let _ = writeln!(
            b,
            "    /// A client on `inner`.\n    pub fn new(inner: ::only_grpc::GrpcClient) -> Self {{\n        {client} {{ inner }}\n    }}\n"
        );
        let _ = writeln!(
            b,
            "    /// The underlying client.\n    pub fn inner(&self) -> &::only_grpc::GrpcClient {{\n        &self.inner\n    }}"
        );
        for m in &s.methods {
            let (i, o) = (ty(&m.input, &cmod), ty(&m.output, &cmod));
            let fname = ident(&snake(&m.name));
            let path = format!("/{full}/{}", m.name);
            let kind = match (m.client_streaming, m.server_streaming) {
                (false, false) => "Unary call (blocking).",
                (false, true) => "Server-streaming call (blocking): every response message.",
                (true, false) => {
                    "Client-streaming call (blocking): sends `requests`, half-closes, returns the response."
                }
                (true, true) => {
                    "Bidirectional call: `on_message` gets each response, `done` the final status and trailers; the returned sink sends requests (`send_message`, `close_send`)."
                }
            };
            b.push('\n');
            doc(&mut b, "    ", &format!("{}\n\n{kind}", m.doc.trim()), kind);
            let code = match (m.client_streaming, m.server_streaming) {
                (false, false) => format!(
                    "    pub fn {fname}(&self, request: &{i}, opts: ::only_grpc::CallOptions) -> {} {{
        let reply = self.inner.unary({path:?}, &::only_grpc::codec::encode(request), opts)?;
        ::only_grpc::codec::decode(&reply)
    }}\n",
                    res(&o)
                ),
                (false, true) => format!(
                    "    pub fn {fname}(&self, request: &{i}, opts: ::only_grpc::CallOptions) -> {} {{
        let (msgs, status) = self.inner.collect({path:?}, ::std::vec![::only_grpc::codec::encode(request)], opts);
        if status.code != ::only_grpc::Code::Ok {{
            return ::core::result::Result::Err(status);
        }}
        msgs.iter().map(|m| ::only_grpc::codec::decode::<{o}>(m.as_slice())).collect()
    }}\n",
                    res(&format!("::std::vec::Vec<{o}>"))
                ),
                (true, false) => format!(
                    "    pub fn {fname}(&self, requests: &[{i}], opts: ::only_grpc::CallOptions) -> {} {{
        let reqs = requests.iter().map(::only_grpc::codec::encode::<{i}>).collect();
        let (msgs, status) = self.inner.collect({path:?}, reqs, opts);
        if status.code != ::only_grpc::Code::Ok {{
            return ::core::result::Result::Err(status);
        }}
        match msgs.first() {{
            ::core::option::Option::Some(m) => ::only_grpc::codec::decode(m),
            ::core::option::Option::None => ::core::result::Result::Err({st}::new(::only_grpc::Code::Internal, \"no response message\")),
        }}
    }}\n",
                    res(&o)
                ),
                (true, true) => format!(
                    "    pub fn {fname}(
        &self,
        opts: ::only_grpc::CallOptions,
        mut on_message: impl ::core::ops::FnMut({o}) + ::core::marker::Send + 'static,
        done: impl ::core::ops::FnOnce({st}, ::only_grpc::Headers) + ::core::marker::Send + 'static,
    ) -> ::only_grpc::ClientSink {{
        let bad = ::std::sync::Arc::new(::std::sync::Mutex::new(::core::option::Option::<{st}>::None));
        let bad2 = ::std::sync::Arc::clone(&bad);
        self.inner.bidi(
            {path:?},
            opts,
            move |m| match ::only_grpc::codec::decode::<{o}>(&m) {{
                ::core::result::Result::Ok(v) => on_message(v),
                ::core::result::Result::Err(status) => {{
                    let mut g = bad2.lock().unwrap_or_else(::std::sync::PoisonError::into_inner);
                    if g.is_none() {{
                        *g = ::core::option::Option::Some(status);
                    }}
                }}
            }},
            move |status, trailers| {{
                let bad = bad.lock().unwrap_or_else(::std::sync::PoisonError::into_inner).take();
                done(bad.unwrap_or(status), trailers);
            }},
        )
    }}\n"
                ),
            };
            b.push_str(&code);
        }
        b.push_str("}\n");
        let _ = writeln!(
            out,
            "/// Client side of the `{full}` service.\npub mod {client_mod} {{"
        );
        out.push_str(&indent(b.trim_end()));
        out.push_str("}\n\n");
    }
}

/// The Rust constant names of an enum's values: SCREAMING_SNAKE_CASE, without the enum's name
/// as a prefix when every value has it (`Corpus::CORPUS_WEB` -> `Corpus::WEB`).
fn const_names(e: &EnumDef) -> Vec<String> {
    let prefix = format!("{}_", screaming(&e.name));
    let plain: Vec<String> = e.values.iter().map(|v| screaming(&v.name)).collect();
    let stripped: Vec<String> = plain
        .iter()
        .map(|n| n.strip_prefix(&prefix).unwrap_or(n).to_owned())
        .collect();
    let ok = stripped
        .iter()
        .all(|s| !s.is_empty() && !s.starts_with(|c: char| c.is_ascii_digit()))
        && stripped.iter().collect::<HashSet<_>>().len() == stripped.len();
    let names = if ok { stripped } else { plain };
    // Aliases whose names differ only in case (`MOO`, `moo`) keep their own spelling.
    let mut seen = HashSet::new();
    names
        .into_iter()
        .zip(&e.values)
        .enumerate()
        .map(|(i, (n, v))| {
            let n = if n == "SELF" { "SELF_".to_owned() } else { n };
            if seen.insert(n.clone()) {
                return n;
            }
            let own = ident(&v.name);
            if seen.insert(own.clone()) {
                own
            } else {
                let n = format!("{n}_{i}");
                seen.insert(n.clone());
                n
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(snake("HTTPRequest"), "http_request");
        assert_eq!(snake("routeGuide"), "route_guide");
        assert_eq!(snake("Int32Value"), "int32_value");
        assert_eq!(snake("foo_bar"), "foo_bar");
        assert_eq!(camel("hello_request"), "HelloRequest");
        assert_eq!(camel("HTTPRequest"), "HttpRequest");
        assert_eq!(camel("UInt64Value"), "UInt64Value");
        assert_eq!(camel("RTP"), "Rtp");
        assert_eq!(camel("self"), "Self_");
        assert_eq!(ident("type"), "r#type");
        assert_eq!(ident("self"), "self_");
        assert_eq!(screaming("phoneType"), "PHONE_TYPE");
        assert_eq!(
            rel(&["a".into(), "b".into()], &["a".into(), "c".into()], "T"),
            "super::c::T"
        );
        assert_eq!(rel(&[], &["x".into()], "T"), "x::T");
        assert_eq!(rel(&["x".into()], &[], "T"), "super::T");
    }

    #[test]
    fn markdown() {
        assert_eq!(
            markdown_safe("see [x] <y> `a[b]`"),
            "see \\[x\\] \\<y\\> `a[b]`"
        );
        assert_eq!(
            markdown_safe("at https://x.org/a."),
            "at <https://x.org/a>."
        );
        assert_eq!(
            markdown_safe("[d](https://x.org)"),
            "\\[d\\](<https://x.org>)"
        );
    }
}
