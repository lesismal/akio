//! Feature resolution: what editions features (or, for proto2 and proto3 files, the equivalent
//! legacy rules) make of each field and enum. Runs after name resolution, since a field's type
//! kind matters.

use crate::parse::{
    Constant, Edition, EnumDef, Field, File, Label, MessageDef, OptionDef, Presence, Resolved,
    TypeRef,
};

/// The resolved `google.protobuf.FeatureSet` values this generator acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Features {
    pub(crate) presence: Presence,
    pub(crate) closed_enums: bool,
    pub(crate) packed: bool,
    pub(crate) verify_utf8: bool,
    pub(crate) delimited: bool,
    pub(crate) json_allow: bool,
    /// 2024 `enforce_naming_style = STYLE2024`.
    pub(crate) style2024: bool,
    /// 2024 `default_symbol_visibility`: whether nested types are local by default (`EXPORT_TOP_LEVEL`),
    /// and whether top-level ones are too (`LOCAL_ALL`, `STRICT`).
    pub(crate) local_nested: bool,
    pub(crate) local_top: bool,
}

impl Features {
    /// The defaults of `edition` (proto2 / proto3: the legacy behaviour).
    pub(crate) fn defaults(edition: Edition) -> Features {
        match edition {
            Edition::Proto2 => Features {
                presence: Presence::Explicit,
                closed_enums: true,
                packed: false,
                verify_utf8: false,
                delimited: false,
                json_allow: false,
                style2024: false,
                local_nested: false,
                local_top: false,
            },
            Edition::Proto3 => Features {
                presence: Presence::Implicit,
                closed_enums: false,
                packed: true,
                verify_utf8: true,
                delimited: false,
                json_allow: true,
                style2024: false,
                local_nested: false,
                local_top: false,
            },
            Edition::E2023 | Edition::E2024 => Features {
                presence: Presence::Explicit,
                closed_enums: false,
                packed: true,
                verify_utf8: true,
                delimited: false,
                json_allow: true,
                style2024: edition == Edition::E2024,
                local_nested: edition == Edition::E2024,
                local_top: false,
            },
        }
    }
}

/// Where a feature is set (`FeatureSet` field targets).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Target {
    File,
    Message,
    Field,
    Oneof,
    Enum,
    EnumValue,
    Service,
    Method,
    ExtensionRange,
}

/// Applies the `features.*` options of one element to its parent's features.
fn apply(
    mut f: Features,
    options: &[OptionDef],
    edition: Edition,
    target: Target,
    what: &str,
) -> Result<Features, String> {
    for o in options {
        let Some(name) = o.name.strip_prefix("features.") else {
            if o.name == "features" {
                return Err(format!(
                    "{what}: set features one by one (features.<name> = ...)"
                ));
            }
            continue;
        };
        if name.starts_with('(') {
            continue; // language-specific features: not ours
        }
        if !edition.is_editions() {
            return Err(format!("{what}: features are only valid in editions files"));
        }
        let v = match &o.value {
            Constant::Ident(v) => v.as_str(),
            _ => return Err(format!("{what}: features.{name} takes an enum value")),
        };
        let bad = || format!("{what}: invalid value {v} for features.{name}");
        let allowed: &[Target] = match name {
            "field_presence"
            | "repeated_field_encoding"
            | "utf8_validation"
            | "message_encoding" => &[Target::File, Target::Field],
            "enum_type" => &[Target::File, Target::Enum],
            "json_format" => &[Target::File, Target::Message, Target::Enum],
            "enforce_naming_style" if edition >= Edition::E2024 => &[
                Target::File,
                Target::Message,
                Target::Field,
                Target::Oneof,
                Target::Enum,
                Target::EnumValue,
                Target::Service,
                Target::Method,
                Target::ExtensionRange,
            ],
            "default_symbol_visibility" if edition >= Edition::E2024 => &[Target::File],
            _ => return Err(format!("{what}: unknown feature features.{name}")),
        };
        if !allowed.contains(&target) {
            return Err(format!(
                "{what}: features.{name} cannot be set on a {}",
                format!("{target:?}").to_ascii_lowercase()
            ));
        }
        match name {
            "field_presence" => {
                f.presence = match v {
                    "EXPLICIT" => Presence::Explicit,
                    "IMPLICIT" => Presence::Implicit,
                    "LEGACY_REQUIRED" => Presence::Required,
                    _ => return Err(bad()),
                }
            }
            "enum_type" => {
                f.closed_enums = match v {
                    "OPEN" => false,
                    "CLOSED" => true,
                    _ => return Err(bad()),
                }
            }
            "repeated_field_encoding" => {
                f.packed = match v {
                    "PACKED" => true,
                    "EXPANDED" => false,
                    _ => return Err(bad()),
                }
            }
            "utf8_validation" => {
                f.verify_utf8 = match v {
                    "VERIFY" => true,
                    "NONE" => false,
                    _ => return Err(bad()),
                }
            }
            "message_encoding" => {
                f.delimited = match v {
                    "LENGTH_PREFIXED" => false,
                    "DELIMITED" => true,
                    _ => return Err(bad()),
                }
            }
            "json_format" => {
                f.json_allow = match v {
                    "ALLOW" => true,
                    "LEGACY_BEST_EFFORT" => false,
                    _ => return Err(bad()),
                }
            }
            "enforce_naming_style" => {
                f.style2024 = match v {
                    "STYLE2024" => true,
                    "STYLE_LEGACY" => false,
                    _ => return Err(bad()),
                }
            }
            "default_symbol_visibility" => {
                (f.local_top, f.local_nested) = match v {
                    "EXPORT_ALL" => (false, false),
                    "EXPORT_TOP_LEVEL" => (false, true),
                    "LOCAL_ALL" | "STRICT" => (true, true),
                    _ => return Err(bad()),
                }
            }
            _ => {}
        }
    }
    Ok(f)
}

fn is_set(options: &[OptionDef], feature: &str) -> bool {
    options.iter().any(|o| o.name == feature)
}

/// Resolves every field and enum of `file` (types already resolved). `closed` tells whether an
/// enum (by full name) of any file is closed; it is filled for this file's enums first.
pub(crate) fn resolve_file(
    file: &mut File,
    closed: &mut dyn FnMut(&str) -> Option<bool>,
) -> Result<(), String> {
    let edition = file.edition;
    let base = apply(
        Features::defaults(edition),
        &file.options,
        edition,
        Target::File,
        &file.name,
    )?;
    if base.style2024 {
        check_package_style(&file.package).map_err(|e| format!("{}: {e}", file.name))?;
    }
    let ctx = Ctx {
        edition,
        file: file.name.clone(),
    };
    for e in &mut file.enums {
        ctx.enumeration(e, base)?;
    }
    for m in &mut file.messages {
        ctx.message_enums(m, base)?;
    }
    for m in &mut file.messages {
        ctx.message(m, base, closed)?;
    }
    for f in &mut file.extensions {
        ctx.field(f, base, None, closed, true)?;
    }
    for s in &file.services {
        let sf = apply(base, &s.options, edition, Target::Service, &s.name)?;
        if sf.style2024 {
            check_type_style(&s.name).map_err(|e| format!("{}: {e}", file.name))?;
        }
        for m in &s.methods {
            let mf = apply(sf, &m.options, edition, Target::Method, &m.name)?;
            if mf.style2024 {
                check_type_style(&m.name).map_err(|e| format!("{}: {e}", file.name))?;
            }
        }
    }
    Ok(())
}

/// Whether a symbol declared at `nested` depth with explicit `visibility` is local to its file.
pub(crate) fn is_local(f: Features, visibility: Option<bool>, nested: bool) -> bool {
    match visibility {
        Some(export) => !export,
        None if nested => f.local_nested,
        None => f.local_top,
    }
}

struct Ctx {
    edition: Edition,
    file: String,
}

impl Ctx {
    fn enumeration(&self, e: &mut EnumDef, parent: Features) -> Result<(), String> {
        let f = apply(parent, &e.options, self.edition, Target::Enum, &e.name)?;
        e.closed = f.closed_enums;
        if !e.closed && e.values[0].number != 0 {
            return Err(format!(
                "{}: the first value of open enum {} must be 0",
                self.file, e.name
            ));
        }
        if f.style2024 {
            check_type_style(&e.name).map_err(|m| format!("{}: {m}", self.file))?;
        }
        for v in &e.values {
            let vf = apply(f, &v.options, self.edition, Target::EnumValue, &v.name)?;
            if vf.style2024 && !is_screaming(&v.name) {
                return Err(format!(
                    "{}: enum value {} should be UPPER_SNAKE_CASE (enforce_naming_style)",
                    self.file, v.name
                ));
            }
        }
        Ok(())
    }

    /// Enums first (fields need to know whether an enum is closed).
    fn message_enums(&self, m: &mut MessageDef, parent: Features) -> Result<(), String> {
        let f = apply(parent, &m.options, self.edition, Target::Message, &m.name)?;
        for e in &mut m.enums {
            self.enumeration(e, f)?;
        }
        for n in &mut m.messages {
            self.message_enums(n, f)?;
        }
        Ok(())
    }

    fn message(
        &self,
        m: &mut MessageDef,
        parent: Features,
        closed: &mut dyn FnMut(&str) -> Option<bool>,
    ) -> Result<(), String> {
        let f = apply(parent, &m.options, self.edition, Target::Message, &m.name)?;
        if f.style2024 {
            check_type_style(&m.name).map_err(|e| format!("{}: {e}", self.file))?;
        }
        for r in &m.extension_ranges {
            apply(f, &r.options, self.edition, Target::ExtensionRange, &m.name)?;
        }
        let oneof_features: Vec<Features> = m
            .oneofs
            .iter()
            .map(|o| apply(f, &o.options, self.edition, Target::Oneof, &o.name))
            .collect::<Result<_, _>>()?;
        for (o, of) in m.oneofs.iter().zip(&oneof_features) {
            if of.style2024 && !is_snake(&o.name) {
                return Err(format!(
                    "{}: oneof {} should be snake_case (enforce_naming_style)",
                    self.file, o.name
                ));
            }
        }
        for fl in &mut m.fields {
            let pf = fl.oneof.map_or(f, |i| oneof_features[i]);
            self.field(fl, pf, Some(&m.name), closed, false)?;
        }
        for fl in &mut m.extensions {
            self.field(fl, f, Some(&m.name), closed, true)?;
        }
        for n in &mut m.messages {
            self.message(n, f, closed)?;
        }
        Ok(())
    }

    fn field(
        &self,
        fl: &mut Field,
        parent: Features,
        msg: Option<&str>,
        closed: &mut dyn FnMut(&str) -> Option<bool>,
        extension: bool,
    ) -> Result<(), String> {
        let what = format!("{}:{}: {}", self.file, fl.line, fl.name);
        let f = apply(parent, &fl.options, self.edition, Target::Field, &what)?;
        if f.style2024 && !is_snake(&fl.name) {
            return Err(format!(
                "{what}: field names should be snake_case (enforce_naming_style)"
            ));
        }
        let is_msg = matches!(fl.ty, TypeRef::Message(_)) && fl.map_key.is_none();
        let repeated = fl.label == Label::Repeated;
        let packable = !repeated
            || fl.map_key.is_some()
            || matches!(fl.ty, TypeRef::Enum(_))
            || matches!(fl.ty, TypeRef::Scalar(s) if !s.is_len());
        let opts = &fl.options;
        if self.edition.is_editions() {
            if is_set(opts, "features.field_presence") {
                if repeated {
                    return Err(format!("{what}: repeated fields cannot set field_presence"));
                }
                if fl.oneof.is_some() {
                    return Err(format!("{what}: oneof members cannot set field_presence"));
                }
                if extension {
                    return Err(format!("{what}: extensions cannot set field_presence"));
                }
                if is_msg && f.presence == Presence::Implicit {
                    return Err(format!(
                        "{what}: message fields cannot have implicit presence"
                    ));
                }
            }
            if is_set(opts, "features.repeated_field_encoding")
                && (!repeated || fl.map_key.is_some())
            {
                return Err(format!(
                    "{what}: only repeated fields can set repeated_field_encoding"
                ));
            }
            if is_set(opts, "features.repeated_field_encoding") && f.packed && !packable {
                return Err(format!(
                    "{what}: only repeated primitive fields can be packed"
                ));
            }
            if is_set(opts, "features.message_encoding")
                && (!matches!(fl.ty, TypeRef::Message(_)) || fl.map_key.is_some())
            {
                if fl.map_key.is_some() && !f.delimited {
                    // LENGTH_PREFIXED on a map is the only encoding anyway.
                } else {
                    return Err(format!(
                        "{what}: only message fields can set message_encoding"
                    ));
                }
            }
            if is_set(opts, "features.utf8_validation")
                && !matches!(fl.ty, TypeRef::Scalar(crate::parse::Scalar::String))
                && fl.map_key != Some(crate::parse::Scalar::String)
            {
                return Err(format!(
                    "{what}: only string fields can set utf8_validation"
                ));
            }
        }
        let presence = if repeated {
            Presence::Implicit
        } else if fl.oneof.is_some() || extension || is_msg {
            Presence::Explicit
        } else if self.edition.is_editions() {
            f.presence
        } else {
            match (self.edition, fl.label) {
                (_, Label::Required) => Presence::Required,
                (_, Label::Optional) | (Edition::Proto2, _) => Presence::Explicit,
                _ => Presence::Implicit,
            }
        };
        if presence == Presence::Implicit && fl.default.is_some() && !repeated {
            return Err(format!(
                "{what}: implicit presence fields cannot have defaults"
            ));
        }
        if presence == Presence::Implicit && !repeated {
            if let TypeRef::Enum(e) = &fl.ty {
                if closed(e) == Some(true) {
                    return Err(format!(
                        "{what}: closed enum {} cannot be used by an implicit presence field",
                        &e[1..]
                    ));
                }
            }
        }
        if repeated && fl.default.is_some() {
            return Err(format!("{what}: repeated fields cannot have defaults"));
        }
        let packed = repeated
            && fl.map_key.is_none()
            && packable
            && match fl.packed {
                Some(p) => p,
                None => f.packed,
            };
        let delimited = matches!(fl.ty, TypeRef::Message(_))
            && fl.map_key.is_none()
            && (fl.group || (self.edition.is_editions() && f.delimited));
        fl.resolved = Resolved {
            presence,
            packed,
            delimited,
            verify_utf8: f.verify_utf8,
            utf8_none: !f.verify_utf8 && self.edition.is_editions(),
        };
        let _ = msg;
        Ok(())
    }
}

fn check_package_style(p: &str) -> Result<(), String> {
    if p.is_empty() || p.split('.').all(is_snake) {
        Ok(())
    } else {
        Err(format!(
            "package {p} should be lower_snake_case (enforce_naming_style)"
        ))
    }
}

fn check_type_style(n: &str) -> Result<(), String> {
    let ok = n.starts_with(|c: char| c.is_ascii_uppercase())
        && n.chars().all(|c| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(format!("{n} should be TitleCase (enforce_naming_style)"))
    }
}

fn is_snake(n: &str) -> bool {
    n.starts_with(|c: char| c.is_ascii_lowercase())
        && n.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_screaming(n: &str) -> bool {
    n.starts_with(|c: char| c.is_ascii_uppercase())
        && n.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// The file-level features of `file` (for symbol visibility).
pub(crate) fn file_features(file: &File) -> Result<Features, String> {
    apply(
        Features::defaults(file.edition),
        &file.options,
        file.edition,
        Target::File,
        &file.name,
    )
}
