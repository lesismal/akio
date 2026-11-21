//! Runtime reflection: a [`DescriptorPool`] built from encoded `FileDescriptorSet`s (generated
//! code embeds one per package as `FILE_DESCRIPTOR_SET`), descriptors for its files, messages,
//! fields, enums, services and extensions, and [`DynamicMessage`], a message of any type known to
//! the pool.
//!
//! Feature resolution is done when the pool is built: every field knows whether it has explicit
//! presence, is packed, is delimited (a group) and whether its enum is closed, for proto2, proto3
//! and editions 2023 / 2024 files alike.
//!
//! ```
//! use only_protobuf::{Message, reflect::{DescriptorPool, DynamicMessage, Value}, well_known};
//!
//! // The well-known types' own pool.
//! let pool = well_known::descriptor_pool();
//! let ts = pool.get_message_by_name("google.protobuf.Timestamp").unwrap();
//! let bytes = well_known::Timestamp { seconds: 5, nanos: 1 }.encode_to_vec();
//! let m = DynamicMessage::decode(ts.clone(), &bytes).unwrap();
//! assert_eq!(m.get_by_name("seconds").as_deref(), Some(&Value::I64(5)));
//! assert_eq!(m.encode_to_vec(), bytes);
//! ```

mod dynamic;

use std::{collections::HashMap, fmt, sync::Arc};

pub use dynamic::{DynamicMessage, MapKey, Value};

use crate::{
    DecodeError, Message, Name,
    well_known::{
        DescriptorProto, EnumDescriptorProto, FeatureSet, FieldDescriptorProto,
        FileDescriptorProto, FileDescriptorSet, MethodDescriptorProto, ServiceDescriptorProto,
        feature_set, field_descriptor_proto as fdp,
    },
};

/// A generated message with a descriptor (only-protobuf-build implements it when descriptors
/// are on, the default).
pub trait ReflectMessage: Message + Name {
    /// The message's descriptor (in its package's pool).
    fn descriptor() -> MessageDescriptor;

    /// The message as a [`DynamicMessage`].
    fn to_dynamic(&self) -> Result<DynamicMessage, DecodeError> {
        DynamicMessage::decode(Self::descriptor(), &self.encode_to_vec())
    }

    /// The message held by a [`DynamicMessage`] (of this type or a compatible one).
    fn from_dynamic(m: &DynamicMessage) -> Result<Self, DecodeError> {
        Self::decode(&m.encode_to_vec())
    }
}

/// Why descriptors could not be added to a pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorError {
    msg: String,
}

impl DescriptorError {
    fn new(m: impl Into<String>) -> DescriptorError {
        DescriptorError { msg: m.into() }
    }
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid descriptors: {}", self.msg)
    }
}

impl std::error::Error for DescriptorError {}

/// The type of a field's values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `double`.
    Double,
    /// `float`.
    Float,
    /// `int32`.
    Int32,
    /// `int64`.
    Int64,
    /// `uint32`.
    Uint32,
    /// `uint64`.
    Uint64,
    /// `sint32`.
    Sint32,
    /// `sint64`.
    Sint64,
    /// `fixed32`.
    Fixed32,
    /// `fixed64`.
    Fixed64,
    /// `sfixed32`.
    Sfixed32,
    /// `sfixed64`.
    Sfixed64,
    /// `bool`.
    Bool,
    /// `string`.
    String,
    /// `bytes`.
    Bytes,
    /// A message (index into the pool; use [`FieldDescriptor::message_type`]).
    Message(usize),
    /// An enum (use [`FieldDescriptor::enum_type`]).
    Enum(usize),
}

/// Whether a field is singular or repeated (maps are repeated).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cardinality {
    /// At most one value.
    Optional,
    /// proto2 `required` (or `LEGACY_REQUIRED`).
    Required,
    /// Any number of values.
    Repeated,
}

#[derive(Clone, Debug)]
struct FileInfo {
    proto: FileDescriptorProto,
}

#[derive(Clone, Debug)]
struct FieldInfo {
    name: String,
    full_name: String,
    json_name: String,
    number: u32,
    kind: Kind,
    cardinality: Cardinality,
    explicit_presence: bool,
    packed: bool,
    delimited: bool,
    verify_utf8: bool,
    oneof: Option<usize>,
    /// The message holding the field, or, for an extension, the scope declaring it.
    parent: Option<usize>,
    /// For extensions: the extended message.
    extendee: Option<usize>,
    default: Option<String>,
    proto: FieldDescriptorProto,
}

#[derive(Clone, Debug)]
struct OneofInfo {
    name: String,
    fields: Vec<usize>,
    synthetic: bool,
}

#[derive(Clone, Debug)]
struct MessageInfo {
    name: String,
    full_name: String,
    file: usize,
    fields: Vec<FieldInfo>,
    by_number: HashMap<u32, usize>,
    by_name: HashMap<String, usize>,
    by_json: HashMap<String, usize>,
    oneofs: Vec<OneofInfo>,
    map_entry: bool,
    message_set: bool,
    ext_ranges: Vec<(u32, u32)>,
    proto: DescriptorProto,
}

#[derive(Clone, Debug)]
struct EnumInfo {
    name: String,
    full_name: String,
    file: usize,
    values: Vec<(String, i32)>,
    closed: bool,
    proto: EnumDescriptorProto,
}

#[derive(Clone, Debug)]
struct MethodInfo {
    name: String,
    input: usize,
    output: usize,
    proto: MethodDescriptorProto,
}

#[derive(Clone, Debug)]
struct ServiceInfo {
    name: String,
    full_name: String,
    file: usize,
    methods: Vec<MethodInfo>,
    proto: ServiceDescriptorProto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Symbol {
    Message(usize),
    Enum(usize),
    Service(usize),
    Extension(usize),
    /// A package, enum value, field, oneof or method: names that exist but are not looked up.
    Other(usize),
}

#[derive(Clone, Debug, Default)]
struct Inner {
    files: Vec<FileInfo>,
    messages: Vec<MessageInfo>,
    enums: Vec<EnumInfo>,
    services: Vec<ServiceInfo>,
    extensions: Vec<FieldInfo>,
    symbols: HashMap<String, Symbol>,
    file_by_name: HashMap<String, usize>,
    exts_by_extendee: HashMap<usize, Vec<usize>>,
}

/// A set of files' descriptors, cross-referenced. Cheap to clone (shared).
#[derive(Clone, Default)]
pub struct DescriptorPool {
    inner: Arc<Inner>,
}

impl fmt::Debug for DescriptorPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DescriptorPool")
            .field("files", &self.inner.files.len())
            .field("messages", &self.inner.messages.len())
            .finish()
    }
}

impl PartialEq for DescriptorPool {
    fn eq(&self, other: &DescriptorPool) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for DescriptorPool {}

impl DescriptorPool {
    /// An empty pool.
    pub fn new() -> DescriptorPool {
        DescriptorPool::default()
    }

    /// A pool of the files in an encoded `FileDescriptorSet`.
    pub fn decode(file_descriptor_set: &[u8]) -> Result<DescriptorPool, DescriptorError> {
        let mut p = DescriptorPool::new();
        p.add_file_descriptor_set(file_descriptor_set)?;
        Ok(p)
    }

    /// Adds the files of an encoded `FileDescriptorSet` (files already in the pool, by name, are
    /// skipped). A file's imports must be in the pool or come before it in the set.
    pub fn add_file_descriptor_set(&mut self, bytes: &[u8]) -> Result<(), DescriptorError> {
        let set = FileDescriptorSet::decode(bytes)
            .map_err(|e| DescriptorError::new(format!("FileDescriptorSet: {e}")))?;
        self.add_files(set.file)
    }

    /// Adds files (skipping names already present), in dependency order or not.
    pub fn add_files(
        &mut self,
        files: impl IntoIterator<Item = FileDescriptorProto>,
    ) -> Result<(), DescriptorError> {
        let mut pending: Vec<FileDescriptorProto> = files
            .into_iter()
            .filter(|f| {
                !self
                    .inner
                    .file_by_name
                    .contains_key(f.name.as_deref().unwrap_or_default())
            })
            .collect();
        let mut dedup = std::collections::HashSet::new();
        pending.retain(|f| dedup.insert(f.name.clone().unwrap_or_default()));
        if pending.is_empty() {
            return Ok(());
        }
        // Order by dependencies.
        let mut ordered = Vec::new();
        let mut have: std::collections::HashSet<String> =
            self.inner.file_by_name.keys().cloned().collect();
        while !pending.is_empty() {
            let before = pending.len();
            let mut rest = Vec::new();
            for f in pending {
                if f.dependency.iter().all(|d| have.contains(d)) {
                    have.insert(f.name.clone().unwrap_or_default());
                    ordered.push(f);
                } else {
                    rest.push(f);
                }
            }
            if rest.len() == before {
                let missing: Vec<String> = rest
                    .iter()
                    .flat_map(|f| f.dependency.iter())
                    .filter(|d| !have.contains(*d))
                    .cloned()
                    .collect();
                return Err(DescriptorError::new(format!(
                    "missing imports: {}",
                    missing.join(", ")
                )));
            }
            pending = rest;
        }
        let mut inner = (*self.inner).clone();
        let first_file = inner.files.len();
        let first_ext = inner.extensions.len();
        let first_msg = inner.messages.len();
        for f in ordered {
            build::add_file(&mut inner, f)?;
        }
        build::resolve(&mut inner, first_file, first_msg, first_ext)?;
        self.inner = Arc::new(inner);
        Ok(())
    }

    /// The message with this full name (`pkg.Outer.Inner`, no leading dot).
    pub fn get_message_by_name(&self, name: &str) -> Option<MessageDescriptor> {
        match self
            .inner
            .symbols
            .get(name.strip_prefix('.').unwrap_or(name))
        {
            Some(Symbol::Message(i)) => Some(MessageDescriptor {
                pool: self.clone(),
                index: *i,
            }),
            _ => None,
        }
    }

    /// The enum with this full name.
    pub fn get_enum_by_name(&self, name: &str) -> Option<EnumDescriptor> {
        match self
            .inner
            .symbols
            .get(name.strip_prefix('.').unwrap_or(name))
        {
            Some(Symbol::Enum(i)) => Some(EnumDescriptor {
                pool: self.clone(),
                index: *i,
            }),
            _ => None,
        }
    }

    /// The service with this full name.
    pub fn get_service_by_name(&self, name: &str) -> Option<ServiceDescriptor> {
        match self
            .inner
            .symbols
            .get(name.strip_prefix('.').unwrap_or(name))
        {
            Some(Symbol::Service(i)) => Some(ServiceDescriptor {
                pool: self.clone(),
                index: *i,
            }),
            _ => None,
        }
    }

    /// The extension with this full name (`pkg.name` or `pkg.Scope.name`).
    pub fn get_extension_by_name(&self, name: &str) -> Option<FieldDescriptor> {
        match self
            .inner
            .symbols
            .get(name.strip_prefix('.').unwrap_or(name))
        {
            Some(Symbol::Extension(i)) => Some(FieldDescriptor {
                pool: self.clone(),
                loc: FieldLoc::Extension(*i),
            }),
            _ => None,
        }
    }

    /// The file with this name (`dir/x.proto`).
    pub fn get_file_by_name(&self, name: &str) -> Option<FileDescriptor> {
        self.inner.file_by_name.get(name).map(|&i| FileDescriptor {
            pool: self.clone(),
            index: i,
        })
    }

    /// The file declaring a symbol (message, enum, service, extension, field, enum value,
    /// method or package member) with this full name.
    pub fn file_containing_symbol(&self, name: &str) -> Option<FileDescriptor> {
        let name = name.strip_prefix('.').unwrap_or(name);
        let file = match self.inner.symbols.get(name)? {
            Symbol::Message(i) => self.inner.messages[*i].file,
            Symbol::Enum(i) => self.inner.enums[*i].file,
            Symbol::Service(i) => self.inner.services[*i].file,
            Symbol::Extension(i) => self.inner.extensions[*i].file_of(&self.inner),
            Symbol::Other(f) => *f,
        };
        Some(FileDescriptor {
            pool: self.clone(),
            index: file,
        })
    }

    /// Every file, in the order added.
    pub fn files(&self) -> impl Iterator<Item = FileDescriptor> + '_ {
        (0..self.inner.files.len()).map(|i| FileDescriptor {
            pool: self.clone(),
            index: i,
        })
    }

    /// Every service.
    pub fn services(&self) -> impl Iterator<Item = ServiceDescriptor> + '_ {
        (0..self.inner.services.len()).map(|i| ServiceDescriptor {
            pool: self.clone(),
            index: i,
        })
    }

    /// Every message (map entry types included).
    pub fn all_messages(&self) -> impl Iterator<Item = MessageDescriptor> + '_ {
        (0..self.inner.messages.len()).map(|i| MessageDescriptor {
            pool: self.clone(),
            index: i,
        })
    }

    /// The extensions of `message` known to the pool.
    pub fn extensions_of(&self, message: &MessageDescriptor) -> Vec<FieldDescriptor> {
        self.inner
            .exts_by_extendee
            .get(&message.index)
            .map(|v| {
                v.iter()
                    .map(|&i| FieldDescriptor {
                        pool: self.clone(),
                        loc: FieldLoc::Extension(i),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The extension of `message` with field number `number`.
    pub fn get_extension(
        &self,
        message: &MessageDescriptor,
        number: u32,
    ) -> Option<FieldDescriptor> {
        self.inner
            .exts_by_extendee
            .get(&message.index)?
            .iter()
            .find(|&&i| self.inner.extensions[i].number == number)
            .map(|&i| FieldDescriptor {
                pool: self.clone(),
                loc: FieldLoc::Extension(i),
            })
    }

    /// The pool's files as an encoded `FileDescriptorSet` (dependencies first).
    pub fn encode_file_descriptor_set(&self) -> Vec<u8> {
        FileDescriptorSet {
            file: self.inner.files.iter().map(|f| f.proto.clone()).collect(),
            ..Default::default()
        }
        .encode_to_vec()
    }
}

impl FieldInfo {
    fn file_of(&self, inner: &Inner) -> usize {
        match (self.parent, self.extendee) {
            (Some(p), _) => inner.messages[p].file,
            _ => {
                // A top-level extension: its full name's package names the file.
                inner
                    .files
                    .iter()
                    .position(|f| {
                        f.proto.extension.iter().any(|x| {
                            let pkg = f.proto.package.as_deref().unwrap_or_default();
                            let n = x.name.as_deref().unwrap_or_default();
                            if pkg.is_empty() {
                                n == self.full_name
                            } else {
                                format!("{pkg}.{n}") == self.full_name
                            }
                        })
                    })
                    .unwrap_or(0)
            }
        }
    }
}

/// A file in a pool.
#[derive(Clone, Debug)]
pub struct FileDescriptor {
    pool: DescriptorPool,
    index: usize,
}

impl FileDescriptor {
    /// Its name (`dir/x.proto`).
    pub fn name(&self) -> &str {
        self.proto().name.as_deref().unwrap_or_default()
    }

    /// Its package.
    pub fn package(&self) -> &str {
        self.proto().package.as_deref().unwrap_or_default()
    }

    /// Its descriptor.
    pub fn proto(&self) -> &FileDescriptorProto {
        &self.pool.inner.files[self.index].proto
    }

    /// The files it imports.
    pub fn dependencies(&self) -> Vec<FileDescriptor> {
        self.proto()
            .dependency
            .iter()
            .filter_map(|d| self.pool.get_file_by_name(d))
            .collect()
    }

    /// The pool.
    pub fn pool(&self) -> &DescriptorPool {
        &self.pool
    }
}

/// A message type in a pool.
#[derive(Clone)]
pub struct MessageDescriptor {
    pool: DescriptorPool,
    index: usize,
}

impl PartialEq for MessageDescriptor {
    fn eq(&self, o: &MessageDescriptor) -> bool {
        self.index == o.index && self.pool == o.pool
    }
}

impl Eq for MessageDescriptor {}

impl fmt::Debug for MessageDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageDescriptor({})", self.full_name())
    }
}

impl MessageDescriptor {
    fn info(&self) -> &MessageInfo {
        &self.pool.inner.messages[self.index]
    }

    /// The name (`Inner`).
    pub fn name(&self) -> &str {
        &self.info().name
    }

    /// The full name (`pkg.Outer.Inner`).
    pub fn full_name(&self) -> &str {
        &self.info().full_name
    }

    /// The pool.
    pub fn pool(&self) -> &DescriptorPool {
        &self.pool
    }

    /// The file declaring it.
    pub fn file(&self) -> FileDescriptor {
        FileDescriptor {
            pool: self.pool.clone(),
            index: self.info().file,
        }
    }

    /// Its descriptor.
    pub fn proto(&self) -> &DescriptorProto {
        &self.info().proto
    }

    /// The fields, in declaration order.
    pub fn fields(&self) -> impl ExactSizeIterator<Item = FieldDescriptor> + '_ {
        (0..self.info().fields.len()).map(|i| FieldDescriptor {
            pool: self.pool.clone(),
            loc: FieldLoc::Field(self.index, i),
        })
    }

    /// The field with this number.
    pub fn get_field(&self, number: u32) -> Option<FieldDescriptor> {
        self.info()
            .by_number
            .get(&number)
            .map(|&i| FieldDescriptor {
                pool: self.pool.clone(),
                loc: FieldLoc::Field(self.index, i),
            })
    }

    /// The field with this name.
    pub fn get_field_by_name(&self, name: &str) -> Option<FieldDescriptor> {
        self.info().by_name.get(name).map(|&i| FieldDescriptor {
            pool: self.pool.clone(),
            loc: FieldLoc::Field(self.index, i),
        })
    }

    /// The field with this JSON name.
    pub fn get_field_by_json_name(&self, name: &str) -> Option<FieldDescriptor> {
        self.info().by_json.get(name).map(|&i| FieldDescriptor {
            pool: self.pool.clone(),
            loc: FieldLoc::Field(self.index, i),
        })
    }

    /// The oneofs' names and fields (synthetic ones of proto3 `optional` included; see
    /// [`FieldDescriptor::containing_oneof`]).
    pub fn oneofs(&self) -> Vec<(String, Vec<FieldDescriptor>)> {
        self.info()
            .oneofs
            .iter()
            .map(|o| {
                (
                    o.name.clone(),
                    o.fields
                        .iter()
                        .map(|&i| FieldDescriptor {
                            pool: self.pool.clone(),
                            loc: FieldLoc::Field(self.index, i),
                        })
                        .collect(),
                )
            })
            .collect()
    }

    /// Whether it is the entry type of a map field.
    pub fn is_map_entry(&self) -> bool {
        self.info().map_entry
    }

    /// Whether it uses the MessageSet wire format.
    pub fn is_message_set(&self) -> bool {
        self.info().message_set
    }

    /// The extension ranges (`start ..= end`).
    pub fn extension_ranges(&self) -> &[(u32, u32)] {
        &self.info().ext_ranges
    }

    /// The extensions of this message known to the pool.
    pub fn extensions(&self) -> Vec<FieldDescriptor> {
        self.pool.extensions_of(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FieldLoc {
    Field(usize, usize),
    Extension(usize),
}

/// A field (or an extension) in a pool.
#[derive(Clone)]
pub struct FieldDescriptor {
    pool: DescriptorPool,
    loc: FieldLoc,
}

impl PartialEq for FieldDescriptor {
    fn eq(&self, o: &FieldDescriptor) -> bool {
        self.loc == o.loc && self.pool == o.pool
    }
}

impl Eq for FieldDescriptor {}

impl fmt::Debug for FieldDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FieldDescriptor({} = {})",
            self.full_name(),
            self.number()
        )
    }
}

impl FieldDescriptor {
    fn info(&self) -> &FieldInfo {
        match self.loc {
            FieldLoc::Field(m, i) => &self.pool.inner.messages[m].fields[i],
            FieldLoc::Extension(i) => &self.pool.inner.extensions[i],
        }
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.info().name
    }

    /// The full name (`pkg.Message.field`, or the extension's).
    pub fn full_name(&self) -> &str {
        &self.info().full_name
    }

    /// The JSON name (`json_name`, or the lowerCamelCase default).
    pub fn json_name(&self) -> &str {
        &self.info().json_name
    }

    /// The field number.
    pub fn number(&self) -> u32 {
        self.info().number
    }

    /// The value type.
    pub fn kind(&self) -> Kind {
        self.info().kind
    }

    /// Singular, required or repeated.
    pub fn cardinality(&self) -> Cardinality {
        self.info().cardinality
    }

    /// Whether it is repeated (maps included).
    pub fn is_list(&self) -> bool {
        self.info().cardinality == Cardinality::Repeated && !self.is_map()
    }

    /// Whether it is a map.
    pub fn is_map(&self) -> bool {
        match self.info().kind {
            Kind::Message(m) => {
                self.info().cardinality == Cardinality::Repeated
                    && self.pool.inner.messages[m].map_entry
            }
            _ => false,
        }
    }

    /// Whether presence is tracked (proto2 `optional`, proto3 `optional`, messages, oneof
    /// members, extensions, editions `EXPLICIT`).
    pub fn has_presence(&self) -> bool {
        self.info().explicit_presence
    }

    /// Whether repeated values are written packed.
    pub fn is_packed(&self) -> bool {
        self.info().packed
    }

    /// Whether a message value is written as a group.
    pub fn is_group(&self) -> bool {
        self.info().delimited
    }

    /// Whether string values must be UTF-8: false for `features.utf8_validation = NONE` and for
    /// proto2 strings. Such a field accepts any bytes when decoding; a [`DynamicMessage`] holds
    /// contents that are not UTF-8 as [`Value::Bytes`], and generated code
    /// types it as [`ProtoString`](crate::ProtoString) (proto2: when asked for).
    pub fn requires_utf8(&self) -> bool {
        self.info().verify_utf8
    }

    /// Whether it is an extension.
    pub fn is_extension(&self) -> bool {
        matches!(self.loc, FieldLoc::Extension(_))
    }

    /// The message it belongs to (for an extension: the extended message).
    pub fn containing_message(&self) -> MessageDescriptor {
        let index = match self.loc {
            FieldLoc::Field(m, _) => m,
            FieldLoc::Extension(_) => self.info().extendee.unwrap_or(0),
        };
        MessageDescriptor {
            pool: self.pool.clone(),
            index,
        }
    }

    /// The oneof it is a member of: its name, and whether it is a proto3 `optional`'s synthetic
    /// one.
    pub fn containing_oneof(&self) -> Option<(String, bool)> {
        let (FieldLoc::Field(m, _), Some(o)) = (self.loc, self.info().oneof) else {
            return None;
        };
        let o = &self.pool.inner.messages[m].oneofs[o];
        Some((o.name.clone(), o.synthetic))
    }

    /// The other members of its (real) oneof, itself included.
    pub(crate) fn oneof_siblings(&self) -> Vec<u32> {
        let (FieldLoc::Field(m, _), Some(o)) = (self.loc, self.info().oneof) else {
            return Vec::new();
        };
        let msg = &self.pool.inner.messages[m];
        msg.oneofs[o]
            .fields
            .iter()
            .map(|&i| msg.fields[i].number)
            .collect()
    }

    /// The message type of a message (or group, or map) field.
    pub fn message_type(&self) -> Option<MessageDescriptor> {
        match self.info().kind {
            Kind::Message(i) => Some(MessageDescriptor {
                pool: self.pool.clone(),
                index: i,
            }),
            _ => None,
        }
    }

    /// The enum type of an enum field.
    pub fn enum_type(&self) -> Option<EnumDescriptor> {
        match self.info().kind {
            Kind::Enum(i) => Some(EnumDescriptor {
                pool: self.pool.clone(),
                index: i,
            }),
            _ => None,
        }
    }

    /// For a map field: its key and value fields.
    pub fn map_entry_fields(&self) -> Option<(FieldDescriptor, FieldDescriptor)> {
        if !self.is_map() {
            return None;
        }
        let m = self.message_type()?;
        Some((m.get_field(1)?, m.get_field(2)?))
    }

    /// The declared `[default = ...]`, as written in the descriptor.
    pub fn default_value_text(&self) -> Option<&str> {
        self.info().default.as_deref()
    }

    /// The value of an unset singular field (the declared default, or the type's).
    pub fn default_value(&self) -> Value {
        dynamic::default_value(self)
    }

    /// Its descriptor.
    pub fn proto(&self) -> &FieldDescriptorProto {
        &self.info().proto
    }

    /// The pool.
    pub fn pool(&self) -> &DescriptorPool {
        &self.pool
    }
}

/// An enum type in a pool.
#[derive(Clone)]
pub struct EnumDescriptor {
    pool: DescriptorPool,
    index: usize,
}

impl PartialEq for EnumDescriptor {
    fn eq(&self, o: &EnumDescriptor) -> bool {
        self.index == o.index && self.pool == o.pool
    }
}

impl Eq for EnumDescriptor {}

impl fmt::Debug for EnumDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnumDescriptor({})", self.full_name())
    }
}

impl EnumDescriptor {
    fn info(&self) -> &EnumInfo {
        &self.pool.inner.enums[self.index]
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.info().name
    }

    /// The full name.
    pub fn full_name(&self) -> &str {
        &self.info().full_name
    }

    /// The values: names and numbers, in declaration order (aliases included).
    pub fn values(&self) -> &[(String, i32)] {
        &self.info().values
    }

    /// The name of `number` (the first declared, with aliases).
    pub fn value_name(&self, number: i32) -> Option<&str> {
        self.info()
            .values
            .iter()
            .find(|(_, n)| *n == number)
            .map(|(s, _)| s.as_str())
    }

    /// The number of the value named `name`.
    pub fn value_number(&self, name: &str) -> Option<i32> {
        self.info()
            .values
            .iter()
            .find(|(s, _)| s == name)
            .map(|(_, n)| *n)
    }

    /// Whether it is closed (unknown numbers are not stored in fields of this type).
    pub fn is_closed(&self) -> bool {
        self.info().closed
    }

    /// The default value (the first declared).
    pub fn default_number(&self) -> i32 {
        self.info().values.first().map_or(0, |v| v.1)
    }

    /// Its descriptor.
    pub fn proto(&self) -> &EnumDescriptorProto {
        &self.info().proto
    }

    /// The file declaring it.
    pub fn file(&self) -> FileDescriptor {
        FileDescriptor {
            pool: self.pool.clone(),
            index: self.info().file,
        }
    }
}

/// A service in a pool.
#[derive(Clone, Debug)]
pub struct ServiceDescriptor {
    pool: DescriptorPool,
    index: usize,
}

impl ServiceDescriptor {
    fn info(&self) -> &ServiceInfo {
        &self.pool.inner.services[self.index]
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.info().name
    }

    /// The full name (`pkg.Service`).
    pub fn full_name(&self) -> &str {
        &self.info().full_name
    }

    /// The file declaring it.
    pub fn file(&self) -> FileDescriptor {
        FileDescriptor {
            pool: self.pool.clone(),
            index: self.info().file,
        }
    }

    /// The methods.
    pub fn methods(&self) -> impl ExactSizeIterator<Item = MethodDescriptor> + '_ {
        (0..self.info().methods.len()).map(|i| MethodDescriptor {
            service: self.clone(),
            index: i,
        })
    }

    /// Its descriptor.
    pub fn proto(&self) -> &ServiceDescriptorProto {
        &self.info().proto
    }
}

/// A method of a service.
#[derive(Clone, Debug)]
pub struct MethodDescriptor {
    service: ServiceDescriptor,
    index: usize,
}

impl MethodDescriptor {
    fn info(&self) -> &MethodInfo {
        &self.service.info().methods[self.index]
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.info().name
    }

    /// The gRPC path: `/pkg.Service/Method`.
    pub fn path(&self) -> String {
        format!("/{}/{}", self.service.full_name(), self.name())
    }

    /// The request type.
    pub fn input(&self) -> MessageDescriptor {
        MessageDescriptor {
            pool: self.service.pool.clone(),
            index: self.info().input,
        }
    }

    /// The response type.
    pub fn output(&self) -> MessageDescriptor {
        MessageDescriptor {
            pool: self.service.pool.clone(),
            index: self.info().output,
        }
    }

    /// Whether the client streams.
    pub fn is_client_streaming(&self) -> bool {
        self.info().proto.client_streaming == Some(true)
    }

    /// Whether the server streams.
    pub fn is_server_streaming(&self) -> bool {
        self.info().proto.server_streaming == Some(true)
    }
}

/// Resolved features (the subset that changes encoding and decoding).
#[derive(Clone, Copy, Debug)]
struct Features {
    explicit: bool,
    required: bool,
    closed: bool,
    packed: bool,
    utf8: bool,
    delimited: bool,
}

impl Features {
    fn for_file(f: &FileDescriptorProto) -> Result<Features, DescriptorError> {
        let base = match f.syntax.as_deref() {
            None | Some("" | "proto2") => Features {
                explicit: true,
                required: false,
                closed: true,
                packed: false,
                utf8: false,
                delimited: false,
            },
            Some("proto3") => Features {
                explicit: false,
                required: false,
                closed: false,
                packed: true,
                utf8: true,
                delimited: false,
            },
            Some("editions") => match f.edition.map(|e| e.0) {
                Some(1000 | 1001) => Features {
                    explicit: true,
                    required: false,
                    closed: false,
                    packed: true,
                    utf8: true,
                    delimited: false,
                },
                e => {
                    return Err(DescriptorError::new(format!(
                        "{}: unsupported edition {e:?}",
                        f.name.as_deref().unwrap_or_default()
                    )));
                }
            },
            Some(s) => {
                return Err(DescriptorError::new(format!("unknown syntax {s:?}")));
            }
        };
        Ok(base.apply(f.options.as_ref().and_then(|o| o.features.as_ref())))
    }

    fn apply(mut self, fs: Option<&FeatureSet>) -> Features {
        let Some(fs) = fs else { return self };
        if let Some(p) = fs.field_presence {
            match p {
                feature_set::FieldPresence::EXPLICIT => {
                    (self.explicit, self.required) = (true, false);
                }
                feature_set::FieldPresence::IMPLICIT => {
                    (self.explicit, self.required) = (false, false);
                }
                feature_set::FieldPresence::LEGACY_REQUIRED => {
                    (self.explicit, self.required) = (true, true);
                }
                _ => {}
            }
        }
        if let Some(e) = fs.enum_type {
            self.closed = e == feature_set::EnumType::CLOSED;
        }
        if let Some(r) = fs.repeated_field_encoding {
            self.packed = r == feature_set::RepeatedFieldEncoding::PACKED;
        }
        if let Some(u) = fs.utf8_validation {
            self.utf8 = u == feature_set::Utf8Validation::VERIFY;
        }
        if let Some(m) = fs.message_encoding {
            self.delimited = m == feature_set::MessageEncoding::DELIMITED;
        }
        self
    }
}

mod build {
    //! Pool construction: indexing, then name resolution and feature resolution.

    use super::*;

    fn err<T>(m: impl Into<String>) -> Result<T, DescriptorError> {
        Err(DescriptorError::new(m))
    }

    fn join(scope: &str, name: &str) -> String {
        if scope.is_empty() {
            name.to_owned()
        } else {
            format!("{scope}.{name}")
        }
    }

    fn add_symbol(inner: &mut Inner, name: String, s: Symbol) -> Result<(), DescriptorError> {
        if let Some(prev) = inner.symbols.get(&name) {
            // Packages may be declared by many files.
            if matches!((prev, s), (Symbol::Other(_), Symbol::Other(_))) {
                return Ok(());
            }
            return err(format!("{name} is defined twice"));
        }
        inner.symbols.insert(name, s);
        Ok(())
    }

    /// Indexes one file (types resolved later).
    pub(super) fn add_file(
        inner: &mut Inner,
        f: FileDescriptorProto,
    ) -> Result<(), DescriptorError> {
        let fi = inner.files.len();
        let name = f.name.clone().unwrap_or_default();
        let pkg = f.package.clone().unwrap_or_default();
        let features = Features::for_file(&f)?;
        if !pkg.is_empty() {
            let mut p = String::new();
            for part in pkg.split('.') {
                p = join(&p, part);
                add_symbol(inner, p.clone(), Symbol::Other(fi))?;
            }
        }
        inner.file_by_name.insert(name, fi);
        let syntax3 = f.syntax.as_deref() == Some("proto3");
        let proto2 = matches!(f.syntax.as_deref(), None | Some("" | "proto2"));
        let ctx = Ctx {
            file: fi,
            syntax3,
            proto2,
        };
        for m in &f.message_type {
            ctx.message(inner, m, &pkg, features)?;
        }
        for e in &f.enum_type {
            ctx.enumeration(inner, e, &pkg, features)?;
        }
        for x in &f.extension {
            ctx.extension(inner, x, &pkg, None, features)?;
        }
        for s in &f.service {
            let full = join(&pkg, s.name.as_deref().unwrap_or_default());
            let si = inner.services.len();
            add_symbol(inner, full.clone(), Symbol::Service(si))?;
            for m in &s.method {
                add_symbol(
                    inner,
                    join(&full, m.name.as_deref().unwrap_or_default()),
                    Symbol::Other(fi),
                )?;
            }
            inner.services.push(ServiceInfo {
                name: s.name.clone().unwrap_or_default(),
                full_name: full,
                file: fi,
                methods: s
                    .method
                    .iter()
                    .map(|m| MethodInfo {
                        name: m.name.clone().unwrap_or_default(),
                        input: usize::MAX,
                        output: usize::MAX,
                        proto: m.clone(),
                    })
                    .collect(),
                proto: s.clone(),
            });
        }
        inner.files.push(FileInfo { proto: f });
        Ok(())
    }

    struct Ctx {
        file: usize,
        syntax3: bool,
        proto2: bool,
    }

    impl Ctx {
        fn message(
            &self,
            inner: &mut Inner,
            m: &DescriptorProto,
            scope: &str,
            parent: Features,
        ) -> Result<(), DescriptorError> {
            let name = m.name.clone().unwrap_or_default();
            let full = join(scope, &name);
            let mi = inner.messages.len();
            add_symbol(inner, full.clone(), Symbol::Message(mi))?;
            let opts = m.options.as_ref();
            let features = parent.apply(opts.and_then(|o| o.features.as_ref()));
            let map_entry = opts.and_then(|o| o.map_entry) == Some(true);
            let message_set = opts.and_then(|o| o.message_set_wire_format) == Some(true);
            inner.messages.push(MessageInfo {
                name,
                full_name: full.clone(),
                file: self.file,
                fields: Vec::new(),
                by_number: HashMap::new(),
                by_name: HashMap::new(),
                by_json: HashMap::new(),
                oneofs: m
                    .oneof_decl
                    .iter()
                    .map(|o| OneofInfo {
                        name: o.name.clone().unwrap_or_default(),
                        fields: Vec::new(),
                        synthetic: false,
                    })
                    .collect(),
                map_entry,
                message_set,
                ext_ranges: m
                    .extension_range
                    .iter()
                    .map(|r| {
                        (
                            r.start.unwrap_or(0).max(0) as u32,
                            (r.end.unwrap_or(0) - 1).max(0) as u32,
                        )
                    })
                    .collect(),
                proto: m.clone(),
            });
            let mut fields = Vec::new();
            for f in &m.field {
                let fi = self.field(f, &full, Some(mi), features, map_entry)?;
                fields.push(fi);
            }
            for (i, f) in fields.iter().enumerate() {
                add_symbol(inner, f.full_name.clone(), Symbol::Other(self.file))?;
                let msg = &mut inner.messages[mi];
                if msg.by_number.insert(f.number, i).is_some() {
                    return err(format!("{full}: field number {} used twice", f.number));
                }
                msg.by_name.insert(f.name.clone(), i);
                msg.by_json.insert(f.json_name.clone(), i);
                if let Some(o) = f.oneof {
                    let Some(od) = msg.oneofs.get_mut(o) else {
                        return err(format!("{full}.{}: bad oneof_index", f.name));
                    };
                    od.fields.push(i);
                    if f.proto.proto3_optional == Some(true) {
                        od.synthetic = true;
                    }
                }
            }
            inner.messages[mi].fields = fields;
            for o in &m.oneof_decl {
                add_symbol(
                    inner,
                    join(&full, o.name.as_deref().unwrap_or_default()),
                    Symbol::Other(self.file),
                )?;
            }
            for n in &m.nested_type {
                self.message(inner, n, &full, features)?;
            }
            for e in &m.enum_type {
                self.enumeration(inner, e, &full, features)?;
            }
            for x in &m.extension {
                self.extension(inner, x, &full, Some(mi), features)?;
            }
            Ok(())
        }

        fn field(
            &self,
            f: &FieldDescriptorProto,
            scope: &str,
            parent: Option<usize>,
            msg_features: Features,
            map_entry: bool,
        ) -> Result<FieldInfo, DescriptorError> {
            let name = f.name.clone().unwrap_or_default();
            let ft = msg_features.apply(f.options.as_ref().and_then(|o| o.features.as_ref()));
            let ty = f.r#type.unwrap_or_default();
            let kind = match ty {
                fdp::Type::DOUBLE => Kind::Double,
                fdp::Type::FLOAT => Kind::Float,
                fdp::Type::INT64 => Kind::Int64,
                fdp::Type::UINT64 => Kind::Uint64,
                fdp::Type::INT32 => Kind::Int32,
                fdp::Type::FIXED64 => Kind::Fixed64,
                fdp::Type::FIXED32 => Kind::Fixed32,
                fdp::Type::BOOL => Kind::Bool,
                fdp::Type::STRING => Kind::String,
                fdp::Type::BYTES => Kind::Bytes,
                fdp::Type::UINT32 => Kind::Uint32,
                fdp::Type::SFIXED32 => Kind::Sfixed32,
                fdp::Type::SFIXED64 => Kind::Sfixed64,
                fdp::Type::SINT32 => Kind::Sint32,
                fdp::Type::SINT64 => Kind::Sint64,
                // Resolved later (the type name may name a message or an enum).
                fdp::Type::GROUP | fdp::Type::MESSAGE | fdp::Type::ENUM | fdp::Type(0) => {
                    Kind::Message(usize::MAX)
                }
                t => return err(format!("{scope}.{name}: unknown type {}", t.0)),
            };
            let label = f.label.unwrap_or(fdp::Label::OPTIONAL);
            let repeated = label == fdp::Label::REPEATED;
            if f.oneof_index.is_some() && (repeated || label == fdp::Label::REQUIRED) {
                return err(format!("{scope}.{name}: oneof members must be singular"));
            }
            if f.proto3_optional == Some(true) && f.oneof_index.is_none() {
                return err(format!("{scope}.{name}: proto3_optional without a oneof"));
            }
            let is_msg_type = matches!(ty, fdp::Type::GROUP | fdp::Type::MESSAGE);
            let required = label == fdp::Label::REQUIRED || (!repeated && ft.required);
            let explicit = !repeated
                && (f.oneof_index.is_some()
                    || f.extendee.is_some()
                    || is_msg_type
                    || required
                    || f.proto3_optional == Some(true)
                    || (!self.syntax3 && ft.explicit && !map_entry));
            let packable = !matches!(
                ty,
                fdp::Type::STRING | fdp::Type::BYTES | fdp::Type::GROUP | fdp::Type::MESSAGE
            );
            let packed = repeated
                && packable
                && match f.options.as_ref().and_then(|o| o.packed) {
                    Some(p) if self.proto2 || self.syntax3 => p,
                    _ => ft.packed,
                };
            let delimited = ty == fdp::Type::GROUP
                || (ty == fdp::Type::MESSAGE
                    && ft.delimited
                    && !self.proto2
                    && !self.syntax3
                    && !map_entry);
            let json_name = f.json_name.clone().unwrap_or_else(|| json_name(&name));
            Ok(FieldInfo {
                full_name: join(scope, &name),
                name,
                json_name,
                number: f.number.unwrap_or(0).max(0) as u32,
                kind,
                cardinality: if repeated {
                    Cardinality::Repeated
                } else if required {
                    Cardinality::Required
                } else {
                    Cardinality::Optional
                },
                explicit_presence: explicit,
                packed,
                delimited,
                verify_utf8: ft.utf8,
                oneof: f.oneof_index.map(|i| i.max(0) as usize),
                parent,
                extendee: None,
                default: f.default_value.clone(),
                proto: f.clone(),
            })
        }

        fn enumeration(
            &self,
            inner: &mut Inner,
            e: &EnumDescriptorProto,
            scope: &str,
            parent: Features,
        ) -> Result<(), DescriptorError> {
            let name = e.name.clone().unwrap_or_default();
            let full = join(scope, &name);
            let ei = inner.enums.len();
            add_symbol(inner, full.clone(), Symbol::Enum(ei))?;
            let ft = parent.apply(e.options.as_ref().and_then(|o| o.features.as_ref()));
            for v in &e.value {
                // Enum values are siblings of their enum.
                let vn = join(scope, v.name.as_deref().unwrap_or_default());
                inner.symbols.entry(vn).or_insert(Symbol::Other(self.file));
            }
            inner.enums.push(EnumInfo {
                name,
                full_name: full,
                file: self.file,
                values: e
                    .value
                    .iter()
                    .map(|v| (v.name.clone().unwrap_or_default(), v.number.unwrap_or(0)))
                    .collect(),
                closed: ft.closed,
                proto: e.clone(),
            });
            Ok(())
        }

        fn extension(
            &self,
            inner: &mut Inner,
            x: &FieldDescriptorProto,
            scope: &str,
            parent: Option<usize>,
            features: Features,
        ) -> Result<(), DescriptorError> {
            let fi = self.field(x, scope, parent, features, false)?;
            let i = inner.extensions.len();
            add_symbol(inner, fi.full_name.clone(), Symbol::Extension(i))?;
            inner.extensions.push(fi);
            Ok(())
        }
    }

    /// Resolves type names (from `first_*` on: what was just added).
    pub(super) fn resolve(
        inner: &mut Inner,
        first_file: usize,
        first_msg: usize,
        first_ext: usize,
    ) -> Result<(), DescriptorError> {
        let symbols = inner.symbols.clone();
        let lookup = |name: &str| -> Result<Kind, DescriptorError> {
            match symbols.get(name.strip_prefix('.').unwrap_or(name)) {
                Some(Symbol::Message(i)) => Ok(Kind::Message(*i)),
                Some(Symbol::Enum(i)) => Ok(Kind::Enum(*i)),
                _ => err(format!("unknown type {name}")),
            }
        };
        let map_entries: Vec<bool> = inner.messages.iter().map(|m| m.map_entry).collect();
        let resolve_field = |f: &mut FieldInfo| -> Result<(), DescriptorError> {
            if f.kind == Kind::Message(usize::MAX) {
                let tn = f.proto.type_name.clone().unwrap_or_default();
                f.kind = lookup(&tn)
                    .map_err(|e| DescriptorError::new(format!("{}: {}", f.full_name, e.msg)))?;
                match f.kind {
                    Kind::Enum(_)
                        if f.proto.r#type != Some(fdp::Type::ENUM) && f.proto.r#type.is_some() =>
                    {
                        return err(format!("{}: {tn} is not a message", f.full_name));
                    }
                    Kind::Message(_) if f.proto.r#type == Some(fdp::Type::ENUM) => {
                        return err(format!("{}: {tn} is not an enum", f.full_name));
                    }
                    // Maps are always length-prefixed.
                    Kind::Message(m) if map_entries[m] => f.delimited = false,
                    _ => {}
                }
            }
            Ok(())
        };
        for m in &mut inner.messages[first_msg..] {
            for f in &mut m.fields {
                resolve_field(f)?;
            }
        }
        for x in &mut inner.extensions[first_ext..] {
            resolve_field(x)?;
            let e = x.proto.extendee.clone().unwrap_or_default();
            match lookup(&e)? {
                Kind::Message(i) => x.extendee = Some(i),
                _ => return err(format!("{}: {e} is not a message", x.full_name)),
            }
        }
        for i in first_ext..inner.extensions.len() {
            if let Some(e) = inner.extensions[i].extendee {
                inner.exts_by_extendee.entry(e).or_default().push(i);
            }
        }
        for s in &mut inner.services {
            for m in &mut s.methods {
                if m.input != usize::MAX {
                    continue;
                }
                let i = m.proto.input_type.clone().unwrap_or_default();
                let o = m.proto.output_type.clone().unwrap_or_default();
                match (lookup(&i)?, lookup(&o)?) {
                    (Kind::Message(a), Kind::Message(b)) => (m.input, m.output) = (a, b),
                    _ => {
                        return err(format!(
                            "{}.{}: input and output must be messages",
                            s.full_name, m.name
                        ));
                    }
                }
            }
        }
        let _ = first_file;
        Ok(())
    }
}

/// protoc's default JSON name: underscores dropped, the letter after one capitalized.
pub(crate) fn json_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut up = false;
    for c in name.chars() {
        if c == '_' {
            up = true;
        } else if up {
            out.push(c.to_ascii_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}
