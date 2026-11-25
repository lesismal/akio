//! Why a module was refused.

use std::fmt;

/// A module refused by [`Module::new`](crate::Module::new): what kind of refusal, where in the
/// bytes, and a short message (the specification's wording where it has one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    offset: usize,
    message: &'static str,
}

/// The kind of an [`Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The bytes are not a WebAssembly binary module: the specification's *malformed*
    /// (a bad header, a truncated section, an unknown opcode ...).
    Malformed,
    /// The module is well formed but does not validate: the specification's *invalid* (a type
    /// mismatch, an unknown index ...).
    Invalid,
    /// The module uses a WebAssembly feature this runtime does not implement (ADR-125, section 2).
    Unsupported(Feature),
    /// The module passes one of the [`ModuleLimits`](crate::ModuleLimits).
    Limit(Limit),
}

/// A WebAssembly feature `akio-wasm` refuses at load (ADR-125, section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Feature {
    /// Fixed-width SIMD (`v128` and the `0xFD` instructions), relaxed SIMD included (its
    /// instructions work on `v128` values, so a module meets SIMD first).
    Simd,
    /// Threads and atomics (shared memories, the `0xFE` instructions).
    Threads,
    /// Exception handling (tags, `try_table`, `throw` ...).
    ExceptionHandling,
    /// Tail calls (`return_call` ...).
    TailCalls,
    /// 64-bit memories and tables (memory64).
    Memory64,
    /// More than one memory (multi-memory).
    MultiMemory,
    /// Extended constant expressions (arithmetic in initializers).
    ExtendedConst,
    /// Typed function references (`call_ref`, `(ref $t)`, non-nullable references ...).
    FunctionReferences,
    /// Garbage collection (structs, arrays, `i31`, recursive and sub types ...).
    Gc,
    /// Component-model binaries.
    ComponentModel,
    /// Custom page sizes.
    CustomPageSizes,
    /// Wide arithmetic (`i64.add128` ...).
    WideArithmetic,
}

/// Which of the [`ModuleLimits`](crate::ModuleLimits) a module passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Limit {
    /// [`ModuleLimits::max_module_bytes`](crate::ModuleLimits::max_module_bytes).
    ModuleBytes,
    /// [`ModuleLimits::max_types`](crate::ModuleLimits::max_types).
    Types,
    /// [`ModuleLimits::max_type_arity`](crate::ModuleLimits::max_type_arity).
    TypeArity,
    /// [`ModuleLimits::max_funcs`](crate::ModuleLimits::max_funcs).
    Funcs,
    /// [`ModuleLimits::max_imports`](crate::ModuleLimits::max_imports).
    Imports,
    /// [`ModuleLimits::max_exports`](crate::ModuleLimits::max_exports).
    Exports,
    /// [`ModuleLimits::max_tables`](crate::ModuleLimits::max_tables).
    Tables,
    /// [`ModuleLimits::max_table_elements`](crate::ModuleLimits::max_table_elements).
    TableElements,
    /// [`ModuleLimits::max_globals`](crate::ModuleLimits::max_globals).
    Globals,
    /// [`ModuleLimits::max_locals`](crate::ModuleLimits::max_locals).
    Locals,
    /// [`ModuleLimits::max_nesting`](crate::ModuleLimits::max_nesting).
    Nesting,
    /// [`ModuleLimits::max_br_table_targets`](crate::ModuleLimits::max_br_table_targets).
    BrTableTargets,
    /// [`ModuleLimits::max_elem_segments`](crate::ModuleLimits::max_elem_segments).
    ElemSegments,
    /// [`ModuleLimits::max_data_segments`](crate::ModuleLimits::max_data_segments).
    DataSegments,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind, offset: usize, message: &'static str) -> Self {
        Self {
            kind,
            offset,
            message,
        }
    }

    /// What kind of refusal this is.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The offset in the module's bytes where it was found.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// A short description: the specification's wording for malformed and invalid modules
    /// (`"type mismatch"`, `"unexpected end"` ...).
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl Feature {
    /// The feature's name, as the WebAssembly proposals call it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Simd => "fixed-width SIMD",
            Self::Threads => "threads and atomics",
            Self::ExceptionHandling => "exception handling",
            Self::TailCalls => "tail calls",
            Self::Memory64 => "64-bit memories and tables",
            Self::MultiMemory => "multiple memories",
            Self::ExtendedConst => "extended constant expressions",
            Self::FunctionReferences => "typed function references",
            Self::Gc => "garbage collection",
            Self::ComponentModel => "the component model",
            Self::CustomPageSizes => "custom page sizes",
            Self::WideArithmetic => "wide arithmetic",
        }
    }
}

impl Limit {
    /// The name of the [`ModuleLimits`](crate::ModuleLimits) field.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::ModuleBytes => "max_module_bytes",
            Self::Types => "max_types",
            Self::TypeArity => "max_type_arity",
            Self::Funcs => "max_funcs",
            Self::Imports => "max_imports",
            Self::Exports => "max_exports",
            Self::Tables => "max_tables",
            Self::TableElements => "max_table_elements",
            Self::Globals => "max_globals",
            Self::Locals => "max_locals",
            Self::Nesting => "max_nesting",
            Self::BrTableTargets => "max_br_table_targets",
            Self::ElemSegments => "max_elem_segments",
            Self::DataSegments => "max_data_segments",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Malformed => write!(f, "malformed module: {}", self.message)?,
            ErrorKind::Invalid => write!(f, "invalid module: {}", self.message)?,
            ErrorKind::Unsupported(feat) => write!(
                f,
                "unsupported WebAssembly feature: {} ({})",
                feat.name(),
                self.message
            )?,
            ErrorKind::Limit(l) => write!(
                f,
                "module over a load limit: {} (ModuleLimits::{})",
                self.message,
                l.field()
            )?,
        }
        write!(f, " at offset {:#x}", self.offset)
    }
}

impl std::error::Error for Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) const fn malformed(offset: usize, message: &'static str) -> Error {
    Error::new(ErrorKind::Malformed, offset, message)
}

pub(crate) const fn invalid(offset: usize, message: &'static str) -> Error {
    Error::new(ErrorKind::Invalid, offset, message)
}

pub(crate) const fn unsupported(offset: usize, feature: Feature, message: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported(feature), offset, message)
}

pub(crate) const fn limit(offset: usize, which: Limit, message: &'static str) -> Error {
    Error::new(ErrorKind::Limit(which), offset, message)
}
