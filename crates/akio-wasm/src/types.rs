//! WebAssembly types: values, functions, tables, memories, globals.

use std::{fmt, sync::Arc};

use crate::{
    error::{Feature, Result, malformed, unsupported},
    reader::Reader,
};

/// A value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValType {
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
    /// 32-bit float.
    F32,
    /// 64-bit float.
    F64,
    /// A nullable reference to a function.
    FuncRef,
    /// A nullable reference to a host value.
    ExternRef,
}

/// A reference type: what a table holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    /// `funcref`.
    FuncRef,
    /// `externref`.
    ExternRef,
}

impl ValType {
    /// Whether this is a reference type.
    #[must_use]
    pub const fn is_ref(self) -> bool {
        matches!(self, Self::FuncRef | Self::ExternRef)
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let at = r.offset();
        decode_valtype(r.u8()?, at)
    }
}

impl From<RefType> for ValType {
    fn from(t: RefType) -> Self {
        match t {
            RefType::FuncRef => Self::FuncRef,
            RefType::ExternRef => Self::ExternRef,
        }
    }
}

impl RefType {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let at = r.offset();
        match decode_valtype(r.u8()?, at)? {
            ValType::FuncRef => Ok(Self::FuncRef),
            ValType::ExternRef => Ok(Self::ExternRef),
            _ => Err(malformed(at, "malformed reference type")),
        }
    }
}

/// A value type from its byte; the bytes of refused features are named.
pub(crate) fn decode_valtype(b: u8, at: usize) -> Result<ValType> {
    match b {
        0x7f => Ok(ValType::I32),
        0x7e => Ok(ValType::I64),
        0x7d => Ok(ValType::F32),
        0x7c => Ok(ValType::F64),
        0x70 => Ok(ValType::FuncRef),
        0x6f => Ok(ValType::ExternRef),
        0x7b => Err(unsupported(at, Feature::Simd, "v128 value type")),
        0x64 | 0x63 => Err(unsupported(
            at,
            Feature::FunctionReferences,
            "typed reference type",
        )),
        0x69 | 0x74 => Err(unsupported(
            at,
            Feature::ExceptionHandling,
            "exnref value type",
        )),
        0x6a..=0x6e | 0x71..=0x73 => Err(unsupported(at, Feature::Gc, "GC reference type")),
        _ => Err(malformed(at, "malformed value type")),
    }
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::FuncRef => "funcref",
            Self::ExternRef => "externref",
        })
    }
}

/// A function type: parameters and results. Cheap to clone (shared).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FuncType {
    /// Parameters then results.
    types: Arc<[ValType]>,
    params: usize,
}

impl FuncType {
    /// A function type from its parameters and results.
    #[must_use]
    pub fn new(params: &[ValType], results: &[ValType]) -> Self {
        let types: Arc<[ValType]> = params.iter().chain(results).copied().collect();
        Self {
            types,
            params: params.len(),
        }
    }

    /// The parameters.
    #[must_use]
    pub fn params(&self) -> &[ValType] {
        &self.types[..self.params]
    }

    /// The results.
    #[must_use]
    pub fn results(&self) -> &[ValType] {
        &self.types[self.params..]
    }
}

impl fmt::Debug for FuncType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for FuncType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(func")?;
        if !self.params().is_empty() {
            f.write_str(" (param")?;
            for t in self.params() {
                write!(f, " {t}")?;
            }
            f.write_str(")")?;
        }
        if !self.results().is_empty() {
            f.write_str(" (result")?;
            for t in self.results() {
                write!(f, " {t}")?;
            }
            f.write_str(")")?;
        }
        f.write_str(")")
    }
}

/// Size limits of a table (in elements) or a memory (in 64 KiB pages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Limits {
    /// The initial size.
    pub min: u32,
    /// The maximum size, if declared.
    pub max: Option<u32>,
}

impl Limits {
    /// The limits' flags byte and values; `memory` tells which feature a flag would need.
    pub(crate) fn read(r: &mut Reader<'_>, memory: bool) -> Result<Self> {
        let at = r.offset();
        let flags = r.u8()?;
        let has_max = match flags {
            0x00 => false,
            0x01 => true,
            0x02 | 0x03 if memory => {
                return Err(unsupported(at, Feature::Threads, "shared memory"));
            }
            0x04..=0x07 => {
                return Err(unsupported(
                    at,
                    Feature::Memory64,
                    if memory {
                        "64-bit memory"
                    } else {
                        "64-bit table"
                    },
                ));
            }
            0x08..=0x0f if memory => {
                return Err(unsupported(
                    at,
                    Feature::CustomPageSizes,
                    "memory page size",
                ));
            }
            _ => return Err(malformed(at, "integer too large")),
        };
        let min = r.u32()?;
        let max = if has_max { Some(r.u32()?) } else { None };
        Ok(Self { min, max })
    }
}

/// A table's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TableType {
    /// What it holds.
    pub elem: RefType,
    /// Its size in elements.
    pub limits: Limits,
}

/// A memory's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryType {
    /// Its size in 64 KiB pages.
    pub limits: Limits,
}

/// A global's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GlobalType {
    /// The type of its value.
    pub val: ValType,
    /// Whether `global.set` may change it.
    pub mutable: bool,
}

impl GlobalType {
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let val = ValType::read(r)?;
        let at = r.offset();
        let mutable = match r.u8()? {
            0 => false,
            1 => true,
            2 | 3 => return Err(unsupported(at, Feature::Threads, "shared global")),
            _ => return Err(malformed(at, "malformed mutability")),
        };
        Ok(Self { val, mutable })
    }
}

/// The type of an import or an export.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExternType {
    /// A function.
    Func(FuncType),
    /// A table.
    Table(TableType),
    /// A memory.
    Memory(MemoryType),
    /// A global.
    Global(GlobalType),
}

/// One of the module's imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The module name (`"wasi_snapshot_preview1"`, `"env"` ...).
    pub module: Box<str>,
    /// The name within it.
    pub name: Box<str>,
    /// What is imported.
    pub ty: ExternType,
}

/// What an export refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportKind {
    /// A function.
    Func,
    /// A table.
    Table,
    /// A memory.
    Memory,
    /// A global.
    Global,
}

/// One of the module's exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// Its name, unique in the module.
    pub name: Box<str>,
    /// What it refers to.
    pub kind: ExportKind,
    /// The index in the module's space of that kind (imports first).
    pub index: u32,
}
