//! Values, and handles to what a store holds.

use crate::types::ValType;

/// A WebAssembly value, as a call's argument or result or a global's value.
///
/// Floats are kept as Rust's `f32` and `f64`, whose bits (a NaN's payload included) pass through
/// unchanged; compare them with `to_bits` when a NaN may be involved.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /// An `i32` (unsigned values as their two's complement).
    I32(i32),
    /// An `i64`.
    I64(i64),
    /// An `f32`.
    F32(f32),
    /// An `f64`.
    F64(f64),
    /// A function reference, or null.
    FuncRef(Option<Func>),
    /// A host reference, or null.
    ExternRef(Option<ExternRef>),
}

impl Value {
    /// The value's type.
    #[must_use]
    pub const fn ty(&self) -> ValType {
        match self {
            Self::I32(_) => ValType::I32,
            Self::I64(_) => ValType::I64,
            Self::F32(_) => ValType::F32,
            Self::F64(_) => ValType::F64,
            Self::FuncRef(_) => ValType::FuncRef,
            Self::ExternRef(_) => ValType::ExternRef,
        }
    }

    /// The zero of a type: `0`, `0.0` or null.
    #[must_use]
    pub const fn default_of(ty: ValType) -> Self {
        match ty {
            ValType::I32 => Self::I32(0),
            ValType::I64 => Self::I64(0),
            ValType::F32 => Self::F32(0.0),
            ValType::F64 => Self::F64(0.0),
            ValType::FuncRef => Self::FuncRef(None),
            ValType::ExternRef => Self::ExternRef(None),
        }
    }

    /// The `i32`, if this is one.
    #[must_use]
    pub const fn i32(&self) -> Option<i32> {
        match *self {
            Self::I32(v) => Some(v),
            _ => None,
        }
    }

    /// The `i64`, if this is one.
    #[must_use]
    pub const fn i64(&self) -> Option<i64> {
        match *self {
            Self::I64(v) => Some(v),
            _ => None,
        }
    }

    /// The `f32`, if this is one.
    #[must_use]
    pub const fn f32(&self) -> Option<f32> {
        match *self {
            Self::F32(v) => Some(v),
            _ => None,
        }
    }

    /// The `f64`, if this is one.
    #[must_use]
    pub const fn f64(&self) -> Option<f64> {
        match *self {
            Self::F64(v) => Some(v),
            _ => None,
        }
    }

    /// The value as a slot's bits; `None` for a reference to another store's function.
    pub(crate) fn to_slot(self, store: u64) -> Option<u64> {
        Some(match self {
            Self::I32(v) => u64::from(v as u32),
            Self::I64(v) => v as u64,
            Self::F32(v) => u64::from(v.to_bits()),
            Self::F64(v) => v.to_bits(),
            Self::FuncRef(None) | Self::ExternRef(None) => 0,
            Self::FuncRef(Some(f)) => {
                if f.store != store {
                    return None;
                }
                u64::from(f.index) + 1
            }
            Self::ExternRef(Some(e)) => u64::from(e.0) + 1,
        })
    }

    /// A slot's bits as a value of type `ty`.
    pub(crate) fn from_slot(bits: u64, ty: ValType, store: u64) -> Self {
        match ty {
            ValType::I32 => Self::I32(bits as u32 as i32),
            ValType::I64 => Self::I64(bits as i64),
            ValType::F32 => Self::F32(f32::from_bits(bits as u32)),
            ValType::F64 => Self::F64(f64::from_bits(bits)),
            ValType::FuncRef => Self::FuncRef(bits.checked_sub(1).map(|i| Func {
                store,
                index: i as u32,
            })),
            ValType::ExternRef => Self::ExternRef(bits.checked_sub(1).map(|i| ExternRef(i as u32))),
        }
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Self::I32(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::I64(v)
    }
}

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Self::F32(v)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Self::F64(v)
    }
}

/// A host value a guest holds as an `externref`: a number the host chooses and gives meaning to
/// (an index into a table of its own, for one). The guest can only pass it around.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExternRef(pub u32);

macro_rules! handle {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name {
            pub(crate) store: u64,
            pub(crate) index: u32,
        }
    };
}

handle!(
    /// A function in a [`Store`](crate::Store): a module's or the host's.
    Func
);
handle!(
    /// A table in a [`Store`](crate::Store).
    Table
);
handle!(
    /// A memory in a [`Store`](crate::Store).
    Memory
);
handle!(
    /// A global in a [`Store`](crate::Store).
    Global
);
handle!(
    /// A module instantiated in a [`Store`](crate::Store).
    Instance
);

/// Something an instance imports or exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extern {
    /// A function.
    Func(Func),
    /// A table.
    Table(Table),
    /// A memory.
    Memory(Memory),
    /// A global.
    Global(Global),
}

impl Extern {
    /// The function, if this is one.
    #[must_use]
    pub const fn func(self) -> Option<Func> {
        match self {
            Self::Func(f) => Some(f),
            _ => None,
        }
    }

    /// The table, if this is one.
    #[must_use]
    pub const fn table(self) -> Option<Table> {
        match self {
            Self::Table(t) => Some(t),
            _ => None,
        }
    }

    /// The memory, if this is one.
    #[must_use]
    pub const fn memory(self) -> Option<Memory> {
        match self {
            Self::Memory(m) => Some(m),
            _ => None,
        }
    }

    /// The global, if this is one.
    #[must_use]
    pub const fn global(self) -> Option<Global> {
        match self {
            Self::Global(g) => Some(g),
            _ => None,
        }
    }
}
