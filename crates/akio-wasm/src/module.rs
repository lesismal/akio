//! A decoded and validated module.

use std::{collections::HashMap, fmt};

use crate::{
    error::{Feature, Limit, Result, invalid, limit, malformed, unsupported},
    limits::ModuleLimits,
    ops::{Decoder, Op},
    reader::Reader,
    translate::{Compiled, Translator},
    types::{
        Export, ExportKind, ExternType, FuncType, GlobalType, Import, Limits, MemoryType, RefType,
        TableType, ValType,
    },
    validate::Validator,
};

/// The most pages a 32-bit memory may have (4 GiB).
const MAX_PAGES: u32 = 65_536;

/// A constant expression: a global's initial value, a segment's offset or element.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ConstExpr {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
    RefNull(RefType),
    RefFunc(u32),
    /// An imported global's value.
    GlobalGet(u32),
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SegmentMode {
    Passive,
    /// An element segment for `ref.func` only, dropped at instantiation.
    Declared,
    /// Copied into table or memory `index` at `offset` when instantiated.
    Active {
        index: u32,
        offset: ConstExpr,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ElemSegment {
    pub(crate) ty: RefType,
    pub(crate) mode: SegmentMode,
    pub(crate) items: Box<[ConstExpr]>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DataSegment {
    pub(crate) mode: SegmentMode,
    pub(crate) bytes: Box<[u8]>,
}

/// A defined function's body: its declared locals and where its instructions were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FuncBody {
    /// `(end, type)` runs of declared locals, counted from the first parameter.
    pub(crate) locals: Box<[(u32, ValType)]>,
    /// Offset of the instructions in the module, for errors.
    pub(crate) offset: usize,
    /// The highest the operand stack gets.
    pub(crate) max_stack: u32,
}

/// A WebAssembly module, decoded and validated: what [`Module::new`] accepted.
///
/// It is immutable and `Send + Sync`: share one (in an `Arc`) between all the instances made
/// from it.
pub struct Module {
    pub(crate) types: Vec<FuncType>,
    pub(crate) imports: Vec<Import>,
    /// The type index of every function, imported ones first.
    pub(crate) funcs: Vec<u32>,
    pub(crate) imported_funcs: u32,
    /// Every table, imported ones first.
    pub(crate) tables: Vec<TableType>,
    pub(crate) imported_tables: u32,
    pub(crate) memory: Option<MemoryType>,
    pub(crate) memory_imported: bool,
    /// Every global, imported ones first.
    pub(crate) globals: Vec<GlobalType>,
    pub(crate) imported_globals: u32,
    /// The initial values of the defined globals.
    pub(crate) global_inits: Vec<ConstExpr>,
    pub(crate) exports: Vec<Export>,
    export_names: HashMap<Box<str>, u32>,
    pub(crate) start: Option<u32>,
    pub(crate) elems: Vec<ElemSegment>,
    pub(crate) data_count: Option<u32>,
    pub(crate) datas: Vec<DataSegment>,
    /// Functions that `ref.func` may name in a body: those named outside bodies (C.refs).
    pub(crate) declared: Vec<bool>,
    pub(crate) bodies: Vec<FuncBody>,
    /// The defined functions, translated to the register form.
    pub(crate) compiled: Vec<Compiled>,
}

impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Module")
            .field("types", &self.types.len())
            .field("imports", &self.imports.len())
            .field("funcs", &self.funcs.len())
            .field("tables", &self.tables.len())
            .field("memory", &self.memory)
            .field("globals", &self.globals.len())
            .field("exports", &self.exports.len())
            .field("elems", &self.elems.len())
            .field("datas", &self.datas.len())
            .field(
                "instructions",
                &self.compiled.iter().map(|c| c.code.len()).sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

/// The order sections must come in (custom sections aside); `None` for an unknown id.
const fn section_rank(id: u8) -> Option<u8> {
    match id {
        1..=9 => Some(id),
        12 => Some(10), // data count, between elements and code
        10 => Some(11),
        11 => Some(12),
        _ => None,
    }
}

impl Module {
    /// Decodes and validates a binary module. Linear in its size; checks `limits` as it goes.
    ///
    /// Refuses, with an [`Error`](crate::Error) saying why and where: bytes that are not a
    /// module ([`ErrorKind::Malformed`](crate::ErrorKind::Malformed)), a module that does not
    /// validate ([`ErrorKind::Invalid`](crate::ErrorKind::Invalid)), one that uses a feature
    /// outside those this crate implements ([`ErrorKind::Unsupported`](crate::ErrorKind::Unsupported))
    /// and one over a limit ([`ErrorKind::Limit`](crate::ErrorKind::Limit)).
    pub fn new(bytes: &[u8], limits: &ModuleLimits) -> Result<Self> {
        if bytes.len() > limits.max_module_bytes {
            return Err(limit(0, Limit::ModuleBytes, "module too large"));
        }
        let mut m = Self {
            types: Vec::new(),
            imports: Vec::new(),
            funcs: Vec::new(),
            imported_funcs: 0,
            tables: Vec::new(),
            imported_tables: 0,
            memory: None,
            memory_imported: false,
            globals: Vec::new(),
            imported_globals: 0,
            global_inits: Vec::new(),
            exports: Vec::new(),
            export_names: HashMap::new(),
            start: None,
            elems: Vec::new(),
            data_count: None,
            datas: Vec::new(),
            declared: Vec::new(),
            bodies: Vec::new(),
            compiled: Vec::new(),
        };
        let mut d = Load {
            limits,
            decoder: Decoder::default(),
        };
        let mut r = Reader::new(bytes, 0);
        d.header(&mut r)?;
        let mut last_rank = 0u8;
        let mut saw_code = false;
        let mut saw_data = false;
        while !r.is_empty() {
            let at = r.offset();
            let id = r.u8()?;
            let size = r.u32()? as usize;
            let mut s = r.sub(size)?;
            if id == 0 {
                // A custom section: its name, then anything.
                s.name()?;
                continue;
            }
            let Some(rank) = section_rank(id) else {
                return Err(if id == 13 {
                    unsupported(at, Feature::ExceptionHandling, "tag section")
                } else {
                    malformed(at, "malformed section id")
                });
            };
            if rank <= last_rank {
                return Err(malformed(at, "unexpected content after last section"));
            }
            last_rank = rank;
            if rank >= 6 && m.declared.len() != m.funcs.len() {
                m.declared = vec![false; m.funcs.len()];
            }
            match id {
                1 => d.types(&mut m, &mut s)?,
                2 => d.imports(&mut m, &mut s)?,
                3 => d.functions(&mut m, &mut s)?,
                4 => d.tables(&mut m, &mut s)?,
                5 => d.memories(&mut m, &mut s)?,
                6 => d.globals(&mut m, &mut s)?,
                7 => d.exports(&mut m, &mut s)?,
                8 => d.start(&mut m, &mut s)?,
                9 => d.elems(&mut m, &mut s)?,
                12 => {
                    let at = s.offset();
                    let n = s.u32()?;
                    if n > limits.max_data_segments {
                        return Err(limit(at, Limit::DataSegments, "too many data segments"));
                    }
                    m.data_count = Some(n);
                }
                10 => {
                    saw_code = true;
                    d.code(&mut m, &mut s)?;
                }
                _ => {
                    saw_data = true;
                    d.datas(&mut m, &mut s)?;
                }
            }
            if !s.is_empty() {
                return Err(malformed(s.offset(), "section size mismatch"));
            }
        }
        let defined = m.funcs.len() - m.imported_funcs as usize;
        if !saw_code && defined > 0 {
            return Err(malformed(
                r.offset(),
                "function and code section have inconsistent lengths",
            ));
        }
        if !saw_data && m.data_count.is_some_and(|n| n > 0) {
            return Err(malformed(
                r.offset(),
                "data count and data section have inconsistent lengths",
            ));
        }
        Ok(m)
    }

    /// The imports, in order.
    #[must_use]
    pub fn imports(&self) -> &[Import] {
        &self.imports
    }

    /// The exports, in order.
    #[must_use]
    pub fn exports(&self) -> &[Export] {
        &self.exports
    }

    /// The export named `name`.
    #[must_use]
    pub fn export(&self, name: &str) -> Option<&Export> {
        self.export_names
            .get(name)
            .map(|&i| &self.exports[i as usize])
    }

    /// The function types of the type section.
    #[must_use]
    pub fn types(&self) -> &[FuncType] {
        &self.types
    }

    /// The number of functions, imported ones included.
    #[must_use]
    pub fn func_count(&self) -> u32 {
        // At most `max_funcs`.
        self.funcs.len() as u32
    }

    /// The type of function `index` (imported functions first).
    #[must_use]
    pub fn func_type(&self, index: u32) -> Option<&FuncType> {
        self.funcs
            .get(index as usize)
            .map(|&t| &self.types[t as usize])
    }

    /// The tables, imported ones first.
    #[must_use]
    pub fn tables(&self) -> &[TableType] {
        &self.tables
    }

    /// The memory, imported or defined, if the module has one.
    #[must_use]
    pub const fn memory(&self) -> Option<MemoryType> {
        self.memory
    }

    /// The globals, imported ones first.
    #[must_use]
    pub fn globals(&self) -> &[GlobalType] {
        &self.globals
    }

    /// The start function, run when an instance is made.
    #[must_use]
    pub const fn start(&self) -> Option<u32> {
        self.start
    }
}

/// The decoding state that is not the module: limits and the instruction decoder.
struct Load<'l> {
    limits: &'l ModuleLimits,
    decoder: Decoder,
}

fn check_limits(l: Limits, max: u32, at: usize, what: &'static str) -> Result<()> {
    if l.min > max || l.max.is_some_and(|m| m > max) {
        return Err(invalid(at, what));
    }
    if l.max.is_some_and(|m| m < l.min) {
        return Err(invalid(at, "size minimum must not be greater than maximum"));
    }
    Ok(())
}

impl Load<'_> {
    fn header(&self, r: &mut Reader<'_>) -> Result<()> {
        let magic = r.bytes(4).map_err(|_| malformed(0, "unexpected end"))?;
        if magic != b"\0asm" {
            return Err(malformed(0, "magic header not detected"));
        }
        let version = r.bytes(4).map_err(|_| malformed(4, "unexpected end"))?;
        match version {
            [1, 0, 0, 0] => Ok(()),
            [_, _, 1, 0] => Err(unsupported(4, Feature::ComponentModel, "component binary")),
            _ => Err(malformed(4, "unknown binary version")),
        }
    }

    fn types(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let n = r.count(1)?;
        if n > self.limits.max_types {
            return Err(limit(at, Limit::Types, "too many types"));
        }
        m.types.reserve(n as usize);
        let mut buf = Vec::new();
        for _ in 0..n {
            let at = r.offset();
            match r.u8()? {
                0x60 => {}
                0x4e..=0x50 | 0x5e | 0x5f => {
                    return Err(unsupported(at, Feature::Gc, "GC type definition"));
                }
                _ => return Err(malformed(at, "integer representation too long")),
            }
            buf.clear();
            let params = self.valtypes(r, &mut buf)?;
            self.valtypes(r, &mut buf)?;
            m.types.push(FuncType::new(&buf[..params], &buf[params..]));
        }
        Ok(())
    }

    /// Appends a vector of value types to `buf`; returns how many were read.
    fn valtypes(&self, r: &mut Reader<'_>, buf: &mut Vec<ValType>) -> Result<usize> {
        let at = r.offset();
        let n = r.count(1)?;
        if n > self.limits.max_type_arity {
            return Err(limit(
                at,
                Limit::TypeArity,
                "too many parameters or results",
            ));
        }
        for _ in 0..n {
            buf.push(ValType::read(r)?);
        }
        Ok(n as usize)
    }

    fn type_index(m: &Module, r: &mut Reader<'_>) -> Result<u32> {
        let at = r.offset();
        let t = r.u32()?;
        if t as usize >= m.types.len() {
            return Err(invalid(at, "unknown type"));
        }
        Ok(t)
    }

    fn add_func(&self, m: &mut Module, ty: u32, at: usize) -> Result<()> {
        if m.funcs.len() >= self.limits.max_funcs as usize {
            return Err(limit(at, Limit::Funcs, "too many functions"));
        }
        m.funcs.push(ty);
        Ok(())
    }

    fn table_type(&self, m: &Module, r: &mut Reader<'_>) -> Result<TableType> {
        let at = r.offset();
        if m.tables.len() >= self.limits.max_tables as usize {
            return Err(limit(at, Limit::Tables, "too many tables"));
        }
        let elem = RefType::read(r)?;
        let limits = Limits::read(r, false)?;
        check_limits(limits, u32::MAX, at, "table size")?;
        if limits.min > self.limits.max_table_elements {
            return Err(limit(at, Limit::TableElements, "table too large"));
        }
        Ok(TableType { elem, limits })
    }

    fn memory_type(m: &Module, r: &mut Reader<'_>) -> Result<MemoryType> {
        let at = r.offset();
        let limits = Limits::read(r, true)?;
        if m.memory.is_some() {
            return Err(unsupported(at, Feature::MultiMemory, "a second memory"));
        }
        check_limits(
            limits,
            MAX_PAGES,
            at,
            "memory size must be at most 65536 pages (4GiB)",
        )?;
        Ok(MemoryType { limits })
    }

    fn global_type(&self, m: &Module, r: &mut Reader<'_>) -> Result<GlobalType> {
        let at = r.offset();
        if m.globals.len() >= self.limits.max_globals as usize {
            return Err(limit(at, Limit::Globals, "too many globals"));
        }
        GlobalType::read(r)
    }

    fn imports(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let n = r.count(4)?;
        if n > self.limits.max_imports {
            return Err(limit(at, Limit::Imports, "too many imports"));
        }
        m.imports.reserve(n as usize);
        for _ in 0..n {
            let module = r.name()?;
            let name = r.name()?;
            let at = r.offset();
            let ty = match r.u8()? {
                0 => {
                    let t = Self::type_index(m, r)?;
                    self.add_func(m, t, at)?;
                    m.imported_funcs += 1;
                    ExternType::Func(m.types[t as usize].clone())
                }
                1 => {
                    let t = self.table_type(m, r)?;
                    m.tables.push(t);
                    m.imported_tables += 1;
                    ExternType::Table(t)
                }
                2 => {
                    let t = Self::memory_type(m, r)?;
                    m.memory = Some(t);
                    m.memory_imported = true;
                    ExternType::Memory(t)
                }
                3 => {
                    let t = self.global_type(m, r)?;
                    m.globals.push(t);
                    m.imported_globals += 1;
                    ExternType::Global(t)
                }
                4 => return Err(unsupported(at, Feature::ExceptionHandling, "tag import")),
                _ => return Err(malformed(at, "malformed import kind")),
            };
            m.imports.push(Import {
                module: module.into(),
                name: name.into(),
                ty,
            });
        }
        Ok(())
    }

    fn functions(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let n = r.count(1)?;
        if m.funcs.len() + n as usize > self.limits.max_funcs as usize {
            return Err(limit(at, Limit::Funcs, "too many functions"));
        }
        m.funcs.reserve(n as usize);
        for _ in 0..n {
            let at = r.offset();
            let t = Self::type_index(m, r)?;
            self.add_func(m, t, at)?;
        }
        Ok(())
    }

    fn tables(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let n = r.count(3)?;
        for _ in 0..n {
            if r.peek() == Some(0x40) {
                return Err(unsupported(
                    r.offset(),
                    Feature::FunctionReferences,
                    "table with an initializer",
                ));
            }
            let t = self.table_type(m, r)?;
            m.tables.push(t);
        }
        Ok(())
    }

    fn memories(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let n = r.count(2)?;
        for _ in 0..n {
            let t = Self::memory_type(m, r)?;
            m.memory = Some(t);
        }
        Ok(())
    }

    fn globals(&mut self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let n = r.count(3)?;
        for _ in 0..n {
            let t = self.global_type(m, r)?;
            let init = self.const_expr(m, r, t.val)?;
            m.globals.push(t);
            m.global_inits.push(init);
        }
        Ok(())
    }

    fn exports(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let n = r.count(3)?;
        if n > self.limits.max_exports {
            return Err(limit(at, Limit::Exports, "too many exports"));
        }
        m.exports.reserve(n as usize);
        m.export_names.reserve(n as usize);
        for _ in 0..n {
            let name_at = r.offset();
            let name = r.name()?;
            let at = r.offset();
            let kind = match r.u8()? {
                0 => ExportKind::Func,
                1 => ExportKind::Table,
                2 => ExportKind::Memory,
                3 => ExportKind::Global,
                4 => return Err(unsupported(at, Feature::ExceptionHandling, "tag export")),
                _ => return Err(malformed(at, "malformed export kind")),
            };
            let at = r.offset();
            let index = r.u32()?;
            let (count, what) = match kind {
                ExportKind::Func => (m.funcs.len(), "unknown function"),
                ExportKind::Table => (m.tables.len(), "unknown table"),
                ExportKind::Memory => (usize::from(m.memory.is_some()), "unknown memory"),
                ExportKind::Global => (m.globals.len(), "unknown global"),
            };
            if index as usize >= count {
                return Err(invalid(at, what));
            }
            if kind == ExportKind::Func {
                m.declared[index as usize] = true;
            }
            let i = m.exports.len() as u32;
            if m.export_names.insert(name.into(), i).is_some() {
                return Err(invalid(name_at, "duplicate export name"));
            }
            m.exports.push(Export {
                name: name.into(),
                kind,
                index,
            });
        }
        Ok(())
    }

    fn start(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let f = r.u32()?;
        let ty = m
            .func_type(f)
            .ok_or_else(|| invalid(at, "unknown function"))?;
        if !ty.params().is_empty() || !ty.results().is_empty() {
            return Err(invalid(at, "start function"));
        }
        m.start = Some(f);
        Ok(())
    }

    fn table_index(m: &Module, r: &mut Reader<'_>) -> Result<u32> {
        let at = r.offset();
        let t = r.u32()?;
        if t as usize >= m.tables.len() {
            return Err(invalid(at, "unknown table"));
        }
        Ok(t)
    }

    fn func_ref(m: &mut Module, r: &mut Reader<'_>) -> Result<ConstExpr> {
        let at = r.offset();
        let f = r.u32()?;
        if f as usize >= m.funcs.len() {
            return Err(invalid(at, "unknown function"));
        }
        m.declared[f as usize] = true;
        Ok(ConstExpr::RefFunc(f))
    }

    fn elems(&mut self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let n = r.count(2)?;
        if n > self.limits.max_elem_segments {
            return Err(limit(at, Limit::ElemSegments, "too many element segments"));
        }
        m.elems.reserve(n as usize);
        for _ in 0..n {
            let at = r.offset();
            let flags = r.u32()?;
            if flags > 7 {
                return Err(malformed(at, "malformed elements segment kind"));
            }
            let exprs = flags & 4 != 0;
            let mode = if flags & 1 == 0 {
                let index = if flags & 2 != 0 {
                    Self::table_index(m, r)?
                } else {
                    if m.tables.is_empty() {
                        return Err(invalid(at, "unknown table"));
                    }
                    0
                };
                let offset = self.const_expr(m, r, ValType::I32)?;
                SegmentMode::Active { index, offset }
            } else if flags & 2 == 0 {
                SegmentMode::Passive
            } else {
                SegmentMode::Declared
            };
            let ty = if flags & 3 == 0 {
                RefType::FuncRef
            } else if exprs {
                RefType::read(r)?
            } else {
                let at = r.offset();
                if r.u8()? != 0 {
                    return Err(malformed(at, "malformed element kind"));
                }
                RefType::FuncRef
            };
            if let SegmentMode::Active { index, .. } = mode {
                if m.tables[index as usize].elem != ty {
                    return Err(invalid(at, "type mismatch"));
                }
            }
            let count = r.count(1)?;
            let mut items = Vec::with_capacity(count as usize);
            for _ in 0..count {
                items.push(if exprs {
                    self.const_expr(m, r, ty.into())?
                } else {
                    Self::func_ref(m, r)?
                });
            }
            m.elems.push(ElemSegment {
                ty,
                mode,
                items: items.into(),
            });
        }
        Ok(())
    }

    fn code(&self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let n = r.count(1)?;
        let defined = m.funcs.len() - m.imported_funcs as usize;
        if n as usize != defined {
            return Err(malformed(
                at,
                "function and code section have inconsistent lengths",
            ));
        }
        let mut v = Validator::new(self.limits);
        let mut t = Translator::default();
        let mut bodies = Vec::with_capacity(n as usize);
        let mut compiled = Vec::with_capacity(n as usize);
        for i in 0..n as usize {
            let len = r.u32()? as usize;
            let mut b = r.sub(len)?;
            let ty = m.funcs[m.imported_funcs as usize + i];
            let params = m.types[ty as usize].params();
            v.read_locals(&mut b, params, self.limits.max_locals)?;
            let start = b.offset();
            // Validated first, then translated from the same bytes: translation may then rely
            // on the body being valid.
            let mut code = b.clone();
            let info = v.body(m, &mut b, ty)?;
            let locals = v
                .locals
                .runs()
                .last()
                .map_or(params.len() as u32, |&(end, _)| end);
            let func_ty = m.types[ty as usize].clone();
            compiled.push(t.translate(m, &mut code, &func_ty, locals, info.max_stack)?);
            bodies.push(FuncBody {
                locals: v.locals.runs().into(),
                offset: start,
                max_stack: info.max_stack,
            });
        }
        m.bodies = bodies;
        m.compiled = compiled;
        Ok(())
    }

    fn datas(&mut self, m: &mut Module, r: &mut Reader<'_>) -> Result<()> {
        let at = r.offset();
        let n = r.count(1)?;
        if n > self.limits.max_data_segments {
            return Err(limit(at, Limit::DataSegments, "too many data segments"));
        }
        if m.data_count.is_some_and(|c| c != n) {
            return Err(malformed(
                at,
                "data count and data section have inconsistent lengths",
            ));
        }
        m.datas.reserve(n as usize);
        for _ in 0..n {
            let at = r.offset();
            let flags = r.u32()?;
            let mode = match flags {
                1 => SegmentMode::Passive,
                0 | 2 => {
                    if flags == 2 {
                        let mat = r.offset();
                        if r.u32()? != 0 {
                            return Err(unsupported(mat, Feature::MultiMemory, "memory index"));
                        }
                    }
                    if m.memory.is_none() {
                        return Err(invalid(at, "unknown memory 0"));
                    }
                    let offset = self.const_expr(m, r, ValType::I32)?;
                    SegmentMode::Active { index: 0, offset }
                }
                _ => return Err(malformed(at, "malformed data segment kind")),
            };
            let len = r.u32()? as usize;
            let bytes = r.bytes(len)?;
            m.datas.push(DataSegment {
                mode,
                bytes: bytes.into(),
            });
        }
        Ok(())
    }

    /// A constant expression of type `want`, through its `end`.
    fn const_expr(
        &mut self,
        m: &mut Module,
        r: &mut Reader<'_>,
        want: ValType,
    ) -> Result<ConstExpr> {
        let mut value: Option<(ConstExpr, ValType)> = None;
        let mut extra = false;
        loop {
            let at = r.offset();
            let (e, t) = match self.decoder.read(r, 1)? {
                Op::End => break,
                Op::I32Const(v) => (ConstExpr::I32(v), ValType::I32),
                Op::I64Const(v) => (ConstExpr::I64(v), ValType::I64),
                Op::F32Const(v) => (ConstExpr::F32(v), ValType::F32),
                Op::F64Const(v) => (ConstExpr::F64(v), ValType::F64),
                Op::RefNull(t) => (ConstExpr::RefNull(t), t.into()),
                Op::RefFunc(f) => {
                    if f as usize >= m.funcs.len() {
                        return Err(invalid(at, "unknown function"));
                    }
                    m.declared[f as usize] = true;
                    (ConstExpr::RefFunc(f), ValType::FuncRef)
                }
                Op::GlobalGet(g) => {
                    // WebAssembly 2.0: imported globals only (extended constants lift it).
                    if g >= m.imported_globals {
                        return Err(invalid(at, "unknown global"));
                    }
                    let gt = m.globals[g as usize];
                    if gt.mutable {
                        return Err(invalid(at, "constant expression required"));
                    }
                    (ConstExpr::GlobalGet(g), gt.val)
                }
                Op::Numeric(0x6a..=0x6c | 0x7c..=0x7e) => {
                    return Err(unsupported(
                        at,
                        Feature::ExtendedConst,
                        "arithmetic in a constant expression",
                    ));
                }
                _ => return Err(invalid(at, "constant expression required")),
            };
            if value.is_some() {
                extra = true;
            }
            value = Some((e, t));
        }
        match value {
            Some((e, t)) if t == want && !extra => Ok(e),
            _ => Err(invalid(r.offset(), "type mismatch")),
        }
    }
}
