//! A store: instances of modules and what they own, the host's functions and state, and the
//! calls into them.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::{
    budget::{Budget, InstanceLimits, Meter},
    exec::Exit,
    module::{ConstExpr, Module, SegmentMode},
    trap::Trap,
    types::{
        ExportKind, ExternType, FuncType, GlobalType, Limits, MemoryType, RefType, TableType,
        ValType,
    },
    value::{Extern, Func, Global, Instance, Memory, Table, Value},
};

pub(crate) const PAGE: usize = 65_536;

/// A host function: called with the caller, its arguments, and its results to fill (each
/// already holding its type's zero).
pub(crate) type HostFn<S> =
    Arc<dyn Fn(&mut Caller<'_, S>, &[Value], &mut [Value]) -> Result<(), Trap> + Send + Sync>;

#[derive(Debug, Clone, Copy)]
pub(crate) enum FuncKind {
    /// Defined function `def` of instance `inst`.
    Wasm { inst: u32, def: u32 },
    /// The host's function `n`.
    Host(u32),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FuncEntity {
    /// The store's type id.
    pub(crate) ty: u32,
    pub(crate) kind: FuncKind,
}

/// An instance's indices into the store.
#[derive(Debug)]
pub(crate) struct InstanceData {
    pub(crate) module: Arc<Module>,
    pub(crate) funcs: Box<[u32]>,
    pub(crate) tables: Box<[u32]>,
    pub(crate) memory: Option<u32>,
    pub(crate) globals: Box<[u32]>,
    /// The store's type id of each of the module's types.
    pub(crate) types: Box<[u32]>,
}

/// An instance's segments: element segments' references (empty once dropped), and whether each
/// data segment was dropped.
#[derive(Debug, Default)]
pub(crate) struct Segments {
    pub(crate) elems: Vec<Box<[u64]>>,
    pub(crate) data_dropped: Vec<bool>,
}

#[derive(Debug, Default)]
pub(crate) struct MemoryEntity {
    pub(crate) data: Vec<u8>,
    /// The most pages it may grow to: its declared maximum and the store's limit.
    pub(crate) max_pages: u32,
    pub(crate) declared_max: Option<u32>,
}

#[derive(Debug)]
pub(crate) struct TableEntity {
    pub(crate) elems: Vec<u64>,
    pub(crate) max: u32,
    pub(crate) declared_max: Option<u32>,
    pub(crate) elem: RefType,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GlobalEntity {
    pub(crate) value: u64,
    pub(crate) ty: GlobalType,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Frame {
    pub(crate) inst: u32,
    /// The defined function's index in its module.
    pub(crate) func: u32,
    /// Where it goes on (saved when it calls).
    pub(crate) pc: u32,
    /// Its first slot in the value stack.
    pub(crate) base: u32,
}

/// The store without its host parts: what the interpreter works on.
#[derive(Debug)]
pub(crate) struct Runtime {
    pub(crate) id: u64,
    pub(crate) limits: InstanceLimits,
    pub(crate) types: Vec<FuncType>,
    type_ids: HashMap<FuncType, u32>,
    pub(crate) funcs: Vec<FuncEntity>,
    pub(crate) instances: Vec<InstanceData>,
    pub(crate) segments: Vec<Segments>,
    pub(crate) memories: Vec<MemoryEntity>,
    pub(crate) tables: Vec<TableEntity>,
    pub(crate) globals: Vec<GlobalEntity>,
    pub(crate) stack: Vec<u64>,
    pub(crate) frames: Vec<Frame>,
}

impl Runtime {
    fn intern(&mut self, t: &FuncType) -> u32 {
        if let Some(&id) = self.type_ids.get(t) {
            return id;
        }
        let id = self.types.len() as u32;
        self.types.push(t.clone());
        self.type_ids.insert(t.clone(), id);
        id
    }

    /// The slot value of a constant expression of instance `inst`'s module.
    fn eval(&self, e: &ConstExpr, funcs: &[u32], globals: &[u32]) -> u64 {
        match *e {
            ConstExpr::I32(v) => u64::from(v as u32),
            ConstExpr::I64(v) => v as u64,
            ConstExpr::F32(b) => u64::from(b),
            ConstExpr::F64(b) => b,
            ConstExpr::RefNull(_) => 0,
            ConstExpr::RefFunc(f) => u64::from(funcs[f as usize]) + 1,
            ConstExpr::GlobalGet(g) => self.globals[globals[g as usize] as usize].value,
        }
    }

    fn max_pages(&self) -> u32 {
        (self.limits.max_memory / PAGE).min(65_536) as u32
    }
}

/// Why [`Store::instantiate`] did not make an instance.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstantiateError {
    /// Import `index` does not fit what the module declares: `"incompatible import type"`,
    /// `"wrong number of imports"`, or `"import from another store"`.
    Unlinkable {
        /// The import's index in the module.
        index: usize,
        /// Why.
        message: &'static str,
    },
    /// The instance would pass one of the store's [`InstanceLimits`]: its field's name.
    Limit(&'static str),
    /// Initializing it trapped: a segment out of bounds, or the start function. What the
    /// segments before it wrote stays written (in tables and memories it imported too), and the
    /// store has ended, as after any trap.
    Trap(Trap),
}

impl fmt::Display for InstantiateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unlinkable { index, message } => write!(f, "import {index}: {message}"),
            Self::Limit(l) => write!(f, "over the store's limit InstanceLimits::{l}"),
            Self::Trap(t) => write!(f, "instantiation trapped: {t}"),
        }
    }
}

impl std::error::Error for InstantiateError {}

/// The caller of a host function: the store's state and the calling instance's memory.
pub struct Caller<'a, S> {
    store: &'a mut Store<S>,
    instance: Option<u32>,
}

impl<S> fmt::Debug for Caller<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Caller")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl<S> Caller<'_, S> {
    /// The store's state.
    #[must_use]
    pub fn state(&self) -> &S {
        &self.store.state
    }

    /// The store's state, to change.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.store.state
    }

    fn memory_index(&self) -> Option<usize> {
        let i = self.instance?;
        self.store.rt.instances[i as usize]
            .memory
            .map(|m| m as usize)
    }

    /// The calling instance's memory, if it has one (none when the host called the function).
    #[must_use]
    pub fn memory(&self) -> Option<&[u8]> {
        let m = self.memory_index()?;
        Some(&self.store.rt.memories[m].data)
    }

    /// The calling instance's memory, to change.
    pub fn memory_mut(&mut self) -> Option<&mut [u8]> {
        let m = self.memory_index()?;
        Some(&mut self.store.rt.memories[m].data)
    }
}

static NEXT_STORE: AtomicU64 = AtomicU64::new(1);

/// Where instances live: their memories, tables, globals and functions, the host's functions,
/// and a state `S` for the host functions to use (ADR-125, section 3).
///
/// A store is `Send` (when `S` is), not `Sync`: one thread runs it at a time, and a host
/// function cannot call back into it, so a call never re-enters the guest. Several instances
/// may live in one store and import from each other; a plugin's store usually holds one.
///
/// **A trap ends the store**: its memory may be half-updated, so later calls return
/// [`Trap::Ended`]; drop it and make another (as fit does). [`Store::set_trap_ends`] turns this
/// off, for tests that follow the specification, where a trap leaves the store as it was.
///
/// Handles ([`Func`], [`Memory`] ...) belong to the store that made them; the accessors below
/// panic when given another store's handle, and calls refuse one with [`Trap::BadCall`].
pub struct Store<S> {
    rt: Runtime,
    hosts: Vec<HostFn<S>>,
    state: S,
    ended: bool,
    trap_ends: bool,
    fuel_used: u64,
    /// Reused for host calls' arguments and results.
    args: Vec<Value>,
    results: Vec<Value>,
}

impl<S> fmt::Debug for Store<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("instances", &self.rt.instances.len())
            .field("funcs", &self.rt.funcs.len())
            .field("memories", &self.rt.memories.len())
            .field("tables", &self.rt.tables.len())
            .field("globals", &self.rt.globals.len())
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

/// Whether limits `actual` (an extern's current size and declared maximum) fit `want` (an
/// import's): at least its minimum, and a maximum no larger than its maximum if it has one.
const fn limits_fit(size: u32, max: Option<u32>, want: Limits) -> bool {
    if size < want.min {
        return false;
    }
    match (want.max, max) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(w), Some(m)) => m <= w,
    }
}

impl<S> Store<S> {
    /// An empty store, with the host's state and the limits on running.
    #[must_use]
    pub fn new(state: S, limits: InstanceLimits) -> Self {
        Self {
            rt: Runtime {
                id: NEXT_STORE.fetch_add(1, Ordering::Relaxed),
                limits,
                types: Vec::new(),
                type_ids: HashMap::new(),
                funcs: Vec::new(),
                instances: Vec::new(),
                segments: Vec::new(),
                memories: Vec::new(),
                tables: Vec::new(),
                globals: Vec::new(),
                stack: Vec::new(),
                frames: Vec::new(),
            },
            hosts: Vec::new(),
            state,
            ended: false,
            trap_ends: true,
            fuel_used: 0,
            args: Vec::new(),
            results: Vec::new(),
        }
    }

    /// The host's state.
    #[must_use]
    pub const fn state(&self) -> &S {
        &self.state
    }

    /// The host's state, to change.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    /// The host's state, the store dropped.
    #[must_use]
    pub fn into_state(self) -> S {
        self.state
    }

    /// The limits on running.
    #[must_use]
    pub const fn limits(&self) -> &InstanceLimits {
        &self.rt.limits
    }

    /// Whether a trap ended the store.
    #[must_use]
    pub const fn ended(&self) -> bool {
        self.ended
    }

    /// Whether a trap ends the store (by default it does). Off, a trap leaves the store usable
    /// with whatever its memories, tables and globals then hold: the specification's semantics,
    /// for its tests.
    pub fn set_trap_ends(&mut self, ends: bool) {
        self.trap_ends = ends;
    }

    /// The fuel the last call took, finished or not: its WebAssembly instructions, and the bulk
    /// instructions' bytes (see [`Budget`]).
    #[must_use]
    pub const fn fuel_used(&self) -> u64 {
        self.fuel_used
    }

    fn own(&self, store: u64) {
        assert!(store == self.rt.id, "a handle of another store");
    }

    /// A host function of type `ty`.
    pub fn func_new(
        &mut self,
        ty: FuncType,
        f: impl Fn(&mut Caller<'_, S>, &[Value], &mut [Value]) -> Result<(), Trap>
        + Send
        + Sync
        + 'static,
    ) -> Func {
        let ty = self.rt.intern(&ty);
        let h = self.hosts.len() as u32;
        self.hosts.push(Arc::new(f));
        let index = self.rt.funcs.len() as u32;
        self.rt.funcs.push(FuncEntity {
            ty,
            kind: FuncKind::Host(h),
        });
        Func {
            store: self.rt.id,
            index,
        }
    }

    /// A global of type `ty` holding `value`, for instances to import.
    ///
    /// # Errors
    ///
    /// [`Trap::BadCall`] if `value` is not of `ty`'s type.
    pub fn global_new(&mut self, ty: GlobalType, value: Value) -> Result<Global, Trap> {
        if value.ty() != ty.val {
            return Err(Trap::BadCall("value of the wrong type"));
        }
        let value = value
            .to_slot(self.rt.id)
            .ok_or(Trap::BadCall("a function of another store"))?;
        let index = self.rt.globals.len() as u32;
        self.rt.globals.push(GlobalEntity { value, ty });
        Ok(Global {
            store: self.rt.id,
            index,
        })
    }

    /// A table of type `ty`, every element `init`, for instances to import.
    ///
    /// # Errors
    ///
    /// [`Trap::BadCall`] if `init` is not of the table's element type or its size is over
    /// [`InstanceLimits::max_table_elements`].
    pub fn table_new(&mut self, ty: TableType, init: Value) -> Result<Table, Trap> {
        if init.ty() != ValType::from(ty.elem) {
            return Err(Trap::BadCall("value of the wrong type"));
        }
        if ty.limits.min > self.rt.limits.max_table_elements {
            return Err(Trap::BadCall(
                "table over InstanceLimits::max_table_elements",
            ));
        }
        let init = init
            .to_slot(self.rt.id)
            .ok_or(Trap::BadCall("a function of another store"))?;
        Ok(self.add_table(ty, init))
    }

    fn add_table(&mut self, ty: TableType, init: u64) -> Table {
        let index = self.rt.tables.len() as u32;
        self.rt.tables.push(TableEntity {
            elems: vec![init; ty.limits.min as usize],
            max: ty
                .limits
                .max
                .unwrap_or(u32::MAX)
                .min(self.rt.limits.max_table_elements),
            declared_max: ty.limits.max,
            elem: ty.elem,
        });
        Table {
            store: self.rt.id,
            index,
        }
    }

    /// A memory of type `ty`, zeroed, for instances to import.
    ///
    /// # Errors
    ///
    /// [`Trap::BadCall`] if its initial size is over [`InstanceLimits::max_memory`].
    pub fn memory_new(&mut self, ty: MemoryType) -> Result<Memory, Trap> {
        if ty.limits.min > self.rt.max_pages() {
            return Err(Trap::BadCall("memory over InstanceLimits::max_memory"));
        }
        Ok(self.add_memory(ty))
    }

    fn add_memory(&mut self, ty: MemoryType) -> Memory {
        let index = self.rt.memories.len() as u32;
        let max_pages = ty.limits.max.unwrap_or(65_536).min(self.rt.max_pages());
        self.rt.memories.push(MemoryEntity {
            data: vec![0; ty.limits.min as usize * PAGE],
            max_pages,
            declared_max: ty.limits.max,
        });
        Memory {
            store: self.rt.id,
            index,
        }
    }

    /// The type of a function.
    ///
    /// # Panics
    ///
    /// If `f` belongs to another store.
    #[must_use]
    pub fn func_type(&self, f: Func) -> &FuncType {
        self.own(f.store);
        &self.rt.types[self.rt.funcs[f.index as usize].ty as usize]
    }

    /// A global's type.
    ///
    /// # Panics
    ///
    /// If `g` belongs to another store.
    #[must_use]
    pub fn global_type(&self, g: Global) -> GlobalType {
        self.own(g.store);
        self.rt.globals[g.index as usize].ty
    }

    /// A global's value.
    ///
    /// # Panics
    ///
    /// If `g` belongs to another store.
    #[must_use]
    pub fn global_get(&self, g: Global) -> Value {
        self.own(g.store);
        let e = self.rt.globals[g.index as usize];
        Value::from_slot(e.value, e.ty.val, self.rt.id)
    }

    /// Sets a mutable global.
    ///
    /// # Errors
    ///
    /// [`Trap::BadCall`] if the global is immutable or `value` of the wrong type.
    ///
    /// # Panics
    ///
    /// If `g` belongs to another store.
    pub fn global_set(&mut self, g: Global, value: Value) -> Result<(), Trap> {
        self.own(g.store);
        let id = self.rt.id;
        let e = &mut self.rt.globals[g.index as usize];
        if !e.ty.mutable {
            return Err(Trap::BadCall("global is immutable"));
        }
        if value.ty() != e.ty.val {
            return Err(Trap::BadCall("value of the wrong type"));
        }
        e.value = value
            .to_slot(id)
            .ok_or(Trap::BadCall("a function of another store"))?;
        Ok(())
    }

    /// A memory's bytes.
    ///
    /// # Panics
    ///
    /// If `m` belongs to another store.
    #[must_use]
    pub fn memory_data(&self, m: Memory) -> &[u8] {
        self.own(m.store);
        &self.rt.memories[m.index as usize].data
    }

    /// A memory's bytes, to change.
    ///
    /// # Panics
    ///
    /// If `m` belongs to another store.
    pub fn memory_data_mut(&mut self, m: Memory) -> &mut [u8] {
        self.own(m.store);
        &mut self.rt.memories[m.index as usize].data
    }

    /// A table's size, in elements.
    ///
    /// # Panics
    ///
    /// If `t` belongs to another store.
    #[must_use]
    pub fn table_size(&self, t: Table) -> u32 {
        self.own(t.store);
        self.rt.tables[t.index as usize].elems.len() as u32
    }

    /// A table's element, `None` past its end.
    ///
    /// # Panics
    ///
    /// If `t` belongs to another store.
    #[must_use]
    pub fn table_get(&self, t: Table, i: u32) -> Option<Value> {
        self.own(t.store);
        let e = &self.rt.tables[t.index as usize];
        let v = *e.elems.get(i as usize)?;
        Some(Value::from_slot(v, e.elem.into(), self.rt.id))
    }

    /// The export `name` of an instance.
    ///
    /// # Panics
    ///
    /// If `inst` belongs to another store.
    #[must_use]
    pub fn export(&self, inst: Instance, name: &str) -> Option<Extern> {
        self.own(inst.store);
        let d = &self.rt.instances[inst.index as usize];
        let e = d.module.export(name)?;
        let store = self.rt.id;
        let i = e.index as usize;
        Some(match e.kind {
            ExportKind::Func => Extern::Func(Func {
                store,
                index: d.funcs[i],
            }),
            ExportKind::Table => Extern::Table(Table {
                store,
                index: d.tables[i],
            }),
            ExportKind::Memory => Extern::Memory(Memory {
                store,
                index: d.memory?,
            }),
            ExportKind::Global => Extern::Global(Global {
                store,
                index: d.globals[i],
            }),
        })
    }

    /// The exported function `name` of an instance.
    ///
    /// # Panics
    ///
    /// If `inst` belongs to another store.
    #[must_use]
    pub fn export_func(&self, inst: Instance, name: &str) -> Option<Func> {
        self.export(inst, name)?.func()
    }

    /// The module an instance was made from.
    ///
    /// # Panics
    ///
    /// If `inst` belongs to another store.
    #[must_use]
    pub fn module(&self, inst: Instance) -> &Arc<Module> {
        self.own(inst.store);
        &self.rt.instances[inst.index as usize].module
    }

    fn end_on(&mut self, t: &Trap) {
        if t.ends_store() && self.trap_ends {
            self.ended = true;
        }
    }

    /// Instantiates `module` with `imports` (one for each of its imports, in order): allocates
    /// its functions, tables, memory and globals, initializes the active segments, and runs its
    /// start function under `budget`.
    ///
    /// # Errors
    ///
    /// An import that does not fit, an instance over the store's limits, or a trap while
    /// initializing (see [`InstantiateError`]); [`Trap::Ended`] if the store has ended.
    pub fn instantiate(
        &mut self,
        module: &Arc<Module>,
        imports: &[Extern],
        budget: &Budget,
    ) -> Result<Instance, InstantiateError> {
        if self.ended {
            return Err(InstantiateError::Trap(Trap::Ended));
        }
        let m = &**module;
        if imports.len() != m.imports.len() {
            return Err(InstantiateError::Unlinkable {
                index: imports.len().min(m.imports.len()),
                message: "wrong number of imports",
            });
        }
        let id = self.rt.id;
        let mut funcs = Vec::with_capacity(m.funcs.len());
        let mut tables = Vec::with_capacity(m.tables.len());
        let mut memory = None;
        let mut globals = Vec::with_capacity(m.globals.len());
        for (index, (imp, ext)) in m.imports.iter().zip(imports).enumerate() {
            let bad = |message| InstantiateError::Unlinkable { index, message };
            let (store, fits) = match (&imp.ty, *ext) {
                (ExternType::Func(ft), Extern::Func(f)) => {
                    let ok = f.store == id
                        && self.rt.types[self.rt.funcs[f.index as usize].ty as usize] == *ft;
                    funcs.push(f.index);
                    (f.store, ok)
                }
                (ExternType::Table(tt), Extern::Table(t)) => {
                    let ok = t.store == id && {
                        let e = &self.rt.tables[t.index as usize];
                        e.elem == tt.elem
                            && limits_fit(e.elems.len() as u32, e.declared_max, tt.limits)
                    };
                    tables.push(t.index);
                    (t.store, ok)
                }
                (ExternType::Memory(mt), Extern::Memory(mm)) => {
                    let ok = mm.store == id && {
                        let e = &self.rt.memories[mm.index as usize];
                        limits_fit((e.data.len() / PAGE) as u32, e.declared_max, mt.limits)
                    };
                    memory = Some(mm.index);
                    (mm.store, ok)
                }
                (ExternType::Global(gt), Extern::Global(g)) => {
                    let ok = g.store == id && self.rt.globals[g.index as usize].ty == *gt;
                    globals.push(g.index);
                    (g.store, ok)
                }
                _ => (id, false),
            };
            if store != id {
                return Err(bad("import from another store"));
            }
            if !fits {
                return Err(bad("incompatible import type"));
            }
        }
        // Over a limit is checked before anything is allocated.
        for t in &m.tables[m.imported_tables as usize..] {
            if t.limits.min > self.rt.limits.max_table_elements {
                return Err(InstantiateError::Limit("max_table_elements"));
            }
        }
        if let (Some(mt), false) = (m.memory, m.memory_imported) {
            if mt.limits.min > self.rt.max_pages() {
                return Err(InstantiateError::Limit("max_memory"));
            }
        }
        let inst = self.rt.instances.len() as u32;
        let types: Box<[u32]> = m.types.iter().map(|t| self.rt.intern(t)).collect();
        for (def, &ty) in m.funcs[m.imported_funcs as usize..].iter().enumerate() {
            funcs.push(self.rt.funcs.len() as u32);
            self.rt.funcs.push(FuncEntity {
                ty: types[ty as usize],
                kind: FuncKind::Wasm {
                    inst,
                    def: def as u32,
                },
            });
        }
        for &t in &m.tables[m.imported_tables as usize..] {
            tables.push(self.add_table(t, 0).index);
        }
        if let (Some(mt), false) = (m.memory, m.memory_imported) {
            memory = Some(self.add_memory(mt).index);
        }
        for (k, &ty) in m.globals[m.imported_globals as usize..].iter().enumerate() {
            let value = self.rt.eval(&m.global_inits[k], &funcs, &globals);
            globals.push(self.rt.globals.len() as u32);
            self.rt.globals.push(GlobalEntity { value, ty });
        }
        let elems = m
            .elems
            .iter()
            .map(|e| {
                e.items
                    .iter()
                    .map(|x| self.rt.eval(x, &funcs, &globals))
                    .collect()
            })
            .collect();
        self.rt.segments.push(Segments {
            elems,
            data_dropped: vec![false; m.datas.len()],
        });
        self.rt.instances.push(InstanceData {
            module: Arc::clone(module),
            funcs: funcs.into(),
            tables: tables.into(),
            memory,
            globals: globals.into(),
            types,
        });
        if let Err(t) = self.initialize(inst, budget) {
            self.end_on(&t);
            return Err(InstantiateError::Trap(t));
        }
        Ok(Instance {
            store: id,
            index: inst,
        })
    }

    /// The active segments, in order, then the start function.
    fn initialize(&mut self, inst: u32, budget: &Budget) -> Result<(), Trap> {
        let module = Arc::clone(&self.rt.instances[inst as usize].module);
        let d = &self.rt.instances[inst as usize];
        let (tables, memory) = (d.tables.clone(), d.memory);
        let globals = d.globals.clone();
        let funcs = d.funcs.clone();
        for (k, seg) in module.elems.iter().enumerate() {
            match &seg.mode {
                SegmentMode::Passive => continue,
                SegmentMode::Declared => {}
                SegmentMode::Active { index, offset } => {
                    let off = self.rt.eval(offset, &funcs, &globals) as u32 as usize;
                    let items = &self.rt.segments[inst as usize].elems[k];
                    let t = &mut self.rt.tables[tables[*index as usize] as usize];
                    let end = off
                        .checked_add(items.len())
                        .filter(|&e| e <= t.elems.len())
                        .ok_or(Trap::TableOutOfBounds)?;
                    t.elems[off..end].copy_from_slice(items);
                }
            }
            self.rt.segments[inst as usize].elems[k] = Box::default();
        }
        for (k, seg) in module.datas.iter().enumerate() {
            let SegmentMode::Active { offset, .. } = &seg.mode else {
                continue;
            };
            let off = self.rt.eval(offset, &funcs, &globals) as u32 as usize;
            let mem = match memory {
                Some(mm) => &mut self.rt.memories[mm as usize].data,
                None => return Err(Trap::MemoryOutOfBounds),
            };
            let end = off
                .checked_add(seg.bytes.len())
                .filter(|&e| e <= mem.len())
                .ok_or(Trap::MemoryOutOfBounds)?;
            mem[off..end].copy_from_slice(&seg.bytes);
            self.rt.segments[inst as usize].data_dropped[k] = true;
        }
        if let Some(f) = module.start {
            let f = funcs[f as usize];
            self.invoke(f, &[], &mut [], budget)?;
        }
        Ok(())
    }

    /// Calls `f` with `args`, writing its results to `results`, under `budget`.
    ///
    /// # Errors
    ///
    /// The [`Trap`] that stopped it, which ends the store; [`Trap::Ended`] if the store has
    /// ended; [`Trap::BadCall`] (nothing run, the store goes on) if `args` or `results` do not
    /// fit the function's type or `f` belongs to another store.
    pub fn call(
        &mut self,
        f: Func,
        args: &[Value],
        results: &mut [Value],
        budget: &Budget,
    ) -> Result<(), Trap> {
        if self.ended {
            return Err(Trap::Ended);
        }
        if f.store != self.rt.id {
            return Err(Trap::BadCall("a function of another store"));
        }
        let r = self.invoke(f.index, args, results, budget);
        if let Err(t) = &r {
            self.end_on(t);
        }
        r
    }

    fn invoke(
        &mut self,
        f: u32,
        args: &[Value],
        results: &mut [Value],
        budget: &Budget,
    ) -> Result<(), Trap> {
        let fe = self.rt.funcs[f as usize];
        let ty = self.rt.types[fe.ty as usize].clone();
        if args.len() != ty.params().len()
            || results.len() != ty.results().len()
            || args.iter().zip(ty.params()).any(|(a, &t)| a.ty() != t)
        {
            return Err(Trap::BadCall(
                "arguments or results do not fit the function's type",
            ));
        }
        self.fuel_used = 0;
        match fe.kind {
            FuncKind::Host(h) => {
                let host = Arc::clone(&self.hosts[h as usize]);
                for (r, &t) in results.iter_mut().zip(ty.results()) {
                    *r = Value::default_of(t);
                }
                let mut caller = Caller {
                    store: self,
                    instance: None,
                };
                host(&mut caller, args, results)?;
                if results.iter().zip(ty.results()).any(|(r, &t)| r.ty() != t) {
                    return Err(Trap::Host(
                        "a host function's result of the wrong type".into(),
                    ));
                }
                Ok(())
            }
            FuncKind::Wasm { inst, def } => {
                let module = &self.rt.instances[inst as usize].module;
                let c = &module.compiled[def as usize];
                let (frame, params, locals) =
                    (c.frame as usize, c.params as usize, c.locals as usize);
                if frame > self.rt.limits.max_value_stack as usize {
                    return Err(Trap::ValueStackExhausted);
                }
                if self.rt.stack.len() < frame {
                    self.rt.stack.resize(frame, 0);
                }
                for (k, a) in args.iter().enumerate() {
                    self.rt.stack[k] = a
                        .to_slot(self.rt.id)
                        .ok_or(Trap::BadCall("a function of another store"))?;
                }
                self.rt.stack[params..locals].fill(0);
                self.rt.frames.clear();
                self.rt.frames.push(Frame {
                    inst,
                    func: def,
                    pc: 0,
                    base: 0,
                });
                let mut meter = Meter::new(budget);
                let r = self.run(&mut meter);
                self.fuel_used = meter.used();
                self.rt.frames.clear();
                r?;
                for (k, (r, &t)) in results.iter_mut().zip(ty.results()).enumerate() {
                    *r = Value::from_slot(self.rt.stack[k], t, self.rt.id);
                }
                Ok(())
            }
        }
    }

    /// Runs the frames on the stack, calling host functions as they come.
    fn run(&mut self, meter: &mut Meter) -> Result<(), Trap> {
        loop {
            match self.rt.run(meter)? {
                Exit::Done => return Ok(()),
                Exit::Host {
                    host,
                    ty,
                    base,
                    inst,
                } => self.call_host(host, ty, base as usize, inst)?,
            }
        }
    }

    fn call_host(&mut self, host: u32, ty: u32, base: usize, inst: u32) -> Result<(), Trap> {
        let ty = self.rt.types[ty as usize].clone();
        let host = Arc::clone(&self.hosts[host as usize]);
        let mut args = std::mem::take(&mut self.args);
        let mut results = std::mem::take(&mut self.results);
        args.clear();
        results.clear();
        let id = self.rt.id;
        args.extend(
            ty.params()
                .iter()
                .enumerate()
                .map(|(k, &t)| Value::from_slot(self.rt.stack[base + k], t, id)),
        );
        results.extend(ty.results().iter().map(|&t| Value::default_of(t)));
        let mut caller = Caller {
            store: self,
            instance: Some(inst),
        };
        let r = host(&mut caller, &args, &mut results);
        let r = r.and_then(|()| {
            for (k, (v, &t)) in results.iter().zip(ty.results()).enumerate() {
                if v.ty() != t {
                    return Err(Trap::Host(
                        "a host function's result of the wrong type".into(),
                    ));
                }
                self.rt.stack[base + k] = v.to_slot(id).ok_or_else(|| {
                    Trap::Host("a host function's result from another store".into())
                })?;
            }
            Ok(())
        });
        self.args = args;
        self.results = results;
        r
    }
}
