//! Validating a function body: the specification's algorithm (its appendix, "Validation
//! Algorithm"), an operand stack of known or unknown types and a stack of control frames, in one
//! pass over the instructions.

use crate::{
    error::{Limit, Result, invalid, limit, malformed},
    module::Module,
    ops::{BlockType, Decoder, Op, natural_align},
    reader::Reader,
    types::{RefType, ValType},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Func,
    Block,
    Loop,
    If,
    Else,
}

#[derive(Debug, Clone, Copy)]
struct Ctrl {
    kind: Kind,
    ty: BlockType,
    /// Operand stack height at the frame's start.
    height: usize,
    /// The rest of the frame cannot be reached (after `br`, `return`, `unreachable` ...).
    unreachable: bool,
}

/// The locals of the function being validated: its parameters, then runs of declared locals.
#[derive(Debug, Default)]
pub(crate) struct Locals {
    params: Vec<ValType>,
    /// `(end, type)`: locals below `end` (counted from the first parameter) and at or past the
    /// previous run's end have type `type`.
    runs: Vec<(u32, ValType)>,
}

impl Locals {
    pub(crate) fn runs(&self) -> &[(u32, ValType)] {
        &self.runs
    }

    fn get(&self, i: u32) -> Option<ValType> {
        if let Some(t) = self.params.get(i as usize) {
            return Some(*t);
        }
        let k = self.runs.partition_point(|&(end, _)| end <= i);
        self.runs.get(k).map(|&(_, t)| t)
    }
}

/// What validating a body found, kept for translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BodyInfo {
    /// The highest the operand stack gets, in values.
    pub(crate) max_stack: u32,
}

/// Validates function bodies; reuses its stacks across functions.
#[derive(Debug, Default)]
pub(crate) struct Validator {
    vals: Vec<Option<ValType>>,
    ctrls: Vec<Ctrl>,
    decoder: Decoder,
    pub(crate) locals: Locals,
    max_stack: usize,
    /// `ModuleLimits::max_nesting`.
    pub(crate) max_nesting: u32,
    /// `ModuleLimits::max_br_table_targets`.
    pub(crate) max_br_targets: u32,
}

const fn one(t: ValType) -> &'static [ValType] {
    match t {
        ValType::I32 => &[ValType::I32],
        ValType::I64 => &[ValType::I64],
        ValType::F32 => &[ValType::F32],
        ValType::F64 => &[ValType::F64],
        ValType::FuncRef => &[ValType::FuncRef],
        ValType::ExternRef => &[ValType::ExternRef],
    }
}

/// The operand types and result type of a numeric instruction (`0x45..=0xc4`).
fn numeric_sig(op: u8) -> (&'static [ValType], ValType) {
    use ValType::{F32, F64, I32, I64};
    const I: &[ValType] = &[I32];
    const II: &[ValType] = &[I32, I32];
    const L: &[ValType] = &[I64];
    const LL: &[ValType] = &[I64, I64];
    const F: &[ValType] = &[F32];
    const FF: &[ValType] = &[F32, F32];
    const D: &[ValType] = &[F64];
    const DD: &[ValType] = &[F64, F64];
    match op {
        0x45 | 0x67..=0x69 | 0xc0 | 0xc1 => (I, I32),
        0x46..=0x4f | 0x6a..=0x78 => (II, I32),
        0x50 | 0xa7 => (L, I32),
        0x51..=0x5a => (LL, I32),
        0x5b..=0x60 => (FF, I32),
        0x61..=0x66 => (DD, I32),
        0x79..=0x7b | 0xc2..=0xc4 => (L, I64),
        0x7c..=0x8a => (LL, I64),
        0x8b..=0x91 => (F, F32),
        0x92..=0x98 => (FF, F32),
        0x99..=0x9f => (D, F64),
        0xa0..=0xa6 => (DD, F64),
        0xa8 | 0xa9 | 0xbc => (F, I32),
        0xaa | 0xab => (D, I32),
        0xac | 0xad => (I, I64),
        0xae | 0xaf => (F, I64),
        0xb0 | 0xb1 | 0xbd => (D, I64),
        0xb2 | 0xb3 | 0xbe => (I, F32),
        0xb4 | 0xb5 => (L, F32),
        0xb6 => (D, F32),
        0xb7 | 0xb8 => (I, F64),
        0xb9 | 0xba | 0xbf => (L, F64),
        _ => (F, F64), // 0xbb f64.promote_f32
    }
}

const fn load_type(op: u8) -> ValType {
    match op {
        0x28 | 0x2c..=0x2f => ValType::I32,
        0x2a => ValType::F32,
        0x2b => ValType::F64,
        _ => ValType::I64,
    }
}

const fn store_type(op: u8) -> ValType {
    match op {
        0x36 | 0x3a | 0x3b => ValType::I32,
        0x38 => ValType::F32,
        0x39 => ValType::F64,
        _ => ValType::I64,
    }
}

/// The type checks of one body, with the module and the instruction's offset at hand.
struct Run<'v, 'm> {
    v: &'v mut Validator,
    m: &'m Module,
    at: usize,
}

impl<'m> Run<'_, 'm> {
    fn mismatch(&self) -> crate::error::Error {
        invalid(self.at, "type mismatch")
    }

    fn params(&self, ty: BlockType) -> &'m [ValType] {
        match ty {
            BlockType::Func(i) => self.m.types[i as usize].params(),
            _ => &[],
        }
    }

    fn results(&self, ty: BlockType) -> &'m [ValType] {
        match ty {
            BlockType::Empty => &[],
            BlockType::Value(t) => one(t),
            BlockType::Func(i) => self.m.types[i as usize].results(),
        }
    }

    fn label_types(&self, c: &Ctrl) -> &'m [ValType] {
        if c.kind == Kind::Loop {
            self.params(c.ty)
        } else {
            self.results(c.ty)
        }
    }

    fn push(&mut self, t: Option<ValType>) {
        self.v.vals.push(t);
        self.v.max_stack = self.v.max_stack.max(self.v.vals.len());
    }

    fn push_all(&mut self, ts: &[ValType]) {
        for &t in ts {
            self.push(Some(t));
        }
    }

    fn pop(&mut self) -> Result<Option<ValType>> {
        let Some(c) = self.v.ctrls.last() else {
            return Err(self.mismatch());
        };
        if self.v.vals.len() == c.height {
            return if c.unreachable {
                Ok(None)
            } else {
                Err(self.mismatch())
            };
        }
        self.v.vals.pop().ok_or_else(|| self.mismatch())
    }

    fn pop_expect(&mut self, want: ValType) -> Result<Option<ValType>> {
        let got = self.pop()?;
        match got {
            Some(t) if t != want => Err(self.mismatch()),
            _ => Ok(got),
        }
    }

    fn pop_all(&mut self, ts: &[ValType]) -> Result<()> {
        for &t in ts.iter().rev() {
            self.pop_expect(t)?;
        }
        Ok(())
    }

    /// Checks the top of the stack against `ts` and leaves it as it is:
    /// `push_vals(pop_vals(ts))` of the specification, without moving anything.
    fn check_top(&self, ts: &[ValType]) -> Result<()> {
        let Some(c) = self.v.ctrls.last() else {
            return Err(self.mismatch());
        };
        let len = self.v.vals.len();
        for (k, &want) in ts.iter().rev().enumerate() {
            // The value `k` below the top, if the frame has it.
            if len - c.height <= k {
                return if c.unreachable {
                    Ok(())
                } else {
                    Err(self.mismatch())
                };
            }
            if self.v.vals[len - 1 - k].is_some_and(|t| t != want) {
                return Err(self.mismatch());
            }
        }
        Ok(())
    }

    fn push_ctrl(&mut self, kind: Kind, ty: BlockType) -> Result<()> {
        if self.v.ctrls.len() >= self.v.max_nesting as usize {
            return Err(limit(self.at, Limit::Nesting, "blocks nested too deep"));
        }
        let height = self.v.vals.len();
        self.v.ctrls.push(Ctrl {
            kind,
            ty,
            height,
            unreachable: false,
        });
        let params = self.params(ty);
        self.push_all(params);
        Ok(())
    }

    fn pop_ctrl(&mut self) -> Result<Ctrl> {
        let Some(&c) = self.v.ctrls.last() else {
            return Err(self.mismatch());
        };
        let results = self.results(c.ty);
        self.pop_all(results)?;
        if self.v.vals.len() != c.height {
            return Err(self.mismatch());
        }
        self.v.ctrls.pop();
        Ok(c)
    }

    fn set_unreachable(&mut self) {
        if let Some(c) = self.v.ctrls.last_mut() {
            self.v.vals.truncate(c.height);
            c.unreachable = true;
        }
    }

    fn label(&self, depth: u32) -> Result<Ctrl> {
        let n = self.v.ctrls.len();
        if depth as usize >= n {
            return Err(invalid(self.at, "unknown label"));
        }
        Ok(self.v.ctrls[n - 1 - depth as usize])
    }

    fn block_type(&self, ty: BlockType) -> Result<()> {
        if let BlockType::Func(i) = ty {
            if i as usize >= self.m.types.len() {
                return Err(invalid(self.at, "unknown type"));
            }
        }
        Ok(())
    }

    fn need_memory(&self) -> Result<()> {
        if self.m.memory.is_none() {
            return Err(invalid(self.at, "unknown memory 0"));
        }
        Ok(())
    }

    fn table(&self, t: u32) -> Result<RefType> {
        self.m
            .tables
            .get(t as usize)
            .map(|t| t.elem)
            .ok_or_else(|| invalid(self.at, "unknown table"))
    }

    fn elem(&self, e: u32) -> Result<RefType> {
        self.m
            .elems
            .get(e as usize)
            .map(|e| e.ty)
            .ok_or_else(|| invalid(self.at, "unknown elem segment"))
    }

    fn data(&self, d: u32) -> Result<()> {
        let Some(n) = self.m.data_count else {
            return Err(malformed(self.at, "data count section required"));
        };
        if d >= n {
            return Err(invalid(self.at, "unknown data segment"));
        }
        Ok(())
    }

    fn op(&mut self, op: Op) -> Result<()> {
        use ValType::{FuncRef, I32, I64};
        match op {
            Op::Unreachable => self.set_unreachable(),
            Op::Nop => {}
            Op::Block(ty) | Op::Loop(ty) => {
                self.block_type(ty)?;
                let params = self.params(ty);
                self.pop_all(params)?;
                let kind = if matches!(op, Op::Loop(_)) {
                    Kind::Loop
                } else {
                    Kind::Block
                };
                self.push_ctrl(kind, ty)?;
            }
            Op::If(ty) => {
                self.block_type(ty)?;
                self.pop_expect(I32)?;
                let params = self.params(ty);
                self.pop_all(params)?;
                self.push_ctrl(Kind::If, ty)?;
            }
            Op::Else => {
                let c = self.pop_ctrl()?;
                if c.kind != Kind::If {
                    return Err(invalid(self.at, "else without if"));
                }
                self.push_ctrl(Kind::Else, c.ty)?;
            }
            Op::End => {
                let c = self.pop_ctrl()?;
                if c.kind == Kind::If {
                    // No else: the missing branch passes its parameters on as its results.
                    self.push_ctrl(Kind::Else, c.ty)?;
                    self.pop_ctrl()?;
                }
                if c.kind != Kind::Func {
                    let results = self.results(c.ty);
                    self.push_all(results);
                }
            }
            Op::Br(l) => {
                let c = self.label(l)?;
                let ts = self.label_types(&c);
                self.pop_all(ts)?;
                self.set_unreachable();
            }
            Op::BrIf(l) => {
                self.pop_expect(I32)?;
                let c = self.label(l)?;
                let ts = self.label_types(&c);
                // [t* i32] -> [t*]: what follows sees the label's types, even after
                // `unreachable` (not the unknown values popped).
                self.pop_all(ts)?;
                self.push_all(ts);
            }
            Op::BrTable => {
                self.pop_expect(I32)?;
                let targets = std::mem::take(&mut self.v.decoder.br_targets);
                let r = self.br_table(&targets);
                self.v.decoder.br_targets = targets;
                r?;
                self.set_unreachable();
            }
            Op::Return => {
                let c = self.v.ctrls[0];
                let ts = self.results(c.ty);
                self.pop_all(ts)?;
                self.set_unreachable();
            }
            Op::Call(f) => {
                let ty = self
                    .m
                    .funcs
                    .get(f as usize)
                    .ok_or_else(|| invalid(self.at, "unknown function"))?;
                let ft = &self.m.types[*ty as usize];
                self.pop_all(ft.params())?;
                self.push_all(ft.results());
            }
            Op::CallIndirect { ty, table } => {
                if self.table(table)? != RefType::FuncRef {
                    return Err(self.mismatch());
                }
                let ft = self
                    .m
                    .types
                    .get(ty as usize)
                    .ok_or_else(|| invalid(self.at, "unknown type"))?;
                self.pop_expect(I32)?;
                self.pop_all(ft.params())?;
                self.push_all(ft.results());
            }
            Op::Drop => {
                self.pop()?;
            }
            Op::Select(None) => {
                self.pop_expect(I32)?;
                let a = self.pop()?;
                let b = self.pop()?;
                if a.is_some_and(ValType::is_ref) || b.is_some_and(ValType::is_ref) {
                    return Err(self.mismatch());
                }
                match (a, b) {
                    (Some(x), Some(y)) if x != y => return Err(self.mismatch()),
                    _ => self.push(a.or(b)),
                }
            }
            Op::Select(Some(t)) => {
                self.pop_expect(I32)?;
                self.pop_expect(t)?;
                self.pop_expect(t)?;
                self.push(Some(t));
            }
            Op::LocalGet(i) => {
                let t = self.local(i)?;
                self.push(Some(t));
            }
            Op::LocalSet(i) => {
                let t = self.local(i)?;
                self.pop_expect(t)?;
            }
            Op::LocalTee(i) => {
                let t = self.local(i)?;
                self.pop_expect(t)?;
                self.push(Some(t));
            }
            Op::GlobalGet(g) => {
                let t = self.global(g)?.val;
                self.push(Some(t));
            }
            Op::GlobalSet(g) => {
                let gt = self.global(g)?;
                if !gt.mutable {
                    return Err(invalid(self.at, "global is immutable"));
                }
                self.pop_expect(gt.val)?;
            }
            Op::TableGet(t) => {
                let et = self.table(t)?;
                self.pop_expect(I32)?;
                self.push(Some(et.into()));
            }
            Op::TableSet(t) => {
                let et = self.table(t)?;
                self.pop_expect(et.into())?;
                self.pop_expect(I32)?;
            }
            Op::Load(op, arg) => {
                self.need_memory()?;
                if arg.align > natural_align(op) {
                    return Err(invalid(
                        self.at,
                        "alignment must not be larger than natural",
                    ));
                }
                self.pop_expect(I32)?;
                self.push(Some(load_type(op)));
            }
            Op::Store(op, arg) => {
                self.need_memory()?;
                if arg.align > natural_align(op) {
                    return Err(invalid(
                        self.at,
                        "alignment must not be larger than natural",
                    ));
                }
                self.pop_expect(store_type(op))?;
                self.pop_expect(I32)?;
            }
            Op::MemorySize => {
                self.need_memory()?;
                self.push(Some(I32));
            }
            Op::MemoryGrow => {
                self.need_memory()?;
                self.pop_expect(I32)?;
                self.push(Some(I32));
            }
            Op::I32Const(_) => self.push(Some(I32)),
            Op::I64Const(_) => self.push(Some(I64)),
            Op::F32Const(_) => self.push(Some(ValType::F32)),
            Op::F64Const(_) => self.push(Some(ValType::F64)),
            Op::Numeric(op) => {
                let (args, result) = numeric_sig(op);
                self.pop_all(args)?;
                self.push(Some(result));
            }
            Op::TruncSat(k) => {
                let from = if k & 2 == 0 {
                    ValType::F32
                } else {
                    ValType::F64
                };
                let to = if k < 4 { I32 } else { I64 };
                self.pop_expect(from)?;
                self.push(Some(to));
            }
            Op::RefNull(t) => self.push(Some(t.into())),
            Op::RefIsNull => {
                if self.pop()?.is_some_and(|t| !t.is_ref()) {
                    return Err(self.mismatch());
                }
                self.push(Some(I32));
            }
            Op::RefFunc(f) => {
                if f as usize >= self.m.funcs.len() {
                    return Err(invalid(self.at, "unknown function"));
                }
                if !self.m.declared.get(f as usize).copied().unwrap_or(false) {
                    return Err(invalid(self.at, "undeclared function reference"));
                }
                self.push(Some(FuncRef));
            }
            Op::MemoryInit(d) => {
                self.need_memory()?;
                self.data(d)?;
                self.pop_all(&[I32, I32, I32])?;
            }
            Op::DataDrop(d) => self.data(d)?,
            Op::MemoryCopy | Op::MemoryFill => {
                self.need_memory()?;
                self.pop_all(&[I32, I32, I32])?;
            }
            Op::TableInit { elem, table } => {
                let tt = self.table(table)?;
                if self.elem(elem)? != tt {
                    return Err(self.mismatch());
                }
                self.pop_all(&[I32, I32, I32])?;
            }
            Op::ElemDrop(e) => {
                self.elem(e)?;
            }
            Op::TableCopy { dst, src } => {
                let d = self.table(dst)?;
                if self.table(src)? != d {
                    return Err(self.mismatch());
                }
                self.pop_all(&[I32, I32, I32])?;
            }
            Op::TableGrow(t) => {
                let et = self.table(t)?;
                self.pop_expect(I32)?;
                self.pop_expect(et.into())?;
                self.push(Some(I32));
            }
            Op::TableSize(t) => {
                self.table(t)?;
                self.push(Some(I32));
            }
            Op::TableFill(t) => {
                let et = self.table(t)?;
                self.pop_expect(I32)?;
                self.pop_expect(et.into())?;
                self.pop_expect(I32)?;
            }
        }
        Ok(())
    }

    fn br_table(&mut self, targets: &[u32]) -> Result<()> {
        let Some((&default, rest)) = targets.split_last() else {
            return Err(malformed(self.at, "unexpected end"));
        };
        let d = self.label(default)?;
        let arity = self.label_types(&d).len();
        for &l in rest {
            let c = self.label(l)?;
            let ts = self.label_types(&c);
            if ts.len() != arity {
                return Err(self.mismatch());
            }
            self.check_top(ts)?;
        }
        let ts = self.label_types(&d);
        self.pop_all(ts)
    }

    fn local(&self, i: u32) -> Result<ValType> {
        self.v
            .locals
            .get(i)
            .ok_or_else(|| invalid(self.at, "unknown local"))
    }

    fn global(&self, g: u32) -> Result<crate::types::GlobalType> {
        self.m
            .globals
            .get(g as usize)
            .copied()
            .ok_or_else(|| invalid(self.at, "unknown global"))
    }
}

impl Validator {
    pub(crate) fn new(limits: &crate::ModuleLimits) -> Self {
        Self {
            max_nesting: limits.max_nesting,
            max_br_targets: limits.max_br_table_targets,
            ..Self::default()
        }
    }

    /// Reads the locals of a body (after its size), checked against `max_locals`; the
    /// parameters come from the function's type.
    pub(crate) fn read_locals(
        &mut self,
        r: &mut Reader<'_>,
        params: &[ValType],
        max_locals: u32,
    ) -> Result<()> {
        self.locals.params.clear();
        self.locals.params.extend_from_slice(params);
        self.locals.runs.clear();
        let at = r.offset();
        let groups = r.count(2)?;
        // Summed over all groups first: a count past `u32::MAX` is malformed, whatever the
        // limit (the groups are at most the body's bytes).
        let mut total = params.len() as u64;
        for _ in 0..groups {
            let n = r.u32()?;
            total += u64::from(n);
            let t = ValType::read(r)?;
            if n > 0 {
                let end = u32::try_from(total).unwrap_or(u32::MAX);
                self.locals.runs.push((end, t));
            }
        }
        if total > u64::from(u32::MAX) {
            return Err(malformed(at, "too many locals"));
        }
        if total > u64::from(max_locals) {
            return Err(limit(at, Limit::Locals, "too many locals"));
        }
        Ok(())
    }

    /// Validates the instructions of the body of a function of type `ty` (after its locals);
    /// `r` holds exactly the body.
    pub(crate) fn body(&mut self, m: &Module, r: &mut Reader<'_>, ty: u32) -> Result<BodyInfo> {
        self.vals.clear();
        self.ctrls.clear();
        self.max_stack = 0;
        let max_br = self.max_br_targets;
        let mut run = Run {
            v: self,
            m,
            at: r.offset(),
        };
        run.push_ctrl(Kind::Func, BlockType::Func(ty))?;
        // The parameters are locals, not operands.
        run.v.vals.clear();
        run.v.max_stack = 0;
        loop {
            run.at = r.offset();
            let op = run.v.decoder.read(r, max_br)?;
            run.op(op)?;
            if run.v.ctrls.is_empty() {
                break;
            }
        }
        if !r.is_empty() {
            return Err(malformed(r.offset(), "section size mismatch"));
        }
        Ok(BodyInfo {
            max_stack: u32::try_from(self.max_stack).unwrap_or(u32::MAX),
        })
    }
}
