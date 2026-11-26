//! Translating a validated function body into the register form ([`crate::instr`]), in one pass
//! over its instructions (ADR-125, section 1).
//!
//! The translator follows WebAssembly's operand stack with a stack of its own whose entries say
//! where each value is: in its own slot, still in a local (`local.get` copies nothing until the
//! local changes or the value must sit in its slot), or a constant (an immediate when the
//! instruction has an immediate form). Every position of the operand stack has its slot, so
//! values never move but at branches whose label's values sit lower in the stack, and a call's
//! arguments are already where the callee's frame begins.
//!
//! Each basic block that a branch can reach starts with a `Fuel` instruction carrying the number
//! of WebAssembly instructions up to the next one; loops start one, so every back edge is metered.
//!
//! Bounded output: every WebAssembly instruction emits at most three instructions, counting the
//! materialization of the value it pushed, so the code is at most `4 * bytes + 4` instructions.

use crate::{
    error::{Result, invalid},
    instr::{BinOp, Cmp, Instr, Mem, Un, thread_fuel},
    module::Module,
    ops::{BlockType, Decoder, Op},
    reader::Reader,
    types::FuncType,
};

/// A function translated to the register form.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Compiled {
    pub(crate) code: Box<[Instr]>,
    /// Parameters, the first locals.
    pub(crate) params: u32,
    /// Locals, parameters included.
    pub(crate) locals: u32,
    /// Slots in a frame: locals, then the operand stack.
    pub(crate) frame: u32,
}

/// Where a value of the operand stack is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V {
    /// In its own slot.
    Slot,
    /// Still in this local.
    Local(u32),
    /// This constant (a slot's bits).
    Const(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Func,
    Block,
    Loop,
    If,
    Else,
}

const NONE: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
struct Ctl {
    kind: Kind,
    /// Operand stack height at the start, below the parameters.
    height: u32,
    params: u32,
    results: u32,
    /// A loop's first instruction, where branches to it go.
    start: u32,
    /// The branches to patch when the end is reached: a list through `Translator::fixups`.
    fixups: u32,
    /// An `if`'s branch to its `else` (or its end), to patch.
    if_branch: u32,
    unreachable: bool,
}

/// A branch condition, from a value or a fused comparison.
#[derive(Debug, Clone, Copy)]
enum Cond {
    Nz(u32),
    Z(u32),
    C32(Cmp, u32, u32),
    C32I(Cmp, u32, i32),
    C64(Cmp, u32, u32),
    C64I(Cmp, u32, i32),
}

impl Cond {
    const fn negate(self) -> Self {
        match self {
            Self::Nz(c) => Self::Z(c),
            Self::Z(c) => Self::Nz(c),
            Self::C32(op, a, b) => Self::C32(op.negate(), a, b),
            Self::C32I(op, a, i) => Self::C32I(op.negate(), a, i),
            Self::C64(op, a, b) => Self::C64(op.negate(), a, b),
            Self::C64I(op, a, i) => Self::C64I(op.negate(), a, i),
        }
    }

    const fn branch(self, t: u32) -> Instr {
        match self {
            Self::Nz(c) => Instr::BrIfNz { c, t, n: 0, f: 0 },
            Self::Z(c) => Instr::BrIfZ { c, t, n: 0, f: 0 },
            Self::C32(op, a, b) => Instr::BrCmp32 { op, n: 0, a, b, t },
            Self::C32I(op, a, imm) => Instr::BrCmp32I {
                op,
                n: 0,
                a,
                imm,
                t,
            },
            Self::C64(op, a, b) => Instr::BrCmp64 { op, n: 0, a, b, t },
            Self::C64I(op, a, imm) => Instr::BrCmp64I {
                op,
                n: 0,
                a,
                imm,
                t,
            },
        }
    }
}

/// Translates function bodies; reuses its buffers across the functions of a module.
#[derive(Debug, Default)]
pub(crate) struct Translator {
    code: Vec<Instr>,
    vals: Vec<V>,
    /// Positions of `vals` that may hold a `Local` or a `Const`, ascending (some may be stale).
    lazy: Vec<u32>,
    /// For each local, how many `Local` entries of `vals` name it.
    local_refs: Vec<u32>,
    ctls: Vec<Ctl>,
    /// `(instruction, next)`: the lists of branches waiting for a label.
    fixups: Vec<(u32, u32)>,
    /// `br_table` entries that need a stub: `(entry, label depth)`.
    stubs: Vec<(u32, u32)>,
    decoder: Decoder,
    locals: u32,
    /// The current basic block's `Fuel` instruction and its count so far.
    fuel_at: usize,
    count: u32,
    /// The last instruction, if it wrote the value on top of the stack: `(index, position)`.
    last: Option<(usize, u32)>,
    /// Blocks opened in code that cannot be reached, being skipped.
    dead: u32,
    at: usize,
}

impl Translator {
    /// Translates the instructions of a validated body; `r` is at its first instruction.
    pub(crate) fn translate(
        &mut self,
        m: &Module,
        r: &mut Reader<'_>,
        ty: &FuncType,
        locals: u32,
        max_stack: u32,
    ) -> Result<Compiled> {
        let bytes = r.remaining();
        self.code.clear();
        self.vals.clear();
        self.lazy.clear();
        self.ctls.clear();
        self.fixups.clear();
        self.last = None;
        self.dead = 0;
        self.locals = locals;
        self.at = r.offset();
        if self.local_refs.len() < locals as usize {
            self.local_refs.resize(locals as usize, 0);
        }
        let params = ty.params().len() as u32;
        self.code.push(Instr::Fuel { n: 0 });
        self.fuel_at = 0;
        // Zeroing the declared locals on each call is work too: one unit per eight.
        self.count = (locals - params) / 8;
        self.ctls.push(Ctl {
            kind: Kind::Func,
            height: 0,
            params: 0,
            results: ty.results().len() as u32,
            start: 0,
            fixups: NONE,
            if_branch: NONE,
            unreachable: false,
        });
        while !self.ctls.is_empty() {
            self.at = r.offset();
            let op = self.decoder.read(r, u32::MAX)?;
            if self.top().unreachable {
                match op {
                    Op::Block(_) | Op::Loop(_) | Op::If(_) => self.dead += 1,
                    Op::Else if self.dead == 0 => self.else_()?,
                    Op::End if self.dead == 0 => self.end()?,
                    Op::End => self.dead -= 1,
                    _ => {}
                }
                continue;
            }
            self.count = self.count.saturating_add(1);
            self.op(m, op)?;
        }
        self.close_fuel();
        debug_assert!(self.local_refs[..locals as usize].iter().all(|&n| n == 0));
        if self.code.len() > 4 * bytes + 4 {
            return Err(invalid(self.at, "translated form too large"));
        }
        thread_fuel(&mut self.code);
        Ok(Compiled {
            code: self.code.as_slice().into(),
            params,
            locals,
            frame: locals.saturating_add(max_stack),
        })
    }

    fn top(&self) -> &Ctl {
        // Never empty while translating.
        &self.ctls[self.ctls.len() - 1]
    }

    fn top_mut(&mut self) -> &mut Ctl {
        let n = self.ctls.len() - 1;
        &mut self.ctls[n]
    }

    fn err(&self) -> crate::error::Error {
        invalid(self.at, "type mismatch")
    }

    fn slot(&self, pos: u32) -> u32 {
        self.locals + pos
    }

    fn len(&self) -> u32 {
        self.vals.len() as u32
    }

    fn emit(&mut self, i: Instr) -> usize {
        self.code.push(i);
        self.code.len() - 1
    }

    /// Emits an instruction that writes one value to the next position, and pushes it.
    fn emit_result(&mut self, i: Instr) {
        let pc = self.emit(i);
        let pos = self.len();
        self.vals.push(V::Slot);
        self.last = Some((pc, pos));
    }

    fn emit_const(&mut self, d: u32, v: u64) {
        match u32::try_from(v) {
            Ok(v) => self.emit(Instr::Const32 { d, v }),
            Err(_) => self.emit(Instr::Const64 { d, v }),
        };
    }

    fn push_lazy(&mut self, v: V) {
        let p = self.len();
        while self.lazy.last().is_some_and(|&q| q >= p) {
            self.lazy.pop();
        }
        self.lazy.push(p);
        if let V::Local(i) = v {
            self.local_refs[i as usize] += 1;
        }
        self.vals.push(v);
    }

    fn pop(&mut self) -> Result<(V, u32)> {
        let v = self.vals.pop().ok_or_else(|| self.err())?;
        if let V::Local(i) = v {
            self.local_refs[i as usize] -= 1;
        }
        Ok((v, self.len()))
    }

    /// Drops values down to `height`.
    fn truncate(&mut self, height: u32) {
        while self.len() > height {
            if let Some(V::Local(i)) = self.vals.pop() {
                self.local_refs[i as usize] -= 1;
            }
        }
    }

    /// The slot to read a popped value from; a constant is written to its position's slot.
    fn operand(&mut self, v: V, pos: u32) -> u32 {
        match v {
            V::Slot => self.slot(pos),
            V::Local(i) => i,
            V::Const(c) => {
                let d = self.slot(pos);
                self.emit_const(d, c);
                d
            }
        }
    }

    /// Puts the value at `pos` (below the top) in its own slot.
    fn materialize(&mut self, pos: u32) {
        let d = self.slot(pos);
        match self.vals[pos as usize] {
            V::Slot => return,
            V::Local(i) => {
                self.local_refs[i as usize] -= 1;
                self.emit(Instr::Copy { d, s: i });
            }
            V::Const(c) => self.emit_const(d, c),
        }
        self.vals[pos as usize] = V::Slot;
    }

    /// Puts every value in its own slot.
    fn flush_all(&mut self) {
        let lazy = std::mem::take(&mut self.lazy);
        for &p in &lazy {
            if p < self.len() {
                self.materialize(p);
            }
        }
        self.lazy = lazy;
        self.lazy.clear();
    }

    /// Puts the top `n` values in their own slots.
    fn flush_top(&mut self, n: u32) {
        let lo = self.len().saturating_sub(n);
        while let Some(&p) = self.lazy.last() {
            if p < lo {
                break;
            }
            self.lazy.pop();
            if p < self.len() {
                self.materialize(p);
            }
        }
    }

    fn set_unreachable(&mut self) {
        let h = self.top().height;
        self.truncate(h);
        self.top_mut().unreachable = true;
        self.last = None;
    }

    /// Ends the current basic block's count and starts a new one here.
    fn close_fuel(&mut self) {
        let n = self.count;
        self.code[self.fuel_at] = Instr::Fuel { n };
        self.count = 0;
    }

    /// A branch target that starts a basic block: a `Fuel` instruction, whose index it is.
    fn bind_fuel(&mut self) -> u32 {
        self.close_fuel();
        self.fuel_at = self.emit(Instr::Fuel { n: 0 });
        self.last = None;
        self.fuel_at as u32
    }

    fn patch(&mut self, pc: u32, t: u32) -> Result<()> {
        if self.code[pc as usize].set_target(t) {
            Ok(())
        } else {
            Err(invalid(self.at, "translation: not a branch"))
        }
    }

    fn block_arity(m: &Module, ty: BlockType) -> (u32, u32) {
        match ty {
            BlockType::Empty => (0, 0),
            BlockType::Value(_) => (0, 1),
            BlockType::Func(i) => {
                let t = &m.types[i as usize];
                (t.params().len() as u32, t.results().len() as u32)
            }
        }
    }

    fn ctl_at(&self, depth: u32) -> Result<(usize, Ctl)> {
        let n = self.ctls.len();
        if depth as usize >= n {
            return Err(invalid(self.at, "unknown label"));
        }
        let k = n - 1 - depth as usize;
        Ok((k, self.ctls[k]))
    }

    /// The values a branch to `c` carries.
    const fn label_arity(c: &Ctl) -> u32 {
        if matches!(c.kind, Kind::Loop) {
            c.params
        } else {
            c.results
        }
    }

    /// Pops a condition; a comparison the last instruction made is fused into the branch.
    fn pop_cond(&mut self) -> Result<Cond> {
        let (v, pos) = self.pop()?;
        if v == V::Slot {
            if let Some((pc, p)) = self.last {
                if p == pos && pc + 1 == self.code.len() {
                    let d = self.slot(pos);
                    let fused = match self.code[pc] {
                        Instr::I32Eqz(Un { d: x, a }) if x == d => Some(Cond::Z(a)),
                        Instr::I64Eqz(Un { d: x, a }) if x == d => Some(Cond::C64I(Cmp::Eq, a, 0)),
                        Instr::I32BinI {
                            op: BinOp::Cmp(c),
                            d: x,
                            a,
                            imm,
                        } if x == d => Some(Cond::C32I(c, a, imm)),
                        Instr::I64BinI {
                            op: BinOp::Cmp(c),
                            d: x,
                            a,
                            imm,
                        } if x == d => Some(Cond::C64I(c, a, imm)),
                        i => cmp_of(i, d),
                    };
                    if let Some(c) = fused {
                        self.code.pop();
                        self.last = None;
                        return Ok(self.not_not(c));
                    }
                }
            }
        }
        self.last = None;
        Ok(Cond::Nz(self.operand(v, pos)))
    }

    /// A branch on `x == 0` where `x` is the `eqz` of `y` that the instruction now last computed
    /// into a slot of the operand stack (read by nothing else): a branch on `y != 0`, the last
    /// instruction dropped. Go's `wasm` code tests a `bool` so (`i64.eqz`, `i64.extend_i32_u`,
    /// `i64.eqz`, `br_if`).
    fn not_not(&mut self, c: Cond) -> Cond {
        let (Cond::Z(x) | Cond::C64I(Cmp::Eq, x, 0)) = c else {
            return c;
        };
        if x < self.locals {
            return c;
        }
        let inner = match self.code.last() {
            Some(&Instr::I32Eqz(Un { d, a })) if d == x => Cond::Nz(a),
            Some(&Instr::I64Eqz(Un { d, a })) if d == x => Cond::C64I(Cmp::Ne, a, 0),
            _ => return c,
        };
        self.code.pop();
        inner
    }

    /// The slot of a load's or store's address, the value `v` at `pos`: when the last instruction
    /// is the `i32.wrap_i64` that put it there, the wrap's operand instead, the wrap dropped (an
    /// address is read as its low 32 bits anyway). Nothing runs between the wrap and the access,
    /// and no branch lands between them (every branch target starts with a `Fuel`, or follows
    /// the branch that made it).
    fn address(&mut self, v: V, pos: u32) -> u32 {
        if v == V::Slot {
            let s = self.slot(pos);
            if let Some(&Instr::I32WrapI64(Un { d, a })) = self.code.last() {
                if d == s {
                    self.code.pop();
                    self.last = None;
                    return a;
                }
            }
        }
        self.operand(v, pos)
    }

    /// Copies the top `n` values (in their slots) to positions `dst..`.
    fn move_values(&mut self, n: u32, dst: u32) {
        let src = self.len() - n;
        if src == dst || n == 0 {
            return;
        }
        let (d, s) = (self.slot(dst), self.slot(src));
        if n == 1 {
            self.emit(Instr::Copy { d, s });
        } else {
            self.emit(Instr::CopyRange { d, s, n });
        }
    }

    /// Returns the top values; does not change the stack unless a constant must be written.
    fn ret(&mut self) {
        let n = self.ctls[0].results;
        let src = self.len() - n;
        match n {
            0 => {
                self.emit(Instr::Return0);
            }
            1 => match self.vals[src as usize] {
                V::Local(s) => {
                    self.emit(Instr::Return1 { s });
                }
                V::Const(v) => {
                    self.emit(Instr::Return1C { v });
                }
                V::Slot => {
                    let s = self.slot(src);
                    self.emit(Instr::Return1 { s });
                }
            },
            _ => {
                self.flush_top(n);
                let s = self.slot(src);
                self.emit(Instr::ReturnN { s, n });
            }
        }
    }

    /// An unconditional jump to label `k` (an index in `ctls`), its values already moved.
    fn jump_to(&mut self, k: usize) {
        let c = self.ctls[k];
        if c.kind == Kind::Loop {
            self.emit(Instr::Br { t: c.start, n: 0 });
        } else {
            let pc = self.emit(Instr::Br { t: NONE, n: 0 }) as u32;
            self.add_fixup(k, pc);
        }
    }

    fn add_fixup(&mut self, k: usize, pc: u32) {
        self.fixups.push((pc, self.ctls[k].fixups));
        self.ctls[k].fixups = (self.fixups.len() - 1) as u32;
    }

    /// A conditional branch to label `depth`.
    fn br_if(&mut self, depth: u32) -> Result<()> {
        let cond = self.pop_cond()?;
        let (k, c) = self.ctl_at(depth)?;
        let n = if c.kind == Kind::Func {
            c.results
        } else {
            Self::label_arity(&c)
        };
        if self.len() < n {
            return Err(self.err());
        }
        self.flush_top(n);
        let src = self.len() - n;
        if c.kind == Kind::Loop && (src == c.height || n == 0) {
            self.emit(cond.branch(c.start));
        } else if c.kind != Kind::Func && c.kind != Kind::Loop && (src == c.height || n == 0) {
            let pc = self.emit(cond.branch(NONE)) as u32;
            self.add_fixup(k, pc);
        } else {
            // Branch over the moves when the condition is false.
            let skip = self.emit(cond.negate().branch(NONE)) as u32;
            if c.kind == Kind::Func {
                self.ret();
            } else {
                self.move_values(n, c.height);
                self.jump_to(k);
            }
            let here = self.code.len() as u32;
            self.patch(skip, here)?;
        }
        self.last = None;
        Ok(())
    }

    fn br(&mut self, depth: u32) -> Result<()> {
        let (k, c) = self.ctl_at(depth)?;
        if c.kind == Kind::Func {
            self.ret();
        } else {
            let n = Self::label_arity(&c);
            if self.len() < n {
                return Err(self.err());
            }
            self.flush_top(n);
            self.move_values(n, c.height);
            self.jump_to(k);
        }
        self.set_unreachable();
        Ok(())
    }

    fn br_table(&mut self) -> Result<()> {
        let targets = std::mem::take(&mut self.decoder.br_targets);
        let r = self.br_table_with(&targets);
        self.decoder.br_targets = targets;
        r
    }

    fn br_table_with(&mut self, targets: &[u32]) -> Result<()> {
        let (v, pos) = self.pop()?;
        let s = self.operand(v, pos);
        let Some(&default) = targets.last() else {
            return Err(self.err());
        };
        let (_, d) = self.ctl_at(default)?;
        let n = if d.kind == Kind::Func {
            d.results
        } else {
            Self::label_arity(&d)
        };
        if self.len() < n {
            return Err(self.err());
        }
        self.flush_top(n);
        let src = self.len() - n;
        self.emit(Instr::BrTable {
            s,
            n: (targets.len() - 1) as u32,
        });
        self.stubs.clear();
        for &depth in targets {
            let (k, c) = self.ctl_at(depth)?;
            let direct = c.kind != Kind::Func && (n == 0 || src == c.height);
            if direct {
                self.jump_to(k);
            } else {
                let pc = self.emit(Instr::Br { t: NONE, n: 0 }) as u32;
                self.stubs.push((pc, depth));
            }
        }
        let stubs = std::mem::take(&mut self.stubs);
        for &(pc, depth) in &stubs {
            let here = self.code.len() as u32;
            self.patch(pc, here)?;
            let (k, c) = self.ctl_at(depth)?;
            if c.kind == Kind::Func {
                self.ret();
            } else {
                self.move_values(n, c.height);
                self.jump_to(k);
            }
        }
        self.stubs = stubs;
        self.set_unreachable();
        Ok(())
    }

    fn push_ctl(&mut self, kind: Kind, params: u32, results: u32, start: u32, if_branch: u32) {
        let height = self.len() - params;
        self.ctls.push(Ctl {
            kind,
            height,
            params,
            results,
            start,
            fixups: NONE,
            if_branch,
            unreachable: false,
        });
    }

    fn else_(&mut self) -> Result<()> {
        let c = *self.top();
        if c.kind != Kind::If {
            return Err(invalid(self.at, "else without if"));
        }
        if !c.unreachable {
            self.flush_top(c.results);
            let k = self.ctls.len() - 1;
            self.jump_to(k);
        }
        self.truncate(c.height);
        for _ in 0..c.params {
            self.vals.push(V::Slot);
        }
        let here = self.bind_fuel();
        if c.if_branch != NONE {
            self.patch(c.if_branch, here)?;
        }
        let t = self.top_mut();
        t.kind = Kind::Else;
        t.if_branch = NONE;
        t.unreachable = false;
        Ok(())
    }

    fn end(&mut self) -> Result<()> {
        let c = *self.top();
        if c.kind == Kind::Func {
            if !c.unreachable {
                if self.len() < c.results {
                    return Err(self.err());
                }
                self.ret();
            }
            self.truncate(0);
            self.ctls.pop();
            return Ok(());
        }
        let branched = c.fixups != NONE || c.if_branch != NONE;
        if c.kind == Kind::Loop || !branched {
            // Reached by falling through only: the values stay where they are.
            self.ctls.pop();
            if c.unreachable {
                self.set_unreachable();
            }
            return Ok(());
        }
        if !c.unreachable {
            if self.len() != c.height + c.results {
                return Err(self.err());
            }
            self.flush_top(c.results);
        }
        let here = self.bind_fuel();
        let mut f = c.fixups;
        while f != NONE {
            let (pc, next) = self.fixups[f as usize];
            self.patch(pc, here)?;
            f = next;
        }
        if c.if_branch != NONE {
            self.patch(c.if_branch, here)?;
        }
        self.truncate(c.height);
        for _ in 0..c.results {
            self.vals.push(V::Slot);
        }
        self.ctls.pop();
        Ok(())
    }

    /// A numeric instruction (`0x45..=0xc4`, or `0x100 + k` for `trunc_sat` `k`).
    fn numeric(&mut self, op: u16) -> Result<()> {
        if Instr::is_binary(op) {
            let (mut b, mut pb) = self.pop()?;
            let (mut a, mut pa) = self.pop()?;
            let int32 = matches!(op, 0x46..=0x4f | 0x6a..=0x78);
            let int64 = matches!(op, 0x51..=0x5a | 0x7c..=0x8a);
            if let (true, Some(bop)) = (int32 || int64, BinOp::of_opcode(op as u8)) {
                if matches!(a, V::Const(_)) && !matches!(b, V::Const(_)) && bop.commutes() {
                    // The constant second, as the immediate; each keeps its position.
                    std::mem::swap(&mut a, &mut b);
                    std::mem::swap(&mut pa, &mut pb);
                }
                if let V::Const(c) = b {
                    let imm = if int32 {
                        Some(c as u32 as i32)
                    } else {
                        i32::try_from(c as i64).ok()
                    };
                    if let Some(imm) = imm {
                        let d = self.slot(pa.min(pb));
                        let sa = self.operand(a, pa);
                        let i = if int32 {
                            Instr::I32BinI {
                                op: bop,
                                d,
                                a: sa,
                                imm,
                            }
                        } else {
                            Instr::I64BinI {
                                op: bop,
                                d,
                                a: sa,
                                imm,
                            }
                        };
                        self.emit_result(i);
                        return Ok(());
                    }
                }
            }
            let d = self.slot(pa.min(pb));
            let sa = self.operand(a, pa);
            let sb = self.operand(b, pb);
            let i = Instr::numeric(op, d, sa, sb).ok_or_else(|| self.err())?;
            self.emit_result(i);
        } else {
            if self.conversion(op)? {
                return Ok(());
            }
            let (a, pa) = self.pop()?;
            let d = self.slot(pa);
            let sa = self.operand(a, pa);
            let i = Instr::numeric(op, d, sa, 0).ok_or_else(|| self.err())?;
            self.emit_result(i);
        }
        Ok(())
    }

    /// The integer conversions done without an instruction: `i64.extend_i32_u` of any value (a
    /// slot holds an `i32` zero-extended, its bits are the `i64`'s), and every integer conversion
    /// of a constant (Go converts constants so). True if `op` was one.
    fn conversion(&mut self, op: u16) -> Result<bool> {
        let fold: fn(u64) -> u64 = match op {
            0xa7 => |c| c & 0xffff_ffff,                       // i32.wrap_i64
            0xac | 0xc4 => |c| i64::from(c as i32) as u64,     // i64.extend_i32_s, extend32_s
            0xad => |c| c & 0xffff_ffff,                       // i64.extend_i32_u
            0xc0 => |c| u64::from(i32::from(c as i8) as u32),  // i32.extend8_s
            0xc1 => |c| u64::from(i32::from(c as i16) as u32), // i32.extend16_s
            0xc2 => |c| i64::from(c as i8) as u64,             // i64.extend8_s
            0xc3 => |c| i64::from(c as i16) as u64,            // i64.extend16_s
            _ => return Ok(false),
        };
        match self.vals.last() {
            Some(&V::Const(c)) => {
                self.pop()?;
                self.push_lazy(V::Const(fold(c)));
                self.last = None;
                Ok(true)
            }
            // The value stays where it is, and the instruction that wrote it stays the last.
            Some(_) if op == 0xad => Ok(true),
            Some(_) => Ok(false),
            None => Err(self.err()),
        }
    }

    /// Pops `n` operands into their slots; returns the first one's slot.
    fn operands(&mut self, n: u32) -> Result<u32> {
        if self.len() < n {
            return Err(self.err());
        }
        self.flush_top(n);
        let base = self.len() - n;
        self.truncate(base);
        self.last = None;
        Ok(self.slot(base))
    }

    fn local_set(&mut self, i: u32, tee: bool) -> Result<()> {
        let (v, pos) = self.pop()?;
        if self.local_refs.get(i as usize).copied().unwrap_or(0) > 0 {
            // Values still read from the local must be copied before it changes.
            self.flush_all();
        }
        match v {
            V::Slot => {
                let s = self.slot(pos);
                let retarget = self.last.is_some_and(|(pc, p)| {
                    p == pos
                        && pc + 1 == self.code.len()
                        && self.code[pc].dest_mut().is_some_and(|d| *d == s)
                });
                if retarget {
                    if let Some(d) = self.code.last_mut().and_then(Instr::dest_mut) {
                        *d = i;
                    }
                    self.last = None;
                    if tee {
                        self.push_lazy(V::Local(i));
                    }
                    return Ok(());
                }
                self.emit(Instr::Copy { d: i, s });
            }
            V::Local(j) => {
                if j != i {
                    self.emit(Instr::Copy { d: i, s: j });
                }
            }
            V::Const(c) => self.emit_const(i, c),
        }
        self.last = None;
        if tee {
            match v {
                V::Slot => self.vals.push(V::Slot),
                v => self.push_lazy(v),
            }
        }
        Ok(())
    }

    fn op(&mut self, m: &Module, op: Op) -> Result<()> {
        match op {
            Op::Unreachable => {
                self.emit(Instr::Unreachable);
                self.set_unreachable();
            }
            Op::Nop => {}
            Op::Block(ty) => {
                let (p, r) = Self::block_arity(m, ty);
                self.flush_all();
                self.last = None;
                self.push_ctl(Kind::Block, p, r, 0, NONE);
            }
            Op::Loop(ty) => {
                let (p, r) = Self::block_arity(m, ty);
                self.flush_all();
                let start = self.bind_fuel();
                self.push_ctl(Kind::Loop, p, r, start, NONE);
            }
            Op::If(ty) => {
                let (p, r) = Self::block_arity(m, ty);
                let cond = self.pop_cond()?;
                self.flush_all();
                let pc = self.emit(cond.negate().branch(NONE)) as u32;
                self.push_ctl(Kind::If, p, r, 0, pc);
            }
            Op::Else => self.else_()?,
            Op::End => self.end()?,
            Op::Br(l) => self.br(l)?,
            Op::BrIf(l) => self.br_if(l)?,
            Op::BrTable => self.br_table()?,
            Op::Return => {
                if self.len() < self.ctls[0].results {
                    return Err(self.err());
                }
                self.ret();
                self.set_unreachable();
            }
            Op::Call(f) => {
                let ty = &m.types[*m.funcs.get(f as usize).ok_or_else(|| self.err())? as usize];
                let (p, r) = (ty.params().len() as u32, ty.results().len() as u32);
                let base = self.operands(p)?;
                if f < m.imported_funcs {
                    self.emit(Instr::CallImport { f, base });
                } else {
                    let f = f - m.imported_funcs;
                    // The first argument a constant written just now (the last written, as
                    // `flush_top` writes the lowest position last): one instruction.
                    match self.code.last() {
                        Some(&Instr::Const32 { d, v }) if p > 0 && d == base => {
                            self.code.pop();
                            self.emit(Instr::CallC { f, base, v });
                        }
                        _ => {
                            self.emit(Instr::Call { f, base });
                        }
                    }
                }
                for _ in 0..r {
                    self.vals.push(V::Slot);
                }
            }
            Op::CallIndirect { ty, table } => {
                let t = m.types.get(ty as usize).ok_or_else(|| self.err())?;
                let (p, r) = (t.params().len() as u32, t.results().len() as u32);
                let base = self.operands(p + 1)?;
                self.emit(Instr::CallIndirect { base, ty, table });
                for _ in 0..r {
                    self.vals.push(V::Slot);
                }
            }
            Op::Drop => {
                self.pop()?;
                self.last = None;
            }
            Op::Select(_) => {
                let (c, pc) = self.pop()?;
                let (b, pb) = self.pop()?;
                let (a, pa) = self.pop()?;
                let d = self.slot(pa);
                match a {
                    V::Slot => {}
                    V::Local(i) => {
                        self.emit(Instr::Copy { d, s: i });
                    }
                    V::Const(k) => self.emit_const(d, k),
                }
                let sb = self.operand(b, pb);
                let sc = self.operand(c, pc);
                self.emit(Instr::Select { d, b: sb, c: sc });
                self.vals.push(V::Slot);
                self.last = None;
            }
            Op::LocalGet(i) => {
                self.push_lazy(V::Local(i));
                self.last = None;
            }
            Op::LocalSet(i) => self.local_set(i, false)?,
            Op::LocalTee(i) => self.local_set(i, true)?,
            Op::GlobalGet(g) => {
                let d = self.slot(self.len());
                self.emit_result(Instr::GlobalGet { d, g });
            }
            Op::GlobalSet(g) => {
                let (v, p) = self.pop()?;
                // The value an `i32` add or subtract of an immediate wrote just now, to its slot
                // or to the local it is still read from: one instruction does both.
                let written = match v {
                    V::Slot => Some(self.slot(p)),
                    V::Local(l) => Some(l),
                    V::Const(_) => None,
                };
                let fused = match (written, self.code.last(), u16::try_from(g)) {
                    (
                        Some(w),
                        Some(&Instr::I32BinI {
                            op: op @ (BinOp::Add | BinOp::Sub),
                            d,
                            a,
                            imm,
                        }),
                        Ok(g),
                    ) if d == w => Some(Instr::I32AddGlobal {
                        g,
                        d,
                        a,
                        imm: if op == BinOp::Add {
                            imm
                        } else {
                            imm.wrapping_neg()
                        },
                    }),
                    _ => None,
                };
                if let Some(i) = fused {
                    self.code.pop();
                    self.emit(i);
                } else {
                    let s = self.operand(v, p);
                    self.emit(Instr::GlobalSet { s, g });
                }
                self.last = None;
            }
            Op::TableGet(t) => {
                let (v, p) = self.pop()?;
                let a = self.operand(v, p);
                let d = self.slot(p);
                self.emit_result(Instr::TableGet { d, a, t });
            }
            Op::TableSet(t) => {
                let (v, pv) = self.pop()?;
                let (a, pa) = self.pop()?;
                let sv = self.operand(v, pv);
                let sa = self.operand(a, pa);
                self.emit(Instr::TableSet { a: sa, v: sv, t });
                self.last = None;
            }
            Op::Load(code, arg) => {
                let (v, p) = self.pop()?;
                let a = self.address(v, p);
                let x = self.slot(p);
                let i = Instr::load(code, x, a, arg.offset).ok_or_else(|| self.err())?;
                self.emit_result(i);
            }
            Op::Store(code, arg) => {
                let (v, pv) = self.pop()?;
                let (a, pa) = self.pop()?;
                // The address first: the wrap it may drop is the last instruction only until
                // the value's constant is written (to another slot: the wrap's operand stays).
                let sa = self.address(a, pa);
                let i = match (v, store_imm(code)) {
                    (V::Const(c), Some((width, wide)))
                        if width < 8 || !wide || i32::try_from(c as i64).is_ok() =>
                    {
                        let m = Mem {
                            x: c as u32,
                            a: sa,
                            off: arg.offset,
                        };
                        match width {
                            1 => Instr::Store8I(m),
                            2 => Instr::Store16I(m),
                            4 => Instr::Store32I(m),
                            _ => Instr::Store64I(m),
                        }
                    }
                    _ => {
                        let sv = self.operand(v, pv);
                        Instr::store(code, sv, sa, arg.offset).ok_or_else(|| self.err())?
                    }
                };
                self.emit(i);
                self.last = None;
            }
            Op::MemorySize => {
                let d = self.slot(self.len());
                self.emit_result(Instr::MemorySize { d });
            }
            Op::MemoryGrow => {
                let (v, p) = self.pop()?;
                let a = self.operand(v, p);
                let d = self.slot(p);
                self.emit_result(Instr::MemoryGrow { d, a });
            }
            Op::I32Const(v) => {
                self.push_lazy(V::Const(u64::from(v as u32)));
                self.last = None;
            }
            Op::I64Const(v) => {
                self.push_lazy(V::Const(v as u64));
                self.last = None;
            }
            Op::F32Const(bits) => {
                self.push_lazy(V::Const(u64::from(bits)));
                self.last = None;
            }
            Op::F64Const(bits) => {
                self.push_lazy(V::Const(bits));
                self.last = None;
            }
            Op::RefNull(_) => {
                self.push_lazy(V::Const(0));
                self.last = None;
            }
            // A null reference is 0: `i64.eqz` on the slot.
            Op::RefIsNull => self.numeric(0x50)?,
            Op::RefFunc(f) => {
                let d = self.slot(self.len());
                self.emit_result(Instr::RefFunc { d, f });
            }
            // A slot holds the same bits either way.
            Op::Numeric(0xbc..=0xbf) => self.last = None,
            Op::Numeric(code) => self.numeric(u16::from(code))?,
            Op::TruncSat(k) => self.numeric(0x100 + u16::from(k))?,
            Op::MemoryInit(seg) => {
                let s = self.operands(3)?;
                self.emit(Instr::MemoryInit { s, seg });
            }
            Op::DataDrop(seg) => {
                self.emit(Instr::DataDrop { seg });
                self.last = None;
            }
            Op::MemoryCopy => {
                let s = self.operands(3)?;
                self.emit(Instr::MemoryCopy { s });
            }
            Op::MemoryFill => {
                let s = self.operands(3)?;
                self.emit(Instr::MemoryFill { s });
            }
            Op::TableInit { elem, table } => {
                let s = self.operands(3)?;
                self.emit(Instr::TableInit { s, elem, table });
            }
            Op::ElemDrop(e) => {
                self.emit(Instr::ElemDrop { e });
                self.last = None;
            }
            Op::TableCopy { dst, src } => {
                let s = self.operands(3)?;
                self.emit(Instr::TableCopy { s, dst, src });
            }
            Op::TableGrow(t) => {
                let s = self.operands(2)?;
                self.emit(Instr::TableGrow { s, t });
                self.vals.push(V::Slot);
            }
            Op::TableSize(t) => {
                let d = self.slot(self.len());
                self.emit_result(Instr::TableSize { d, t });
            }
            Op::TableFill(t) => {
                let s = self.operands(3)?;
                self.emit(Instr::TableFill { s, t });
            }
        }
        Ok(())
    }
}

/// The bytes store opcode `op` writes, and whether its value is 64 bits wide (`i64.store`,
/// `f64.store`), for the stores of a constant.
const fn store_imm(op: u8) -> Option<(u32, bool)> {
    Some(match op {
        0x36 | 0x38 | 0x3e => (4, false), // i32.store, f32.store, i64.store32
        0x37 | 0x39 => (8, true),         // i64.store, f64.store
        0x3a | 0x3c => (1, false),        // i32.store8, i64.store8
        0x3b | 0x3d => (2, false),        // i32.store16, i64.store16
        _ => return None,
    })
}

/// A fused branch condition from a two-operand comparison writing slot `d`.
fn cmp_of(i: Instr, d: u32) -> Option<Cond> {
    use Instr as I;
    let (wide, b) = match i {
        I::I32Eq(b)
        | I::I32Ne(b)
        | I::I32LtS(b)
        | I::I32LtU(b)
        | I::I32GtS(b)
        | I::I32GtU(b)
        | I::I32LeS(b)
        | I::I32LeU(b)
        | I::I32GeS(b)
        | I::I32GeU(b) => (false, b),
        I::I64Eq(b)
        | I::I64Ne(b)
        | I::I64LtS(b)
        | I::I64LtU(b)
        | I::I64GtS(b)
        | I::I64GtU(b)
        | I::I64LeS(b)
        | I::I64LeU(b)
        | I::I64GeS(b)
        | I::I64GeU(b) => (true, b),
        _ => return None,
    };
    if b.d != d {
        return None;
    }
    let op = match i {
        I::I32Eq(_) | I::I64Eq(_) => Cmp::Eq,
        I::I32Ne(_) | I::I64Ne(_) => Cmp::Ne,
        I::I32LtS(_) | I::I64LtS(_) => Cmp::LtS,
        I::I32LtU(_) | I::I64LtU(_) => Cmp::LtU,
        I::I32GtS(_) | I::I64GtS(_) => Cmp::GtS,
        I::I32GtU(_) | I::I64GtU(_) => Cmp::GtU,
        I::I32LeS(_) | I::I64LeS(_) => Cmp::LeS,
        I::I32LeU(_) | I::I64LeU(_) => Cmp::LeU,
        I::I32GeS(_) | I::I64GeS(_) => Cmp::GeS,
        _ => Cmp::GeU,
    };
    Some(if wide {
        Cond::C64(op, b.a, b.b)
    } else {
        Cond::C32(op, b.a, b.b)
    })
}

// The integration tests' module builder.
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::common::{Builder, Code, I32, I64};
    use super::*;
    use crate::ModuleLimits;

    /// The sequences Go's `wasm` code is made of translate to the fused instructions: what
    /// keeps a call of Go's `headers` guest at about two thousand dispatches (W5).
    #[test]
    fn go_sequences_are_fused() {
        let mut b = Builder::default();
        b.memory(1, None);
        let sp = b.global_i32(1 << 16);
        let t = b.ty(&[I32], &[I32]);
        let callee = b.func(t, &[], Code::default().get(0).end());
        let f = b.func(
            t,
            &[(1, I32), (1, I64)],
            Code::default()
                // The stack pointer moves, in a local and its global.
                .op(&[0x23])
                .idx(sp)
                .i32c(8)
                .op(&[0x6b])
                .tee(1)
                .op(&[0x24])
                .idx(sp)
                // A constant stored.
                .get(1)
                .i64c(1234)
                .op(&[0x37, 3, 0])
                // An i64 address, wrapped.
                .get(2)
                .op(&[0xa7, 0x29, 3, 0])
                .set(2)
                // An i32 widened, moved and wrapped.
                .get(1)
                .op(&[0xad])
                .i64c(8)
                .op(&[0x7c, 0xa7, 0x29, 3, 0, 0x1a])
                // A bool's test.
                .op(&[0x02, 0x40])
                .get(2)
                .op(&[0x50, 0xad, 0x50, 0x0d, 0])
                .end()
                // A call with 0, and a constant returned.
                .i32c(0)
                .call(callee)
                .op(&[0x1a])
                .i32c(0)
                .end(),
        );
        let _ = f;
        let m = Module::new(&b.build(), &ModuleLimits::default()).unwrap();
        let code = &m.compiled[1].code;
        for i in code {
            assert!(
                !matches!(
                    i,
                    Instr::I32WrapI64(_)
                        | Instr::I64ExtendI32U(_)
                        | Instr::I64Eqz(_)
                        | Instr::Const32 { .. }
                        | Instr::Const64 { .. }
                        | Instr::GlobalSet { .. }
                        | Instr::Return1 { .. }
                        | Instr::Call { .. }
                ),
                "{i:?} in {code:#?}"
            );
        }
        let has = |p: fn(&Instr) -> bool| code.iter().any(p);
        assert!(has(|i| matches!(i, Instr::I32AddGlobal { imm: -8, .. })));
        assert!(has(|i| matches!(i, Instr::Store64I(m) if m.x == 1234)));
        assert!(has(|i| matches!(i, Instr::I64Load(m) if m.a == 2)));
        assert!(has(|i| matches!(
            i,
            Instr::BrCmp64I {
                op: Cmp::Ne,
                a: 2,
                imm: 0,
                ..
            }
        )));
        assert!(has(|i| matches!(i, Instr::CallC { v: 0, .. })));
        assert!(has(|i| matches!(i, Instr::Return1C { v: 0 })));
        // No branch lands on a `Fuel`: each takes its target's fuel itself.
        for i in code {
            let (Instr::Br { t, .. }
            | Instr::BrIfNz { t, .. }
            | Instr::BrIfZ { t, .. }
            | Instr::BrCmp32 { t, .. }
            | Instr::BrCmp32I { t, .. }
            | Instr::BrCmp64 { t, .. }
            | Instr::BrCmp64I { t, .. }) = *i
            else {
                continue;
            };
            assert!(!matches!(code[t as usize], Instr::Fuel { .. }), "{code:#?}");
        }
    }
}
