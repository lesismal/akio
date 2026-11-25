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
    instr::{BinOp, Cmp, Instr, Un},
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
            Self::Nz(c) => Instr::BrIfNz { c, t },
            Self::Z(c) => Instr::BrIfZ { c, t },
            Self::C32(op, a, b) => Instr::BrCmp32 { op, a, b, t },
            Self::C32I(op, a, imm) => Instr::BrCmp32I { op, a, imm, t },
            Self::C64(op, a, b) => Instr::BrCmp64 { op, a, b, t },
            Self::C64I(op, a, imm) => Instr::BrCmp64I { op, a, imm, t },
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
                        return Ok(c);
                    }
                }
            }
        }
        self.last = None;
        Ok(Cond::Nz(self.operand(v, pos)))
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
            1 => {
                let s = match self.vals[src as usize] {
                    V::Local(i) => i,
                    v => self.operand(v, src),
                };
                self.emit(Instr::Return1 { s });
            }
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
            self.emit(Instr::Br { t: c.start });
        } else {
            let pc = self.emit(Instr::Br { t: NONE }) as u32;
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
                let pc = self.emit(Instr::Br { t: NONE }) as u32;
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
            let (a, pa) = self.pop()?;
            let d = self.slot(pa);
            let sa = self.operand(a, pa);
            let i = Instr::numeric(op, d, sa, 0).ok_or_else(|| self.err())?;
            self.emit_result(i);
        }
        Ok(())
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
                    self.emit(Instr::Call {
                        f: f - m.imported_funcs,
                        base,
                    });
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
                let s = self.operand(v, p);
                self.emit(Instr::GlobalSet { s, g });
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
                let a = self.operand(v, p);
                let x = self.slot(p);
                let i = Instr::load(code, x, a, arg.offset).ok_or_else(|| self.err())?;
                self.emit_result(i);
            }
            Op::Store(code, arg) => {
                let (v, pv) = self.pop()?;
                let (a, pa) = self.pop()?;
                let sv = self.operand(v, pv);
                let sa = self.operand(a, pa);
                let i = Instr::store(code, sv, sa, arg.offset).ok_or_else(|| self.err())?;
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
