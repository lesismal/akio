//! The interpreter: a `match` loop over the register form, with explicit frames on a `Vec` (no
//! native recursion), every memory and table access bounds-checked.

use crate::{
    budget::Meter,
    instr::{Bin, Instr, Mem, Un},
    store::{Frame, FuncKind, MemoryEntity, PAGE, Runtime},
    trap::Trap,
};

/// Why the interpreter loop stopped without a trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    /// The entry frame returned.
    Done,
    /// A host function must be called: its arguments in slots `base..`, results to go there;
    /// the frames resume after it.
    Host {
        host: u32,
        ty: u32,
        base: u32,
        inst: u32,
    },
}

/// A value read from, or written to, a slot.
trait Sv: Copy {
    fn get(v: u64) -> Self;
    fn put(self) -> u64;
}

impl Sv for i32 {
    #[inline(always)]
    fn get(v: u64) -> Self {
        v as u32 as Self
    }
    #[inline(always)]
    fn put(self) -> u64 {
        u64::from(self as u32)
    }
}

impl Sv for u32 {
    #[inline(always)]
    fn get(v: u64) -> Self {
        v as Self
    }
    #[inline(always)]
    fn put(self) -> u64 {
        u64::from(self)
    }
}

impl Sv for i64 {
    #[inline(always)]
    fn get(v: u64) -> Self {
        v as Self
    }
    #[inline(always)]
    fn put(self) -> u64 {
        self as u64
    }
}

impl Sv for u64 {
    #[inline(always)]
    fn get(v: u64) -> Self {
        v
    }
    #[inline(always)]
    fn put(self) -> u64 {
        self
    }
}

impl Sv for f32 {
    #[inline(always)]
    fn get(v: u64) -> Self {
        Self::from_bits(v as u32)
    }
    #[inline(always)]
    fn put(self) -> u64 {
        u64::from(self.to_bits())
    }
}

impl Sv for f64 {
    #[inline(always)]
    fn get(v: u64) -> Self {
        Self::from_bits(v)
    }
    #[inline(always)]
    fn put(self) -> u64 {
        self.to_bits()
    }
}

impl Sv for bool {
    #[inline(always)]
    fn get(v: u64) -> Self {
        v != 0
    }
    #[inline(always)]
    fn put(self) -> u64 {
        u64::from(self)
    }
}

#[inline(always)]
fn un<A: Sv, R: Sv>(r: &mut [u64], i: Un, f: impl FnOnce(A) -> R) {
    r[i.d as usize] = f(A::get(r[i.a as usize])).put();
}

#[inline(always)]
fn bin<A: Sv, R: Sv>(r: &mut [u64], i: Bin, f: impl FnOnce(A, A) -> R) {
    r[i.d as usize] = f(A::get(r[i.a as usize]), A::get(r[i.b as usize])).put();
}

#[inline(always)]
fn try_un<A: Sv, R: Sv>(
    r: &mut [u64],
    i: Un,
    f: impl FnOnce(A) -> Result<R, Trap>,
) -> Result<(), Trap> {
    r[i.d as usize] = f(A::get(r[i.a as usize]))?.put();
    Ok(())
}

#[inline(always)]
fn try_bin<A: Sv, R: Sv>(
    r: &mut [u64],
    i: Bin,
    f: impl FnOnce(A, A) -> Result<R, Trap>,
) -> Result<(), Trap> {
    r[i.d as usize] = f(A::get(r[i.a as usize]), A::get(r[i.b as usize]))?.put();
    Ok(())
}

/// The effective address of an access of `N` bytes, if it is inside `len`.
#[inline(always)]
fn ea(r: &[u64], m: Mem, n: usize, len: usize) -> Result<usize, Trap> {
    let a = u64::from(r[m.a as usize] as u32) + u64::from(m.off);
    usize::try_from(a)
        .ok()
        .filter(|&a| a.checked_add(n).is_some_and(|e| e <= len))
        .ok_or(Trap::MemoryOutOfBounds)
}

#[inline(always)]
fn load<const N: usize>(mem: &[u8], r: &[u64], m: Mem) -> Result<[u8; N], Trap> {
    let a = ea(r, m, N, mem.len())?;
    mem[a..a + N]
        .try_into()
        .map_err(|_| Trap::MemoryOutOfBounds)
}

#[inline(always)]
fn store<const N: usize>(mem: &mut [u8], r: &[u64], m: Mem, b: [u8; N]) -> Result<(), Trap> {
    let a = ea(r, m, N, mem.len())?;
    mem[a..a + N].copy_from_slice(&b);
    Ok(())
}

/// `start + n` if inside `len`.
#[inline(always)]
fn range(start: u32, n: u32, len: usize, trap: Trap) -> Result<std::ops::Range<usize>, Trap> {
    let (s, e) = (start as usize, start as usize + n as usize);
    if e > len {
        return Err(trap);
    }
    Ok(s..e)
}

const CANON32: u32 = 0x7fc0_0000;
const CANON64: u64 = 0x7ff8_0000_0000_0000;

/// A NaN result as the canonical NaN, so that results do not depend on the host's hardware.
#[inline(always)]
fn c32(x: f32) -> f32 {
    if x.is_nan() {
        f32::from_bits(CANON32)
    } else {
        x
    }
}

#[inline(always)]
fn c64(x: f64) -> f64 {
    if x.is_nan() {
        f64::from_bits(CANON64)
    } else {
        x
    }
}

fn fmin32(a: f32, b: f32) -> f32 {
    if a.is_nan() || b.is_nan() {
        f32::from_bits(CANON32)
    } else if a == b {
        // -0 and +0: -0.
        f32::from_bits(a.to_bits() | b.to_bits())
    } else if a < b {
        a
    } else {
        b
    }
}

fn fmax32(a: f32, b: f32) -> f32 {
    if a.is_nan() || b.is_nan() {
        f32::from_bits(CANON32)
    } else if a == b {
        f32::from_bits(a.to_bits() & b.to_bits())
    } else if a > b {
        a
    } else {
        b
    }
}

fn fmin64(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::from_bits(CANON64)
    } else if a == b {
        f64::from_bits(a.to_bits() | b.to_bits())
    } else if a < b {
        a
    } else {
        b
    }
}

fn fmax64(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::from_bits(CANON64)
    } else if a == b {
        f64::from_bits(a.to_bits() & b.to_bits())
    } else if a > b {
        a
    } else {
        b
    }
}

/// A float truncated toward zero, as an integer in `[lo, hi)`, or the trap.
#[inline]
fn trunc_check(x: f64, lo: f64, hi: f64) -> Result<f64, Trap> {
    if x.is_nan() {
        return Err(Trap::InvalidConversion);
    }
    let t = x.trunc();
    if t >= lo && t < hi {
        Ok(t)
    } else {
        Err(Trap::IntegerOverflow)
    }
}

const I32_LO: f64 = -2_147_483_648.0;
const I32_HI: f64 = 2_147_483_648.0;
const U32_HI: f64 = 4_294_967_296.0;
// Powers of two: exact.
#[allow(clippy::lossy_float_literal)]
const I64_LO: f64 = -9_223_372_036_854_775_808.0;
#[allow(clippy::lossy_float_literal)]
const I64_HI: f64 = 9_223_372_036_854_775_808.0;
#[allow(clippy::lossy_float_literal)]
const U64_HI: f64 = 18_446_744_073_709_551_616.0;

fn div_s32(a: i32, b: i32) -> Result<i32, Trap> {
    if b == 0 {
        return Err(Trap::IntegerDivideByZero);
    }
    a.checked_div(b).ok_or(Trap::IntegerOverflow)
}

fn rem_s32(a: i32, b: i32) -> Result<i32, Trap> {
    if b == 0 {
        return Err(Trap::IntegerDivideByZero);
    }
    Ok(a.wrapping_rem(b))
}

fn div_u32(a: u32, b: u32) -> Result<u32, Trap> {
    a.checked_div(b).ok_or(Trap::IntegerDivideByZero)
}

fn rem_u32(a: u32, b: u32) -> Result<u32, Trap> {
    a.checked_rem(b).ok_or(Trap::IntegerDivideByZero)
}

fn div_s64(a: i64, b: i64) -> Result<i64, Trap> {
    if b == 0 {
        return Err(Trap::IntegerDivideByZero);
    }
    a.checked_div(b).ok_or(Trap::IntegerOverflow)
}

fn rem_s64(a: i64, b: i64) -> Result<i64, Trap> {
    if b == 0 {
        return Err(Trap::IntegerDivideByZero);
    }
    Ok(a.wrapping_rem(b))
}

fn div_u64(a: u64, b: u64) -> Result<u64, Trap> {
    a.checked_div(b).ok_or(Trap::IntegerDivideByZero)
}

fn rem_u64(a: u64, b: u64) -> Result<u64, Trap> {
    a.checked_rem(b).ok_or(Trap::IntegerDivideByZero)
}

impl Runtime {
    /// Runs the frames on the stack from the top one's saved position, until only `floor` frames
    /// are left (the frames of the calls a host function made this one from) or a host function
    /// must be called.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn run(&mut self, meter: &mut Meter, floor: usize) -> Result<Exit, Trap> {
        let Self {
            limits,
            funcs,
            instances,
            segments,
            memories,
            tables,
            globals,
            stack,
            frames,
            ..
        } = self;
        let max_depth = limits.max_call_depth as usize;
        let max_stack = limits.max_value_stack as usize;
        let mut no_memory = MemoryEntity::default();
        'frame: loop {
            let fr = match frames.last() {
                Some(&fr) if frames.len() > floor => fr,
                _ => return Ok(Exit::Done),
            };
            let inst = &instances[fr.inst as usize];
            let module = &*inst.module;
            let func = &module.compiled[fr.func as usize];
            let code = &*func.code;
            let base = fr.base as usize;
            let mem: &mut MemoryEntity = match inst.memory {
                Some(m) => &mut memories[m as usize],
                None => &mut no_memory,
            };
            let r = &mut stack[base..base + func.frame as usize];
            let mut pc = fr.pc as usize;

            // Enters store function `$f` with its frame at slot `$at` of this one.
            macro_rules! enter {
                ($f:expr, $at:expr) => {{
                    let target = $f as usize;
                    let at = base + $at as usize;
                    let fe = funcs[target];
                    if let Some(top) = frames.last_mut() {
                        top.pc = pc as u32;
                    }
                    match fe.kind {
                        FuncKind::Host(host) => {
                            return Ok(Exit::Host {
                                host,
                                ty: fe.ty,
                                base: at as u32,
                                inst: fr.inst,
                            });
                        }
                        FuncKind::Wasm { inst: ci, def } => {
                            if frames.len() >= max_depth {
                                return Err(Trap::CallStackExhausted);
                            }
                            let c = &instances[ci as usize].module.compiled[def as usize];
                            let end = at + c.frame as usize;
                            if end > max_stack {
                                return Err(Trap::ValueStackExhausted);
                            }
                            if stack.len() < end {
                                let grown = (stack.len() * 2).clamp(end, max_stack);
                                stack.resize(grown, 0);
                            }
                            stack[at + c.params as usize..at + c.locals as usize].fill(0);
                            // The callee's first block's fuel, taken here: its `Fuel` is
                            // skipped (the first instruction of every function).
                            let entry = match c.code.first() {
                                Some(&Instr::Fuel { n }) => {
                                    meter.take(u64::from(n))?;
                                    1
                                }
                                _ => 0,
                            };
                            frames.push(Frame {
                                inst: ci,
                                func: def,
                                pc: entry,
                                base: at as u32,
                            });
                            continue 'frame;
                        }
                    }
                }};
            }

            // Returns from this frame.
            macro_rules! ret {
                () => {{
                    frames.pop();
                    continue 'frame;
                }};
            }

            loop {
                let i = code[pc];
                pc += 1;
                match i {
                    Instr::Fuel { n } => meter.take(u64::from(n))?,
                    Instr::Unreachable => return Err(Trap::Unreachable),
                    Instr::Br { t, n } => {
                        meter.take(u64::from(n))?;
                        pc = t as usize;
                    }
                    Instr::BrIfNz { c, t, n, f } => {
                        if r[c as usize] as u32 != 0 {
                            meter.take(u64::from(n))?;
                            pc = t as usize;
                        } else if f != 0 {
                            meter.take(u64::from(f - 1))?;
                            pc += 1;
                        }
                    }
                    Instr::BrIfZ { c, t, n, f } => {
                        if r[c as usize] as u32 == 0 {
                            meter.take(u64::from(n))?;
                            pc = t as usize;
                        } else if f != 0 {
                            meter.take(u64::from(f - 1))?;
                            pc += 1;
                        }
                    }
                    Instr::BrCmp32 { op, n, a, b, t } => {
                        if op.i32(r[a as usize] as i32, r[b as usize] as i32) {
                            meter.take(u64::from(n))?;
                            pc = t as usize;
                        }
                    }
                    Instr::BrCmp32I { op, n, a, imm, t } => {
                        if op.i32(r[a as usize] as i32, imm) {
                            meter.take(u64::from(n))?;
                            pc = t as usize;
                        }
                    }
                    Instr::BrCmp64 { op, n, a, b, t } => {
                        if op.i64(r[a as usize] as i64, r[b as usize] as i64) {
                            meter.take(u64::from(n))?;
                            pc = t as usize;
                        }
                    }
                    Instr::BrCmp64I { op, n, a, imm, t } => {
                        if op.i64(r[a as usize] as i64, i64::from(imm)) {
                            meter.take(u64::from(n))?;
                            pc = t as usize;
                        }
                    }
                    Instr::BrTable { s, n } => {
                        // The chosen `Br` taken here, not dispatched.
                        let k = pc + (r[s as usize] as u32).min(n) as usize;
                        match code[k] {
                            Instr::Br { t, n } => {
                                meter.take(u64::from(n))?;
                                pc = t as usize;
                            }
                            _ => pc = k,
                        }
                    }
                    Instr::Copy { d, s } => r[d as usize] = r[s as usize],
                    Instr::CopyRange { d, s, n } => {
                        let s = s as usize;
                        r.copy_within(s..s + n as usize, d as usize);
                    }
                    Instr::Const32 { d, v } => r[d as usize] = u64::from(v),
                    Instr::Const64 { d, v } => r[d as usize] = v,
                    Instr::I32BinI { op, d, a, imm } => {
                        r[d as usize] = u64::from(op.i32(r[a as usize] as i32, imm) as u32);
                    }
                    Instr::I64BinI { op, d, a, imm } => {
                        r[d as usize] = op.i64(r[a as usize] as i64, i64::from(imm));
                    }
                    Instr::Return0 => ret!(),
                    Instr::Return1 { s } => {
                        r[0] = r[s as usize];
                        ret!()
                    }
                    Instr::Return1C { v } => {
                        r[0] = v;
                        ret!()
                    }
                    Instr::ReturnN { s, n } => {
                        let s = s as usize;
                        r.copy_within(s..s + n as usize, 0);
                        ret!()
                    }
                    Instr::Call { f, base: at } => {
                        enter!(inst.funcs[module.imported_funcs as usize + f as usize], at);
                    }
                    Instr::CallC { f, base: at, v } => {
                        r[at as usize] = u64::from(v);
                        enter!(inst.funcs[module.imported_funcs as usize + f as usize], at);
                    }
                    Instr::CallImport { f, base: at } => enter!(inst.funcs[f as usize], at),
                    Instr::CallIndirect {
                        base: at,
                        ty,
                        table,
                    } => {
                        let n = module.types[ty as usize].params().len();
                        let idx = r[at as usize + n] as u32 as usize;
                        let t = &tables[inst.tables[table as usize] as usize];
                        let e = *t.elems.get(idx).ok_or(Trap::UndefinedElement)?;
                        let f = e.checked_sub(1).ok_or(Trap::UninitializedElement)? as u32;
                        if funcs[f as usize].ty != inst.types[ty as usize] {
                            return Err(Trap::IndirectCallType);
                        }
                        enter!(f, at);
                    }
                    Instr::Select { d, b, c } => {
                        if r[c as usize] as u32 == 0 {
                            r[d as usize] = r[b as usize];
                        }
                    }
                    Instr::GlobalGet { d, g } => {
                        r[d as usize] = globals[inst.globals[g as usize] as usize].value;
                    }
                    Instr::GlobalSet { s, g } => {
                        globals[inst.globals[g as usize] as usize].value = r[s as usize];
                    }
                    Instr::I32AddGlobal { g, d, a, imm } => {
                        let v = u64::from((r[a as usize] as u32).wrapping_add(imm as u32));
                        r[d as usize] = v;
                        globals[inst.globals[g as usize] as usize].value = v;
                    }
                    Instr::TableGet { d, a, t } => {
                        let t = &tables[inst.tables[t as usize] as usize];
                        r[d as usize] = *t
                            .elems
                            .get(r[a as usize] as u32 as usize)
                            .ok_or(Trap::TableOutOfBounds)?;
                    }
                    Instr::TableSet { a, v, t } => {
                        let t = &mut tables[inst.tables[t as usize] as usize];
                        *t.elems
                            .get_mut(r[a as usize] as u32 as usize)
                            .ok_or(Trap::TableOutOfBounds)? = r[v as usize];
                    }
                    Instr::TableSize { d, t } => {
                        r[d as usize] = tables[inst.tables[t as usize] as usize].elems.len() as u64;
                    }
                    Instr::TableGrow { s, t } => {
                        let s = s as usize;
                        let t = &mut tables[inst.tables[t as usize] as usize];
                        let (init, n) = (r[s], r[s + 1] as u32);
                        let old = t.elems.len();
                        let new = old as u64 + u64::from(n);
                        r[s] = if new > u64::from(t.max) || t.elems.try_reserve(n as usize).is_err()
                        {
                            u64::from(u32::MAX)
                        } else {
                            meter.take(u64::from(n) >> 3)?;
                            t.elems.resize(new as usize, init);
                            old as u64
                        };
                    }
                    Instr::TableFill { s, t } => {
                        let s = s as usize;
                        let t = &mut tables[inst.tables[t as usize] as usize];
                        let (i, v, n) = (r[s] as u32, r[s + 1], r[s + 2] as u32);
                        let span = range(i, n, t.elems.len(), Trap::TableOutOfBounds)?;
                        meter.take(u64::from(n) >> 3)?;
                        t.elems[span].fill(v);
                    }
                    Instr::TableCopy { s, dst, src } => {
                        let s = s as usize;
                        let (d, from, n) = (r[s] as u32, r[s + 1] as u32, r[s + 2] as u32);
                        let td = inst.tables[dst as usize] as usize;
                        let ts = inst.tables[src as usize] as usize;
                        let dr = range(d, n, tables[td].elems.len(), Trap::TableOutOfBounds)?;
                        let sr = range(from, n, tables[ts].elems.len(), Trap::TableOutOfBounds)?;
                        meter.take(u64::from(n) >> 3)?;
                        if td == ts {
                            tables[td].elems.copy_within(sr, dr.start);
                        } else if td < ts {
                            let (lo, hi) = tables.split_at_mut(ts);
                            lo[td].elems[dr].copy_from_slice(&hi[0].elems[sr]);
                        } else {
                            let (lo, hi) = tables.split_at_mut(td);
                            hi[0].elems[dr].copy_from_slice(&lo[ts].elems[sr]);
                        }
                    }
                    Instr::TableInit { s, elem, table } => {
                        let s = s as usize;
                        let (d, from, n) = (r[s] as u32, r[s + 1] as u32, r[s + 2] as u32);
                        let seg = &segments[fr.inst as usize].elems[elem as usize];
                        let t = &mut tables[inst.tables[table as usize] as usize];
                        let sr = range(from, n, seg.len(), Trap::TableOutOfBounds)?;
                        let dr = range(d, n, t.elems.len(), Trap::TableOutOfBounds)?;
                        meter.take(u64::from(n) >> 3)?;
                        t.elems[dr].copy_from_slice(&seg[sr]);
                    }
                    Instr::ElemDrop { e } => {
                        segments[fr.inst as usize].elems[e as usize] = Box::default();
                    }
                    Instr::MemorySize { d } => r[d as usize] = (mem.data.len() / PAGE) as u64,
                    Instr::MemoryGrow { d, a } => {
                        let n = r[a as usize] as u32;
                        let old = mem.data.len() / PAGE;
                        let new = old as u64 + u64::from(n);
                        let bytes = n as usize * PAGE;
                        r[d as usize] = if new > u64::from(mem.max_pages)
                            || mem.data.try_reserve_exact(bytes).is_err()
                        {
                            u64::from(u32::MAX)
                        } else {
                            meter.take(bytes as u64 >> 6)?;
                            mem.data.resize(new as usize * PAGE, 0);
                            old as u64
                        };
                    }
                    Instr::MemoryFill { s } => {
                        let s = s as usize;
                        let (d, v, n) = (r[s] as u32, r[s + 1] as u8, r[s + 2] as u32);
                        let dr = range(d, n, mem.data.len(), Trap::MemoryOutOfBounds)?;
                        meter.take(u64::from(n) >> 6)?;
                        mem.data[dr].fill(v);
                    }
                    Instr::MemoryCopy { s } => {
                        let s = s as usize;
                        let (d, from, n) = (r[s] as u32, r[s + 1] as u32, r[s + 2] as u32);
                        let len = mem.data.len();
                        let dr = range(d, n, len, Trap::MemoryOutOfBounds)?;
                        let sr = range(from, n, len, Trap::MemoryOutOfBounds)?;
                        meter.take(u64::from(n) >> 6)?;
                        mem.data.copy_within(sr, dr.start);
                    }
                    Instr::MemoryInit { s, seg } => {
                        let s = s as usize;
                        let (d, from, n) = (r[s] as u32, r[s + 1] as u32, r[s + 2] as u32);
                        let bytes: &[u8] = if segments[fr.inst as usize].data_dropped[seg as usize]
                        {
                            &[]
                        } else {
                            &module.datas[seg as usize].bytes
                        };
                        let sr = range(from, n, bytes.len(), Trap::MemoryOutOfBounds)?;
                        let dr = range(d, n, mem.data.len(), Trap::MemoryOutOfBounds)?;
                        meter.take(u64::from(n) >> 6)?;
                        mem.data[dr].copy_from_slice(&bytes[sr]);
                    }
                    Instr::DataDrop { seg } => {
                        segments[fr.inst as usize].data_dropped[seg as usize] = true;
                    }
                    Instr::RefFunc { d, f } => {
                        r[d as usize] = u64::from(inst.funcs[f as usize]) + 1;
                    }

                    Instr::I32Load(m) => {
                        r[m.x as usize] = u64::from(u32::from_le_bytes(load(&mem.data, r, m)?));
                    }
                    Instr::I64Load(m) => {
                        r[m.x as usize] = u64::from_le_bytes(load(&mem.data, r, m)?);
                    }
                    Instr::F32Load(m) => {
                        r[m.x as usize] = u64::from(u32::from_le_bytes(load(&mem.data, r, m)?));
                    }
                    Instr::F64Load(m) => {
                        r[m.x as usize] = u64::from_le_bytes(load(&mem.data, r, m)?);
                    }
                    Instr::I32Load8S(m) => {
                        r[m.x as usize] =
                            i32::from(i8::from_le_bytes(load(&mem.data, r, m)?)).put();
                    }
                    Instr::I32Load8U(m) => {
                        r[m.x as usize] = u64::from(u8::from_le_bytes(load(&mem.data, r, m)?));
                    }
                    Instr::I32Load16S(m) => {
                        r[m.x as usize] =
                            i32::from(i16::from_le_bytes(load(&mem.data, r, m)?)).put();
                    }
                    Instr::I32Load16U(m) => {
                        r[m.x as usize] = u64::from(u16::from_le_bytes(load(&mem.data, r, m)?));
                    }
                    Instr::I64Load8S(m) => {
                        r[m.x as usize] =
                            i64::from(i8::from_le_bytes(load(&mem.data, r, m)?)) as u64;
                    }
                    Instr::I64Load8U(m) => {
                        r[m.x as usize] = u64::from(u8::from_le_bytes(load(&mem.data, r, m)?));
                    }
                    Instr::I64Load16S(m) => {
                        r[m.x as usize] =
                            i64::from(i16::from_le_bytes(load(&mem.data, r, m)?)) as u64;
                    }
                    Instr::I64Load16U(m) => {
                        r[m.x as usize] = u64::from(u16::from_le_bytes(load(&mem.data, r, m)?));
                    }
                    Instr::I64Load32S(m) => {
                        r[m.x as usize] =
                            i64::from(i32::from_le_bytes(load(&mem.data, r, m)?)) as u64;
                    }
                    Instr::I64Load32U(m) => {
                        r[m.x as usize] = u64::from(u32::from_le_bytes(load(&mem.data, r, m)?));
                    }
                    Instr::I32Store(m) | Instr::F32Store(m) => {
                        let v = r[m.x as usize] as u32;
                        store(&mut mem.data, r, m, v.to_le_bytes())?;
                    }
                    Instr::I64Store(m) | Instr::F64Store(m) => {
                        let v = r[m.x as usize];
                        store(&mut mem.data, r, m, v.to_le_bytes())?;
                    }
                    Instr::I32Store8(m) | Instr::I64Store8(m) => {
                        let v = r[m.x as usize] as u8;
                        store(&mut mem.data, r, m, v.to_le_bytes())?;
                    }
                    Instr::I32Store16(m) | Instr::I64Store16(m) => {
                        let v = r[m.x as usize] as u16;
                        store(&mut mem.data, r, m, v.to_le_bytes())?;
                    }
                    Instr::I64Store32(m) => {
                        let v = r[m.x as usize] as u32;
                        store(&mut mem.data, r, m, v.to_le_bytes())?;
                    }
                    Instr::Store8I(m) => store(&mut mem.data, r, m, [m.x as u8])?,
                    Instr::Store16I(m) => {
                        store(&mut mem.data, r, m, (m.x as u16).to_le_bytes())?;
                    }
                    Instr::Store32I(m) => store(&mut mem.data, r, m, m.x.to_le_bytes())?,
                    Instr::Store64I(m) => {
                        let v = i64::from(m.x as i32);
                        store(&mut mem.data, r, m, v.to_le_bytes())?;
                    }

                    Instr::I32Eqz(i) => un(r, i, |x: u32| x == 0),
                    Instr::I64Eqz(i) => un(r, i, |x: u64| x == 0),
                    Instr::I32Clz(i) => un(r, i, u32::leading_zeros),
                    Instr::I32Ctz(i) => un(r, i, u32::trailing_zeros),
                    Instr::I32Popcnt(i) => un(r, i, u32::count_ones),
                    Instr::I64Clz(i) => un(r, i, |x: u64| u64::from(x.leading_zeros())),
                    Instr::I64Ctz(i) => un(r, i, |x: u64| u64::from(x.trailing_zeros())),
                    Instr::I64Popcnt(i) => un(r, i, |x: u64| u64::from(x.count_ones())),
                    Instr::F32Abs(i) => un(r, i, |x: u32| x & 0x7fff_ffff),
                    Instr::F32Neg(i) => un(r, i, |x: u32| x ^ 0x8000_0000),
                    Instr::F32Ceil(i) => un(r, i, |x: f32| c32(x.ceil())),
                    Instr::F32Floor(i) => un(r, i, |x: f32| c32(x.floor())),
                    Instr::F32Trunc(i) => un(r, i, |x: f32| c32(x.trunc())),
                    Instr::F32Nearest(i) => un(r, i, |x: f32| c32(x.round_ties_even())),
                    Instr::F32Sqrt(i) => un(r, i, |x: f32| c32(x.sqrt())),
                    Instr::F64Abs(i) => un(r, i, |x: u64| x & 0x7fff_ffff_ffff_ffff),
                    Instr::F64Neg(i) => un(r, i, |x: u64| x ^ 0x8000_0000_0000_0000),
                    Instr::F64Ceil(i) => un(r, i, |x: f64| c64(x.ceil())),
                    Instr::F64Floor(i) => un(r, i, |x: f64| c64(x.floor())),
                    Instr::F64Trunc(i) => un(r, i, |x: f64| c64(x.trunc())),
                    Instr::F64Nearest(i) => un(r, i, |x: f64| c64(x.round_ties_even())),
                    Instr::F64Sqrt(i) => un(r, i, |x: f64| c64(x.sqrt())),
                    Instr::I32WrapI64(i) => un(r, i, |x: u64| x as u32),
                    Instr::I32TruncF32S(i) => try_un(r, i, |x: f32| {
                        trunc_check(f64::from(x), I32_LO, I32_HI).map(|t| t as i32)
                    })?,
                    Instr::I32TruncF32U(i) => try_un(r, i, |x: f32| {
                        trunc_check(f64::from(x), 0.0, U32_HI).map(|t| t as u32)
                    })?,
                    Instr::I32TruncF64S(i) => try_un(r, i, |x: f64| {
                        trunc_check(x, I32_LO, I32_HI).map(|t| t as i32)
                    })?,
                    Instr::I32TruncF64U(i) => {
                        try_un(r, i, |x: f64| trunc_check(x, 0.0, U32_HI).map(|t| t as u32))?;
                    }
                    Instr::I64ExtendI32S(i) => un(r, i, |x: i32| i64::from(x)),
                    Instr::I64ExtendI32U(i) => un(r, i, |x: u32| u64::from(x)),
                    Instr::I64TruncF32S(i) => try_un(r, i, |x: f32| {
                        trunc_check(f64::from(x), I64_LO, I64_HI).map(|t| t as i64)
                    })?,
                    Instr::I64TruncF32U(i) => try_un(r, i, |x: f32| {
                        trunc_check(f64::from(x), 0.0, U64_HI).map(|t| t as u64)
                    })?,
                    Instr::I64TruncF64S(i) => try_un(r, i, |x: f64| {
                        trunc_check(x, I64_LO, I64_HI).map(|t| t as i64)
                    })?,
                    Instr::I64TruncF64U(i) => {
                        try_un(r, i, |x: f64| trunc_check(x, 0.0, U64_HI).map(|t| t as u64))?;
                    }
                    Instr::F32ConvertI32S(i) => un(r, i, |x: i32| x as f32),
                    Instr::F32ConvertI32U(i) => un(r, i, |x: u32| x as f32),
                    Instr::F32ConvertI64S(i) => un(r, i, |x: i64| x as f32),
                    Instr::F32ConvertI64U(i) => un(r, i, |x: u64| x as f32),
                    Instr::F32DemoteF64(i) => un(r, i, |x: f64| c32(x as f32)),
                    Instr::F64ConvertI32S(i) => un(r, i, |x: i32| f64::from(x)),
                    Instr::F64ConvertI32U(i) => un(r, i, |x: u32| f64::from(x)),
                    Instr::F64ConvertI64S(i) => un(r, i, |x: i64| x as f64),
                    Instr::F64ConvertI64U(i) => un(r, i, |x: u64| x as f64),
                    Instr::F64PromoteF32(i) => un(r, i, |x: f32| c64(f64::from(x))),
                    Instr::I32Extend8S(i) => un(r, i, |x: i32| i32::from(x as i8)),
                    Instr::I32Extend16S(i) => un(r, i, |x: i32| i32::from(x as i16)),
                    Instr::I64Extend8S(i) => un(r, i, |x: i64| i64::from(x as i8)),
                    Instr::I64Extend16S(i) => un(r, i, |x: i64| i64::from(x as i16)),
                    Instr::I64Extend32S(i) => un(r, i, |x: i64| i64::from(x as i32)),
                    // Rust's float-to-int `as` saturates and takes NaN to 0: `trunc_sat`.
                    Instr::I32TruncSatF32S(i) => un(r, i, |x: f32| x as i32),
                    Instr::I32TruncSatF32U(i) => un(r, i, |x: f32| x as u32),
                    Instr::I32TruncSatF64S(i) => un(r, i, |x: f64| x as i32),
                    Instr::I32TruncSatF64U(i) => un(r, i, |x: f64| x as u32),
                    Instr::I64TruncSatF32S(i) => un(r, i, |x: f32| x as i64),
                    Instr::I64TruncSatF32U(i) => un(r, i, |x: f32| x as u64),
                    Instr::I64TruncSatF64S(i) => un(r, i, |x: f64| x as i64),
                    Instr::I64TruncSatF64U(i) => un(r, i, |x: f64| x as u64),

                    Instr::I32Eq(i) => bin(r, i, |x: u32, y| x == y),
                    Instr::I32Ne(i) => bin(r, i, |x: u32, y| x != y),
                    Instr::I32LtS(i) => bin(r, i, |x: i32, y| x < y),
                    Instr::I32LtU(i) => bin(r, i, |x: u32, y| x < y),
                    Instr::I32GtS(i) => bin(r, i, |x: i32, y| x > y),
                    Instr::I32GtU(i) => bin(r, i, |x: u32, y| x > y),
                    Instr::I32LeS(i) => bin(r, i, |x: i32, y| x <= y),
                    Instr::I32LeU(i) => bin(r, i, |x: u32, y| x <= y),
                    Instr::I32GeS(i) => bin(r, i, |x: i32, y| x >= y),
                    Instr::I32GeU(i) => bin(r, i, |x: u32, y| x >= y),
                    Instr::I64Eq(i) => bin(r, i, |x: u64, y| x == y),
                    Instr::I64Ne(i) => bin(r, i, |x: u64, y| x != y),
                    Instr::I64LtS(i) => bin(r, i, |x: i64, y| x < y),
                    Instr::I64LtU(i) => bin(r, i, |x: u64, y| x < y),
                    Instr::I64GtS(i) => bin(r, i, |x: i64, y| x > y),
                    Instr::I64GtU(i) => bin(r, i, |x: u64, y| x > y),
                    Instr::I64LeS(i) => bin(r, i, |x: i64, y| x <= y),
                    Instr::I64LeU(i) => bin(r, i, |x: u64, y| x <= y),
                    Instr::I64GeS(i) => bin(r, i, |x: i64, y| x >= y),
                    Instr::I64GeU(i) => bin(r, i, |x: u64, y| x >= y),
                    Instr::F32Eq(i) => bin(r, i, |x: f32, y| x == y),
                    Instr::F32Ne(i) => bin(r, i, |x: f32, y| x != y),
                    Instr::F32Lt(i) => bin(r, i, |x: f32, y| x < y),
                    Instr::F32Gt(i) => bin(r, i, |x: f32, y| x > y),
                    Instr::F32Le(i) => bin(r, i, |x: f32, y| x <= y),
                    Instr::F32Ge(i) => bin(r, i, |x: f32, y| x >= y),
                    Instr::F64Eq(i) => bin(r, i, |x: f64, y| x == y),
                    Instr::F64Ne(i) => bin(r, i, |x: f64, y| x != y),
                    Instr::F64Lt(i) => bin(r, i, |x: f64, y| x < y),
                    Instr::F64Gt(i) => bin(r, i, |x: f64, y| x > y),
                    Instr::F64Le(i) => bin(r, i, |x: f64, y| x <= y),
                    Instr::F64Ge(i) => bin(r, i, |x: f64, y| x >= y),
                    Instr::I32Add(i) => bin(r, i, u32::wrapping_add),
                    Instr::I32Sub(i) => bin(r, i, u32::wrapping_sub),
                    Instr::I32Mul(i) => bin(r, i, u32::wrapping_mul),
                    Instr::I32DivS(i) => try_bin(r, i, div_s32)?,
                    Instr::I32DivU(i) => try_bin(r, i, div_u32)?,
                    Instr::I32RemS(i) => try_bin(r, i, rem_s32)?,
                    Instr::I32RemU(i) => try_bin(r, i, rem_u32)?,
                    Instr::I32And(i) => bin(r, i, |x: u32, y| x & y),
                    Instr::I32Or(i) => bin(r, i, |x: u32, y| x | y),
                    Instr::I32Xor(i) => bin(r, i, |x: u32, y| x ^ y),
                    Instr::I32Shl(i) => bin(r, i, |x: u32, y| x.wrapping_shl(y)),
                    Instr::I32ShrS(i) => bin(r, i, |x: i32, y| x.wrapping_shr(y as u32)),
                    Instr::I32ShrU(i) => bin(r, i, |x: u32, y| x.wrapping_shr(y)),
                    Instr::I32Rotl(i) => bin(r, i, |x: u32, y| x.rotate_left(y & 31)),
                    Instr::I32Rotr(i) => bin(r, i, |x: u32, y| x.rotate_right(y & 31)),
                    Instr::I64Add(i) => bin(r, i, u64::wrapping_add),
                    Instr::I64Sub(i) => bin(r, i, u64::wrapping_sub),
                    Instr::I64Mul(i) => bin(r, i, u64::wrapping_mul),
                    Instr::I64DivS(i) => try_bin(r, i, div_s64)?,
                    Instr::I64DivU(i) => try_bin(r, i, div_u64)?,
                    Instr::I64RemS(i) => try_bin(r, i, rem_s64)?,
                    Instr::I64RemU(i) => try_bin(r, i, rem_u64)?,
                    Instr::I64And(i) => bin(r, i, |x: u64, y| x & y),
                    Instr::I64Or(i) => bin(r, i, |x: u64, y| x | y),
                    Instr::I64Xor(i) => bin(r, i, |x: u64, y| x ^ y),
                    Instr::I64Shl(i) => bin(r, i, |x: u64, y| x.wrapping_shl(y as u32)),
                    Instr::I64ShrS(i) => bin(r, i, |x: i64, y| x.wrapping_shr(y as u32)),
                    Instr::I64ShrU(i) => bin(r, i, |x: u64, y| x.wrapping_shr(y as u32)),
                    Instr::I64Rotl(i) => bin(r, i, |x: u64, y| x.rotate_left((y & 63) as u32)),
                    Instr::I64Rotr(i) => bin(r, i, |x: u64, y| x.rotate_right((y & 63) as u32)),
                    Instr::F32Add(i) => bin(r, i, |x: f32, y| c32(x + y)),
                    Instr::F32Sub(i) => bin(r, i, |x: f32, y| c32(x - y)),
                    Instr::F32Mul(i) => bin(r, i, |x: f32, y| c32(x * y)),
                    Instr::F32Div(i) => bin(r, i, |x: f32, y| c32(x / y)),
                    Instr::F32Min(i) => bin(r, i, fmin32),
                    Instr::F32Max(i) => bin(r, i, fmax32),
                    Instr::F32Copysign(i) => {
                        bin(r, i, |x: u32, y| (x & 0x7fff_ffff) | (y & 0x8000_0000));
                    }
                    Instr::F64Add(i) => bin(r, i, |x: f64, y| c64(x + y)),
                    Instr::F64Sub(i) => bin(r, i, |x: f64, y| c64(x - y)),
                    Instr::F64Mul(i) => bin(r, i, |x: f64, y| c64(x * y)),
                    Instr::F64Div(i) => bin(r, i, |x: f64, y| c64(x / y)),
                    Instr::F64Min(i) => bin(r, i, fmin64),
                    Instr::F64Max(i) => bin(r, i, fmax64),
                    Instr::F64Copysign(i) => bin(r, i, |x: u64, y| {
                        (x & 0x7fff_ffff_ffff_ffff) | (y & 0x8000_0000_0000_0000)
                    }),
                }
            }
        }
    }
}
