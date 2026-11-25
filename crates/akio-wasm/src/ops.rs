//! Decoding instructions: one [`Op`] at a time from a function body or a constant expression.
//! The opcodes of refused features are recognised and named (ADR-125, section 2).

use crate::{
    error::{Feature, Result, malformed, unsupported},
    reader::Reader,
    types::{RefType, ValType, decode_valtype},
};

/// A block's type: what it takes from the stack and leaves on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlockType {
    Empty,
    Value(ValType),
    /// A function type's index (multi-value).
    Func(u32),
}

/// A memory access's immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemArg {
    /// log2 of the alignment hint.
    pub(crate) align: u32,
    pub(crate) offset: u32,
}

/// One instruction. `BrTable`'s labels are left in the decoder's buffer
/// ([`Decoder::br_targets`]), the default last.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Op {
    Unreachable,
    Nop,
    Block(BlockType),
    Loop(BlockType),
    If(BlockType),
    Else,
    End,
    Br(u32),
    BrIf(u32),
    BrTable,
    Return,
    Call(u32),
    CallIndirect {
        ty: u32,
        table: u32,
    },
    Drop,
    /// `select`, or `select t` with its one type.
    Select(Option<ValType>),
    LocalGet(u32),
    LocalSet(u32),
    LocalTee(u32),
    GlobalGet(u32),
    GlobalSet(u32),
    TableGet(u32),
    TableSet(u32),
    /// A load (opcodes `0x28..=0x35`).
    Load(u8, MemArg),
    /// A store (opcodes `0x36..=0x3e`).
    Store(u8, MemArg),
    MemorySize,
    MemoryGrow,
    I32Const(i32),
    I64Const(i64),
    F32Const(u32),
    F64Const(u64),
    /// A numeric instruction without immediates (opcodes `0x45..=0xc4`).
    Numeric(u8),
    RefNull(RefType),
    RefIsNull,
    RefFunc(u32),
    /// `i32.trunc_sat_f32_s` (0) to `i64.trunc_sat_f64_u` (7).
    TruncSat(u8),
    MemoryInit(u32),
    DataDrop(u32),
    MemoryCopy,
    MemoryFill,
    TableInit {
        elem: u32,
        table: u32,
    },
    ElemDrop(u32),
    TableCopy {
        dst: u32,
        src: u32,
    },
    TableGrow(u32),
    TableSize(u32),
    TableFill(u32),
}

/// Decodes instructions; owns the buffer `br_table`'s labels are read into.
#[derive(Debug, Default)]
pub(crate) struct Decoder {
    pub(crate) br_targets: Vec<u32>,
}

/// The natural alignment (log2) of a load or store opcode.
pub(crate) const fn natural_align(op: u8) -> u32 {
    match op {
        0x28 | 0x2a | 0x34 | 0x35 | 0x36 | 0x38 | 0x3e => 2,
        0x29 | 0x2b | 0x37 | 0x39 => 3,
        0x2c | 0x2d | 0x30 | 0x31 | 0x3a | 0x3c => 0,
        _ => 1, // 0x2e 0x2f 0x32 0x33 0x3b 0x3d
    }
}

impl Decoder {
    /// Reads one instruction. `max_br_targets` bounds a `br_table`'s labels, default included
    /// (checked before they are read).
    pub(crate) fn read(&mut self, r: &mut Reader<'_>, max_br_targets: u32) -> Result<Op> {
        let at = r.offset();
        let op = r.u8()?;
        Ok(match op {
            0x00 => Op::Unreachable,
            0x01 => Op::Nop,
            0x02 => Op::Block(read_block_type(r)?),
            0x03 => Op::Loop(read_block_type(r)?),
            0x04 => Op::If(read_block_type(r)?),
            0x05 => Op::Else,
            0x06..=0x0a | 0x18 | 0x19 | 0x1f => {
                return Err(unsupported(
                    at,
                    Feature::ExceptionHandling,
                    "exception-handling instruction",
                ));
            }
            0x0b => Op::End,
            0x0c => Op::Br(r.u32()?),
            0x0d => Op::BrIf(r.u32()?),
            0x0e => {
                let n_at = r.offset();
                let n = r.count(1)?;
                if n >= max_br_targets {
                    return Err(crate::error::limit(
                        n_at,
                        crate::error::Limit::BrTableTargets,
                        "too many br_table targets",
                    ));
                }
                self.br_targets.clear();
                self.br_targets.reserve(n as usize + 1);
                for _ in 0..=n {
                    let l = r.u32()?;
                    self.br_targets.push(l);
                }
                Op::BrTable
            }
            0x0f => Op::Return,
            0x10 => Op::Call(r.u32()?),
            0x11 => {
                let ty = r.u32()?;
                let table = r.u32()?;
                Op::CallIndirect { ty, table }
            }
            0x12 | 0x13 | 0x15 => {
                return Err(unsupported(at, Feature::TailCalls, "tail call"));
            }
            0x14 | 0xd4..=0xd6 => {
                return Err(unsupported(
                    at,
                    Feature::FunctionReferences,
                    "typed function reference instruction",
                ));
            }
            0xd3 => return Err(unsupported(at, Feature::Gc, "ref.eq")),
            0x1a => Op::Drop,
            0x1b => Op::Select(None),
            0x1c => {
                let n_at = r.offset();
                let n = r.u32()?;
                if n != 1 {
                    // Several types would be a later proposal; the specification calls it invalid.
                    return Err(crate::error::invalid(n_at, "invalid result arity"));
                }
                Op::Select(Some(ValType::read(r)?))
            }
            0x20 => Op::LocalGet(r.u32()?),
            0x21 => Op::LocalSet(r.u32()?),
            0x22 => Op::LocalTee(r.u32()?),
            0x23 => Op::GlobalGet(r.u32()?),
            0x24 => Op::GlobalSet(r.u32()?),
            0x25 => Op::TableGet(r.u32()?),
            0x26 => Op::TableSet(r.u32()?),
            0x28..=0x35 => Op::Load(op, read_memarg(r)?),
            0x36..=0x3e => Op::Store(op, read_memarg(r)?),
            0x3f => {
                read_memory_zero(r)?;
                Op::MemorySize
            }
            0x40 => {
                read_memory_zero(r)?;
                Op::MemoryGrow
            }
            0x41 => Op::I32Const(r.s32()?),
            0x42 => Op::I64Const(r.s64()?),
            0x43 => Op::F32Const(r.f32_bits()?),
            0x44 => Op::F64Const(r.f64_bits()?),
            0x45..=0xc4 => Op::Numeric(op),
            0xd0 => Op::RefNull(read_heap_type(r)?),
            0xd1 => Op::RefIsNull,
            0xd2 => Op::RefFunc(r.u32()?),
            0xfb => return Err(unsupported(at, Feature::Gc, "GC instruction")),
            0xfc => {
                let sub = r.u32()?;
                match sub {
                    0..=7 => Op::TruncSat(sub as u8),
                    8 => {
                        let seg = r.u32()?;
                        read_memory_zero(r)?;
                        Op::MemoryInit(seg)
                    }
                    9 => Op::DataDrop(r.u32()?),
                    10 => {
                        read_memory_zero(r)?;
                        read_memory_zero(r)?;
                        Op::MemoryCopy
                    }
                    11 => {
                        read_memory_zero(r)?;
                        Op::MemoryFill
                    }
                    12 => {
                        let elem = r.u32()?;
                        let table = r.u32()?;
                        Op::TableInit { elem, table }
                    }
                    13 => Op::ElemDrop(r.u32()?),
                    14 => {
                        let dst = r.u32()?;
                        let src = r.u32()?;
                        Op::TableCopy { dst, src }
                    }
                    15 => Op::TableGrow(r.u32()?),
                    16 => Op::TableSize(r.u32()?),
                    17 => Op::TableFill(r.u32()?),
                    19..=22 => {
                        return Err(unsupported(
                            at,
                            Feature::WideArithmetic,
                            "wide-arithmetic instruction",
                        ));
                    }
                    _ => return Err(malformed(at, "illegal opcode")),
                }
            }
            0xfd => {
                let sub = r.u32()?;
                return Err(unsupported(
                    at,
                    Feature::Simd,
                    if (0x100..=0x113).contains(&sub) {
                        "relaxed SIMD instruction"
                    } else {
                        "SIMD instruction"
                    },
                ));
            }
            0xfe => return Err(unsupported(at, Feature::Threads, "atomic instruction")),
            _ => return Err(malformed(at, "illegal opcode")),
        })
    }
}

fn read_block_type(r: &mut Reader<'_>) -> Result<BlockType> {
    let at = r.offset();
    match r.peek() {
        Some(0x40) => {
            r.u8()?;
            Ok(BlockType::Empty)
        }
        // A one-byte negative s33 is a value type.
        Some(b) if b & 0xc0 == 0x40 => {
            r.u8()?;
            Ok(BlockType::Value(decode_valtype(b, at)?))
        }
        _ => {
            let idx = r.s33()?;
            u32::try_from(idx)
                .map(BlockType::Func)
                .map_err(|_| malformed(at, "malformed block type"))
        }
    }
}

fn read_heap_type(r: &mut Reader<'_>) -> Result<RefType> {
    let at = r.offset();
    let b = r.peek().ok_or_else(|| malformed(at, "unexpected end"))?;
    if b & 0xc0 != 0x40 {
        // A type index: a typed function reference.
        r.s33()?;
        return Err(unsupported(
            at,
            Feature::FunctionReferences,
            "concrete heap type",
        ));
    }
    r.u8()?;
    match b {
        0x70 => Ok(RefType::FuncRef),
        0x6f => Ok(RefType::ExternRef),
        0x69 | 0x74 => Err(unsupported(at, Feature::ExceptionHandling, "exn heap type")),
        0x6a..=0x6e | 0x71..=0x73 => Err(unsupported(at, Feature::Gc, "GC heap type")),
        _ => Err(malformed(at, "malformed reference type")),
    }
}

fn read_memarg(r: &mut Reader<'_>) -> Result<MemArg> {
    let at = r.offset();
    let align = r.u32()?;
    if align >= 32 {
        return Err(if (0x40..0x80).contains(&align) {
            // Bit 6 announces a memory index (multi-memory).
            unsupported(at, Feature::MultiMemory, "memory index")
        } else {
            malformed(at, "malformed memop flags")
        });
    }
    let offset = r.u32()?;
    Ok(MemArg { align, offset })
}

/// The memory index of `memory.size` and the bulk instructions: one zero byte.
fn read_memory_zero(r: &mut Reader<'_>) -> Result<()> {
    let at = r.offset();
    match r.u8()? {
        0 => Ok(()),
        b if b & 0x80 != 0 => Err(malformed(at, "zero byte expected")),
        _ => Err(unsupported(at, Feature::MultiMemory, "memory index")),
    }
}
