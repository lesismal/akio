//! The register form (ADR-125, section 1): what a function body is translated to, and the
//! interpreter runs.
//!
//! A frame is a run of 64-bit slots: the function's locals (parameters first), then one slot for
//! each position of WebAssembly's operand stack, whose height is static at each instruction. An
//! instruction names the slots it reads and writes (`u32` indices from the frame's start), so
//! nothing is pushed or popped at run time. Branch targets are instruction indices in the
//! function's code. Every instruction is 16 bytes.
//!
//! What a slot holds: an `i32` or `f32` zero-extended (an `f32` as its bits), an `i64` or `f64`
//! as its 64 bits, a reference as 0 for null, else a function's index in the store plus one, or
//! a host value plus one.

/// An operation with one operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Un {
    pub(crate) d: u32,
    pub(crate) a: u32,
}

/// An operation with two operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bin {
    pub(crate) d: u32,
    pub(crate) a: u32,
    pub(crate) b: u32,
}

/// A load (`x` the destination) or a store (`x` the value): address slot `a` plus `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mem {
    pub(crate) x: u32,
    pub(crate) a: u32,
    pub(crate) off: u32,
}

/// An integer comparison, for the fused compare-and-branch instructions and the immediate forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmp {
    Eq,
    Ne,
    LtS,
    LtU,
    GtS,
    GtU,
    LeS,
    LeU,
    GeS,
    GeU,
}

impl Cmp {
    /// The comparison that is true exactly when this one is false.
    pub(crate) const fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::LtS => Self::GeS,
            Self::LtU => Self::GeU,
            Self::GtS => Self::LeS,
            Self::GtU => Self::LeU,
            Self::LeS => Self::GtS,
            Self::LeU => Self::GtU,
            Self::GeS => Self::LtS,
            Self::GeU => Self::LtU,
        }
    }

    /// The comparison of an `i32` compare opcode (`0x46..=0x4f`) or an `i64` one (`0x51..=0x5a`).
    pub(crate) const fn of_opcode(op: u8) -> Option<Self> {
        let k = match op {
            0x46..=0x4f => op - 0x46,
            0x51..=0x5a => op - 0x51,
            _ => return None,
        };
        Some(match k {
            0 => Self::Eq,
            1 => Self::Ne,
            2 => Self::LtS,
            3 => Self::LtU,
            4 => Self::GtS,
            5 => Self::GtU,
            6 => Self::LeS,
            7 => Self::LeU,
            8 => Self::GeS,
            _ => Self::GeU,
        })
    }

    #[inline]
    pub(crate) const fn i32(self, x: i32, y: i32) -> bool {
        let (ux, uy) = (x as u32, y as u32);
        match self {
            Self::Eq => x == y,
            Self::Ne => x != y,
            Self::LtS => x < y,
            Self::LtU => ux < uy,
            Self::GtS => x > y,
            Self::GtU => ux > uy,
            Self::LeS => x <= y,
            Self::LeU => ux <= uy,
            Self::GeS => x >= y,
            Self::GeU => ux >= uy,
        }
    }

    #[inline]
    pub(crate) const fn i64(self, x: i64, y: i64) -> bool {
        let (ux, uy) = (x as u64, y as u64);
        match self {
            Self::Eq => x == y,
            Self::Ne => x != y,
            Self::LtS => x < y,
            Self::LtU => ux < uy,
            Self::GtS => x > y,
            Self::GtU => ux > uy,
            Self::LeS => x <= y,
            Self::LeU => ux <= uy,
            Self::GeS => x >= y,
            Self::GeU => ux >= uy,
        }
    }
}

/// An integer operation with an immediate second operand (`I32BinI`, `I64BinI`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    ShrS,
    ShrU,
    Rotl,
    Rotr,
    Cmp(Cmp),
}

impl BinOp {
    /// The operation of an `i32` binary opcode (or `i64`, `wide`), if it has an immediate form.
    pub(crate) const fn of_opcode(op: u8) -> Option<Self> {
        if let Some(c) = Cmp::of_opcode(op) {
            return Some(Self::Cmp(c));
        }
        let k = match op {
            0x6a..=0x78 => op - 0x6a,
            0x7c..=0x8a => op - 0x7c,
            _ => return None,
        };
        Some(match k {
            0 => Self::Add,
            1 => Self::Sub,
            2 => Self::Mul,
            7 => Self::And,
            8 => Self::Or,
            9 => Self::Xor,
            10 => Self::Shl,
            11 => Self::ShrS,
            12 => Self::ShrU,
            13 => Self::Rotl,
            14 => Self::Rotr,
            _ => return None, // division and remainder trap: no immediate form
        })
    }

    /// Whether `a op b == b op a`, so that a constant first operand can be the immediate.
    pub(crate) const fn commutes(self) -> bool {
        matches!(
            self,
            Self::Add | Self::Mul | Self::And | Self::Or | Self::Xor | Self::Cmp(Cmp::Eq | Cmp::Ne)
        )
    }

    #[inline]
    pub(crate) const fn i32(self, x: i32, y: i32) -> i32 {
        match self {
            Self::Add => x.wrapping_add(y),
            Self::Sub => x.wrapping_sub(y),
            Self::Mul => x.wrapping_mul(y),
            Self::And => x & y,
            Self::Or => x | y,
            Self::Xor => x ^ y,
            Self::Shl => x.wrapping_shl(y as u32),
            Self::ShrS => x.wrapping_shr(y as u32),
            Self::ShrU => (x as u32).wrapping_shr(y as u32) as i32,
            Self::Rotl => x.rotate_left(y as u32 & 31),
            Self::Rotr => x.rotate_right(y as u32 & 31),
            Self::Cmp(c) => c.i32(x, y) as i32,
        }
    }

    #[inline]
    pub(crate) const fn i64(self, x: i64, y: i64) -> u64 {
        (match self {
            Self::Add => x.wrapping_add(y),
            Self::Sub => x.wrapping_sub(y),
            Self::Mul => x.wrapping_mul(y),
            Self::And => x & y,
            Self::Or => x | y,
            Self::Xor => x ^ y,
            Self::Shl => x.wrapping_shl(y as u32),
            Self::ShrS => x.wrapping_shr(y as u32),
            Self::ShrU => (x as u64).wrapping_shr(y as u32) as i64,
            Self::Rotl => x.rotate_left((y & 63) as u32),
            Self::Rotr => x.rotate_right((y & 63) as u32),
            // An `i32` result, zero-extended.
            Self::Cmp(c) => return c.i64(x, y) as u64,
        }) as u64
    }
}

macro_rules! instrs {
    (
        fixed { $($fixed:tt)* }
        dest { $($dname:ident),* }
        un { $($un:ident = $uop:literal,)* }
        bin { $($bin:ident = $bop:literal,)* }
        load { $($load:ident = $lop:literal,)* }
        store { $($store:ident = $sop:literal,)* }
    ) => {
        /// One instruction of the register form.
        #[derive(Debug, Clone, Copy, PartialEq)]
        pub(crate) enum Instr {
            $($fixed)*
            $($un(Un),)*
            $($bin(Bin),)*
            $($load(Mem),)*
            $($store(Mem),)*
        }

        impl Instr {
            /// The numeric instruction of `op` (`0x45..=0xc4`, or `0x100 + k` for
            /// `trunc_sat` `k`): one operand `a`, or two `a` and `b`.
            pub(crate) const fn numeric(op: u16, d: u32, a: u32, b: u32) -> Option<Self> {
                Some(match op {
                    $($uop => Self::$un(Un { d, a }),)*
                    $($bop => Self::$bin(Bin { d, a, b }),)*
                    _ => {
                        let _ = b;
                        return None;
                    }
                })
            }

            /// Whether `op` (a numeric opcode as for [`Instr::numeric`]) takes two operands.
            pub(crate) const fn is_binary(op: u16) -> bool {
                matches!(op, $($bop)|*)
            }

            /// The load of opcode `op` (`0x28..=0x35`).
            pub(crate) const fn load(op: u8, x: u32, a: u32, off: u32) -> Option<Self> {
                Some(match op {
                    $($lop => Self::$load(Mem { x, a, off }),)*
                    _ => return None,
                })
            }

            /// The store of opcode `op` (`0x36..=0x3e`).
            pub(crate) const fn store(op: u8, x: u32, a: u32, off: u32) -> Option<Self> {
                Some(match op {
                    $($sop => Self::$store(Mem { x, a, off }),)*
                    _ => return None,
                })
            }

            /// The slot this instruction writes its one result to, if it is one that reads all
            /// its operands before writing and writes nothing else: its destination may then be
            /// moved (to a local, for `local.set`).
            pub(crate) fn dest_mut(&mut self) -> Option<&mut u32> {
                match self {
                    $(Self::$un(x) => Some(&mut x.d),)*
                    $(Self::$bin(x) => Some(&mut x.d),)*
                    $(Self::$load(x) => Some(&mut x.x),)*
                    $(Self::$dname { d, .. } => Some(d),)*
                    _ => None,
                }
            }
        }
    };
}

instrs! {
    fixed {
        /// Traps.
        Unreachable,
        /// Meters a basic block: takes `n` from the call's budget (ADR-125, section 3).
        Fuel { n: u32 },
        /// Jumps to `t`.
        Br { t: u32 },
        /// Jumps to `t` if slot `c` (an `i32`) is not zero.
        BrIfNz { c: u32, t: u32 },
        /// Jumps to `t` if slot `c` (an `i32`) is zero.
        BrIfZ { c: u32, t: u32 },
        /// Jumps to `t` if the `i32` comparison holds.
        BrCmp32 { op: Cmp, a: u32, b: u32, t: u32 },
        /// Jumps to `t` if the `i32` comparison with an immediate holds.
        BrCmp32I { op: Cmp, a: u32, imm: i32, t: u32 },
        /// Jumps to `t` if the `i64` comparison holds.
        BrCmp64 { op: Cmp, a: u32, b: u32, t: u32 },
        /// Jumps to `t` if the `i64` comparison with an immediate (sign-extended) holds.
        BrCmp64I { op: Cmp, a: u32, imm: i32, t: u32 },
        /// Jumps to the `min(slot s, n)`-th of the `n + 1` `Br` instructions that follow.
        BrTable { s: u32, n: u32 },
        /// Copies slot `s` to slot `d`.
        Copy { d: u32, s: u32 },
        /// Copies slots `s..s + n` to `d..d + n` (`d < s`).
        CopyRange { d: u32, s: u32, n: u32 },
        /// Writes a 32-bit constant (zero-extended).
        Const32 { d: u32, v: u32 },
        /// Writes a 64-bit constant.
        Const64 { d: u32, v: u64 },
        /// An `i32` operation with an immediate second operand.
        I32BinI { op: BinOp, d: u32, a: u32, imm: i32 },
        /// An `i64` operation with an immediate (sign-extended) second operand.
        I64BinI { op: BinOp, d: u32, a: u32, imm: i32 },
        /// Returns no value.
        Return0,
        /// Returns slot `s`.
        Return1 { s: u32 },
        /// Returns slots `s..s + n`.
        ReturnN { s: u32, n: u32 },
        /// Calls the module's defined function `f`; its frame starts at slot `base`, where the
        /// arguments are and the results go.
        Call { f: u32, base: u32 },
        /// Calls the instance's imported function `f` (a module function index).
        CallImport { f: u32, base: u32 },
        /// Calls through table `table`, checked against type `ty`; the element index is in the
        /// slot after the arguments.
        CallIndirect { base: u32, ty: u32, table: u32 },
        /// `d = c != 0 ? d : b` (the first operand is in `d`).
        Select { d: u32, b: u32, c: u32 },
        GlobalGet { d: u32, g: u32 },
        GlobalSet { s: u32, g: u32 },
        TableGet { d: u32, a: u32, t: u32 },
        TableSet { a: u32, v: u32, t: u32 },
        TableSize { d: u32, t: u32 },
        /// `table.grow`: the initial value in `s`, the count in `s + 1`, the result to `s`.
        TableGrow { s: u32, t: u32 },
        /// `table.fill`: operands in `s`, `s + 1`, `s + 2`.
        TableFill { s: u32, t: u32 },
        TableCopy { s: u32, dst: u32, src: u32 },
        TableInit { s: u32, elem: u32, table: u32 },
        ElemDrop { e: u32 },
        MemorySize { d: u32 },
        MemoryGrow { d: u32, a: u32 },
        /// `memory.fill`: operands in `s`, `s + 1`, `s + 2`.
        MemoryFill { s: u32 },
        MemoryCopy { s: u32 },
        MemoryInit { s: u32, seg: u32 },
        DataDrop { seg: u32 },
        /// A reference to the module's function `f`.
        RefFunc { d: u32, f: u32 },
    }
    dest {
        Copy, Const32, Const64, I32BinI, I64BinI, GlobalGet, TableGet, TableSize, MemorySize,
        MemoryGrow, RefFunc
    }
    un {
        I32Eqz = 0x45,
        I64Eqz = 0x50,
        I32Clz = 0x67,
        I32Ctz = 0x68,
        I32Popcnt = 0x69,
        I64Clz = 0x79,
        I64Ctz = 0x7a,
        I64Popcnt = 0x7b,
        F32Abs = 0x8b,
        F32Neg = 0x8c,
        F32Ceil = 0x8d,
        F32Floor = 0x8e,
        F32Trunc = 0x8f,
        F32Nearest = 0x90,
        F32Sqrt = 0x91,
        F64Abs = 0x99,
        F64Neg = 0x9a,
        F64Ceil = 0x9b,
        F64Floor = 0x9c,
        F64Trunc = 0x9d,
        F64Nearest = 0x9e,
        F64Sqrt = 0x9f,
        I32WrapI64 = 0xa7,
        I32TruncF32S = 0xa8,
        I32TruncF32U = 0xa9,
        I32TruncF64S = 0xaa,
        I32TruncF64U = 0xab,
        I64ExtendI32S = 0xac,
        I64ExtendI32U = 0xad,
        I64TruncF32S = 0xae,
        I64TruncF32U = 0xaf,
        I64TruncF64S = 0xb0,
        I64TruncF64U = 0xb1,
        F32ConvertI32S = 0xb2,
        F32ConvertI32U = 0xb3,
        F32ConvertI64S = 0xb4,
        F32ConvertI64U = 0xb5,
        F32DemoteF64 = 0xb6,
        F64ConvertI32S = 0xb7,
        F64ConvertI32U = 0xb8,
        F64ConvertI64S = 0xb9,
        F64ConvertI64U = 0xba,
        F64PromoteF32 = 0xbb,
        I32Extend8S = 0xc0,
        I32Extend16S = 0xc1,
        I64Extend8S = 0xc2,
        I64Extend16S = 0xc3,
        I64Extend32S = 0xc4,
        I32TruncSatF32S = 0x100,
        I32TruncSatF32U = 0x101,
        I32TruncSatF64S = 0x102,
        I32TruncSatF64U = 0x103,
        I64TruncSatF32S = 0x104,
        I64TruncSatF32U = 0x105,
        I64TruncSatF64S = 0x106,
        I64TruncSatF64U = 0x107,
    }
    bin {
        I32Eq = 0x46,
        I32Ne = 0x47,
        I32LtS = 0x48,
        I32LtU = 0x49,
        I32GtS = 0x4a,
        I32GtU = 0x4b,
        I32LeS = 0x4c,
        I32LeU = 0x4d,
        I32GeS = 0x4e,
        I32GeU = 0x4f,
        I64Eq = 0x51,
        I64Ne = 0x52,
        I64LtS = 0x53,
        I64LtU = 0x54,
        I64GtS = 0x55,
        I64GtU = 0x56,
        I64LeS = 0x57,
        I64LeU = 0x58,
        I64GeS = 0x59,
        I64GeU = 0x5a,
        F32Eq = 0x5b,
        F32Ne = 0x5c,
        F32Lt = 0x5d,
        F32Gt = 0x5e,
        F32Le = 0x5f,
        F32Ge = 0x60,
        F64Eq = 0x61,
        F64Ne = 0x62,
        F64Lt = 0x63,
        F64Gt = 0x64,
        F64Le = 0x65,
        F64Ge = 0x66,
        I32Add = 0x6a,
        I32Sub = 0x6b,
        I32Mul = 0x6c,
        I32DivS = 0x6d,
        I32DivU = 0x6e,
        I32RemS = 0x6f,
        I32RemU = 0x70,
        I32And = 0x71,
        I32Or = 0x72,
        I32Xor = 0x73,
        I32Shl = 0x74,
        I32ShrS = 0x75,
        I32ShrU = 0x76,
        I32Rotl = 0x77,
        I32Rotr = 0x78,
        I64Add = 0x7c,
        I64Sub = 0x7d,
        I64Mul = 0x7e,
        I64DivS = 0x7f,
        I64DivU = 0x80,
        I64RemS = 0x81,
        I64RemU = 0x82,
        I64And = 0x83,
        I64Or = 0x84,
        I64Xor = 0x85,
        I64Shl = 0x86,
        I64ShrS = 0x87,
        I64ShrU = 0x88,
        I64Rotl = 0x89,
        I64Rotr = 0x8a,
        F32Add = 0x92,
        F32Sub = 0x93,
        F32Mul = 0x94,
        F32Div = 0x95,
        F32Min = 0x96,
        F32Max = 0x97,
        F32Copysign = 0x98,
        F64Add = 0xa0,
        F64Sub = 0xa1,
        F64Mul = 0xa2,
        F64Div = 0xa3,
        F64Min = 0xa4,
        F64Max = 0xa5,
        F64Copysign = 0xa6,
    }
    load {
        I32Load = 0x28,
        I64Load = 0x29,
        F32Load = 0x2a,
        F64Load = 0x2b,
        I32Load8S = 0x2c,
        I32Load8U = 0x2d,
        I32Load16S = 0x2e,
        I32Load16U = 0x2f,
        I64Load8S = 0x30,
        I64Load8U = 0x31,
        I64Load16S = 0x32,
        I64Load16U = 0x33,
        I64Load32S = 0x34,
        I64Load32U = 0x35,
    }
    store {
        I32Store = 0x36,
        I64Store = 0x37,
        F32Store = 0x38,
        F64Store = 0x39,
        I32Store8 = 0x3a,
        I32Store16 = 0x3b,
        I64Store8 = 0x3c,
        I64Store16 = 0x3d,
        I64Store32 = 0x3e,
    }
}

impl Instr {
    /// Points a branch at `t`; false for an instruction that is not a branch.
    pub(crate) fn set_target(&mut self, to: u32) -> bool {
        match self {
            Self::Br { t }
            | Self::BrIfNz { t, .. }
            | Self::BrIfZ { t, .. }
            | Self::BrCmp32 { t, .. }
            | Self::BrCmp32I { t, .. }
            | Self::BrCmp64 { t, .. }
            | Self::BrCmp64I { t, .. } => {
                *t = to;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_are_16_bytes() {
        assert_eq!(size_of::<Instr>(), 16);
    }

    #[test]
    fn negated_comparisons() {
        let ops = [
            Cmp::Eq,
            Cmp::Ne,
            Cmp::LtS,
            Cmp::LtU,
            Cmp::GtS,
            Cmp::GtU,
            Cmp::LeS,
            Cmp::LeU,
            Cmp::GeS,
            Cmp::GeU,
        ];
        let vals = [i64::MIN, -1, 0, 1, i64::MAX];
        for op in ops {
            assert_eq!(op.negate().negate(), op);
            for &x in &vals {
                for &y in &vals {
                    assert_eq!(op.i64(x, y), !op.negate().i64(x, y));
                    assert_eq!(
                        op.i32(x as i32, y as i32),
                        !op.negate().i32(x as i32, y as i32)
                    );
                }
            }
        }
    }
}
