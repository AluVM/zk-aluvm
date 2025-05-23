// AluVM ISA extension for Galois fields
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2024-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@ubideco.org>
//
// Copyright (C) 2024-2025 Laboratories for Ubiquitous Deterministic Computing (UBIDECO),
//                         Institute for Distributed and Cognitive Systems (InDCS), Switzerland.
// Copyright (C) 2024-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use aluvm::isa::{CtrlInstr, ReservedInstr};
use aluvm::SiteId;
use amplify::num::{u2, u3};

use crate::{fe256, RegE};

/// Instruction set, which includes core AluVM control-flow instructions and GFA256 ISA extension
/// (see [`FieldInstr`]).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display, From)]
#[display(inner)]
#[non_exhaustive]
pub enum Instr<Id: SiteId> {
    /// Control flow instructions.
    #[from]
    Ctrl(CtrlInstr<Id>),

    /// Arithmetic instructions for finite fields.
    #[from]
    Gfa(FieldInstr),

    /// Reserved instruction for future use in core `ALU` ISAs.
    #[from]
    Reserved(ReservedInstr),
}

/// Arithmetic instructions for finite fields.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[non_exhaustive]
pub enum FieldInstr {
    /// Tests if register contains a value and is not set to `None`.
    ///
    /// Sets `CO` register to [`Status::Ok`] if a register contains a value, and to [`Status::Fail`]
    /// otherwise.
    ///
    /// Does not affect the value in the `CK` register.
    #[display("test    {src}")]
    Test {
        /** The source register */
        src: RegE,
    },

    /// Clears register value by setting it to `None`.
    ///
    /// Does not affect values in the `CO` and `CK` registers.
    #[display("clr     {dst}")]
    Clr {
        /** The destination register */
        dst: RegE,
    },

    /// Puts value into a register, replacing the previous value in it if there was any.
    ///
    /// Does not affect values in the `CO` and `CK` registers.
    #[display("put     {dst}, {data}")]
    PutD {
        /** The destination register */
        dst: RegE,
        /** Finite field element taken from the data segment, used to initialize the register */
        data: fe256,
    },

    /// Puts zero (`0`) value into a register, replacing the previous value in it if there was any.
    ///
    /// Does not affect values in the `CO` and `CK` registers.
    #[display("put     {dst}, 0")]
    PutZ {
        /** The destination register */
        dst: RegE,
    },

    /// Puts `val` value, which is a power of 2, into a register, replacing the previous value in
    /// it if there was any.
    ///
    /// Does not affect values in the `CO` and `CK` registers.
    #[display("put     {dst}, {val}")]
    PutV {
        /** The destination register */
        dst: RegE,
        /** A constant finite field element used to initialize the register */
        val: ConstVal,
    },

    /// Test whether a value in a register fits in the provided number of bits.
    ///
    /// Sets `CO` register to [`Status::Ok`] if the value fits the given number of bits, and to
    /// [`Status::Fail`] otherwise.
    ///
    /// If `src` is set to `None`, sets both `CO` and `CK` to [`Status::Fail`]; otherwise leaves
    /// value in the `CK` unchanged.
    #[display("fits    {src}, {bits}")]
    Fits {
        /** The source register */
        src: RegE,
        /** The maximum bit dimension which the source register value must fit into */
        bits: Bits,
    },

    /// Moves (copies) value from `src` to `dst` register, overwriting the previous value in `dst`.
    /// If `src` has no value (i.e., set to `None`), sets `dst` to `None`.
    ///
    /// Leaves the state of the `src` register unaffected.
    ///
    /// Does not affect values in the `CO` and `CK` registers.
    #[display("mov     {dst}, {src}")]
    Mov {
        /** The destination register */
        dst: RegE,
        /** The source register */
        src: RegE,
    },

    /// Checks whether `src1` and `src2` registers are equal.
    ///
    /// Sets `CO` register to represent equivalence of the registers. If both `src1` and `src2`
    /// registers contain no value, sets `CK` to a failed state.
    ///
    /// Does not affect the value in the `CK` register.
    #[display("eq      {src1}, {src2}")]
    Eq {
        /** The first source register */
        src1: RegE,
        /** The second source register */
        src2: RegE,
    },

    /// Negate value in `src` using finite-field arithmetics, and put result into `dst`.
    ///
    /// Does not affect values in the `CO` register.
    ///
    /// If `src` is set to `None`, sets `CK` to [`Status::Fail`]; otherwise leaves value in  `CK`
    /// unchanged.
    #[display("neg     {dst}, {src}")]
    Neg {
        /** The destination register */
        dst: RegE,
        /** The source register */
        src: RegE,
    },

    /// Add `src` value to `dst_src` value using finite-field (modulo) arithmetics of the `FQ`
    /// order, putting the result to `dst_src`.
    ///
    /// Does not affect values in the `CO` register.
    ///
    /// If either `src` or `dst_src` (or both) is set to `None`, sets `CK` to [`Status::Fail`];
    /// otherwise leaves value in the `CK` unchanged.
    #[display("add     {dst_src}, {src}")]
    Add {
        /** The first source and the destination register */
        dst_src: RegE,
        /** The second source register */
        src: RegE,
    },

    /// Multiply `src` value to `dst_src` value using finite-field (modulo) arithmetics of the
    /// `FQ` order, putting the result to `dst_src`.
    ///
    /// Does not affect values in the `CO` register.
    ///
    /// If either `src` or `dst_src` (or both) is set to `None`, sets `CK` to [`Status::Fail`];
    /// otherwise leaves value in the `CK` unchanged.
    #[display("mul     {dst_src}, {src}")]
    Mul {
        /** The first source and the destination register */
        dst_src: RegE,
        /** The second source register */
        src: RegE,
    },
}

/// A predefined constant field element for a register initialization.
///
/// These constants are used to keep the space and complexity metric of the code low, since reading
/// a field element from the data segment will take 16 bytes in the code segment; while initializing
/// with a common constant will take just 2 bits.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[repr(u8)]
pub enum ConstVal {
    /// Zero field element.
    #[display("1")]
    Val1 = 0,

    /// Field element equal to the [`u64::MAX`].
    #[display("ffff_ffff_ffff_ffff#h")]
    ValU64Max = 1,

    /// Field element equal to the [`u128::MAX`].
    #[display("ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff#h")]
    ValU128Max = 2,

    /// Field element equal to the finite field order minus one. The finite field order value is
    /// taken from the constant `FQ` register.
    #[display("-1#fe")]
    ValFeMAX = 3,
}

impl From<u2> for ConstVal {
    fn from(val: u2) -> Self {
        match val {
            x if x == ConstVal::Val1.to_u2() => ConstVal::Val1,
            x if x == ConstVal::ValU64Max.to_u2() => ConstVal::ValU64Max,
            x if x == ConstVal::ValU128Max.to_u2() => ConstVal::ValU128Max,
            x if x == ConstVal::ValFeMAX.to_u2() => ConstVal::ValFeMAX,
            _ => unreachable!(),
        }
    }
}

impl ConstVal {
    /// Get a 2-bit representation of the constant value.
    #[inline]
    pub const fn to_u2(self) -> u2 { u2::with(self as u8) }

    /// Get a finite field element corresponding to the constant.
    ///
    /// Returns `None` for the [`ConstVal::ValFeMAX`].
    pub fn to_fe256(self) -> Option<fe256> {
        let val = match self {
            ConstVal::Val1 => 1u128,
            ConstVal::ValU64Max => u64::MAX as u128,
            ConstVal::ValU128Max => u128::MAX,
            ConstVal::ValFeMAX => return None,
        };
        Some(fe256::from(val))
    }
}

/// Maximum bit dimension which a register value should fit (used in [`FieldInstr::Fits`]
/// instruction).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[repr(u8)]
pub enum Bits {
    /// 8 bits (a byte).
    #[display("8.bits")]
    Bits8,

    /// 16 bits (two bytes).
    #[display("16.bits")]
    Bits16,

    /// 24 bits (three bytes).
    #[display("24.bits")]
    Bits24,

    /// 32 bits (four bytes).
    #[display("32.bits")]
    Bits32,

    /// 48 bits (six bytes).
    #[display("48.bits")]
    Bits48,

    /// 64 bits (8 bytes).
    #[display("64.bits")]
    Bits64,

    /// 96 bits (12 bytes).
    #[display("96.bits")]
    Bits96,

    /// 128 bits (16 bytes).
    #[display("128.bits")]
    Bits128,
}

impl From<u3> for Bits {
    fn from(val: u3) -> Self {
        match val {
            x if x == Bits::Bits8.to_u3() => Bits::Bits8,
            x if x == Bits::Bits16.to_u3() => Bits::Bits16,
            x if x == Bits::Bits24.to_u3() => Bits::Bits24,
            x if x == Bits::Bits32.to_u3() => Bits::Bits32,
            x if x == Bits::Bits48.to_u3() => Bits::Bits48,
            x if x == Bits::Bits64.to_u3() => Bits::Bits64,
            x if x == Bits::Bits96.to_u3() => Bits::Bits96,
            x if x == Bits::Bits128.to_u3() => Bits::Bits96,
            _ => unreachable!(),
        }
    }
}

impl Bits {
    /// Get a 3-bit representation of the bit dimension variant.
    #[inline]
    pub const fn to_u3(self) -> u3 { u3::with(self as u8) }

    /// Construct a dimension variant a bit out of bit length.
    ///
    /// # Panics
    ///
    /// If there is no enum variant matching the provided bit length.
    pub fn from_bit_len(len: usize) -> Self {
        match len {
            8 => Bits::Bits8,
            16 => Bits::Bits16,
            24 => Bits::Bits24,
            32 => Bits::Bits32,
            48 => Bits::Bits48,
            64 => Bits::Bits64,
            96 => Bits::Bits96,
            128 => Bits::Bits128,
            invalid => panic!("unsupported bit length {invalid}"),
        }
    }

    /// Returns a bit length corresponding to the enum variant.
    pub const fn bit_len(self) -> usize {
        match self {
            Bits::Bits8 => 8,
            Bits::Bits16 => 16,
            Bits::Bits24 => 24,
            Bits::Bits32 => 32,
            Bits::Bits48 => 48,
            Bits::Bits64 => 64,
            Bits::Bits96 => 96,
            Bits::Bits128 => 128,
        }
    }
}
