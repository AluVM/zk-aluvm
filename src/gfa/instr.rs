// AluVM extensions for zero knowledge, STARKs and SNARKs"
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

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display, From)]
#[display(inner)]
#[non_exhaustive]
pub enum Instr<Id: SiteId> {
    /// Control flow instructions.
    #[from]
    Ctrl(CtrlInstr<Id>),

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
    /// Sets `co` register to `true` if a register contains a value, and to `false` otherwise.
    ///
    /// Doesn't affect value in `ck` register.
    #[display("test     {src}")]
    Test { src: RegE },

    /// Clears register value by setting it to `None`.
    ///
    /// Doesn't affect values in `co` and `ck` registers.
    #[display("clr      {dst}")]
    Clr { dst: RegE },

    /// Puts value into a register, replacing previous value in it, if there was any.
    ///
    /// Doesn't affect values in `co` and `ck` registers.
    #[display("mov      {dst}, {data}")]
    PutD { dst: RegE, data: fe256 },

    /// Puts zero (`0`) value into a register, replacing previous value in it, if there was any.
    ///
    /// Doesn't affect values in `co` and `ck` registers.
    #[display("mov      {dst}, 0")]
    PutZ { dst: RegE },

    /// Puts `val` value, which is a power of 2, into a register, replacing previous value in it, if
    /// there was any.
    ///
    /// Doesn't affect values in `co` and `ck` registers.
    #[display("mov      {dst}, {val}")]
    PutV { dst: RegE, val: ConstVal },

    /// Test whether a value in a register fits in the provided number of bits.
    ///
    /// Sets `co` register to `true` if the value fits given number of bits, and to `false`
    /// otherwise.
    ///
    /// If `src` is set to `None`, sets both `co` and `ck` to `false`; otherwise leaves value in
    /// `ck` unchanged.
    #[display("fits     {src}, {bits}")]
    Fits { src: RegE, bits: Bits },

    /// Moves (copies) value from `src` to `dst` register, overwriting previous value in `dst`. If
    /// `src` has no value (i.e. set to `None`), sets `dst` to `None`. State of `src` register
    /// remains unaffected.
    ///
    /// Doesn't affect values in `co` and `ck` registers.
    #[display("mov      {dst}, {src}")]
    Mov { dst: RegE, src: RegE },

    /// Checks whether `src1` and `src2` registers are equal. If both `src1` and `src2` registers
    /// contain no value, considers them equal.
    ///
    /// Sets `co` register to a boolean representing equivalence of the registers.
    ///
    /// Doesn't affect value in `ck` register.
    #[display("eq       {src1}, {src2}")]
    Eq { src1: RegE, src2: RegE },

    /// Negate value in `src` using finite-field arithmetics, and put result into `dst`.
    ///
    /// Doesn't affect values in `co` register.
    ///
    /// If `src` is set to `None`, sets `ck` to `false`; otherwise leaves value in  `ck` unchanged.
    #[display("neg      {dst}, {src}")]
    Neg { dst: RegE, src: RegE },

    /// Add `src` value to `dst_src` value using finite-field (modulo) arithmetics of the `order`,
    /// putting result to `dst_src`.
    ///
    /// Doesn't affect values in `co` register.
    ///
    /// If either `src` or `dst_src` (or both) is set to `None`, sets `ck` to `false`; otherwise
    /// leaves value in  `ck` unchanged.
    #[display("add      {dst_src}, {src}")]
    Add { dst_src: RegE, src: RegE },

    /// Multiply `src` value to `dst_src` value using finite-field (modulo) arithmetics of the
    /// `order`, putting result to `dst_src`.
    ///
    /// Doesn't affect values in `co` register.
    ///
    /// If either `src` or `dst_src` (or both) is set to `None`, sets `ck` to `false`; otherwise
    /// leaves value in  `ck` unchanged.
    #[display("mul      {dst_src}, {src}")]
    Mul { dst_src: RegE, src: RegE },
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[repr(u8)]
pub enum ConstVal {
    #[display("1")]
    Val1 = 0,

    #[display("ffff_ffff_ffff_ffff#h")]
    ValU64Max = 1,

    #[display("ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff#h")]
    ValU128Max = 2,

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
    #[inline]
    pub const fn to_u2(self) -> u2 { u2::with(self as u8) }

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

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[repr(u8)]
pub enum Bits {
    #[display("8")]
    Bits8,

    #[display("16")]
    Bits16,

    #[display("24")]
    Bits24,

    #[display("32")]
    Bits32,

    #[display("48")]
    Bits48,

    #[display("64")]
    Bits64,

    #[display("96")]
    Bits96,

    #[display("128")]
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
    #[inline]
    pub const fn to_u3(self) -> u3 { u3::with(self as u8) }

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
