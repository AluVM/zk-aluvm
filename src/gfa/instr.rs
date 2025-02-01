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
use amplify::num::u3;

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
    #[display("put      {dst}, {data}")]
    PutD { dst: RegE, data: fe256 },

    /// Puts zero (`0`) value into a register, replacing previous value in it, if there was any.
    ///
    /// Doesn't affect values in `co` and `ck` registers.
    PutZ { dst: RegE },

    /// Puts `val` value, which is a power of 2, into a register, replacing previous value in it, if
    /// there was any.
    ///
    /// Doesn't affect values in `co` and `ck` registers.
    #[display("put      {dst}, {val}")]
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
    #[display("neg.gf   {dst}, {src}")]
    NegMod { dst: RegE, src: RegE },

    /// Add `src` value to `dst_src` value using finite-field (modulo) arithmetics of the `order`,
    /// putting result to `dst_src`.
    ///
    /// Doesn't affect values in `co` register.
    ///
    /// If either `src` or `dst_src` (or both) is set to `None`, sets `ck` to `false`; otherwise
    /// leaves value in  `ck` unchanged.
    #[display("add.gf   {dst_src}, {src}")]
    AddMod { dst_src: RegE, src: RegE },

    /// Multiply `src` value to `dst_src` value using finite-field (modulo) arithmetics of the
    /// `order`, putting result to `dst_src`.
    ///
    /// Doesn't affect values in `co` register.
    ///
    /// If either `src` or `dst_src` (or both) is set to `None`, sets `ck` to `false`; otherwise
    /// leaves value in  `ck` unchanged.
    #[display("mul.gf   {dst_src}, {src}")]
    MulMod { dst_src: RegE, src: RegE },
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[repr(u8)]
pub enum ConstVal {
    #[display("1")]
    Val1 = 0,

    #[display("2")]
    Val2 = 1,

    #[display("4")]
    Val4 = 2,

    #[display("8")]
    Val8 = 3,

    #[display("16")]
    Val16 = 4,

    #[display("32")]
    Val32 = 5,

    #[display("64")]
    Val64 = 6,

    #[display("max")]
    ValMAX = 7,
}

impl From<u3> for ConstVal {
    fn from(val: u3) -> Self {
        match val {
            x if x == ConstVal::Val1.to_u3() => ConstVal::Val1,
            x if x == ConstVal::Val2.to_u3() => ConstVal::Val2,
            x if x == ConstVal::Val4.to_u3() => ConstVal::Val4,
            x if x == ConstVal::Val8.to_u3() => ConstVal::Val8,
            x if x == ConstVal::Val16.to_u3() => ConstVal::Val16,
            x if x == ConstVal::Val32.to_u3() => ConstVal::Val32,
            x if x == ConstVal::Val64.to_u3() => ConstVal::Val64,
            x if x == ConstVal::ValMAX.to_u3() => ConstVal::ValMAX,
            _ => unreachable!(),
        }
    }
}

impl ConstVal {
    #[inline]
    pub const fn to_u3(self) -> u3 { u3::with(self as u8) }

    pub fn to_fe256(self) -> Option<fe256> {
        let val = match self {
            ConstVal::Val1 => 1u8,
            ConstVal::Val2 => 2u8,
            ConstVal::Val4 => 4u8,
            ConstVal::Val8 => 8u8,
            ConstVal::Val16 => 16u8,
            ConstVal::Val32 => 32u8,
            ConstVal::Val64 => 64u8,
            ConstVal::ValMAX => return None,
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

    pub const fn bits_len(self) -> usize {
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
