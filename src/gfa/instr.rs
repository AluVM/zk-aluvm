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
use amplify::num::u4;

use crate::RegE;

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
    /// Test whether a value in a register fits in the provided number of bits.
    #[display("fits     {src}, {bits}")]
    Fits { src: RegE, bits: Bits },

    /// Negate value using finite-field arithmetics.
    #[display("neg.gf   {dst}, {src}")]
    NegMod { dst: RegE, src: RegE },

    /// Add `src` value to `dst_src` value using finite-field (modulo) arithmetics of the `order`.
    #[display("add.gf   {dst_src}, {src}")]
    AddMod { dst_src: RegE, src: RegE },

    /// Multiply `src` value to `dst_src` value using finite-field (modulo) arithmetics of the
    /// `order`.
    #[display("mul.gf   {dst_src}, {src}")]
    MulMod { dst_src: RegE, src: RegE },
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Display)]
#[repr(u8)]
pub enum Bits {
    #[display("1")]
    Bit,
    #[display("8")]
    Bits8,
    #[display("16")]
    Bits16,
    #[display("24")]
    Bits24,
    #[display("32")]
    Bits32,
    #[display("40")]
    Bits40,
    #[display("48")]
    Bits48,
    #[display("56")]
    Bits56,
    #[display("64")]
    Bits64,
    #[display("72")]
    Bits72,
    #[display("80")]
    Bits80,
    #[display("88")]
    Bits88,
    #[display("96")]
    Bits96,
    #[display("104")]
    Bits104,
    #[display("112")]
    Bits112,
    #[display("120")]
    Bits120,
}

impl From<u4> for Bits {
    fn from(val: u4) -> Self {
        match val {
            x if x == Bits::Bit.to_u4() => Bits::Bit,
            x if x == Bits::Bits8.to_u4() => Bits::Bits8,
            x if x == Bits::Bits16.to_u4() => Bits::Bits16,
            x if x == Bits::Bits24.to_u4() => Bits::Bits24,
            x if x == Bits::Bits32.to_u4() => Bits::Bits32,
            x if x == Bits::Bits40.to_u4() => Bits::Bits40,
            x if x == Bits::Bits48.to_u4() => Bits::Bits48,
            x if x == Bits::Bits56.to_u4() => Bits::Bits56,
            x if x == Bits::Bits64.to_u4() => Bits::Bits64,
            x if x == Bits::Bits72.to_u4() => Bits::Bits72,
            x if x == Bits::Bits80.to_u4() => Bits::Bits80,
            x if x == Bits::Bits88.to_u4() => Bits::Bits88,
            x if x == Bits::Bits96.to_u4() => Bits::Bits96,
            x if x == Bits::Bits104.to_u4() => Bits::Bits104,
            x if x == Bits::Bits112.to_u4() => Bits::Bits112,
            x if x == Bits::Bits120.to_u4() => Bits::Bits120,
            _ => unreachable!(),
        }
    }
}

impl Bits {
    #[inline]
    pub const fn to_u4(self) -> u4 { u4::with(self as u8) }
}
