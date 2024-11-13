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

#[doc(hidden)]
#[macro_export]
macro_rules! instr {
    // Modulo-increment
    (incmod $A:ident : $idx:literal, $val:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::IncMod { src_dst: a!($A : $idx), val: $val })
    };
    (incmod $A:ident : $idx:ident, $val:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::IncMod { src_dst: a!($A : $idx), val: $val })
    };
    (incmod $A:ident . $idx:ident, $val:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::IncMod { src_dst: a!($A . $idx), val: $val })
    };
    // Modulo-decrement
    (decmod $A:ident : $idx:literal, $val:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::DecMod { src_dst: a!($A : $idx), val: $val })
    };
    (decmod $A:ident : $idx:ident, $val:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::DecMod { src_dst: a!($A : $idx), val: $val })
    };
    (decmod $A:ident . $idx:ident, $val:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::DecMod { src_dst: a!($A . $idx), val: $val })
    };
    // Modulo-negate
    (negmod $A:ident : $idx:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::NegMod { src_dst: a!($A : $idx) })
    };
    (negmod $A:ident : $idx:ident) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::NegMod { src_dst: a!($A : $idx) })
    };
    (negmod $A:ident . $idx:ident) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::NegMod { src_dst: a!($A . $idx) })
    };
    // Modulo-add
    (addmod A128 : $dst:literal, A128 : $src1:literal, A128 : $src2:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::AddMod { reg: A::A128, dst: _a_idx!(:$dst), src1: _a_idx!(:$src1), src2: _a_idx!(:$src2) })
    };
    (addmod A128 : $dst:ident, A128 : $src1:ident, A128 : $src2:ident) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::AddMod { reg: A::A128, dst: _a_idx!(:$dst), src1: _a_idx!(:$src1), src2: _a_idx!(:$src2) })
    };
    (addmod A128 . $dst:ident, A128 . $src1:ident, A128 . $src2:ident) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::AddMod { reg: A::A128, dst: _a_idx!(.$dst), src1: _a_idx!(.$src1), src2: _a_idx!(.$src2) })
    };
    // Modulo-multiply
    (mulmod A128 : $dst:literal, A128 : $src1:literal, A128 : $src2:literal) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::MulMod { reg: A::A128, dst: _a_idx!(:$dst), src1: _a_idx!(:$src1), src2: _a_idx!(:$src2) })
    };
    (mulmod A128 : $dst:ident, A128 : $src1:ident, A128 : $src2:ident) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::MulMod { reg: A::A128, dst: _a_idx!(:$dst), src1: _a_idx!(:$src1), src2: _a_idx!(:$src2) })
    };
    (mulmod A128 . $dst:ident, A128 . $src1:ident, A128 . $src2:ident) => {
        #[cfg(feature = "GFA")]
        Instr::GFqA(FieldInstr::MulMod { reg: A::A128, dst: _a_idx!(.$dst), src1: _a_idx!(.$src1), src2: _a_idx!(.$src2) })
    };

    { $($tt:tt)+ } => {
        Instr::Reserved(isa_instr! { $( $tt )+ })
    };
}

#[macro_export]
macro_rules! a {
    ($A:ident : $idx:literal) => {
$crate::regs::RegA::$A(_a_idx!(: $idx))
    };
    ($A:ident : $idx:ident) => {
$crate::regs::RegA::$A(_a_idx!(: $idx))
    };
    ($A:ident. $idx:ident) => {
$crate::regs::RegA::$A(_a_idx!(. $idx))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! _a_idx {
    (: $idx:literal) => {
        $crate::regs::IdxA::from($crate::paste! { $crate::regs::Idx32 :: [< L $idx >] })
    };
    (: $idx:ident) => {
        $crate::regs::IdxA::from($crate::regs::Idx32::$idx)
    };
    (. $idx:ident) => {
        $crate::regs::IdxA::from($crate::paste! { $crate::regs::Idx32 :: [< S $idx >] })
    };
}
