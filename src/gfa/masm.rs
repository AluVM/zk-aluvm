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

/// Macro compiler for AluVM assembler.
///
/// # Example
///
/// ```
/// use aluvm::regs::Status;
/// use aluvm::{Lib, LibId, LibSite, Vm};
/// use zkaluvm::gfa::Instr;
/// use zkaluvm::zk_aluasm;
///
/// let code = zk_aluasm! {
///     nop                 ;
///     chk                 ;
///     test    E1          ;
///     clr     EA          ;
///     mov     E2, 0       ;
///     fits    EA, 8:bits  ;
///     mov     EB, 20      ;
///     mov     E1, E2      ;
///     eq      E1, E2      ;
///     neg     EA, EH      ;
///     add     EA, EH      ;
///     mul     EA, EH      ;
/// };
///
/// let lib = Lib::assemble::<Instr<LibId>>(&code).unwrap();
/// let mut vm = Vm::<Instr<LibId>>::new();
/// match vm.exec(LibSite::new(lib.lib_id(), 0), &(), |_| Some(&lib)) {
///     Status::Ok => println!("success"),
///     Status::Fail => println!("failure"),
/// }
/// ```
#[macro_export]
macro_rules! zk_aluasm {
    ($( $tt:tt )+) => {{
        use $crate::instr;
        #[cfg(not(feature = "std"))]
        use alloc::vec::Vec;

        let mut code: Vec<$crate::gfa::Instr<$crate::alu::LibId>> = Default::default();
        #[allow(unreachable_code)] {
            $crate::alu::aluasm_inner! { code => $( $tt )+ }
        }
        code
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! instr {
    // Test register
    (test $src:ident) => {
        $crate::gfa::FieldInstr::Test {
            src: $crate::RegE::$src
        }.into()
    };

    // Clear register
    (clr $dst:ident) => {
        $crate::gfa::FieldInstr::Clr {
            dst: $crate::RegE::$dst
        }.into()
    };

    // Checks whether a value in a register fits the provided number of bits
    (fits $src:ident, $bits:literal :bits) => {
        $crate::gfa::FieldInstr::Fits {
            src: $crate::RegE::$src,
            bits: $crate::gfa::Bits::from_bit_len($bits)
        }.into()
    };

    // Moving value between regs
    (mov $dst:ident, $src:ident) => {
        $crate::gfa::FieldInstr::Mov {
            dst: $crate::RegE::$dst,
            src: $crate::RegE::$src
        }.into()
    };

    // Put zero value to a register
    (mov $dst:ident, 0) => {
        $crate::gfa::FieldInstr::PutZ {
            dst: $crate::RegE::$dst
        }.into()
    };

    // Put a specific value to a register
    (mov $dst:ident, $val:literal) => {
        $crate::gfa::FieldInstr::PutD {
            dst: $crate::RegE::$dst,
            data: $crate::fe256::from($val as u128)
        }.into()
    };

    (mov $dst:ident, :$ident:ident) => {
        $crate::gfa::FieldInstr::PutD {
            dst: $crate::RegE::$dst,
            data: $crate::fe256::from($ident)
        }.into()
    };

    // Equivalence
    (eq $dst:ident, $src:ident) => {
        $crate::gfa::FieldInstr::Eq {
            src1: $crate::RegE::$dst,
            src2: $crate::RegE::$src
        }.into()
    };
    // Modulo-negate
    (neg $dst:ident, $src:ident) => {
        $crate::gfa::FieldInstr::Neg {
            dst: $crate::RegE::$dst,
            src: $crate::RegE::$src
        }.into()
    };
    // Modulo-add
    (add $dst_src:ident, $src:ident) => {
        $crate::gfa::FieldInstr::Add {
            dst_src: $crate::RegE::$dst_src,
            src: $crate::RegE::$src
        }.into()
    };
    // Modulo-multiply
    (mul $dst_src:ident, $src:ident) => {
        $crate::gfa::FieldInstr::Mul {
            dst_src: $crate::RegE::$dst_src,
            src: $crate::RegE::$src
        }.into()
    };

    { $($tt:tt)+ } => {
        $crate::gfa::Instr::Ctrl($crate::alu::instr! { $( $tt )+ }).into()
    };
}
