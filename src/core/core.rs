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

use core::fmt::{self, Debug, Formatter};

use aluvm::{CoreExt, Register};
use amplify::num::u4;

use crate::fe128;

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct GfaCore {
    pub(super) fq: u128,
    pub(super) e: [Option<fe128>; 16],
}

impl CoreExt for GfaCore {
    type Reg = RegE;
    type Config = u128; // Field order

    #[inline]
    fn with(config: Self::Config) -> Self {
        GfaCore {
            fq: config,
            e: [None; 16],
        }
    }

    #[inline]
    fn get(&self, reg: Self::Reg) -> Option<fe128> { self.e[reg as usize] }

    #[inline]
    fn clr(&mut self, reg: Self::Reg) -> Option<fe128> {
        let prev = self.e[reg as usize];
        self.e[reg as usize] = None;
        prev
    }

    #[inline]
    fn set(&mut self, reg: Self::Reg, val: fe128) -> Option<fe128> {
        assert!(val.0 < self.fq);
        let prev = self.e[reg as usize];
        self.e[reg as usize] = Some(val);
        prev
    }

    #[inline]
    fn reset(&mut self) { self.e = [None; 16]; }
}

impl Debug for GfaCore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (sect, reg, val, reset) =
            if f.alternate() { ("\x1B[0;4;1m", "\x1B[0;1m", "\x1B[0;32m", "\x1B[0m") } else { ("", "", "", "") };

        writeln!(f)?;
        writeln!(f, "{reg}FQ{reset} {val}{:X}{reset}#h", self.fq)?;
        writeln!(f, "{sect}E-regs:{reset}")?;
        for (no, item) in self.e.iter().enumerate() {
            write!(f, "{reg}{}{reset} ", RegE::from(u4::with(no as u8)))?;
            if let Some(e) = item {
                writeln!(f, "{val}{e}{reset}#h")?;
            } else {
                writeln!(f, "~")?;
            }
        }
        writeln!(f)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
#[display(uppercase)]
#[repr(u8)]
pub enum RegE {
    E1 = 0,
    E2,
    E3,
    E4,
    E5,
    E6,
    E7,
    E8,
    EA,
    EB,
    EC,
    ED,
    EE,
    EF,
    EG,
    EH,
}

impl Register for RegE {
    type Value = fe128;

    #[inline]
    fn bytes(self) -> u16 { 16 }
}

impl From<u4> for RegE {
    fn from(val: u4) -> Self {
        match val {
            x if x == RegE::E1.to_u4() => RegE::E1,
            x if x == RegE::E2.to_u4() => RegE::E2,
            x if x == RegE::E3.to_u4() => RegE::E3,
            x if x == RegE::E4.to_u4() => RegE::E4,
            x if x == RegE::E5.to_u4() => RegE::E5,
            x if x == RegE::E6.to_u4() => RegE::E6,
            x if x == RegE::E7.to_u4() => RegE::E7,
            x if x == RegE::E8.to_u4() => RegE::E8,
            x if x == RegE::EA.to_u4() => RegE::EA,
            x if x == RegE::EB.to_u4() => RegE::EB,
            x if x == RegE::EC.to_u4() => RegE::EC,
            x if x == RegE::ED.to_u4() => RegE::ED,
            x if x == RegE::EE.to_u4() => RegE::EE,
            x if x == RegE::EF.to_u4() => RegE::EF,
            x if x == RegE::EG.to_u4() => RegE::EG,
            x if x == RegE::EH.to_u4() => RegE::EH,
            _ => unreachable!(),
        }
    }
}

impl RegE {
    #[inline]
    pub const fn to_u4(self) -> u4 { u4::with(self as u8) }
}
