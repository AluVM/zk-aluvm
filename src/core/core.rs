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

use aluvm::{CoreExt, NoExt, Register, Supercore};
use amplify::num::{u256, u4};

use crate::fe256;

pub const FIELD_ORDER_25519: u256 =
    u256::from_inner([0xFFFF_FFFF_FFFF_FFEC, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x8FFF_FFFF_FFFF_FFFF]);
pub const FIELD_ORDER_STARK: u256 = u256::from_inner([1, 0, 17, 0x0800_0000_0000_0000]);
pub const FIELD_ORDER_SECP: u256 =
    u256::from_inner([0xFFFF_FFFE_FFFF_FC2E, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF]);

impl Default for GfaConfig {
    fn default() -> Self {
        Self {
            field_order: FIELD_ORDER_25519,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct GfaCore {
    /// Used field order.
    pub(super) fq: u256,
    pub(super) e: [Option<fe256>; 16],
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct GfaConfig {
    pub field_order: u256,
}

impl CoreExt for GfaCore {
    type Reg = RegE;
    type Config = GfaConfig; // Field order

    #[inline]
    fn with(config: Self::Config) -> Self {
        GfaCore {
            fq: config.field_order,
            e: [None; 16],
        }
    }

    #[inline]
    fn get(&self, reg: Self::Reg) -> Option<fe256> { self.e[reg as usize] }

    #[inline]
    fn clr(&mut self, reg: Self::Reg) { self.e[reg as usize] = None; }

    #[inline]
    fn put(&mut self, reg: Self::Reg, val: Option<fe256>) {
        let Some(val) = val else {
            self.e[reg as usize] = None;
            return;
        };
        assert!(val.to_u256() < self.fq, "value {val} exceeds field order {}", self.fq);
        self.e[reg as usize] = Some(val);
    }

    #[inline]
    fn reset(&mut self) { self.e = [None; 16]; }
}

impl Supercore<NoExt> for GfaCore {
    fn subcore(&self) -> NoExt { NoExt }

    fn merge_subcore(&mut self, _subcore: NoExt) {}
}

#[cfg_attr(coverage_nightly, coverage(off))]
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
    E1 = 0b_0000,
    E2 = 0b_0001,
    E3 = 0b_0010,
    E4 = 0b_0011,
    E5 = 0b_0100,
    E6 = 0b_0101,
    E7 = 0b_0110,
    E8 = 0b_0111,
    EA = 0b_1000,
    EB = 0b_1001,
    EC = 0b_1010,
    ED = 0b_1011,
    EE = 0b_1100,
    EF = 0b_1101,
    EG = 0b_1110,
    EH = 0b_1111,
}

impl Register for RegE {
    type Value = fe256;

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
    pub const ALL: [Self; 16] = [
        RegE::E1,
        RegE::E2,
        RegE::E3,
        RegE::E4,
        RegE::E5,
        RegE::E6,
        RegE::E7,
        RegE::E8,
        RegE::EA,
        RegE::EB,
        RegE::EC,
        RegE::ED,
        RegE::EE,
        RegE::EF,
        RegE::EG,
        RegE::EH,
    ];

    #[inline]
    pub const fn to_u4(self) -> u4 { u4::with(self as u8) }
}
