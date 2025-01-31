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

use alloc::collections::BTreeSet;

use aluvm::isa::{ExecStep, Instruction};
use aluvm::regs::Status;
use aluvm::{Core, CoreExt, Site, SiteId};

use super::{FieldInstr, Instr, ISA_GFA128};
use crate::{GfaCore, RegE};

impl<Id: SiteId> Instruction<Id> for FieldInstr {
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA128];
    type Core = GfaCore;
    type Context<'ctx> = ();

    fn src_regs(&self) -> BTreeSet<RegE> {
        match *self {
            FieldInstr::Fits { src, bits: _ }
            | FieldInstr::NegMod { dst: _, src } => bset![src],
            FieldInstr::AddMod { dst_src, src }
            | FieldInstr::MulMod { dst_src, src } => bset![src, dst_src],
        }
    }

    fn dst_regs(&self) -> BTreeSet<RegE> {
        match *self {
            FieldInstr::Fits { src: _, bits: _ } => none!(),
            FieldInstr::NegMod { dst, src: _ }
            | FieldInstr::AddMod { dst_src: dst, src: _ }
            | FieldInstr::MulMod { dst_src: dst, src: _ } => bset![dst],
        }
    }

    fn op_data_bytes(&self) -> u16 {
        match self {
            FieldInstr::Fits { src: _, bits: _ } => 1,
            FieldInstr::NegMod { dst: _, src: _ }
            | FieldInstr::AddMod { dst_src: _, src: _ }
            | FieldInstr::MulMod { dst_src: _, src: _ } => 0,
        }
    }

    fn ext_data_bytes(&self) -> u16 { 0 }

    fn complexity(&self) -> u64 {
        // Double the default complexity since each instruction performs two operations (and each arithmetic
        // operations is x10 of move operation).
        Instruction::<Id>::base_complexity(self) * 20
    }

    fn exec(&self, _: Site<Id>, core: &mut Core<Id, GfaCore>, _: &Self::Context<'_>) -> ExecStep<Site<Id>> {
        let res = match *self {
            FieldInstr::Fits { src, bits } => match core.cx.fits(src, bits) {
                None => Status::Fail,
                Some(fits) => {
                    core.set_co(!fits);
                    Status::Ok
                }
            },
            FieldInstr::NegMod { dst, src } => core.cx.neg_mod(dst, src),
            FieldInstr::AddMod { dst_src, src } => core.cx.add_mod(dst_src, src),
            FieldInstr::MulMod { dst_src, src } => core.cx.mul_mod(dst_src, src),
        };
        if res == Status::Ok {
            ExecStep::Next
        } else {
            ExecStep::FailContinue
        }
    }
}

impl<Id: SiteId> Instruction<Id> for Instr<Id> {
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA128];
    type Core = GfaCore;
    type Context<'ctx> = ();

    fn src_regs(&self) -> BTreeSet<<Self::Core as CoreExt>::Reg> {
        match self {
            Instr::Ctrl(_) => none!(),
            Instr::Gfa(instr) => Instruction::<Id>::src_regs(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn dst_regs(&self) -> BTreeSet<<Self::Core as CoreExt>::Reg> {
        match self {
            Instr::Ctrl(_) => none!(),
            Instr::Gfa(instr) => Instruction::<Id>::dst_regs(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn op_data_bytes(&self) -> u16 {
        match self {
            Instr::Ctrl(instr) => instr.op_data_bytes(),
            Instr::Gfa(instr) => Instruction::<Id>::op_data_bytes(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn ext_data_bytes(&self) -> u16 {
        match self {
            Instr::Ctrl(instr) => instr.ext_data_bytes(),
            Instr::Gfa(instr) => Instruction::<Id>::ext_data_bytes(instr),
            Instr::Reserved(_) => none!(),
        }
    }

    fn exec(&self, site: Site<Id>, core: &mut Core<Id, Self::Core>, context: &Self::Context<'_>) -> ExecStep<Site<Id>> {
        match self {
            Instr::Ctrl(instr) => {
                let mut subcore = Core::from(core.clone());
                let step = instr.exec(site, &mut subcore, context);
                *core = subcore.extend(core.cx.clone());
                step
            }
            Instr::Gfa(instr) => {
                let mut subcore = Core::from(core.clone());
                let step = instr.exec(site, &mut subcore, context);
                *core = subcore.extend(core.cx.clone());
                step
            }
            Instr::Reserved(instr) => {
                let mut subcore = Core::from(core.clone());
                let step = instr.exec(site, &mut subcore, context);
                *core = subcore.extend(core.cx.clone());
                step
            }
        }
    }
}
