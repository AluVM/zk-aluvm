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
use aluvm::{Core, CoreExt, Site, SiteId, Supercore};

use super::{FieldInstr, Instr, ISA_GFA128};
use crate::{fe256, GfaCore, RegE};

impl<Id: SiteId> Instruction<Id> for FieldInstr {
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA128];
    type Core = GfaCore;
    type Context<'ctx> = ();

    fn is_local_goto_target(&self) -> bool { false }

    fn local_goto_pos(&mut self) -> Option<&mut u16> { None }

    fn src_regs(&self) -> BTreeSet<RegE> {
        match *self {
            FieldInstr::Clr { dst: _ }
            | FieldInstr::PutD { dst: _, data: _ }
            | FieldInstr::PutZ { dst: _ }
            | FieldInstr::PutV { dst: _, val: _ } => none!(),

            FieldInstr::Eq { src1, src2 } => bset![src1, src2],

            FieldInstr::Test { src }
            | FieldInstr::Fits { src, bits: _ }
            | FieldInstr::Mov { dst: _, src }
            | FieldInstr::Neg { dst: _, src } => bset![src],

            FieldInstr::Add { dst_src, src } | FieldInstr::Mul { dst_src, src } => bset![src, dst_src],
        }
    }

    fn dst_regs(&self) -> BTreeSet<RegE> {
        match *self {
            FieldInstr::Clr { dst }
            | FieldInstr::PutD { dst, data: _ }
            | FieldInstr::PutZ { dst }
            | FieldInstr::PutV { dst, val: _ }
            | FieldInstr::Mov { dst, src: _ } => bset![dst],

            FieldInstr::Eq { src1: _, src2: _ }
            | FieldInstr::Test { src: _ }
            | FieldInstr::Fits { src: _, bits: _ } => none!(),

            FieldInstr::Neg { dst, src: _ }
            | FieldInstr::Add { dst_src: dst, src: _ }
            | FieldInstr::Mul { dst_src: dst, src: _ } => bset![dst],
        }
    }

    fn op_data_bytes(&self) -> u16 {
        match self {
            FieldInstr::PutV { dst: _, val: _ } | FieldInstr::Fits { src: _, bits: _ } => 1,

            FieldInstr::Test { src: _ }
            | FieldInstr::Clr { dst: _ }
            | FieldInstr::PutD { dst: _, data: _ }
            | FieldInstr::PutZ { dst: _ }
            | FieldInstr::Mov { dst: _, src: _ }
            | FieldInstr::Eq { src1: _, src2: _ }
            | FieldInstr::Neg { dst: _, src: _ }
            | FieldInstr::Add { dst_src: _, src: _ }
            | FieldInstr::Mul { dst_src: _, src: _ } => 0,
        }
    }

    fn ext_data_bytes(&self) -> u16 {
        match self {
            FieldInstr::PutD { dst: _, data: _ } => 32,

            FieldInstr::Test { src: _ }
            | FieldInstr::Clr { dst: _ }
            | FieldInstr::PutZ { dst: _ }
            | FieldInstr::PutV { dst: _, val: _ }
            | FieldInstr::Fits { src: _, bits: _ }
            | FieldInstr::Mov { dst: _, src: _ }
            | FieldInstr::Eq { src1: _, src2: _ }
            | FieldInstr::Neg { dst: _, src: _ }
            | FieldInstr::Add { dst_src: _, src: _ }
            | FieldInstr::Mul { dst_src: _, src: _ } => 0,
        }
    }

    fn complexity(&self) -> u64 {
        let base = Instruction::<Id>::base_complexity(self);
        match self {
            FieldInstr::Test { src: _ }
            | FieldInstr::Clr { dst: _ }
            | FieldInstr::PutZ { dst: _ }
            | FieldInstr::PutV { dst: _, val: _ }
            | FieldInstr::PutD { dst: _, data: _ }
            | FieldInstr::Mov { dst: _, src: _ }
            | FieldInstr::Eq { src1: _, src2: _ } => base,

            FieldInstr::Fits { src: _, bits: _ }
            | FieldInstr::Neg { dst: _, src: _ }
            | FieldInstr::Add { dst_src: _, src: _ }
            | FieldInstr::Mul { dst_src: _, src: _ } => {
                // Double the default complexity since each instruction performs two operations (and each
                // arithmetic operations is x10 of move operation).
                base * 20
            }
        }
    }

    fn exec(&self, _: Site<Id>, core: &mut Core<Id, GfaCore>, _: &Self::Context<'_>) -> ExecStep<Site<Id>> {
        let res = match *self {
            FieldInstr::Test { src } => {
                let res = core.cx.test(src);
                core.set_co(res);
                Status::Ok
            }
            FieldInstr::Clr { dst } => {
                core.cx.clr(dst);
                Status::Ok
            }
            FieldInstr::PutD { dst, data } => {
                core.cx.set(dst, data);
                Status::Ok
            }
            FieldInstr::PutZ { dst } => {
                core.cx.set(dst, fe256::ZERO);
                Status::Ok
            }
            FieldInstr::PutV { dst, val } => {
                let val = val.to_fe256().unwrap_or_else(|| core.cx.fq().into());
                core.cx.set(dst, val);
                Status::Ok
            }
            FieldInstr::Mov { dst, src } => {
                core.cx.mov(dst, src);
                Status::Ok
            }
            FieldInstr::Eq { src1, src2 } => {
                let res = core.cx.eqv(src1, src2);
                core.set_co(res);
                Status::Ok
            }

            FieldInstr::Fits { src, bits } => match core.cx.fits(src, bits) {
                None => Status::Fail,
                Some(true) => {
                    core.set_co(Status::Ok);
                    Status::Ok
                }
                Some(false) => {
                    core.set_co(Status::Fail);
                    Status::Ok
                }
            },
            FieldInstr::Neg { dst, src } => core.cx.neg_mod(dst, src),
            FieldInstr::Add { dst_src, src } => core.cx.add_mod(dst_src, src),
            FieldInstr::Mul { dst_src, src } => core.cx.mul_mod(dst_src, src),
        };
        if res == Status::Ok {
            ExecStep::Next
        } else {
            ExecStep::Fail
        }
    }
}

impl<Id: SiteId> Instruction<Id> for Instr<Id> {
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA128];
    type Core = GfaCore;
    type Context<'ctx> = ();

    fn is_local_goto_target(&self) -> bool {
        match self {
            Instr::Ctrl(ctrl) => ctrl.is_local_goto_target(),
            Instr::Gfa(instr) => Instruction::<Id>::is_local_goto_target(instr),
            Instr::Reserved(reserved) => Instruction::<Id>::is_local_goto_target(reserved),
        }
    }

    fn local_goto_pos(&mut self) -> Option<&mut u16> {
        match self {
            Instr::Ctrl(ctrl) => ctrl.local_goto_pos(),
            Instr::Gfa(instr) => Instruction::<Id>::local_goto_pos(instr),
            Instr::Reserved(reserved) => Instruction::<Id>::local_goto_pos(reserved),
        }
    }

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
                let mut subcore = core.subcore();
                let step = instr.exec(site, &mut subcore, context);
                core.merge_subcore(subcore);
                step
            }
            Instr::Gfa(instr) => {
                let step = instr.exec(site, core, context);
                step
            }
            Instr::Reserved(instr) => {
                let mut subcore = core.subcore();
                let step = instr.exec(site, &mut subcore, context);
                core.merge_subcore(subcore);
                step
            }
        }
    }
}

#[cfg(test)]
mod test {
    use aluvm::{CoreConfig, Lib, LibId, LibSite, Vm};
    use amplify::num::u256;

    use super::*;
    use crate::zk_aluasm;

    const CONFIG: CoreConfig = CoreConfig {
        halt: true,
        complexity_lim: None,
    };

    #[test]
    fn putd() {
        const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
        let code = zk_aluasm! {
            mov EA, :VAL;
        };
        let lib = Lib::assemble(&code).unwrap();
        let lib_id = lib.lib_id();

        let mut vm = Vm::<Instr<LibId>>::with(CONFIG, default!());
        let resolver = |id: LibId| {
            assert_eq!(id, lib_id);
            Some(&lib)
        };
        let res = vm.exec(LibSite::new(lib_id, 0), &(), resolver).is_ok();
        assert!(res);

        assert_eq!(vm.core.cx.get(RegE::EA), Some(fe256::from(VAL)));
    }
}
