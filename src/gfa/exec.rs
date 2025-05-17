// AluVM ISA extension for Galouis fields
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
use amplify::num::u256;

use super::{FieldInstr, Instr, ISA_GFA256};
use crate::{fe256, GfaCore, RegE};

impl<Id: SiteId> Instruction<Id> for FieldInstr {
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA256];
    type Core = GfaCore;
    type Context<'ctx> = ();

    fn is_goto_target(&self) -> bool { false }

    fn local_goto_pos(&mut self) -> Option<&mut u16> { None }

    fn remote_goto_pos(&mut self) -> Option<&mut Site<Id>> { None }

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
                // Double the default complexity since each instruction performs two operations.
                base * 2
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
                let val = val
                    .to_fe256()
                    .unwrap_or_else(|| (core.cx.fq() - u256::ONE).into());
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
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA256];
    type Core = GfaCore;
    type Context<'ctx> = ();

    fn is_goto_target(&self) -> bool {
        match self {
            Instr::Ctrl(ctrl) => ctrl.is_goto_target(),
            Instr::Gfa(instr) => Instruction::<Id>::is_goto_target(instr),
            Instr::Reserved(reserved) => Instruction::<Id>::is_goto_target(reserved),
        }
    }

    fn local_goto_pos(&mut self) -> Option<&mut u16> {
        match self {
            Instr::Ctrl(ctrl) => ctrl.local_goto_pos(),
            Instr::Gfa(instr) => Instruction::<Id>::local_goto_pos(instr),
            Instr::Reserved(reserved) => Instruction::<Id>::local_goto_pos(reserved),
        }
    }

    fn remote_goto_pos(&mut self) -> Option<&mut Site<Id>> {
        match self {
            Instr::Ctrl(ctrl) => ctrl.remote_goto_pos(),
            Instr::Gfa(instr) => Instruction::<Id>::remote_goto_pos(instr),
            Instr::Reserved(reserved) => Instruction::<Id>::remote_goto_pos(reserved),
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

    fn complexity(&self) -> u64 {
        match self {
            Instr::Ctrl(instr) => instr.complexity(),
            Instr::Gfa(instr) => Instruction::<Id>::complexity(instr),
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
            Instr::Gfa(instr) => instr.exec(site, core, context),
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
    #![cfg_attr(coverage_nightly, coverage(off))]

    use aluvm::LibId;

    use super::*;
    use crate::gfa::{Bits, ConstVal};

    #[test]
    fn test() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Test { src: RegE::E1 });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), bset![RegE::E1]);
        assert_eq!(instr.dst_regs(), none!());
        assert_eq!(instr.src_reg_bytes(), 32);
        assert_eq!(instr.dst_reg_bytes(), 0);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 256000);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }

    #[test]
    fn clr() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Clr { dst: RegE::E1 });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), none!());
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 0);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 256000);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }

    #[test]
    fn putd() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::PutD {
            dst: RegE::E1,
            data: fe256::ZERO,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), none!());
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 0);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 32);
        assert_eq!(instr.base_complexity(), 768000);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }

    #[test]
    fn putz() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::PutZ { dst: RegE::E1 });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), none!());
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 0);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 256000);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }

    #[test]
    fn putv() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::PutV {
            dst: RegE::E1,
            val: ConstVal::ValFeMAX,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), none!());
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 0);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 1);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 264000);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }

    #[test]
    fn fits() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Fits {
            src: RegE::E1,
            bits: Bits::Bits8,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), bset![RegE::E1]);
        assert_eq!(instr.dst_regs(), none!());
        assert_eq!(instr.src_reg_bytes(), 32);
        assert_eq!(instr.dst_reg_bytes(), 0);
        assert_eq!(instr.op_data_bytes(), 1);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 264000);
        assert_eq!(instr.complexity(), instr.base_complexity() * 2);
    }

    #[test]
    fn mov() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Mov {
            dst: RegE::E1,
            src: RegE::EA,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), bset![RegE::EA]);
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 32);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 512000);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }

    #[test]
    fn eq() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Eq {
            src1: RegE::E1,
            src2: RegE::EA,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), bset![RegE::E1, RegE::EA]);
        assert_eq!(instr.dst_regs(), none!());
        assert_eq!(instr.src_reg_bytes(), 64);
        assert_eq!(instr.dst_reg_bytes(), 0);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 512000);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }

    #[test]
    fn neg() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Neg {
            dst: RegE::E1,
            src: RegE::EA,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), bset![RegE::EA]);
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 32);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 512000);
        assert_eq!(instr.complexity(), instr.base_complexity() * 2);
    }

    #[test]
    fn add() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Add {
            dst_src: RegE::E1,
            src: RegE::EA,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), bset![RegE::EA, RegE::E1]);
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 64);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 768000);
        assert_eq!(instr.complexity(), instr.base_complexity() * 2);
    }

    #[test]
    fn mul() {
        let mut instr = Instr::<LibId>::Gfa(FieldInstr::Mul {
            dst_src: RegE::E1,
            src: RegE::EA,
        });
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), instr.src_regs().union(&instr.dst_regs()).copied().collect());
        assert_eq!(instr.src_regs(), bset![RegE::EA, RegE::E1]);
        assert_eq!(instr.dst_regs(), bset![RegE::E1]);
        assert_eq!(instr.src_reg_bytes(), 64);
        assert_eq!(instr.dst_reg_bytes(), 32);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 768000);
        assert_eq!(instr.complexity(), instr.base_complexity() * 2);
    }

    #[test]
    fn reserved() {
        let mut instr = Instr::<LibId>::Reserved(default!());
        assert_eq!(instr.is_goto_target(), false);
        assert_eq!(instr.local_goto_pos(), None);
        assert_eq!(instr.remote_goto_pos(), None);
        assert_eq!(instr.regs(), none!());
        assert_eq!(instr.src_regs(), none!());
        assert_eq!(instr.dst_regs(), none!());
        assert_eq!(instr.src_reg_bytes(), 0);
        assert_eq!(instr.dst_reg_bytes(), 0);
        assert_eq!(instr.op_data_bytes(), 0);
        assert_eq!(instr.ext_data_bytes(), 0);
        assert_eq!(instr.base_complexity(), 0);
        assert_eq!(instr.complexity(), instr.base_complexity());
    }
}
