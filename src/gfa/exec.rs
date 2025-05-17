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
use amplify::num::u256;

use super::{FieldInstr, Instr, ISA_GFA128};
use crate::{fe256, GfaCore, RegE};

impl<Id: SiteId> Instruction<Id> for FieldInstr {
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA128];
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
    const ISA_EXT: &'static [&'static str] = &[ISA_GFA128];
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

    use aluvm::{CoreConfig, Lib, LibId, LibSite, Vm};
    use amplify::num::u256;

    use super::*;
    use crate::gfa::ConstVal;
    use crate::zk_aluasm;

    const CONFIG: CoreConfig = CoreConfig {
        halt: false,
        complexity_lim: None,
    };

    fn stand(code: Vec<Instr<LibId>>) -> Vm<Instr<LibId>> { stand_check(code, true) }

    fn stand_fail(code: Vec<Instr<LibId>>) -> Vm<Instr<LibId>> { stand_check(code, false) }

    fn stand_check(code: Vec<Instr<LibId>>, expect: bool) -> Vm<Instr<LibId>> {
        let lib = Lib::assemble(&code).unwrap();
        let lib_id = lib.lib_id();

        let mut vm = Vm::<Instr<LibId>>::with(CONFIG, default!());
        let resolver = |id: LibId| {
            assert_eq!(id, lib_id);
            Some(&lib)
        };
        let res = vm.exec(LibSite::new(lib_id, 0), &(), resolver).is_ok();
        assert_eq!(res, expect);

        vm
    }

    #[test]
    fn test() {
        let code = zk_aluasm! {
            mov     E2, 0;
            test    E2;
        };
        let vm = stand(code);
        assert_eq!(vm.core.co(), Status::Ok);
        assert_eq!(vm.core.ck(), Status::Ok);

        let code = zk_aluasm! {
            test    E2;
        };
        let vm = stand(code);
        assert_eq!(vm.core.co(), Status::Fail);
        assert_eq!(vm.core.ck(), Status::Ok);
    }

    #[test]
    fn clr() {
        let code = zk_aluasm! {
            mov     E3, 0;
            clr     E3;
            test    E3;
        };
        let vm = stand(code);
        assert_eq!(vm.core.co(), Status::Fail);
        assert_eq!(vm.core.ck(), Status::Ok);
    }

    #[test]
    fn putd() {
        const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);
    }

    #[test]
    fn putz() {
        let vm = stand(zk_aluasm! {
            mov     E4, 0;
        });
        assert_eq!(vm.core.cx.get(RegE::E4), Some(fe256::ZERO));

        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);
    }

    #[test]
    fn putv() {
        let vm = stand(vec![FieldInstr::PutV {
            dst: RegE::E5,
            val: ConstVal::Val1,
        }
        .into()]);
        assert_eq!(vm.core.cx.get(RegE::E5), Some(1u8.into()));

        let vm = stand(vec![FieldInstr::PutV {
            dst: RegE::E6,
            val: ConstVal::ValU64Max,
        }
        .into()]);
        assert_eq!(vm.core.cx.get(RegE::E6), Some(u64::MAX.into()));

        let vm = stand(vec![FieldInstr::PutV {
            dst: RegE::E7,
            val: ConstVal::ValU128Max,
        }
        .into()]);
        assert_eq!(vm.core.cx.get(RegE::E7), Some(u128::MAX.into()));

        let vm = stand(vec![FieldInstr::PutV {
            dst: RegE::E8,
            val: ConstVal::ValFeMAX,
        }
        .into()]);
        assert_eq!(vm.core.cx.get(RegE::E8), Some((vm.core.cx.fq() - u256::ONE).into()));

        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);
    }

    #[test]
    fn fits() {
        const VAL1: u256 = u256::from_inner([3456556, 23456657, 0, 0]);
        assert!(VAL1 < u128::MAX.into());
        assert!(VAL1 > u64::MAX.into());
        assert!(VAL1 > u32::MAX.into());
        assert!(VAL1 > u16::MAX.into());
        assert!(VAL1 > u8::MAX.into());

        let val2: u256 = u256::from(15u8);
        assert!(val2 < u128::MAX.into());
        assert!(val2 < u64::MAX.into());
        assert!(val2 < u32::MAX.into());
        assert!(val2 < u16::MAX.into());
        assert!(val2 < u8::MAX.into());

        let vm = stand(zk_aluasm! {
            mov     EA, :VAL1;

            fits    EA, 128 :bits;
            chk     CO;
            chk     CK;

            fits    EA, 64 :bits;
            not     CO;
            chk     CO;
            mov     CO, CK;
            not     CO;
            chk     CK;

            fits    EA, 32 :bits;
            not     CO;
            chk     CO;
            mov     CO, CK;
            not     CO;
            chk     CK;

            fits    EA, 16 :bits;
            not     CO;
            chk     CO;
            mov     CO, CK;
            not     CO;
            chk     CK;

            fits    EA, 8 :bits;
            not     CO;
            chk     CO;
            mov     CO, CK;
            not     CO;
            chk     CK;

            mov     EB, :val2;

            fits    EB, 8 :bits;
            chk     CO;
            chk     CK;
        });
        assert_eq!(vm.core.cx.get(RegE::EA), Some(fe256::from(VAL1)));
        assert_eq!(vm.core.cx.get(RegE::EB), Some(fe256::from(val2)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);
    }

    #[test]
    fn mov() {
        const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
        let vm = stand(zk_aluasm! {
            mov     EC, :VAL;
            mov     ED, EC;
        });
        assert_eq!(vm.core.cx.get(RegE::EC), Some(fe256::from(VAL)));
        assert_eq!(vm.core.cx.get(RegE::ED), Some(fe256::from(VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);
    }

    #[test]
    fn eq() {
        // Cmp equals
        const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
        let vm = stand(zk_aluasm! {
            mov     EE, :VAL;
            mov     EF, :VAL;
            eq      EF, EE;
        });
        assert_eq!(vm.core.cx.get(RegE::EE), Some(fe256::from(VAL)));
        assert_eq!(vm.core.cx.get(RegE::EF), Some(fe256::from(VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Cmp non-equals
        let vm = stand(zk_aluasm! {
            mov     EE, :VAL;
            mov     EF, :VAL;
            neg     EF, EF;
            eq      EF, EE;
        });
        assert_eq!(vm.core.cx.get(RegE::EE), Some(fe256::from(VAL)));
        assert_eq!(vm.core.cx.get(RegE::EF), Some(fe256::from(vm.core.cx.fq() - VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Fail);

        // Cmp with None
        let vm = stand(zk_aluasm! {
            mov     EE, :VAL;
            eq      EF, EE;
        });
        assert_eq!(vm.core.cx.get(RegE::EE), Some(fe256::from(VAL)));
        assert_eq!(vm.core.cx.get(RegE::EF), None);
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Fail);

        // Two None's
        let vm = stand(zk_aluasm! {
            eq      EF, EE;
        });
        assert_eq!(vm.core.cx.get(RegE::EE), None);
        assert_eq!(vm.core.cx.get(RegE::EF), None);
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Fail);
    }

    #[test]
    fn neg() {
        const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
        // Negate a value, same register
        let vm = stand(zk_aluasm! {
            mov     EF, :VAL;
            neg     EF, EF;
        });
        assert_eq!(vm.core.cx.get(RegE::EF), Some(fe256::from(vm.core.cx.fq() - VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Negate a value, different registers
        let vm = stand(zk_aluasm! {
            mov     EF, :VAL;
            neg     E1, EF;
        });
        assert_eq!(vm.core.cx.get(RegE::EF), Some(fe256::from(VAL)));
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(vm.core.cx.fq() - VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Negate a None
        let vm = stand_fail(zk_aluasm! {
            neg     EF, EF;
        });
        assert_eq!(vm.core.cx.get(RegE::EF), None);
        assert_eq!(vm.core.ck(), Status::Fail);
        assert_eq!(vm.core.co(), Status::Ok);
    }

    #[test]
    fn add() {
        const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
        const ONE: u256 = u256::from_inner([1, 0, 0, 0]);

        // Increment
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, :ONE;
            add     E1, E2;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL + ONE)));
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(ONE)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Double
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, :VAL;
            add     E1, E2;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL + VAL)));
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Overflow
        let max: u256 = vm.core.cx.fq() - u256::ONE;
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, :max;
            add     E1, E2;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL - ONE)));
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(max)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);
    }

    #[test]
    fn mul() {
        const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
        const ONE: u256 = u256::from_inner([1, 0, 0, 0]);

        // * 0
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, 0;
            mul     E1, E2;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(u256::ZERO)));
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(u256::ZERO)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // * 1
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, :ONE;
            mul     E1, E2;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL * ONE)));
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(ONE)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // * 2
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, 2;
            mul     E1, E2;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL * u256::from(2u8))));
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(u256::from(2u8))));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Double no overflow
        let vm = stand(zk_aluasm! {
            mov     E1, 2;
            mov     E2, 4;
            mul     E1, E2;
        });
        assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(u256::from(8u8))));
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(u256::from(4u8))));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Double with overflow
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, :VAL;
            mul     E1, E2;
        });
        assert_eq!(
            vm.core.cx.get(RegE::E1),
            Some(fe256::from(u256::from_inner([
                0x1c896b19a830b708,
                0x38f848556f7080a7,
                0x0047513c5c11959e,
                0x300c528a96299c6c,
            ])))
        );
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(VAL)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);

        // Overflow
        let max: u256 = vm.core.cx.fq() - u256::ONE;
        let vm = stand(zk_aluasm! {
            mov     E1, :VAL;
            mov     E2, :max;
            mul     E1, E2;
        });
        assert_eq!(
            vm.core.cx.get(RegE::E1),
            Some(fe256::from(u256::from_inner([
                0xfffffffffb98e8f6,
                0xfffffffffff8ecd7,
                0xffffffffffcb41d3,
                0x8ffffffffe9a146e,
            ])))
        );
        assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(max)));
        assert_eq!(vm.core.ck(), Status::Ok);
        assert_eq!(vm.core.co(), Status::Ok);
    }
}
