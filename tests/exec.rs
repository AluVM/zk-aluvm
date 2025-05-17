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

extern crate alloc;

use aluvm::isa::ReservedInstr;
use aluvm::regs::Status;
use aluvm::{CoreConfig, CoreExt, Lib, LibId, LibSite, Vm};
use amplify::default;
use amplify::num::u256;
use zkaluvm::gfa::{ConstVal, FieldInstr, Instr};
use zkaluvm::{fe256, zk_aluasm, RegE};

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
        put     E2, 0;
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
        put     E3, 0;
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
        put     E1, VAL;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);
}

#[test]
fn putz() {
    let code = zk_aluasm! {
        put     E4, 0;
    };
    assert_eq!(code, vec![FieldInstr::PutZ { dst: RegE::E4 }.into()]);
    let vm = stand(code);
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
        put     EA, VAL1;

        fits    EA, 128.bits;
        chk     CO;
        chk     CK;

        fits    EA, 96.bits;
        chk     CO;
        chk     CK;

        fits    EA, 64.bits;
        not     CO;
        chk     CO;
        mov     CO, CK;
        not     CO;
        chk     CK;

        fits    EA, 48.bits;
        not     CO;
        chk     CO;
        mov     CO, CK;
        not     CO;
        chk     CK;

        fits    EA, 32.bits;
        not     CO;
        chk     CO;
        mov     CO, CK;
        not     CO;
        chk     CK;

        fits    EA, 24.bits;
        not     CO;
        chk     CO;
        mov     CO, CK;
        not     CO;
        chk     CK;

        fits    EA, 16.bits;
        not     CO;
        chk     CO;
        mov     CO, CK;
        not     CO;
        chk     CK;

        fits    EA, 8.bits;
        not     CO;
        chk     CO;
        mov     CO, CK;
        not     CO;
        chk     CK;

        put     EB, val2;

        fits    EB, 8.bits;
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
        put     EC, VAL;
        mov     ED, EC;
    });
    assert_eq!(vm.core.cx.get(RegE::EC), Some(fe256::from(VAL)));
    assert_eq!(vm.core.cx.get(RegE::ED), Some(fe256::from(VAL)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // None
    let vm = stand(zk_aluasm! {
        put     EG, VAL;
        mov     EG, EH;
    });
    assert_eq!(vm.core.cx.get(RegE::EC), None);
    assert_eq!(vm.core.cx.get(RegE::EG), None);
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);
}

#[test]
fn eq() {
    // Cmp equals
    const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
    let vm = stand(zk_aluasm! {
        put     EE, VAL;
        put     EF, VAL;
        eq      EF, EE;
    });
    assert_eq!(vm.core.cx.get(RegE::EE), Some(fe256::from(VAL)));
    assert_eq!(vm.core.cx.get(RegE::EF), Some(fe256::from(VAL)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // Cmp non-equals
    let vm = stand(zk_aluasm! {
        put     EE, VAL;
        put     EF, VAL;
        neg     EF, EF;
        eq      EF, EE;
    });
    assert_eq!(vm.core.cx.get(RegE::EE), Some(fe256::from(VAL)));
    assert_eq!(vm.core.cx.get(RegE::EF), Some(fe256::from(vm.core.cx.fq() - VAL)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Fail);

    // Cmp with None
    let vm = stand(zk_aluasm! {
        put     EE, VAL;
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
        put     EF, VAL;
        neg     EF, EF;
    });
    assert_eq!(vm.core.cx.get(RegE::EF), Some(fe256::from(vm.core.cx.fq() - VAL)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // Negate a value, different registers
    let vm = stand(zk_aluasm! {
        put     EF, VAL;
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
        put     E1, VAL;
        put     E2, ONE;
        add     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL + ONE)));
    assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(ONE)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // Double
    let vm = stand(zk_aluasm! {
        put     E1, VAL;
        put     E2, VAL;
        add     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL + VAL)));
    assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(VAL)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // Overflow
    let max: u256 = vm.core.cx.fq() - u256::ONE;
    let vm = stand(zk_aluasm! {
        put     E1, VAL;
        put     E2, max;
        add     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL - ONE)));
    assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(max)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // none
    let vm = stand_fail(zk_aluasm! {
        put     E1, VAL;
        add     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL)));
    assert_eq!(vm.core.cx.get(RegE::E2), None);
    assert_eq!(vm.core.ck(), Status::Fail);
    assert_eq!(vm.core.co(), Status::Ok);

    let vm = stand_fail(zk_aluasm! {
        put     E1, VAL;
        add     E2, E1;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL)));
    assert_eq!(vm.core.cx.get(RegE::E2), None);
    assert_eq!(vm.core.ck(), Status::Fail);
    assert_eq!(vm.core.co(), Status::Ok);

    let vm = stand_fail(zk_aluasm! {
        add     E2, E1;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), None);
    assert_eq!(vm.core.cx.get(RegE::E2), None);
    assert_eq!(vm.core.ck(), Status::Fail);
    assert_eq!(vm.core.co(), Status::Ok);
}

#[test]
fn mul() {
    const VAL: u256 = u256::from_inner([73864950, 463656, 3456556, 23456657]);
    const ONE: u256 = u256::from_inner([1, 0, 0, 0]);

    // * 0
    let vm = stand(zk_aluasm! {
        put     E1, VAL;
        put     E2, 0;
        mul     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(u256::ZERO)));
    assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(u256::ZERO)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // * 1
    let vm = stand(zk_aluasm! {
        put     E1, VAL;
        put     E2, ONE;
        mul     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL * ONE)));
    assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(ONE)));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // * 2
    let vm = stand(zk_aluasm! {
        put     E1, VAL;
        put     E2, 2;
        mul     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL * u256::from(2u8))));
    assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(u256::from(2u8))));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // Double no overflow
    let vm = stand(zk_aluasm! {
        put     E1, 2;
        put     E2, 4;
        mul     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(u256::from(8u8))));
    assert_eq!(vm.core.cx.get(RegE::E2), Some(fe256::from(u256::from(4u8))));
    assert_eq!(vm.core.ck(), Status::Ok);
    assert_eq!(vm.core.co(), Status::Ok);

    // Double with overflow
    let vm = stand(zk_aluasm! {
        put     E1, VAL;
        put     E2, VAL;
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
        put     E1, VAL;
        put     E2, max;
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

    // none
    let vm = stand_fail(zk_aluasm! {
        put     E1, VAL;
        mul     E1, E2;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL)));
    assert_eq!(vm.core.cx.get(RegE::E2), None);
    assert_eq!(vm.core.ck(), Status::Fail);
    assert_eq!(vm.core.co(), Status::Ok);

    let vm = stand_fail(zk_aluasm! {
        put     E1, VAL;
        mul     E2, E1;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), Some(fe256::from(VAL)));
    assert_eq!(vm.core.cx.get(RegE::E2), None);
    assert_eq!(vm.core.ck(), Status::Fail);
    assert_eq!(vm.core.co(), Status::Ok);

    let vm = stand_fail(zk_aluasm! {
        mul     E2, E1;
    });
    assert_eq!(vm.core.cx.get(RegE::E1), None);
    assert_eq!(vm.core.cx.get(RegE::E2), None);
    assert_eq!(vm.core.ck(), Status::Fail);
    assert_eq!(vm.core.co(), Status::Ok);
}

#[test]
fn reset() {
    // Increment
    let mut vm = stand(zk_aluasm! {
        put     E1, 1;
        put     E2, 2;
        put     E3, 3;
        put     E4, 4;
        put     E5, 5;
        put     E6, 6;
        put     E7, 7;
        put     E8, 8;
        put     EA, 9;
        put     EB, 10;
        put     EC, 11;
        put     ED, 12;
        put     EE, 13;
        put     EF, 14;
        put     EG, 15;
        put     EH, 16;
    });
    for (no, reg) in RegE::ALL.iter().enumerate() {
        assert_eq!(vm.core.cx.get(*reg), Some(fe256::from(no as u64 + 1)));
    }
    vm.core.reset();
    for reg in RegE::ALL {
        assert_eq!(vm.core.cx.get(reg), None);
        vm.core.cx.put(reg, Some(fe256::from(reg as u64)));
        assert_eq!(vm.core.cx.get(reg), Some(fe256::from(reg as u64)));
        vm.core.cx.put(reg, None);
        assert_eq!(vm.core.cx.get(reg), None);
    }
}

#[test]
fn reserved() {
    let code = vec![Instr::<LibId>::Reserved(ReservedInstr::default())];
    let vm = stand_fail(code);
    assert_eq!(vm.core.co(), Status::Ok);
    assert_eq!(vm.core.ck(), Status::Fail);
}
