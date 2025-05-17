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

use core::ops::RangeInclusive;

use aluvm::isa::{Bytecode, BytecodeRead, BytecodeWrite, CodeEofError, CtrlInstr, ReservedInstr};
use aluvm::SiteId;
use amplify::num::{u2, u256, u3, u4};

use super::{Bits, ConstVal, FieldInstr, Instr};
use crate::{fe256, RegE};

#[allow(clippy::identity_op)]
impl FieldInstr {
    pub const START: u8 = 64;
    pub const END: u8 = Self::MUL;

    pub const SET: u8 = Self::START + 0;
    pub const TEST: u8 = Self::START + 0;
    pub const CLR: u8 = Self::START + 0;
    pub const PUTD: u8 = Self::START + 0;
    pub const PUTZ: u8 = Self::START + 0;
    pub const PUTV: u8 = Self::START + 0;
    pub const FITS: u8 = Self::START + 0;

    pub const MOV: u8 = Self::START + 1;
    pub const EQ: u8 = Self::START + 2;
    pub const NEG: u8 = Self::START + 3;
    pub const ADD: u8 = Self::START + 4;
    pub const MUL: u8 = Self::START + 5;
}

const SUB_TEST: u8 = 0b_0000;
const SUB_CLR: u8 = 0b_0001;
const SUB_PUTD: u8 = 0b_0010;
const SUB_PUTZ: u8 = 0b_0011;
const MASK_PUTV: u8 = 0b_1100;
const TEST_PUTV: u8 = 0b_0100;
const MASK_FITS: u8 = 0b_1000;
const TEST_FITS: u8 = 0b_1000;

impl<Id: SiteId> Bytecode<Id> for FieldInstr {
    fn op_range() -> RangeInclusive<u8> { Self::START..=Self::END }

    fn opcode_byte(&self) -> u8 {
        match *self {
            FieldInstr::Test { .. }
            | FieldInstr::Clr { .. }
            | FieldInstr::PutD { .. }
            | FieldInstr::PutZ { .. }
            | FieldInstr::PutV { .. }
            | FieldInstr::Fits { .. } => Self::SET,
            FieldInstr::Mov { .. } => Self::MOV,
            FieldInstr::Eq { .. } => Self::EQ,
            FieldInstr::Neg { .. } => Self::NEG,
            FieldInstr::Add { .. } => Self::ADD,
            FieldInstr::Mul { .. } => Self::MUL,
        }
    }

    fn code_byte_len(&self) -> u16 {
        let arg_len = match *self {
            FieldInstr::Test { src: _ } => 1,
            FieldInstr::Clr { dst: _ } => 1,
            FieldInstr::PutD { dst: _, data: _ } => 3,
            FieldInstr::PutZ { dst: _ } => 1,
            FieldInstr::PutV { dst: _, val: _ } => 1,
            FieldInstr::Fits { src: _, bits: _ } => 1,
            FieldInstr::Mov { dst: _, src: _ } => 1,
            FieldInstr::Eq { src1: _, src2: _ } => 1,
            FieldInstr::Neg { dst: _, src: _ } => 1,
            FieldInstr::Add { dst_src: _, src: _ } => 1,
            FieldInstr::Mul { dst_src: _, src: _ } => 1,
        };
        arg_len + 1
    }

    fn external_ref(&self) -> Option<Id> { None }

    fn encode_operands<W>(&self, writer: &mut W) -> Result<(), W::Error>
    where W: BytecodeWrite<Id> {
        match *self {
            FieldInstr::Test { src } => {
                writer.write_4bits(u4::with(SUB_TEST))?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::Clr { dst } => {
                writer.write_4bits(u4::with(SUB_CLR))?;
                writer.write_4bits(dst.to_u4())?;
            }
            FieldInstr::PutD { dst, data } => {
                writer.write_4bits(u4::with(SUB_PUTD))?;
                writer.write_4bits(dst.to_u4())?;
                writer.write_fixed(data.to_u256().to_le_bytes())?;
            }
            FieldInstr::PutZ { dst } => {
                writer.write_4bits(u4::with(SUB_PUTZ))?;
                writer.write_4bits(dst.to_u4())?;
            }
            FieldInstr::PutV { dst, val } => {
                let half = u4::with(TEST_PUTV | val.to_u2().to_u8());
                writer.write_4bits(half)?;
                writer.write_4bits(dst.to_u4())?;
            }
            FieldInstr::Fits { src, bits } => {
                let half = u4::with(TEST_FITS | bits.to_u3().to_u8());
                writer.write_4bits(half)?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::Mov { dst, src } => {
                writer.write_4bits(dst.to_u4())?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::Eq { src1, src2 } => {
                writer.write_4bits(src1.to_u4())?;
                writer.write_4bits(src2.to_u4())?;
            }
            FieldInstr::Neg { dst, src } => {
                writer.write_4bits(dst.to_u4())?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::Add { dst_src, src } => {
                writer.write_4bits(dst_src.to_u4())?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::Mul { dst_src, src } => {
                writer.write_4bits(dst_src.to_u4())?;
                writer.write_4bits(src.to_u4())?;
            }
        }
        Ok(())
    }

    fn decode_operands<R>(reader: &mut R, opcode: u8) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: BytecodeRead<Id>,
    {
        Ok(match opcode {
            Self::SET => {
                let sub = reader.read_4bits()?.to_u8();
                match sub {
                    SUB_TEST => {
                        let src = RegE::from(reader.read_4bits()?);
                        FieldInstr::Test { src }
                    }
                    SUB_CLR => {
                        let dst = RegE::from(reader.read_4bits()?);
                        FieldInstr::Clr { dst }
                    }
                    SUB_PUTD => {
                        let dst = RegE::from(reader.read_4bits()?);
                        let data = reader.read_fixed(|d: [u8; 32]| fe256::from(u256::from_le_bytes(d)))?;
                        FieldInstr::PutD { dst, data }
                    }
                    SUB_PUTZ => {
                        let dst = RegE::from(reader.read_4bits()?);
                        FieldInstr::PutZ { dst }
                    }
                    x if x & MASK_PUTV == TEST_PUTV => {
                        let val = ConstVal::from(u2::with(sub & !MASK_PUTV));
                        let dst = RegE::from(reader.read_4bits()?);
                        FieldInstr::PutV { dst, val }
                    }
                    x if x & MASK_FITS == TEST_FITS => {
                        let bits = Bits::from(u3::with(sub & !MASK_FITS));
                        let src = RegE::from(reader.read_4bits()?);
                        FieldInstr::Fits { src, bits }
                    }
                    _ => unreachable!(),
                }
            }
            Self::MOV => {
                let dst = RegE::from(reader.read_4bits()?);
                let src = RegE::from(reader.read_4bits()?);
                FieldInstr::Mov { dst, src }
            }
            Self::EQ => {
                let src1 = RegE::from(reader.read_4bits()?);
                let src2 = RegE::from(reader.read_4bits()?);
                FieldInstr::Eq { src1, src2 }
            }
            Self::NEG => {
                let dst = RegE::from(reader.read_4bits()?);
                let src = RegE::from(reader.read_4bits()?);
                FieldInstr::Neg { dst, src }
            }
            Self::ADD => {
                let dst_src = RegE::from(reader.read_4bits()?);
                let src = RegE::from(reader.read_4bits()?);
                FieldInstr::Add { dst_src, src }
            }
            Self::MUL => {
                let dst_src = RegE::from(reader.read_4bits()?);
                let src = RegE::from(reader.read_4bits()?);
                FieldInstr::Mul { dst_src, src }
            }
            _ => unreachable!(),
        })
    }
}

impl<Id: SiteId> Bytecode<Id> for Instr<Id> {
    fn op_range() -> RangeInclusive<u8> { 0..=0xFF }

    fn opcode_byte(&self) -> u8 {
        match self {
            Instr::Ctrl(instr) => instr.opcode_byte(),
            Instr::Gfa(instr) => Bytecode::<Id>::opcode_byte(instr),
            Instr::Reserved(instr) => Bytecode::<Id>::opcode_byte(instr),
        }
    }

    fn code_byte_len(&self) -> u16 {
        match self {
            Instr::Ctrl(instr) => instr.code_byte_len(),
            Instr::Gfa(instr) => Bytecode::<Id>::code_byte_len(instr),
            Instr::Reserved(instr) => Bytecode::<Id>::code_byte_len(instr),
        }
    }

    fn external_ref(&self) -> Option<Id> {
        match self {
            Instr::Ctrl(instr) => instr.external_ref(),
            Instr::Gfa(instr) => Bytecode::<Id>::external_ref(instr),
            Instr::Reserved(instr) => Bytecode::<Id>::external_ref(instr),
        }
    }

    fn encode_operands<W>(&self, writer: &mut W) -> Result<(), W::Error>
    where W: BytecodeWrite<Id> {
        match self {
            Instr::Ctrl(instr) => instr.encode_operands(writer),
            Instr::Gfa(instr) => instr.encode_operands(writer),
            Instr::Reserved(instr) => instr.encode_operands(writer),
        }
    }

    fn decode_operands<R>(reader: &mut R, opcode: u8) -> Result<Self, CodeEofError>
    where
        Self: Sized,
        R: BytecodeRead<Id>,
    {
        match opcode {
            op if CtrlInstr::<Id>::op_range().contains(&op) => {
                CtrlInstr::<Id>::decode_operands(reader, op).map(Self::Ctrl)
            }
            op if <FieldInstr as Bytecode<Id>>::op_range().contains(&op) => {
                FieldInstr::decode_operands(reader, op).map(Self::Gfa)
            }
            _ => ReservedInstr::decode_operands(reader, opcode).map(Self::Reserved),
        }
    }
}

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]
    use core::str::FromStr;

    use aluvm::{LibId, LibsSeg, Marshaller};
    use amplify::confinement::SmallBlob;

    use super::*;
    use crate::RegE;

    const LIB_ID: &str = "5iMb1eHJ-bN5BOe6-9RvBjYL-jF1ELjj-VV7c8Bm-WvFen1Q";

    fn roundtrip(instr: impl Into<Instr<LibId>>, bytecode: impl AsRef<[u8]>, dataseg: Option<&[u8]>) -> SmallBlob {
        let instr = instr.into();
        let mut libs = LibsSeg::new();
        libs.push(LibId::from_str(LIB_ID).unwrap()).unwrap();
        let mut marshaller = Marshaller::new(&libs);
        instr.encode_instr(&mut marshaller).unwrap();
        let (code, data) = marshaller.finish();
        assert_eq!(code.as_slice(), bytecode.as_ref());
        if let Some(d) = dataseg {
            assert_eq!(data.as_slice(), d);
        } else {
            assert!(data.is_empty());
        }
        let mut marshaller = Marshaller::with(code, data, &libs);
        let decoded = Instr::<LibId>::decode_instr(&mut marshaller).unwrap();
        assert_eq!(decoded, instr);
        marshaller.into_code_data().1
    }

    #[test]
    fn test() {
        for reg in RegE::ALL {
            let instr = Instr::<LibId>::Gfa(FieldInstr::Test { src: reg });
            let opcode = FieldInstr::SET;
            let sub = reg.to_u4().to_u8() << 4 | SUB_TEST;

            roundtrip(instr, [opcode, sub], None);

            assert_eq!(instr.code_byte_len(), 2);
            assert_eq!(instr.opcode_byte(), FieldInstr::TEST);
            assert_eq!(instr.external_ref(), None);
        }
    }

    #[test]
    fn clr() {
        for reg in RegE::ALL {
            let instr = Instr::<LibId>::Gfa(FieldInstr::Clr { dst: reg });
            let opcode = FieldInstr::SET;
            let sub = reg.to_u4().to_u8() << 4 | SUB_CLR;

            roundtrip(instr, [opcode, sub], None);

            assert_eq!(instr.code_byte_len(), 2);
            assert_eq!(instr.opcode_byte(), FieldInstr::CLR);
            assert_eq!(instr.external_ref(), None);
        }
    }

    #[test]
    fn putd() {
        for reg in RegE::ALL {
            let val = u256::from(0xdeadcafe1badbeef_u64);
            let data = val.to_le_bytes();

            let instr = Instr::<LibId>::Gfa(FieldInstr::PutD {
                dst: reg,
                data: fe256::from(val),
            });
            let opcode = FieldInstr::SET;
            let sub = reg.to_u4().to_u8() << 4 | SUB_PUTD;

            roundtrip(instr, [opcode, sub, 0, 0], Some(&data[..]));

            assert_eq!(instr.code_byte_len(), 4);
            assert_eq!(instr.opcode_byte(), FieldInstr::PUTD);
            assert_eq!(instr.external_ref(), None);
        }
    }

    #[test]
    fn putz() {
        for reg in RegE::ALL {
            let instr = Instr::<LibId>::Gfa(FieldInstr::PutZ { dst: reg });
            let opcode = FieldInstr::SET;
            let sub = reg.to_u4().to_u8() << 4 | SUB_PUTZ;

            roundtrip(instr, [opcode, sub], None);

            assert_eq!(instr.code_byte_len(), 2);
            assert_eq!(instr.opcode_byte(), FieldInstr::PUTZ);
            assert_eq!(instr.external_ref(), None);
        }
    }

    #[test]
    fn putv() {
        for reg in RegE::ALL {
            for val_u8 in 0..4 {
                let val = ConstVal::from(u2::with(val_u8));
                let instr = Instr::<LibId>::Gfa(FieldInstr::PutV { dst: reg, val });
                let opcode = FieldInstr::SET;
                let sub = reg.to_u4().to_u8() << 4 | TEST_PUTV | val.to_u2().to_u8();

                roundtrip(instr, [opcode, sub], None);

                assert_eq!(instr.code_byte_len(), 2);
                assert_eq!(instr.opcode_byte(), FieldInstr::PUTV);
                assert_eq!(instr.external_ref(), None);
            }
        }
    }

    #[test]
    fn fits() {
        for reg in RegE::ALL {
            for bits_u8 in 0..8 {
                let bits = Bits::from(u3::with(bits_u8));
                let instr = Instr::<LibId>::Gfa(FieldInstr::Fits { src: reg, bits });
                let opcode = FieldInstr::SET;
                let sub = reg.to_u4().to_u8() << 4 | TEST_FITS | bits.to_u3().to_u8();

                roundtrip(instr, [opcode, sub], None);

                assert_eq!(instr.code_byte_len(), 2);
                assert_eq!(instr.opcode_byte(), FieldInstr::FITS);
                assert_eq!(instr.external_ref(), None);
            }
        }
    }

    #[test]
    fn mov() {
        for reg1 in RegE::ALL {
            for reg2 in RegE::ALL {
                let instr = Instr::<LibId>::Gfa(FieldInstr::Mov { dst: reg1, src: reg2 });
                let opcode = FieldInstr::MOV;
                let regs = reg2.to_u4().to_u8() << 4 | reg1.to_u4().to_u8();

                roundtrip(instr, [opcode, regs], None);

                assert_eq!(instr.code_byte_len(), 2);
                assert_eq!(instr.opcode_byte(), FieldInstr::MOV);
                assert_eq!(instr.external_ref(), None);
            }
        }
    }

    #[test]
    fn eq() {
        for reg1 in RegE::ALL {
            for reg2 in RegE::ALL {
                let instr = Instr::<LibId>::Gfa(FieldInstr::Eq { src1: reg1, src2: reg2 });
                let opcode = FieldInstr::EQ;
                let regs = reg2.to_u4().to_u8() << 4 | reg1.to_u4().to_u8();

                roundtrip(instr, [opcode, regs], None);

                assert_eq!(instr.code_byte_len(), 2);
                assert_eq!(instr.opcode_byte(), FieldInstr::EQ);
                assert_eq!(instr.external_ref(), None);
            }
        }
    }

    #[test]
    fn neq() {
        for reg1 in RegE::ALL {
            for reg2 in RegE::ALL {
                let instr = Instr::<LibId>::Gfa(FieldInstr::Neg { dst: reg1, src: reg2 });
                let opcode = FieldInstr::NEG;
                let regs = reg2.to_u4().to_u8() << 4 | reg1.to_u4().to_u8();

                roundtrip(instr, [opcode, regs], None);

                assert_eq!(instr.code_byte_len(), 2);
                assert_eq!(instr.opcode_byte(), FieldInstr::NEG);
                assert_eq!(instr.external_ref(), None);
            }
        }
    }

    #[test]
    fn add() {
        for reg1 in RegE::ALL {
            for reg2 in RegE::ALL {
                let instr = Instr::<LibId>::Gfa(FieldInstr::Add {
                    dst_src: reg1,
                    src: reg2,
                });
                let opcode = FieldInstr::ADD;
                let regs = reg2.to_u4().to_u8() << 4 | reg1.to_u4().to_u8();

                roundtrip(instr, [opcode, regs], None);

                assert_eq!(instr.code_byte_len(), 2);
                assert_eq!(instr.opcode_byte(), FieldInstr::ADD);
                assert_eq!(instr.external_ref(), None);
            }
        }
    }

    #[test]
    fn mul() {
        for reg1 in RegE::ALL {
            for reg2 in RegE::ALL {
                let instr = Instr::<LibId>::Gfa(FieldInstr::Mul {
                    dst_src: reg1,
                    src: reg2,
                });
                let opcode = FieldInstr::MUL;
                let regs = reg2.to_u4().to_u8() << 4 | reg1.to_u4().to_u8();

                roundtrip(instr, [opcode, regs], None);

                assert_eq!(instr.code_byte_len(), 2);
                assert_eq!(instr.opcode_byte(), FieldInstr::MUL);
                assert_eq!(instr.external_ref(), None);
            }
        }
    }

    #[test]
    fn reserved() {
        let instr = Instr::<LibId>::Reserved(default!());
        roundtrip(instr, [0xFF], None);

        assert_eq!(instr.code_byte_len(), 1);
        assert_eq!(instr.opcode_byte(), 0xFF);
        assert_eq!(instr.external_ref(), None);
    }
}
