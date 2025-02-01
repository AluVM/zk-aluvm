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
use amplify::num::{u1, u2, u256, u4};

use super::{Bits, ConstVal, FieldInstr, Instr};
use crate::{fe256, RegE};

impl FieldInstr {
    const START: u8 = 64;
    const END: u8 = Self::START + Self::MUL;
    const SET: u8 = 0;
    const MOV: u8 = 1;
    const EQ: u8 = 2;
    const NEG: u8 = 3;
    const ADD: u8 = 4;
    const MUL: u8 = 5;
}

impl<Id: SiteId> Bytecode<Id> for FieldInstr {
    fn op_range() -> RangeInclusive<u8> { Self::START..=Self::END }

    fn opcode_byte(&self) -> u8 {
        Self::START
            + match *self {
                FieldInstr::Test { .. }
                | FieldInstr::Clr { .. }
                | FieldInstr::PutD { .. }
                | FieldInstr::PutZ { .. }
                | FieldInstr::PutV { .. }
                | FieldInstr::Fits { .. } => Self::SET,
                FieldInstr::Mov { .. } => Self::MOV,
                FieldInstr::Eq { .. } => Self::EQ,
                FieldInstr::NegMod { .. } => Self::NEG,
                FieldInstr::AddMod { .. } => Self::ADD,
                FieldInstr::MulMod { .. } => Self::MUL,
            }
    }

    fn encode_operands<W>(&self, writer: &mut W) -> Result<(), W::Error>
    where W: BytecodeWrite<Id> {
        match *self {
            FieldInstr::Test { src } => {
                writer.write_4bits(u4::with(0b_0000))?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::Clr { dst } => {
                writer.write_4bits(u4::with(0b_0001))?;
                writer.write_4bits(dst.to_u4())?;
            }
            FieldInstr::PutD { dst, data } => {
                writer.write_4bits(u4::with(0b_0010))?;
                writer.write_4bits(dst.to_u4())?;
                writer.write_fixed(data.to_u256().to_le_bytes())?;
            }
            FieldInstr::PutZ { dst } => {
                writer.write_4bits(u4::with(0b_0011))?;
                writer.write_4bits(dst.to_u4())?;
            }
            FieldInstr::PutV { dst, val } => {
                writer.write_1bit(u1::ZERO)?;
                writer.write_3bits(val.to_u3())?;
                writer.write_4bits(dst.to_u4())?;
            }
            FieldInstr::Fits { src: dst, bits } => {
                writer.write_1bit(u1::ONE)?;
                writer.write_3bits(bits.to_u3())?;
                writer.write_4bits(dst.to_u4())?;
            }
            FieldInstr::Mov { dst, src } => {
                writer.write_4bits(dst.to_u4())?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::Eq { src1, src2 } => {
                writer.write_4bits(src1.to_u4())?;
                writer.write_4bits(src2.to_u4())?;
            }
            FieldInstr::NegMod { dst, src } => {
                writer.write_4bits(dst.to_u4())?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::AddMod { dst_src, src } => {
                writer.write_4bits(dst_src.to_u4())?;
                writer.write_4bits(src.to_u4())?;
            }
            FieldInstr::MulMod { dst_src, src } => {
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
        Ok(match opcode - Self::START {
            Self::SET => {
                let sub = u1::from(reader.read_1bit()?);
                match sub {
                    u1::ZERO => {
                        let sub2 = u1::from(reader.read_1bit()?);
                        match sub2 {
                            u1::ZERO => {
                                let sub3 = u2::from(reader.read_2bits()?);
                                match sub3 {
                                    u2::ZERO => {
                                        let src = RegE::from(reader.read_4bits()?);
                                        FieldInstr::Test { src }
                                    }
                                    u2::ONE => {
                                        let dst = RegE::from(reader.read_4bits()?);
                                        FieldInstr::Clr { dst }
                                    }
                                    x if x == u2::with(2) => {
                                        let dst = RegE::from(reader.read_4bits()?);
                                        let data =
                                            reader.read_fixed(|d: [u8; 32]| fe256::from(u256::from_le_bytes(d)))?;
                                        FieldInstr::PutD { dst, data }
                                    }
                                    u2::MAX => {
                                        let dst = RegE::from(reader.read_4bits()?);
                                        FieldInstr::PutZ { dst }
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            u1::ONE => {
                                let val = ConstVal::from(reader.read_3bits()?);
                                let dst = RegE::from(reader.read_4bits()?);
                                FieldInstr::PutV { dst, val }
                            }
                            _ => unreachable!(),
                        }
                    }
                    u1::ONE => {
                        let bits = Bits::from(reader.read_3bits()?);
                        let dst = RegE::from(reader.read_4bits()?);
                        FieldInstr::Fits { src: dst, bits }
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
                FieldInstr::NegMod { dst, src }
            }
            Self::ADD => {
                let dst_src = RegE::from(reader.read_4bits()?);
                let src = RegE::from(reader.read_4bits()?);
                FieldInstr::AddMod { dst_src, src }
            }
            Self::MUL => {
                let dst_src = RegE::from(reader.read_4bits()?);
                let src = RegE::from(reader.read_4bits()?);
                FieldInstr::MulMod { dst_src, src }
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
