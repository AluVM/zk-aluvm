// AluVM ISA extension for Galois fields
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

use aluvm::regs::Status;
use aluvm::CoreExt;
use amplify::num::{u256, u512};

use crate::gfa::Bits;
use crate::{fe256, GfaCore, RegE};

/// Microcode for finite field arithmetics.
impl GfaCore {
    /// Get value of the field order register (`FQ`).
    pub fn fq(&self) -> u256 { self.fq }

    /// Test whether the register has a value, returning a status.
    ///
    /// # Register modification
    ///
    /// No registers are modified, including `CK` and `CO`.
    pub fn test(&self, src: RegE) -> Status {
        if self.get(src).is_some() {
            Status::Ok
        } else {
            Status::Fail
        }
    }

    /// Check whether a register value fits the provided number of bits.
    ///
    /// # Returns
    ///
    /// `None`, if the register contains no value. Otherwise, a boolean value indicating the test
    /// result.
    ///
    /// # Register modification
    ///
    /// No registers are modified, including `CK` and `CO`.
    pub fn fits(&self, src: RegE, bits: Bits) -> Option<bool> {
        let order = self.fq();
        let a = self.get(src)?;
        debug_assert!(a.to_u256() < order);
        let check = a.to_u256() >> bits.bit_len();
        Some(check == u256::ZERO)
    }

    /// Move a value from the `src` to `dst` register.
    ///
    /// The value of the `src` register is not changed.
    ///
    /// If the `src` register does not have a value, sets `dst` to `None`, clearing any previous
    /// value in it.
    pub fn mov(&mut self, dst: RegE, src: RegE) {
        match self.get(src) {
            Some(val) => {
                self.set(dst, val);
            }
            None => {
                self.clr(dst);
            }
        }
    }

    /// Checks the equivalence of values in `src1` and `src2`.
    ///
    /// If both registers do not have a value, returns [`Status::Fail`].
    pub fn eqv(&mut self, src1: RegE, src2: RegE) -> Status {
        let a = self.get(src1);
        let b = self.get(src2);
        if a == b && a.is_some() {
            Status::Ok
        } else {
            Status::Fail
        }
    }

    /// Add a value from the `src` register to `dst_src` value, storing the result back in
    /// `dst_src`.
    ///
    /// Overflow is handled according to finite field arithmetics, by doing a modulo-division. The
    /// fact of the overflow cannot be determined in order to keep the implementation compatible
    /// with zk-STARK and zk-SNARK circuits and arithmetizations.
    ///
    /// # Returns
    ///
    /// If any of `src` or `dst_src` registers do not have a value, returns [`Status::Fail`].
    /// Otherwise, returns success.
    #[inline]
    pub fn add_mod(&mut self, dst_src: RegE, src: RegE) -> Status {
        let order = self.fq();

        let Some(a) = self.get(dst_src) else {
            return Status::Fail;
        };
        let Some(b) = self.get(src) else {
            return Status::Fail;
        };

        let a = a.to_u256();
        let b = b.to_u256();
        debug_assert!(a < order && b < order);

        let (mut res, overflow) = a.overflowing_add(b);
        if overflow {
            res += u256::MAX - order;
        }

        let res = res % order;
        self.set(dst_src, fe256::from(res));
        Status::Ok
    }

    /// Multiply a value from the `src` register to `dst_src` value, storing the result back in
    /// `dst_src`.
    ///
    /// Overflow is handled according to finite field arithmetics, by doing a modulo-division. The
    /// fact of the overflow cannot be determined in order to keep the implementation compatible
    /// with zk-STARK and zk-SNARK circuits and arithmetizations.
    ///
    /// # Returns
    ///
    /// If any of `src` or `dst_src` registers do not have a value, returns [`Status::Fail`].
    /// Otherwise, returns success.
    #[inline]
    pub fn mul_mod(&mut self, dst_src: RegE, src: RegE) -> Status {
        let order = self.fq();

        let Some(a) = self.get(dst_src) else {
            return Status::Fail;
        };
        let Some(b) = self.get(src) else {
            return Status::Fail;
        };

        let a = a.to_u256();
        let b = b.to_u256();
        debug_assert!(a < order && b < order);

        let (res, _) = mul_mod_int(order, a, b);

        let res = res % order;
        self.set(dst_src, fe256::from(res));
        Status::Ok
    }

    /// Negate a value in the `dst_src` register by subtracting it from the field order, stored in
    /// `FQ` register.
    ///
    /// # Returns
    ///
    /// If the `dst_src` register does not have a value, returns [`Status::Fail`].
    /// Otherwise, returns success.
    #[inline]
    pub fn neg_mod(&mut self, dst_src: RegE, src: RegE) -> Status {
        let order = self.fq();

        let Some(a) = self.get(src) else {
            return Status::Fail;
        };

        debug_assert!(a.to_u256() < order);

        let res = order - a.to_u256();
        self.set(dst_src, fe256::from(res));
        Status::Ok
    }
}

fn mul_mod_int(order: u256, a: u256, b: u256) -> (u256, bool) {
    let a = u512::from(a);
    let b = u512::from(b);
    let c = a * b;
    let o = u512::from(order);
    let res = u256::from_le_slice(&(c % o).to_le_bytes()[..32]).expect("");
    (res, c >= o)
}
