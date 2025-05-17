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
//! Strict types library generator methods.

use strict_types::typelib::{CompileError, LibBuilder};
use strict_types::TypeLib;

use crate::{fe256, LIB_NAME_FINITE_FIELD};

/// Strict type id for the lib-old providing data types from this crate.
pub const LIB_ID_FINITE_FIELD: &str = "stl:Nm0yhN4V-rj3RTrE-tXIS14e-JV1OFTx-zPNhRZU-54QW0tg#report-canal-convert";

#[allow(clippy::result_large_err)]
fn _finite_field_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(LIB_NAME_FINITE_FIELD, [strict_types::stl::std_stl().to_dependency_types()])
        .transpile::<fe256>()
        .compile()
}

/// Generates strict type lib-old providing data types from this crate.
pub fn finite_field_stl() -> TypeLib { _finite_field_stl().expect("invalid strict type AluVM lib-old") }

#[cfg(test)]
mod test {
    #![cfg_attr(coverage_nightly, coverage(off))]
    use super::*;

    #[test]
    fn lib_id() {
        let lib = finite_field_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_FINITE_FIELD);
    }
}
