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

#![deny(
    unsafe_code,
    dead_code,
    // missing_docs,
    unused_variables,
    unused_mut,
    unused_imports,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
#![allow(clippy::bool_assert_comparison)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

mod core;
#[macro_use]
pub mod gfa;
#[cfg(feature = "stl")]
pub mod zkstl;
mod fe;

pub use aluvm as alu;
pub use aluvm::isa;
pub use fe::{fe256, ParseFeError};

pub use self::core::{GfaConfig, GfaCore, RegE, FIELD_ORDER_25519, FIELD_ORDER_SECP, FIELD_ORDER_STARK};

pub const LIB_NAME_FINITE_FIELD: &str = "FiniteField";
