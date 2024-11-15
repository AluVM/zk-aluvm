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

#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    // missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod core;
pub mod gfa;
#[cfg(feature = "stl")]
pub mod zkstl;

pub use aluvm::*;
use strict_encoding::{StrictProduct, StrictTuple, StrictType, TypeName};

pub use self::core::{GfaCore, RegE};

pub const LIB_NAME_FINITE_FIELD: &str = "FiniteField";

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display)]
#[display("{0:X}")]
#[derive(StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_FINITE_FIELD)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct fe128(pub u128);

impl StrictType for fe128 {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_FINITE_FIELD;
    fn strict_name() -> Option<TypeName> { Some(tn!("Fe128")) }
}
impl StrictProduct for fe128 {}
impl StrictTuple for fe128 {
    const FIELD_COUNT: u8 = 1;
}
