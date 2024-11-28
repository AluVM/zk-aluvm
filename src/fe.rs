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

use core::str::FromStr;

use amplify::confinement::TinyBlob;
use amplify::hex::FromHex;
use amplify::num::u256;
use amplify::{hex, Bytes32, Wrapper};
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictProduct, StrictTuple, StrictType, TypeName, TypedRead,
};

use crate::LIB_NAME_FINITE_FIELD;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, From)]
#[display("{0:X}.fe")]
#[derive(StrictDumb, StrictEncode)]
#[strict_type(lib = LIB_NAME_FINITE_FIELD)]
pub struct fe256(
    #[from(u8)]
    #[from(u16)]
    #[from(u32)]
    #[from(u64)]
    #[from(u128)]
    u256,
);

impl fe256 {
    #[must_use]
    fn test_value(val: u256) -> bool { val.into_inner()[3] & 0xF800_0000_0000_0000 == 0 }

    pub const fn to_u256(&self) -> u256 { self.0 }
}

impl From<Bytes32> for fe256 {
    fn from(bytes: Bytes32) -> Self { Self::from(bytes.into_inner()) }
}

impl From<[u8; 32]> for fe256 {
    fn from(bytes: [u8; 32]) -> Self {
        let val = u256::from_le_bytes(bytes);
        Self::from(val)
    }
}

impl From<u256> for fe256 {
    fn from(val: u256) -> Self {
        // We make sure we are well below any commonly used field order
        assert!(
            Self::test_value(val),
            "the provided value for 256-bit field element is in a risk zone above order of some commonly used 256-bit \
             finite fields. The probability of this event for randomly-generated values (including the ones coming \
             from hashes) is astronomically low, thus, an untrusted input is used in an unfiltered way. Adjust your \
             code and do not use externally-provided values without checking them first."
        );
        Self(val)
    }
}

impl StrictType for fe256 {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_FINITE_FIELD;
    fn strict_name() -> Option<TypeName> { Some(tn!("Fe256")) }
}
impl StrictProduct for fe256 {}
impl StrictTuple for fe256 {
    const FIELD_COUNT: u8 = 1;
}
impl StrictDecode for fe256 {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let val = r.read_field::<u256>()?;
            if !Self::test_value(val) {
                return Err(DecodeError::DataIntegrityError(format!(
                    "the provided value {val:#X} for a field element is above the order of some of the finite fields \
                     and is disallowed"
                )));
            }
            Ok(Self(val))
        })
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde::de::{Error, Unexpected};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for fe256 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                self.to_string().serialize(serializer)
            } else {
                self.0.serialize(serializer)
            }
        }
    }

    impl<'de> Deserialize<'de> for fe256 {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(|e| D::Error::invalid_value(Unexpected::Str(&s), &e.to_string().as_str()))
            } else {
                let val = u256::deserialize(deserializer)?;
                if !Self::test_value(val) {
                    return Err(D::Error::invalid_value(
                        Unexpected::Bytes(&val.to_le_bytes()),
                        &"the value for a field element is above the order of some of the finite fields and is \
                          disallowed",
                    ));
                }
                Ok(Self(val))
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum ParseFeError {
    /// field element `{0}` must have a `.fe` suffix.
    NoSuffix(String),

    #[from]
    #[display(inner)]
    Value(hex::Error),

    /// value {0:#x} overflows safe range for field element values.
    Overflow(u256),
}

impl FromStr for fe256 {
    type Err = ParseFeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_suffix(".fe")
            .ok_or_else(|| ParseFeError::NoSuffix(s.to_owned()))?;
        let bytes = if s.len() % 2 == 1 { TinyBlob::from_hex(&format!("0{s}"))? } else { TinyBlob::from_hex(s)? };
        let mut buf = [0u8; 32];
        if bytes.len() > 32 {
            return Err(hex::Error::InvalidLength(32, bytes.len()).into());
        }
        buf[..bytes.len()].copy_from_slice(bytes.as_slice());
        let val = u256::from_le_bytes(buf);
        if !Self::test_value(val) {
            return Err(ParseFeError::Overflow(val));
        }
        Ok(Self(val))
    }
}
