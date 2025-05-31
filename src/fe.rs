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

use core::str::FromStr;

use amplify::confinement::TinyBlob;
use amplify::hex::FromHex;
use amplify::num::u256;
use amplify::{hex, Bytes32, Wrapper};
use strict_encoding::{StrictDecode, StrictProduct, StrictTuple, StrictType, TypeName};

use crate::LIB_NAME_FINITE_FIELD;

/// Element of a Galois finite field.
///
/// Maximum size is 256 bits.
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, From)]
#[display("{0:X}.fe", alt = "{0:064X}.fe")]
#[derive(StrictDumb, StrictEncode, StrictDecode)]
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
    /// Zero element of the field.
    pub const ZERO: Self = Self(u256::ZERO);

    /// Construct a field element from a 256-bit unsigned integer value.
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
    fn from(val: u256) -> Self { Self(val) }
}

impl StrictType for fe256 {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_FINITE_FIELD;
    fn strict_name() -> Option<TypeName> { Some(tn!("Fe256")) }
}
impl StrictProduct for fe256 {}
impl StrictTuple for fe256 {
    const FIELD_COUNT: u8 = 1;
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
                Ok(Self(val))
            }
        }
    }
}

/// Errors parsing field elements.
#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
pub enum ParseFeError {
    /// Missed `.fe` suffix.
    #[display("field element `{0}` must have a `.fe` suffix.")]
    NoSuffix(String),

    /// Invalid hex value.
    #[from]
    #[display(inner)]
    Value(hex::Error),
}

impl FromStr for fe256 {
    type Err = ParseFeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .strip_suffix(".fe")
            .ok_or_else(|| ParseFeError::NoSuffix(s.to_owned()))?;
        let bytes = if s.len() % 2 == 1 { TinyBlob::from_hex(&format!("0{s}"))? } else { TinyBlob::from_hex(s)? };
        const BUF_SIZE: usize = 32;
        let mut buf = [0u8; BUF_SIZE];
        if bytes.len() > BUF_SIZE {
            return Err(hex::Error::InvalidLength(BUF_SIZE, bytes.len()).into());
        }
        buf[(BUF_SIZE - bytes.len())..].copy_from_slice(bytes.as_slice());
        let val = u256::from_be_bytes(buf);
        Ok(Self(val))
    }
}

#[cfg(test)]
mod tests {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use amplify::confinement::Confined;
    use strict_encoding::{StrictDeserialize, StrictDumb, StrictSerialize};

    use super::*;

    #[test]
    fn display_from_str() {
        let s = "0000000000000000000000000000000000000000000000000000000000000000.fe";
        let fe = fe256::from_str(s).unwrap();
        assert_eq!(fe, fe256::ZERO);
        assert_eq!(format!("{}", fe), "0.fe");
        assert_eq!(format!("{:#}", fe), s);
        assert_eq!(format!("{:?}", fe), "fe256(0x0000000000000000000000000000000000000000000000000000000000000000)");

        let s = "A489C5940DEDEADBEEFBADCAFEFEEDDEEDABCDEF012345678047345495749857.fe";
        let fe = fe256::from_str(s).unwrap();
        assert_eq!(format!("{}", fe), s);
        assert_eq!(format!("{:#}", fe), s);
        assert_eq!(format!("{:?}", fe), "fe256(0xa489c5940dedeadbeefbadcafefeeddeedabcdef012345678047345495749857)");

        let s = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.fe";
        let fe = fe256::from_str(s).unwrap();
        assert_eq!(fe, fe256::from(u256::MAX));
        assert_eq!(format!("{}", fe), s);
        assert_eq!(format!("{:#}", fe), s);
        assert_eq!(format!("{:?}", fe), "fe256(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)");

        let s = "0000000000000000000000000000000000000000000000000000000000000345.fe";
        let fe = fe256::from_str(s).unwrap();
        assert_eq!(format!("{}", fe), "345.fe");
        assert_eq!(format!("{:#}", fe), s);
        assert_eq!(format!("{:?}", fe), "fe256(0x0000000000000000000000000000000000000000000000000000000000000345)");

        let s = "1230000000000000000000000000000000000000000000000000000000000000.fe";
        let fe = fe256::from_str(s).unwrap();
        assert_eq!(format!("{}", fe), "1230000000000000000000000000000000000000000000000000000000000000.fe");
        assert_eq!(format!("{:#}", fe), s);
        assert_eq!(format!("{:?}", fe), "fe256(0x1230000000000000000000000000000000000000000000000000000000000000)");
    }

    #[test]
    #[should_panic(expected = r#"NoSuffix("0000000000000000000000000000000000000000000000000000000000000000")"#)]
    fn from_str_no_suffix() {
        let s = "0000000000000000000000000000000000000000000000000000000000000000";
        fe256::from_str(s).unwrap();
    }

    #[test]
    #[should_panic(expected = "Value(InvalidLength(32, 33))")]
    fn from_str_invalid_len() {
        let s = "AA0000000000000000000000000000000000000000000000000000000000000000.fe";
        fe256::from_str(s).unwrap();
    }

    #[test]
    fn serde() {
        use serde_test::{assert_tokens, Configure, Token};

        let s = "A489C5940DEDEADBEEFBADCAFEFEEDDEEDABCDEF012345678047345495749857.fe";
        let val = fe256::from_str(s).unwrap();
        let dat = [
            // Bincode length prefix
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // The actual value
            0xA4, 0x89, 0xC5, 0x94, 0x0D, 0xED, 0xEA, 0xDB, 0xEE, 0xFB, 0xAD, 0xCA, 0xFE, 0xFE, 0xED, 0xDE, 0xED, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x80, 0x47, 0x34, 0x54, 0x95, 0x74, 0x98, 0x57,
        ];
        assert_eq!(bincode::serialize(&val).unwrap(), dat);
        assert_eq!(bincode::deserialize::<fe256>(&dat).unwrap(), val);
        assert_eq!(bincode::serialize(&val).unwrap(), bincode::serialize(&val.0).unwrap());
        assert_tokens(&val.readable(), &[Token::Str(s)]);
    }

    #[test]
    fn from_bytes() {
        let mut bytes = [
            0xA4, 0x89, 0xC5, 0x94, 0x0D, 0xED, 0xEA, 0xDB, 0xEE, 0xFB, 0xAD, 0xCA, 0xFE, 0xFE, 0xED, 0xDE, 0xED, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x80, 0x47, 0x34, 0x54, 0x95, 0x74, 0x98, 0x57,
        ];
        // We use little-endian!
        bytes.reverse();
        let fe1 = fe256::from(bytes);
        let fe2 = fe256::from(Bytes32::from_byte_array(bytes));
        assert_eq!(fe1, fe2);
        assert_eq!(fe1.to_string(), "A489C5940DEDEADBEEFBADCAFEFEEDDEEDABCDEF012345678047345495749857.fe");
    }

    #[test]
    fn strict_encoding() {
        #![allow(non_local_definitions)]

        assert_eq!(fe256::strict_dumb(), fe256::ZERO);

        impl StrictSerialize for fe256 {}
        impl StrictDeserialize for fe256 {}

        let bytes = [
            0xA4, 0x89, 0xC5, 0x94, 0x0D, 0xED, 0xEA, 0xDB, 0xEE, 0xFB, 0xAD, 0xCA, 0xFE, 0xFE, 0xED, 0xDE, 0xED, 0xAB,
            0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x80, 0x47, 0x34, 0x54, 0x95, 0x74, 0x98, 0x57,
        ];
        let mut rev = bytes;
        // We use little-endian!
        rev.reverse();
        let fe = fe256::from(rev);
        assert_eq!(fe.to_strict_serialized::<32>().unwrap().as_slice(), rev.as_slice());
        assert_eq!(fe, fe256::from_strict_serialized::<32>(Confined::from_iter_checked(rev)).unwrap());
        assert_eq!(fe.to_string(), "A489C5940DEDEADBEEFBADCAFEFEEDDEEDABCDEF012345678047345495749857.fe");
    }
}
