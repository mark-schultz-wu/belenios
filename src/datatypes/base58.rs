//! Base58 characters are used in two places within Belenios:
//! 1. UUIDs, which are public, and
//! 2. As "secrets", that various keys are derived from, namely
//!    * encryption/signing keys between trustees (section 4.5), and
//!    * encryption keys for voters (section 4.7).
//!
//! There are some mild differences between all situations corresponding to the
//! * length, and
//! * presence of a checksum "digit"
//! in each of the three contexts.
//!
//! The shorter lengths in certain contexts were likely chosen for better user experience.
//! In this implementation, we will ignore this, and have all Base58 strings be length 22, the
//! maximum used.
//!

use ring::rand::SecureRandom;
use std::fmt;
use std::sync::{Arc, Mutex};

/// The maximum length of a base58 string generated.
/// This is a little annoying, as 128 / log2(58) ~ 21.8, e.g. a uniformly random 22 character long
/// base58 string has ~128.8 bits of entropy. For simplicity, we will ignore this ~.8th of a bit of
/// entropy, and generate base58 characters from u128s.
const BASE58_BYTELEN: usize = 128 / 8;
pub(crate) const BASE58_STRLEN: usize = 22;

/// The base-58 alphabet used by Belenios, see section 4.7 of the specification.
const ALPHABET_STR: &'static [u8; 58] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A lookup table such that the ith element is equal to ith byte of ALPHABET_STR.
/// ```ignore
/// # let ALPHABET_STR = belenios::datatypes::base58::ALPHABET_STR;
/// # let LOOKUPTABLE = belenios::datatypes::base58::LOOKUPTABLE;
/// for idx in 0..58 {
///     assert_eq!(ALPHABET_STR[idx], LOOKUPTABLE[idx]);
/// }
/// ```
pub(crate) const LOOKUPTABLE: [u8; 58] = [
    49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71, 72, 74, 75, 76, 77, 78, 80, 81,
    82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 109,
    110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
];

/// A lookup table that "inverts" `LOOKUPTABLE`. This can in particular be used to convert between
/// the base58 representation of a string in terms of characters in ALPHABET_STR, and the corresponding
/// representation in terms of numbers {0, 1, ..., 57}, which are needed for computing the
/// `checksum`
/// ```ignore
/// # // doctest is ignored as one cannot write doctests on private elements of a module.
/// # let INV_LOOKUPTABLE = belenios::datatypes::base58::INV_LOOKUPTABLE;
/// # let LOOKUPTABLE = belenios::datatypes::base58::LOOKUPTABLE;
/// for idx in 0..58 {
///     assert_eq!(INV_LOOKUPTABLE[LOOKUPTABLE[idx] as usize], idx as u8);
/// }
/// ```
pub(crate) const INV_LOOKUPTABLE: [u8; 128] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 255, 255,
    255, 255, 255, 255, 255, 9, 10, 11, 12, 13, 14, 15, 16, 255, 17, 18, 19, 20, 21, 255, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31, 32, 255, 255, 255, 255, 255, 255, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 255, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 255, 255, 255,
    255, 255,
];

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Base58(pub(crate) String);

impl From<u128> for Base58 {
    /// Naively converts a u128 (viewed as a &[u8] in Big Endian representation) to a Base58
    /// string.
    /// Would be good to extend to arbitrary &[u8]s, but not needed for this implementation.
    /// ```ignore
    /// # use belenios::datatypes::base58::Base58;
    /// let s : String = String::from("1");
    /// let other = Base58(s);
    /// let bytearray = [0 as u8; 1];
    /// assert_eq!(Base58::from(&bytearray[..]), other);
    /// ```
    fn from(inp: u128) -> Self {
        let mut left = inp;
        let mut out = Vec::with_capacity(BASE58_STRLEN);
        for _ in 0..BASE58_STRLEN {
            out.push(LOOKUPTABLE[(left % 58) as usize] as char);
            left /= 58;
        }
        let out: String = out.into_iter().rev().collect::<String>();
        Base58(out)
    }
}

impl<'a> Into<&'a [u8]> for &'a Base58 {
    fn into(self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for Base58 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Base58 {
    /// Generates a Base58 (close to) uniformly randomly.
    /// It is only close to uniformly random as it as 128 bits of entropy,
    /// while there are ~2^128.8 base58 numbers of length 22.
    pub fn gen(rng: Arc<Mutex<dyn SecureRandom>>) -> Self {
        let mut buff = [0 as u8; 128 / 8];
        rng.lock().unwrap().fill(&mut buff).unwrap();
        Base58::from(u128::from_be_bytes(buff))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_conversion() {
        // Single character
        let mut v: Vec<u8> = vec![LOOKUPTABLE[0]; BASE58_STRLEN];
        for num in 0..58 {
            let converted_val: Base58 = (num as u128).into();
            v[BASE58_STRLEN - 1] = LOOKUPTABLE[num];
            let s = String::from_utf8(v.clone()).unwrap();
            let intended_val = Base58(s);
            assert_eq!(&converted_val, &intended_val);
        }
        // Two characters
        for low in 0..58 {
            for high in 0..58 {
                let converted_val: Base58 = (low + 58 * high).into();
                v[BASE58_STRLEN - 1] = LOOKUPTABLE[low as usize];
                v[BASE58_STRLEN - 2] = LOOKUPTABLE[high as usize];
                let s = String::from_utf8(v.clone()).unwrap();
                let intended_val = Base58(s);
                assert_eq!(&converted_val, &intended_val);
            }
        }
    }
}
