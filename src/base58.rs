//! Belenios uses base58 in two places
//!   * defining UUIDs for each election, and
//!   * defining "credentials", which are later used to generate El Gamal keypairs.
//! This document defines both of these structs, and generally handles parsing base58.
use bs58::Alphabet;
use ring::rand::SecureRandom;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

/// The length of a `credential` measured in Base58 characters
const CREDENTIAL_LEN: usize = 15;

/// Base58 alphabet used for encoding/decoding, taken from [page 7 of the Belenios paper](https://www.belenios.org/specification.pdf#page=7).
/// Note that this alphabet is contained in `bs58`, but it is marked pub(crate), so we must do this.
const ALPHA_STR: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ALPHA: Alphabet = Alphabet::new_unwrap(ALPHA_STR);

/// One of the basic types of Belenios, which is supposed to uniquely define
/// an election.
/// The only requirement for it ([page 7 of the specification](https://www.belenios.org/specification.pdf#page=7)) is that it is a base58
/// string of size at least 14.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UUID(Vec<u8>);

impl Into<String> for UUID {
    fn into(self) -> String {
        bs58::encode(self.0).into_string()
    }
}

impl TryFrom<&String> for UUID {
    type Error = bs58::decode::Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        let res = bs58::decode(value).with_alphabet(&ALPHA).into_vec()?;
        Ok(UUID(res))
    }
}

/// A 15-character Base58 string where the first 14 characters are random, and
/// the last is a checksum (to detect typing errors).
///
/// These serve as entropy sources for PBKDF2.
/// Note that the specification claims they have 88 bits of entropy, but as the checksum is
/// deterministic it is closer to 82.
#[derive(Debug)]
struct Credential([u8; CREDENTIAL_LEN]);

impl Credential {
    /// Per [page 11 of the spec](https://www.belenios.org/specification.pdf#page=11),
    /// the checksum is computed by
    ///   1. interpreting the input base58 characters as a big-endian integer c, and
    ///   2. computing (53 - c) mod 53.
    fn checksum(nums: &[u8]) -> u8 {
        let mut sum: u128 = 0;
        let mut base = 1;
        for i in (0..(CREDENTIAL_LEN - 1)).rev() {
            sum += (nums[i] as u128) * base;
            base *= 58;
        }
        (u128::wrapping_sub(53, sum) % 53) as u8
    }
    /// Generates a new Credential pseudorandomly.
    /// The type signature of the rng is for compatibility with the `cryptid` library.
    fn gen(rng: Arc<Mutex<dyn SecureRandom>>) -> Self {
        // Sample random u128 (for simplicity)
        let mut buf = [0; 16];
        let rng = rng.lock().unwrap();
        rng.fill(&mut buf).unwrap();
        let mut rand_num = u128::from_be_bytes(buf);
        // Convert u128 into the first CREDENTIAL_LEN-1 elems of a credential
        let mut cred_buf = [0 as u8; CREDENTIAL_LEN];
        for idx in 0..CREDENTIAL_LEN - 1 {
            cred_buf[idx] = (rand_num % 58) as u8;
            rand_num /= 58;
        }
        // Computing the checksum
        cred_buf[CREDENTIAL_LEN - 1] = Credential::checksum(&cred_buf[..(CREDENTIAL_LEN - 1)]);
        Credential(cred_buf)
    }
}

#[cfg(test)]
mod tests {
    /// Impl **only** for testing, as
    ///   * not needed in the general lib, and
    ///   * want to control to/from impls for "secret" types.
    impl Into<String> for Credential {
        fn into(self) -> String {
            let mut res = String::new();
            for idx in 0..CREDENTIAL_LEN {
                res.push(ALPHA_STR[self.0[idx] as usize] as char);
            }
            res
        }
    }

    use super::*;
    #[test]
    fn test_base58_coding() {
        let input = String::from("aAbBcdE");
        let decoded: UUID = UUID::try_from(&input).unwrap();
        let res: String = decoded.into();
        assert_eq!(input, res);
    }
    #[test]
    #[should_panic]
    fn test_base58_panic() {
        let input = String::from("0o"); // ambiguous chars not in alphabet
        let _decoded: UUID = UUID::try_from(&input).unwrap();
    }
    #[test]
    fn test_credential_generation() {
        //! Credentials should be valid base58
        const RUNS: usize = 1000;
        let rng = Arc::new(Mutex::new(ring::rand::SystemRandom::new()));
        for _ in 0..RUNS {
            let new_rng = rng.clone();
            let cred = Credential::gen(new_rng);
            let string: String = Credential::into(cred);
            // is valid Base58 if we can convert it into a UUID.
            // Note: Don't do this in real code, Credentials are secret,
            // UUIDs are (assumed) public.
            let rand_uuid = UUID::try_from(&string).unwrap();
            let encoded_uuid: String = UUID::into(rand_uuid);
            assert_eq!(encoded_uuid, string);
        }
    }
}
