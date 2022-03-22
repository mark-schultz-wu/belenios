//! UUIDs

use bs58::Alphabet;
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

/// Base58 alphabet used for encoding/decoding, taken from [page 7 of the Belenios paper](https://www.belenios.org/specification.pdf#page=7).
const ALPHABET: &'static str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// One of the basic types of Belenios, which is supposed to uniquely define
/// an election.
/// The only requirement for it ([page 7 of the specification](https://www.belenios.org/specification.pdf#page=7)) is that it is a base58
/// string of size at least 14.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UUID(pub(crate) Vec<u8>);

impl Into<String> for UUID {
    fn into(self) -> String {
        bs58::encode(self.0).into_string()
    }
}

impl TryFrom<&String> for UUID {
    type Error = bs58::decode::Error;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        let res = bs58::decode(value).into_vec()?;
        Ok(UUID(res))
    }
}

impl From<u128> for UUID {
    /// For `deterministic` choices of election UUIDs.
    fn from(val: u128) -> Self {
        let mut remaining = val;
        let mut output = Vec::new();
        while remaining > 0 {
            output.push((remaining % 58) as u8);
            remaining /= 58;
        }
        UUID(output)
    }
}

impl UUID {
    /// a UUID from a random u128, shouldn't collide for << 2^64 elections
    pub(crate) fn gen(rng: Arc<Mutex<dyn SecureRandom>>) -> Self {
        let mut buf = [0; 16];
        let rng = rng.lock().unwrap();
        rng.fill(&mut buf).unwrap();
        let rand_num = u128::from_be_bytes(buf);
        UUID::from(rand_num)
    }
}

#[cfg(test)]
mod tests {
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
}
