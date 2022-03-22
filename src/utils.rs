use crate::primitives::curve::{Point, Scalar};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar;
use ring::digest::{digest, SHA256, SHA256_OUTPUT_LEN};
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

/// Generates a uniformly random usize x in the range lower <= x < upper.
/// Currently both:
///   * somewhat wasteful, uses a full u128 of randomness even to sample uniformly from [0,...15], and
///   * may introduce a (tiny) bias.
/// Could fix both later via a rejection sampling argument, seems like a premature optimization.
fn rand_range(lower: usize, upper: usize, rng: Arc<Mutex<dyn SecureRandom>>) -> usize {
    assert!(lower <= upper);
    let mut rand_buff = [0 as u8; (usize::BITS / 8) as usize];
    // Reducing the problem to generating a uniformly random variable in [0, ..., range_size).
    let range_size = upper - lower + 1 as usize;
    rng.lock()
        .unwrap()
        .fill(&mut rand_buff)
        .expect("RNG call failed.");
    let rand_usize = usize::from_le_bytes(rand_buff);
    lower + (rand_usize % range_size)
}

/// Applies a uniform permutation to a `Vec<T>` in-place, using
/// the `GenPermutation` algorithm of Table 2 of the specification
/// (which is simply the [Fisher-Yates Shuffle](https://en.wikipedia.org/wiki/Random_permutation#Fisher-Yates_shuffles)).
///
/// Note that, to support `non-homomorphic questions` would require a zero-knowledge proof that a
/// shuffle occurred. No ZK proof is needed if only handling homomorphic questions, see section 2.3
/// of the [Benelios Paper](https://hal.inria.fr/hal-02066930/document).
pub fn uniformly_permute<T>(inp: &mut [T], rng: Arc<Mutex<dyn SecureRandom>>) {
    let n = inp.len();
    for i in 0..n - 1 {
        let j = rand_range(i, n, rng.clone());
        inp.swap(i, j);
    }
}

/// Hashes a &[u8] to a `Scalar`. Note that `Scalar` has an impl of a similar function,
/// but the documentation seems to be out of data/the example listed did not work.
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = digest(&SHA256, data);
    let mut collected_hash = [0; SHA256_OUTPUT_LEN];
    for idx in 0..SHA256_OUTPUT_LEN {
        collected_hash[idx] = hash.as_ref()[idx];
    }
    Scalar(scalar::Scalar::from_bytes_mod_order(collected_hash))
}

pub fn random_scalar(rng: Arc<Mutex<dyn SecureRandom>>) -> Scalar {
    let mut buff = [0 as u8; 32];
    rng.lock().unwrap().fill(&mut buff).unwrap();
    Scalar(scalar::Scalar::from_bytes_mod_order(buff))
}

/// Samples a uniformly random group element.
pub fn random_point(rng: Arc<Mutex<dyn SecureRandom>>) -> Point {
    let mut buff = [0 as u8; 64];
    rng.lock().unwrap().fill(&mut buff).unwrap();
    Point(RistrettoPoint::from_uniform_bytes(&buff))
}
