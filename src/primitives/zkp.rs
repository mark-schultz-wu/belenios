//! Zero-knowledge Proofs needed for Belenios.
//! These are detailed in the [Zero-knowledge Proofs Document](https://hal.inria.fr/hal-01576379/document).
//!
//! We model ZKPs via three structs:
//!   * Public parameters, which in most cases is simply a RNG,
//!   * an Instance of a statement to prove, and
//!   * a Witness to the statement.
//! We implement our ZKPs through the Sigma Protocols described in the linked document.
//! These are then generically transformed to NIZKs using the Fiat Shamir transform.
//! We ensure our NIZKs use domain-separated hashes.
//!
//! Note that our Sigma protocols aren't *really* Sigma protocols, as their `challenge` is not
//! random --- we `hard code` the Fiat Shamir transform at this step.
//! While this is technically a little incorrect, it doesn't impact the final NIZKs, and greatly
//! simplifies the transformation from SigmaProtocol -> NIZKs, as we do not need to describe how
//!   * Generically serialize the prior transcript for hashing with the FS transform, and
//!   * generically produce a challenge from this hash.

use array_init::array_init;
use std::convert::{TryFrom, TryInto};
use std::ops::{Add, AddAssign, Mul};
use std::sync::{Arc, Mutex};

use ring::rand::SecureRandom;

use crate::primitives::group::{Point, Scalar};
use crate::primitives::pki::Ciphertext;

#[derive(Debug, Clone)]
pub struct Proof {
    pub(crate) challenge: Scalar,
    pub(crate) response: Scalar,
}

impl From<(Scalar, Scalar)> for Proof {
    fn from(pair: (Scalar, Scalar)) -> Self {
        Self {
            challenge: pair.0,
            response: pair.1,
        }
    }
}

impl Into<(Scalar, Scalar)> for Proof {
    fn into(self) -> (Scalar, Scalar) {
        (self.challenge, self.response)
    }
}

pub trait ProofSystem {
    type Witness;
    type Proof;
    type Transcript;
    const DOMAIN_SEP: &'static str;
    fn hash(trans: Self::Transcript) -> Scalar;
    fn prove(&self, w: &Self::Witness) -> Self::Proof;
    // A domain-separated hash
    fn verify(&self, p: &Self::Proof) -> bool;
}

/// For proving knowledge of a point x such that
/// x = dlog(pt)
pub(crate) struct DLog {
    pub(crate) pt: Point,
    pub(crate) rng: Arc<Mutex<dyn SecureRandom>>,
}

impl ProofSystem for DLog {
    type Witness = Scalar;
    type Proof = Proof;
    type Transcript = Ciphertext;
    const DOMAIN_SEP: &'static str = "pok";
    fn hash(trans: Self::Transcript) -> Scalar {
        let data = [
            Self::DOMAIN_SEP.as_bytes(),
            &trans.alpha.as_bytes(),
            &trans.beta.as_bytes(),
        ]
        .concat();
        Scalar::hash_to_scalar(&data)
    }
    fn prove(&self, wit: &Self::Witness) -> Self::Proof {
        let w = Scalar::sample_uniform(self.rng.clone());
        let A = w * Point::generator();
        let challenge = Self::hash((self.pt.clone(), A).into());
        let response = (w - wit * challenge).into();
        Proof {
            challenge,
            response,
        }
    }
    fn verify(&self, p: &Self::Proof) -> bool {
        let A = (p.response * Point::generator()) + (p.challenge * self.pt);
        p.challenge == Self::hash((self.pt.clone(), A).into())
    }
}

/// Proof of Section 4.11.
pub(crate) struct IntervalMembership {
    pub(crate) ctxt: Ciphertext,
    // y is election public key, see section 4.10.1
    pub(crate) y: Point,
    pub(crate) rng: Arc<Mutex<dyn SecureRandom>>,
    pub(crate) finite_set: Vec<Scalar>,
    // Not strictly needed for the proof, but prepended to hash calls.
    pub(crate) S: Vec<u8>,
}

pub(crate) struct IntervalMembershipWitness {
    pub(crate) r: Scalar,
    pub(crate) i: usize,
}

impl ProofSystem for IntervalMembership {
    type Witness = IntervalMembershipWitness;
    type Proof = Vec<Proof>;
    // Transcript is S, (alpha, beta), along with (A0, B0),..., (Ak-1, Bk-1).
    type Transcript = (Vec<u8>, Ciphertext, Vec<Ciphertext>);
    const DOMAIN_SEP: &'static str = "prove";
    fn hash(trans: Self::Transcript) -> Scalar {
        let (s, ctxt, rest) = trans;
        let first_data = [
            Self::DOMAIN_SEP.as_bytes(),
            &s,
            &ctxt.alpha.as_bytes(),
            &ctxt.beta.as_bytes(),
        ]
        .concat();
        let second_data: Vec<u8> = rest
            .into_iter()
            .map(|c| c.into())
            .map(|(a, b)| [a.as_bytes(), b.as_bytes()].concat())
            .flatten()
            .collect();
        let data = [&first_data[..], &second_data[..]].concat();
        Scalar::hash_to_scalar(&data)
    }
    fn prove(&self, wit: &Self::Witness) -> Self::Proof {
        let mut proof: Vec<Proof> = Vec::new();
        let mut ctxts = Vec::new();
        for j in 0..self.finite_set.len() {
            let challenge = Scalar::sample_uniform(self.rng.clone());
            let response = Scalar::sample_uniform(self.rng.clone());
            proof.push((challenge, response).into());
            let (alpha, beta) = self.ctxt.into();
            let A_j = (response * Point::generator()) + (challenge * alpha);
            let B_j = (response * self.y)
                + (beta + (Point::generator() * -self.finite_set[j])) * challenge;
            ctxts.push((A_j, B_j).into());
        }
        // Fixing the case of j = wit.i
        let w = Scalar::sample_uniform(self.rng.clone());
        let A_i = Point::generator() * w;
        let B_i = self.y * w;
        ctxts[wit.i] = (A_i, B_i).into();
        let trans = (self.S.clone(), self.ctxt, ctxts);
        let mut challenge_i = Self::hash(trans);
        for j in 0..self.finite_set.len() {
            if j != wit.i {
                challenge_i = challenge_i - proof[j].challenge;
            }
        }
        let response_i = w - wit.r * challenge_i;
        proof[wit.i] = (challenge_i, response_i).into();
        proof
    }
    fn verify(&self, p: &Self::Proof) -> bool {
        let mut ctxts: Vec<Ciphertext> = Vec::new();
        let mut chal_sum = Scalar::zero();
        for j in 0..self.finite_set.len() {
            let (challenge, response) = (p[j].challenge, p[j].response);
            let (alpha, beta) = self.ctxt.into();
            let A_j = (response * Point::generator()) + (challenge * alpha);
            let B_j = (response * self.y)
                + (beta + (Point::generator() * -self.finite_set[j])) * challenge;
            ctxts.push((A_j, B_j).into());
            chal_sum = chal_sum + challenge;
        }
        let trans = (self.S.clone(), self.ctxt, ctxts);
        Self::hash(trans) == chal_sum
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ring::rand::SystemRandom;

    use super::*;
    const TRIALS: usize = 100;

    #[test]
    fn dlog_completeness() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        for _ in 0..TRIALS {
            let w = Scalar::sample_uniform(rng.clone());
            let pt = Point::generator() * w;
            let instance = DLog {
                pt,
                rng: rng.clone(),
            };
            let proof = instance.prove(&w);
            assert!(instance.verify(&proof));
        }
    }
    #[test]
    fn dlog_soundness() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        for _ in 0..TRIALS {
            let w = Scalar::sample_uniform(rng.clone());
            let pt = Point::generator() * w;
            let w = Scalar::sample_uniform(rng.clone());
            let instance = DLog {
                pt,
                rng: rng.clone(),
            };
            let proof = instance.prove(&w);
            assert!(!instance.verify(&proof));
        }
    }
    #[test]
    fn interval_completeness() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        const N: usize = 2;
        let finite_set = vec![Scalar::zero(), Scalar::one()];
        let S: Vec<u8> = String::from_str("words").unwrap().into();
        for _ in 0..TRIALS {
            let y = Point::sample_uniform(rng.clone());
            for i in 0..N {
                let M = finite_set[i];
                let r = Scalar::sample_uniform(rng.clone());
                let alpha = Point::generator() * r;
                let beta: Point = y * r + Point::generator() * M;
                let ctxt = (alpha, beta).into();
                let instance = IntervalMembership {
                    ctxt,
                    y,
                    rng: rng.clone(),
                    finite_set: finite_set.clone(),
                    S: S.clone(),
                };
                let w = IntervalMembershipWitness { r, i };
                let proof = instance.prove(&w);
                assert!(instance.verify(&proof));
            }
        }
    }
    #[test]
    fn interval_soundness() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        const N: usize = 2;
        let finite_set = vec![Scalar::zero(), Scalar::one()];
        let S: Vec<u8> = String::from_str("words").unwrap().into();
        for _ in 0..TRIALS {
            let y = Point::sample_uniform(rng.clone());
            for i in 0..N {
                let M = finite_set[i];
                let r = Scalar::sample_uniform(rng.clone());
                let alpha = Point::generator() * r;
                let beta: Point = y * r + Point::generator() * M;
                let ctxt = (alpha, beta).into();
                let instance = IntervalMembership {
                    ctxt,
                    y,
                    rng: rng.clone(),
                    finite_set: finite_set.clone(),
                    S: S.clone(),
                };
                let r = Scalar::sample_uniform(rng.clone());
                let w = IntervalMembershipWitness { r, i };
                let proof = instance.prove(&w);
                assert!(!instance.verify(&proof));
            }
        }
    }
}
