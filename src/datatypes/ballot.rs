//! The Ballot Datatype

use crate::{
    datatypes::credentials::{Credential, ExpandedCredential, Password, UUID},
    datatypes::election::Election,
    datatypes::questions::Question,
    primitives::group::{Point, Scalar},
    primitives::pki::{Ciphertext, EncryptionKey, EncryptionKeys},
    primitives::zkp::{IntervalMembership, IntervalMembershipWitness, Proof, ProofSystem},
};
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

#[derive(Builder, Clone, Debug)]
pub struct Ballot {
    pub(crate) election_uuid: UUID,
    pub(crate) election_hash: Vec<u8>,
    pub(crate) credential: Point,
    pub(crate) answers: Vec<Answer>,
}

impl Ballot {
    pub fn verify(
        &self,
        rng: Arc<Mutex<dyn SecureRandom>>,
        pub_key: &Point,
        questions: &[Question],
    ) -> bool {
        for i in 0..self.answers.len() {
            if self.answers[i].verify(
                rng.clone(),
                &self.election_hash,
                self.credential,
                pub_key,
                &questions[i],
            ) != true
            {
                return false;
            }
        }
        true
    }
}

// Base `type` of an interval proof is a `Vec<Proof>`.
// We have one individual proof per choice, so `Vec<Vec<Proof>>`.
// We also have one proof of the sum being bounded, so `Vec<Proof>`.
//
// Note that these are comperable sizes, as the length of the vec = length of the interval.
#[derive(Clone, Debug, Builder)]
pub struct Answer {
    choices: Vec<Ciphertext>,
    // Coincidence that these are both Vec<Proofs>
    individual_proofs: Vec<Vec<Proof>>,
    overall_proof: Vec<Proof>,
    // Not implementing blank_proofs at this point
    blank_proof: Option<()>,
}

impl Answer {
    // Verifies a single Answer, to ease testing.
    // RNG not used in verification, but I need to pass one in due to API design choices in the
    // ZKPs.
    pub(crate) fn verify(
        &self,
        rng: Arc<Mutex<dyn SecureRandom>>,
        election_hash: &[u8],
        cred: Point,
        pub_key: &Point,
        question: &Question,
    ) -> bool {
        // also need a Credential
        // and an Election Hash
        let choices = &self.choices;
        let ind_proofs = &self.individual_proofs;
        if choices.len() != ind_proofs.len() {
            return false;
        }
        let overall_proof = &self.overall_proof;
        // Publicly computing S0
        let mut S0: Vec<u8> = election_hash.clone().into();
        S0.extend(cred.as_bytes());
        // verify the individual proofs.
        for i in 0..choices.len() {
            let finite_set = vec![Scalar::zero(), Scalar::one()];
            let ctxt = choices[i].clone();
            let y = pub_key.clone();
            let pf = ind_proofs[i].clone();
            let rng = rng.clone();
            let instance = IntervalMembership {
                ctxt,
                y,
                rng,
                finite_set,
                S: S0.clone(),
            };
            if instance.verify(&pf) == false {
                return false;
            }
        }
        // verify the overall proof
        // Need (summed) ctxt, finite set, and S.
        let mut alpha_sum = Point::identity();
        let mut beta_sum = Point::identity();
        let mut finite_set = Vec::new();
        for i in question.min..=question.max {
            finite_set.push(Scalar::from(i));
        }
        for i in 0..choices.len() {
            let (alpha, beta) = choices[i].into();
            alpha_sum = alpha_sum + alpha;
            beta_sum = beta_sum + beta;
        }
        let serialized = bincode::serialize(&choices).unwrap();
        let S = [S0.clone(), serialized].concat();
        let ctxt: Ciphertext = (alpha_sum, beta_sum).into();
        let instance = IntervalMembership {
            ctxt,
            y: pub_key.clone(),
            rng: rng.clone(),
            finite_set,
            S,
        };
        instance.verify(&overall_proof)
    }
}

#[derive(Builder)]
pub(crate) struct StateNeededForAnswer {
    choices: Vec<bool>,
    question: Question,
    election: Election,
    pass: Password,
    rng: Arc<Mutex<dyn SecureRandom>>,
}

pub(crate) fn gen_S0(election_hash: &[u8], cred: Point) -> Vec<u8> {
    let S0: Vec<u8> = [election_hash, &cred.as_bytes()].concat();
    S0
}

impl From<StateNeededForAnswer> for Answer {
    fn from(state: StateNeededForAnswer) -> Self {
        let rng = state.rng.clone();
        let ms = state.choices.clone();
        let question = state.question.clone();
        let uuid = state.election.uuid.clone();
        let cred: Credential = (state.pass.clone(), uuid).into();
        let expanded_cred: ExpandedCredential = cred.into();
        let pub_key = expanded_cred.public_key;
        // Generating encryptions + randomness
        let mut ctxts: Vec<Ciphertext> = Vec::new();
        let mut rs: Vec<Scalar> = Vec::new();
        let mut individual_pfs = Vec::new();
        for i in 0..ms.len() {
            let pk: EncryptionKey = state.election.public_key.into();
            let (ctxt, r) = pk.enc_leak_randomness(rng.clone(), Scalar::from(ms[i] as u128));
            ctxts.push(ctxt);
            rs.push(r);
        }
        // Getting ready the items we need for proofs
        let election_hash = state.election.fingerprint();
        let S0 = gen_S0(&election_hash, pub_key);
        let serialized = bincode::serialize(&ctxts).unwrap();
        let S = [S0.clone(), serialized].concat();
        let y = state.election.public_key.clone();
        let finite_set = vec![Scalar::zero(), Scalar::one()];

        // Genrating proofs for each encryption
        for i in 0..ms.len() {
            let rng = rng.clone();
            let ctxt = ctxts[i];
            let r = rs[i];
            let instance = IntervalMembership {
                ctxt,
                y,
                rng,
                finite_set: finite_set.clone(),
                S: S0.clone(),
            };
            let w = IntervalMembershipWitness {
                r,
                i: (ms[i] as usize),
            };
            let pf = instance.prove(&w);
            individual_pfs.push(pf);
        }
        // Generating the overall proof that the sum of the ciphertexts is in in [min..max]
        let mut R: Scalar = Scalar::zero();
        let mut M: Scalar = Scalar::zero();
        let mut idx: u128 = 0;
        let mut alpha_sum = Point::identity();
        let mut beta_sum = Point::identity();
        for i in 0..ms.len() {
            R = R + rs[i];
            idx += ms[i] as u128;
            M = M + Scalar::from(ms[i] as u128);
            let (alpha, beta) = ctxts[i].into();
            alpha_sum = alpha_sum + alpha;
            beta_sum = beta_sum + beta;
        }
        let mut finite_set = Vec::new();
        for i in question.min..=question.max {
            let M = Scalar::from(i);
            finite_set.push(M);
        }
        let ctxt = (alpha_sum, beta_sum).into();
        let instance = IntervalMembership {
            ctxt,
            y,
            rng: rng.clone(),
            finite_set,
            S,
        };
        let w = IntervalMembershipWitness {
            r: R,
            i: (idx - question.min) as usize,
        };
        let overall_proof = instance.prove(&w);
        AnswerBuilder::default()
            .choices(ctxts)
            .individual_proofs(individual_pfs)
            .overall_proof(overall_proof)
            .blank_proof(None)
            .build()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;

    use super::*;

    #[test]
    fn test_if_answering_proofs_verify() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        let pass = Password::gen(rng.clone());
        // a sample election with a single question that has min = 0, max = 1, and 3 possible
        // answers.
        let election = crate::datatypes::election::tests::build_election();
        let questions = election.questions.clone();
        let uuid = election.uuid.clone();
        let cred: Credential = (pass.clone(), uuid).into();
        let choices = vec![false, true, false];
        let state = StateNeededForAnswerBuilder::default()
            .choices(choices)
            .question(questions[0].clone())
            .pass(pass.clone())
            .election(election.clone())
            .rng(rng.clone())
            .build()
            .unwrap();
        let answer: Answer = state.into();
        let expanded_cred: ExpandedCredential = cred.into();
        assert!(answer.verify(
            rng.clone(),
            &election.fingerprint(),
            expanded_cred.public_key,
            &election.public_key,
            &questions[0],
        ));
    }
}
