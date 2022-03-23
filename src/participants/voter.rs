//! The Voters

use crate::datatypes::ballot::{Answer, AnswerBuilder};
use crate::datatypes::credentials::Password;
use crate::datatypes::election::Election;
use crate::datatypes::questions::Question;
use crate::participants::messages::*;
use crate::participants::participant_template::*;
use crate::primitives::group::{Point, Scalar};
use crate::primitives::pki::{Ciphertext, EncryptionKeys};
use crate::primitives::zkp::{IntervalMembership, IntervalMembershipWitness, ProofSystem};
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

initialize_participant_impl!(Voter);

process_message_impl!(
    Voter,
    EmptyState,
    E5,
    E4Mi,
    EmptyMessage,
    |_: Voter<EmptyState>, message: E4Mi| {
        let state = E5Builder::default().pass(message.password).build().unwrap();
        (state, EmptyMessage)
    }
);

#[derive(Builder)]
pub struct E5 {
    pass: Password,
}

#[derive(Builder)]
pub struct V1 {
    pass: Password,
    election: Election,
}

process_message_impl!(
    Voter,
    E5,
    V1,
    E11M,
    EmptyMessage,
    |s: Voter<E5>, message: E11M| {
        let state = V1Builder::default()
            .pass(s.state.pass)
            .election(message.election)
            .build()
            .unwrap();
        (state, EmptyMessage)
    }
);

#[cfg(test)]
pub(crate) mod tests {

    use crate::datatypes::election::{Election, ElectionBuilder};
    use ring::rand::SystemRandom;

    use super::*;

    #[test]
    fn test_proofs_verify() {
        // Build an election
    }
}
