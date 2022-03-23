//! The Voters

use crate::datatypes::ballot::{
    Answer, Ballot, BallotBuilder, StateNeededForAnswer, StateNeededForAnswerBuilder,
};
use crate::datatypes::credentials::{Credential, ExpandedCredential, Password};
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

pub struct V2 {
    pass: Password,
    election: Election,
}

process_message_impl!(Voter, V1, V1, V2Mi, V3Mi, |s: Voter<V1>, message: V2Mi| {
    let choices_vec = &message.choices;
    let election = s.state.election.clone();
    let pass = s.state.pass.clone();
    let uuid = s.state.election.uuid.clone();
    let mut answers: Vec<Answer> = Vec::new();
    for i in 0..election.questions.len() {
        let answer = StateNeededForAnswerBuilder::default()
            .choices(choices_vec[i].clone())
            .question(election.questions[i].clone())
            .pass(s.state.pass.clone())
            .rng(s.rng.clone())
            .election(election.clone())
            .build()
            .unwrap();
        answers.push(answer.into());
    }
    let election_hash = election.fingerprint();
    let cred: Credential = (pass, uuid).into();
    let cred: ExpandedCredential = cred.into();
    let cred = cred.public_key;

    let ballot = BallotBuilder::default()
        .election_uuid(election.uuid)
        .election_hash(election_hash)
        .answers(answers)
        .credential(cred)
        .build()
        .unwrap();
    let message = V3Mi { vote: ballot };
    (s.state, message)
});
