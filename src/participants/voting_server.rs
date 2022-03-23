//! The voting server

use crate::datatypes::ballot::Ballot;
use crate::datatypes::election::{Election, ElectionBuilder};
use crate::datatypes::{base58::Base58, credentials::UUID, questions::Question};
use crate::participants::messages::*;
use crate::participants::participant_template::*;
use crate::primitives::group::{Point, Scalar};
use crate::primitives::pki::VerificationKey;
use crate::primitives::zkp::{DLog, ProofSystem};
use crate::ProtocolError;
use ring::rand::SecureRandom;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

initialize_participant_impl!(VotingServer);

process_message_impl!(
    VotingServer,
    EmptyState,
    E3,
    E1M,
    E3M_VS_to_CA,
    |s: VotingServer<EmptyState>, m: E1M| {
        let uuid = UUID::gen(s.rng);
        let state = E3Builder::default()
            .voters(m.voters)
            .uuid(uuid.clone())
            .build()
            .unwrap();
        let message = E3M_VS_to_CABuilder::default().uuid(uuid).build().unwrap();
        (state, message)
    }
);

#[derive(Builder)]
pub struct E3 {
    voters: Vec<u128>,
    uuid: UUID,
}

// E7:
process_message_impl!(
    VotingServer,
    E3,
    E8,
    E7M,
    ErrorM,
    |s: VotingServer<E3>, m: E7M| {
        // Verify the multi-set of weights is correct.
        let mut local_weights = s.state.voters.clone();
        local_weights.sort_unstable();
        let (_, mut remote_weights): (Vec<_>, Vec<u128>) = m.L.iter().cloned().unzip();
        remote_weights.sort_unstable();
        let check = if local_weights == remote_weights {
            Ok(())
        } else {
            Err(ProtocolError::DifferentMultisetError)
        };
        let state = E8Builder::default()
            .uuid(s.state.uuid)
            .L(m.L)
            .build()
            .unwrap();
        let message = ErrorM { check };
        (state, message)
    }
);

#[derive(Builder)]
pub struct E8 {
    uuid: UUID,
    L: Vec<(Point, u128)>,
}

process_message_impl!(
    VotingServer,
    E8,
    E9,
    E9M,
    ErrorM,
    |s: VotingServer<E8>, m: E9M| {
        // Check all of the proofs of the trustees.
        // Record any indices of failing proofs.
        let trustee_keys = m.trustee_keys;
        let mut cheaters = Vec::new();
        let mut trustee_pk = Point::identity();
        for i in 0..trustee_keys.len() {
            let pk: Point = trustee_keys[i].public_key.clone().into();
            let dlog = DLog {
                rng: s.rng.clone(),
                pt: pk.clone(),
            };
            if !dlog.verify(&trustee_keys[i].proof) {
                cheaters.push(i);
            } else {
                trustee_pk = trustee_pk + pk;
            }
        }
        let state = E9Builder::default()
            .uuid(s.state.uuid)
            .L(s.state.L)
            .trustee_pk(trustee_pk)
            .build()
            .unwrap();
        let check = if cheaters.len() > 0 {
            Err(ProtocolError::TrusteePKProofFailedError(cheaters))
        } else {
            Ok(())
        };
        (state, ErrorM { check })
    }
);

#[derive(Builder)]
pub struct E9 {
    uuid: UUID,
    L: Vec<(Point, u128)>,
    trustee_pk: Point,
}

process_message_impl!(
    VotingServer,
    E9,
    E11,
    E10M,
    E11M,
    |s: VotingServer<E9>, m: E10M| {
        let election = ElectionBuilder::default()
            .version(m.version)
            .description(m.description)
            .name(m.name)
            .group("RISTRETTO-25519".to_string())
            .public_key(s.state.trustee_pk)
            .questions(m.questions)
            .uuid(s.state.uuid)
            .administrator(m.administrator)
            .credential_authority(m.credential_authority)
            .build()
            .unwrap();
        let state = E11 {
            election: election.clone(),
            L: s.state.L.clone(),
        };
        let message = E11M {
            election,
            L: s.state.L,
        };
        (state, message)
    }
);

pub struct E11 {
    pub(crate) election: Election,
    pub(crate) L: Vec<(Point, u128)>,
}

process_message_impl!(
    VotingServer,
    E11,
    V4,
    EmptyMessage,
    EmptyMessage,
    |s: VotingServer<E11>, m: EmptyMessage| {
        let accepted_ballots: Vec<(Ballot, u128)> = Vec::new();
        let state = V4 {
            election: s.state.election,
            L: s.state.L,
            accepted_ballots,
        };
        (state, EmptyMessage)
    }
);

// Processing a Ballot

process_message_impl!(
    VotingServer,
    V4,
    V4,
    V3Mi,
    ErrorM,
    |s: VotingServer<V4>, m: V3Mi| {
        let L = s.state.L.clone();
        let election = s.state.election.clone();
        let accepted_ballots = s.state.accepted_ballots.clone();
        let ballot = m.vote;
        let cred = ballot.credential;
        // Find the weight of the ballot
        let mut found = false;
        let mut found_wt = 1;
        for (pt, wt) in L.iter() {
            if *pt == cred {
                found = true;
                found_wt = *wt;
            }
        }
        if !found {
            return (
                s.state,
                ErrorM {
                    check: Err(ProtocolError::CredentialNotFoundError),
                },
            );
        }
        let mut found = false;
        for (ballot, _) in accepted_ballots.iter() {
            if cred == ballot.credential {
                found = true;
            }
        }
        if found {
            return (
                s.state,
                ErrorM {
                    check: Err(ProtocolError::CredentialUsedTwiceError),
                },
            );
        }
        if !ballot.verify(s.rng.clone(), &election.public_key, &election.questions) {
            return (
                s.state,
                ErrorM {
                    check: Err(ProtocolError::BallotVerificationError),
                },
            );
        }
        let mut accepted_ballots = accepted_ballots;
        accepted_ballots.push((ballot, found_wt));
        let state = V4 {
            election,
            L,
            accepted_ballots,
        };
        (state, ErrorM { check: Ok(()) })
    }
);

pub struct V4 {
    pub(crate) election: Election,
    pub(crate) L: Vec<(Point, u128)>,
    pub(crate) accepted_ballots: Vec<(Ballot, u128)>,
}
