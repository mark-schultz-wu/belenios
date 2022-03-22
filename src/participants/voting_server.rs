//! The voting server

use crate::datatypes::{base58::Base58, credentials::UUID, questions::Question};
use crate::participants::messages::{EmptyMessage, Error, E1M, E3M_VS, E7M, E8M};
use crate::participants::participant_template::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use ring::rand::SecureRandom;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

initialize_participant_impl!(VotingServer);

process_message_impl!(
    VotingServer,
    EmptyState,
    E2,
    E1M,
    EmptyMessage,
    |_: VotingServer<EmptyState>, m: E1M| {
        (
            E2 {
                questions: m.questions,
                voters: m.voters,
            },
            EmptyMessage,
        )
    }
);

struct E2 {
    questions: Vec<Question>,
    voters: Vec<u128>,
}

process_message_impl!(
    VotingServer,
    E2,
    E3,
    EmptyMessage,
    E3M_VS,
    |s: VotingServer<E2>, _| {
        let uuid = UUID::gen(s.rng);
        (
            E3 {
                questions: s.state.questions,
                voters: s.state.voters,
                uuid: uuid.clone(),
            },
            E3M_VS { uuid },
        )
    }
);

struct E3 {
    questions: Vec<Question>,
    voters: Vec<u128>,
    uuid: UUID,
}

// E7:
process_message_impl!(
    VotingServer,
    E3,
    E8,
    E7M,
    E8M,
    |s: VotingServer<E3>, m: E7M| {
        // Verify the multi-set of weights is correct.
        let mut local_weights = s.state.voters.clone();
        local_weights.sort_unstable();
        let (_, mut remote_weights): (Vec<_>, Vec<u128>) = m.L.iter().cloned().unzip();
        remote_weights.sort_unstable();
        let check = if local_weights == remote_weights {
            Ok(())
        } else {
            Err(Error::DifferentMultisetError)
        };

        (
            E8 {
                uuid: s.state.uuid,
                L: m.L,
            },
            E8M { check },
        )
    }
);

struct E8 {
    uuid: UUID,
    L: Vec<(RistrettoPoint, u128)>,
}
