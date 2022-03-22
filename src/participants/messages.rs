//! The Belenios protocol requires several participants to exchange messages between eachother.
//! This file encodes the different participants may send within the protocol.
//! See TODO: write up somewhere centrally.
#![allow(dead_code)]

use crate::datatypes::credentials::{Credential, Password, UUID};
use crate::datatypes::questions::Question;
use curve25519_dalek::ristretto::RistrettoPoint;
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

pub enum Error {
    DifferentMultisetError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmptyMessage;

/// The initialization message for the Server administrator.
///
/// FROM: Specification of the election,
/// TO: Server administrator, Voting Server
///
/// The number of voters is `voters.len()`.
/// Voter i's weight (written `wi` in the spec) is `voters[i]`.
#[derive(Builder)]
pub(crate) struct E1M {
    pub(crate) questions: Vec<Question>,
    pub(crate) voters: Vec<u128>,
}

/// The UUID
///
/// FROM: Voting Server
/// TO: Credential Authority
pub(crate) struct E3M_VS {
    pub(crate) uuid: UUID,
}
/// The list of weights of voters
///
/// FROM: ServerAdmin
/// TO: CredentialAuthority.
pub(crate) struct E3M_VA {
    pub(crate) voters: Vec<u128>,
}
pub(crate) struct E3M {
    pub(crate) uuid: UUID,
    pub(crate) voters: Vec<u128>,
}

/// Combining the two messages for step E3
impl From<(E3M_VS, E3M_VA)> for E3M {
    fn from((message_VS, message_VA): (E3M_VS, E3M_VA)) -> Self {
        E3M {
            uuid: message_VS.uuid,
            voters: message_VA.voters,
        }
    }
}

/// The list of passwords.
///
/// From: CredentialAuthority
/// TO: Voters
///
/// Each individual voter should only get their password,
/// e.g. the Credential Authority should iterate over this, sending
/// the i-th password to the i-th voter.
pub(crate) struct E4M {
    pub(crate) passwords: Vec<Password>,
}

/// The password of the ith voter.
///
/// FROM: CredentialAuthority,
/// TO: (the i-th) Voter.
pub(crate) struct E4Mi {
    pub(crate) password: Password,
}

/// The (public) list of keys/weights L.
///
/// FROM: CredentialAuthority,
/// TO: VotingServer.
pub(crate) struct E7M {
    pub(crate) L: Vec<(RistrettoPoint, u128)>,
}

/// The result of the Voting Server verifying the multi-set of weights
/// obtained from the CredentialAuthority is correct.
///
/// FROM: VotingServer,
/// TO: Nobody in particular --- if this is an error, the voting server could just panic,
/// or broadcast the error to all parties.
pub(crate) struct E8M {
    pub(crate) check: Result<(), Error>,
}

/// The result of the Voting Server's check

/// The Election Setup phase is divided into twelve steps, described in section 3.1.
struct E1;
struct E2;
struct E3;
struct E4;
struct E5;
struct E6;
struct E7;
struct E8;
struct E9;
struct E10;
struct E11;
struct E12;

/// The Voting phase is divided into 4 steps, described in section 3.2.
struct V1;
struct V2;
struct V3;
struct V4;

/// The Credential Recovery phase is divided into 3 steps, described in section 3.3.
struct C1;
struct C2;
struct C3;

/// The Tally phase is divided into 7 steps, described in section 3.4.
struct T1;
struct T2;
struct T3;
struct T4;
struct T5;
struct T6;
struct T7;
