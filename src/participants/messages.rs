//! The Belenios protocol requires several participants to exchange messages between eachother.
//! This file encodes the different participants may send within the protocol.
//! See TODO: write up somewhere centrally.
#![allow(dead_code)]

use crate::datatypes::credentials::{Credential, Password, UUID};
use crate::datatypes::election::Election;
use crate::datatypes::questions::Question;
use crate::participants::trustee::TrusteePublicKey;
use crate::primitives::group::{Point, Scalar};
use crate::ProtocolError;
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

/// Type used to raise an error when some cheating behavior is detected.
pub struct ErrorM {
    pub check: Result<(), ProtocolError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyMessage;

/// The initialization message for the Server administrator.
///
/// FROM: Specification of the election,
/// TO: Server administrator, Voting Server
///
/// The number of voters is `voters.len()`.
/// Voter i's weight (written `wi` in the spec) is `voters[i]`.
#[derive(Builder, Clone)]
pub struct E1M {
    pub(crate) voters: Vec<u128>,
}

/// The UUID
///
/// FROM: Voting Server
/// TO: Credential Authority
#[derive(Builder)]
pub struct E3M_VS_to_CA {
    pub(crate) uuid: UUID,
}
/// The list of weights of voters
///
/// FROM: ServerAdmin
/// TO: CredentialAuthority.
#[derive(Builder, PartialEq)]
pub struct E3M_SA_to_CA {
    pub(crate) voters: Vec<u128>,
}
pub struct E3M {
    pub(crate) uuid: UUID,
    pub(crate) voters: Vec<u128>,
}

/// Combining the two messages for step E3
impl From<(E3M_VS_to_CA, E3M_SA_to_CA)> for E3M {
    fn from((message_VS, message_CA): (E3M_VS_to_CA, E3M_SA_to_CA)) -> Self {
        E3M {
            uuid: message_VS.uuid,
            voters: message_CA.voters,
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
#[derive(Builder)]
pub struct E4M {
    pub(crate) passwords: Vec<Password>,
}

/// The password of the ith voter.
///
/// FROM: CredentialAuthority,
/// TO: (the i-th) Voter.
#[derive(Clone)]
pub struct E4Mi {
    pub(crate) password: Password,
}

impl From<E4M> for Vec<E4Mi> {
    fn from(message: E4M) -> Self {
        let vec_of_passes = message.passwords;
        let mut output = Vec::new();
        for i in 0..vec_of_passes.len() {
            let individual_pass = E4Mi {
                password: vec_of_passes[i].clone(),
            };
            output.push(individual_pass)
        }
        output
    }
}

/// The (public) list of keys/weights L.
///
/// FROM: CredentialAuthority,
/// TO: VotingServer.
pub struct E7M {
    pub(crate) L: Vec<(Point, u128)>,
}

pub struct E9Mi {
    pub(crate) trustee_key: TrusteePublicKey,
}
pub struct E9M {
    pub(crate) trustee_keys: Vec<TrusteePublicKey>,
}

impl From<Vec<E9Mi>> for E9M {
    fn from(v: Vec<E9Mi>) -> Self {
        let mut trustee_keys = Vec::new();
        for i in 0..v.len() {
            trustee_keys.push(v[i].trustee_key.clone());
        }
        E9M { trustee_keys }
    }
}

#[derive(Builder)]
pub struct E10M {
    pub(crate) description: String,
    pub(crate) name: String,
    pub(crate) version: usize,
    pub(crate) questions: Vec<Question>,
    pub(crate) administrator: String,
    pub(crate) credential_authority: String,
}

#[derive(Clone)]
pub struct E11M {
    pub(crate) election: Election,
    pub(crate) L: Vec<(Point, u128)>,
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
