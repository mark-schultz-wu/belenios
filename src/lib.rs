#![allow(non_camel_case_types, unused_imports, dead_code, non_snake_case)]
#[macro_use]
extern crate derive_builder;

#[macro_use]
extern crate serde;

#[derive(Debug)]
pub enum ProtocolError {
    IncorrectLenError,
    DifferentMultisetError,
    TrusteePKProofFailedError(Vec<usize>),
    // The CA and Voting Server disagree over the public list L.
    DisagreementOverLError,
    CredentialNotFoundError,
    CredentialUsedTwiceError,
    BallotVerificationError,
}

pub mod datatypes {
    pub mod ballot;
    pub mod base58;
    pub mod credentials;
    pub mod election;
    pub mod questions;
    pub mod voter_ids;
}

pub mod participants {
    pub mod credential_authority;
    pub mod messages;
    pub mod participant_template;
    pub mod server_admin;
    pub mod trustee;
    pub mod voter;
    pub mod voting_server;
}

pub mod primitives {
    pub mod group;
    pub mod pki;
    pub mod zkp;
}
