#![allow(non_camel_case_types, unused_imports, dead_code, non_snake_case)]
#[macro_use]
extern crate derive_builder;

enum Error {
    IncorrectLenError,
}

pub mod datatypes {
    pub mod base58;
    pub mod credentials;
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
    pub mod pki;
    pub mod zkp;
    pub mod curve;
}

pub mod utils;
