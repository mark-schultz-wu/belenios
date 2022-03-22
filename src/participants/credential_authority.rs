//! The Credential Authority

use std::sync::{Arc, Mutex};

use crate::datatypes::credentials::{Credential, ExpandedCredential, Password, UUID};
use crate::participants::messages::{EmptyMessage, E3M, E4M, E7M};
use crate::participants::participant_template::*;
use crate::utils::uniformly_permute;
use curve25519_dalek::ristretto::RistrettoPoint;
use ring::rand::SecureRandom;

initialize_participant_impl!(CredentialAuthority);

process_message_impl!(
    CredentialAuthority,
    EmptyState,
    E4,
    E3M,
    E4M,
    |s: CredentialAuthority<EmptyState>, message: E3M| {
        let rng = s.rng.clone();
        let uuid = message.uuid;
        let num_voters = message.voters.len();
        let mut passwords: Vec<Password> = Vec::with_capacity(num_voters);
        let mut L: Vec<(RistrettoPoint, u128)> = Vec::with_capacity(num_voters);
        for i in 0..num_voters {
            let expanded_cred = ExpandedCredential::gen(rng.clone(), &uuid);
            let (pass, pub_key): (Password, RistrettoPoint) =
                (expanded_cred.password, expanded_cred.public_key);
            passwords[i] = pass;
            L[i] = (pub_key, message.voters[i]);
        }
        uniformly_permute(&mut L, rng);
        (E4 { uuid, L }, E4M { passwords })
    }
);

struct E4 {
    uuid: UUID,
    L: Vec<(RistrettoPoint, u128)>,
}

// Note that we have already had the CA forget the credentials c1, ..., cn,
// so while we do not explicitly write step 5, it has occurred as part of step 4.
//
// We could explicitly save c1, ...,cn as part of CA's state in step 4,
// but this would either require copying the ci's, or dealing with lifetimes, for no good reason.

process_message_impl!(
    CredentialAuthority,
    E4,
    E4,
    EmptyMessage,
    E7M,
    |s: CredentialAuthority<E4>, _: EmptyMessage| {
        let L = s.state.L.clone();
        (s.state, E7M { L })
    }
);
