//! The Credential Authority

use std::sync::{Arc, Mutex};

use crate::datatypes::credentials::{Credential, ExpandedCredential, Password, UUID};
use crate::datatypes::election::Election;
use crate::participants::messages::*;
use crate::participants::participant_template::*;
use crate::primitives::group::{Point, Scalar};
use crate::ProtocolError;
use ring::rand::SecureRandom;

initialize_participant_impl!(CredentialAuthority);

/// Randomly samples from [a, b).
/// For |b-a| large enough there may be issues with the distribution being non-uniform.
/// We will not need to worry about this, as |b-a| < 100, and we will be using 128 bits of
/// randomness (huge overkill).
fn rand_range(rng: Arc<Mutex<dyn SecureRandom>>, a: usize, b: usize) -> usize {
    assert!(a <= b);
    let zero_centered_range = (b - a) as u128;
    let mut buff = [0 as u8; 128 / 8];
    rng.lock().unwrap().fill(&mut buff).unwrap();
    let rand_val: u128 = u128::from_be_bytes(buff);
    let mod_val = (rand_val % zero_centered_range) as usize;
    a + mod_val
}

/// Uniformly permutes a vector using the Fischer-Yates Shuffle
fn uniformly_permute<T>(rng: Arc<Mutex<dyn SecureRandom>>, vec: Vec<T>) -> Vec<T> {
    let mut vec = vec;
    let n = vec.len();
    for i in 0..n - 1 {
        // j is uniformly random in i <= j < n
        let j = rand_range(rng.clone(), i, n);
        vec.swap(i, j);
    }
    vec
}

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
        let mut L: Vec<(Point, u128)> = Vec::with_capacity(num_voters);
        for i in 0..num_voters {
            let expanded_cred = ExpandedCredential::gen(rng.clone(), &uuid);
            let (pass, pub_key): (Password, Point) =
                (expanded_cred.password, expanded_cred.public_key);
            passwords.push(pass);
            L.push((pub_key, message.voters[i]))
        }
        L = uniformly_permute(rng, L);
        let state = E4Builder::default().uuid(uuid).L(L).build().unwrap();
        let message = E4MBuilder::default().passwords(passwords).build().unwrap();
        (state, message)
    }
);

#[derive(Builder)]
pub struct E4 {
    uuid: UUID,
    L: Vec<(Point, u128)>,
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

pub struct E12 {
    election: Election,
    L: Vec<(Point, u128)>,
}

process_message_impl!(
    CredentialAuthority,
    E4,
    E12,
    E11M,
    ErrorM,
    |s: CredentialAuthority<E4>, m: E11M| {
        let election = m.election;
        let check = if m.L != s.state.L {
            // Voting Server posted wrong L
            Err(ProtocolError::DisagreementOverLError)
        } else {
            Ok(())
        };
        let state = E12 {
            election,
            L: s.state.L,
        };
        let message = ErrorM { check };
        (state, message)
    }
);
