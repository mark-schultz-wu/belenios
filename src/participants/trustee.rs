//! The Trustee(s)
//! The Belenios protocol describes two "kinds" of trustees,
//! * Single trustees,
//! * "pederson" trustees, which have a "threshold"-type behavior.
//!
//! To start, I will work in terms of single trustees for simplicity.

use crate::datatypes::credentials::Password;
use crate::participants::messages::*;
use crate::participants::participant_template::*;
use crate::primitives::pki::{SigningKeys, VerificationKey};
use crate::primitives::zkp::{DLog, ProofSystem};
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

// Doing the "single" trustee protocol, not "pederson".
initialize_participant_impl!(Trustee);

pub struct E9 {
    keys: TrusteeKeys,
    proof: <DLog as ProofSystem>::Proof,
}

#[derive(Clone)]
pub(crate) struct TrusteePublicKey {
    pub(crate) public_key: VerificationKey,
    pub(crate) proof: <DLog as ProofSystem>::Proof,
}

pub(crate) struct TrusteeKeys {
    pub(crate) secret: Password,
    pub(crate) keys: SigningKeys,
}

impl TrusteeKeys {
    pub fn gen(rng: Arc<Mutex<dyn SecureRandom>>) -> Self {
        let secret = Password::gen(rng);
        let keys = SigningKeys::from(&secret);
        TrusteeKeys { secret, keys }
    }
}

process_message_impl!(
    Trustee,
    EmptyState,
    E9,
    EmptyMessage,
    E9Mi,
    |state: Trustee<EmptyState>, _: EmptyMessage| {
        let keys = TrusteeKeys::gen(state.rng.clone());
        let public_key = &keys.keys.public;
        let instance = DLog {
            pt: public_key.0.clone(),
            rng: state.rng.clone(),
        };
        let proof = instance.prove(&keys.keys.private.0);
        let trustee_key = TrusteePublicKey {
            public_key: public_key.clone(),
            proof: proof.clone(),
        };
        let message = E9Mi { trustee_key };
        let state = E9 { keys, proof };
        (state, message)
    }
);

// Send trustee public key to S. Is a verification key, along with a ZK proof.
