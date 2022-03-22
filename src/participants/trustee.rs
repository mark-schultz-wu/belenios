//! The Trustee(s)
//! The Belenios protocol describes two "kinds" of trustees,
//! * Single trustees,
//! * "pederson" trustees, which have a "threshold"-type behavior.
//!
//! To start, I will work in terms of single trustees for simplicity.

use crate::participants::participant_template::*;
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

initialize_participant_impl!(SingleTrustee);

struct E8 {}

// Send trustee public key to S. Is a verification key, along with a ZK proof.
