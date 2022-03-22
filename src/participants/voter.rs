//! The Voters

use crate::datatypes::credentials::Password;
use crate::participants::messages::{E4Mi, EmptyMessage};
use crate::participants::participant_template::*;
use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

initialize_participant_impl!(Voter);

process_message_impl!(
    Voter,
    EmptyState,
    E5,
    E4Mi,
    EmptyMessage,
    |_: Voter<EmptyState>, message: E4Mi| {
        (
            E5 {
                pass: message.password,
            },
            EmptyMessage,
        )
    }
);

struct E5 {
    pass: Password,
}
