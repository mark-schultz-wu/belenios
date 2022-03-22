//! The Belenios protocol has five distinct roles a participant may hold within it, namely
//! * SA: the Server Administrator,
//! * CA: the Credential Authority,
//! * T: the Trustee(s),
//! * V: the Voters,
//! * VS: the Voting Server.
//!
//! The only roles that are not uniquely specified by the above are the Trustees and the Voters, as
//! multiple participants may hold each of these roles. We assume (for simplicity) that there is
//! only a single Trustee, e.g. we implement the `Single` version of the protocol (see section
//! 3.1.1 of the specification).
//!
//! As mentioned in the `messages.rs` file, we implement the protocol using the State Machine
//! pattern.
//! All of our state machines take the same abstract form:
//!
//! ```rust
//! # use std::sync::{Arc, Mutex};
//! # use ring::rand::SecureRandom;
//! struct Role<T> {
//!     state: T,
//!     rng: Arc<Mutex<dyn SecureRandom>>,
//! }
//! ```

use ring::rand::SecureRandom;
use std::sync::{Arc, Mutex};

/// Implements the aformentioned abstract form for each role uniformly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmptyState;
macro_rules! initialize_participant_impl {
    ($Role: ident) => {
        struct $Role<T> {
            state: T,
            rng: Arc<Mutex<dyn SecureRandom>>,
        }

        impl $Role<EmptyState> {
            pub fn new(rng: Arc<Mutex<dyn SecureRandom>>) -> $Role<EmptyState> {
                $Role::<EmptyState> {
                    state: EmptyState,
                    rng,
                }
            }
        }
    };
}
pub(crate) use initialize_participant_impl;

/// We solely assume each participant implements a `process_message` function, which takes
/// 1. the pair (S, M) of some state S and a message M, and
/// 2. outputs some other (S', M') state+message pair.
///
/// The State Machine pattern then ensures we only call this on
/// * participants with the right role + input state, and
/// * messages that are appropriate for that step of the protocol.
pub trait Participant<M1, M2, S2> {
    fn process_message(self, message: M1) -> (S2, M2);
}
/// The state machine pattern introduces a large amount of boiler-plate, as
/// we need to define an `impl` block for each possible state transition.
/// We reduce some of this boiler-plate with the following macro.
/// Intended usage of it is, for
/// * Role the name of some role R in the protocol,
/// * S1 some initial state for R at some timestep,
/// * S2 some final state for R at that timestep,
/// * M1 some message for R to process at that timestep,
/// * M2 some message for R to produce at that timestep,
/// * f some closure from (State, Message) -> (State, Message) pairs which encodes
///     how R will act at that timestep.
macro_rules! process_message_impl {
    ($Role: ident, $S1:ty, $S2:ty, $M1:ty, $M2:ty, $f:expr) => {
        impl Participant<$M1, $M2, $Role<$S2>> for $Role<$S1> {
            fn process_message(self, message: $M1) -> ($Role<$S2>, $M2) {
                let rng = self.rng.clone();
                let (state, message) = $f(self, message);
                ($Role::<$S2> { state, rng }, message)
            }
        }
    };
}
pub(crate) use process_message_impl;
