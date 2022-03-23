//! The Server Administrator;

use std::sync::{Arc, Mutex};

use crate::datatypes::questions::Question;
use crate::participants::messages::*;
use crate::participants::participant_template::*;
use ring::rand::SecureRandom;

initialize_participant_impl!(ServerAdmin);

process_message_impl!(
    ServerAdmin,
    EmptyState,
    E2,
    E1M,
    E3M_SA_to_CA,
    |_: ServerAdmin<EmptyState>, message: E1M| {
        let state = E2Builder::default()
            .voters(message.voters.clone())
            .build()
            .unwrap();
        let message = E3M_SA_to_CABuilder::default()
            .voters(message.voters)
            .build()
            .unwrap();
        (state, message)
    }
);

/// The state of the ServerAdmin at the end of step E1/beginning of step E2.
#[derive(Builder)]
pub struct E2 {
    voters: Vec<u128>,
}

#[cfg(test)]

mod tests {
    use ring::rand::SystemRandom;

    /*
    use super::*;
    use crate::datatypes::questions::QuestionBuilder;
    use crate::participants::messages::E1MBuilder;

    fn test_step_one_election_setup() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        let quest = "Who should be IACR director in 2021?";
        let ans = vec!["Mark Fischlin", "Nadia Heninger", "Anna Lysyanskaya"];
        let question: Question = QuestionBuilder::default()
            .question(quest.clone())
            .answers(ans.clone())
            .build()
            .unwrap()
            .into();
        let message = E1MBuilder::default()
            .questions(vec![question.clone()])
            .voters(vec![1, 1, 1, 1, 1])
            .build()
            .unwrap();
        let initial_admin = ServerAdmin::<EmptyState>::new(rng);
        let (final_admin, final_message) = initial_admin.process_message(message);
        assert_eq!(final_admin.state.questions, vec![question]);
        assert_eq!(final_admin.state.voters.len(), 5);
    }
    */
}
