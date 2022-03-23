/// A (Homomorphic) question, the basic [1] type of Belenios.
/// * `question` is the question
/// * `answers` is the list of possible answers to a question, e.g. candidates in an election.
/// * `blank` is a boolean which can set to be `true` to indicate abstaining.
/// * `min` is the minimum number of candidates to vote for (at most once per candidate).
/// * `max` is the maximum number of candidates to vote for.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Builder, Serialize, Deserialize)]
pub struct Question {
    #[builder(setter(into))]
    pub(crate) question: String,
    #[builder(setter(custom))]
    pub(crate) answers: Vec<String>,
    #[builder(default = "false")]
    pub(crate) blank: bool,
    #[builder(default = "0")]
    pub(crate) min: u128,
    #[builder(default = "1")]
    pub(crate) max: u128,
}

impl QuestionBuilder {
    /// The standard .into method cannot coerce a Vec<&str> to a Vec<String>.
    /// Using this, we can initialize anwers using `vec!["Answer 1", "Answer 2"]`,
    /// rather than having to write `vec!["Answer 1".to_string(), "Answer 2".to_string()]`.
    pub fn answers(&mut self, answers: Vec<&str>) -> &mut Self {
        self.answers = Some(
            answers
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        );
        self
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;

    pub(crate) fn build_question() -> Question {
        let quest = "Who should be IACR director in 2021?";
        let ans = vec!["Mark Fischlin", "Nadia Heninger", "Anna Lysyanskaya"];
        let question = QuestionBuilder::default()
            .question(quest.clone())
            .answers(ans.clone())
            .build()
            .unwrap();
        question
    }

    #[test]
    fn test_build_quest() {
        let quest = "Who should be IACR director in 2021?";
        let ans = vec!["Mark Fischlin", "Nadia Heninger", "Anna Lysyanskaya"];

        let question = build_question();
        assert_eq!(question.question, quest);
        assert_eq!(question.answers, ans);
        assert_eq!(question.blank, false);
        assert_eq!(question.min, 0);
        assert_eq!(question.max, 1);
    }
    #[test]
    #[should_panic]
    /// We omit a giving a `question`, which should panic as there is no sensible default question.
    fn test_build_quest_wo_question() {
        let ans = vec!["Mark Fischlin", "Nadia Heninger", "Anna Lysyanskaya"];
        let _ = QuestionBuilder::default()
            .answers(ans.clone())
            .build()
            .unwrap();
    }
}
