/// A (Homomorphic) question, the basic [1] type of Belenios.
/// * `question` is the question
/// * `answers` is the list of possible answers to a question, e.g. candidates in an election.
/// * `blank` is a boolean which can set to be `true` to indicate abstaining.
/// * `min` is the minimum number of candidates to vote for (at most once per candidate).
/// * `max` is the maximum number of candidates to vote for.
#[derive(Debug, Clone, PartialEq, Builder)]
pub struct HomQuest {
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

impl HomQuestBuilder {
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

#[derive(Debug, Clone, PartialEq)]
pub enum Question {
    Homomorphic(HomQuest),
}

impl Into<Question> for HomQuest {
    fn into(self) -> Question {
        Question::Homomorphic(self)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_build_hom_quest() {
        let quest = "Who should be IACR director in 2021?";
        let ans = vec!["Mark Fischlin", "Nadia Heninger", "Anna Lysyanskaya"];
        let question = HomQuestBuilder::default()
            .question(quest.clone())
            .answers(ans.clone())
            .build()
            .unwrap();
        assert_eq!(question.question, quest);
        assert_eq!(question.answers, ans);
        assert_eq!(question.blank, false);
        assert_eq!(question.min, 0);
        assert_eq!(question.max, 1);
    }
    #[test]
    #[should_panic]
    /// We omit a giving a `question`, which should panic as there is no sensible default question.
    fn test_build_hom_quest_wo_question() {
        let ans = vec!["Mark Fischlin", "Nadia Heninger", "Anna Lysyanskaya"];
        let _ = HomQuestBuilder::default()
            .answers(ans.clone())
            .build()
            .unwrap();
    }
}
