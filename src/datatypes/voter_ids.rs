//! A Voter within the Belenios protocol can be specified by an index i, along with a weight w_i

pub(crate) struct Voter_ID {
    pub(crate) idx: usize,
    pub(crate) weight: usize,
}
