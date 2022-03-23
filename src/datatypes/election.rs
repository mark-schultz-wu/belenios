//! The Election datatype, defined in section 4.9

use crate::datatypes::credentials::UUID;
use crate::datatypes::questions::Question;
use crate::primitives::group::{Point, Scalar};

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

#[derive(Builder, Clone, Serialize, Deserialize)]
pub struct Election {
    version: usize,
    description: String,
    name: String,
    group: String,
    pub(crate) public_key: Point,
    pub(crate) questions: Vec<Question>,
    pub(crate) uuid: UUID,
    administrator: String,
    credential_authority: String,
}

impl Election {
    // Won't bother doing the base8 -> base64 conversion
    pub fn fingerprint(&self) -> Vec<u8> {
        let data = bincode::serialize(self).unwrap();
        digest(&SHA256, &data).as_ref().into()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::datatypes::credentials::UUID;
    use ring::rand::{SecureRandom, SystemRandom};
    use std::sync::{Arc, Mutex};

    pub(crate) fn build_election() -> Election {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        let question = crate::datatypes::questions::tests::build_question();
        let pt = Point::sample_uniform(rng.clone());
        let uuid = UUID::gen(rng.clone());
        let election = ElectionBuilder::default()
            .version(1)
            .description("Sample".to_string())
            .name("Sample".to_string())
            .group("RISTRETTO".to_string())
            .public_key(pt)
            .questions(vec![question])
            .uuid(uuid)
            .administrator("Sample".to_string())
            .credential_authority("Sample".to_string())
            .build()
            .unwrap();
        election
    }
}
