//! The Public Key Infrastructure that Belenios uses, described in [section 4.5 of the
//! specification](https://www.belenios.org/specification.pdf).

use std::sync::{Arc, Mutex};

use ring::{
    digest::{digest, SHA256, SHA256_OUTPUT_LEN},
    rand::SecureRandom,
};

use crate::datatypes::credentials::Password;
use crate::primitives::curve::{Point, Scalar};
use crate::primitives::zkp::{DLog, NIZK};
use crate::utils::{hash_to_scalar, random_point, random_scalar};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{self, RistrettoPoint},
    scalar,
};

pub(crate) struct Ciphertext {
    alpha: Point,
    beta: Point,
}

impl Into<(Point, Point)> for Ciphertext {
    fn into(self) -> (Point, Point) {
        (self.alpha, self.beta)
    }
}

impl<'a> Into<(&'a Point, &'a Point)> for &'a Ciphertext {
    fn into(self) -> (&'a Point, &'a Point) {
        (&self.alpha, &self.beta)
    }
}

impl From<(Point, Point)> for Ciphertext {
    fn from(p: (Point, Point)) -> Self {
        Ciphertext {
            alpha: p.0,
            beta: p.1,
        }
    }
}

struct ElGamalKeys {
    public: Point,
    private: Scalar,
}

/// Used for domain-separating hash function calls
struct DomainSeparator(String);

impl From<(&Password, DomainSeparator)> for ElGamalKeys {
    fn from((pass, sep): (&Password, DomainSeparator)) -> Self {
        let mut data = sep.0.clone();
        let underlying_string = &pass.0 .0;
        data.extend(underlying_string.as_bytes().iter().map(|c| *c as char));
        let private = hash_to_scalar(&data.as_bytes());
        let public = Point(private.0 * RISTRETTO_BASEPOINT_POINT);
        ElGamalKeys { public, private }
    }
}

struct EncryptionKey(Point);
struct DecryptionKey(Scalar);

struct EncryptionKeys {
    public: EncryptionKey,
    private: DecryptionKey,
}

impl From<&Password> for EncryptionKeys {
    fn from(secret: &Password) -> Self {
        let enc_sep = DomainSeparator(String::from("dk"));
        let keys = ElGamalKeys::from((secret, enc_sep));
        EncryptionKeys {
            public: EncryptionKey(keys.public),
            private: DecryptionKey(keys.private),
        }
    }
}

struct SigningKey(Scalar);
struct VerificationKey(Point);

struct SigningKeys {
    public: VerificationKey,
    private: SigningKey,
}

impl From<&Password> for SigningKeys {
    fn from(secret: &Password) -> Self {
        let sign_sep = DomainSeparator(String::from("sk"));
        let keys = ElGamalKeys::from((secret, sign_sep));
        SigningKeys {
            public: VerificationKey(keys.public),
            private: SigningKey(keys.private),
        }
    }
}

impl SigningKeys {
    fn sign(
        signing_key: SigningKey,
        rng: Arc<Mutex<dyn SecureRandom>>,
        message: &[u8],
    ) -> (&[u8], (Scalar, Scalar)) {
        let mut buff = [0 as u8; 32];
        rng.lock()
            .unwrap()
            .fill(&mut buff)
            .expect("RNG call failed");
        let w = Scalar(scalar::Scalar::from_bytes_mod_order(buff));
        let commitment = (RISTRETTO_BASEPOINT_POINT * w.0).compress();
        // The domain separtion constant for signing
        let separator = String::from("sigmsg");
        let data = [separator.as_bytes(), message, commitment.as_bytes()].concat();
        let challenge = hash_to_scalar(&data);
        let response = w.0 - signing_key.0 .0 * challenge.0;
        (message, (challenge, response.into()))
    }
    fn verify(
        verif_key: Point,
        (message, (challenge, response)): (&[u8], (Scalar, Scalar)),
    ) -> bool {
        let commitment =
            ((response.0 * RISTRETTO_BASEPOINT_POINT) + (verif_key.0 * challenge.0)).compress();
        let separator = String::from("sigmsg");
        let data = [separator.as_bytes(), message, commitment.as_bytes()].concat();
        challenge == hash_to_scalar(&data)
    }
}

struct TrusteePublicKey {
    public_key: Point,
    proof: <DLog::DLog as NIZK>::Proof,
}

struct TrusteeKeys {
    secret: Password,
    encryption: EncryptionKeys,
    signing: SigningKeys,
}

impl TrusteeKeys {
    pub fn gen(rng: Arc<Mutex<dyn SecureRandom>>) -> Self {
        let secret = Password::gen(rng);
        TrusteeKeys::from(secret)
    }
}

impl From<Password> for TrusteeKeys {
    fn from(secret: Password) -> Self {
        let encryption = EncryptionKeys::from(&secret);
        let signing = SigningKeys::from(&secret);
        TrusteeKeys {
            secret,
            encryption,
            signing,
        }
    }
}
