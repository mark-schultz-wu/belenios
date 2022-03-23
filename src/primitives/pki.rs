//! The Public Key Infrastructure that Belenios uses, described in [section 4.5 of the
//! specification](https://www.belenios.org/specification.pdf).

use std::sync::{Arc, Mutex};

use ring::{
    digest::{self, digest, SHA256, SHA256_OUTPUT_LEN},
    rand::SecureRandom,
};

use crate::datatypes::credentials::Password;
use crate::primitives::group::{Point, Scalar};
use crate::primitives::zkp::{DLog, Proof, ProofSystem};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct Ciphertext {
    pub(crate) alpha: Point,
    pub(crate) beta: Point,
}

impl From<(Point, Point)> for Ciphertext {
    fn from(pair: (Point, Point)) -> Self {
        Self {
            alpha: pair.0,
            beta: pair.1,
        }
    }
}

impl Into<(Point, Point)> for Ciphertext {
    fn into(self) -> (Point, Point) {
        (self.alpha, self.beta)
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
        let private = Scalar::hash_to_scalar(&data.as_bytes());
        let public = private * Point::generator();
        ElGamalKeys { public, private }
    }
}

/// A 256-bit symmetric key
struct SymKey([u8; SHA256_OUTPUT_LEN]);
/// A 96-bit nonce.
struct IV([u8; 96 / 8]);

impl IV {
    fn hash_to_iv(data: &[u8]) -> Self {
        const SIZE: usize = 96 / 8;
        let hash = digest(&SHA256, &data);
        let mut buff = [0 as u8; SIZE];
        for i in 0..SIZE {
            buff[i] = hash.as_ref()[i];
        }
        Self(buff)
    }
}

/// A `trivial` symmetric encryption scheme.
/// Was having issues getting an AES crate to work, will revisit if I have time.
impl SymKey {
    fn hash_to_key(data: &[u8]) -> Self {
        let hash = digest(&SHA256, &data);
        let mut buff = [0 as u8; SHA256_OUTPUT_LEN];
        for i in 0..SHA256_OUTPUT_LEN {
            buff[i] = hash.as_ref()[i];
        }
        Self(buff)
    }
    fn encrypt(&self, iv: IV, data: &[u8]) -> Vec<u8> {
        data.to_owned()
    }
    fn decrypt(&self, iv: IV, ctxt: &[u8]) -> Vec<u8> {
        ctxt.to_owned()
    }
}

impl Into<EncryptionKey> for VerificationKey {
    fn into(self) -> EncryptionKey {
        EncryptionKey(self.0)
    }
}

impl Into<VerificationKey> for EncryptionKey {
    fn into(self) -> VerificationKey {
        VerificationKey(self.0)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EncryptionKey(Point);
#[derive(Clone, Copy, Debug)]
pub(crate) struct DecryptionKey(Scalar);

pub(crate) struct EncryptionKeys {
    pub(crate) public: EncryptionKey,
    pub(crate) private: DecryptionKey,
}

impl DecryptionKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl EncryptionKey {
    pub(crate) fn as_bytes(&self) -> [u8; 32] {
        self.0.as_bytes()
    }
}

impl Into<Point> for EncryptionKey {
    fn into(self) -> Point {
        self.0
    }
}

impl From<Point> for EncryptionKey {
    fn from(p: Point) -> Self {
        Self(p)
    }
}

impl EncryptionKey {
    /// El-gamal encrypts m while returning the encryption randomness r.
    /// Used for ZK proofs later.
    pub(crate) fn enc_leak_randomness(
        &self,
        rng: Arc<Mutex<dyn SecureRandom>>,
        m: Scalar,
    ) -> (Ciphertext, Scalar) {
        let rng = rng.clone();
        let y: Point = (*self).into();
        let r = Scalar::sample_uniform(rng.clone());
        let alpha = r * Point::generator();
        let beta = (y * r) + (m * Point::generator());
        ((alpha, beta).into(), r)
    }
}

pub(crate) struct EncryptedMessage {
    ctxt: Ciphertext,
    data: Vec<u8>,
}

/*
impl EncryptionKeys {
    // Need the randomness for certain proofs
    pub(crate) fn encrypt_leaking_randomness(
        rng: Arc<Mutex<dyn SecureRandom>>,
        encryption_key: &EncryptionKey,
        m: Vec<u8>,
    ) -> (EncryptedMessage, (Scalar, Scalar)) {
        let r = Scalar::sample_uniform(rng.clone());
        let s = Scalar::sample_uniform(rng.clone());
        let alpha = Point::generator() * r;
        let beta = encryption_key.0 * r + (Point::generator() * s);

        // Computing AES key as SHA256("key" | g^s) with IV SHA256("iv"| g^r)
        let key_data = [
            "key".to_string().as_bytes(),
            &(Point::generator() * s).as_bytes()[..],
        ]
        .concat();
        let key = SymKey::hash_to_key(&key_data);
        let iv_data = [
            "iv".to_string().as_bytes(),
            &(Point::generator() * r).as_bytes()[..],
        ]
        .concat();
        let iv = IV::hash_to_iv(&iv_data);
        let data = key.encrypt(iv, &m);
        let ctxt = (alpha, beta).into();
        let enc_m = EncryptedMessage { ctxt, data };
        (enc_m, (r, s))
    }
    pub fn encrypt(
        rng: Arc<Mutex<dyn SecureRandom>>,
        encryption_key: &EncryptionKey,
        m: Vec<u8>,
    ) -> EncryptedMessage {
        Self::encrypt_leaking_randomness(rng.clone(), encryption_key, m).0
    }
    pub fn decrypt(self, dk: DecryptionKey, c: EncryptedMessage) -> Vec<u8> {
        let (ctxt, data) = (c.ctxt, c.data);
        let (alpha, beta) = ctxt.into();
        let pt = beta - (dk.0 * alpha);
        // Computing Symmetric key as SHA256("key"| pt);
        let key_data = ["key".to_string().as_bytes(), &pt.as_bytes()[..]].concat();
        let key = SymKey::hash_to_key(&key_data);
        let iv_data = ["iv".to_string().as_bytes(), &alpha.as_bytes()[..]].concat();
        let iv = IV::hash_to_iv(&iv_data);
        key.decrypt(iv, &data)
    }
}
*/

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

#[derive(Debug, Clone)]
pub(crate) struct SigningKey(pub(crate) Scalar);
#[derive(Debug, Clone)]
pub(crate) struct VerificationKey(pub(crate) Point);

impl From<VerificationKey> for Point {
    fn from(vk: VerificationKey) -> Self {
        vk.0
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SigningKeys {
    pub(crate) public: VerificationKey,
    pub(crate) private: SigningKey,
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
        hash: &[u8],
    ) -> (&[u8], Proof) {
        let w = Scalar::sample_uniform(rng);
        let commitment = Point::generator() * w;
        // The domain separtion constant for signing
        let separator = String::from("sigmsg");
        let data = [separator.as_bytes(), hash, &commitment.as_bytes()].concat();
        let challenge = Scalar::hash_to_scalar(&data);
        let response = w - signing_key.0 * challenge;
        let proof = (challenge, response).into();
        (hash, proof)
    }
    fn verify(verif_key: Point, (hash, pf): (&[u8], Proof)) -> bool {
        let (challenge, response) = pf.into();
        let commitment = (response * Point::generator()) + (verif_key * challenge);
        let separator = String::from("sigmsg");
        let data = [separator.as_bytes(), hash, &commitment.as_bytes()].concat();
        challenge == Scalar::hash_to_scalar(&data)
    }
}
