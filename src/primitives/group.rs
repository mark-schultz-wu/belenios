//! A wrapper around the Ristretto group implementation.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, traits::Identity};
use ring::digest;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Mul, Neg, Sub};
use std::sync::{Arc, Mutex};

#[derive(Clone, PartialEq, Debug, Copy, Serialize, Deserialize)]
pub struct Point(pub(crate) RistrettoPoint);

impl Point {
    pub fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }
    pub fn as_bytes(&self) -> [u8; 32] {
        *self.0.compress().as_bytes()
    }
    pub fn generator() -> Self {
        Self(RISTRETTO_BASEPOINT_POINT)
    }
    pub fn sample_uniform(rng: Arc<Mutex<dyn SecureRandom>>) -> Self {
        let mut buff = [0 as u8; 64];
        rng.lock().unwrap().fill(&mut buff).unwrap();
        Self(RistrettoPoint::from_uniform_bytes(&buff))
    }
}

// Would be generically good to remove the Copy
// derive, but thats a later optimization.
#[derive(Clone, PartialEq, Debug, Copy, Serialize, Deserialize)]
pub struct Scalar(pub(crate) scalar::Scalar);

impl Scalar {
    pub fn zero() -> Self {
        Self(scalar::Scalar::zero())
    }
    pub fn one() -> Self {
        Self(scalar::Scalar::one())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        scalar::Scalar::as_bytes(&self.0)
    }
    pub fn sample_uniform(rng: Arc<Mutex<dyn SecureRandom>>) -> Scalar {
        let mut buff = [0 as u8; 32];
        rng.lock().unwrap().fill(&mut buff).unwrap();
        Self(scalar::Scalar::from_bytes_mod_order(buff))
    }
    pub fn hash_to_scalar(data: &[u8]) -> Scalar {
        let hash = digest::digest(&digest::SHA256, data);
        let mut collected_hash = [0; digest::SHA256_OUTPUT_LEN];
        for idx in 0..digest::SHA256_OUTPUT_LEN {
            collected_hash[idx] = hash.as_ref()[idx];
        }
        Self(scalar::Scalar::from_bytes_mod_order(collected_hash))
    }
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
        Self(scalar::Scalar::from_bytes_mod_order(bytes))
    }
}

impl Neg for Point {
    type Output = Point;
    fn neg(self) -> Self::Output {
        Self(self.0.neg())
    }
}

impl Sub<Point> for Point {
    type Output = Point;
    fn sub(self, rhs: Point) -> Self::Output {
        self + (-rhs)
    }
}

impl Add<Point> for Point {
    type Output = Point;
    fn add(self, rhs: Point) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Scalar) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;
    fn mul(self, rhs: &Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<Scalar> for &Scalar {
    type Output = Scalar;
    fn mul(self, rhs: Scalar) -> Self::Output {
        Scalar(self.0 * rhs.0)
    }
}

impl From<u128> for Scalar {
    fn from(inp: u128) -> Self {
        Self(scalar::Scalar::from(inp))
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;
    fn add(self, rhs: Scalar) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Mul<Scalar> for Point {
    type Output = Point;
    fn mul(self, rhs: Scalar) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl Mul<Point> for Scalar {
    type Output = Point;
    fn mul(self, rhs: Point) -> Self::Output {
        Point(self.0 * rhs.0)
    }
}

impl Neg for Scalar {
    type Output = Scalar;
    fn neg(self) -> Self::Output {
        Scalar(-self.0)
    }
}
