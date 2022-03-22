//! A wrapper around the Ristretto group implementation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar;

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Point(pub(crate) RistrettoPoint);

impl Into<RistrettoPoint> for Point {
    fn into(self) -> RistrettoPoint {
        self.0
    }
}

impl From<RistrettoPoint> for Point {
    fn from(p: RistrettoPoint) -> Self {
        Point(p)
    }
}

impl Default for Point {
    fn default() -> Self {
        Point(RISTRETTO_BASEPOINT_POINT)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Scalar(pub(crate) scalar::Scalar);

impl Into<scalar::Scalar> for Scalar {
    fn into(self) -> scalar::Scalar {
        self.0
    }
}

impl From<scalar::Scalar> for Scalar {
    fn from(p: scalar::Scalar) -> Self {
        Scalar(p)
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Scalar(scalar::Scalar::zero())
    }
}
