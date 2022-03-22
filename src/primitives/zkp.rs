//! Zero-knowledge Proofs needed for Belenios.
//! These are detailed in the [Zero-knowledge Proofs Document](https://hal.inria.fr/hal-01576379/document).
//!
//! We model ZKPs via three structs:
//!   * Public parameters, which in most cases is simply a RNG,
//!   * an Instance of a statement to prove, and
//!   * a Witness to the statement.
//! We implement our ZKPs through the Sigma Protocols described in the linked document.
//! These are then generically transformed to NIZKs using the Fiat Shamir transform.
//! We ensure our NIZKs use domain-separated hashes.
//!
//! Note that our Sigma protocols aren't *really* Sigma protocols, as their `challenge` is not
//! random --- we `hard code` the Fiat Shamir transform at this step.
//! While this is technically a little incorrect, it doesn't impact the final NIZKs, and greatly
//! simplifies the transformation from SigmaProtocol -> NIZKs, as we do not need to describe how
//!   * Generically serialize the prior transcript for hashing with the FS transform, and
//!   * generically produce a challenge from this hash.

use array_init;
use std::convert::{TryFrom, TryInto};
use std::ops::{Add, AddAssign, Mul};
use std::sync::{Arc, Mutex};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{self, RistrettoPoint},
    scalar,
};
use ring::{
    digest::{digest, SHA256, SHA256_OUTPUT_LEN},
    rand::SecureRandom,
};

use crate::primitives::{
    curve::{Point, Scalar},
    pki::Ciphertext,
};
use crate::utils::{hash_to_scalar, random_point, random_scalar};

trait SigmaProtocol {
    type Instance;
    type Witness;
    type Commitment;
    type ProverState;
    type Challenge;
    type Response;
    const DOMAIN_SEP: &'static str;
    // &self used for public parameters, e.g. an rng to use, or other non-instance specific things.
    fn commitment(
        &self,
        x: &Self::Instance,
        w: &Self::Witness,
    ) -> (Self::Commitment, Self::ProverState);
    // In standard Sigma protocols this takes no inputs and outputs a random challenge.
    // Here, to avoid code duplication later, we "hard code" the challenge to be a Fiat Shamir
    // challenge.
    fn challenge(&self, x: &Self::Instance, com: &Self::Commitment) -> Self::Challenge;
    fn response(
        &self,
        w: &Self::Witness,
        ps: &Self::ProverState,
        chal: &Self::Challenge,
    ) -> Self::Response;
    fn result(
        &self,
        x: &Self::Instance,
        com: &Self::Commitment,
        chal: &Self::Challenge,
        resp: &Self::Response,
    ) -> bool;
}

trait NIZK {
    type Proof;
    type Instance;
    type Witness;
    fn prove(&self, x: &Self::Instance, w: &Self::Witness) -> Self::Proof;
    fn verify(&self, x: &Self::Instance, p: &Self::Proof) -> bool;
}

impl<T: SigmaProtocol> NIZK for T
where
    <T as SigmaProtocol>::Response: PartialEq,
{
    type Proof = (
        <T as SigmaProtocol>::Commitment,
        <T as SigmaProtocol>::Response,
    );
    type Instance = <T as SigmaProtocol>::Instance;
    type Witness = <T as SigmaProtocol>::Witness;
    fn prove(&self, x: &Self::Instance, w: &Self::Witness) -> Self::Proof {
        let (com, ps) = T::commitment(&self, x, w);
        let chal: <T as SigmaProtocol>::Challenge = T::challenge(&self, x, &com);
        let resp = T::response(&self, w, &ps, &chal);
        (com, resp)
    }
    fn verify(&self, x: &Self::Instance, p: &Self::Proof) -> bool {
        let (com, resp) = (&p.0, &p.1);
        let chal: <T as SigmaProtocol>::Challenge = T::challenge(&self, x, com);
        (*resp == p.1) && <T as SigmaProtocol>::result(&self, x, com, &chal, resp)
    }
}

pub(crate) mod DLog {
    use super::*;

    pub(crate) struct DLog {
        pub(crate) rng: Arc<Mutex<dyn SecureRandom>>,
    }
    pub(crate) struct DLogInstance(pub(crate) Point);
    pub(crate) struct DLogWitness(pub(crate) Scalar);

    impl SigmaProtocol for DLog {
        type Instance = DLogInstance;
        type Witness = DLogWitness;
        type Commitment = Point;
        type ProverState = Scalar;
        type Challenge = Scalar;
        type Response = Scalar;
        const DOMAIN_SEP: &'static str = "dlog";
        fn commitment(
            &self,
            _: &Self::Instance,
            _: &Self::Witness,
        ) -> (Self::Commitment, Self::ProverState) {
            let k = random_scalar(self.rng.clone());
            let r = RISTRETTO_BASEPOINT_POINT * k.0;
            (r.into(), k.into())
        }
        fn challenge(&self, x: &Self::Instance, com: &Self::Commitment) -> Self::Challenge {
            let data = [
                Self::DOMAIN_SEP.as_bytes(),
                x.0 .0.compress().as_bytes(),
                com.0.compress().as_bytes(),
            ]
            .concat();
            hash_to_scalar(&data)
        }
        fn response(
            &self,
            w: &Self::Witness,
            ps: &Self::ProverState,
            c: &Self::Challenge,
        ) -> Self::Response {
            (ps.0 + w.0 .0 * c.0).into()
        }
        fn result(
            &self,
            x: &Self::Instance,
            com: &Self::Commitment,
            chal: &Self::Challenge,
            response: &Self::Response,
        ) -> bool {
            com.0 == (response.0 * RISTRETTO_BASEPOINT_POINT) + (x.0 .0 * (-chal.0))
        }
    }
}

pub(crate) mod CorDec {
    use super::*;

    pub(crate) struct CorDecInstance {
        pub(crate) C: Point,
        pub(crate) M: Point,
        pub(crate) h: Point,
    }
    pub(crate) struct CorDecWitness {
        pub(crate) x: Scalar,
    }

    pub(crate) struct CorDec {
        pub(crate) rng: Arc<Mutex<dyn SecureRandom>>,
    }
    impl SigmaProtocol for CorDec {
        type Instance = CorDecInstance;
        type Witness = CorDecWitness;
        type Commitment = (Point, Point);
        type ProverState = Scalar;
        type Challenge = Scalar;
        type Response = Scalar;
        const DOMAIN_SEP: &'static str = "cordec";
        fn commitment(
            &self,
            x: &Self::Instance,
            _: &Self::Witness,
        ) -> (Self::Commitment, Self::ProverState) {
            let k = random_scalar(self.rng.clone());
            let B = Point(x.C.0 * k.0);
            let A = Point(RISTRETTO_BASEPOINT_POINT * k.0);
            ((A, B), k.into())
        }
        fn challenge(&self, x: &Self::Instance, com: &Self::Commitment) -> Self::Challenge {
            let data = [
                Self::DOMAIN_SEP.as_bytes(),
                x.C.0.compress().as_bytes(),
                x.M.0.compress().as_bytes(),
                x.h.0.compress().as_bytes(),
                com.0 .0.compress().as_bytes(),
                com.1 .0.compress().as_bytes(),
            ]
            .concat();
            hash_to_scalar(&data)
        }
        fn response(
            &self,
            w: &Self::Witness,
            ps: &Self::ProverState,
            c: &Self::Challenge,
        ) -> Self::Response {
            Scalar(ps.0 + w.x.0 * c.0)
        }
        fn result(
            &self,
            x: &Self::Instance,
            com: &Self::Commitment,
            chal: &Self::Challenge,
            response: &Self::Response,
        ) -> bool {
            let recomputed_chal = CorDec::challenge(&self, x, com);
            let (A, B) = com;
            let (h, M, C) = (&x.h, &x.M, &x.C);
            let s = response;
            let e = chal;
            (recomputed_chal == *chal)
                && (A.0 == (s.0 * RISTRETTO_BASEPOINT_POINT) + (-e.0 * h.0))
                && (B.0 == (s.0 * C.0) + (-e.0 * M.0))
        }
    }
}

mod SetMem {
    use super::*;
    use array_init::array_init;

    pub(crate) struct SetMemInstance<const N: usize> {
        pub(crate) h: Point,
        pub(crate) ctxt: Ciphertext,
        pub(crate) FinSet: [Scalar; N],
    }
    pub(crate) struct SetMemWitness {
        pub(crate) r: Scalar,
        pub(crate) i: usize,
    }
    pub(crate) struct SetMem<const N: usize> {
        pub(crate) rng: Arc<Mutex<dyn SecureRandom>>,
    }
    impl<const N: usize> SigmaProtocol for SetMem<N> {
        type Instance = SetMemInstance<N>;
        type Witness = SetMemWitness;
        type Commitment = [(Point, Point); N];
        type ProverState = [(Scalar, Scalar); N];
        type Challenge = Scalar;
        type Response = [(Scalar, Scalar); N];
        const DOMAIN_SEP: &'static str = "setmem";
        fn commitment(
            &self,
            x: &Self::Instance,
            wit: &Self::Witness,
        ) -> (Self::Commitment, Self::ProverState) {
            // Have to use array_init as Point/Scalar are non-copy.
            let mut com: Self::Commitment =
                array_init(|_: usize| (Point::default(), Point::default()));
            let mut ps: Self::ProverState =
                array_init(|_: usize| (Scalar::default(), Scalar::default()));
            for i in 0..N {
                let rho = random_scalar(self.rng.clone());
                let sigma = random_scalar(self.rng.clone());
                ps[i] = (sigma.into(), rho.into());
            }
            // The two cases are the same, with the only exception that sigma_i = 0;
            // We therefore view ps[wit.i] = (sigma_i, rho_i) = (0, w);
            // Note that this implies that (A_i, B_i) has the correct form.
            ps[wit.i].0 = Scalar::default();
            let (alpha, beta) = (&x.ctxt).into();
            let h = &x.h;
            let M = &x.FinSet;
            for i in 0..N {
                let (sigma_i, rho_i) = (&ps[i].0, &ps[i].1);
                let A_i = Point((RISTRETTO_BASEPOINT_POINT * rho_i.0) + (alpha.0 * (-sigma_i.0)));
                let B_i = Point(
                    (rho_i.0 * h.0)
                        + ((beta.0 + (-M[i].0 * RISTRETTO_BASEPOINT_POINT)) * (-sigma_i.0)),
                );
                com[i] = (A_i, B_i);
            }
            // Ensuring (not) treating the case of i = wit.i separately doesn't cause issues.
            assert_eq!(
                com[wit.i],
                (
                    Point(RISTRETTO_BASEPOINT_POINT * ps[wit.i].1 .0),
                    Point(x.h.0 * ps[wit.i].1 .0)
                )
            );
            (com, ps)
        }
        fn challenge(&self, x: &Self::Instance, com: &Self::Commitment) -> Self::Challenge {
            let mut data: Vec<u8> = Self::DOMAIN_SEP.clone().into();
            data.extend(x.h.0.compress().as_bytes());
            let (alpha, beta) = (&x.ctxt).into();
            data.extend(alpha.0.compress().as_bytes());
            data.extend(beta.0.compress().as_bytes());
            for bytestr in x.FinSet.iter().map(|s: &Scalar| *s.0.as_bytes()) {
                data.extend(bytestr);
            }
            for (A, B) in com.iter() {
                data.extend(A.0.compress().as_bytes());
                data.extend(B.0.compress().as_bytes());
            }
            hash_to_scalar(&data)
        }
        fn response(
            &self,
            wit: &Self::Witness,
            ps: &Self::ProverState,
            c: &Self::Challenge,
        ) -> Self::Response {
            let mut resp = ps.clone();
            let mut sigma: scalar::Scalar = c.clone().0;
            for i in 0..N {
                if i != wit.i {
                    let (sigma_i, _) = &ps[i];
                    sigma -= sigma_i.0;
                }
            }
            let w = ps[wit.i].1 .0;
            // We stored w in the rho component of the ith index of the prover state.
            // Recall prover state has entries of the form (sigma, rho).
            let rho = w + (wit.r.0 * sigma);
            resp[wit.i] = (Scalar(sigma), Scalar(rho));
            resp
        }
        fn result(
            &self,
            x: &Self::Instance,
            com: &Self::Commitment,
            chal: &Self::Challenge,
            response: &Self::Response,
        ) -> bool {
            let (alpha, beta) = (&x.ctxt).into();
            let M = &x.FinSet;
            let h = &x.h;
            let mut sigma = Scalar::default().0;
            for i in 0..N {
                let (expected_A, expected_B) = (&com[i].0, &com[i].1);
                let (sigma_i, rho_i) = (&response[i].0, &response[i].1);
                sigma += sigma_i.0;
                let A_i = Point((RISTRETTO_BASEPOINT_POINT * rho_i.0) + (alpha.0 * -sigma_i.0));
                let B_i = Point(
                    (rho_i.0 * h.0)
                        + ((beta.0 + (-M[i].0 * RISTRETTO_BASEPOINT_POINT)) * (-sigma_i.0)),
                );
                if *expected_A != A_i || *expected_B != B_i {
                    return false;
                }
            }
            // still need to check sigma
            sigma == chal.0
        }
    }
}

mod Disjunction {
    use super::*;
    use array_init::array_init;

    // N (num of equalities) < M (num of ctxts)
    pub(crate) struct DisjunctionInstance<const N: usize, const M: usize> {
        pub(crate) h: Point,
        pub(crate) ctxt: [Ciphertext; M],
        pub(crate) FinSet: [Scalar; N],
    }
    pub(crate) struct DisjunctionWitness<const N: usize, const M: usize> {
        pub(crate) rs: [Scalar; M],
        // Index of the inequality that holds.
        // Indexes into [_; N], can be made into an [_;M] index with `indices` above.
        pub(crate) i: usize,
    }
    pub(crate) struct Disjunction<const N: usize, const M: usize> {
        // indices[j] = i_j is the mapping of indices of [_; N] to indices of [_; M].
        // it seems fine to be made public, but only the prover needs it, so it is simpler to store
        // it here.
        pub(crate) indices: [usize; N],
        pub(crate) rng: Arc<Mutex<dyn SecureRandom>>,
    }
    impl<const N: usize, const M: usize> SigmaProtocol for Disjunction<N, M> {
        type Instance = DisjunctionInstance<N, M>;
        type Witness = DisjunctionWitness<N, M>;
        type Commitment = [(Point, Point); N];
        type ProverState = [(Scalar, Scalar); N];
        type Challenge = Scalar;
        type Response = [(Scalar, Scalar); N];
        const DOMAIN_SEP: &'static str = "setmem";
        /// Only difference from before is that the ciphertext (alpha, beta) may change within
        /// loops.
        fn commitment(
            &self,
            x: &Self::Instance,
            wit: &Self::Witness,
        ) -> (Self::Commitment, Self::ProverState) {
            let mut com: Self::Commitment =
                array_init(|_: usize| (Point::default(), Point::default()));
            let mut ps: Self::ProverState =
                array_init(|_: usize| (Scalar::default(), Scalar::default()));
            for i in 0..N {
                let rho = random_scalar(self.rng.clone());
                let sigma = random_scalar(self.rng.clone());
                ps[i] = (sigma.into(), rho.into());
            }
            ps[wit.i].0 = Scalar::default();
            let h = &x.h;
            for i in 0..N {
                let (alpha_i, beta_i) = (&x.ctxt[self.indices[i]]).into();
                let (sigma_i, rho_i) = (&ps[i].0, &ps[i].1);
                let v_i = &x.FinSet[self.indices[i]];
                let A = Point(RISTRETTO_BASEPOINT_POINT * rho_i.0 + (alpha_i.0 * (-sigma_i.0)));
                let B = Point(
                    (rho_i.0 * h.0)
                        + ((beta_i.0 + (-v_i.0 * RISTRETTO_BASEPOINT_POINT)) * (-sigma_i.0)),
                );
                com[i] = (A, B);
            }
            (com, ps)
        }
        fn challenge(&self, x: &Self::Instance, com: &Self::Commitment) -> Self::Challenge {
            let mut data: Vec<u8> = Self::DOMAIN_SEP.clone().into();
            data.extend(x.h.0.compress().as_bytes());
            for ctxt in x.ctxt.iter() {
                let (alpha_i, beta_i) = ctxt.into();
                data.extend(alpha_i.0.compress().as_bytes());
                data.extend(beta_i.0.compress().as_bytes());
            }
            for bytestr in x.FinSet.iter().map(|s: &Scalar| *s.0.as_bytes()) {
                data.extend(bytestr);
            }
            for (A, B) in com.iter() {
                data.extend(A.0.compress().as_bytes());
                data.extend(B.0.compress().as_bytes());
            }
            hash_to_scalar(&data)
        }
        fn response(
            &self,
            wit: &Self::Witness,
            ps: &Self::ProverState,
            c: &Self::Challenge,
        ) -> Self::Response {
            let mut resp = ps.clone();
            let mut sigma = c.clone().0;
            for i in 0..N {
                if i != wit.i {
                    let (sigma_i, _) = &ps[i];
                    sigma -= sigma_i.0;
                }
            }
            // We stored w in the rho component of the ith index of the prover state.
            let w = ps[wit.i].1 .0;
            let rho = w + (wit.rs[self.indices[wit.i]].0 * sigma);
            resp[wit.i] = (Scalar(sigma), Scalar(rho));
            resp
        }
        fn result(
            &self,
            x: &Self::Instance,
            com: &Self::Commitment,
            chal: &Self::Challenge,
            response: &Self::Response,
        ) -> bool {
            let h = &x.h;
            let mut sigma = Scalar::default().0;
            for i in 0..N {
                let (alpha_i, beta_i) = (&x.ctxt[self.indices[i]]).into();
                let (expected_A, expected_B) = (&com[i].0, &com[i].1);
                let (sigma_i, rho_i) = (&response[i].0, &response[i].1);
                sigma += sigma_i.0;
                /*
                let A_i = Point((RISTRETTO_BASEPOINT_POINT * rho_i.0) + (alpha.0 * -sigma_i.0));
                let B_i = Point(
                    (rho_i.0 * h.0)
                        + ((beta.0 + (-M[i].0 * RISTRETTO_BASEPOINT_POINT)) * (-sigma_i.0)),
                );
                */
                let A_i = Point((RISTRETTO_BASEPOINT_POINT * rho_i.0) + (alpha_i.0 * -sigma_i.0));
                let B_i = Point(
                    (rho_i.0 * h.0)
                        + ((beta_i.0 + (-x.FinSet[i].0 * RISTRETTO_BASEPOINT_POINT))
                            * (-sigma_i.0)),
                );
                if *expected_A != A_i || *expected_B != B_i {
                    return false;
                }
            }
            // still need to check sigma
            sigma == chal.0
        }
    }
}

#[cfg(test)]
/// Completeness/Soundness tests for our NIZKs.
/// We test completeness by generating random instances of statements to prove, and ensuring they
/// are correctly verified.
/// We test soundness by generating random instances of statements to prove, and then resampling
/// (at least part of) the witness, and ensuring the proofs are now rejected.
/// More in-depth testing would implement extractors (as the ZKPs are special sound).
/// We do not do this due to time requirements.
mod tests {
    use array_init::array_init;
    use ring::rand::SystemRandom;

    use super::*;
    const TRIALS: usize = 100;
    #[test]
    fn dlog_complete() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Public Parameters
        let PP = DLog::DLog { rng };
        for _ in 0..TRIALS {
            let w: DLog::DLogWitness = DLog::DLogWitness(random_scalar(PP.rng.clone()));
            let x = DLog::DLogInstance(Point(RISTRETTO_BASEPOINT_POINT * w.0 .0));
            let p = PP.prove(&x, &w);
            assert!(PP.verify(&x, &p));
        }
    }
    #[test]
    fn dlog_sound() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Public Parameters
        let PP = DLog::DLog { rng };
        for _ in 0..TRIALS {
            let w: DLog::DLogWitness = DLog::DLogWitness(random_scalar(PP.rng.clone()));
            let x = DLog::DLogInstance(Point(RISTRETTO_BASEPOINT_POINT * w.0 .0));
            let other_w: DLog::DLogWitness = DLog::DLogWitness(random_scalar(PP.rng.clone()));
            let p = PP.prove(&x, &other_w);
            assert!(!PP.verify(&x, &p));
        }
    }
    #[test]
    fn cordec_complete() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Public Parameters
        let PP = CorDec::CorDec { rng };
        for _ in 0..TRIALS {
            let x = random_scalar(PP.rng.clone());
            let h = Point(x.0 * RISTRETTO_BASEPOINT_POINT);
            let C = random_point(PP.rng.clone());
            let M = Point(x.0 * C.0);
            let w: CorDec::CorDecWitness = CorDec::CorDecWitness { x };
            let x: CorDec::CorDecInstance = CorDec::CorDecInstance { C, M, h };
            let p = PP.prove(&x, &w);
            assert!(PP.verify(&x, &p));
        }
    }
    #[test]
    fn cordec_sound() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Public Parameters
        let PP = CorDec::CorDec { rng };
        for _ in 0..TRIALS {
            let x = random_scalar(PP.rng.clone());
            let h = Point(x.0 * RISTRETTO_BASEPOINT_POINT);
            let C = random_point(PP.rng.clone());
            let M = Point(x.0 * C.0);
            let fake_x = random_scalar(PP.rng.clone());
            let w: CorDec::CorDecWitness = CorDec::CorDecWitness { x: fake_x };
            let x: CorDec::CorDecInstance = CorDec::CorDecInstance { C, M, h };
            let p = PP.prove(&x, &w);
            assert!(!PP.verify(&x, &p));
        }
    }
    #[test]
    fn setmem_complete() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Most common case will be proving M_i in {0,1} so we will focus on this case.
        const N: usize = 2;
        // Public Parameters
        let PP = SetMem::SetMem::<N> { rng };
        let FinSet = [
            Scalar(scalar::Scalar::zero()),
            Scalar(scalar::Scalar::one()),
        ];
        for _ in 0..TRIALS {
            let x = random_scalar(PP.rng.clone());
            let h = Point(x.0 * RISTRETTO_BASEPOINT_POINT);
            let r = random_scalar(PP.rng.clone());
            for i in 0..2 {
                let ctxt = (
                    Point(RISTRETTO_BASEPOINT_POINT * &r.0),
                    Point((&h.0 * r.0) + (&FinSet[i].0 * RISTRETTO_BASEPOINT_POINT)),
                );
                let w = SetMem::SetMemWitness { r: r.clone(), i };
                let x = SetMem::SetMemInstance {
                    h: h.clone(),
                    ctxt: ctxt.into(),
                    FinSet: FinSet.clone(),
                };
                let p = PP.prove(&x, &w);
                assert!(PP.verify(&x, &p));
            }
        }
    }
    #[test]
    fn setmem_sound() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Most common case will be proving M_i in {0,1} so we will focus on this case.
        const N: usize = 2;
        // Public Parameters
        let PP = SetMem::SetMem::<N> { rng };
        let FinSet = [
            Scalar(scalar::Scalar::zero()),
            Scalar(scalar::Scalar::one()),
        ];
        for _ in 0..TRIALS {
            let x = random_scalar(PP.rng.clone());
            let h = Point(x.0 * RISTRETTO_BASEPOINT_POINT);
            let r = random_scalar(PP.rng.clone());
            for i in 0..2 {
                let ctxt = (
                    Point(RISTRETTO_BASEPOINT_POINT * &r.0),
                    Point((&h.0 * r.0) + (&FinSet[i].0 * RISTRETTO_BASEPOINT_POINT)),
                );
                // sampling a new r, e.g. using a wrong witness.
                let r = random_scalar(PP.rng.clone());
                let w = SetMem::SetMemWitness { r: r.clone(), i };
                let x = SetMem::SetMemInstance {
                    h: h.clone(),
                    ctxt: ctxt.into(),
                    FinSet: FinSet.clone(),
                };
                let p = PP.prove(&x, &w);
                assert!(!PP.verify(&x, &p));
            }
        }
    }
    #[test]
    fn disj_complete() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Most common case will be proving M_i in {0,1} so we will focus on this case.
        const N: usize = 2;
        const M: usize = 2;
        // Public Parameters
        let indices = [0, 1];
        let PP = Disjunction::Disjunction::<N, M> { rng, indices };
        let FinSet = [
            Scalar(scalar::Scalar::zero()),
            Scalar(scalar::Scalar::one()),
        ];
        // Will be proving the first ciphertext encrypts FinSet[0] = 0;
        for _ in 0..TRIALS {
            let x = random_scalar(PP.rng.clone());
            let h = Point(x.0 * RISTRETTO_BASEPOINT_POINT);
            let rs: [Scalar; M] = array_init(|_: usize| random_scalar(PP.rng.clone()));
            // Using random messages m_i, as they are not needed for any later part of the proof.
            // Hard-coding m_0 = 0 though, so we can later prove this value occurs.
            let ctxts: [Ciphertext; M] = array_init(|i: usize| {
                (
                    Point(&rs[i].0 * RISTRETTO_BASEPOINT_POINT),
                    Point(
                        (h.0 * rs[i].0)
                            + (RISTRETTO_BASEPOINT_POINT * {
                                if i == 0 {
                                    Scalar::default().0
                                } else {
                                    random_scalar(PP.rng.clone()).0
                                }
                            }),
                    ),
                )
                    .into()
            });
            let x: Disjunction::DisjunctionInstance<N, M> = Disjunction::DisjunctionInstance {
                h: h.clone(),
                ctxt: ctxts,
                FinSet: FinSet.clone(),
            };
            let w: Disjunction::DisjunctionWitness<N, M> =
                Disjunction::DisjunctionWitness { rs, i: 0 };
            let p = PP.prove(&x, &w);
            assert!(PP.verify(&x, &p));
        }
    }
    #[test]
    fn disj_sound() {
        let rng = Arc::new(Mutex::new(SystemRandom::new()));
        // Most common case will be proving M_i in {0,1} so we will focus on this case.
        const N: usize = 2;
        const M: usize = 2;
        // Public Parameters
        let indices = [0, 1];
        let PP = Disjunction::Disjunction::<N, M> { rng, indices };
        let FinSet = [
            Scalar(scalar::Scalar::zero()),
            Scalar(scalar::Scalar::one()),
        ];
        // Will be proving the first ciphertext encrypts FinSet[0] = 0;
        for _ in 0..TRIALS {
            let x = random_scalar(PP.rng.clone());
            let h = Point(x.0 * RISTRETTO_BASEPOINT_POINT);
            let rs: [Scalar; M] = array_init(|_: usize| random_scalar(PP.rng.clone()));
            // Using random messages m_i, as they are not needed for any later part of the proof.
            // Hard-coding m_0 = 0 though, so we can later prove this value occurs.
            let ctxts: [Ciphertext; M] = array_init(|i: usize| {
                (
                    Point(&rs[i].0 * RISTRETTO_BASEPOINT_POINT),
                    Point(
                        (h.0 * rs[i].0)
                            + (RISTRETTO_BASEPOINT_POINT * {
                                if i == 0 {
                                    Scalar::default().0
                                } else {
                                    random_scalar(PP.rng.clone()).0
                                }
                            }),
                    ),
                )
                    .into()
            });
            let x: Disjunction::DisjunctionInstance<N, M> = Disjunction::DisjunctionInstance {
                h: h.clone(),
                ctxt: ctxts,
                FinSet: FinSet.clone(),
            };
            // resampling the encryption randomness.
            let rs: [Scalar; M] = array_init(|_: usize| random_scalar(PP.rng.clone()));
            let w: Disjunction::DisjunctionWitness<N, M> =
                Disjunction::DisjunctionWitness { rs, i: 0 };
            let p = PP.prove(&x, &w);
            assert!(!PP.verify(&x, &p));
        }
    }
}
