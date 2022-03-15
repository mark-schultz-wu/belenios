An implementation of the [Belenios e-voting system](https://www.belenios.org/) in Rust.
The following resources are useful in understanding the scheme, namely a

* [paper presenting the scheme](https://hal.inria.fr/hal-02066930/document), an
* [OCaml implementation](https://gitlab.inria.fr/belenios/belenios), a
* [specification of the implementation](https://www.belenios.org/specification.pdf), and a
* [analysis of the ZKPs in the implemntation](https://hal.inria.fr/hal-01576379/document).

Roughly speaking, implementing Belenious requires the following cryptographic
primitives, namely

* El Gamal encryption over some group G,
* (Domain-separated) hashing into that same group G
* Schnorr signatures over that same group G, and
* Zero-Knowledge proofs

The Zero-Knowledge proofs needed are specified in the above specification.
They can be summarized as
* proof of knowledge of a discrete logarithm,
* proof of correct (El Gamal) decryption,
* proof that a dlog belongs to a finite set, and
* a disjunction proof of certain equalities.

I am implementing this as part of a job application, so (initially) plan on only
spending ~7 days on it. A particular summary of the current project is to 

There are some natural extensions of this protocol, namely

* BeleniosRF, which is "receipt free" --- dishonest parties cannot prove how
  they have voted, and
* BeleniosVF, which protects against malicious voting devices via a "voting
  sheet".
* There is a ``non-homomorphic'' variant (using mixnets to tally votes) that is
  more general, that I am initially not considering.
* There is also a variant that (using threshold decryption) supports multiple
  trustees

I will not target these initially, but have made some initial decisions (namely
the el-gamal encryption library) to hopefully ease future implementation.

Note that the plan is **NOT** to provide an implementation of Belenios that is
exactly compatible with the existing implementation (meaning any "test vectors"
of the existing implementation should *fail*).
This is because, given excellent Rust libraries existing for elliptic
curve-based cryptography, it seems obvious for the implementation to be in terms
of elliptic curves rather than  finite fields.

Due to the above (large) difference, I am being less careful with getting other
parts of the implementation to exactly match up. For example, the library I am
using for `base58` encoding and decoding includes a checksum calculation
(similarly to Belenios).
I will not ensure the checksums are computed in the *exact* same way though, as
the goal is not compatability at the test vector level.

Things to potentially do:
* depend on UUID crate explicitly,

