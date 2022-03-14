An implementation of the [Belenios e-voting system](https://www.belenios.org/) in Rust.
The following resources are useful in understanding the scheme, namely a

* [paper presenting the scheme](https://hal.inria.fr/hal-02066930/document), an
* [OCaml implementation](https://gitlab.inria.fr/belenios/belenios)), a
* [specification of the implementation](https://www.belenios.org/specification.pdf)), and a
* [analysis of the ZKPs in the implemntation](https://hal.inria.fr/hal-01576379/document).

Roughly speaking, implementing Belenious requires the following cryptographic
primitives, namely

* El Gamal encryption over some group G,
* (Domain-separated) hashing into that same group G
* Schnorr signatures over that same group G, and
* Zero-Knowledge proofs

The Zero-Knowledge proofs needed are
* Proofs of knowledge of a discrete logarithm,
* Proof that an (El Gamal) ciphertext encrypts an element of a (public) finite set V, and
* Proof of correct (El Gamal) decryption.

