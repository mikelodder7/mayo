// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO post-quantum signature scheme.
//!
//! This crate implements the MAYO signature scheme, a post-quantum
//! multivariate-based signature scheme submitted to the NIST PQC
//! standardization process.
//!
//! # Supported Parameter Sets
//!
//! - [`Mayo1`] - NIST security level 1
//! - [`Mayo2`] - NIST security level 2
//! - [`Mayo3`] - NIST security level 3
//! - [`Mayo5`] - NIST security level 5
//!
//! # Example
//!
//! ```
//! use pq_mayo::{KeyPair, Mayo1};
//! use signature::{Signer, Verifier};
//!
//! let mut rng = rand::rng();
//! let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
//! let msg = b"hello world";
//!
//! let sig = keypair.signing_key().try_sign(msg).expect("sign");
//! keypair.verifying_key().verify(msg, &sig).expect("verify");
//! ```

pub mod error;
pub mod keypair;
pub mod mayo_signature;
pub mod params;
pub mod signing_key;
pub mod verifying_key;

mod bitsliced;
mod codec;
mod echelon;
mod gf16;
mod keygen;
mod matrix_ops;
mod sample;
mod sign;
mod verify;

pub use error::Error;
pub use keypair::KeyPair;
pub use mayo_signature::Signature;
pub use params::{Mayo1, Mayo2, Mayo3, Mayo5, MayoParameter};
pub use signing_key::SigningKey;
pub use verifying_key::VerifyingKey;

#[cfg(feature = "serde")]
#[cfg(test)]
mod tests {
    use super::*;
    use signature::Signer;

    fn keypair_serde<P: MayoParameter>() {
        let mut rng = rand::rng();
        let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
        let serialized = serde_json::to_string(&keypair).expect("serialize");
        let deserialized: KeyPair<P> = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(keypair, deserialized);

        let serialized = postcard::to_stdvec(&keypair).expect("serialize");
        let deserialized: KeyPair<P> = postcard::from_bytes(&serialized).expect("deserialize");
        assert_eq!(keypair, deserialized);
    }

    fn signing_key_serde<P: MayoParameter>() {
        let mut rng = rand::rng();
        let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
        let serialized = serde_json::to_string(keypair.signing_key()).expect("serialize");
        let deserialized: SigningKey<P> = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(keypair.signing_key(), &deserialized);

        let serialized = postcard::to_stdvec(keypair.signing_key()).expect("serialize");
        let deserialized: SigningKey<P> = postcard::from_bytes(&serialized).expect("deserialize");
        assert_eq!(keypair.signing_key(), &deserialized);
    }

    fn verifying_key_serde<P: MayoParameter>() {
        let mut rng = rand::rng();
        let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
        let serialized = serde_json::to_string(keypair.verifying_key()).expect("serialize");
        let deserialized: VerifyingKey<P> = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(keypair.verifying_key(), &deserialized);

        let serialized = postcard::to_stdvec(keypair.verifying_key()).expect("serialize");
        let deserialized: VerifyingKey<P> = postcard::from_bytes(&serialized).expect("deserialize");
        assert_eq!(keypair.verifying_key(), &deserialized);
    }

    fn signature_serde<P: MayoParameter>() {
        let mut rng = rand::rng();
        let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
        let msg = b"hello world";
        let sig = keypair.signing_key().try_sign(msg).expect("sign");
        let serialized = serde_json::to_string(&sig).expect("serialize");
        let deserialized: Signature<P> = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(sig, deserialized);

        let serialized = postcard::to_stdvec(&sig).expect("serialize");
        let deserialized: Signature<P> = postcard::from_bytes(&serialized).expect("deserialize");
        assert_eq!(sig, deserialized);
    }

    #[test]
    fn keypair_serde_mayo1() {
        keypair_serde::<Mayo1>();
    }
    #[test]
    fn keypair_serde_mayo2() {
        keypair_serde::<Mayo2>();
    }
    #[test]
    fn keypair_serde_mayo3() {
        keypair_serde::<Mayo3>();
    }
    #[test]
    fn keypair_serde_mayo5() {
        keypair_serde::<Mayo5>();
    }

    #[test]
    fn signing_key_serde_mayo1() {
        signing_key_serde::<Mayo1>();
    }
    #[test]
    fn signing_key_serde_mayo2() {
        signing_key_serde::<Mayo2>();
    }
    #[test]
    fn signing_key_serde_mayo3() {
        signing_key_serde::<Mayo3>();
    }
    #[test]
    fn signing_key_serde_mayo5() {
        signing_key_serde::<Mayo5>();
    }

    #[test]
    fn verifying_key_serde_mayo1() {
        verifying_key_serde::<Mayo1>();
    }
    #[test]
    fn verifying_key_serde_mayo2() {
        verifying_key_serde::<Mayo2>();
    }
    #[test]
    fn verifying_key_serde_mayo3() {
        verifying_key_serde::<Mayo3>();
    }
    #[test]
    fn verifying_key_serde_mayo5() {
        verifying_key_serde::<Mayo5>();
    }

    #[test]
    fn signature_serde_mayo1() {
        signature_serde::<Mayo1>();
    }
    #[test]
    fn signature_serde_mayo2() {
        signature_serde::<Mayo2>();
    }
    #[test]
    fn signature_serde_mayo3() {
        signature_serde::<Mayo3>();
    }
    #[test]
    fn signature_serde_mayo5() {
        signature_serde::<Mayo5>();
    }
}
