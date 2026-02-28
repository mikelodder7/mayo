// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO post-quantum signature scheme.
//!
//! This crate implements the [MAYO](https://pqmayo.org/) signature scheme, a
//! post-quantum multivariate-based signature scheme submitted to the NIST PQC
//! standardization process. MAYO is based on the "oil and vinegar" trapdoor
//! and produces compact signatures with small public keys relative to other
//! multivariate schemes.
//!
//! # Supported Parameter Sets
//!
//! | Type | Security Level | Signature Size | Public Key Size |
//! |---------|----------------|----------------|-----------------|
//! | [`Mayo1`] | 1 | 454 bytes | 1,420 bytes |
//! | [`Mayo2`] | 2 | 186 bytes | 4,912 bytes |
//! | [`Mayo3`] | 3 | 681 bytes | 2,986 bytes |
//! | [`Mayo5`] | 5 | 964 bytes | 5,554 bytes |
//!
//! All parameter sets implement the [`MayoParameter`] trait and can be used
//! interchangeably as the generic parameter on [`KeyPair`], [`SigningKey`],
//! [`VerifyingKey`], and [`Signature`].
//!
//! # Quick Start
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
//!
//! # Choosing a Parameter Set
//!
//! Select the parameter set that matches your target NIST security level.
//! Higher security levels provide stronger guarantees but produce larger
//! keys and signatures.
//!
//! ```
//! use pq_mayo::{KeyPair, Mayo1, Mayo2, Mayo3, Mayo5};
//! use signature::{Signer, Verifier};
//!
//! let mut rng = rand::rng();
//!
//! // NIST security level 1 — smallest signatures
//! let kp1 = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
//!
//! // NIST security level 2 — smallest signatures overall (186 bytes)
//! let kp2 = KeyPair::<Mayo2>::generate(&mut rng).expect("keygen");
//! let sig = kp2.signing_key().try_sign(b"message").expect("sign");
//! kp2.verifying_key().verify(b"message", &sig).expect("verify");
//!
//! // NIST security level 3
//! let kp3 = KeyPair::<Mayo3>::generate(&mut rng).expect("keygen");
//!
//! // NIST security level 5 — strongest security
//! let kp5 = KeyPair::<Mayo5>::generate(&mut rng).expect("keygen");
//! ```
//!
//! # Key Serialization
//!
//! Keys and signatures implement [`AsRef<[u8]>`] for exporting raw bytes
//! and [`TryFrom<&[u8]>`] for importing them. This allows easy
//! integration with any transport or storage layer.
//!
//! ```
//! use pq_mayo::{KeyPair, Mayo1, SigningKey, VerifyingKey, Signature};
//! use signature::{Signer, Verifier};
//!
//! let mut rng = rand::rng();
//! let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
//!
//! // Export keys as raw bytes
//! let sk_bytes: &[u8] = keypair.signing_key().as_ref();
//! let vk_bytes: &[u8] = keypair.verifying_key().as_ref();
//!
//! // Reconstruct keys from bytes
//! let sk = SigningKey::<Mayo1>::try_from(sk_bytes).expect("valid signing key");
//! let vk = VerifyingKey::<Mayo1>::try_from(vk_bytes).expect("valid verifying key");
//!
//! // Sign with reconstructed key, verify with reconstructed key
//! let sig = sk.try_sign(b"hello").expect("sign");
//! vk.verify(b"hello", &sig).expect("verify");
//!
//! // Signatures can also be round-tripped through bytes
//! let sig_bytes: &[u8] = sig.as_ref();
//! let sig2 = Signature::<Mayo1>::try_from(sig_bytes).expect("valid signature");
//! vk.verify(b"hello", &sig2).expect("verify restored sig");
//! ```
//!
//! # Deriving a Verifying Key from a Signing Key
//!
//! A [`VerifyingKey`] can be derived from a [`SigningKey`] without
//! needing the original [`KeyPair`]. This is useful when only the
//! secret key was stored or transmitted.
//!
//! ```
//! use pq_mayo::{KeyPair, Mayo1, VerifyingKey};
//! use signature::{Signer, Verifier};
//!
//! let mut rng = rand::rng();
//! let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
//!
//! let vk = VerifyingKey::<Mayo1>::from(keypair.signing_key());
//! assert_eq!(&vk, keypair.verifying_key());
//!
//! let sig = keypair.signing_key().try_sign(b"test").expect("sign");
//! vk.verify(b"test", &sig).expect("verify");
//! ```
//!
//! # Deterministic Key Generation from a Seed
//!
//! [`KeyPair::from_seed`] generates a keypair deterministically from a
//! fixed-length seed. The seed length depends on the parameter set
//! (24 bytes for Mayo1/Mayo2, 32 bytes for Mayo3, 40 bytes for Mayo5).
//!
//! ```
//! use pq_mayo::{KeyPair, Mayo1};
//!
//! let seed = [42u8; 24]; // Mayo1 requires a 24-byte seed
//! let kp1 = KeyPair::<Mayo1>::from_seed(&seed).expect("from seed");
//! let kp2 = KeyPair::<Mayo1>::from_seed(&seed).expect("from seed");
//!
//! // Same seed always produces the same keypair
//! assert_eq!(
//!     kp1.verifying_key().as_ref(),
//!     kp2.verifying_key().as_ref()
//! );
//! ```
//!
//! # Signing with a Caller-Provided RNG
//!
//! The [`SigningKey::sign_with_rng`] method allows passing a custom
//! [`CryptoRng`](rand::CryptoRng) for salt generation. This is useful
//! for reproducible testing or when a specific entropy source is required.
//!
//! ```
//! use pq_mayo::{KeyPair, Mayo1};
//! use signature::Verifier;
//!
//! let mut rng = rand::rng();
//! let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
//!
//! let sig = keypair.signing_key().sign_with_rng(&mut rng, b"data").expect("sign");
//! keypair.verifying_key().verify(b"data", &sig).expect("verify");
//! ```
//!
//! # Error Handling
//!
//! All fallible operations return [`error::Result<T>`](error::Result), which
//! uses the [`Error`] enum. Key and signature deserialization validate lengths
//! and will return descriptive errors on mismatch.
//!
//! ```
//! use pq_mayo::{Error, SigningKey, VerifyingKey, Signature, Mayo1};
//!
//! // Wrong-length byte slices are rejected
//! let result = SigningKey::<Mayo1>::try_from(&[0u8; 3][..]);
//! assert!(result.is_err());
//!
//! let result = VerifyingKey::<Mayo1>::try_from(&[0u8; 3][..]);
//! assert!(result.is_err());
//!
//! let result = Signature::<Mayo1>::try_from(&[0u8; 3][..]);
//! assert!(result.is_err());
//! ```
//!
//! # Serde Support
//!
//! Enable the `serde` feature for serialization with any serde-compatible
//! format. Keys and signatures are serialized as hex strings in
//! human-readable formats (JSON, TOML, YAML) and as raw bytes in binary
//! formats (bincode, postcard, CBOR).
//!
//! ```toml
//! [dependencies]
//! pq-mayo = { version = "0.1", features = ["serde"] }
//! ```
//!
//! ```rust,ignore
//! use pq_mayo::{KeyPair, Mayo1};
//!
//! let mut rng = rand::rng();
//! let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");
//!
//! // JSON (human-readable, hex-encoded)
//! let json = serde_json::to_string(&keypair).expect("serialize");
//! let restored: KeyPair<Mayo1> = serde_json::from_str(&json).expect("deserialize");
//! assert_eq!(keypair, restored);
//!
//! // Postcard (binary, compact)
//! let bytes = postcard::to_stdvec(&keypair).expect("serialize");
//! let restored: KeyPair<Mayo1> = postcard::from_bytes(&bytes).expect("deserialize");
//! assert_eq!(keypair, restored);
//! ```
//!
//! # WebAssembly Support
//!
//! This crate compiles to `wasm32-unknown-unknown` using pure Rust
//! implementations for all cryptographic primitives. Enable the `js`
//! feature to use the browser's `crypto.getRandomValues` for randomness:
//!
//! ```toml
//! [dependencies]
//! pq-mayo = { version = "0.1", features = ["js"] }
//! ```
//!
//! # Security Considerations
//!
//! - All operations are implemented in **constant time** to resist
//!   timing side-channel attacks. There are no secret-dependent branches
//!   or memory accesses.
//! - Signing keys are **zeroized on drop** via the [`zeroize`](https://docs.rs/zeroize)
//!   crate to prevent secret material from lingering in memory.
//! - The [`Debug`](core::fmt::Debug) implementation for [`SigningKey`] redacts
//!   the key bytes, printing `**FILTERED**` instead.

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
