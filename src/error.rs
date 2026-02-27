// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for the MAYO signature scheme.

/// Errors that can occur during MAYO operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Key generation failed.
    #[error("key generation failed")]
    KeyGeneration,
    /// Signing failed.
    #[error("signing failed")]
    Signing,
    /// Signature verification failed.
    #[error("verification failed")]
    VerificationFailed,
    /// Invalid key length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// Invalid signature length.
    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// Invalid seed length.
    #[error("invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
}

impl From<Error> for signature::Error {
    fn from(e: Error) -> Self {
        signature::Error::from_source(e.to_string())
    }
}

/// Result type alias using [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
