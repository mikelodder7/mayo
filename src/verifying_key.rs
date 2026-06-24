// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO verifying (public) key.

use crate::error::Error;
use crate::mayo_signature::Signature;
use crate::params::MayoParameter;
use crate::signing_key::SigningKey;
use crate::verify::{
    VerifyScratch, expand_public_key, mayo_verify, mayo_verify_with_expanded_pk,
    mayo_verify_with_expanded_pk_and_scratch,
};
use core::marker::PhantomData;

/// A MAYO verifying key (compact public key).
#[derive(Clone)]
pub struct VerifyingKey<P: MayoParameter> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) _marker: PhantomData<P>,
}

impl<P: MayoParameter> AsRef<[u8]> for VerifyingKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: MayoParameter> TryFrom<&[u8]> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::CPK_BYTES {
            return Err(Error::InvalidKeyLength {
                expected: P::CPK_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self::from_bytes_unchecked(bytes.to_vec()))
    }
}

impl<P: MayoParameter> TryFrom<Vec<u8>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() != P::CPK_BYTES {
            return Err(Error::InvalidKeyLength {
                expected: P::CPK_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self::from_bytes_unchecked(bytes))
    }
}

impl<P: MayoParameter> TryFrom<&Vec<u8>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: MayoParameter> TryFrom<Box<[u8]>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        if bytes.len() != P::CPK_BYTES {
            return Err(Error::InvalidKeyLength {
                expected: P::CPK_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self::from_bytes_unchecked(bytes.into_vec()))
    }
}

impl<P: MayoParameter> PartialEq for VerifyingKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: MayoParameter> Eq for VerifyingKey<P> {}

impl<P: MayoParameter> core::fmt::Debug for VerifyingKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("variant", &P::NAME)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: MayoParameter> From<&SigningKey<P>> for VerifyingKey<P> {
    fn from(sk: &SigningKey<P>) -> Self {
        Self::from_bytes_unchecked(sk.cpk.clone())
    }
}

impl<P: MayoParameter> signature::Verifier<Signature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &Signature<P>) -> Result<(), signature::Error> {
        mayo_verify::<P>(msg, signature.as_ref(), &self.bytes).map_err(Into::into)
    }
}

impl<P: MayoParameter> VerifyingKey<P> {
    pub(crate) fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Expand this compact verifying key for faster repeated verification.
    pub fn expand(&self) -> ExpandedVerifyingKey<P> {
        ExpandedVerifyingKey::from_bytes_unchecked(self.bytes.clone())
    }
}

/// A MAYO verifying key with cached expanded public material.
///
/// This keeps the compact public key bytes for serialization and equality,
/// and additionally stores expanded public data used by verification.
#[derive(Clone)]
pub struct ExpandedVerifyingKey<P: MayoParameter> {
    bytes: Vec<u8>,
    expanded_pk: Vec<u64>,
    p3: Vec<u64>,
    _marker: PhantomData<P>,
}

/// A reusable MAYO verification context.
///
/// This stores an expanded verifying key plus mutable scratch buffers for
/// repeated verification with the same public key.
pub struct VerificationContext<P: MayoParameter> {
    key: ExpandedVerifyingKey<P>,
    scratch: VerifyScratch,
}

impl<P: MayoParameter> AsRef<[u8]> for ExpandedVerifyingKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: MayoParameter> TryFrom<&[u8]> for ExpandedVerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        VerifyingKey::<P>::try_from(bytes).map(|vk| vk.expand())
    }
}

impl<P: MayoParameter> TryFrom<Vec<u8>> for ExpandedVerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() != P::CPK_BYTES {
            return Err(Error::InvalidKeyLength {
                expected: P::CPK_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self::from_bytes_unchecked(bytes))
    }
}

impl<P: MayoParameter> TryFrom<&Vec<u8>> for ExpandedVerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: MayoParameter> TryFrom<Box<[u8]>> for ExpandedVerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.into_vec())
    }
}

impl<P: MayoParameter> From<&VerifyingKey<P>> for ExpandedVerifyingKey<P> {
    fn from(vk: &VerifyingKey<P>) -> Self {
        vk.expand()
    }
}

impl<P: MayoParameter> From<&SigningKey<P>> for ExpandedVerifyingKey<P> {
    fn from(sk: &SigningKey<P>) -> Self {
        Self::from_bytes_unchecked(sk.cpk.clone())
    }
}

impl<P: MayoParameter> PartialEq for ExpandedVerifyingKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: MayoParameter> Eq for ExpandedVerifyingKey<P> {}

impl<P: MayoParameter> PartialEq for VerificationContext<P> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<P: MayoParameter> Eq for VerificationContext<P> {}

impl<P: MayoParameter> core::fmt::Debug for ExpandedVerifyingKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExpandedVerifyingKey")
            .field("variant", &P::NAME)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: MayoParameter> core::fmt::Debug for VerificationContext<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerificationContext")
            .field("variant", &P::NAME)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl<P: MayoParameter> signature::Verifier<Signature<P>> for ExpandedVerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &Signature<P>) -> Result<(), signature::Error> {
        mayo_verify_with_expanded_pk::<P>(msg, signature.as_ref(), &self.expanded_pk, &self.p3)
            .map_err(Into::into)
    }
}

impl<P: MayoParameter> ExpandedVerifyingKey<P> {
    fn from_bytes_unchecked(bytes: Vec<u8>) -> Self {
        let (expanded_pk, p3) = expand_public_key::<P>(&bytes);
        Self {
            bytes,
            expanded_pk,
            p3,
            _marker: PhantomData,
        }
    }

    /// Return the compact verifying key form.
    pub fn compact(&self) -> VerifyingKey<P> {
        VerifyingKey::from_bytes_unchecked(self.bytes.clone())
    }

    /// Create a reusable verification context for this expanded key.
    pub fn context(&self) -> VerificationContext<P> {
        VerificationContext::from(self)
    }
}

impl<P: MayoParameter> VerificationContext<P> {
    /// Verify a signature using cached expanded public material and scratch buffers.
    pub fn verify(&mut self, msg: &[u8], signature: &Signature<P>) -> Result<(), signature::Error> {
        mayo_verify_with_expanded_pk_and_scratch::<P>(
            msg,
            signature.as_ref(),
            &self.key.expanded_pk,
            &self.key.p3,
            &mut self.scratch,
        )
        .map_err(Into::into)
    }

    /// Return the expanded verifying key backing this context.
    pub fn verifying_key(&self) -> &ExpandedVerifyingKey<P> {
        &self.key
    }
}

impl<P: MayoParameter> From<&ExpandedVerifyingKey<P>> for VerificationContext<P> {
    fn from(key: &ExpandedVerifyingKey<P>) -> Self {
        Self {
            key: key.clone(),
            scratch: VerifyScratch::new::<P>(),
        }
    }
}

impl<P: MayoParameter> From<&VerifyingKey<P>> for VerificationContext<P> {
    fn from(key: &VerifyingKey<P>) -> Self {
        Self::from(&key.expand())
    }
}

#[cfg(feature = "serde")]
impl<P: MayoParameter> serde::Serialize for VerifyingKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: MayoParameter> serde::Deserialize<'de> for VerifyingKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<P: MayoParameter> serde::Serialize for ExpandedVerifyingKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: MayoParameter> serde::Deserialize<'de> for ExpandedVerifyingKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serde::de::Error::custom)
    }
}
