// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO verifying (public) key.

use crate::error::Error;
use crate::keypair::derive_cpk_from_csk;
use crate::mayo_signature::Signature;
use crate::params::MayoParameter;
use crate::signing_key::SigningKey;
use crate::verify::mayo_verify;
use core::marker::PhantomData;

/// A MAYO verifying key (compact public key).
#[derive(Clone)]
pub struct VerifyingKey<P: MayoParameter> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
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
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: MayoParameter> TryFrom<Vec<u8>> for VerifyingKey<P> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
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
        Self::try_from(bytes.as_ref())
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
        let mut cpk = vec![0u8; P::CPK_BYTES];
        derive_cpk_from_csk::<P>(sk.as_ref(), &mut cpk);
        Self {
            bytes: cpk,
            _marker: PhantomData,
        }
    }
}

impl<P: MayoParameter> signature::Verifier<Signature<P>> for VerifyingKey<P> {
    fn verify(&self, msg: &[u8], signature: &Signature<P>) -> Result<(), signature::Error> {
        mayo_verify::<P>(msg, signature.as_ref(), &self.bytes).map_err(Into::into)
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
