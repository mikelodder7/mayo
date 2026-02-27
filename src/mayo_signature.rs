// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO signature type.

use crate::error::Error;
use crate::params::MayoParameter;
use core::marker::PhantomData;

/// A MAYO signature.
#[derive(Clone)]
pub struct Signature<P: MayoParameter> {
    bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

impl<P: MayoParameter> PartialEq for Signature<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: MayoParameter> Eq for Signature<P> {}

impl<P: MayoParameter> AsRef<[u8]> for Signature<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: MayoParameter> core::fmt::Debug for Signature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signature")
            .field("variant", &P::NAME)
            .field("bytes", &hex::encode(&self.bytes))
            .finish()
    }
}

impl<P: MayoParameter> TryFrom<&[u8]> for Signature<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != P::SIG_BYTES {
            return Err(Error::InvalidSignatureLength {
                expected: P::SIG_BYTES,
                got: bytes.len(),
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }
}

impl<P: MayoParameter> TryFrom<Vec<u8>> for Signature<P> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: MayoParameter> TryFrom<&Vec<u8>> for Signature<P> {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: MayoParameter> TryFrom<Box<[u8]>> for Signature<P> {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl<P: MayoParameter> From<Signature<P>> for Vec<u8> {
    fn from(sig: Signature<P>) -> Vec<u8> {
        sig.bytes
    }
}

impl<P: MayoParameter> signature::SignatureEncoding for Signature<P> {
    type Repr = Vec<u8>;
}

#[cfg(feature = "serde")]
impl<P: MayoParameter> serde::Serialize for Signature<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: MayoParameter> serde::Deserialize<'de> for Signature<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serde::de::Error::custom)
    }
}
