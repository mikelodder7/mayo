// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO signing key.

use crate::error::Error;
use crate::keypair::derive_cpk_from_csk;
use crate::mayo_signature::Signature;
use crate::params::MayoParameter;
use crate::sign::mayo_sign_signature;
use hybrid_array::Array;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A MAYO signing key (compact secret key = seed).
#[derive(Clone)]
pub struct SigningKey<P: MayoParameter> {
    pub(crate) bytes: Array<u8, P::CskSize>,
    pub(crate) cpk: Vec<u8>,
}

impl<P: MayoParameter> Zeroize for SigningKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: MayoParameter> Drop for SigningKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: MayoParameter> ZeroizeOnDrop for SigningKey<P> {}

impl<P: MayoParameter> AsRef<[u8]> for SigningKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<P: MayoParameter> TryFrom<&[u8]> for SigningKey<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let csk =
            Array::<u8, P::CskSize>::try_from(bytes).map_err(|_e| Error::InvalidKeyLength {
                expected: P::CSK_BYTES,
                got: bytes.len(),
            })?;
        let mut cpk = vec![0u8; P::CPK_BYTES];
        derive_cpk_from_csk::<P>(bytes, &mut cpk);
        Ok(Self { bytes: csk, cpk })
    }
}

impl<P: MayoParameter> TryFrom<Vec<u8>> for SigningKey<P> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: MayoParameter> TryFrom<&Vec<u8>> for SigningKey<P> {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl<P: MayoParameter> TryFrom<Box<[u8]>> for SigningKey<P> {
    type Error = Error;

    fn try_from(bytes: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_ref())
    }
}

impl<P: MayoParameter> PartialEq for SigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: MayoParameter> Eq for SigningKey<P> {}

impl<P: MayoParameter> core::fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("variant", &P::NAME)
            .field("bytes", &"**FILTERED**")
            .finish_non_exhaustive()
    }
}

impl<P: MayoParameter> SigningKey<P> {
    /// Sign a message using a caller-provided RNG for salt generation.
    ///
    /// This is useful for deterministic testing with a seeded RNG.
    pub fn sign_with_rng(
        &self,
        rng: &mut impl rand::CryptoRng,
        msg: &[u8],
    ) -> crate::error::Result<Signature<P>> {
        let mut sig_bytes = vec![0u8; P::SIG_BYTES];
        mayo_sign_signature::<P>(&mut sig_bytes, msg, &self.bytes, &self.cpk, rng)?;
        Signature::try_from(sig_bytes)
    }
}

impl<P: MayoParameter> signature::Signer<Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, signature::Error> {
        let mut sig_bytes = vec![0u8; P::SIG_BYTES];
        let mut rng = rand::rng();
        mayo_sign_signature::<P>(&mut sig_bytes, msg, &self.bytes, &self.cpk, &mut rng)
            .map_err(|e| -> signature::Error { e.into() })?;
        Signature::try_from(sig_bytes).map_err(|e| -> signature::Error { e.into() })
    }
}

#[cfg(feature = "serde")]
impl<P: MayoParameter> serde::Serialize for SigningKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serdect::slice::serialize_hex_lower_or_bin(&self.bytes, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, P: MayoParameter> serde::Deserialize<'de> for SigningKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = serdect::slice::deserialize_hex_or_bin_vec(deserializer)?;
        Self::try_from(bytes).map_err(serde::de::Error::custom)
    }
}
