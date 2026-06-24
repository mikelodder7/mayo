// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO signing key.

use crate::error::Error;
use crate::keypair::derive_cpk_from_csk;
use crate::mayo_signature::Signature;
use crate::params::MayoParameter;
use crate::sign::{expand_sk, mayo_sign_signature, mayo_sign_signature_with_expanded_sk};
use hybrid_array::Array;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A MAYO signing key (compact secret key = seed).
#[derive(Clone)]
pub struct SigningKey<P: MayoParameter> {
    pub(crate) bytes: Array<u8, P::CskSize>,
    pub(crate) cpk: Vec<u8>,
}

/// A MAYO signing key with cached expanded secret material.
///
/// This type is intended for repeated signing with the same key. It keeps the
/// compact secret key for the signing fault check and also stores expanded
/// secret-derived matrices, so it uses more memory and retains more sensitive
/// material than [`SigningKey`].
#[derive(Clone)]
pub struct ExpandedSigningKey<P: MayoParameter> {
    bytes: Array<u8, P::CskSize>,
    p: Zeroizing<Vec<u64>>,
    p2: Vec<u64>,
    o: Zeroizing<Vec<u8>>,
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

impl<P: MayoParameter> Zeroize for ExpandedSigningKey<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.p.zeroize();
        self.p2.zeroize();
        self.o.zeroize();
    }
}

impl<P: MayoParameter> Drop for ExpandedSigningKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: MayoParameter> ZeroizeOnDrop for ExpandedSigningKey<P> {}

impl<P: MayoParameter> AsRef<[u8]> for ExpandedSigningKey<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

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

impl<P: MayoParameter> PartialEq for ExpandedSigningKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<P: MayoParameter> Eq for ExpandedSigningKey<P> {}

impl<P: MayoParameter> core::fmt::Debug for SigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("variant", &P::NAME)
            .field("bytes", &"**FILTERED**")
            .finish_non_exhaustive()
    }
}

impl<P: MayoParameter> core::fmt::Debug for ExpandedSigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExpandedSigningKey")
            .field("variant", &P::NAME)
            .field("bytes", &"**FILTERED**")
            .field("expanded", &"**FILTERED**")
            .finish_non_exhaustive()
    }
}

impl<P: MayoParameter> SigningKey<P> {
    /// Expand this signing key for repeated signing.
    ///
    /// The returned key caches secret-derived signing material. Prefer the
    /// compact [`SigningKey`] unless repeated signing throughput matters.
    pub fn expand(&self) -> ExpandedSigningKey<P> {
        ExpandedSigningKey::from(self)
    }

    /// Sign a message using a caller-provided RNG for salt generation.
    ///
    /// This is useful for deterministic testing with a seeded RNG.
    pub fn sign_with_rng(
        &self,
        rng: &mut impl rand::CryptoRng,
        msg: &[u8],
    ) -> crate::error::Result<Signature<P>> {
        let mut sig_bytes = vec![0u8; P::SIG_BYTES];
        mayo_sign_signature::<P>(&mut sig_bytes, msg, &self.bytes, rng)?;
        Signature::try_from(sig_bytes)
    }
}

impl<P: MayoParameter> ExpandedSigningKey<P> {
    /// Sign a message using a caller-provided RNG for salt generation.
    pub fn sign_with_rng(
        &self,
        rng: &mut impl rand::CryptoRng,
        msg: &[u8],
    ) -> crate::error::Result<Signature<P>> {
        let mut sig_bytes = vec![0u8; P::SIG_BYTES];
        mayo_sign_signature_with_expanded_sk::<P>(
            &mut sig_bytes,
            msg,
            &self.bytes,
            &self.p,
            &self.p2,
            &self.o,
            rng,
        )?;
        Signature::try_from(sig_bytes)
    }
}

impl<P: MayoParameter> From<&SigningKey<P>> for ExpandedSigningKey<P> {
    fn from(signing_key: &SigningKey<P>) -> Self {
        let esk = expand_sk::<P>(&signing_key.bytes);
        Self {
            bytes: signing_key.bytes.clone(),
            p: esk.p1_l,
            p2: esk.p2,
            o: esk.o,
        }
    }
}

impl<P: MayoParameter> signature::Signer<Signature<P>> for SigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, signature::Error> {
        let mut sig_bytes = vec![0u8; P::SIG_BYTES];
        let mut rng = rand::rng();
        mayo_sign_signature::<P>(&mut sig_bytes, msg, &self.bytes, &mut rng)
            .map_err(|e| -> signature::Error { e.into() })?;
        Signature::try_from(sig_bytes).map_err(|e| -> signature::Error { e.into() })
    }
}

impl<P: MayoParameter> signature::Signer<Signature<P>> for ExpandedSigningKey<P> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<P>, signature::Error> {
        let mut sig_bytes = vec![0u8; P::SIG_BYTES];
        let mut rng = rand::rng();
        mayo_sign_signature_with_expanded_sk::<P>(
            &mut sig_bytes,
            msg,
            &self.bytes,
            &self.p,
            &self.p2,
            &self.o,
            &mut rng,
        )
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
