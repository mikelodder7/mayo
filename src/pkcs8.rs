// SPDX-License-Identifier: Apache-2.0 OR MIT

//! PKCS#8 and SPKI encoding/decoding support for MAYO keys.
//!
//! This module implements the standard key encoding traits from the
//! [`pkcs8`] and [`spki`] crates, enabling DER-encoded
//! key serialization compatible with X.509 and PKCS#8.
//!
//! Since MAYO has not yet been standardized by NIST, this module uses
//! **experimental OIDs** assigned by the [Open Quantum Safe](https://openquantumsafe.org/)
//! project under the `1.3.9999.8` arc. These OIDs will be replaced with
//! official NIST OIDs once MAYO is standardized.

use crate::{
    KeyPair, Mayo1, Mayo2, Mayo3, Mayo5, MayoParameter, Signature, SigningKey, VerifyingKey,
};
use ::pkcs8::{
    AlgorithmIdentifierRef, EncodePrivateKey, ObjectIdentifier, PrivateKeyInfoRef,
    der::{
        self, AnyRef, Encode, Reader, TagMode, TagNumber,
        asn1::{BitStringRef, ContextSpecific, OctetStringRef},
    },
    spki::{
        self, AlgorithmIdentifier, AssociatedAlgorithmIdentifier, EncodePublicKey,
        SignatureAlgorithmIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfo,
        SubjectPublicKeyInfoRef,
    },
};

/// Tag number for the seed value in the PKCS#8 private key encoding.
const SEED_TAG_NUMBER: TagNumber = TagNumber(0);

/// Seed serialized as ASN.1 context-specific implicit OCTET STRING.
type SeedString<'a> = ContextSpecific<&'a OctetStringRef>;

// ============================================================================
// Experimental OIDs from the Open Quantum Safe (OQS) project.
//
// Arc: 1.3.9999.8.{variant}.3
//
// These are NOT officially registered and are intended for interoperability
// testing only. They will be replaced with NIST-assigned OIDs once MAYO
// is standardized under a FIPS publication.
//
// Reference: https://github.com/open-quantum-safe/oqs-provider
// ============================================================================

/// Experimental OID for MAYO-1 (`1.3.9999.8.1.3`).
pub const MAYO1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.8.1.3");

/// Experimental OID for MAYO-2 (`1.3.9999.8.2.3`).
pub const MAYO2_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.8.2.3");

/// Experimental OID for MAYO-3 (`1.3.9999.8.3.3`).
pub const MAYO3_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.8.3.3");

/// Experimental OID for MAYO-5 (`1.3.9999.8.5.3`).
pub const MAYO5_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.9999.8.5.3");

// ============================================================================
// AssociatedAlgorithmIdentifier for parameter set types
// ============================================================================

macro_rules! impl_algorithm_id {
    ($type:ty, $oid:expr) => {
        impl AssociatedAlgorithmIdentifier for $type {
            type Params = AnyRef<'static>;

            const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
                oid: $oid,
                parameters: None,
            };
        }
    };
}

impl_algorithm_id!(Mayo1, MAYO1_OID);
impl_algorithm_id!(Mayo2, MAYO2_OID);
impl_algorithm_id!(Mayo3, MAYO3_OID);
impl_algorithm_id!(Mayo5, MAYO5_OID);

// ============================================================================
// AssociatedAlgorithmIdentifier + SignatureBitStringEncoding for Signature<P>
// ============================================================================

impl<P> AssociatedAlgorithmIdentifier for Signature<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = P::ALGORITHM_IDENTIFIER;
}

impl<P: MayoParameter> SignatureBitStringEncoding for Signature<P> {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        der::asn1::BitString::new(0, self.as_ref().to_vec())
    }
}

// ============================================================================
// SignatureAlgorithmIdentifier for key types
// ============================================================================

impl<P> SignatureAlgorithmIdentifier for KeyPair<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

impl<P> SignatureAlgorithmIdentifier for SigningKey<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

impl<P> SignatureAlgorithmIdentifier for VerifyingKey<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<P>::ALGORITHM_IDENTIFIER;
}

// ============================================================================
// KeyPair: EncodePrivateKey + TryFrom<PrivateKeyInfoRef> (DecodePrivateKey)
// ============================================================================

impl<P> TryFrom<PrivateKeyInfoRef<'_>> for KeyPair<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = ::pkcs8::Error;

    fn try_from(private_key_info: PrivateKeyInfoRef<'_>) -> ::pkcs8::Result<Self> {
        private_key_info
            .algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;

        let mut reader = der::SliceReader::new(private_key_info.private_key.as_bytes())?;
        let seed_string = SeedString::decode_implicit(&mut reader, SEED_TAG_NUMBER)?
            .ok_or(::pkcs8::Error::KeyMalformed)?;
        let seed = seed_string.value.as_bytes();
        reader.finish()?;

        KeyPair::from_seed(seed).map_err(|_| ::pkcs8::Error::KeyMalformed)
    }
}

impl<P> EncodePrivateKey for KeyPair<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_pkcs8_der(&self) -> ::pkcs8::Result<der::SecretDocument> {
        let seed = self.signing_key().as_ref();
        let seed_der = SeedString {
            tag_mode: TagMode::Implicit,
            tag_number: SEED_TAG_NUMBER,
            value: OctetStringRef::new(seed)?,
        }
        .to_der()?;

        let private_key = OctetStringRef::new(&seed_der)?;
        let private_key_info = PrivateKeyInfoRef::new(P::ALGORITHM_IDENTIFIER, private_key);
        ::pkcs8::SecretDocument::encode_msg(&private_key_info).map_err(::pkcs8::Error::Asn1)
    }
}

// ============================================================================
// SigningKey: TryFrom<PrivateKeyInfoRef> (DecodePrivateKey via blanket impl)
// ============================================================================

impl<P> TryFrom<PrivateKeyInfoRef<'_>> for SigningKey<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = ::pkcs8::Error;

    fn try_from(private_key_info: PrivateKeyInfoRef<'_>) -> ::pkcs8::Result<Self> {
        let keypair = KeyPair::<P>::try_from(private_key_info)?;
        Ok(keypair.signing_key().clone())
    }
}

// ============================================================================
// VerifyingKey: EncodePublicKey + TryFrom<SubjectPublicKeyInfoRef>
// ============================================================================

impl<P> TryFrom<SubjectPublicKeyInfoRef<'_>> for VerifyingKey<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Error = spki::Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> spki::Result<Self> {
        spki.algorithm
            .assert_algorithm_oid(P::ALGORITHM_IDENTIFIER.oid)?;

        let pk_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(::pkcs8::Error::KeyMalformed)?;

        VerifyingKey::try_from(pk_bytes).map_err(|_| ::pkcs8::Error::KeyMalformed.into())
    }
}

impl<P> EncodePublicKey for VerifyingKey<P>
where
    P: MayoParameter + AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        let subject_public_key = BitStringRef::new(0, self.as_ref())?;

        SubjectPublicKeyInfo {
            algorithm: P::ALGORITHM_IDENTIFIER,
            subject_public_key,
        }
        .try_into()
    }
}
