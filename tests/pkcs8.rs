//! PKCS#8 and SPKI encoding/decoding tests.

#![cfg(feature = "pkcs8")]

use pkcs8::DecodePrivateKey;
use pkcs8::EncodePrivateKey;
use pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use pq_mayo::{KeyPair, Mayo1, Mayo2, Mayo3, Mayo5, MayoParameter, SigningKey, VerifyingKey};
use signature::{Signer, Verifier};

// ============================================================================
// Private key (PKCS#8) round-trip
// ============================================================================

fn keypair_pkcs8_roundtrip<P>()
where
    P: MayoParameter
        + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");

    // Encode to PKCS#8 DER
    let der = keypair.to_pkcs8_der().expect("encode pkcs8");

    // Decode back
    let restored = KeyPair::<P>::from_pkcs8_der(der.as_bytes()).expect("decode pkcs8");

    // Keys must match
    assert_eq!(
        keypair.signing_key().as_ref(),
        restored.signing_key().as_ref(),
        "signing key mismatch after PKCS#8 round-trip"
    );
    assert_eq!(
        keypair.verifying_key().as_ref(),
        restored.verifying_key().as_ref(),
        "verifying key mismatch after PKCS#8 round-trip"
    );
}

#[test]
fn keypair_pkcs8_roundtrip_mayo1() {
    keypair_pkcs8_roundtrip::<Mayo1>();
}

#[test]
fn keypair_pkcs8_roundtrip_mayo2() {
    keypair_pkcs8_roundtrip::<Mayo2>();
}

#[test]
fn keypair_pkcs8_roundtrip_mayo3() {
    keypair_pkcs8_roundtrip::<Mayo3>();
}

#[test]
fn keypair_pkcs8_roundtrip_mayo5() {
    keypair_pkcs8_roundtrip::<Mayo5>();
}

// ============================================================================
// Public key (SPKI) round-trip
// ============================================================================

fn verifying_key_spki_roundtrip<P>()
where
    P: MayoParameter
        + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");

    // Encode to SPKI DER
    let der = keypair
        .verifying_key()
        .to_public_key_der()
        .expect("encode spki");

    // Decode back
    let restored = VerifyingKey::<P>::from_public_key_der(der.as_bytes()).expect("decode spki");

    assert_eq!(
        keypair.verifying_key().as_ref(),
        restored.as_ref(),
        "verifying key mismatch after SPKI round-trip"
    );
}

#[test]
fn verifying_key_spki_roundtrip_mayo1() {
    verifying_key_spki_roundtrip::<Mayo1>();
}

#[test]
fn verifying_key_spki_roundtrip_mayo2() {
    verifying_key_spki_roundtrip::<Mayo2>();
}

#[test]
fn verifying_key_spki_roundtrip_mayo3() {
    verifying_key_spki_roundtrip::<Mayo3>();
}

#[test]
fn verifying_key_spki_roundtrip_mayo5() {
    verifying_key_spki_roundtrip::<Mayo5>();
}

// ============================================================================
// Decode PKCS#8 as SigningKey
// ============================================================================

fn signing_key_from_pkcs8<P>()
where
    P: MayoParameter
        + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");

    // Encode keypair to PKCS#8
    let der = keypair.to_pkcs8_der().expect("encode pkcs8");

    // Decode as SigningKey (not KeyPair)
    let sk = SigningKey::<P>::from_pkcs8_der(der.as_bytes()).expect("decode signing key");

    assert_eq!(
        keypair.signing_key().as_ref(),
        sk.as_ref(),
        "signing key mismatch after PKCS#8 decode"
    );
}

#[test]
fn signing_key_from_pkcs8_mayo1() {
    signing_key_from_pkcs8::<Mayo1>();
}

#[test]
fn signing_key_from_pkcs8_mayo2() {
    signing_key_from_pkcs8::<Mayo2>();
}

#[test]
fn signing_key_from_pkcs8_mayo3() {
    signing_key_from_pkcs8::<Mayo3>();
}

#[test]
fn signing_key_from_pkcs8_mayo5() {
    signing_key_from_pkcs8::<Mayo5>();
}

// ============================================================================
// Sign with decoded key, verify with decoded key
// ============================================================================

fn sign_verify_after_pkcs8_roundtrip<P>()
where
    P: MayoParameter
        + pkcs8::spki::AssociatedAlgorithmIdentifier<Params = pkcs8::der::AnyRef<'static>>,
{
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
    let msg = b"PKCS#8 round-trip sign/verify test";

    // Encode and decode keys through DER
    let sk_der = keypair.to_pkcs8_der().expect("encode pkcs8");
    let vk_der = keypair
        .verifying_key()
        .to_public_key_der()
        .expect("encode spki");

    let restored_kp = KeyPair::<P>::from_pkcs8_der(sk_der.as_bytes()).expect("decode pkcs8");
    let restored_vk =
        VerifyingKey::<P>::from_public_key_der(vk_der.as_bytes()).expect("decode spki");

    // Sign with restored key
    let sig = restored_kp
        .signing_key()
        .try_sign(msg.as_slice())
        .expect("sign");

    // Verify with restored public key
    restored_vk
        .verify(msg.as_slice(), &sig)
        .expect("verify with restored vk");

    // Also verify with original public key
    keypair
        .verifying_key()
        .verify(msg.as_slice(), &sig)
        .expect("verify with original vk");
}

#[test]
fn sign_verify_after_pkcs8_roundtrip_mayo1() {
    sign_verify_after_pkcs8_roundtrip::<Mayo1>();
}

#[test]
fn sign_verify_after_pkcs8_roundtrip_mayo2() {
    sign_verify_after_pkcs8_roundtrip::<Mayo2>();
}

#[test]
fn sign_verify_after_pkcs8_roundtrip_mayo3() {
    sign_verify_after_pkcs8_roundtrip::<Mayo3>();
}

#[test]
fn sign_verify_after_pkcs8_roundtrip_mayo5() {
    sign_verify_after_pkcs8_roundtrip::<Mayo5>();
}

// ============================================================================
// Wrong OID rejection
// ============================================================================

#[test]
fn wrong_oid_rejected() {
    let mut rng = rand::rng();
    let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");

    let der = keypair.to_pkcs8_der().expect("encode");

    // Try to decode Mayo1 PKCS#8 as Mayo2 — should fail due to OID mismatch
    let result = KeyPair::<Mayo2>::from_pkcs8_der(der.as_bytes());
    assert!(result.is_err(), "should reject wrong OID");
}

#[test]
fn wrong_oid_rejected_spki() {
    let mut rng = rand::rng();
    let keypair = KeyPair::<Mayo1>::generate(&mut rng).expect("keygen");

    let der = keypair.verifying_key().to_public_key_der().expect("encode");

    // Try to decode Mayo1 SPKI as Mayo2 — should fail
    let result = VerifyingKey::<Mayo2>::from_public_key_der(der.as_bytes());
    assert!(result.is_err(), "should reject wrong OID");
}
