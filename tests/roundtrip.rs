//! Basic sign/verify roundtrip tests.

use pq_mayo::{KeyPair, Mayo1, Mayo2, Mayo3, Mayo5, VerifyingKey};
use signature::{Signer, Verifier};

fn roundtrip<P: pq_mayo::MayoParameter>() {
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen failed");
    let msg = b"test message for MAYO signature scheme";

    let sig = keypair
        .signing_key()
        .try_sign(msg.as_slice())
        .expect("signing failed");

    keypair
        .verifying_key()
        .verify(msg.as_slice(), &sig)
        .expect("verification failed");
}

fn wrong_message<P: pq_mayo::MayoParameter>() {
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen failed");
    let msg = b"test message";

    let sig = keypair
        .signing_key()
        .try_sign(msg.as_slice())
        .expect("signing failed");

    let wrong_msg = b"wrong message";
    assert!(
        keypair
            .verifying_key()
            .verify(wrong_msg.as_slice(), &sig)
            .is_err()
    );
}

#[test]
fn roundtrip_mayo1() {
    roundtrip::<Mayo1>();
}

#[test]
fn wrong_message_mayo1() {
    wrong_message::<Mayo1>();
}

#[test]
fn roundtrip_mayo2() {
    roundtrip::<Mayo2>();
}

#[test]
fn roundtrip_mayo3() {
    roundtrip::<Mayo3>();
}

#[test]
fn roundtrip_mayo5() {
    roundtrip::<Mayo5>();
}

fn vk_from_sk<P: pq_mayo::MayoParameter>() {
    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen failed");

    // Derive verifying key from signing key
    let derived_vk = VerifyingKey::<P>::from(keypair.signing_key());

    // Must match the original verifying key
    assert_eq!(derived_vk.as_ref(), keypair.verifying_key().as_ref());

    // Sign with the signing key, verify with the derived verifying key
    let msg = b"verifying key derivation test";
    let sig = keypair
        .signing_key()
        .try_sign(msg.as_slice())
        .expect("signing failed");
    derived_vk
        .verify(msg.as_slice(), &sig)
        .expect("verification with derived vk failed");
}

#[test]
fn vk_from_sk_mayo1() {
    vk_from_sk::<Mayo1>();
}

#[test]
fn vk_from_sk_mayo2() {
    vk_from_sk::<Mayo2>();
}

#[test]
fn vk_from_sk_mayo3() {
    vk_from_sk::<Mayo3>();
}

#[test]
fn vk_from_sk_mayo5() {
    vk_from_sk::<Mayo5>();
}
