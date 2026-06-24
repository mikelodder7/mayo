//! Public key, signing key, and signature size checks.

use pq_mayo::{KeyPair, Mayo1, Mayo2, Mayo3, Mayo5, MayoParameter, Signature};
use signature::Signer;

fn sizes<P: MayoParameter>(sk_bytes: usize, vk_bytes: usize, sig_bytes: usize) {
    assert_eq!(P::CSK_BYTES, sk_bytes);
    assert_eq!(P::CPK_BYTES, vk_bytes);
    assert_eq!(P::SIG_BYTES, sig_bytes);

    let mut rng = rand::rng();
    let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen");
    assert_eq!(keypair.signing_key().as_ref().len(), sk_bytes);
    assert_eq!(keypair.verifying_key().as_ref().len(), vk_bytes);

    let sig = keypair.signing_key().try_sign(b"size check").expect("sign");
    assert_eq!(sig.as_ref().len(), sig_bytes);
    assert_eq!(
        Signature::<P>::try_from(sig.as_ref())
            .expect("signature")
            .as_ref()
            .len(),
        sig_bytes
    );
}

#[test]
fn mayo1_sizes() {
    sizes::<Mayo1>(24, 1420, 454);
}

#[test]
fn mayo2_sizes() {
    sizes::<Mayo2>(24, 4368, 216);
}

#[test]
fn mayo3_sizes() {
    sizes::<Mayo3>(32, 2986, 681);
}

#[test]
fn mayo5_sizes() {
    sizes::<Mayo5>(40, 5554, 964);
}
