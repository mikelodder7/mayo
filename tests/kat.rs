//! NIST KAT (Known Answer Test) vectors for MAYO signature scheme.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use core::convert::Infallible;
use pq_mayo::{KeyPair, Mayo1, Mayo2, Mayo3, Mayo5, MayoParameter};
use signature::Verifier;

// ============================================================================
// NIST CTR-DRBG (AES-256 based, no prediction resistance)
// ============================================================================

struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl NistDrbg {
    fn new(seed: &[u8; 48]) -> Self {
        let mut drbg = Self {
            key: [0u8; 32],
            v: [0u8; 16],
        };
        drbg.update(Some(seed));
        drbg
    }

    fn update(&mut self, provided_data: Option<&[u8; 48]>) {
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));
        let mut temp = [0u8; 48];

        for i in 0..3 {
            self.increment_v();
            let mut block = GenericArray::clone_from_slice(&self.v);
            cipher.encrypt_block(&mut block);
            temp[16 * i..16 * (i + 1)].copy_from_slice(&block);
        }

        if let Some(data) = provided_data {
            for i in 0..48 {
                temp[i] ^= data[i];
            }
        }

        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..48]);
    }

    fn increment_v(&mut self) {
        for j in (0..16).rev() {
            if self.v[j] == 0xff {
                self.v[j] = 0x00;
            } else {
                self.v[j] += 1;
                break;
            }
        }
    }

    fn generate(&mut self, output: &mut [u8]) {
        let cipher = Aes256::new(GenericArray::from_slice(&self.key));
        let mut i = 0;
        while i < output.len() {
            self.increment_v();
            let mut block = GenericArray::clone_from_slice(&self.v);
            cipher.encrypt_block(&mut block);
            let end = (i + 16).min(output.len());
            output[i..end].copy_from_slice(&block[..end - i]);
            i += 16;
        }
        let zeroes: [u8; 48] = [0; 48];
        self.update(Some(&zeroes));
    }
}

impl rand::TryRng for NistDrbg {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut buf = [0u8; 4];
        self.generate(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut buf = [0u8; 8];
        self.generate(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        self.generate(dest);
        Ok(())
    }
}

impl rand::TryCryptoRng for NistDrbg {}

// ============================================================================
// KAT file parser
// ============================================================================

struct KatVector {
    count: usize,
    seed: Vec<u8>,
    mlen: usize,
    msg: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    smlen: usize,
    sm: Vec<u8>,
}

fn parse_kat_file(content: &str) -> Vec<KatVector> {
    let mut vectors = Vec::new();
    let mut current: Option<KatVector> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            if let Some(v) = current.take() {
                vectors.push(v);
            }
            continue;
        }

        if let Some(pos) = line.find('=') {
            let key = line[..pos].trim();
            let value = line[pos + 1..].trim();

            match key {
                "count" => {
                    let count: usize = value.parse().expect("parse count");
                    current = Some(KatVector {
                        count,
                        seed: Vec::new(),
                        mlen: 0,
                        msg: Vec::new(),
                        pk: Vec::new(),
                        sk: Vec::new(),
                        smlen: 0,
                        sm: Vec::new(),
                    });
                }
                "seed" => {
                    if let Some(ref mut v) = current {
                        v.seed = hex::decode(value).expect("parse seed");
                    }
                }
                "mlen" => {
                    if let Some(ref mut v) = current {
                        v.mlen = value.parse().expect("parse mlen");
                    }
                }
                "msg" => {
                    if let Some(ref mut v) = current {
                        v.msg = hex::decode(value).expect("parse msg");
                    }
                }
                "pk" => {
                    if let Some(ref mut v) = current {
                        v.pk = hex::decode(value).expect("parse pk");
                    }
                }
                "sk" => {
                    if let Some(ref mut v) = current {
                        v.sk = hex::decode(value).expect("parse sk");
                    }
                }
                "smlen" => {
                    if let Some(ref mut v) = current {
                        v.smlen = value.parse().expect("parse smlen");
                    }
                }
                "sm" => {
                    if let Some(ref mut v) = current {
                        v.sm = hex::decode(value).expect("parse sm");
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(v) = current.take() {
        vectors.push(v);
    }

    vectors
}

// ============================================================================
// KAT test runner
// ============================================================================

fn run_kat_tests<P: MayoParameter>(kat_content: &str, max_vectors: usize) {
    let vectors = parse_kat_file(kat_content);
    let test_count = max_vectors.min(vectors.len());

    for vector in vectors.iter().take(test_count) {
        // Initialize DRBG with seed
        let mut seed = [0u8; 48];
        seed.copy_from_slice(&vector.seed);
        let mut rng = NistDrbg::new(&seed);

        // Generate keypair
        let keypair = KeyPair::<P>::generate(&mut rng).expect("keygen failed");

        // Compare public key
        assert_eq!(
            keypair.verifying_key().as_ref(),
            &vector.pk[..],
            "KAT {}: public key mismatch",
            vector.count
        );

        // Compare secret key
        assert_eq!(
            keypair.signing_key().as_ref(),
            &vector.sk[..],
            "KAT {}: secret key mismatch",
            vector.count
        );

        // Sign the message
        let sig = keypair
            .signing_key()
            .sign_with_rng(&mut rng, &vector.msg)
            .expect("signing failed");

        // Build sm = sig || msg
        let mut sm = Vec::new();
        sm.extend_from_slice(sig.as_ref());
        sm.extend_from_slice(&vector.msg);

        assert_eq!(
            sm.len(),
            vector.smlen,
            "KAT {}: smlen mismatch",
            vector.count
        );
        assert_eq!(
            sm, vector.sm,
            "KAT {}: signed message mismatch",
            vector.count
        );

        // Verify the signature
        keypair
            .verifying_key()
            .verify(&vector.msg, &sig)
            .expect("verification failed");
    }

    eprintln!("  {} KAT vectors passed for {}", test_count, P::NAME);
}

// ============================================================================
// Test functions
// ============================================================================

#[test]
fn kat_mayo1() {
    let content = include_str!("../../whodouthinkur/KAT/PQCsignKAT_24_MAYO_1.rsp");
    run_kat_tests::<Mayo1>(content, 100);
}

#[test]
fn kat_mayo2() {
    let content = include_str!("../../whodouthinkur/KAT/PQCsignKAT_24_MAYO_2.rsp");
    run_kat_tests::<Mayo2>(content, 100);
}

#[test]
fn kat_mayo3() {
    let content = include_str!("../../whodouthinkur/KAT/PQCsignKAT_32_MAYO_3.rsp");
    run_kat_tests::<Mayo3>(content, 100);
}

#[test]
fn kat_mayo5() {
    let content = include_str!("../../whodouthinkur/KAT/PQCsignKAT_40_MAYO_5.rsp");
    run_kat_tests::<Mayo5>(content, 100);
}
