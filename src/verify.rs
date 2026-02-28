// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO signature verification.

use crate::codec::{decode, unpack_m_vecs};
use crate::error::{Error, Result};
use crate::keygen::expand_p1_p2;
use crate::matrix_ops::m_calculate_ps_sps;
use crate::params::MayoParameter;
use crate::sign::compute_rhs;
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Evaluate the public map: compute SPS from s and P1, P2, P3.
fn eval_public_map<P: MayoParameter>(
    s: &[u8],
    p1: &[u64],
    p2: &[u64],
    p3: &[u64],
    eval: &mut [u8],
) {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_k = P::K;

    let mut sps = vec![0u64; param_k * param_k * m_vec_limbs];
    m_calculate_ps_sps::<P>(p1, p2, p3, s, &mut sps);

    let zero = vec![0u8; P::M];
    compute_rhs::<P>(&mut sps, &zero, eval);
}

/// Verify a MAYO signature.
///
/// Returns `Ok(())` if the signature is valid, `Err(VerificationFailed)` otherwise.
pub(crate) fn mayo_verify<P: MayoParameter>(msg: &[u8], sig: &[u8], cpk: &[u8]) -> Result<()> {
    let param_m = P::M;
    let param_n = P::N;
    let param_k = P::K;
    let param_m_bytes = P::M_BYTES;
    let param_sig_bytes = P::SIG_BYTES;
    let param_digest_bytes = P::DIGEST_BYTES;
    let param_salt_bytes = P::SALT_BYTES;
    let param_pk_seed_bytes = P::PK_SEED_BYTES;
    let m_vec_limbs = P::M_VEC_LIMBS;

    // Expand public key
    let pk = expand_p1_p2::<P>(&cpk[..param_pk_seed_bytes]);

    // Unpack P3
    let p3_vecs = P::P3_LIMBS / m_vec_limbs;
    let mut p3 = vec![0u64; P::P3_LIMBS];
    unpack_m_vecs(&cpk[param_pk_seed_bytes..], &mut p3, p3_vecs, param_m);

    let p1 = &pk[..P::P1_LIMBS];
    let p2 = &pk[P::P1_LIMBS..P::P1_LIMBS + P::P2_LIMBS];

    // Hash message
    let mut tmp = vec![0u8; param_digest_bytes + param_salt_bytes];
    {
        let mut hasher = Shake256::default();
        hasher.update(msg);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut tmp[..param_digest_bytes]);
    }

    // Compute t = SHAKE256(digest || salt)
    tmp[param_digest_bytes..param_digest_bytes + param_salt_bytes]
        .copy_from_slice(&sig[param_sig_bytes - param_salt_bytes..param_sig_bytes]);
    let mut tenc = vec![0u8; param_m_bytes];
    {
        let mut hasher = Shake256::default();
        hasher.update(&tmp[..param_digest_bytes + param_salt_bytes]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut tenc);
    }
    let mut t = vec![0u8; param_m];
    decode(&tenc, &mut t, param_m);

    // Decode s from signature
    let mut s = vec![0u8; param_k * param_n];
    decode(sig, &mut s, param_k * param_n);

    // Evaluate public map
    let mut y = vec![0u8; 2 * param_m]; // Extra space
    eval_public_map::<P>(&s, p1, p2, &p3, &mut y);

    // Constant-time compare y == t
    if y[..param_m] == t[..param_m] {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}
