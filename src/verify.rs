// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO signature verification.

use crate::codec::{decode, unpack_m_vecs};
use crate::error::{Error, Result};
use crate::keygen::expand_p1_p2;
use crate::matrix_ops::{PsSpsScratch, m_calculate_ps_sps_with_scratch};
use crate::params::{MAX_M, MayoParameter};
use crate::sign::compute_rhs;
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};
use subtle::ConstantTimeEq;

pub(crate) struct VerifyScratch {
    ps_sps: PsSpsScratch,
    sps: Vec<u64>,
    tmp: Vec<u8>,
    tenc: Vec<u8>,
    t: Vec<u8>,
    s: Vec<u8>,
    y: Vec<u8>,
}

impl VerifyScratch {
    pub(crate) fn new<P: MayoParameter>() -> Self {
        Self {
            ps_sps: PsSpsScratch::new::<P>(),
            sps: vec![0u64; P::K * P::K * P::M_VEC_LIMBS],
            tmp: vec![0u8; P::DIGEST_BYTES + P::SALT_BYTES],
            tenc: vec![0u8; P::M_BYTES],
            t: vec![0u8; P::M],
            s: vec![0u8; P::K * P::N],
            y: vec![0u8; P::M],
        }
    }
}

pub(crate) fn expand_public_key<P: MayoParameter>(cpk: &[u8]) -> (Vec<u64>, Vec<u64>) {
    let param_m = P::M;
    let param_pk_seed_bytes = P::PK_SEED_BYTES;
    let m_vec_limbs = P::M_VEC_LIMBS;

    let pk = expand_p1_p2::<P>(&cpk[..param_pk_seed_bytes]);

    let p3_vecs = P::P3_LIMBS / m_vec_limbs;
    let mut p3 = vec![0u64; P::P3_LIMBS];
    unpack_m_vecs(&cpk[param_pk_seed_bytes..], &mut p3, p3_vecs, param_m);

    (pk, p3)
}

/// Evaluate the public map: compute SPS from s and P1, P2, P3.
fn eval_public_map<P: MayoParameter>(
    s: &[u8],
    p1: &[u64],
    p2: &[u64],
    p3: &[u64],
    eval: &mut [u8],
    sps: &mut [u64],
    scratch: &mut PsSpsScratch,
) {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_k = P::K;

    let sps_len = param_k * param_k * m_vec_limbs;
    debug_assert!(sps.len() >= sps_len);
    let sps = &mut sps[..sps_len];
    m_calculate_ps_sps_with_scratch::<P>(p1, p2, p3, s, sps, scratch);

    let zero = [0u8; MAX_M];
    compute_rhs::<P>(sps, &zero, eval);
}

/// Verify a MAYO signature.
///
/// Returns `Ok(())` if the signature is valid, `Err(VerificationFailed)` otherwise.
pub(crate) fn mayo_verify<P: MayoParameter>(msg: &[u8], sig: &[u8], cpk: &[u8]) -> Result<()> {
    let (pk, p3) = expand_public_key::<P>(cpk);
    let mut scratch = VerifyScratch::new::<P>();
    mayo_verify_with_expanded_pk_and_scratch::<P>(msg, sig, &pk, &p3, &mut scratch)
}

pub(crate) fn mayo_verify_split_with_scratch<P: MayoParameter>(
    msg: &[u8],
    sig: &[u8],
    p1: &[u64],
    p2: &[u64],
    p3: &[u64],
    scratch: &mut VerifyScratch,
) -> Result<()> {
    let param_m = P::M;
    let param_n = P::N;
    let param_k = P::K;
    let param_m_bytes = P::M_BYTES;
    let param_sig_bytes = P::SIG_BYTES;
    let param_digest_bytes = P::DIGEST_BYTES;
    let param_salt_bytes = P::SALT_BYTES;
    let VerifyScratch {
        ps_sps,
        sps,
        tmp,
        tenc,
        t,
        s,
        y,
    } = scratch;

    // Hash message
    let tmp_len = param_digest_bytes + param_salt_bytes;
    debug_assert!(tmp.len() >= tmp_len);
    let tmp = &mut tmp[..tmp_len];
    {
        let mut hasher = Shake256::default();
        hasher.update(msg);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut tmp[..param_digest_bytes]);
    }

    // Compute t = SHAKE256(digest || salt)
    tmp[param_digest_bytes..param_digest_bytes + param_salt_bytes]
        .copy_from_slice(&sig[param_sig_bytes - param_salt_bytes..param_sig_bytes]);
    debug_assert!(tenc.len() >= param_m_bytes);
    let tenc = &mut tenc[..param_m_bytes];
    {
        let mut hasher = Shake256::default();
        hasher.update(&tmp[..param_digest_bytes + param_salt_bytes]);
        let mut reader = hasher.finalize_xof();
        reader.read(tenc);
    }
    debug_assert!(t.len() >= param_m);
    let t = &mut t[..param_m];
    decode(tenc, t, param_m);

    // Decode s from signature
    let s_len = param_k * param_n;
    debug_assert!(s.len() >= s_len);
    let s = &mut s[..s_len];
    decode(sig, s, param_k * param_n);

    // Evaluate public map
    debug_assert!(y.len() >= param_m);
    let y = &mut y[..param_m];
    eval_public_map::<P>(s, p1, p2, p3, y, sps, ps_sps);

    // Constant-time compare y == t
    if bool::from(y[..param_m].ct_eq(&t[..param_m])) {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

pub(crate) fn mayo_verify_with_expanded_pk_and_scratch<P: MayoParameter>(
    msg: &[u8],
    sig: &[u8],
    pk: &[u64],
    p3: &[u64],
    scratch: &mut VerifyScratch,
) -> Result<()> {
    let p1 = &pk[..P::P1_LIMBS];
    let p2 = &pk[P::P1_LIMBS..P::P1_LIMBS + P::P2_LIMBS];
    mayo_verify_split_with_scratch::<P>(msg, sig, p1, p2, p3, scratch)
}

pub(crate) fn mayo_verify_with_expanded_pk<P: MayoParameter>(
    msg: &[u8],
    sig: &[u8],
    pk: &[u64],
    p3: &[u64],
) -> Result<()> {
    let mut scratch = VerifyScratch::new::<P>();
    mayo_verify_with_expanded_pk_and_scratch::<P>(msg, sig, pk, p3, &mut scratch)
}

/// Verify a signature with P1, P2, and P3 supplied as separate (non-contiguous)
/// slices, allocating a fresh verification scratch.
///
/// Used by the verify-after-sign fault check, which reuses the public P1/P2 it
/// already expanded for signing instead of re-expanding them.
pub(crate) fn mayo_verify_with_split_pk<P: MayoParameter>(
    msg: &[u8],
    sig: &[u8],
    p1: &[u64],
    p2: &[u64],
    p3: &[u64],
) -> Result<()> {
    let mut scratch = VerifyScratch::new::<P>();
    mayo_verify_split_with_scratch::<P>(msg, sig, p1, p2, p3, &mut scratch)
}
