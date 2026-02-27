// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO key generation.

use crate::codec::{decode, pack_m_vecs, unpack_m_vecs};
use crate::error::Result;
use crate::matrix_ops::{compute_p3, m_upper};
use crate::params::MayoParameter;
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::CryptoRng;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

type Aes128Ctr32 = ctr::Ctr32BE<Aes128>;

/// Expand P1 and P2 from a public key seed using AES-128-CTR.
pub(crate) fn expand_p1_p2<P: MayoParameter>(seed_pk: &[u8]) -> Vec<u64> {
    let total_bytes = P::P1_BYTES + P::P2_BYTES;
    let total_limbs = P::P1_LIMBS + P::P2_LIMBS;
    let num_vecs = total_limbs / P::M_VEC_LIMBS;

    // Generate raw bytes using AES-128-CTR
    let mut raw = vec![0u8; total_bytes];
    let iv = [0u8; 16];
    let mut cipher = Aes128Ctr32::new(seed_pk[..16].into(), &iv.into());
    cipher.apply_keystream(&mut raw);

    // Unpack into bitsliced form
    let mut result = vec![0u64; total_limbs];
    unpack_m_vecs(&raw, &mut result, num_vecs, P::M);

    result
}

/// Generate a compact MAYO keypair.
///
/// Produces a compact secret key (`csk`) and compact public key (`cpk`).
pub(crate) fn mayo_keypair_compact<P: MayoParameter>(
    cpk: &mut [u8],
    csk: &mut [u8],
    rng: &mut impl CryptoRng,
) -> Result<()> {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_m = P::M;
    let param_v = P::V;
    let param_o = P::O;
    let param_o_bytes = P::O_BYTES;
    let param_pk_seed_bytes = P::PK_SEED_BYTES;
    let param_sk_seed_bytes = P::SK_SEED_BYTES;
    let param_p3_limbs = P::P3_LIMBS;

    // seed_sk <- random bytes
    rng.fill_bytes(&mut csk[..param_sk_seed_bytes]);
    let seed_sk = &csk[..param_sk_seed_bytes];

    // S = SHAKE256(seed_sk) -> pk_seed || O_bytes
    let mut s = vec![0u8; param_pk_seed_bytes + param_o_bytes];
    let mut hasher = Shake256::default();
    hasher.update(seed_sk);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut s);

    let seed_pk = &s[..param_pk_seed_bytes];

    // Decode O matrix
    let mut o = vec![0u8; param_v * param_o];
    decode(&s[param_pk_seed_bytes..], &mut o, param_v * param_o);

    // Expand P1 and P2
    let mut p = expand_p1_p2::<P>(seed_pk);

    let p1_limbs = P::P1_LIMBS;

    // Compute P3 = O^t * (P1*O + P2)
    let mut p3 = vec![0u64; param_o * param_o * m_vec_limbs];
    {
        let (p1, p2) = p.split_at_mut(p1_limbs);
        compute_p3::<P>(p1, p2, &o, &mut p3);
    }

    // Store seed_pk in cpk
    cpk[..param_pk_seed_bytes].copy_from_slice(seed_pk);

    // Compute Upper(P3) and pack into cpk
    let mut p3_upper = vec![0u64; param_p3_limbs];
    m_upper(m_vec_limbs, &p3, &mut p3_upper, param_o);
    pack_m_vecs(
        &p3_upper,
        &mut cpk[param_pk_seed_bytes..],
        param_p3_limbs / m_vec_limbs,
        param_m,
    );

    Ok(())
}
