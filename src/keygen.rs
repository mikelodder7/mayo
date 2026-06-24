// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO key generation.

use crate::codec::{decode, pack_m_vecs};
use crate::error::Result;
use crate::matrix_ops::{compute_p3, m_upper};
use crate::params::{MAX_M, MayoParameter};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::CryptoRng;
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroizing;

type Aes128Ctr32 = ctr::Ctr32BE<Aes128>;

/// Expand P1 and P2 from a public key seed using AES-128-CTR.
pub(crate) fn expand_p1_p2<P: MayoParameter>(seed_pk: &[u8]) -> Vec<u64> {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let total_limbs = P::P1_LIMBS + P::P2_LIMBS;
    let num_vecs = total_limbs / m_vec_limbs;
    let packed_size = P::M / 2;

    let mut result = vec![0u64; total_limbs];
    let iv = [0u8; 16];
    // cipher 0.5 / hybrid-array: `new` wants `&Array` key/iv; `new_from_slices`
    // takes plain byte slices. Both inputs are exactly 16 bytes (PK seed + IV),
    // so the length check never fails.
    let mut cipher = Aes128Ctr32::new_from_slices(&seed_pk[..16], &iv)
        .expect("AES-128-CTR key and IV are both 16 bytes");

    // Generate keystream for several m-vectors per AES call to amortize the
    // per-call `apply_keystream` overhead (thousands of vectors per expansion),
    // while keeping the scratch on the stack — no ~840 KB bulk heap allocation.
    // CTR keystream is continuous, so chunking yields byte-identical output to
    // one-vector-at-a-time.
    const VECS_PER_CHUNK: usize = 64;
    let mut buf = [0u8; VECS_PER_CHUNK * (MAX_M / 2)];

    let mut i = 0;
    while i < num_vecs {
        let chunk_vecs = VECS_PER_CHUNK.min(num_vecs - i);
        let chunk = &mut buf[..chunk_vecs * packed_size];
        chunk.fill(0);
        cipher.apply_keystream(chunk);

        for v in 0..chunk_vecs {
            let src = &chunk[v * packed_size..(v + 1) * packed_size];
            let dst = &mut result[(i + v) * m_vec_limbs..(i + v + 1) * m_vec_limbs];
            for (j, c) in src.chunks(8).enumerate() {
                let mut tmp = [0u8; 8];
                tmp[..c.len()].copy_from_slice(c);
                dst[j] = u64::from_le_bytes(tmp);
            }
        }
        i += chunk_vecs;
    }

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
    let mut s = Zeroizing::new(vec![0u8; param_pk_seed_bytes + param_o_bytes]);
    let mut hasher = Shake256::default();
    hasher.update(seed_sk);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut s);

    let seed_pk = &s[..param_pk_seed_bytes];

    // Decode O matrix
    let mut o = Zeroizing::new(vec![0u8; param_v * param_o]);
    decode(&s[param_pk_seed_bytes..], &mut o, param_v * param_o);

    // Expand P1 and P2
    let mut p = Zeroizing::new(expand_p1_p2::<P>(seed_pk));

    let p1_limbs = P::P1_LIMBS;

    // Compute P3 = O^t * (P1*O + P2)
    let mut p3 = Zeroizing::new(vec![0u64; param_o * param_o * m_vec_limbs]);
    {
        let (p1, p2) = p.split_at_mut(p1_limbs);
        compute_p3::<P>(p1, p2, &o, &mut p3);
    }

    // Store seed_pk in cpk
    cpk[..param_pk_seed_bytes].copy_from_slice(seed_pk);

    // Compute Upper(P3) and pack into cpk
    let mut p3_upper = Zeroizing::new(vec![0u64; param_p3_limbs]);
    m_upper(m_vec_limbs, &p3, &mut p3_upper, param_o);
    pack_m_vecs(
        &p3_upper,
        &mut cpk[param_pk_seed_bytes..],
        param_p3_limbs / m_vec_limbs,
        param_m,
    );

    Ok(())
}
