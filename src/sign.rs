// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO signature generation.

use crate::codec::{decode, encode};
use crate::error::Result;
use crate::gf16::{mat_add, mat_mul, mul_f};
use crate::keygen::expand_p1_p2;
use crate::matrix_ops::{compute_m_and_vpv, p1p1t_times_o};
use crate::params::{MayoParameter, F_TAIL_LEN};
use crate::sample::sample_solution;
use rand::CryptoRng;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Expand a compact secret key into P1, L (=(P1+P1^t)*O + P2), and O.
fn expand_sk<P: MayoParameter>(
    csk: &[u8],
) -> (Vec<u64>, Vec<u8>) {
    let param_o = P::O;
    let param_v = P::V;
    let param_o_bytes = P::O_BYTES;
    let param_pk_seed_bytes = P::PK_SEED_BYTES;
    let param_sk_seed_bytes = P::SK_SEED_BYTES;

    let seed_sk = &csk[..param_sk_seed_bytes];

    // S = SHAKE256(seed_sk) -> pk_seed || O_bytes
    let mut s = vec![0u8; param_pk_seed_bytes + param_o_bytes];
    let mut hasher = Shake256::default();
    hasher.update(seed_sk);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut s);

    let seed_pk = &s[..param_pk_seed_bytes];

    // Decode O
    let mut o = vec![0u8; param_v * param_o];
    decode(&s[param_pk_seed_bytes..], &mut o, param_v * param_o);

    // Expand P1 and P2
    let mut p = expand_p1_p2::<P>(seed_pk);

    // Compute L = (P1 + P1^t)*O + P2
    // L replaces P2 in memory
    {
        let (p1, l) = p.split_at_mut(P::P1_LIMBS);
        p1p1t_times_o::<P>(p1, &o, l);
    }

    (p, o)
}

/// Transpose a 16x16 matrix of nibbles packed in 16 u64 values.
fn transpose_16x16_nibbles(m: &mut [u64]) {
    let even_nibbles: u64 = 0x0f0f0f0f0f0f0f0f;
    let even_bytes: u64 = 0x00ff00ff00ff00ff;
    let even_2bytes: u64 = 0x0000ffff0000ffff;
    let even_half: u64 = 0x00000000ffffffff;

    let mut i = 0;
    while i < 16 {
        let t = ((m[i] >> 4) ^ m[i + 1]) & even_nibbles;
        m[i] ^= t << 4;
        m[i + 1] ^= t;
        i += 2;
    }

    i = 0;
    while i < 16 {
        let t0 = ((m[i] >> 8) ^ m[i + 2]) & even_bytes;
        let t1 = ((m[i + 1] >> 8) ^ m[i + 3]) & even_bytes;
        m[i] ^= t0 << 8;
        m[i + 1] ^= t1 << 8;
        m[i + 2] ^= t0;
        m[i + 3] ^= t1;
        i += 4;
    }

    for i in 0..4 {
        let t0 = ((m[i] >> 16) ^ m[i + 4]) & even_2bytes;
        let t1 = ((m[i + 8] >> 16) ^ m[i + 12]) & even_2bytes;
        m[i] ^= t0 << 16;
        m[i + 8] ^= t1 << 16;
        m[i + 4] ^= t0;
        m[i + 12] ^= t1;
    }

    for i in 0..8 {
        let t = ((m[i] >> 32) ^ m[i + 8]) & even_half;
        m[i] ^= t << 32;
        m[i + 8] ^= t;
    }
}

/// Compute the right-hand side: y = t XOR reduce(vPv).
fn compute_rhs<P: MayoParameter>(vpv: &mut [u64], t: &[u8], y: &mut [u8]) {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_m = P::M;
    let param_k = P::K;
    let f_tail = P::F_TAIL;

    let top_pos = ((param_m - 1) % 16) * 4;

    // Zero out tails of m_vecs if necessary
    if param_m % 16 != 0 {
        let mut mask: u64 = 1;
        mask <<= (param_m % 16) * 4;
        mask -= 1;
        for i in 0..(param_k * param_k) {
            vpv[i * m_vec_limbs + m_vec_limbs - 1] &= mask;
        }
    }

    let mut temp = vec![0u64; m_vec_limbs];

    for i in (0..param_k).rev() {
        for j in i..param_k {
            // Multiply by X (shift up 4 bits)
            let top = ((temp[m_vec_limbs - 1] >> top_pos) % 16) as u8;
            temp[m_vec_limbs - 1] <<= 4;
            for k in (0..m_vec_limbs - 1).rev() {
                temp[k + 1] ^= temp[k] >> 60;
                temp[k] <<= 4;
            }

            // Reduce mod f(X)
            for (jj, &f_coeff) in f_tail.iter().enumerate().take(F_TAIL_LEN) {
                let product = mul_f(top, f_coeff);
                if jj % 2 == 0 {
                    // XOR into the low nibble of byte jj/2
                    let limb_idx = (jj / 2) / 8;
                    let byte_idx = (jj / 2) % 8;
                    temp[limb_idx] ^= u64::from(product) << (byte_idx * 8);
                } else {
                    // XOR into the high nibble of byte jj/2
                    let limb_idx = (jj / 2) / 8;
                    let byte_idx = (jj / 2) % 8;
                    temp[limb_idx] ^= u64::from(product) << (byte_idx * 8 + 4);
                }
            }

            // Extract from vPv and add
            let idx_ij = (i * param_k + j) * m_vec_limbs;
            let idx_ji = (j * param_k + i) * m_vec_limbs;
            for k in 0..m_vec_limbs {
                let sym = if i != j { vpv[idx_ji + k] } else { 0 };
                temp[k] ^= vpv[idx_ij + k] ^ sym;
            }
        }
    }

    // Compute y = t XOR temp (unpacked)
    for i in (0..param_m).step_by(2) {
        let limb_idx = (i / 2) / 8;
        let byte_idx = (i / 2) % 8;
        let byte_val = ((temp[limb_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        y[i] = t[i] ^ (byte_val & 0xF);
        if i + 1 < param_m {
            y[i + 1] = t[i + 1] ^ (byte_val >> 4);
        }
    }
}

/// Compute the linearized system matrix A from the M matrices (VtL).
fn compute_a<P: MayoParameter>(vtl: &mut [u64], a_out: &mut [u8]) {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_m = P::M;
    let param_o = P::O;
    let param_k = P::K;
    let a_cols = P::A_COLS;
    let f_tail = P::F_TAIL;
    let m_over_8 = param_m.div_ceil(8);

    let a_width = (param_o * param_k).div_ceil(16) * 16;

    let mut bits_to_shift: usize = 0;
    let mut words_to_shift: usize = 0;

    let a_total = a_width * m_over_8;
    let mut a = vec![0u64; a_total];

    // Zero out tails of m_vecs if necessary
    if param_m % 16 != 0 {
        let mut mask: u64 = 1;
        mask <<= (param_m % 16) * 4;
        mask -= 1;
        for i in 0..(param_o * param_k) {
            vtl[i * m_vec_limbs + m_vec_limbs - 1] &= mask;
        }
    }

    for i in 0..param_k {
        for j in (i..param_k).rev() {
            // Add Mj to A
            let mj_base = j * m_vec_limbs * param_o;
            for c in 0..param_o {
                for k in 0..m_vec_limbs {
                    let src = vtl[mj_base + k + c * m_vec_limbs];
                    let dst_idx = param_o * i + c + (k + words_to_shift) * a_width;
                    if dst_idx < a_total {
                        a[dst_idx] ^= src << bits_to_shift;
                    }
                    if bits_to_shift > 0 {
                        let dst_idx2 = param_o * i + c + (k + words_to_shift + 1) * a_width;
                        if dst_idx2 < a_total {
                            a[dst_idx2] ^= src >> (64 - bits_to_shift);
                        }
                    }
                }
            }

            if i != j {
                let mi_base = i * m_vec_limbs * param_o;
                for c in 0..param_o {
                    for k in 0..m_vec_limbs {
                        let src = vtl[mi_base + k + c * m_vec_limbs];
                        let dst_idx = param_o * j + c + (k + words_to_shift) * a_width;
                        if dst_idx < a_total {
                            a[dst_idx] ^= src << bits_to_shift;
                        }
                        if bits_to_shift > 0 {
                            let dst_idx2 = param_o * j + c + (k + words_to_shift + 1) * a_width;
                            if dst_idx2 < a_total {
                                a[dst_idx2] ^= src >> (64 - bits_to_shift);
                            }
                        }
                    }
                }
            }

            bits_to_shift += 4;
            if bits_to_shift == 64 {
                words_to_shift += 1;
                bits_to_shift = 0;
            }
        }
    }

    // Transpose 16x16 nibble blocks
    let total_transpose = a_width * (param_m + (param_k + 1) * param_k / 2).div_ceil(16);
    let mut c = 0;
    while c < total_transpose {
        if c + 16 <= a.len() {
            transpose_16x16_nibbles(&mut a[c..c + 16]);
        }
        c += 16;
    }

    // Reduce mod f(X)
    let mut tab = [0u8; F_TAIL_LEN * 4];
    for i in 0..F_TAIL_LEN {
        tab[4 * i] = mul_f(f_tail[i], 1);
        tab[4 * i + 1] = mul_f(f_tail[i], 2);
        tab[4 * i + 2] = mul_f(f_tail[i], 4);
        tab[4 * i + 3] = mul_f(f_tail[i], 8);
    }

    let low_bit_in_nibble: u64 = 0x1111111111111111;

    let mut c = 0;
    while c < a_width {
        for r in param_m..(param_m + (param_k + 1) * param_k / 2) {
            let pos = (r / 16) * a_width + c + (r % 16);
            if pos >= a.len() {
                continue;
            }
            let val = a[pos];
            let t0 = val & low_bit_in_nibble;
            let t1 = (val >> 1) & low_bit_in_nibble;
            let t2 = (val >> 2) & low_bit_in_nibble;
            let t3 = (val >> 3) & low_bit_in_nibble;

            for t in 0..F_TAIL_LEN {
                let target_r = r + t - param_m;
                let target_pos = (target_r / 16) * a_width + c + (target_r % 16);
                if target_pos < a.len() {
                    a[target_pos] ^= t0.wrapping_mul(u64::from(tab[4 * t]))
                        ^ t1.wrapping_mul(u64::from(tab[4 * t + 1]))
                        ^ t2.wrapping_mul(u64::from(tab[4 * t + 2]))
                        ^ t3.wrapping_mul(u64::from(tab[4 * t + 3]));
                }
            }
        }
        c += 16;
    }

    // Extract A matrix from transposed packed form
    for r in (0..param_m).step_by(16) {
        let mut c = 0;
        while c < a_cols - 1 {
            for i in 0..16 {
                if r + i >= param_m {
                    break;
                }
                let src_pos = r * a_width / 16 + c + i;
                let decode_len = 16.min(a_cols - 1 - c);
                if src_pos < a.len() {
                    let src_bytes = a[src_pos].to_le_bytes();
                    decode_packed_nibbles(
                        &src_bytes,
                        &mut a_out[(r + i) * a_cols + c..],
                        decode_len,
                    );
                }
            }
            c += 16;
        }
    }
}

/// Decode up to `len` nibbles from a packed byte slice.
fn decode_packed_nibbles(input: &[u8], output: &mut [u8], len: usize) {
    let mut out_idx = 0;
    let mut i = 0;
    while out_idx < len && i < input.len() {
        output[out_idx] = input[i] & 0xf;
        out_idx += 1;
        if out_idx < len {
            output[out_idx] = input[i] >> 4;
            out_idx += 1;
        }
        i += 1;
    }
}

/// Generate a MAYO signature for a message.
///
/// Returns the signature length on success.
pub(crate) fn mayo_sign_signature<P: MayoParameter>(
    sig: &mut [u8],
    msg: &[u8],
    csk: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<usize> {
    let param_m = P::M;
    let param_n = P::N;
    let param_o = P::O;
    let param_k = P::K;
    let param_v = P::V;
    let param_m_bytes = P::M_BYTES;
    let param_v_bytes = P::V_BYTES;
    let param_r_bytes = P::R_BYTES;
    let param_sig_bytes = P::SIG_BYTES;
    let param_a_cols = P::A_COLS;
    let param_digest_bytes = P::DIGEST_BYTES;
    let param_sk_seed_bytes = P::SK_SEED_BYTES;
    let param_salt_bytes = P::SALT_BYTES;

    // Expand secret key
    let (p, o_mat) = expand_sk::<P>(csk);

    let seed_sk = &csk[..param_sk_seed_bytes];

    let p1 = &p[..P::P1_LIMBS];
    let l = &p[P::P1_LIMBS..];

    // Hash message
    let mut tmp = vec![0u8; param_digest_bytes + param_salt_bytes + param_sk_seed_bytes + 1];
    {
        let mut hasher = Shake256::default();
        hasher.update(msg);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut tmp[..param_digest_bytes]);
    }

    // Choose randomizer
    rng.fill_bytes(&mut tmp[param_digest_bytes..param_digest_bytes + param_salt_bytes]);

    // Compute salt = SHAKE256(digest || random || seed_sk)
    let mut salt = vec![0u8; param_salt_bytes];
    tmp[param_digest_bytes + param_salt_bytes..param_digest_bytes + param_salt_bytes + param_sk_seed_bytes]
        .copy_from_slice(seed_sk);
    {
        let mut hasher = Shake256::default();
        hasher.update(&tmp[..param_digest_bytes + param_salt_bytes + param_sk_seed_bytes]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut salt);
    }

    // Compute t = SHAKE256(digest || salt)
    let mut tenc = vec![0u8; param_m_bytes];
    let mut t = vec![0u8; param_m];
    tmp[param_digest_bytes..param_digest_bytes + param_salt_bytes].copy_from_slice(&salt);
    {
        let mut hasher = Shake256::default();
        hasher.update(&tmp[..param_digest_bytes + param_salt_bytes]);
        let mut reader = hasher.finalize_xof();
        reader.read(&mut tenc);
    }
    decode(&tenc, &mut t, param_m);

    let ctrbyte_offset = param_digest_bytes + param_salt_bytes + param_sk_seed_bytes;

    let mut x = vec![0u8; param_k * param_n];
    let mut s = vec![0u8; param_k * param_n];
    let mut vdec = vec![0u8; param_v * param_k];

    for ctr in 0..=255u8 {
        tmp[ctrbyte_offset] = ctr;

        // Generate V and r
        let mut v_and_r = vec![0u8; param_k * param_v_bytes + param_r_bytes];
        {
            let mut hasher = Shake256::default();
            hasher.update(&tmp[..ctrbyte_offset + 1]);
            let mut reader = hasher.finalize_xof();
            reader.read(&mut v_and_r);
        }

        // Decode the v_i vectors
        for i in 0..param_k {
            decode(
                &v_and_r[i * param_v_bytes..],
                &mut vdec[i * param_v..],
                param_v,
            );
        }

        // Compute M matrices and vPv
        let m_vec_limbs = P::M_VEC_LIMBS;
        let mut mtmp = vec![0u64; param_k * param_o * m_vec_limbs];
        let mut vpv = vec![0u64; param_k * param_k * m_vec_limbs];

        compute_m_and_vpv::<P>(&vdec, l, p1, &mut mtmp, &mut vpv);

        // Compute y = t XOR reduce(vPv)
        let mut y = vec![0u8; param_m];
        compute_rhs::<P>(&mut vpv, &t, &mut y);

        // Compute the linearized system A
        let a_row_size = param_m.div_ceil(8) * 8;
        let mut a_matrix = vec![0u8; a_row_size * param_a_cols];
        compute_a::<P>(&mut mtmp, &mut a_matrix);

        // Clear last column
        for i in 0..param_m {
            a_matrix[(1 + i) * param_a_cols - 1] = 0;
        }

        // Decode r
        let mut r = vec![0u8; param_k * param_o + 1];
        decode(
            &v_and_r[param_k * param_v_bytes..],
            &mut r,
            param_k * param_o,
        );

        if sample_solution(
            &mut a_matrix,
            &y,
            &r,
            &mut x,
            param_k,
            param_o,
            param_m,
            param_a_cols,
        ) {
            break;
        }
    }

    // Compute s[i] = v[i] + O*x[i]
    for i in 0..param_k {
        let vi = &vdec[i * param_v..(i + 1) * param_v];
        let xi = &x[i * param_o..(i + 1) * param_o];
        let mut ox = vec![0u8; param_v];
        mat_mul(&o_mat, xi, &mut ox, param_o, param_v, 1);
        mat_add(vi, &ox, &mut s[i * param_n..], param_v, 1);
        s[i * param_n + param_v..i * param_n + param_n]
            .copy_from_slice(&x[i * param_o..(i + 1) * param_o]);
    }

    encode(&s, sig, param_n * param_k);
    sig[param_sig_bytes - param_salt_bytes..param_sig_bytes].copy_from_slice(&salt);

    Ok(param_sig_bytes)
}
