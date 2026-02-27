// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Matrix operations on bitsliced m-vectors for MAYO.

use crate::bitsliced::{m_vec_add, m_vec_mul_add, m_vec_multiply_bins};
use crate::params::MayoParameter;

/// Multiply m (possibly upper-triangular) matrices by a single matrix and accumulate.
///
/// `bs_mat` contains bitsliced m-vectors in row-major upper-triangular order.
/// `mat` is a plain byte matrix of size `bs_mat_cols x mat_cols`.
/// Result is accumulated into `acc` of size `bs_mat_rows x mat_cols` m-vectors.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mul_add_m_upper_triangular_mat_x_mat(
    m_vec_limbs: usize,
    bs_mat: &[u64],
    mat: &[u8],
    acc: &mut [u64],
    bs_mat_rows: usize,
    bs_mat_cols: usize,
    mat_cols: usize,
    triangular: bool,
) {
    let mut bs_mat_entries_used = 0;
    for r in 0..bs_mat_rows {
        let c_start = if triangular { r } else { 0 };
        for c in c_start..bs_mat_cols {
            for k in 0..mat_cols {
                let src_offset = m_vec_limbs * bs_mat_entries_used;
                let dst_offset = m_vec_limbs * (r * mat_cols + k);
                let scalar = mat[c * mat_cols + k];
                m_vec_mul_add(
                    &bs_mat[src_offset..src_offset + m_vec_limbs],
                    scalar,
                    &mut acc[dst_offset..dst_offset + m_vec_limbs],
                    m_vec_limbs,
                );
            }
            bs_mat_entries_used += 1;
        }
    }
}

/// Multiply m (possibly upper-triangular) matrices by the transpose of a single matrix.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mul_add_m_upper_triangular_mat_x_mat_trans(
    m_vec_limbs: usize,
    bs_mat: &[u64],
    mat: &[u8],
    acc: &mut [u64],
    bs_mat_rows: usize,
    bs_mat_cols: usize,
    mat_rows: usize,
    triangular: bool,
) {
    let mut bs_mat_entries_used = 0;
    for r in 0..bs_mat_rows {
        let c_start = if triangular { r } else { 0 };
        for c in c_start..bs_mat_cols {
            for k in 0..mat_rows {
                let src_offset = m_vec_limbs * bs_mat_entries_used;
                let dst_offset = m_vec_limbs * (r * mat_rows + k);
                let scalar = mat[k * bs_mat_cols + c];
                m_vec_mul_add(
                    &bs_mat[src_offset..src_offset + m_vec_limbs],
                    scalar,
                    &mut acc[dst_offset..dst_offset + m_vec_limbs],
                    m_vec_limbs,
                );
            }
            bs_mat_entries_used += 1;
        }
    }
}

/// Multiply the transpose of a single matrix by m matrices and accumulate.
pub(crate) fn mul_add_mat_trans_x_m_mat(
    m_vec_limbs: usize,
    mat: &[u8],
    bs_mat: &[u64],
    acc: &mut [u64],
    mat_rows: usize,
    mat_cols: usize,
    bs_mat_cols: usize,
) {
    for r in 0..mat_cols {
        for c in 0..mat_rows {
            for k in 0..bs_mat_cols {
                let src_offset = m_vec_limbs * (c * bs_mat_cols + k);
                let dst_offset = m_vec_limbs * (r * bs_mat_cols + k);
                let scalar = mat[c * mat_cols + r];
                m_vec_mul_add(
                    &bs_mat[src_offset..src_offset + m_vec_limbs],
                    scalar,
                    &mut acc[dst_offset..dst_offset + m_vec_limbs],
                    m_vec_limbs,
                );
            }
        }
    }
}

/// Multiply a single matrix by m matrices and accumulate.
pub(crate) fn mul_add_mat_x_m_mat(
    m_vec_limbs: usize,
    mat: &[u8],
    bs_mat: &[u64],
    acc: &mut [u64],
    mat_rows: usize,
    mat_cols: usize,
    bs_mat_cols: usize,
) {
    for r in 0..mat_rows {
        for c in 0..mat_cols {
            for k in 0..bs_mat_cols {
                let src_offset = m_vec_limbs * (c * bs_mat_cols + k);
                let dst_offset = m_vec_limbs * (r * bs_mat_cols + k);
                let scalar = mat[r * mat_cols + c];
                m_vec_mul_add(
                    &bs_mat[src_offset..src_offset + m_vec_limbs],
                    scalar,
                    &mut acc[dst_offset..dst_offset + m_vec_limbs],
                    m_vec_limbs,
                );
            }
        }
    }
}

/// Compute P1 * O (upper-triangular P1 times O matrix).
pub(crate) fn p1_times_o<P: MayoParameter>(p1: &[u64], o: &[u8], acc: &mut [u64]) {
    mul_add_m_upper_triangular_mat_x_mat(
        P::M_VEC_LIMBS, p1, o, acc, P::V, P::V, P::O, true,
    );
}

/// Compute P1 * V^t (upper-triangular P1 times transpose of V).
pub(crate) fn p1_times_vt<P: MayoParameter>(p1: &[u64], v: &[u8], acc: &mut [u64]) {
    mul_add_m_upper_triangular_mat_x_mat_trans(
        P::M_VEC_LIMBS, p1, v, acc, P::V, P::V, P::K, true,
    );
}

/// Compute (P1 + P1^t) * O and add to acc (which already contains P2).
///
/// This computes L = (P1 + P1^t) * O + P2 by skipping diagonal entries
/// and adding both (r,c) and (c,r) contributions.
pub(crate) fn p1p1t_times_o<P: MayoParameter>(p1: &[u64], o: &[u8], acc: &mut [u64]) {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_o = P::O;
    let param_v = P::V;

    let mut bs_mat_entries_used = 0;
    for r in 0..param_v {
        for c in r..param_v {
            if c == r {
                bs_mat_entries_used += 1;
                continue;
            }
            for k in 0..param_o {
                let src_offset = m_vec_limbs * bs_mat_entries_used;
                // P1[r,c] * O[c,k] -> acc[r,k]
                m_vec_mul_add(
                    &p1[src_offset..src_offset + m_vec_limbs],
                    o[c * param_o + k],
                    &mut acc[m_vec_limbs * (r * param_o + k)..m_vec_limbs * (r * param_o + k) + m_vec_limbs],
                    m_vec_limbs,
                );
                // P1[r,c] * O[r,k] -> acc[c,k] (transpose contribution)
                m_vec_mul_add(
                    &p1[src_offset..src_offset + m_vec_limbs],
                    o[r * param_o + k],
                    &mut acc[m_vec_limbs * (c * param_o + k)..m_vec_limbs * (c * param_o + k) + m_vec_limbs],
                    m_vec_limbs,
                );
            }
            bs_mat_entries_used += 1;
        }
    }
}

/// Compute M matrices (V^t * L) and v^t * P1 * v (VPV).
pub(crate) fn compute_m_and_vpv<P: MayoParameter>(
    vdec: &[u8],
    l: &[u64],
    p1: &[u64],
    vl: &mut [u64],
    vp1v: &mut [u64],
) {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_k = P::K;
    let param_v = P::V;
    let param_o = P::O;

    // VL = V * L
    mul_add_mat_x_m_mat(m_vec_limbs, vdec, l, vl, param_k, param_v, param_o);

    // VP1V = V * P1 * V^t
    let mut pv = vec![0u64; param_v * param_k * m_vec_limbs];
    p1_times_vt::<P>(p1, vdec, &mut pv);
    mul_add_mat_x_m_mat(m_vec_limbs, vdec, &pv, vp1v, param_k, param_v, param_k);
}

/// Compute P3 = O^t * (P1*O + P2).
///
/// Note: this modifies P2 in place (adds P1*O to it).
pub(crate) fn compute_p3<P: MayoParameter>(
    p1: &[u64],
    p2: &mut [u64],
    o: &[u8],
    p3: &mut [u64],
) {
    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_v = P::V;
    let param_o = P::O;

    // P2 += P1 * O
    p1_times_o::<P>(p1, o, p2);

    // P3 = O^t * P2
    mul_add_mat_trans_x_m_mat(m_vec_limbs, o, p2, p3, param_v, param_o, param_o);
}

/// Compute upper-triangular form of a square matrix of m-vectors.
///
/// For an `size x size` matrix, produce the upper-triangular representation
/// with `size*(size+1)/2` entries, where diagonal entries are kept and
/// off-diagonal entries are summed: upper[r,c] = mat[r,c] + mat[c,r].
pub(crate) fn m_upper(m_vec_limbs: usize, input: &[u64], output: &mut [u64], size: usize) {
    let mut m_vecs_stored = 0;
    for r in 0..size {
        for c in r..size {
            let dst = &mut output[m_vec_limbs * m_vecs_stored..m_vec_limbs * (m_vecs_stored + 1)];
            let src_rc = &input[m_vec_limbs * (r * size + c)..m_vec_limbs * (r * size + c + 1)];
            dst[..m_vec_limbs].copy_from_slice(&src_rc[..m_vec_limbs]);
            if r != c {
                let src_cr_start = m_vec_limbs * (c * size + r);
                for i in 0..m_vec_limbs {
                    dst[i] ^= input[src_cr_start + i];
                }
            }
            m_vecs_stored += 1;
        }
    }
}

/// Compute P * S^t and then S * P * S^t (the SPS matrix for verification).
pub(crate) fn m_calculate_ps_sps<P: MayoParameter>(
    p1: &[u64],
    p2: &[u64],
    p3: &[u64],
    s: &[u8],
    sps: &mut [u64],
) {
    let m = P::M;
    let v = P::V;
    let o = P::O;
    let k = P::K;
    let n = P::N;
    let m_vec_limbs = P::M_VEC_LIMBS;

    // Compute PS using bins accumulator
    let mut ps = vec![0u64; n * k * m_vec_limbs];
    let acc_size = 16 * m.div_ceil(16) * k * n;
    let mut accumulator = vec![0u64; acc_size];

    let mut p1_used = 0;
    for row in 0..v {
        for j in row..v {
            for col in 0..k {
                let bin_idx = ((row * k + col) * 16 + usize::from(s[col * n + j])) * m_vec_limbs;
                m_vec_add(
                    &p1[p1_used * m_vec_limbs..(p1_used + 1) * m_vec_limbs],
                    &mut accumulator[bin_idx..bin_idx + m_vec_limbs],
                    m_vec_limbs,
                );
            }
            p1_used += 1;
        }

        for j in 0..o {
            for col in 0..k {
                let bin_idx = ((row * k + col) * 16 + usize::from(s[col * n + j + v])) * m_vec_limbs;
                m_vec_add(
                    &p2[(row * o + j) * m_vec_limbs..(row * o + j + 1) * m_vec_limbs],
                    &mut accumulator[bin_idx..bin_idx + m_vec_limbs],
                    m_vec_limbs,
                );
            }
        }
    }

    let mut p3_used = 0;
    for row in v..n {
        for j in row..n {
            for col in 0..k {
                let bin_idx = ((row * k + col) * 16 + usize::from(s[col * n + j])) * m_vec_limbs;
                m_vec_add(
                    &p3[p3_used * m_vec_limbs..(p3_used + 1) * m_vec_limbs],
                    &mut accumulator[bin_idx..bin_idx + m_vec_limbs],
                    m_vec_limbs,
                );
            }
            p3_used += 1;
        }
    }

    // Multiply bins
    let mut idx = 0;
    while idx < n * k {
        m_vec_multiply_bins(
            &mut accumulator[idx * 16 * m_vec_limbs..],
            &mut ps[idx * m_vec_limbs..(idx + 1) * m_vec_limbs],
            m_vec_limbs,
        );
        idx += 1;
    }

    // Compute SPS = S * PS
    let sps_acc_size = 16 * m.div_ceil(16) * k * k;
    let mut sps_accumulator = vec![0u64; sps_acc_size];

    for row in 0..k {
        for j in 0..n {
            for col in 0..k {
                let bin_idx = ((row * k + col) * 16 + usize::from(s[row * n + j])) * m_vec_limbs;
                m_vec_add(
                    &ps[(j * k + col) * m_vec_limbs..(j * k + col + 1) * m_vec_limbs],
                    &mut sps_accumulator[bin_idx..bin_idx + m_vec_limbs],
                    m_vec_limbs,
                );
            }
        }
    }

    idx = 0;
    while idx < k * k {
        m_vec_multiply_bins(
            &mut sps_accumulator[idx * 16 * m_vec_limbs..],
            &mut sps[idx * m_vec_limbs..(idx + 1) * m_vec_limbs],
            m_vec_limbs,
        );
        idx += 1;
    }
}
