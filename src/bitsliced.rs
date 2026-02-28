// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bitsliced GF(16) vector operations on nibble-packed `u64` limbs.

use crate::gf16::mul_table;

/// LSB of each nibble: isolates bit 0 of every 4-bit element.
const MASK_LSB: u64 = 0x1111111111111111;
/// MSB of each nibble: isolates bit 3 of every 4-bit element.
const MASK_MSB: u64 = 0x8888888888888888;

/// Copy an m-vector: `dst = src`.
#[inline]
#[allow(dead_code)]
pub(crate) fn m_vec_copy(src: &[u64], dst: &mut [u64], m_vec_limbs: usize) {
    dst[..m_vec_limbs].copy_from_slice(&src[..m_vec_limbs]);
}

/// Add an m-vector: `acc ^= src`.
#[inline]
pub(crate) fn m_vec_add(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    for i in 0..m_vec_limbs {
        acc[i] ^= src[i];
    }
}

/// Multiply-accumulate: `acc += src * a` where a is a GF(16) scalar.
#[inline]
pub(crate) fn m_vec_mul_add(src: &[u64], a: u8, acc: &mut [u64], m_vec_limbs: usize) {
    let tab = mul_table(a);
    let t0 = u64::from(tab & 0xff);
    let t1 = u64::from((tab >> 8) & 0xf);
    let t2 = u64::from((tab >> 16) & 0xf);
    let t3 = u64::from((tab >> 24) & 0xf);

    for i in 0..m_vec_limbs {
        acc[i] ^= (src[i] & MASK_LSB).wrapping_mul(t0)
            ^ ((src[i] >> 1) & MASK_LSB).wrapping_mul(t1)
            ^ ((src[i] >> 2) & MASK_LSB).wrapping_mul(t2)
            ^ ((src[i] >> 3) & MASK_LSB).wrapping_mul(t3);
    }
}

/// Multiply by x and accumulate: `acc += src * x` in GF(16).
#[inline]
#[allow(dead_code)]
pub(crate) fn m_vec_mul_add_x(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    for i in 0..m_vec_limbs {
        let t = src[i] & MASK_MSB;
        acc[i] ^= ((src[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
    }
}

/// Multiply by x^{-1} and accumulate: `acc += src * x^{-1}` in GF(16).
#[inline]
#[allow(dead_code)]
pub(crate) fn m_vec_mul_add_x_inv(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    for i in 0..m_vec_limbs {
        let t = src[i] & MASK_LSB;
        acc[i] ^= ((src[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
    }
}

/// Apply mul-add-x-inv from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[inline]
fn bins_mul_add_x_inv(bins: &mut [u64], src: usize, dst: usize, n: usize) {
    for i in 0..n {
        let t = bins[src + i] & MASK_LSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) >> 1) ^ (t.wrapping_mul(9));
    }
}

/// Apply mul-add-x from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[inline]
fn bins_mul_add_x(bins: &mut [u64], src: usize, dst: usize, n: usize) {
    for i in 0..n {
        let t = bins[src + i] & MASK_MSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
    }
}

/// Multiply 16 bins using the Karatsuba-like decomposition and store result in `out`.
///
/// `bins` must have at least `16 * m_vec_limbs` elements.
/// `out` must have at least `m_vec_limbs` elements.
pub(crate) fn m_vec_multiply_bins(bins: &mut [u64], out: &mut [u64], m_vec_limbs: usize) {
    let mvl = m_vec_limbs;

    bins_mul_add_x_inv(bins, 5 * mvl, 10 * mvl, mvl);
    bins_mul_add_x(bins, 11 * mvl, 12 * mvl, mvl);
    bins_mul_add_x_inv(bins, 10 * mvl, 7 * mvl, mvl);
    bins_mul_add_x(bins, 12 * mvl, 6 * mvl, mvl);
    bins_mul_add_x_inv(bins, 7 * mvl, 14 * mvl, mvl);
    bins_mul_add_x(bins, 6 * mvl, 3 * mvl, mvl);
    bins_mul_add_x_inv(bins, 14 * mvl, 15 * mvl, mvl);
    bins_mul_add_x(bins, 3 * mvl, 8 * mvl, mvl);
    bins_mul_add_x_inv(bins, 15 * mvl, 13 * mvl, mvl);
    bins_mul_add_x(bins, 8 * mvl, 4 * mvl, mvl);
    bins_mul_add_x_inv(bins, 13 * mvl, 9 * mvl, mvl);
    bins_mul_add_x(bins, 4 * mvl, 2 * mvl, mvl);
    bins_mul_add_x_inv(bins, 9 * mvl, mvl, mvl);
    bins_mul_add_x(bins, 2 * mvl, mvl, mvl);

    out[..mvl].copy_from_slice(&bins[mvl..2 * mvl]);
}

/// Multiply-accumulate for variable-length vectors (used in echelon form).
///
/// Same as `m_vec_mul_add` but takes `legs` as the loop count
/// (which may differ from the parameter set's m_vec_limbs).
#[inline]
pub(crate) fn vec_mul_add_u64(legs: usize, src: &[u64], a: u8, acc: &mut [u64]) {
    let tab = mul_table(a);
    let t0 = u64::from(tab & 0xff);
    let t1 = u64::from((tab >> 8) & 0xf);
    let t2 = u64::from((tab >> 16) & 0xf);
    let t3 = u64::from((tab >> 24) & 0xf);

    for i in 0..legs {
        acc[i] ^= (src[i] & MASK_LSB).wrapping_mul(t0)
            ^ ((src[i] >> 1) & MASK_LSB).wrapping_mul(t1)
            ^ ((src[i] >> 2) & MASK_LSB).wrapping_mul(t2)
            ^ ((src[i] >> 3) & MASK_LSB).wrapping_mul(t3);
    }
}
