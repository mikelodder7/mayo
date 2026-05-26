// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bitsliced GF(16) vector operations on nibble-packed `u64` limbs.

use crate::gf16::{mul_f, mul_table};

/// LSB of each nibble: isolates bit 0 of every 4-bit element.
const MASK_LSB: u64 = 0x1111111111111111;
/// MSB of each nibble: isolates bit 3 of every 4-bit element.
const MASK_MSB: u64 = 0x8888888888888888;

/// Add an m-vector: `acc ^= src`.
#[inline]
pub(crate) fn m_vec_add(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    for i in 0..m_vec_limbs {
        acc[i] ^= src[i];
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Scalar fallback for m_vec_mul_add / vec_mul_add_u64
// ────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn m_vec_mul_add_scalar(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
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

// ────────────────────────────────────────────────────────────────────────────
// x86 / x86_64 SSSE3 fast path
//
// Each 16-byte SSE register holds 2 u64 limbs = 32 packed GF(16) elements.
// VPSHUFB (pshufb) performs a byte-wise table lookup in one cycle, replacing
// 4 scalar wrapping_mul passes per limb.
//
// Table construction (constant-time, done once per call):
//   lo_tbl[i] = mul_f(a, i)        — result in low  nibble of output byte
//   hi_tbl[i] = mul_f(a, i) << 4   — result in high nibble of output byte
//
// Per 16-byte chunk:
//   lo_idx = data & 0x0F per byte    (low  nibbles of each byte, 0..15)
//   hi_idx = (data >> 4) & 0x0F     (high nibbles, via _mm_srli_epi16+mask)
//   result = shuffle(lo_tbl, lo_idx) ^ shuffle(hi_tbl, hi_idx)
// ────────────────────────────────────────────────────────────────────────────

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "ssse3")]
unsafe fn m_vec_mul_add_ssse3(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let mut lo_bytes = [0u8; 16];
    let mut hi_bytes = [0u8; 16];
    for i in 0..16u8 {
        let m = mul_f(a, i);
        lo_bytes[i as usize] = m;
        hi_bytes[i as usize] = m << 4;
    }
    let lo_tbl = _mm_loadu_si128(lo_bytes.as_ptr().cast());
    let hi_tbl = _mm_loadu_si128(hi_bytes.as_ptr().cast());
    let lo_mask = _mm_set1_epi8(0x0F_u8 as i8);

    let src_ptr = src.as_ptr().cast::<u8>();
    let acc_ptr = acc.as_mut_ptr().cast::<u8>();
    let total_bytes = legs * 8;
    let mut i = 0usize;

    while i + 16 <= total_bytes {
        let data = _mm_loadu_si128(src_ptr.add(i).cast());
        let acc_v = _mm_loadu_si128(acc_ptr.add(i).cast());

        let lo_idx = _mm_and_si128(data, lo_mask);
        // _mm_srli_epi16 shifts 16-bit lanes right; masking extracts high nibble of each byte
        let hi_idx = _mm_and_si128(_mm_srli_epi16(data, 4), lo_mask);

        let product = _mm_xor_si128(
            _mm_shuffle_epi8(lo_tbl, lo_idx),
            _mm_shuffle_epi8(hi_tbl, hi_idx),
        );
        _mm_storeu_si128(acc_ptr.add(i).cast(), _mm_xor_si128(acc_v, product));
        i += 16;
    }

    // At most one trailing u64 limb (when `legs` is odd).
    let j = i / 8;
    if j < legs {
        m_vec_mul_add_scalar(&src[j..], a, &mut acc[j..], legs - j);
    }
}

// ────────────────────────────────────────────────────────────────────────────
// aarch64 NEON fast path
//
// NEON is mandatory on all AArch64 targets, so no runtime feature check is
// needed. vqtbl1q_u8 is the NEON equivalent of VPSHUFB (zero-on-index≥16).
// vshrq_n_u8 shifts each byte individually (unlike _mm_srli_epi16), so no
// extra masking is required for the high-nibble extraction.
// ────────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn m_vec_mul_add_neon(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    use std::arch::aarch64::*;

    let mut lo_bytes = [0u8; 16];
    let mut hi_bytes = [0u8; 16];
    for i in 0..16u8 {
        let m = mul_f(a, i);
        lo_bytes[i as usize] = m;
        hi_bytes[i as usize] = m << 4;
    }

    // SAFETY: pointers derived from valid slices; loop stays within bounds.
    unsafe {
        let lo_tbl = vld1q_u8(lo_bytes.as_ptr());
        let hi_tbl = vld1q_u8(hi_bytes.as_ptr());
        let lo_mask = vdupq_n_u8(0x0F);

        let src_ptr = src.as_ptr().cast::<u8>();
        let acc_ptr = acc.as_mut_ptr().cast::<u8>();
        let total_bytes = legs * 8;
        let mut i = 0usize;

        while i + 16 <= total_bytes {
            let data = vld1q_u8(src_ptr.add(i));
            let acc_v = vld1q_u8(acc_ptr.add(i));

            let lo_idx = vandq_u8(data, lo_mask);
            // vshrq_n_u8 shifts each byte right — directly gives high nibble in 0..15
            let hi_idx = vshrq_n_u8::<4>(data);

            let product = veorq_u8(vqtbl1q_u8(lo_tbl, lo_idx), vqtbl1q_u8(hi_tbl, hi_idx));
            vst1q_u8(acc_ptr.add(i), veorq_u8(acc_v, product));
            i += 16;
        }

        let j = i / 8;
        if j < legs {
            m_vec_mul_add_scalar(&src[j..], a, &mut acc[j..], legs - j);
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Architecture-dispatched public entry points
// ────────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
#[inline]
fn dispatch_mul_add(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    // SAFETY: NEON is part of the AArch64 baseline ISA.
    unsafe { m_vec_mul_add_neon(src, a, acc, legs) }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
fn dispatch_mul_add(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    if is_x86_feature_detected!("ssse3") {
        // SAFETY: ssse3 confirmed available.
        unsafe { m_vec_mul_add_ssse3(src, a, acc, legs) }
    } else {
        m_vec_mul_add_scalar(src, a, acc, legs)
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64")))]
#[inline]
fn dispatch_mul_add(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    m_vec_mul_add_scalar(src, a, acc, legs)
}

/// Multiply-accumulate: `acc += src * a` where `a` is a GF(16) scalar.
#[inline]
pub(crate) fn m_vec_mul_add(src: &[u64], a: u8, acc: &mut [u64], m_vec_limbs: usize) {
    dispatch_mul_add(src, a, acc, m_vec_limbs);
}

/// Multiply-accumulate for variable-length vectors (used in echelon form).
#[inline]
pub(crate) fn vec_mul_add_u64(legs: usize, src: &[u64], a: u8, acc: &mut [u64]) {
    dispatch_mul_add(src, a, acc, legs);
}

// ────────────────────────────────────────────────────────────────────────────
// Remaining bitsliced primitives
// ────────────────────────────────────────────────────────────────────────────

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
