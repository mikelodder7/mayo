// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bitsliced GF(16) vector operations on nibble-packed `u64` limbs.

use crate::gf16::mul_table;

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
    let lsb_mask: u64 = 0x1111111111111111;

    for i in 0..m_vec_limbs {
        acc[i] ^= (src[i] & lsb_mask).wrapping_mul(u64::from(tab & 0xff))
            ^ ((src[i] >> 1) & lsb_mask).wrapping_mul(u64::from((tab >> 8) & 0xf))
            ^ ((src[i] >> 2) & lsb_mask).wrapping_mul(u64::from((tab >> 16) & 0xf))
            ^ ((src[i] >> 3) & lsb_mask).wrapping_mul(u64::from((tab >> 24) & 0xf));
    }
}

/// Multiply by x and accumulate: `acc += src * x` in GF(16).
#[inline]
#[allow(dead_code)]
pub(crate) fn m_vec_mul_add_x(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    let mask_msb: u64 = 0x8888888888888888;
    for i in 0..m_vec_limbs {
        let t = src[i] & mask_msb;
        acc[i] ^= ((src[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
    }
}

/// Multiply by x^{-1} and accumulate: `acc += src * x^{-1}` in GF(16).
#[inline]
#[allow(dead_code)]
pub(crate) fn m_vec_mul_add_x_inv(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    let mask_lsb: u64 = 0x1111111111111111;
    for i in 0..m_vec_limbs {
        let t = src[i] & mask_lsb;
        acc[i] ^= ((src[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
    }
}

/// Multiply 16 bins using the Karatsuba-like decomposition and store result in `out`.
///
/// `bins` must have at least `16 * m_vec_limbs` elements.
/// `out` must have at least `m_vec_limbs` elements.
pub(crate) fn m_vec_multiply_bins(bins: &mut [u64], out: &mut [u64], m_vec_limbs: usize) {
    // This sequence of operations reduces the 16 bins to a single result.
    // The pattern matches the C reference exactly.
    {
        let (left, right) = bins.split_at_mut(10 * m_vec_limbs);
        let src = &left[5 * m_vec_limbs..6 * m_vec_limbs];
        // m_vec_mul_add_x_inv(bins+5*mvl, bins+10*mvl)
        let mask_lsb: u64 = 0x1111111111111111;
        for i in 0..m_vec_limbs {
            let t = src[i] & mask_lsb;
            right[i] ^= ((src[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
        }
    }
    {
        let (left, right) = bins.split_at_mut(12 * m_vec_limbs);
        let src = &left[11 * m_vec_limbs..12 * m_vec_limbs];
        let mask_msb: u64 = 0x8888888888888888;
        for i in 0..m_vec_limbs {
            let t = src[i] & mask_msb;
            right[i] ^= ((src[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
        }
    }
    {
        let (left, right) = bins.split_at_mut(10 * m_vec_limbs);
        // We need bins[10*mvl..11*mvl] -> that's right[0..mvl]
        // and bins[7*mvl..8*mvl] -> that's left[7*mvl..8*mvl]
        let mask_lsb: u64 = 0x1111111111111111;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_lsb;
            left[7 * m_vec_limbs + i] ^= ((right[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
        }
    }
    {
        let (left, right) = bins.split_at_mut(12 * m_vec_limbs);
        // m_vec_mul_add_x(bins+12*mvl, bins+6*mvl)
        let mask_msb: u64 = 0x8888888888888888;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_msb;
            left[6 * m_vec_limbs + i] ^= ((right[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
        }
    }
    {
        let (left, right) = bins.split_at_mut(14 * m_vec_limbs);
        // m_vec_mul_add_x_inv(bins+7*mvl, bins+14*mvl)
        let src = &left[7 * m_vec_limbs..8 * m_vec_limbs];
        let mask_lsb: u64 = 0x1111111111111111;
        for i in 0..m_vec_limbs {
            let t = src[i] & mask_lsb;
            right[i] ^= ((src[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
        }
    }
    {
        let (left, right) = bins.split_at_mut(6 * m_vec_limbs);
        // m_vec_mul_add_x(bins+6*mvl, bins+3*mvl)
        let mask_msb: u64 = 0x8888888888888888;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_msb;
            left[3 * m_vec_limbs + i] ^= ((right[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
        }
    }
    {
        let (left, right) = bins.split_at_mut(15 * m_vec_limbs);
        // m_vec_mul_add_x_inv(bins+14*mvl, bins+15*mvl)
        let src = &left[14 * m_vec_limbs..15 * m_vec_limbs];
        let mask_lsb: u64 = 0x1111111111111111;
        for i in 0..m_vec_limbs {
            let t = src[i] & mask_lsb;
            right[i] ^= ((src[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
        }
    }
    {
        let (left, right) = bins.split_at_mut(8 * m_vec_limbs);
        // m_vec_mul_add_x(bins+3*mvl, bins+8*mvl)
        let src = &left[3 * m_vec_limbs..4 * m_vec_limbs];
        let mask_msb: u64 = 0x8888888888888888;
        for i in 0..m_vec_limbs {
            let t = src[i] & mask_msb;
            right[i] ^= ((src[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
        }
    }
    {
        let (left, right) = bins.split_at_mut(15 * m_vec_limbs);
        // m_vec_mul_add_x_inv(bins+15*mvl, bins+13*mvl)
        // src = bins[15*mvl..], dst = bins[13*mvl..14*mvl]
        let mask_lsb: u64 = 0x1111111111111111;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_lsb;
            left[13 * m_vec_limbs + i] ^= ((right[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
        }
    }
    {
        let (left, right) = bins.split_at_mut(8 * m_vec_limbs);
        // m_vec_mul_add_x(bins+8*mvl, bins+4*mvl)
        let mask_msb: u64 = 0x8888888888888888;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_msb;
            left[4 * m_vec_limbs + i] ^= ((right[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
        }
    }
    {
        let (left, right) = bins.split_at_mut(13 * m_vec_limbs);
        // m_vec_mul_add_x_inv(bins+13*mvl, bins+9*mvl)
        // src = bins[13*mvl..14*mvl], dst = bins[9*mvl..10*mvl]
        // But 13*mvl is in the right part after split_at_mut(13*mvl)... no wait
        // split_at_mut(13*mvl) -> left = [0..13*mvl], right = [13*mvl..]
        // src = right[0..mvl], dst = left[9*mvl..10*mvl]
        let mask_lsb: u64 = 0x1111111111111111;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_lsb;
            left[9 * m_vec_limbs + i] ^= ((right[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
        }
    }
    {
        let (left, right) = bins.split_at_mut(4 * m_vec_limbs);
        // m_vec_mul_add_x(bins+4*mvl, bins+2*mvl)
        let mask_msb: u64 = 0x8888888888888888;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_msb;
            left[2 * m_vec_limbs + i] ^= ((right[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
        }
    }
    {
        let (left, right) = bins.split_at_mut(9 * m_vec_limbs);
        // m_vec_mul_add_x_inv(bins+9*mvl, bins+1*mvl)
        // split_at_mut(9*mvl) -> left = [0..9*mvl], right = [9*mvl..]
        // src = right[0..mvl], dst = left[1*mvl..2*mvl]
        let mask_lsb: u64 = 0x1111111111111111;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_lsb;
            left[m_vec_limbs + i] ^= ((right[i] ^ t) >> 1) ^ (t.wrapping_mul(9));
        }
    }
    {
        let (left, right) = bins.split_at_mut(2 * m_vec_limbs);
        // m_vec_mul_add_x(bins+2*mvl, bins+1*mvl)
        let mask_msb: u64 = 0x8888888888888888;
        for i in 0..m_vec_limbs {
            let t = right[i] & mask_msb;
            left[m_vec_limbs + i] ^= ((right[i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
        }
    }

    // m_vec_copy(bins + mvl, out)
    out[..m_vec_limbs].copy_from_slice(&bins[m_vec_limbs..2 * m_vec_limbs]);
}

/// Multiply-accumulate for variable-length vectors (used in echelon form).
///
/// Same as `m_vec_mul_add` but takes `legs` as the loop count
/// (which may differ from the parameter set's m_vec_limbs).
#[inline]
pub(crate) fn vec_mul_add_u64(legs: usize, src: &[u64], a: u8, acc: &mut [u64]) {
    let tab = mul_table(a);
    let lsb_mask: u64 = 0x1111111111111111;

    for i in 0..legs {
        acc[i] ^= (src[i] & lsb_mask).wrapping_mul(u64::from(tab & 0xff))
            ^ ((src[i] >> 1) & lsb_mask).wrapping_mul(u64::from((tab >> 8) & 0xf))
            ^ ((src[i] >> 2) & lsb_mask).wrapping_mul(u64::from((tab >> 16) & 0xf))
            ^ ((src[i] >> 3) & lsb_mask).wrapping_mul(u64::from((tab >> 24) & 0xf));
    }
}
