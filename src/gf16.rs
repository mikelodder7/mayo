// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Scalar GF(16) arithmetic over GF(2)[x]/(x^4 + x + 1).

/// Multiply two GF(16) elements: a * b mod (x^4 + x + 1).
#[inline]
pub(crate) fn mul_f(a: u8, b: u8) -> u8 {
    // Carryless multiply
    let mut p: u8 = 0;
    p ^= (a & 1).wrapping_mul(b);
    p ^= (a & 2).wrapping_mul(b);
    p ^= (a & 4).wrapping_mul(b);
    p ^= (a & 8).wrapping_mul(b);

    // Reduce mod x^4 + x + 1
    let top_p = p & 0xf0;
    (p ^ (top_p >> 4) ^ (top_p >> 3)) & 0x0f
}

/// Multiply a GF(16) scalar by 8 packed GF(16) elements in a u64.
#[inline]
pub(crate) fn mul_fx8(a: u8, b: u64) -> u64 {
    let mut p: u64 = 0;
    p ^= u64::from(a & 1).wrapping_mul(b);
    p ^= u64::from(a & 2).wrapping_mul(b);
    p ^= u64::from(a & 4).wrapping_mul(b);
    p ^= u64::from(a & 8).wrapping_mul(b);

    let top_p = p & 0xf0f0f0f0f0f0f0f0;
    (p ^ (top_p >> 4) ^ (top_p >> 3)) & 0x0f0f0f0f0f0f0f0f
}

/// Add two GF(16) elements (same as XOR).
#[inline]
pub(crate) fn add_f(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Subtract two GF(16) elements (same as XOR in characteristic 2).
#[inline]
pub(crate) fn sub_f(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Compute the multiplicative inverse of a GF(16) element.
///
/// Uses the identity a^14 = a^{-1} in GF(16).
#[inline]
pub(crate) fn inverse_f(a: u8) -> u8 {
    let a2 = mul_f(a, a);
    let a4 = mul_f(a2, a2);
    let a8 = mul_f(a4, a4);
    let a6 = mul_f(a2, a4);
    mul_f(a8, a6) // a^14
}

/// Compute a multiplication lookup table for scalar b.
///
/// Returns a u32 with 4 packed bytes: mul(b,1), mul(b,2), mul(b,4), mul(b,8).
#[inline]
pub(crate) fn mul_table(b: u8) -> u32 {
    let x = u32::from(b).wrapping_mul(0x08040201);
    let high_nibble_mask: u32 = 0xf0f0f0f0;
    let high_half = x & high_nibble_mask;
    x ^ (high_half >> 4) ^ (high_half >> 3)
}

/// Multiply 16 packed GF(16) nibbles in a u64 by a scalar.
#[inline]
#[allow(dead_code)]
pub(crate) fn gf16v_mul_u64(a: u64, b: u8) -> u64 {
    let mask_msb: u64 = 0x8888888888888888;
    let mut a64 = a;
    let b64 = u64::from(b);
    let mut r64 = a64.wrapping_mul(b64 & 1);

    let a_msb = a64 & mask_msb;
    a64 ^= a_msb;
    a64 = (a64 << 1) ^ ((a_msb >> 3).wrapping_mul(3));
    r64 ^= a64.wrapping_mul((b64 >> 1) & 1);

    let a_msb = a64 & mask_msb;
    a64 ^= a_msb;
    a64 = (a64 << 1) ^ ((a_msb >> 3).wrapping_mul(3));
    r64 ^= a64.wrapping_mul((b64 >> 2) & 1);

    let a_msb = a64 & mask_msb;
    a64 ^= a_msb;
    a64 = (a64 << 1) ^ ((a_msb >> 3).wrapping_mul(3));
    r64 ^= a64.wrapping_mul((b64 >> 3) & 1);

    r64
}

/// Linear combination: sum of a[i] * b[i*m] for i in 0..n.
#[inline]
pub(crate) fn lincomb(a: &[u8], b: &[u8], n: usize, m: usize) -> u8 {
    let mut ret: u8 = 0;
    for i in 0..n {
        ret = add_f(mul_f(a[i], b[i * m]), ret);
    }
    ret
}

/// Matrix multiply: c = a * b, where a is row_a x colrow_ab and b is colrow_ab x col_b.
pub(crate) fn mat_mul(a: &[u8], b: &[u8], c: &mut [u8], colrow_ab: usize, row_a: usize, col_b: usize) {
    for i in 0..row_a {
        for j in 0..col_b {
            c[i * col_b + j] = lincomb(&a[i * colrow_ab..], &b[j..], colrow_ab, col_b);
        }
    }
}

/// Matrix add: c = a + b, where both are m x n.
pub(crate) fn mat_add(a: &[u8], b: &[u8], c: &mut [u8], m: usize, n: usize) {
    for i in 0..m {
        for j in 0..n {
            c[i * n + j] = add_f(a[i * n + j], b[i * n + j]);
        }
    }
}
