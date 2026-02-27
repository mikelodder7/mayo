// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Constant-time row echelon form computation.

use crate::bitsliced::vec_mul_add_u64;
use crate::gf16::inverse_f;

/// Extract a single GF(16) nibble from a packed u64 array.
#[inline]
#[allow(clippy::cast_possible_truncation)]
fn m_extract_element(data: &[u64], index: usize) -> u8 {
    let leg = index / 16;
    let offset = index % 16;
    ((data[leg] >> (offset * 4)) & 0xF) as u8
}

/// Constant-time comparison: returns 0 if a == b, else all-ones (0xFFFFFFFFFFFFFFFF).
#[inline]
#[allow(clippy::cast_sign_loss)]
fn ct_compare_64(a: i32, b: i32) -> u64 {
    let diff = (a ^ b) as i64;
    ((-diff) >> 63) as u64
}

/// Constant-time greater-than: returns all-ones if a > b, else 0.
#[inline]
#[allow(clippy::cast_sign_loss)]
fn ct_64_is_greater_than(a: i32, b: i32) -> u64 {
    let diff = (b as i64) - (a as i64);
    (diff >> 63) as u64
}

/// Constant-time comparison for u8: returns 0 if a == b, else 0xFF.
#[inline]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
pub(crate) fn ct_compare_8(a: u8, b: u8) -> u8 {
    let diff = (a ^ b) as i32;
    ((-diff) >> 31) as i8 as u8
}

/// Pack a row of GF(16) nibbles into u64 limbs (safe version).
fn ef_pack_m_vec_safe(input: &[u8], output: &mut [u64], ncols: usize) {
    for v in output.iter_mut() {
        *v = 0;
    }

    let mut i = 0;
    while i + 1 < ncols {
        let byte_val = u64::from(input[i]) | (u64::from(input[i + 1]) << 4);
        let limb_idx = (i / 2) / 8;
        let byte_idx = (i / 2) % 8;
        output[limb_idx] |= byte_val << (byte_idx * 8);
        i += 2;
    }
    if ncols % 2 == 1 {
        let byte_val = u64::from(input[i]);
        let limb_idx = (i / 2) / 8;
        let byte_idx = (i / 2) % 8;
        output[limb_idx] |= byte_val << (byte_idx * 8);
    }
}

/// Unpack u64 limbs into a row of GF(16) nibbles (safe version).
#[allow(clippy::cast_possible_truncation)]
fn ef_unpack_m_vec_safe(legs: usize, input: &[u64], output: &mut [u8]) {
    for i in (0..legs * 16).step_by(2) {
        let limb_idx = (i / 2) / 8;
        let byte_idx = (i / 2) % 8;
        let byte_val = ((input[limb_idx] >> (byte_idx * 8)) & 0xFF) as u8;
        output[i] = byte_val & 0xF;
        output[i + 1] = byte_val >> 4;
    }
}

/// Put matrix in row echelon form with leading ones, in constant time.
///
/// `a` is an `nrows x ncols` matrix of GF(16) elements stored as bytes.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub(crate) fn ef(a: &mut [u8], nrows: usize, ncols: usize) {
    let row_len = ncols.div_ceil(16);

    // Pack the matrix A into nibble-sliced form
    let mut packed_a = vec![0u64; row_len * nrows];
    for i in 0..nrows {
        ef_pack_m_vec_safe(&a[i * ncols..(i + 1) * ncols], &mut packed_a[i * row_len..(i + 1) * row_len], ncols);
    }

    let mut pivot_row_packed = vec![0u64; row_len];
    let mut pivot_row2 = vec![0u64; row_len];

    let mut pivot_row: i32 = 0;

    for pivot_col in 0..ncols {
        let pivot_row_lower_bound = 0i32.max(pivot_col as i32 + nrows as i32 - ncols as i32);
        let pivot_row_upper_bound = (nrows as i32 - 1).min(pivot_col as i32);

        // Zero out pivot row buffers
        for v in pivot_row_packed.iter_mut() {
            *v = 0;
        }
        for v in pivot_row2.iter_mut() {
            *v = 0;
        }

        // Try to get a pivot row in constant time
        let mut pivot: u8 = 0;
        let mut pivot_is_zero: u64 = u64::MAX;

        let search_upper = (nrows as i32 - 1).min(pivot_row_upper_bound + 32);
        for row in pivot_row_lower_bound..=search_upper {
            let is_pivot_row = !ct_compare_64(row, pivot_row);
            let below_pivot_row = ct_64_is_greater_than(row, pivot_row);

            for j in 0..row_len {
                pivot_row_packed[j] ^= (is_pivot_row | (below_pivot_row & pivot_is_zero))
                    & packed_a[row as usize * row_len + j];
            }
            pivot = m_extract_element(&pivot_row_packed, pivot_col);
            pivot_is_zero = !ct_compare_64(i32::from(pivot), 0);
        }

        // Multiply pivot row by inverse of pivot
        let inverse = inverse_f(pivot);
        vec_mul_add_u64(row_len, &pivot_row_packed, inverse, &mut pivot_row2);

        // Conditionally write pivot row to the correct row
        for row in pivot_row_lower_bound..=pivot_row_upper_bound {
            let do_copy = !ct_compare_64(row, pivot_row) & !pivot_is_zero;
            let do_not_copy = !do_copy;
            for col in 0..row_len {
                packed_a[row as usize * row_len + col] =
                    (do_not_copy & packed_a[row as usize * row_len + col])
                        .wrapping_add(do_copy & pivot_row2[col]);
            }
        }

        // Eliminate entries below pivot
        for row in pivot_row_lower_bound..nrows as i32 {
            let below_pivot = if row > pivot_row { 1u8 } else { 0u8 };
            let elt_to_elim = m_extract_element(
                &packed_a[row as usize * row_len..(row as usize + 1) * row_len],
                pivot_col,
            );
            vec_mul_add_u64(
                row_len,
                &pivot_row2.clone(),
                below_pivot.wrapping_mul(elt_to_elim),
                &mut packed_a[row as usize * row_len..(row as usize + 1) * row_len],
            );
        }

        pivot_row += (-((!pivot_is_zero) as i64)) as i32;
    }

    // Unpack the matrix
    let mut temp = vec![0u8; ncols + 16]; // Extra space for unpacking
    for i in 0..nrows {
        ef_unpack_m_vec_safe(
            row_len,
            &packed_a[i * row_len..(i + 1) * row_len],
            &mut temp,
        );
        a[i * ncols..(i + 1) * ncols].copy_from_slice(&temp[..ncols]);
    }
}
