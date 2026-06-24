// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Constant-time row echelon form computation.

use crate::bitsliced::vec_mul_add_u64;
use crate::gf16::inverse_f;

#[inline]
fn low_u8(value: u64) -> u8 {
    value.to_le_bytes()[0]
}

/// Extract a single GF(16) nibble from a packed u64 array.
#[inline]
fn m_extract_element(data: &[u64], index: usize) -> u8 {
    let leg = index / 16;
    let offset = index % 16;
    low_u8((data[leg] >> (offset * 4)) & 0xF)
}

/// Constant-time comparison: returns 0 if a == b, else all-ones (0xFFFFFFFFFFFFFFFF).
#[inline]
fn ct_compare_64(a: usize, b: usize) -> u64 {
    let diff = a ^ b;
    let nonzero = ((diff | diff.wrapping_neg()) >> (usize::BITS - 1)) & 1;
    0u64.wrapping_sub(u64::from(nonzero != 0))
}

/// Constant-time greater-than: returns all-ones if a > b, else 0.
#[inline]
fn ct_64_is_greater_than(a: usize, b: usize) -> u64 {
    0u64.wrapping_sub(u64::from(a > b))
}

/// Constant-time comparison for u8: returns 0 if a == b, else 0xFF.
#[inline]
pub(crate) fn ct_compare_8(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    let nonzero = ((diff | diff.wrapping_neg()) >> 7) & 1;
    0u8.wrapping_sub(nonzero)
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
fn ef_unpack_m_vec_safe(legs: usize, input: &[u64], output: &mut [u8]) {
    for i in (0..legs * 16).step_by(2) {
        let limb_idx = (i / 2) / 8;
        let byte_idx = (i / 2) % 8;
        let byte_val = low_u8((input[limb_idx] >> (byte_idx * 8)) & 0xFF);
        output[i] = byte_val & 0xF;
        output[i + 1] = byte_val >> 4;
    }
}

/// Put matrix in row echelon form with leading ones, in constant time.
///
/// `a` is an `nrows x ncols` matrix of GF(16) elements stored as bytes.
pub(crate) fn ef(a: &mut [u8], nrows: usize, ncols: usize) {
    let row_len = ncols.div_ceil(16);

    // Pack the matrix A into nibble-sliced form
    let mut packed_a = vec![0u64; row_len * nrows];
    for i in 0..nrows {
        ef_pack_m_vec_safe(
            &a[i * ncols..(i + 1) * ncols],
            &mut packed_a[i * row_len..(i + 1) * row_len],
            ncols,
        );
    }

    let mut pivot_row_packed = vec![0u64; row_len];
    let mut pivot_row2 = vec![0u64; row_len];

    let mut pivot_row: usize = 0;

    for pivot_col in 0..ncols {
        let pivot_row_lower_bound = pivot_col.saturating_add(nrows).saturating_sub(ncols);
        let pivot_row_upper_bound = (nrows - 1).min(pivot_col);

        // Zero out pivot row buffers
        pivot_row_packed.fill(0);
        pivot_row2.fill(0);

        // Try to get a pivot row in constant time
        let mut pivot: u8 = 0;
        let mut pivot_is_zero: u64 = u64::MAX;

        let search_upper = (nrows - 1).min(pivot_row_upper_bound + 32);
        for row in pivot_row_lower_bound..=search_upper {
            let is_pivot_row = !ct_compare_64(row, pivot_row);
            let below_pivot_row = ct_64_is_greater_than(row, pivot_row);

            for j in 0..row_len {
                pivot_row_packed[j] ^= (is_pivot_row | (below_pivot_row & pivot_is_zero))
                    & packed_a[row * row_len + j];
            }
            pivot = m_extract_element(&pivot_row_packed, pivot_col);
            pivot_is_zero = !ct_compare_64(usize::from(pivot), 0);
        }

        // Multiply pivot row by inverse of pivot
        let inverse = inverse_f(pivot);
        vec_mul_add_u64(row_len, &pivot_row_packed, inverse, &mut pivot_row2);

        // Conditionally write pivot row to the correct row
        for row in pivot_row_lower_bound..=pivot_row_upper_bound {
            let do_copy = !ct_compare_64(row, pivot_row) & !pivot_is_zero;
            let do_not_copy = !do_copy;
            for col in 0..row_len {
                packed_a[row * row_len + col] = (do_not_copy & packed_a[row * row_len + col])
                    .wrapping_add(do_copy & pivot_row2[col]);
            }
        }

        // Eliminate entries below pivot
        for row in pivot_row_lower_bound..nrows {
            let below_pivot = if row > pivot_row { 1u8 } else { 0u8 };
            let elt_to_elim =
                m_extract_element(&packed_a[row * row_len..(row + 1) * row_len], pivot_col);
            vec_mul_add_u64(
                row_len,
                &pivot_row2,
                below_pivot.wrapping_mul(elt_to_elim),
                &mut packed_a[row * row_len..(row + 1) * row_len],
            );
        }

        pivot_row += usize::from(pivot_is_zero != u64::MAX);
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
