// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Constant-time solution sampling for the linearized MAYO system.

use crate::echelon::{ct_compare_8, ef};
use crate::gf16::{mat_mul, mul_fx8, sub_f};

/// Sample a solution x to Ax = y, with r used as randomness.
///
/// - `a` is an `m x a_cols` matrix (last column will be overwritten with y - Ar)
/// - `y` is a vector with `m` elements
/// - `r` and `x` are `k*o` bytes long
///
/// Returns `true` on success, `false` if the system is singular.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sample_solution(
    a: &mut [u8],
    y: &[u8],
    r: &[u8],
    x: &mut [u8],
    k: usize,
    o: usize,
    m: usize,
    a_cols: usize,
) -> bool {
    let ko = k * o;

    // x <- r
    x[..ko].copy_from_slice(&r[..ko]);

    // Compute Ar
    let mut ar = vec![0u8; m];
    // Clear last column of A
    for i in 0..m {
        a[ko + i * a_cols] = 0;
    }
    mat_mul(a, r, &mut ar, a_cols, m, 1);

    // Move y - Ar to last column of matrix A
    for i in 0..m {
        a[ko + i * a_cols] = sub_f(y[i], ar[i]);
    }

    // Row echelon form
    ef(a, m, a_cols);

    // Check if last row of A (excluding the last entry) is zero
    let mut full_rank: u8 = 0;
    for i in 0..(a_cols - 1) {
        full_rank |= a[(m - 1) * a_cols + i];
    }

    if full_rank == 0 {
        return false;
    }

    // Back substitution in constant time
    for row in (0..m).rev() {
        let mut finished: u8 = 0;
        let col_upper_bound = (row + 32 / (m - row)).min(ko);

        for col in row..=col_upper_bound {
            // Constant-time check if this is the pivot column
            let correct_column = ct_compare_8(a[row * a_cols + col], 0) & !finished;

            let u = correct_column & a[row * a_cols + a_cols - 1];
            x[col] ^= u;

            // Update rows above
            let mut i = 0;
            while i < row {
                let end = (i + 8).min(row);
                let mut tmp: u64 = 0;
                for ii in i..end {
                    tmp ^= u64::from(a[ii * a_cols + col]) << ((ii - i) * 8);
                }
                tmp = mul_fx8(u, tmp);

                for ii in i..end {
                    a[ii * a_cols + a_cols - 1] ^= ((tmp >> ((ii - i) * 8)) & 0xf) as u8;
                }
                i += 8;
            }

            finished |= correct_column;
        }
    }

    true
}
