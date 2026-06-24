// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bitsliced GF(16) vector operations on nibble-packed `u64` limbs.

use crate::gf16::mul_table;
// `mul_f` only builds the SIMD shuffle LUTs, which exist solely on x86/aarch64.
// Importing it unconditionally is an unused-import error on other targets
// (e.g. wasm32) under `-D warnings`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
use crate::gf16::mul_f;

/// LSB of each nibble: isolates bit 0 of every 4-bit element.
const MASK_LSB: u64 = 0x1111111111111111;
/// MSB of each nibble: isolates bit 3 of every 4-bit element.
const MASK_MSB: u64 = 0x8888888888888888;

/// Add an m-vector: `acc ^= src`.
///
/// This is the hottest primitive in the bin-accumulator matmuls, called O(V²·K)
/// times per signature, always at a length equal to the parameter set's
/// (compile-time) `M_VEC_LIMBS` ∈ {4,5,7,9}. The length is threaded as a runtime
/// `usize` through the matmul call chain, so the per-arch SIMD loops below can't
/// see it. This dispatcher recovers that constant: it matches the known MAYO
/// lengths and forwards to a fully-unrolled const-generic body, letting the
/// optimizer drop the loop counter, the bounds re-slice, and emit straight-line
/// (auto-vectorized) XORs. Non-MAYO lengths fall back to the dynamic SIMD path.
#[inline]
pub(crate) fn m_vec_add(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    match m_vec_limbs {
        4 => m_vec_add_n::<4>(src, acc),
        5 => m_vec_add_n::<5>(src, acc),
        7 => m_vec_add_n::<7>(src, acc),
        9 => m_vec_add_n::<9>(src, acc),
        _ => m_vec_add_dyn(src, acc, m_vec_limbs),
    }
}

/// Fully-unrolled `acc ^= src` for a compile-time length. With `N` const the
/// loop unrolls to `N` straight-line XORs and LLVM auto-vectorizes them; the
/// `[..N]` reslices give the optimizer a provable length so the per-element
/// bounds checks fold away.
#[inline(always)]
fn m_vec_add_n<const N: usize>(src: &[u64], acc: &mut [u64]) {
    let src = &src[..N];
    let acc = &mut acc[..N];
    for i in 0..N {
        acc[i] ^= src[i];
    }
}

/// Dynamic-length `acc ^= src` (non-MAYO lengths and the scalar-only targets).
#[cfg(target_arch = "aarch64")]
#[inline]
fn m_vec_add_dyn(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    use std::arch::aarch64::*;

    let src = &src[..m_vec_limbs];
    let acc = &mut acc[..m_vec_limbs];
    let mut i = 0;
    // SAFETY: NEON is baseline on aarch64; the `i + 2 <= m_vec_limbs` bound and
    // the reslices above keep every 128-bit load/store in range.
    unsafe {
        while i + 2 <= m_vec_limbs {
            let s = vld1q_u64(src.as_ptr().add(i));
            let a = vld1q_u64(acc.as_ptr().add(i));
            vst1q_u64(acc.as_mut_ptr().add(i), veorq_u64(s, a));
            i += 2;
        }
    }
    if i < m_vec_limbs {
        acc[i] ^= src[i];
    }
}

/// Dynamic-length `acc ^= src` on x86_64: two `u64` limbs per SSE2 op (baseline
/// ISA, no feature branch). Reached only for non-MAYO lengths; the MAYO lengths
/// take the const-generic unrolled path in [`m_vec_add`].
#[cfg(target_arch = "x86_64")]
#[inline]
fn m_vec_add_dyn(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
    use std::arch::x86_64::*;

    let src = &src[..m_vec_limbs];
    let acc = &mut acc[..m_vec_limbs];
    let mut i = 0;
    // SAFETY: SSE2 is baseline on x86_64; the `i + 2 <= m_vec_limbs` bound and
    // the reslices above keep every 128-bit load/store in range.
    unsafe {
        while i + 2 <= m_vec_limbs {
            let s = _mm_loadu_si128(src.as_ptr().add(i).cast());
            let a = _mm_loadu_si128(acc.as_ptr().add(i).cast());
            _mm_storeu_si128(acc.as_mut_ptr().add(i).cast(), _mm_xor_si128(s, a));
            i += 2;
        }
    }
    if i < m_vec_limbs {
        acc[i] ^= src[i];
    }
}

/// Dynamic-length `acc ^= src` (scalar fallback for non-SIMD targets).
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[inline]
fn m_vec_add_dyn(src: &[u64], acc: &mut [u64], m_vec_limbs: usize) {
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

/// Const-length scalar GF(16) multiply-accumulate (keygen's `m_vec_mul_add`
/// path). With `N` const the body unrolls and the bounds re-slice folds away —
/// the same constant-length recovery that `m_vec_add` uses, here for the LUT
/// multiply that the bin-accumulator deliberately avoids.
#[inline(always)]
fn m_vec_mul_add_scalar_n<const N: usize>(src: &[u64], a: u8, acc: &mut [u64]) {
    let tab = mul_table(a);
    let t0 = u64::from(tab & 0xff);
    let t1 = u64::from((tab >> 8) & 0xf);
    let t2 = u64::from((tab >> 16) & 0xf);
    let t3 = u64::from((tab >> 24) & 0xf);

    let src = &src[..N];
    let acc = &mut acc[..N];
    for i in 0..N {
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
/// # Safety
///
/// The caller must ensure SSSE3 is available on the current CPU. `src` and
/// `acc` must each contain at least `legs` limbs.
unsafe fn m_vec_mul_add_ssse3(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    // Table construction is pure scalar work and constant-time: `mul_f` has no
    // data-dependent branch or memory index, so building the LUT leaks nothing
    // about the (secret-derived) scalar `a`.
    let mut lo_bytes = [0u8; 16];
    let mut hi_bytes = [0u8; 16];
    for i in 0..16u8 {
        let m = mul_f(a, i);
        lo_bytes[i as usize] = m;
        hi_bytes[i as usize] = m << 4;
    }

    // SAFETY: pointers derive from valid slices; the `i + 16 <= total_bytes`
    // bound keeps every 16-byte load/store in range, and the scalar tail covers
    // the final odd u64 limb. Edition-2024 requires the explicit unsafe block.
    unsafe {
        let lo_tbl = _mm_loadu_si128(lo_bytes.as_ptr().cast());
        let hi_tbl = _mm_loadu_si128(hi_bytes.as_ptr().cast());
        let lo_mask = _mm_set1_epi8(0x0F);

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
}

// ────────────────────────────────────────────────────────────────────────────
// x86_64 / x86 AVX2 fast path
//
// Each 32-byte AVX register holds 4 u64 limbs = 64 packed GF(16) elements,
// doubling the SSSE3 chunk size. The one non-obvious detail: VPSHUFB on AVX2
// (`_mm256_shuffle_epi8`) shuffles WITHIN each 128-bit lane independently — it
// is NOT a full 32-byte cross-lane shuffle — so the 16-byte lookup table must be
// replicated into BOTH lanes via `_mm256_broadcastsi128_si256`. Forgetting this
// is the classic AVX2-from-SSSE3 porting bug (the upper 16 output bytes come out
// wrong). Indices are masked to 0..15, so VPSHUFB's "high bit set ⇒ output 0"
// rule never triggers (same invariant the SSSE3 path relies on). Like SSSE3
// there is no per-byte shift, so the high nibble is taken with
// `_mm256_srli_epi16` + a 0x0F mask. Timing is data-independent: the shuffle and
// arithmetic costs do not depend on `a` or the input bytes.
//
// The 0..3-limb tail reuses the tested SSSE3 routine, which itself falls back to
// the scalar path for a final odd u64.
// ────────────────────────────────────────────────────────────────────────────

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn m_vec_mul_add_avx2(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    // Constant-time table construction (identical to the SSSE3 path).
    let mut lo_bytes = [0u8; 16];
    let mut hi_bytes = [0u8; 16];
    for i in 0..16u8 {
        let m = mul_f(a, i);
        lo_bytes[i as usize] = m;
        hi_bytes[i as usize] = m << 4;
    }

    // SAFETY: pointers derive from valid slices; the `i + 32 <= total_bytes`
    // bound keeps every 32-byte load/store in range. AVX2 implies SSSE3, so the
    // delegated tail call to `m_vec_mul_add_ssse3` is sound on this target.
    unsafe {
        // Replicate the 16-byte LUT into both 128-bit lanes (per-lane shuffle).
        let lo_tbl = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_bytes.as_ptr().cast()));
        let hi_tbl = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_bytes.as_ptr().cast()));
        let lo_mask = _mm256_set1_epi8(0x0F);

        let src_ptr = src.as_ptr().cast::<u8>();
        let acc_ptr = acc.as_mut_ptr().cast::<u8>();
        let total_bytes = legs * 8;
        let mut i = 0usize;

        while i + 32 <= total_bytes {
            let data = _mm256_loadu_si256(src_ptr.add(i).cast());
            let acc_v = _mm256_loadu_si256(acc_ptr.add(i).cast());

            let lo_idx = _mm256_and_si256(data, lo_mask);
            // _mm256_srli_epi16 shifts 16-bit lanes; mask extracts each byte's high nibble.
            let hi_idx = _mm256_and_si256(_mm256_srli_epi16(data, 4), lo_mask);

            let product = _mm256_xor_si256(
                _mm256_shuffle_epi8(lo_tbl, lo_idx),
                _mm256_shuffle_epi8(hi_tbl, hi_idx),
            );
            _mm256_storeu_si256(acc_ptr.add(i).cast(), _mm256_xor_si256(acc_v, product));
            i += 32;
        }

        // VEX-128 tail. Calling the SSE-encoded `m_vec_mul_add_ssse3` here would
        // force an AVX→legacy-SSE state transition (tens of cycles each call), so
        // instead we inline a 128-bit step: these `_mm_*` ops are VEX-encoded
        // because this fn enables avx2, keeping the upper-state clean. The low
        // 128-bit lane of the broadcast LUT is exactly the original 16-byte
        // table, so the cast is free and correct.
        if i + 16 <= total_bytes {
            let lo_tbl128 = _mm256_castsi256_si128(lo_tbl);
            let hi_tbl128 = _mm256_castsi256_si128(hi_tbl);
            let lo_mask128 = _mm_set1_epi8(0x0F);
            let data = _mm_loadu_si128(src_ptr.add(i).cast());
            let acc_v = _mm_loadu_si128(acc_ptr.add(i).cast());
            let lo_idx = _mm_and_si128(data, lo_mask128);
            let hi_idx = _mm_and_si128(_mm_srli_epi16(data, 4), lo_mask128);
            let product = _mm_xor_si128(
                _mm_shuffle_epi8(lo_tbl128, lo_idx),
                _mm_shuffle_epi8(hi_tbl128, hi_idx),
            );
            _mm_storeu_si128(acc_ptr.add(i).cast(), _mm_xor_si128(acc_v, product));
            i += 16;
        }

        // Final odd u64 limb (if any) via the scalar path.
        let j = i / 8;
        if j < legs {
            m_vec_mul_add_scalar(&src[j..], a, &mut acc[j..], legs - j);
        }
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
/// # Safety
///
/// The caller must ensure NEON is available on the current CPU. This is true
/// for the AArch64 baseline. `src` and `acc` must each contain at least `legs`
/// limbs.
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

/// Minimum vector length (in u64 limbs) at which a SIMD kernel beats scalar.
///
/// Each SIMD call rebuilds a 16-entry GF(16) lookup table (16 `mul_f` calls)
/// before the shuffle loop; the scalar path instead uses a single packed
/// `mul_table` multiply. For short vectors that fixed per-call table-build cost
/// dominates and scalar wins decisively. Benchmarking `m_vec_mul_add` on x86_64
/// (see the `timing_mul_add` test) put the AVX2-vs-scalar crossover between 128
/// and 256 limbs: scalar was 1.8–4.5× faster at MAYO's sizes (legs 4–9), still
/// faster at legs=128 (~1.1×), and AVX2 only pulled ahead at legs≥256. SSSE3
/// never beat scalar at any measured size.
///
/// MAYO's `M_VEC_LIMBS` is 4–9, so MAYO always takes the scalar path — and
/// because `m_vec_mul_add` is called with a `const` length, the `legs < THRESHOLD`
/// branch folds away at compile time, leaving pure inlined scalar code with no
/// dispatch overhead. The SIMD kernels stay available for any future long-vector
/// caller.
///
/// NOTE: this crossover was measured on x86_64. The same per-call table-build
/// asymmetry applies to the aarch64 NEON path, so the same gate is used there,
/// but the exact crossover should be re-validated on aarch64 hardware (run the
/// `timing_mul_add` test on an ARM box).
///
/// Only defined on architectures whose dispatcher consults it; the scalar-only
/// fallback (e.g. wasm32) never references it, where an unconditional definition
/// would be a dead-code error under `-D warnings`.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
const SIMD_MIN_LIMBS: usize = 256;

#[cfg(target_arch = "aarch64")]
#[inline]
fn dispatch_mul_add(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    if legs >= SIMD_MIN_LIMBS {
        // SAFETY: NEON is part of the AArch64 baseline ISA.
        unsafe { m_vec_mul_add_neon(src, a, acc, legs) }
    } else {
        m_vec_mul_add_scalar(src, a, acc, legs)
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
fn dispatch_mul_add(src: &[u64], a: u8, acc: &mut [u64], legs: usize) {
    // Length-aware: short vectors (all MAYO parameter sets) go straight to scalar,
    // which is several times faster than SIMD there. Only long vectors amortize
    // the SIMD table build, and only AVX2 (32B/iter) ever beats scalar — so we
    // prefer AVX2, fall back to SSSE3 for non-AVX2 x86, then scalar.
    if legs >= SIMD_MIN_LIMBS {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: avx2 confirmed available at runtime.
            unsafe { m_vec_mul_add_avx2(src, a, acc, legs) }
        } else if is_x86_feature_detected!("ssse3") {
            // SAFETY: ssse3 confirmed available at runtime.
            unsafe { m_vec_mul_add_ssse3(src, a, acc, legs) }
        } else {
            m_vec_mul_add_scalar(src, a, acc, legs)
        }
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
    // Re-slice to the exact length so a too-short slice panics here (safe) rather
    // than reaching the raw-pointer SIMD kernels, where `legs * 8` byte offsets
    // would be out-of-bounds UB. One bounds check per call — negligible beside
    // the kernel work, and it lets the optimizer prove the SIMD accesses in-range.
    let src = &src[..m_vec_limbs];
    let acc = &mut acc[..m_vec_limbs];
    // MAYO calls this at a compile-time `M_VEC_LIMBS` ∈ {4,5,7,9}, all below
    // `SIMD_MIN_LIMBS`, so the dispatcher would pick the scalar path anyway —
    // route straight to the unrolled const-length scalar kernel.
    // Const arms for mvl 4/5/7 only: benchmarking showed the unrolled kernel wins
    // there (keygen −2% to −10.5%) but *pessimizes* mvl=9 (MAYO_5, +3–5%), so the
    // 9-limb case keeps the original dynamic path.
    match m_vec_limbs {
        4 => m_vec_mul_add_scalar_n::<4>(src, a, acc),
        5 => m_vec_mul_add_scalar_n::<5>(src, a, acc),
        7 => m_vec_mul_add_scalar_n::<7>(src, a, acc),
        _ => dispatch_mul_add(src, a, acc, m_vec_limbs),
    }
}

/// Multiply-accumulate for variable-length vectors (used in echelon form).
#[inline]
pub(crate) fn vec_mul_add_u64(legs: usize, src: &[u64], a: u8, acc: &mut [u64]) {
    m_vec_mul_add(src, a, acc, legs);
}

// ────────────────────────────────────────────────────────────────────────────
// Remaining bitsliced primitives
// ────────────────────────────────────────────────────────────────────────────

// The bin-fold ladder below is the second-hottest signing primitive after
// `m_vec_add`. The aarch64 (NEON) and x86_64 (SSE2, baseline ISA) paths process
// two `u64` limbs per SIMD op. Two GF(16) identities let the per-lane "multiply
// by small constant" be done with only shifts and XORs (neither NEON nor SSE2
// has a 64-bit-lane SIMD multiply): for `t` whose set bits sit only at each
// nibble's low bit, `t * 9 == t ^ (t << 3)`; likewise for `u` of the same shape,
// `u * 3 == u ^ (u << 1)`. SSE2 needs no runtime detect, so the per-call-heavy
// ladder stays branch-free.

/// Apply mul-add-x-inv from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[cfg(target_arch = "aarch64")]
#[inline]
fn bins_mul_add_x_inv(bins: &mut [u64], src: usize, dst: usize, n: usize) {
    use std::arch::aarch64::*;
    let mut i = 0;
    // SAFETY: NEON is baseline on aarch64; `src`/`dst` bin ranges are in-bounds
    // (callers pass valid bin offsets) and disjoint, so the raw read/write pair
    // never aliases. `i + 2 <= n` keeps each 128-bit access in range.
    unsafe {
        let lsb = vdupq_n_u64(MASK_LSB);
        let base = bins.as_mut_ptr();
        while i + 2 <= n {
            let x = vld1q_u64(base.add(src + i));
            let t = vandq_u64(x, lsb);
            let term1 = vshrq_n_u64::<1>(veorq_u64(x, t));
            let term2 = veorq_u64(t, vshlq_n_u64::<3>(t)); // t * 9
            let d = vld1q_u64(base.add(dst + i));
            vst1q_u64(base.add(dst + i), veorq_u64(d, veorq_u64(term1, term2)));
            i += 2;
        }
    }
    if i < n {
        let t = bins[src + i] & MASK_LSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) >> 1) ^ (t.wrapping_mul(9));
    }
}

/// Apply mul-add-x-inv from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[cfg(target_arch = "x86_64")]
#[inline]
fn bins_mul_add_x_inv(bins: &mut [u64], src: usize, dst: usize, n: usize) {
    use std::arch::x86_64::*;
    let mut i = 0;
    // SAFETY: SSE2 is baseline on x86_64; `src`/`dst` bin ranges are in-bounds
    // (callers pass valid bin offsets) and disjoint, so the raw read/write pair
    // never aliases. `i + 2 <= n` keeps each 128-bit access in range.
    unsafe {
        let lsb = _mm_set1_epi64x(MASK_LSB.cast_signed());
        let base = bins.as_mut_ptr();
        while i + 2 <= n {
            let x = _mm_loadu_si128(base.add(src + i).cast());
            let t = _mm_and_si128(x, lsb);
            let term1 = _mm_srli_epi64(_mm_xor_si128(x, t), 1);
            let term2 = _mm_xor_si128(t, _mm_slli_epi64(t, 3)); // t * 9
            let d = _mm_loadu_si128(base.add(dst + i).cast());
            _mm_storeu_si128(
                base.add(dst + i).cast(),
                _mm_xor_si128(d, _mm_xor_si128(term1, term2)),
            );
            i += 2;
        }
    }
    if i < n {
        let t = bins[src + i] & MASK_LSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) >> 1) ^ (t.wrapping_mul(9));
    }
}

/// Apply mul-add-x-inv from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[inline]
fn bins_mul_add_x_inv(bins: &mut [u64], src: usize, dst: usize, n: usize) {
    for i in 0..n {
        let t = bins[src + i] & MASK_LSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) >> 1) ^ (t.wrapping_mul(9));
    }
}

/// Apply mul-add-x from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[cfg(target_arch = "aarch64")]
#[inline]
fn bins_mul_add_x(bins: &mut [u64], src: usize, dst: usize, n: usize) {
    use std::arch::aarch64::*;
    let mut i = 0;
    // SAFETY: as in `bins_mul_add_x_inv` — NEON baseline, in-bounds disjoint
    // `src`/`dst` ranges, bounded 128-bit accesses.
    unsafe {
        let msb = vdupq_n_u64(MASK_MSB);
        let base = bins.as_mut_ptr();
        while i + 2 <= n {
            let x = vld1q_u64(base.add(src + i));
            let t = vandq_u64(x, msb);
            let term1 = vshlq_n_u64::<1>(veorq_u64(x, t));
            let u = vshrq_n_u64::<3>(t);
            let term2 = veorq_u64(u, vshlq_n_u64::<1>(u)); // (t >> 3) * 3
            let d = vld1q_u64(base.add(dst + i));
            vst1q_u64(base.add(dst + i), veorq_u64(d, veorq_u64(term1, term2)));
            i += 2;
        }
    }
    if i < n {
        let t = bins[src + i] & MASK_MSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
    }
}

/// Apply mul-add-x from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[cfg(target_arch = "x86_64")]
#[inline]
fn bins_mul_add_x(bins: &mut [u64], src: usize, dst: usize, n: usize) {
    use std::arch::x86_64::*;
    let mut i = 0;
    // SAFETY: as in `bins_mul_add_x_inv` — SSE2 baseline, in-bounds disjoint
    // `src`/`dst` ranges, bounded 128-bit accesses.
    unsafe {
        let msb = _mm_set1_epi64x(MASK_MSB.cast_signed());
        let base = bins.as_mut_ptr();
        while i + 2 <= n {
            let x = _mm_loadu_si128(base.add(src + i).cast());
            let t = _mm_and_si128(x, msb);
            let term1 = _mm_slli_epi64(_mm_xor_si128(x, t), 1);
            let u = _mm_srli_epi64(t, 3);
            let term2 = _mm_xor_si128(u, _mm_slli_epi64(u, 1)); // (t >> 3) * 3
            let d = _mm_loadu_si128(base.add(dst + i).cast());
            _mm_storeu_si128(
                base.add(dst + i).cast(),
                _mm_xor_si128(d, _mm_xor_si128(term1, term2)),
            );
            i += 2;
        }
    }
    if i < n {
        let t = bins[src + i] & MASK_MSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
    }
}

/// Apply mul-add-x from `bins[src..]` into `bins[dst..]` for `n` limbs.
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
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
    // Same constant-length recovery as `m_vec_add`: MAYO always folds at a
    // compile-time `M_VEC_LIMBS` ∈ {4,5,7,9}, so dispatch to a const-generic
    // ladder whose shift/XOR steps unroll and auto-vectorize.
    match m_vec_limbs {
        4 => m_vec_multiply_bins_n::<4>(bins, out),
        5 => m_vec_multiply_bins_n::<5>(bins, out),
        7 => m_vec_multiply_bins_n::<7>(bins, out),
        9 => m_vec_multiply_bins_n::<9>(bins, out),
        _ => m_vec_multiply_bins_dyn(bins, out, m_vec_limbs),
    }
}

/// `bins[dst..] ^= ((x ^ t) >> 1) ^ (t * 9)`, `t = x & LSB`, unrolled at const `N`.
#[inline(always)]
fn bins_mul_add_x_inv_n<const N: usize>(bins: &mut [u64], src: usize, dst: usize) {
    for i in 0..N {
        let t = bins[src + i] & MASK_LSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) >> 1) ^ (t.wrapping_mul(9));
    }
}

/// `bins[dst..] ^= ((x ^ t) << 1) ^ ((t >> 3) * 3)`, `t = x & MSB`, unrolled at const `N`.
#[inline(always)]
fn bins_mul_add_x_n<const N: usize>(bins: &mut [u64], src: usize, dst: usize) {
    for i in 0..N {
        let t = bins[src + i] & MASK_MSB;
        bins[dst + i] ^= ((bins[src + i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
    }
}

/// Const-length bin-fold ladder — identical step sequence to the dynamic path.
#[inline(always)]
fn m_vec_multiply_bins_n<const N: usize>(bins: &mut [u64], out: &mut [u64]) {
    bins_mul_add_x_inv_n::<N>(bins, 5 * N, 10 * N);
    bins_mul_add_x_n::<N>(bins, 11 * N, 12 * N);
    bins_mul_add_x_inv_n::<N>(bins, 10 * N, 7 * N);
    bins_mul_add_x_n::<N>(bins, 12 * N, 6 * N);
    bins_mul_add_x_inv_n::<N>(bins, 7 * N, 14 * N);
    bins_mul_add_x_n::<N>(bins, 6 * N, 3 * N);
    bins_mul_add_x_inv_n::<N>(bins, 14 * N, 15 * N);
    bins_mul_add_x_n::<N>(bins, 3 * N, 8 * N);
    bins_mul_add_x_inv_n::<N>(bins, 15 * N, 13 * N);
    bins_mul_add_x_n::<N>(bins, 8 * N, 4 * N);
    bins_mul_add_x_inv_n::<N>(bins, 13 * N, 9 * N);
    bins_mul_add_x_n::<N>(bins, 4 * N, 2 * N);
    bins_mul_add_x_inv_n::<N>(bins, 9 * N, N);
    bins_mul_add_x_n::<N>(bins, 2 * N, N);

    out[..N].copy_from_slice(&bins[N..2 * N]);
}

/// Dynamic-length bin-fold ladder (non-MAYO lengths).
fn m_vec_multiply_bins_dyn(bins: &mut [u64], out: &mut [u64], m_vec_limbs: usize) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift-filled (src, acc) of `legs` limbs, run through
    /// `f`, returning the resulting accumulator. Lets us cross-check any kernel
    /// against the scalar reference bit-for-bit.
    fn run<F: FnMut(&[u64], u8, &mut [u64], usize)>(
        mut f: F,
        seed: u64,
        a: u8,
        legs: usize,
    ) -> Vec<u64> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let mut src = vec![0u64; legs];
        let mut acc = vec![0u64; legs];
        for k in 0..legs {
            src[k] = next();
            acc[k] = next();
        }
        f(&src, a, &mut acc, legs);
        acc
    }

    /// Deterministic xorshift fill of `n` u64s.
    fn fill(seed: u64, n: usize) -> Vec<u64> {
        let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        (0..n)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s
            })
            .collect()
    }

    /// `m_vec_add` (NEON / SSE2 / scalar, whichever the target selects) must
    /// equal the plain scalar XOR for every length, including the SIMD tail.
    #[test]
    fn m_vec_add_matches_scalar() {
        for legs in 1..=33usize {
            let src = fill(0xADD ^ legs as u64, legs);
            let mut acc = fill(0xACC ^ legs as u64, legs);
            let mut expected = acc.clone();
            for i in 0..legs {
                expected[i] ^= src[i];
            }
            m_vec_add(&src, &mut acc, legs);
            assert_eq!(expected, acc, "m_vec_add != scalar (legs={legs})");
        }
    }

    /// Scalar reference for the bin-fold ladder, identical algorithm to the
    /// dispatched (possibly SIMD) `bins_mul_add_x[_inv]`. Guarantees the SIMD
    /// ladder is validated against scalar on every architecture's CI.
    fn multiply_bins_ref(bins: &[u64], mvl: usize) -> Vec<u64> {
        let mut b = bins.to_vec();
        let x_inv = |b: &mut [u64], src: usize, dst: usize| {
            for i in 0..mvl {
                let t = b[src + i] & MASK_LSB;
                b[dst + i] ^= ((b[src + i] ^ t) >> 1) ^ (t.wrapping_mul(9));
            }
        };
        let x = |b: &mut [u64], src: usize, dst: usize| {
            for i in 0..mvl {
                let t = b[src + i] & MASK_MSB;
                b[dst + i] ^= ((b[src + i] ^ t) << 1) ^ ((t >> 3).wrapping_mul(3));
            }
        };
        x_inv(&mut b, 5 * mvl, 10 * mvl);
        x(&mut b, 11 * mvl, 12 * mvl);
        x_inv(&mut b, 10 * mvl, 7 * mvl);
        x(&mut b, 12 * mvl, 6 * mvl);
        x_inv(&mut b, 7 * mvl, 14 * mvl);
        x(&mut b, 6 * mvl, 3 * mvl);
        x_inv(&mut b, 14 * mvl, 15 * mvl);
        x(&mut b, 3 * mvl, 8 * mvl);
        x_inv(&mut b, 15 * mvl, 13 * mvl);
        x(&mut b, 8 * mvl, 4 * mvl);
        x_inv(&mut b, 13 * mvl, 9 * mvl);
        x(&mut b, 4 * mvl, 2 * mvl);
        x_inv(&mut b, 9 * mvl, mvl);
        x(&mut b, 2 * mvl, mvl);
        b[mvl..2 * mvl].to_vec()
    }

    /// The dispatched `m_vec_multiply_bins` (SIMD ladder on aarch64/x86_64) must
    /// match the scalar ladder for every MAYO `m_vec_limbs`.
    #[test]
    fn multiply_bins_matches_scalar() {
        for mvl in 1..=9usize {
            let bins = fill(0xB1 ^ mvl as u64, 16 * mvl);
            let expected = multiply_bins_ref(&bins, mvl);
            let mut work = bins.clone();
            let mut out = vec![0u64; mvl];
            m_vec_multiply_bins(&mut work, &mut out, mvl);
            assert_eq!(expected, out, "multiply_bins != scalar (mvl={mvl})");
        }
    }

    /// The scalar path is the source of truth. Every SIMD path — and the
    /// runtime dispatcher — must produce byte-identical output for every GF(16)
    /// scalar (0..16) and every vector length we exercise (1..=33 covers all
    /// MAYO m_vec_limbs values 4/5/7/9 plus the variable echelon lengths, and
    /// both the 32-byte main loop and the 16-byte/8-byte tail paths).
    #[test]
    fn simd_paths_match_scalar() {
        // 1..=33 covers every MAYO m_vec_limbs plus the SIMD main-loop and tail
        // paths; the larger sizes (around and above SIMD_MIN_LIMBS) exercise the
        // length-aware dispatcher's SIMD branch end-to-end, not just direct calls.
        let sizes = (1..=33usize).chain([255usize, 256, 257, 260, 300, 384, 512]);
        for legs in sizes {
            for a in 0u8..16 {
                let seed = 0x5EED ^ (legs as u64) ^ ((a as u64) << 32);
                let expected = run(m_vec_mul_add_scalar, seed, a, legs);

                let got = run(dispatch_mul_add, seed, a, legs);
                assert_eq!(expected, got, "dispatch != scalar (legs={legs}, a={a})");

                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    if is_x86_feature_detected!("ssse3") {
                        let g = run(
                            |s, a, acc, l| unsafe { m_vec_mul_add_ssse3(s, a, acc, l) },
                            seed,
                            a,
                            legs,
                        );
                        assert_eq!(expected, g, "ssse3 != scalar (legs={legs}, a={a})");
                    }
                    if is_x86_feature_detected!("avx2") {
                        let g = run(
                            |s, a, acc, l| unsafe { m_vec_mul_add_avx2(s, a, acc, l) },
                            seed,
                            a,
                            legs,
                        );
                        assert_eq!(expected, g, "avx2 != scalar (legs={legs}, a={a})");
                    }
                }
            }
        }
    }

    /// Micro-benchmark of the kernel, isolated from key/sign/verify overhead.
    /// Ignored by default (timing is environment-dependent). Run with:
    ///   cargo test --release -p pq-mayo --lib timing_mul_add -- --ignored --nocapture
    #[test]
    #[ignore = "timing benchmark; run with --release --ignored --nocapture"]
    #[allow(clippy::cast_precision_loss, clippy::type_complexity)]
    fn timing_mul_add() {
        use std::hint::black_box;
        use std::time::Instant;

        let iters: u32 = 4_000_000;
        let a: u8 = 0xB;

        // MAYO m_vec_limbs (4,5,7,9) plus larger sizes to locate the scalar→SIMD
        // crossover (where the per-call LUT rebuild finally amortizes).
        for &legs in &[4usize, 5, 7, 9, 16, 32, 64, 128, 256, 512, 1024] {
            let mut src = vec![0u64; legs];
            for (k, v) in src.iter_mut().enumerate() {
                *v = 0x0123_4567_89AB_CDEFu64.wrapping_mul(k as u64 + 1) ^ 0xDEAD_BEEF_CAFE_BABE;
            }

            let time = |label: &str, mut f: Box<dyn FnMut(&mut [u64])>| -> f64 {
                let mut acc = vec![0u64; legs];
                let start = Instant::now();
                for _ in 0..iters {
                    f(&mut acc);
                    black_box(&acc);
                }
                let ns = start.elapsed().as_nanos() as f64 / iters as f64;
                println!("  {label:<8} {ns:7.3} ns/op");
                ns
            };

            println!("\nm_vec_mul_add timing (legs={legs}, {iters} iters):");
            let src_s = src.clone();
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let scalar = time(
                "scalar",
                Box::new(move |acc| {
                    m_vec_mul_add_scalar(black_box(&src_s), black_box(a), acc, legs)
                }),
            );
            #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
            let _ = time(
                "scalar",
                Box::new(move |acc| {
                    m_vec_mul_add_scalar(black_box(&src_s), black_box(a), acc, legs)
                }),
            );

            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                if is_x86_feature_detected!("ssse3") {
                    let src_x = src.clone();
                    let ssse3 = time(
                        "ssse3",
                        Box::new(move |acc| unsafe {
                            m_vec_mul_add_ssse3(black_box(&src_x), black_box(a), acc, legs)
                        }),
                    );
                    println!("  ssse3 vs scalar: {:.2}x", scalar / ssse3);
                    if is_x86_feature_detected!("avx2") {
                        let src_y = src.clone();
                        let avx2 = time(
                            "avx2",
                            Box::new(move |acc| unsafe {
                                m_vec_mul_add_avx2(black_box(&src_y), black_box(a), acc, legs)
                            }),
                        );
                        println!("  avx2  vs scalar: {:.2}x", scalar / avx2);
                        println!("  avx2  vs ssse3:  {:.2}x", ssse3 / avx2);
                    }
                }
            }
        }
    }
}
