// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO parameter sets.
//!
//! Defines the [`MayoParameter`] trait and concrete parameter sets
//! [`Mayo1`], [`Mayo2`], [`Mayo3`], and [`Mayo5`].

/// Length of the f(X) tail polynomial coefficients.
pub(crate) const F_TAIL_LEN: usize = 4;

/// Trait defining all constants for a MAYO parameter set.
pub trait MayoParameter: Clone + Copy + Send + Sync + 'static {
    /// Human-readable name of this parameter set.
    const NAME: &'static str;
    /// Total number of variables (n).
    const N: usize;
    /// Number of equations (m).
    const M: usize;
    /// Oil dimension (o).
    const O: usize;
    /// Whipping parameter (k).
    const K: usize;
    /// Vinegar dimension (v = n - o).
    const V: usize;
    /// Number of u64 limbs per m-vector.
    const M_VEC_LIMBS: usize;
    /// Number of columns in the linearized system A (k*o + 1).
    const A_COLS: usize;
    /// Byte length of m field elements packed as nibbles.
    const M_BYTES: usize;
    /// Byte length of the O matrix packed as nibbles.
    const O_BYTES: usize;
    /// Byte length of a vinegar vector packed as nibbles.
    const V_BYTES: usize;
    /// Byte length of a random vector r packed as nibbles.
    const R_BYTES: usize;
    /// Byte length of P1 matrix packed.
    const P1_BYTES: usize;
    /// Byte length of P2 matrix packed.
    const P2_BYTES: usize;
    /// Byte length of P3 matrix packed.
    const P3_BYTES: usize;
    /// Byte length of compact secret key.
    const CSK_BYTES: usize;
    /// Byte length of compact public key.
    const CPK_BYTES: usize;
    /// Byte length of signature.
    const SIG_BYTES: usize;
    /// Byte length of salt.
    const SALT_BYTES: usize;
    /// Byte length of message digest.
    const DIGEST_BYTES: usize;
    /// Byte length of public key seed.
    const PK_SEED_BYTES: usize;
    /// Byte length of secret key seed.
    const SK_SEED_BYTES: usize;
    /// Tail coefficients of the irreducible polynomial f(X).
    const F_TAIL: [u8; F_TAIL_LEN];
    /// Number of u64 limbs for P1 in bitsliced form.
    const P1_LIMBS: usize;
    /// Number of u64 limbs for P2 in bitsliced form.
    const P2_LIMBS: usize;
    /// Number of u64 limbs for P3 in bitsliced form.
    const P3_LIMBS: usize;
}

macro_rules! define_mayo_parameter {
    (
        $name:ident, $display:expr,
        n = $n:expr, m = $m:expr, o = $o:expr, k = $k:expr,
        m_vec_limbs = $mvl:expr,
        m_bytes = $mb:expr, O_bytes = $ob:expr, v_bytes = $vb:expr, r_bytes = $rb:expr,
        P1_bytes = $p1b:expr, P2_bytes = $p2b:expr, P3_bytes = $p3b:expr,
        csk_bytes = $cskb:expr, cpk_bytes = $cpkb:expr, sig_bytes = $sigb:expr,
        salt_bytes = $saltb:expr, digest_bytes = $db:expr,
        pk_seed_bytes = $pksb:expr, sk_seed_bytes = $sksb:expr,
        f_tail = $ft:expr
    ) => {
        #[doc = concat!("MAYO parameter set ", $display, ".")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name;

        impl MayoParameter for $name {
            const NAME: &'static str = $display;
            const N: usize = $n;
            const M: usize = $m;
            const O: usize = $o;
            const K: usize = $k;
            const V: usize = $n - $o;
            const M_VEC_LIMBS: usize = $mvl;
            const A_COLS: usize = $k * $o + 1;
            const M_BYTES: usize = $mb;
            const O_BYTES: usize = $ob;
            const V_BYTES: usize = $vb;
            const R_BYTES: usize = $rb;
            const P1_BYTES: usize = $p1b;
            const P2_BYTES: usize = $p2b;
            const P3_BYTES: usize = $p3b;
            const CSK_BYTES: usize = $cskb;
            const CPK_BYTES: usize = $cpkb;
            const SIG_BYTES: usize = $sigb;
            const SALT_BYTES: usize = $saltb;
            const DIGEST_BYTES: usize = $db;
            const PK_SEED_BYTES: usize = $pksb;
            const SK_SEED_BYTES: usize = $sksb;
            const F_TAIL: [u8; F_TAIL_LEN] = $ft;
            const P1_LIMBS: usize = ($n - $o) * (($n - $o) + 1) / 2 * $mvl;
            const P2_LIMBS: usize = ($n - $o) * $o * $mvl;
            const P3_LIMBS: usize = $o * ($o + 1) / 2 * $mvl;
        }
    };
}

define_mayo_parameter!(
    Mayo1, "MAYO_1",
    n = 86, m = 78, o = 8, k = 10,
    m_vec_limbs = 5,
    m_bytes = 39, O_bytes = 312, v_bytes = 39, r_bytes = 40,
    P1_bytes = 120159, P2_bytes = 24336, P3_bytes = 1404,
    csk_bytes = 24, cpk_bytes = 1420, sig_bytes = 454,
    salt_bytes = 24, digest_bytes = 32,
    pk_seed_bytes = 16, sk_seed_bytes = 24,
    f_tail = [8, 1, 1, 0]
);

define_mayo_parameter!(
    Mayo2, "MAYO_2",
    n = 81, m = 64, o = 17, k = 4,
    m_vec_limbs = 4,
    m_bytes = 32, O_bytes = 544, v_bytes = 32, r_bytes = 34,
    P1_bytes = 66560, P2_bytes = 34816, P3_bytes = 4896,
    csk_bytes = 24, cpk_bytes = 4912, sig_bytes = 186,
    salt_bytes = 24, digest_bytes = 32,
    pk_seed_bytes = 16, sk_seed_bytes = 24,
    f_tail = [8, 0, 2, 8]
);

define_mayo_parameter!(
    Mayo3, "MAYO_3",
    n = 118, m = 108, o = 10, k = 11,
    m_vec_limbs = 7,
    m_bytes = 54, O_bytes = 540, v_bytes = 54, r_bytes = 55,
    P1_bytes = 317844, P2_bytes = 58320, P3_bytes = 2970,
    csk_bytes = 32, cpk_bytes = 2986, sig_bytes = 681,
    salt_bytes = 32, digest_bytes = 48,
    pk_seed_bytes = 16, sk_seed_bytes = 32,
    f_tail = [8, 0, 1, 7]
);

define_mayo_parameter!(
    Mayo5, "MAYO_5",
    n = 154, m = 142, o = 12, k = 12,
    m_vec_limbs = 9,
    m_bytes = 71, O_bytes = 852, v_bytes = 71, r_bytes = 72,
    P1_bytes = 720863, P2_bytes = 120984, P3_bytes = 5538,
    csk_bytes = 40, cpk_bytes = 5554, sig_bytes = 964,
    salt_bytes = 40, digest_bytes = 64,
    pk_seed_bytes = 16, sk_seed_bytes = 40,
    f_tail = [4, 0, 8, 1]
);
