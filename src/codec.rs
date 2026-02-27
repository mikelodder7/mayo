// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encoding and decoding of nibble-packed GF(16) elements.

/// Decode packed nibbles into individual bytes.
///
/// Each byte in `input` contains two GF(16) elements (low nibble first).
/// Produces `len` output bytes, each containing a single GF(16) element.
pub(crate) fn decode(input: &[u8], output: &mut [u8], len: usize) {
    let mut out_idx = 0;
    let mut i = 0;
    while i < len / 2 {
        output[out_idx] = input[i] & 0xf;
        output[out_idx + 1] = input[i] >> 4;
        out_idx += 2;
        i += 1;
    }
    if len % 2 == 1 {
        output[out_idx] = input[i] & 0x0f;
    }
}

/// Encode individual GF(16) bytes into packed nibbles.
///
/// Each pair of input bytes is packed into one output byte (low nibble first).
pub(crate) fn encode(input: &[u8], output: &mut [u8], len: usize) {
    let mut in_idx = 0;
    let mut i = 0;
    while i < len / 2 {
        output[i] = input[in_idx] | (input[in_idx + 1] << 4);
        in_idx += 2;
        i += 1;
    }
    if len % 2 == 1 {
        output[i] = input[in_idx];
    }
}

/// Unpack packed byte vectors into bitsliced m-vectors.
///
/// Each vector occupies `m/2` bytes in packed form and `m_vec_limbs * 8` bytes
/// in unpacked (bitsliced u64) form.
pub(crate) fn unpack_m_vecs(input: &[u8], output: &mut [u64], vecs: usize, m: usize) {
    let m_vec_limbs = m.div_ceil(16);
    let packed_size = m / 2;
    let limb_bytes = m_vec_limbs * 8;

    // Work backwards to support potential in-place operation
    for i in (0..vecs).rev() {
        let mut tmp = vec![0u64; m_vec_limbs];
        let tmp_bytes =
            &mut vec![0u8; limb_bytes];

        // Copy packed bytes into temp
        tmp_bytes[..packed_size].copy_from_slice(&input[i * packed_size..i * packed_size + packed_size]);

        // Convert bytes to u64 limbs (little-endian)
        for (j, tmp_val) in tmp.iter_mut().enumerate().take(m_vec_limbs) {
            let mut val: u64 = 0;
            for b in 0..8 {
                let idx = j * 8 + b;
                if idx < limb_bytes {
                    val |= u64::from(tmp_bytes[idx]) << (b * 8);
                }
            }
            *tmp_val = val;
        }

        output[i * m_vec_limbs..(i + 1) * m_vec_limbs].copy_from_slice(&tmp);
    }
}

/// Pack bitsliced m-vectors into packed byte vectors.
///
/// Each vector occupies `m_vec_limbs * 8` bytes in bitsliced form and `m/2` bytes
/// in packed form.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn pack_m_vecs(input: &[u64], output: &mut [u8], vecs: usize, m: usize) {
    let m_vec_limbs = m.div_ceil(16);
    let packed_size = m / 2;

    for i in 0..vecs {
        // Convert u64 limbs to bytes (little-endian)
        let src = &input[i * m_vec_limbs..(i + 1) * m_vec_limbs];
        for j in 0..packed_size {
            let limb_idx = j / 8;
            let byte_idx = j % 8;
            output[i * packed_size + j] = (src[limb_idx] >> (byte_idx * 8)) as u8;
        }
    }
}
