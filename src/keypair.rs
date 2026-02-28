// SPDX-License-Identifier: Apache-2.0 OR MIT

//! MAYO keypair generation.

use crate::error::Result;
use crate::keygen::mayo_keypair_compact;
use crate::params::MayoParameter;
use crate::signing_key::SigningKey;
use crate::verifying_key::VerifyingKey;
use rand::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A MAYO keypair containing both signing and verifying keys.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(bound = ""))]
pub struct KeyPair<P: MayoParameter> {
    signing_key: SigningKey<P>,
    verifying_key: VerifyingKey<P>,
}

impl<P: MayoParameter> AsRef<VerifyingKey<P>> for KeyPair<P> {
    fn as_ref(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

impl<P: MayoParameter> signature::KeypairRef for KeyPair<P> {
    type VerifyingKey = VerifyingKey<P>;
}

impl<P: MayoParameter> core::fmt::Debug for KeyPair<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyPair")
            .field("variant", &P::NAME)
            .field("signing_key", &self.signing_key)
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

impl<P: MayoParameter> PartialEq for KeyPair<P> {
    fn eq(&self, other: &Self) -> bool {
        self.signing_key == other.signing_key && self.verifying_key == other.verifying_key
    }
}

impl<P: MayoParameter> Eq for KeyPair<P> {}

impl<P: MayoParameter> Zeroize for KeyPair<P> {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
    }
}

impl<P: MayoParameter> ZeroizeOnDrop for KeyPair<P> {}

impl<P: MayoParameter> KeyPair<P> {
    /// Generate a new random keypair.
    pub fn generate(rng: &mut impl CryptoRng) -> Result<Self> {
        let mut cpk = vec![0u8; P::CPK_BYTES];
        let mut csk = vec![0u8; P::CSK_BYTES];
        mayo_keypair_compact::<P>(&mut cpk, &mut csk, rng)?;
        Ok(Self {
            signing_key: SigningKey::try_from(csk)?,
            verifying_key: VerifyingKey::try_from(cpk)?,
        })
    }

    /// Generate a keypair from a specific seed.
    ///
    /// The seed must be exactly `SK_SEED_BYTES` long.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        use crate::error::Error;
        if seed.len() != P::SK_SEED_BYTES {
            return Err(Error::InvalidSeedLength {
                expected: P::SK_SEED_BYTES,
                got: seed.len(),
            });
        }

        // Use the seed directly as the secret key, then derive the public key
        let mut csk = vec![0u8; P::CSK_BYTES];
        csk[..P::SK_SEED_BYTES].copy_from_slice(seed);

        let mut cpk = vec![0u8; P::CPK_BYTES];
        // We need to derive cpk from seed - use the keygen logic
        derive_cpk_from_csk::<P>(&csk, &mut cpk);

        Ok(Self {
            signing_key: SigningKey::try_from(csk)?,
            verifying_key: VerifyingKey::try_from(cpk)?,
        })
    }

    /// Construct a keypair from a [`SigningKey`], deriving the corresponding [`VerifyingKey`].
    pub fn from_signing_key(signing_key: SigningKey<P>) -> Result<Self> {
        let csk = signing_key.as_ref();
        let mut cpk = vec![0u8; P::CPK_BYTES];
        derive_cpk_from_csk::<P>(csk, &mut cpk);
        Ok(Self {
            signing_key,
            verifying_key: VerifyingKey::try_from(cpk)?,
        })
    }

    /// Get a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey<P> {
        &self.signing_key
    }

    /// Get a reference to the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey<P> {
        &self.verifying_key
    }
}

/// Derive the compact public key from a compact secret key.
pub(crate) fn derive_cpk_from_csk<P: MayoParameter>(csk: &[u8], cpk: &mut [u8]) {
    use crate::codec::{decode, pack_m_vecs};
    use crate::keygen::expand_p1_p2;
    use crate::matrix_ops::{compute_p3, m_upper};
    use sha3::Shake256;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let m_vec_limbs = P::M_VEC_LIMBS;
    let param_m = P::M;
    let param_v = P::V;
    let param_o = P::O;
    let param_o_bytes = P::O_BYTES;
    let param_pk_seed_bytes = P::PK_SEED_BYTES;
    let param_sk_seed_bytes = P::SK_SEED_BYTES;
    let param_p3_limbs = P::P3_LIMBS;

    let seed_sk = &csk[..param_sk_seed_bytes];

    // S = SHAKE256(seed_sk) -> pk_seed || O_bytes
    let mut s = vec![0u8; param_pk_seed_bytes + param_o_bytes];
    let mut hasher = Shake256::default();
    hasher.update(seed_sk);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut s);

    let seed_pk = &s[..param_pk_seed_bytes];

    // Decode O
    let mut o = vec![0u8; param_v * param_o];
    decode(&s[param_pk_seed_bytes..], &mut o, param_v * param_o);

    // Expand P1, P2
    let mut p = expand_p1_p2::<P>(seed_pk);
    let p1_limbs = P::P1_LIMBS;

    // Compute P3
    let mut p3 = vec![0u64; param_o * param_o * m_vec_limbs];
    {
        let (p1, p2) = p.split_at_mut(p1_limbs);
        compute_p3::<P>(p1, p2, &o, &mut p3);
    }

    // Store seed_pk
    cpk[..param_pk_seed_bytes].copy_from_slice(seed_pk);

    // Upper(P3) -> pack into cpk
    let mut p3_upper = vec![0u64; param_p3_limbs];
    m_upper(m_vec_limbs, &p3, &mut p3_upper, param_o);
    pack_m_vecs(
        &p3_upper,
        &mut cpk[param_pk_seed_bytes..],
        param_p3_limbs / m_vec_limbs,
        param_m,
    );
}
