//! Complete ZKPC presentation circuit.
//!
//! Composes:
//! 1. Credential facts & predicates:
//!    - tier (posture level exposed publicly at Index 0 for verifier policy check)
//!    - issued_at <= now, expires_at > now (freshness / validity window)
//!    - rev_epoch >= min_epoch (single-epoch or accumulation validity)
//!    - pins SHA-256 padding and IV
//! 2. Hardware binding:
//!    - extracts device key K_dev = (Qx, Qy) from authenticated credential words
//!    - verifies live hardware signature (r_live, s_live) over bound challenge c
//!    - ensures K_dev is a private witness: NEVER disclosed to verifiers
//! 3. Software secret commitment & service pseudonym:
//!    - verifies software secret s binds to credential secret_commit: [s]G == (Cx, Cy)
//!    - derives service pseudonym point: P_svc = [s]P_base over RFC 9380 service base point
//!    - exposes pseudonym coordinates publicly for service-specific unlinkability
//! 4. Verifier challenge binding:
//!    - c = SHA-256(nonce || service_id || policy_hash)
//!    - exposes binding limbs publicly to prevent replay and cross-service relay

use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError, Variable,
};
use ff::{Field, PrimeField};
use halo2curves::t256::Fq;
use num_bigint::BigUint;
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::ProjectivePoint;
use vega_prover::traits::{circuit::VegaCircuit, Engine};
use zkpc_core::{binding::split_u128, credential as cred};

use crate::{
    core::{u128_to_scalar, NUM_WORDS},
    ecdsa::{reconstruct, scalar_mul, verify_ecdsa, Point},
    predicates::assert_u32_ge,
    step::decompose_32,
};

#[derive(Clone, Default)]
pub struct PresentationCircuit {
    /// 104 words linking payload, padding, IV and chained intermediate hash states.
    pub shared_vals: Vec<u32>,
    pub now: u32,
    pub min_epoch: u32,
    pub min_tier: u8,
    pub binding: [u8; 32],
    /// Live hardware signature over `binding`
    pub live_sig_r: [u8; 32],
    pub live_sig_s: [u8; 32],
    /// Software secret for service pseudonym derivation
    pub software_secret: [u8; 32],
    pub service_id: Vec<u8>,
    /// Verifier-supplied Issuer Public Key (affine coordinates Qx, Qy)
    pub issuer_pk_x: [u8; 32],
    pub issuer_pk_y: [u8; 32],
    /// Issuer signature over H4 (final credential digest)
    pub issuer_sig_r: [u8; 32],
    pub issuer_sig_s: [u8; 32],
    /// Optional override for testing negative binding attacks
    #[cfg(test)]
    pub witness_m_override: Option<[u8; 32]>,
    /// Optional override for testing secret mismatch in pseudonym vs commitment
    #[cfg(test)]
    pub witness_s_override: Option<[u8; 32]>,
    /// Optional override for testing service base substitution
    #[cfg(test)]
    pub p_base_override: Option<([u8; 32], [u8; 32])>,
    /// Optional override for testing arbitrary pseudonym witness
    #[cfg(test)]
    pub p_svc_override: Option<([u8; 32], [u8; 32])>,
}

pub fn be_to_fq(be_bytes: &[u8; 32]) -> Option<Fq> {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = be_bytes[31 - i];
    }
    Fq::from_repr(le.into()).into()
}

pub struct EcdsaWitness {
    pub e_bytes: [u8; 32],
    pub rx_bytes: [u8; 32],
    pub ry_fq: Fq,
    pub q_e: bool,
    pub q_r: bool,
}

pub fn compute_ecdsa_witness(
    pk_x: &[u8; 32],
    pk_y: &[u8; 32],
    digest: &[u8; 32],
    sig_r: &[u8; 32],
    sig_s: &[u8; 32],
) -> Result<EcdsaWitness, SynthesisError> {
    let p256_n_str =
        "115792089210356248762697446949407573529996955224135760342422259061068512044369";
    let n_big = BigUint::parse_bytes(p256_n_str.as_bytes(), 10).unwrap();
    let e_big = BigUint::from_bytes_be(digest);
    let q_e = e_big >= n_big;
    let e_mod_n = e_big % &n_big;
    let mut e_bytes_32 = [0u8; 32];
    let e_bytes = e_mod_n.to_bytes_be();
    for (i, b) in e_bytes.iter().rev().enumerate() {
        if i < 32 {
            e_bytes_32[31 - i] = *b;
        }
    }

    let mut r_proj = ProjectivePoint::IDENTITY;
    let mut valid_r = false;
    let mut q_r = false;

    let s_scalar_opt = p256::Scalar::from_repr((*sig_s).into());
    let e_scalar_opt = p256::Scalar::from_repr(e_bytes_32.into());
    let r_scalar_opt = p256::Scalar::from_repr((*sig_r).into());

    if bool::from(s_scalar_opt.is_some())
        && bool::from(e_scalar_opt.is_some())
        && bool::from(r_scalar_opt.is_some())
    {
        let s_inv = s_scalar_opt.unwrap().invert();
        if bool::from(s_inv.is_some()) {
            let s_inv_val = s_inv.unwrap();
            let u1 = e_scalar_opt.unwrap() * s_inv_val;
            let u2 = r_scalar_opt.unwrap() * s_inv_val;

            let mut q_uncompressed = vec![0x04];
            q_uncompressed.extend_from_slice(pk_x);
            q_uncompressed.extend_from_slice(pk_y);

            if let Ok(q_pt) = p256::PublicKey::from_sec1_bytes(&q_uncompressed) {
                let r_pt = ProjectivePoint::GENERATOR * u1 + q_pt.to_projective() * u2;
                if !bool::from(r_pt.is_identity()) {
                    r_proj = r_pt;
                    valid_r = true;
                    let r_affine = r_pt.to_affine();
                    let r_encoded = r_affine.to_encoded_point(false);
                    let rx_b: &[u8] = r_encoded.x().unwrap().as_ref();
                    let rx_big = BigUint::from_bytes_be(rx_b);
                    let r_big = BigUint::from_bytes_be(sig_r);
                    q_r = rx_big > r_big;
                }
            }
        }
    }

    if !valid_r {
        r_proj = ProjectivePoint::GENERATOR;
    }

    let r_affine = r_proj.to_affine();
    let r_encoded = r_affine.to_encoded_point(false);
    let rx_slice: &[u8] = r_encoded.x().unwrap().as_ref();
    let ry_slice: &[u8] = r_encoded.y().unwrap().as_ref();

    let mut rx_bytes = [0u8; 32];
    rx_bytes.copy_from_slice(rx_slice);

    let mut ry_le = [0u8; 32];
    for i in 0..32 {
        ry_le[i] = ry_slice[31 - i];
    }
    let ry_opt: Option<Fq> = Fq::from_repr(ry_le.into()).into();
    let ry_fq = ry_opt.unwrap_or(Fq::ZERO);

    Ok(EcdsaWitness {
        e_bytes: e_bytes_32,
        rx_bytes,
        ry_fq,
        q_e,
        q_r,
    })
}

fn bits_to_lc<F: PrimeField>(bits: &[Boolean], one: Variable) -> LinearCombination<F> {
    let mut lc = LinearCombination::<F>::zero();
    let mut coeff = F::ONE;
    for bit in bits {
        match bit {
            Boolean::Is(b) => lc = lc + (coeff, b.get_variable()),
            Boolean::Not(b) => lc = lc + (coeff, one) - (coeff, b.get_variable()),
            Boolean::Constant(c) => {
                if *c {
                    lc = lc + (coeff, one)
                }
            }
        }
        coeff = coeff.double();
    }
    lc
}

fn low_u32<F: PrimeField>(v: &F) -> u32 {
    let r = v.to_repr();
    let b = r.as_ref();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes.iter().rev() {
        for i in 0..8 {
            bits.push((b >> i) & 1 == 1);
        }
    }
    bits
}

fn alloc_bits_le<CS: ConstraintSystem<Fq>>(cs: &mut CS, bits: &[bool], name: &str) -> Vec<Boolean> {
    let mut allocated = Vec::with_capacity(bits.len());
    for (i, &b) in bits.iter().enumerate() {
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("{}_{}", name, i)), Some(b)).unwrap();
        allocated.push(Boolean::Is(bit));
    }
    allocated
}

impl PresentationCircuit {
    pub fn words(&self) -> Result<Vec<u32>, SynthesisError> {
        match self.shared_vals.len() {
            0 => Ok(vec![0; NUM_WORDS]),
            NUM_WORDS => Ok(self.shared_vals.clone()),
            _ => Err(SynthesisError::Unsatisfiable),
        }
    }

    /// Computes the public service base point P_base for this presentation.
    pub fn try_service_base(&self) -> Result<([u8; 32], [u8; 32]), SynthesisError> {
        #[cfg(test)]
        if let Some(base) = self.p_base_override {
            return Ok(base);
        }
        let (_, _, bx, by) = zkpc_core::hash2curve::derive_service_base(&self.service_id)
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        Ok((bx, by))
    }

    pub fn service_base(&self) -> ([u8; 32], [u8; 32]) {
        self.try_service_base().unwrap_or(([0u8; 32], [0u8; 32]))
    }

    /// Computes the public service pseudonym point P_svc = [s]P_base for this presentation.
    pub fn try_service_pseudonym_point(&self) -> Result<([u8; 32], [u8; 32]), SynthesisError> {
        #[cfg(test)]
        if let Some(p) = self.p_svc_override {
            return Ok(p);
        }
        let (bx, by) = self.try_service_base()?;
        let s_scalar_opt = p256::Scalar::from_repr(self.software_secret.into());
        if bool::from(s_scalar_opt.is_none()) {
            return Err(SynthesisError::AssignmentMissing);
        }
        let s_scalar = s_scalar_opt.unwrap();
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&bx);
        sec1.extend_from_slice(&by);
        let pk = p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let p_base_pt = pk.to_projective();
        let p_svc_aff = (p_base_pt * s_scalar).to_affine();
        let enc = p_svc_aff.to_encoded_point(false);
        let mut sx = [0u8; 32];
        let mut sy = [0u8; 32];
        if let Some(x) = enc.x() {
            sx.copy_from_slice(x);
        }
        if let Some(y) = enc.y() {
            sy.copy_from_slice(y);
        }
        Ok((sx, sy))
    }

    pub fn service_pseudonym_point(&self) -> ([u8; 32], [u8; 32]) {
        self.try_service_pseudonym_point()
            .unwrap_or(([0u8; 32], [0u8; 32]))
    }
}

impl<E: Engine<Scalar = Fq>> VegaCircuit<E> for PresentationCircuit {
    fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
        let w = self.words()?;
        let tier = (w[cred::OFF_TIER / 4] >> ((3 - (cred::OFF_TIER % 4)) * 8)) & 0xFF;
        let k = cred::OFF_ISSUER_KEY_ID / 4;
        let (hi, lo) = split_u128(&self.binding);
        let issuer_x = be_to_fq(&self.issuer_pk_x).ok_or(SynthesisError::AssignmentMissing)?;
        let issuer_y = be_to_fq(&self.issuer_pk_y).ok_or(SynthesisError::AssignmentMissing)?;
        let (bx, by) = self.try_service_base()?;
        let p_base_x = be_to_fq(&bx).ok_or(SynthesisError::AssignmentMissing)?;
        let p_base_y = be_to_fq(&by).ok_or(SynthesisError::AssignmentMissing)?;
        let (sx, sy) = self.try_service_pseudonym_point()?;
        let p_svc_x = be_to_fq(&sx).ok_or(SynthesisError::AssignmentMissing)?;
        let p_svc_y = be_to_fq(&sy).ok_or(SynthesisError::AssignmentMissing)?;

        Ok(vec![
            E::Scalar::from(tier as u64),
            E::Scalar::from(w[k] as u64),
            E::Scalar::from(w[k + 1] as u64),
            E::Scalar::from(self.now as u64),
            E::Scalar::from(self.min_epoch as u64),
            u128_to_scalar::<E::Scalar>(hi),
            u128_to_scalar::<E::Scalar>(lo),
            issuer_x,
            issuer_y,
            p_base_x,
            p_base_y,
            p_svc_x,
            p_svc_y,
        ])
    }

    fn shared<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        let w = self.words()?;
        w.iter()
            .enumerate()
            .map(|(i, v)| {
                AllocatedNum::alloc(cs.namespace(|| format!("shared_{i}")), || {
                    Ok(E::Scalar::from(*v as u64))
                })
            })
            .collect()
    }

    fn precommitted<CS: ConstraintSystem<E::Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<E::Scalar>],
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<E::Scalar>],
        _precommitted: &[AllocatedNum<E::Scalar>],
        _challenges: Option<&[E::Scalar]>,
    ) -> Result<(), SynthesisError> {
        if shared.len() != NUM_WORDS {
            return Err(SynthesisError::Unsatisfiable);
        }

        // =====================================================================
        // SECTION 1: Credential Facts & Predicates
        // =====================================================================
        let tier_word = &shared[cred::OFF_TIER / 4];
        let tier_bits = decompose_32::<E, _>(cs.namespace(|| "tier_word"), tier_word)?;
        let byte_lsb = 3 - (cred::OFF_TIER % 4);
        let tier_lc =
            bits_to_lc::<E::Scalar>(&tier_bits[byte_lsb * 8..byte_lsb * 8 + 8], CS::one());
        let tier_var = AllocatedNum::alloc(cs.namespace(|| "tier"), || {
            let w = tier_word
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(E::Scalar::from(
                ((low_u32(&w) >> (byte_lsb * 8)) & 0xFF) as u64,
            ))
        })?;
        cs.enforce(
            || "tier_match",
            |lc| lc + tier_var.get_variable(),
            |lc| lc + CS::one(),
            |_| tier_lc,
        );

        let issued_at = &shared[cred::OFF_ISSUED_AT / 4];
        let expires_at = &shared[cred::OFF_EXPIRES_AT / 4];
        let rev_epoch = &shared[cred::OFF_REVOCATION_EPOCH / 4];
        let key_id_0 = &shared[cred::OFF_ISSUER_KEY_ID / 4];
        let key_id_1 = &shared[cred::OFF_ISSUER_KEY_ID / 4 + 1];

        let now_var = AllocatedNum::alloc(cs.namespace(|| "now"), || {
            Ok(E::Scalar::from(self.now as u64))
        })?;
        let min_epoch_var = AllocatedNum::alloc(cs.namespace(|| "min_epoch"), || {
            Ok(E::Scalar::from(self.min_epoch as u64))
        })?;
        let min_tier_var = AllocatedNum::alloc(cs.namespace(|| "min_tier"), || {
            Ok(E::Scalar::from(self.min_tier as u64))
        })?;

        // Validity window and epoch predicates:
        // (Note: presented posture tier is exposed publicly at Index 0 and checked against policy.min_tier by verifier)
        assert_u32_ge::<E, _>(
            cs.namespace(|| "tier >= min_tier"),
            &tier_var,
            &min_tier_var,
            false,
        )?;
        assert_u32_ge::<E, _>(
            cs.namespace(|| "issued_at <= now"),
            &now_var,
            issued_at,
            false,
        )?;
        assert_u32_ge::<E, _>(
            cs.namespace(|| "expires_at > now"),
            expires_at,
            &now_var,
            true,
        )?;
        assert_u32_ge::<E, _>(
            cs.namespace(|| "epoch >= min_epoch"),
            rev_epoch,
            &min_epoch_var,
            false,
        )?;

        // SHA-256 padding block and IV pinning:
        let pad_start = cred::PAYLOAD_SIZE / 4;
        let padding: [u32; 16] = [
            0x8000_0000,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x0000_0600,
        ];
        for (i, v) in padding.iter().enumerate() {
            let c = E::Scalar::from(*v as u64);
            cs.enforce(
                || format!("padding_{i}"),
                |lc| lc + shared[pad_start + i].get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + (c, CS::one()),
            );
        }
        let iv: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        for (i, v) in iv.iter().enumerate() {
            let c = E::Scalar::from(*v as u64);
            cs.enforce(
                || format!("h0_iv_{i}"),
                |lc| lc + shared[64 + i].get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + (c, CS::one()),
            );
        }

        // =====================================================================
        // SECTION 2: Extract Credential-Bound Hardware Key K_dev
        // =====================================================================
        // K_dev.x is payload words 2..10 (8 words = 32 bytes)
        // K_dev.y is payload words 10..18 (8 words = 32 bytes)
        let kdev_x_start = cred::OFF_KDEV_X / 4;
        let mut kdev_x_bits = Vec::with_capacity(256);
        for word_idx in (0..8).rev() {
            let bits = decompose_32::<E, _>(
                cs.namespace(|| format!("kdev_x_w_{word_idx}")),
                &shared[kdev_x_start + word_idx],
            )?;
            kdev_x_bits.extend(bits);
        }
        let qx_num = reconstruct(cs.namespace(|| "kdev_x_recon"), &kdev_x_bits)?;

        let kdev_y_start = cred::OFF_KDEV_Y / 4;
        let mut kdev_y_bits = Vec::with_capacity(256);
        for word_idx in (0..8).rev() {
            let bits = decompose_32::<E, _>(
                cs.namespace(|| format!("kdev_y_w_{word_idx}")),
                &shared[kdev_y_start + word_idx],
            )?;
            kdev_y_bits.extend(bits);
        }
        let qy_num = reconstruct(cs.namespace(|| "kdev_y_recon"), &kdev_y_bits)?;

        let pub_key = Point {
            x: qx_num,
            y: qy_num,
            is_inf: Boolean::Constant(false),
        };

        // =====================================================================
        // SECTION 3: Live Hardware Signature Proof-of-Possession
        // =====================================================================
        // Verifies (live_sig_r, live_sig_s) over challenge binding under K_dev.
        // HARDWARE SIGNING SEMANTICS DECISION & SOURCE:
        // - TPM 2.0: Command TPM2_Sign (TCG TPM 2.0 Library Spec Part 3, Sec 14.2)
        //   takes `digest: TPM2B_DIGEST`. For scheme TPM_ALG_ECDSA, the TPM does
        //   NOT hash `digest` again; it converts the 32-byte digest directly into
        //   the scalar message representative `e = int(digest) mod n`.
        // - Apple Secure Enclave: `SecKeyCreateSignature` with algorithm
        //   `kSecKeyAlgorithmECDSASignatureDigestX962SHA256` (Apple Security Framework)
        //   takes an already-computed 32-byte SHA-256 digest and computes ECDSA
        //   directly over that digest without hashing it again.
        #[cfg(test)]
        let digest_bytes = self.witness_m_override.unwrap_or(self.binding);
        #[cfg(not(test))]
        let digest_bytes = self.binding;
        let words = self.words()?;
        let mut q_x = [0u8; 32];
        let mut q_y = [0u8; 32];
        for (w_i, w_val) in words[kdev_x_start..kdev_x_start + 8].iter().enumerate() {
            q_x[w_i * 4..w_i * 4 + 4].copy_from_slice(&w_val.to_be_bytes());
        }
        for (w_i, w_val) in words[kdev_y_start..kdev_y_start + 8].iter().enumerate() {
            q_y[w_i * 4..w_i * 4 + 4].copy_from_slice(&w_val.to_be_bytes());
        }

        let live_wit = compute_ecdsa_witness(
            &q_x,
            &q_y,
            &digest_bytes,
            &self.live_sig_r,
            &self.live_sig_s,
        )?;

        let r_y = AllocatedNum::alloc(cs.namespace(|| "ry_alloc"), || Ok(live_wit.ry_fq))?;

        let m_bits = alloc_bits_le(cs, &bytes_to_bits_le(&digest_bytes), "m_bind");
        let r_bits = alloc_bits_le(cs, &bytes_to_bits_le(&self.live_sig_r), "r_live");
        let s_bits = alloc_bits_le(cs, &bytes_to_bits_le(&self.live_sig_s), "s_live");
        let e_bits = alloc_bits_le(cs, &bytes_to_bits_le(&live_wit.e_bytes), "e_bind");
        let rx_bits = alloc_bits_le(cs, &bytes_to_bits_le(&live_wit.rx_bytes), "rx_live");

        let q_e = Boolean::Is(AllocatedBit::alloc(
            cs.namespace(|| "qe_alloc"),
            Some(live_wit.q_e),
        )?);
        let q_r = Boolean::Is(AllocatedBit::alloc(
            cs.namespace(|| "qr_alloc"),
            Some(live_wit.q_r),
        )?);

        // Verify ECDSA proof of possession in zero-knowledge:
        verify_ecdsa(
            cs.namespace(|| "live_hardware_ecdsa"),
            &pub_key,
            &m_bits,
            &r_bits,
            &s_bits,
            &e_bits,
            &rx_bits,
            &q_e,
            &q_r,
            &r_y,
        )?;

        // =====================================================================
        // SECTION 4: Authenticate Credential with Enrollment Authority Signature
        // =====================================================================
        // The EA signs the final SHA-256 digest H4 of the authenticated
        // credential words (192 bytes payload + 64 bytes padding).
        // H4 is stored in shared words 96..104, constrained by CredentialStepCircuit.
        // The issuer public key is a verifier-supplied public input, NEVER a witness.
        let mut h4_bytes = [0u8; 32];
        for (w_i, w_val) in words[96..104].iter().enumerate() {
            h4_bytes[w_i * 4..w_i * 4 + 4].copy_from_slice(&w_val.to_be_bytes());
        }

        let issuer_wit = compute_ecdsa_witness(
            &self.issuer_pk_x,
            &self.issuer_pk_y,
            &h4_bytes,
            &self.issuer_sig_r,
            &self.issuer_sig_s,
        )?;

        // Decompose shared[96..104] (H4) into in-circuit bits (LSB to MSB)
        let mut h4_bits = Vec::with_capacity(256);
        for word_idx in (0..8).rev() {
            let bits = decompose_32::<E, _>(
                cs.namespace(|| format!("h4_w_{word_idx}")),
                &shared[96 + word_idx],
            )?;
            h4_bits.extend(bits);
        }

        let r_issuer_bits = alloc_bits_le(cs, &bytes_to_bits_le(&self.issuer_sig_r), "r_issuer");
        let s_issuer_bits = alloc_bits_le(cs, &bytes_to_bits_le(&self.issuer_sig_s), "s_issuer");
        let e_issuer_bits = alloc_bits_le(cs, &bytes_to_bits_le(&issuer_wit.e_bytes), "e_issuer");
        let rx_issuer_bits =
            alloc_bits_le(cs, &bytes_to_bits_le(&issuer_wit.rx_bytes), "rx_issuer");
        let qe_issuer = Boolean::Is(AllocatedBit::alloc(
            cs.namespace(|| "qe_issuer_alloc"),
            Some(issuer_wit.q_e),
        )?);
        let qr_issuer = Boolean::Is(AllocatedBit::alloc(
            cs.namespace(|| "qr_issuer_alloc"),
            Some(issuer_wit.q_r),
        )?);
        let ry_issuer =
            AllocatedNum::alloc(cs.namespace(|| "ry_issuer_alloc"), || Ok(issuer_wit.ry_fq))?;

        // Allocate issuer public key as public input
        let issuer_pk_x_num = AllocatedNum::alloc(cs.namespace(|| "issuer_pk_x"), || {
            be_to_fq(&self.issuer_pk_x).ok_or(SynthesisError::AssignmentMissing)
        })?;
        let issuer_pk_y_num = AllocatedNum::alloc(cs.namespace(|| "issuer_pk_y"), || {
            be_to_fq(&self.issuer_pk_y).ok_or(SynthesisError::AssignmentMissing)
        })?;

        let issuer_pub_key = Point {
            x: issuer_pk_x_num.clone(),
            y: issuer_pk_y_num.clone(),
            is_inf: Boolean::Constant(false),
        };

        verify_ecdsa(
            cs.namespace(|| "issuer_ecdsa"),
            &issuer_pub_key,
            &h4_bits,
            &r_issuer_bits,
            &s_issuer_bits,
            &e_issuer_bits,
            &rx_issuer_bits,
            &qe_issuer,
            &qr_issuer,
            &ry_issuer,
        )?;

        // =====================================================================
        // SECTION 5: Software Secret Binding & Algebraic Pseudonym Derivation
        // =====================================================================
        // Authoritative Construction:
        // C = [s]G  (credential commitment in payload words 22..38)
        // P_base = hash_to_curve(DST_svc, service_id)  (public verifier-supplied base point)
        // P_svc = [s]P_base  (public service-specific pseudonym point)
        // Both scalar multiplications consume the exact same allocated `secret_bits` witness.

        // Decompose software secret s and enforce s != 0 and s < n
        let secret_bits = alloc_bits_le(cs, &bytes_to_bits_le(&self.software_secret), "sec_s");
        crate::ecdsa::enforce_not_zero(cs.namespace(|| "sec_s != 0"), &secret_bits)?;
        crate::ecdsa::enforce_less_than_const(
            cs.namespace(|| "sec_s < n"),
            &secret_bits,
            &crate::ecdsa::N_BITS_LE,
        )?;

        // Credential payload words 22..30 hold secret commitment Cx (32 bytes)
        // Credential payload words 30..38 hold secret commitment Cy (32 bytes)
        let s_commit_x_start = cred::OFF_SECRET_COMMIT / 4;
        let mut commit_x_bits = Vec::with_capacity(256);
        for word_idx in (0..8).rev() {
            let bits = decompose_32::<E, _>(
                cs.namespace(|| format!("commit_x_w_{word_idx}")),
                &shared[s_commit_x_start + word_idx],
            )?;
            commit_x_bits.extend(bits);
        }
        let commit_x_num = reconstruct(cs.namespace(|| "commit_x_recon"), &commit_x_bits)?;
        crate::ecdsa::enforce_less_than_const(
            cs.namespace(|| "commit_x < p"),
            &commit_x_bits,
            &crate::ecdsa::P_BITS_LE,
        )?;

        let s_commit_y_start = cred::OFF_SECRET_COMMIT / 4 + 8;
        let mut commit_y_bits = Vec::with_capacity(256);
        for word_idx in (0..8).rev() {
            let bits = decompose_32::<E, _>(
                cs.namespace(|| format!("commit_y_w_{word_idx}")),
                &shared[s_commit_y_start + word_idx],
            )?;
            commit_y_bits.extend(bits);
        }
        let commit_y_num = reconstruct(cs.namespace(|| "commit_y_recon"), &commit_y_bits)?;
        crate::ecdsa::enforce_less_than_const(
            cs.namespace(|| "commit_y < p"),
            &commit_y_bits,
            &crate::ecdsa::P_BITS_LE,
        )?;

        let gx_val = Fq::from_str_vartime(
            "48439561293906451759052585252797914202762949526041747995844080717082404635286",
        )
        .unwrap();
        let gy_val = Fq::from_str_vartime(
            "36134250956749795798585127919587881956611106672985015071877198253568414405109",
        )
        .unwrap();
        let g_pt = Point {
            x: AllocatedNum::alloc(cs.namespace(|| "sec_gx"), || Ok(gx_val))?,
            y: AllocatedNum::alloc(cs.namespace(|| "sec_gy"), || Ok(gy_val))?,
            is_inf: Boolean::Constant(false),
        };
        let a_val = Fq::from_str_vartime(
            "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        )
        .unwrap();
        let b_val = Fq::from_str_vartime(
            "41058363725152142129326129780047268409114441015993725554835256314039467401291",
        )
        .unwrap();

        // 1. Enforce C = [s]G
        let s_g = scalar_mul(cs.namespace(|| "compute_sg"), &g_pt, &secret_bits, a_val)?;

        cs.enforce(
            || "commit_x_match",
            |lc| lc + s_g.x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + commit_x_num.get_variable(),
        );
        cs.enforce(
            || "commit_y_match",
            |lc| lc + s_g.y.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + commit_y_num.get_variable(),
        );

        // 2. Allocate and constrain Service Base P_base
        let (bx, by) = self.try_service_base()?;
        let p_base_x_fq = be_to_fq(&bx).ok_or(SynthesisError::AssignmentMissing)?;
        let p_base_y_fq = be_to_fq(&by).ok_or(SynthesisError::AssignmentMissing)?;
        let p_base_x_var = AllocatedNum::alloc(cs.namespace(|| "p_base_x"), || Ok(p_base_x_fq))?;
        let p_base_y_var = AllocatedNum::alloc(cs.namespace(|| "p_base_y"), || Ok(p_base_y_fq))?;

        // On-curve check for P_base: y^2 == x^3 + ax + b
        let pbase_y2 = p_base_y_var.square(cs.namespace(|| "pbase_y2"))?;
        let pbase_x2 = p_base_x_var.square(cs.namespace(|| "pbase_x2"))?;
        let pbase_x3 = pbase_x2.mul(cs.namespace(|| "pbase_x3"), &p_base_x_var)?;
        let pbase_ax = AllocatedNum::alloc(cs.namespace(|| "pbase_ax"), || {
            let x_val = p_base_x_var
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a_val * x_val)
        })?;
        cs.enforce(
            || "pbase_ax_calc",
            |lc| lc + (a_val, p_base_x_var.get_variable()),
            |lc| lc + CS::one(),
            |lc| lc + pbase_ax.get_variable(),
        );
        cs.enforce(
            || "pbase_on_curve",
            |lc| lc + CS::one(),
            |lc| lc + pbase_x3.get_variable() + pbase_ax.get_variable() + (b_val, CS::one()),
            |lc| lc + pbase_y2.get_variable(),
        );

        let p_base_pt = Point {
            x: p_base_x_var.clone(),
            y: p_base_y_var.clone(),
            is_inf: Boolean::Constant(false),
        };

        // 3. Enforce P_svc = [s]P_base
        // For shared-scalar binding adversarial tests, witness_s_override allows providing s' != s for pseudonym
        #[cfg(test)]
        let pseudo_secret_bits = if let Some(override_s) = self.witness_s_override {
            alloc_bits_le(cs, &bytes_to_bits_le(&override_s), "pseudo_s_override")
        } else {
            secret_bits.clone()
        };
        #[cfg(not(test))]
        let pseudo_secret_bits = secret_bits.clone();
        let s_pbase = scalar_mul(
            cs.namespace(|| "compute_s_pbase"),
            &p_base_pt,
            &pseudo_secret_bits,
            a_val,
        )?;

        let (sx, sy) = self.try_service_pseudonym_point()?;
        let p_svc_x_fq = be_to_fq(&sx).ok_or(SynthesisError::AssignmentMissing)?;
        let p_svc_y_fq = be_to_fq(&sy).ok_or(SynthesisError::AssignmentMissing)?;
        let p_svc_x_var = AllocatedNum::alloc(cs.namespace(|| "p_svc_x"), || Ok(p_svc_x_fq))?;
        let p_svc_y_var = AllocatedNum::alloc(cs.namespace(|| "p_svc_y"), || Ok(p_svc_y_fq))?;

        cs.enforce(
            || "p_svc_x_match",
            |lc| lc + s_pbase.x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + p_svc_x_var.get_variable(),
        );
        cs.enforce(
            || "p_svc_y_match",
            |lc| lc + s_pbase.y.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + p_svc_y_var.get_variable(),
        );

        // =====================================================================
        // SECTION 6: Challenge Binding Integrity & Public Inputs
        // =====================================================================
        let (hi, lo) = split_u128(&self.binding);
        let hi_var = AllocatedNum::alloc(cs.namespace(|| "binding_hi"), || {
            Ok(u128_to_scalar::<E::Scalar>(hi))
        })?;
        let lo_var = AllocatedNum::alloc(cs.namespace(|| "binding_lo"), || {
            Ok(u128_to_scalar::<E::Scalar>(lo))
        })?;

        let mut lo_lc = bellpepper_core::LinearCombination::<E::Scalar>::zero();
        let mut base_lo = E::Scalar::ONE;
        for bit in &m_bits[0..128] {
            lo_lc = lo_lc + &bit.lc(CS::one(), base_lo);
            base_lo = base_lo.double();
        }
        cs.enforce(
            || "binding_lo == m_bits[0..128]",
            |_| lo_lc,
            |lc| lc + CS::one(),
            |lc| lc + lo_var.get_variable(),
        );

        let mut hi_lc = bellpepper_core::LinearCombination::<E::Scalar>::zero();
        let mut base_hi = E::Scalar::ONE;
        for bit in &m_bits[128..256] {
            hi_lc = hi_lc + &bit.lc(CS::one(), base_hi);
            base_hi = base_hi.double();
        }
        cs.enforce(
            || "binding_hi == m_bits[128..256]",
            |_| hi_lc,
            |lc| lc + CS::one(),
            |lc| lc + hi_var.get_variable(),
        );

        // Canonical public inputs matching statement layout V2:
        // 0: tier
        tier_var.inputize(cs.namespace(|| "pub tier"))?;
        // 1..2: key_id
        key_id_0.inputize(cs.namespace(|| "pub key_id_0"))?;
        key_id_1.inputize(cs.namespace(|| "pub key_id_1"))?;
        // 3: now
        now_var.inputize(cs.namespace(|| "pub now"))?;
        // 4: min_epoch
        min_epoch_var.inputize(cs.namespace(|| "pub min_epoch"))?;
        // 5..6: binding limbs
        hi_var.inputize(cs.namespace(|| "pub binding_hi"))?;
        lo_var.inputize(cs.namespace(|| "pub binding_lo"))?;
        // 7..8: issuer public key coordinates
        issuer_pk_x_num.inputize(cs.namespace(|| "pub issuer_pk_x"))?;
        issuer_pk_y_num.inputize(cs.namespace(|| "pub issuer_pk_y"))?;
        // 9..10: service base point P_base coordinates
        p_base_x_var.inputize(cs.namespace(|| "pub p_base_x"))?;
        p_base_y_var.inputize(cs.namespace(|| "pub p_base_y"))?;
        // 11..12: service pseudonym point P_svc coordinates
        p_svc_x_var.inputize(cs.namespace(|| "pub p_svc_x"))?;
        p_svc_y_var.inputize(cs.namespace(|| "pub p_svc_y"))?;

        Ok(())
    }
}

/// Enforces that all step circuits and the presentation circuit share identical `shared_vals`.
///
/// Vega takes the shared values from step 0. Because host-side witness derivation in the
/// presentation circuit computes credential intermediate digests and curve witnesses directly
/// from `presentation.shared_vals`, any divergence between step circuits and the presentation
/// circuit leads to silent inconsistencies or proof generation / verification failures.
pub fn guard_identical_presentation_shared(
    steps: &[crate::step::CredentialStepCircuit],
    presentation: &PresentationCircuit,
) -> Result<(), SynthesisError> {
    if steps.is_empty() {
        return Err(SynthesisError::AssignmentMissing);
    }
    for step in steps {
        if step.shared_vals != presentation.shared_vals {
            return Err(SynthesisError::Unsatisfiable);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use rand_core::OsRng;
    use std::time::Instant;
    use vega_prover::provider::T256HyraxEngine;
    use vega_prover::vega_mc_zkp::VegaMcZkSNARK;

    const NOW: u32 = 1_800_000_000;
    const KEY: u64 = (0xAAAA_0001u64 << 32) | 2;

    fn build_test_credential_with_keys(
        tier: u8,
        now: u32,
        issued_at: u32,
        expires_at: u32,
        epoch: u32,
        secret_bytes: [u8; 32],
        binding: [u8; 32],
        service_id: Vec<u8>,
        hw_sk: &SigningKey,
        issuer_sk: &SigningKey,
    ) -> PresentationCircuit {
        let hw_vk = hw_sk.verifying_key();
        let hw_pt = hw_vk.to_encoded_point(false);
        let q_x = &hw_pt.x().unwrap()[..];
        let q_y = &hw_pt.y().unwrap()[..];

        let issuer_vk = issuer_sk.verifying_key();
        let issuer_pt = issuer_vk.to_encoded_point(false);
        let mut issuer_pk_x = [0u8; 32];
        let mut issuer_pk_y = [0u8; 32];
        issuer_pk_x.copy_from_slice(&issuer_pt.x().unwrap()[..]);
        issuer_pk_y.copy_from_slice(&issuer_pt.y().unwrap()[..]);

        // Software secret commitment: [s]G
        let s_scalar_opt = p256::Scalar::from_repr(secret_bytes.into());
        let s_scalar = s_scalar_opt.unwrap();
        let commit_pt = (ProjectivePoint::GENERATOR * s_scalar).to_affine();
        let commit_encoded = commit_pt.to_encoded_point(false);
        let cx = &commit_encoded.x().unwrap()[..];
        let cy = &commit_encoded.y().unwrap()[..];

        let mut p = [0u8; 192];
        p[cred::OFF_VERSION] = 1;
        p[cred::OFF_PLATFORM] = 3;
        p[cred::OFF_TIER] = tier;
        p[cred::OFF_POSTURE..cred::OFF_POSTURE + 4].copy_from_slice(&0x0000_0001u32.to_be_bytes());
        p[cred::OFF_KDEV_X..cred::OFF_KDEV_X + 32].copy_from_slice(q_x);
        p[cred::OFF_KDEV_Y..cred::OFF_KDEV_Y + 32].copy_from_slice(q_y);
        p[cred::OFF_SECRET_COMMIT..cred::OFF_SECRET_COMMIT + 32].copy_from_slice(cx);
        p[cred::OFF_SECRET_COMMIT + 32..cred::OFF_SECRET_COMMIT + 64].copy_from_slice(cy);
        p[cred::OFF_ISSUED_AT..cred::OFF_ISSUED_AT + 4].copy_from_slice(&issued_at.to_be_bytes());
        p[cred::OFF_EXPIRES_AT..cred::OFF_EXPIRES_AT + 4]
            .copy_from_slice(&expires_at.to_be_bytes());
        p[cred::OFF_REVOCATION_EPOCH..cred::OFF_REVOCATION_EPOCH + 4]
            .copy_from_slice(&epoch.to_be_bytes());
        p[cred::OFF_ISSUER_KEY_ID..cred::OFF_ISSUER_KEY_ID + 8].copy_from_slice(&KEY.to_be_bytes());

        let (w, h4_state) = crate::step::build_shared(&p);

        // Sign final credential hash H4 with issuer key
        let mut h4_bytes = [0u8; 32];
        for (i, val) in h4_state.iter().enumerate() {
            h4_bytes[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        let issuer_sig: p256::ecdsa::Signature = issuer_sk
            .sign_prehash(&h4_bytes)
            .expect("issuer sign_prehash");
        let mut issuer_sig_r = [0u8; 32];
        let mut issuer_sig_s = [0u8; 32];
        issuer_sig_r.copy_from_slice(&issuer_sig.r().to_bytes());
        issuer_sig_s.copy_from_slice(&issuer_sig.s().to_bytes());

        // Sign live challenge raw digest with hardware key (pre-hashed)
        let sig: p256::ecdsa::Signature = hw_sk.sign_prehash(&binding).expect("sign_prehash");
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&sig.r().to_bytes());
        s_bytes.copy_from_slice(&sig.s().to_bytes());

        PresentationCircuit {
            shared_vals: w,
            now,
            min_epoch: epoch,
            min_tier: tier,
            binding,
            live_sig_r: r_bytes,
            live_sig_s: s_bytes,
            software_secret: secret_bytes,
            service_id,
            issuer_pk_x,
            issuer_pk_y,
            issuer_sig_r,
            issuer_sig_s,
            witness_m_override: None,
            witness_s_override: None,
            p_base_override: None,
            p_svc_override: None,
        }
    }

    fn build_test_credential_and_sig(
        tier: u8,
        issued_at: u32,
        expires_at: u32,
        epoch: u32,
        secret_bytes: [u8; 32],
        binding: [u8; 32],
    ) -> (PresentationCircuit, SigningKey, SigningKey) {
        let hw_sk = SigningKey::random(&mut OsRng);
        let issuer_sk = SigningKey::random(&mut OsRng);
        let circuit = build_test_credential_with_keys(
            tier,
            NOW,
            issued_at,
            expires_at,
            epoch,
            secret_bytes,
            binding,
            b"vpn.example".to_vec(),
            &hw_sk,
            &issuer_sk,
        );
        (circuit, hw_sk, issuer_sk)
    }

    #[test]
    fn test_presentation_honest_satisfied_and_constraints() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None).unwrap();

        println!("\n==========================================================");
        println!("=== COMPLETE PRESENTATION CIRCUIT CONSTRAINT MEASUREMENT ===");
        println!("Total R1CS Constraints: {}", cs.num_constraints());
        println!("Honest Presentation Satisfied: {}", cs.is_satisfied());
        println!("==========================================================\n");

        assert!(
            cs.is_satisfied(),
            "Unsatisfied: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn test_presentation_rejects_wrong_hardware_key() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Sign challenge with a DIFFERENT hardware key
        let rogue_sk = SigningKey::random(&mut OsRng);
        let rogue_sig: p256::ecdsa::Signature = rogue_sk.sign(&binding);
        circuit
            .live_sig_r
            .copy_from_slice(&rogue_sig.r().to_bytes());
        circuit
            .live_sig_s
            .copy_from_slice(&rogue_sig.s().to_bytes());

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Presentation with rogue signature must be rejected"
        );
        println!("Rogue HW key signature rejected: true");
    }

    #[test]
    fn test_presentation_rejects_altered_challenge() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, hw_sk, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Hardware key signed a DIFFERENT challenge
        let other_binding =
            zkpc_core::binding::binding_hash(b"nonce_attacker", b"vpn.example", b"policy456");
        let other_sig: p256::ecdsa::Signature =
            hw_sk.sign_prehash(&other_binding).expect("sign_prehash");
        circuit
            .live_sig_r
            .copy_from_slice(&other_sig.r().to_bytes());
        circuit
            .live_sig_s
            .copy_from_slice(&other_sig.s().to_bytes());

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Altered challenge must be rejected");
        println!("Altered challenge signature rejected: true");
    }

    #[test]
    fn test_presentation_binding_enforces_digest_equality_against_forged_witness() {
        let binding_verifier =
            zkpc_core::binding::binding_hash(b"fresh_nonce", b"vpn.example", b"policy");
        let binding_attacker =
            zkpc_core::binding::binding_hash(b"replay_nonce", b"vpn.example", b"policy");
        let secret = [0x42u8; 32];
        let (mut circuit, hw_sk, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding_attacker);

        // Attacker has a valid signature over binding_attacker:
        let sig: p256::ecdsa::Signature =
            hw_sk.sign_prehash(&binding_attacker).expect("sign_prehash");
        circuit.live_sig_r.copy_from_slice(&sig.r().to_bytes());
        circuit.live_sig_s.copy_from_slice(&sig.s().to_bytes());

        // Case A: Attacker attempts to feed witness bits for binding_attacker (making ECDSA pass)
        // while declaring public inputs for binding_verifier:
        circuit.binding = binding_verifier;
        circuit.witness_m_override = Some(binding_attacker);

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Forged witness with divergent binding must fail binding constraint"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Forged witness rejected by binding constraint: true (failing constraint: {})",
            failing
        );
        assert!(
            failing.contains("binding_lo") || failing.contains("binding_hi"),
            "Must fail binding integrity constraint"
        );

        // Case B: Attacker attempts to sign binding_attacker but pass binding_verifier without override (ECDSA fails):
        circuit.witness_m_override = None;
        let mut cs2 = TestConstraintSystem::<Fq>::new();
        let sh2 = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs2).unwrap();
        let pre2 = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs2, &sh2).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs2, &sh2, &pre2, None);

        assert!(
            !cs2.is_satisfied(),
            "Valid signature over different digest without override must fail"
        );
        let failing2 = cs2.which_is_unsatisfied().unwrap();
        println!(
            "Signature over different digest rejected by ECDSA: true (failing constraint: {})",
            failing2
        );
    }

    #[test]
    fn test_presentation_rejects_credential_signed_by_untrusted_issuer() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _trusted_issuer_sk) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Sign H4 with a ROGUE untrusted issuer key
        let untrusted_sk = SigningKey::random(&mut OsRng);
        let h4_words = &circuit.shared_vals[96..104];
        let mut h4_bytes = [0u8; 32];
        for (i, val) in h4_words.iter().enumerate() {
            h4_bytes[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        let untrusted_sig: p256::ecdsa::Signature = untrusted_sk
            .sign_prehash(&h4_bytes)
            .expect("untrusted sign_prehash");

        // Prover passes signature from untrusted key, while public input remains trusted issuer key
        circuit
            .issuer_sig_r
            .copy_from_slice(&untrusted_sig.r().to_bytes());
        circuit
            .issuer_sig_s
            .copy_from_slice(&untrusted_sig.s().to_bytes());

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Credential signed by untrusted key must fail"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Credential signed by untrusted key rejected: true (failing constraint: {})",
            failing
        );
        assert!(
            failing.contains("issuer_ecdsa"),
            "Must fail in issuer_ecdsa namespace"
        );
    }

    #[test]
    fn test_presentation_rejects_self_signed_credential() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, hw_sk, _trusted_issuer_sk) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Attacker self-signs H4 using their own device hardware key K_dev
        let h4_words = &circuit.shared_vals[96..104];
        let mut h4_bytes = [0u8; 32];
        for (i, val) in h4_words.iter().enumerate() {
            h4_bytes[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        let self_sig: p256::ecdsa::Signature =
            hw_sk.sign_prehash(&h4_bytes).expect("self sign_prehash");

        circuit
            .issuer_sig_r
            .copy_from_slice(&self_sig.r().to_bytes());
        circuit
            .issuer_sig_s
            .copy_from_slice(&self_sig.s().to_bytes());

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Self-signed credential must fail");
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Self-signed credential rejected: true (failing constraint: {})",
            failing
        );
        assert!(
            failing.contains("issuer_ecdsa"),
            "Must fail in issuer_ecdsa namespace"
        );
    }

    #[test]
    fn test_presentation_rejects_tampered_credential_byte() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _trusted_issuer_sk) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Attacker tampers with one byte in the credential (e.g. flips 1 bit in posture)
        // This causes the SHA-256 compression chain to produce a different H4 digest,
        // while all facts and predicates in Section 1 still pass.
        let mut tampered_payload = [0u8; 192];
        for (i, w) in circuit.shared_vals[..48].iter().enumerate() {
            tampered_payload[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        tampered_payload[cred::OFF_POSTURE + 3] ^= 0x01; // flip 1 bit in posture!

        let (tampered_shared, _) = crate::step::build_shared(&tampered_payload);
        circuit.shared_vals = tampered_shared;
        // Keep issuer signature over ORIGINAL credential (so it's invalid for tampered H4)

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Trusted credential with one changed byte must fail"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Trusted credential with 1 changed byte rejected: true (failing constraint: {})",
            failing
        );
        assert!(
            failing.contains("issuer_ecdsa"),
            "Must fail in issuer_ecdsa namespace"
        );
    }

    #[test]
    fn test_presentation_rejects_software_secret_mismatch() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Prover uses a DIFFERENT secret not matching commitment
        circuit.software_secret[0] ^= 0x01;

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Secret mismatch must be rejected");
        println!("Mismatched software secret rejected: true");
    }

    #[test]
    fn test_presentation_rejects_tier_below_policy() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(2, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Verifier policy requires tier >= 3, credential is tier 2
        circuit.min_tier = 3;

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Tier below policy must be rejected");
        println!("Tier below policy rejected: true");
    }

    #[test]
    fn test_presentation_rejects_expired() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 2000, NOW - 1, 7, secret, binding);

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Expired credential must be rejected");
        println!("Expired credential rejected: true");
    }

    #[test]
    fn test_presentation_rejects_divergent_pseudonym_secret() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Attacker derives commitment with s, but computes pseudonym with s' != s
        let mut s_other = secret;
        s_other[0] ^= 0x01;
        circuit.witness_s_override = Some(s_other);

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Divergent pseudonym secret must be rejected"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Divergent pseudonym secret rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("p_svc_x_match") || failing.contains("p_svc_y_match"));
    }

    #[test]
    fn test_presentation_rejects_changed_commitment_with_original_secret() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Attacker alters commitment bytes in shared_vals
        circuit.shared_vals[cred::OFF_SECRET_COMMIT / 4] ^= 0x01;

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Changed commitment with original secret must fail"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Changed commitment rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("commit_x_match") || failing.contains("commit_y_match"));
    }

    #[test]
    fn test_presentation_rejects_arbitrary_pseudonym_witness() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Attacker supplies a forged arbitrary pseudonym point
        circuit.p_svc_override = Some(([0xAAu8; 32], [0xBBu8; 32]));

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Arbitrary pseudonym witness must be rejected"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Arbitrary pseudonym rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("p_svc_x_match") || failing.contains("p_svc_y_match"));
    }

    #[test]
    fn test_commitment_rejects_zero_secret() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0u8; 32]; // s = 0
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, [0x42u8; 32], binding);
        circuit.software_secret = secret;

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Secret s = 0 must be rejected");
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Secret s = 0 rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("sec_s != 0") || failing.contains("commit_x_match"));
    }

    #[test]
    fn test_commitment_rejects_secret_ge_order_n() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        // P-256 group order n in big-endian:
        // FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
        let secret_ge_n = [0xFFu8; 32]; // > n
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, [0x42u8; 32], binding);
        circuit.software_secret = secret_ge_n;

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Secret s >= n must be rejected");
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Secret s >= n rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("sec_s < n") || failing.contains("commit_x_match"));
    }

    #[test]
    fn test_commitment_rejects_noncanonical_commitment_coordinate() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Put noncanonical Cx >= p (e.g. all 1s in big-endian: 0xFFFFFFFF... > p)
        for w in 0..8 {
            circuit.shared_vals[cred::OFF_SECRET_COMMIT / 4 + w] = 0xFFFF_FFFF;
        }

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Noncanonical Cx >= p must be rejected");
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Noncanonical Cx >= p rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("commit_x < p") || failing.contains("commit_x_match"));
    }

    #[test]
    fn test_presentation_rejects_tampered_commitment_payload_byte_via_step_chain() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Tamper with serialized commitment bytes in shared_vals without recomputing hash chain:
        let mut tampered_shared = circuit.shared_vals.clone();
        tampered_shared[cred::OFF_SECRET_COMMIT / 4] ^= 0x01; // flip 1 bit in Cx!
                                                              // Note: tampered_shared[64..104] still contains original H0..H4 states!

        // Step 1 processes block 1 (shared words 16..32), which contains words 22..30 (Cx).
        let step1 = crate::step::CredentialStepCircuit {
            step_idx: 1,
            shared_vals: tampered_shared.clone(),
        };

        let mut cs_step = TestConstraintSystem::<Fq>::new();
        let sh_step = VegaCircuit::<T256HyraxEngine>::shared(&step1, &mut cs_step).unwrap();
        let pre_step =
            VegaCircuit::<T256HyraxEngine>::precommitted(&step1, &mut cs_step, &sh_step).unwrap();
        VegaCircuit::<T256HyraxEngine>::synthesize(&step1, &mut cs_step, &sh_step, &pre_step, None)
            .unwrap();

        assert!(
            !cs_step.is_satisfied(),
            "Step circuit must reject tampered commitment word"
        );
        let failing_step = cs_step.which_is_unsatisfied().unwrap();
        println!(
            "Tampered commitment byte rejected by SHA-256 step chain: true (failing constraint namespace: {})",
            failing_step
        );
        assert!(
            failing_step.contains("check_out_state"),
            "Must fail in check_out_state namespace"
        );
    }

    #[test]
    fn test_pseudonym_rejects_substituted_service_base() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Prover attempts to substitute an off-curve base point
        circuit.p_base_override = Some(([0x11u8; 32], [0x22u8; 32]));

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Off-curve base point must be rejected");
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Off-curve base point rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("pbase_on_curve"));
    }

    #[test]
    fn test_pseudonym_deterministic_for_fixed_secret_and_service() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (circuit1, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);
        let (circuit2, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        let p1 = circuit1.service_pseudonym_point();
        let p2 = circuit2.service_pseudonym_point();
        assert_eq!(
            p1, p2,
            "Pseudonyms for same secret and service must be byte-identical"
        );

        // Distinct service identifier produces distinct pseudonym:
        let mut circuit_other_svc = circuit1.clone();
        circuit_other_svc.service_id = b"banking.example".to_vec();
        let p3 = circuit_other_svc.service_pseudonym_point();
        assert_ne!(p1, p3, "Pseudonyms for different services must be distinct");
    }

    #[test]
    fn test_complete_presentation_proof_10_iteration_benchmark() {
        println!("\n===============================================================");
        println!("=== 10-ITERATION BENCHMARK: COMPLETE PRESENTATION PROTOCOL ===");
        println!("=== (REAL CREDENTIAL STEP CIRCUITS 0..4 + CORE CIRCUIT)     ===");
        println!("===============================================================");

        let binding = zkpc_core::binding::binding_hash(
            b"bench_nonce_2026",
            b"vpn.example",
            b"policy_prod_v1",
        );
        let secret = [0x55u8; 32];
        let (circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        let shared_words = circuit.words().unwrap();
        let step_proto = crate::step::CredentialStepCircuit::default();
        let core_proto = circuit.clone();
        let steps: Vec<crate::step::CredentialStepCircuit> = (0..4)
            .map(|i| crate::step::CredentialStepCircuit {
                step_idx: i,
                shared_vals: shared_words.clone(),
            })
            .collect();

        // 1. Setup
        let t_setup = Instant::now();
        let (pk, vk) =
            VegaMcZkSNARK::<T256HyraxEngine>::setup(&step_proto, &core_proto, steps.len())
                .expect("Presentation SNARK setup");
        let setup_duration = t_setup.elapsed();
        println!("Setup Time: {:?}", setup_duration);

        let prep = VegaMcZkSNARK::<T256HyraxEngine>::prep_prove(&pk, &steps, &circuit, false)
            .expect("prep_prove");

        let mut prove_times: Vec<f64> = Vec::with_capacity(10);
        let mut verify_times: Vec<f64> = Vec::with_capacity(10);
        let mut last_proof_bytes_len = 0;

        for run in 0..10 {
            let t_prove = Instant::now();
            let (proof, _) =
                VegaMcZkSNARK::<T256HyraxEngine>::prove(&pk, &steps, &circuit, prep.clone(), false)
                    .expect("prove");
            let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;
            prove_times.push(prove_ms);

            let proof_bytes = bincode::serialize(&proof).expect("serialize");
            last_proof_bytes_len = proof_bytes.len();

            let t_verify = Instant::now();
            let res = proof.verify(&vk, steps.len());
            let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
            verify_times.push(verify_ms);

            assert!(res.is_ok(), "Verification failed on run {}", run + 1);
            println!(
                "  Run {:>2}/10: prove = {:>7.2} ms, verify = {:>6.2} ms",
                run + 1,
                prove_ms,
                verify_ms
            );
        }

        prove_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        verify_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let min_prove = prove_times[0];
        let max_prove = prove_times[9];
        let median_prove = (prove_times[4] + prove_times[5]) / 2.0;
        let mean_prove: f64 = prove_times.iter().sum::<f64>() / 10.0;
        let variance_prove: f64 = prove_times
            .iter()
            .map(|t| (t - mean_prove).powi(2))
            .sum::<f64>()
            / 10.0;
        let std_dev_prove = variance_prove.sqrt();

        let min_verify = verify_times[0];
        let max_verify = verify_times[9];
        let median_verify = (verify_times[4] + verify_times[5]) / 2.0;

        println!("\n--- COMPLETE PRESENTATION BENCHMARK SUMMARY (10 RUNS) ---");
        println!("Prover Time Median:   {:.2} ms", median_prove);
        println!("Prover Time Min:      {:.2} ms", min_prove);
        println!("Prover Time Max:      {:.2} ms", max_prove);
        println!("Prover Time Spread (StdDev): ±{:.2} ms", std_dev_prove);
        println!(
            "Verifier Time Median: {:.2} ms (min: {:.2} ms, max: {:.2} ms)",
            median_verify, min_verify, max_verify
        );
        println!(
            "Proof Size:           {} bytes ({:.2} KB)",
            last_proof_bytes_len,
            (last_proof_bytes_len as f64) / 1024.0
        );
        println!("Setup Time:           {:?}", setup_duration);
        println!("===============================================================\n");
    }

    #[test]
    fn test_commitment_rejects_noncanonical_cy() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Put noncanonical Cy >= p (e.g. all 1s in big-endian: 0xFFFFFFFF... > p)
        for w in 0..8 {
            circuit.shared_vals[cred::OFF_SECRET_COMMIT / 4 + 8 + w] = 0xFFFF_FFFF;
        }

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Noncanonical Cy >= p must be rejected");
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Noncanonical Cy >= p rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("commit_y < p") || failing.contains("commit_y_match"));
    }

    #[test]
    fn test_commitment_rejects_off_curve_commitment() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Perturb Cy so that (Cx, Cy) is not on curve P-256
        circuit.shared_vals[cred::OFF_SECRET_COMMIT / 4 + 8] ^= 0x02;

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(!cs.is_satisfied(), "Off-curve commitment point must fail");
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Off-curve commitment rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("commit_y_match"));
    }

    #[test]
    fn test_presentation_rejects_tampered_psvc_y_match() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        let (sx, mut sy) = circuit.service_pseudonym_point();
        // Keep correct sx, but tamper sy
        sy[31] ^= 0x01;
        circuit.p_svc_override = Some((sx, sy));

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Tampered p_svc_y must be rejected by p_svc_y_match"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Tampered p_svc_y rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("p_svc_y_match"));
    }

    #[test]
    fn test_commitment_rejects_identity_encoding() {
        let binding = zkpc_core::binding::binding_hash(b"nonce123", b"vpn.example", b"policy456");
        let secret = [0x42u8; 32];
        let (mut circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 1000, NOW + 1000, 7, secret, binding);

        // Attacker sets commitment coordinates in shared_vals to identity encoding (0, 0)
        for w in 0..16 {
            circuit.shared_vals[cred::OFF_SECRET_COMMIT / 4 + w] = 0;
        }

        let mut cs = TestConstraintSystem::<Fq>::new();
        let sh = VegaCircuit::<T256HyraxEngine>::shared(&circuit, &mut cs).unwrap();
        let pre = VegaCircuit::<T256HyraxEngine>::precommitted(&circuit, &mut cs, &sh).unwrap();
        let _ = VegaCircuit::<T256HyraxEngine>::synthesize(&circuit, &mut cs, &sh, &pre, None);

        assert!(
            !cs.is_satisfied(),
            "Identity commitment (0, 0) must be rejected"
        );
        let failing = cs.which_is_unsatisfied().unwrap();
        println!(
            "Identity commitment (0, 0) rejected: true (failing constraint: {})",
            failing
        );
        assert!(failing.contains("commit_x_match") || failing.contains("commit_y_match"));
    }

    struct FixedClock(u64);
    impl zkpc_verifier::Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    #[test]
    fn test_real_v2_presentation_proof_end_to_end_through_verifier() {
        use std::collections::{BTreeMap, BTreeSet};
        use zkpc_verifier::{InMemoryNonceStore, Policy, Verifier, VerifyError};

        let now = NOW;
        let service_id = b"vpn.example".to_vec();
        let secret = [0x42u8; 32];

        // 1. Generate hardware and issuer signing keys
        let hw_sk = SigningKey::random(&mut OsRng);
        let issuer_sk = SigningKey::random(&mut OsRng);
        let issuer_vk = issuer_sk.verifying_key();
        let issuer_pt = issuer_vk.to_encoded_point(false);
        let mut issuer_pk_x = [0u8; 32];
        let mut issuer_pk_y = [0u8; 32];
        issuer_pk_x.copy_from_slice(&issuer_pt.x().unwrap()[..]);
        issuer_pk_y.copy_from_slice(&issuer_pt.y().unwrap()[..]);

        // 2. Setup verifier with policy pinning the issuer public key coordinates
        let mut trusted_keys = BTreeSet::new();
        trusted_keys.insert(KEY);

        let mut trusted_coords = BTreeMap::new();
        trusted_coords.insert(KEY, (issuer_pk_x, issuer_pk_y));

        let policy = Policy {
            min_tier: 3,
            min_epoch: 7,
            trusted_issuer_keys: trusted_keys,
            trusted_issuer_coords: trusted_coords,
            max_skew_secs: 60,
            challenge_ttl_secs: 120,
            quantize_secs: 0,
        };

        // 3. Setup Vega SNARK prover and verifier keys
        let proto_circuit = build_test_credential_with_keys(
            3,
            now,
            now - 1000,
            now + 1000,
            7,
            secret,
            [0u8; 32],
            service_id.clone(),
            &hw_sk,
            &issuer_sk,
        );
        let step_proto = crate::step::CredentialStepCircuit::default();
        let (pk, vk) =
            VegaMcZkSNARK::<T256HyraxEngine>::setup(&step_proto, &proto_circuit, 4).unwrap();

        let verifier = Verifier::new(
            service_id.clone(),
            policy,
            Box::new(FixedClock(now as u64)),
            Box::new(InMemoryNonceStore::default()),
            Box::new(crate::backend::VegaBackend::new(vk, 4)),
        );

        // 4. Verifier issues a fresh challenge
        let fresh_ch = verifier.issue_challenge();
        let fresh_b_hash = zkpc_core::binding::binding_hash(
            &fresh_ch.nonce,
            &fresh_ch.service_id,
            &fresh_ch.policy_hash,
        );

        // 5. Prover constructs presentation circuit and hardware signature bound to fresh challenge
        let circuit = build_test_credential_with_keys(
            3,
            now,
            now - 1000,
            now + 1000,
            7,
            secret,
            fresh_b_hash,
            fresh_ch.service_id.clone(),
            &hw_sk,
            &issuer_sk,
        );

        // 6. Build 4 real CredentialStepCircuit steps
        let steps: Vec<crate::step::CredentialStepCircuit> = (0..4)
            .map(|i| crate::step::CredentialStepCircuit {
                step_idx: i,
                shared_vals: circuit.shared_vals.clone(),
            })
            .collect();

        // 7. Generate real Vega SNARK proof
        let prep =
            VegaMcZkSNARK::<T256HyraxEngine>::prep_prove(&pk, &steps, &circuit, false).unwrap();
        let (proof, _) =
            VegaMcZkSNARK::<T256HyraxEngine>::prove(&pk, &steps, &circuit, prep, false).unwrap();
        let proof_bytes = bincode::serialize(&proof).unwrap();

        // 8. Verifier verifies the REAL proof bytes end-to-end
        let res = verifier.verify_presentation(&fresh_ch.nonce, &proof_bytes);
        assert!(
            res.is_ok(),
            "Real V2 proof must be accepted by verifier: {:?}",
            res
        );
        let accepted = res.unwrap();
        assert_eq!(accepted.tier, 3);
        assert_eq!(accepted.issuer_key_id, KEY);
        assert!(accepted.pseudonym.is_some());
        assert!(accepted.pseudonym_point.is_some());
        println!("Real V2 presentation proof verified end-to-end through Verifier: OK");

        // 9. Replay check: second attempt with same nonce must be rejected
        let res_replay = verifier.verify_presentation(&fresh_ch.nonce, &proof_bytes);
        assert_eq!(res_replay, Err(VerifyError::UnknownOrReusedNonce));
        println!("Replay of real proof rejected: OK");

        // 10. Negative check A: Verifier rejects if proof was generated for a different service
        let ch_other_svc = verifier.issue_challenge();
        let b_other_hash = zkpc_core::binding::binding_hash(
            &ch_other_svc.nonce,
            b"other.example", // Mismatched service
            &ch_other_svc.policy_hash,
        );
        let circuit_other_svc = build_test_credential_with_keys(
            3,
            now,
            now - 1000,
            now + 1000,
            7,
            secret,
            b_other_hash,
            b"other.example".to_vec(),
            &hw_sk,
            &issuer_sk,
        );
        let steps_other_svc: Vec<crate::step::CredentialStepCircuit> = (0..4)
            .map(|i| crate::step::CredentialStepCircuit {
                step_idx: i,
                shared_vals: circuit_other_svc.shared_vals.clone(),
            })
            .collect();
        let prep_other_svc = VegaMcZkSNARK::<T256HyraxEngine>::prep_prove(
            &pk,
            &steps_other_svc,
            &circuit_other_svc,
            false,
        )
        .unwrap();
        let (proof_other_svc, _) = VegaMcZkSNARK::<T256HyraxEngine>::prove(
            &pk,
            &steps_other_svc,
            &circuit_other_svc,
            prep_other_svc,
            false,
        )
        .unwrap();
        let proof_other_svc_bytes = bincode::serialize(&proof_other_svc).unwrap();

        let res_wrong_svc =
            verifier.verify_presentation(&ch_other_svc.nonce, &proof_other_svc_bytes);
        assert_eq!(res_wrong_svc, Err(VerifyError::ServiceBaseMismatch));
        println!("Real proof with mismatched service rejected at verifier boundary: OK");

        // 11. Negative check B: Verifier rejects if proof binding was forged / altered
        let ch_altered_bind = verifier.issue_challenge();
        let b_altered_hash = zkpc_core::binding::binding_hash(
            b"tampered_nonce_value___________",
            &ch_altered_bind.service_id,
            &ch_altered_bind.policy_hash,
        );
        let circuit_altered = build_test_credential_with_keys(
            3,
            now,
            now - 1000,
            now + 1000,
            7,
            secret,
            b_altered_hash,
            ch_altered_bind.service_id.clone(),
            &hw_sk,
            &issuer_sk,
        );
        let steps_altered: Vec<crate::step::CredentialStepCircuit> = (0..4)
            .map(|i| crate::step::CredentialStepCircuit {
                step_idx: i,
                shared_vals: circuit_altered.shared_vals.clone(),
            })
            .collect();
        let prep_altered = VegaMcZkSNARK::<T256HyraxEngine>::prep_prove(
            &pk,
            &steps_altered,
            &circuit_altered,
            false,
        )
        .unwrap();
        let (proof_altered, _) = VegaMcZkSNARK::<T256HyraxEngine>::prove(
            &pk,
            &steps_altered,
            &circuit_altered,
            prep_altered,
            false,
        )
        .unwrap();
        let proof_altered_bytes = bincode::serialize(&proof_altered).unwrap();

        let res_wrong_bind =
            verifier.verify_presentation(&ch_altered_bind.nonce, &proof_altered_bytes);
        assert_eq!(res_wrong_bind, Err(VerifyError::BindingMismatch));
        println!("Real proof with mismatched binding rejected at verifier boundary: OK");

        // 12. Negative check C: Verifier rejects if proof was generated using an untrusted issuer key
        // Attacker presents with matching key ID (KEY), but signed with an untrusted rogue issuer key
        let rogue_issuer_sk = SigningKey::random(&mut OsRng);
        let ch_rogue = verifier.issue_challenge();
        let b_rogue_hash = zkpc_core::binding::binding_hash(
            &ch_rogue.nonce,
            &ch_rogue.service_id,
            &ch_rogue.policy_hash,
        );
        let circuit_rogue = build_test_credential_with_keys(
            3,
            now,
            now - 1000,
            now + 1000,
            7,
            secret,
            b_rogue_hash,
            ch_rogue.service_id.clone(),
            &hw_sk,
            &rogue_issuer_sk,
        );
        let steps_rogue: Vec<crate::step::CredentialStepCircuit> = (0..4)
            .map(|i| crate::step::CredentialStepCircuit {
                step_idx: i,
                shared_vals: circuit_rogue.shared_vals.clone(),
            })
            .collect();
        let prep_rogue =
            VegaMcZkSNARK::<T256HyraxEngine>::prep_prove(&pk, &steps_rogue, &circuit_rogue, false)
                .unwrap();
        let (proof_rogue, _) = VegaMcZkSNARK::<T256HyraxEngine>::prove(
            &pk,
            &steps_rogue,
            &circuit_rogue,
            prep_rogue,
            false,
        )
        .unwrap();
        let proof_rogue_bytes = bincode::serialize(&proof_rogue).unwrap();

        let res_rogue = verifier.verify_presentation(&ch_rogue.nonce, &proof_rogue_bytes);
        assert_eq!(res_rogue, Err(VerifyError::UntrustedIssuerKey(KEY)));
        println!(
            "Real proof with untrusted issuer key coordinates rejected at verifier boundary: OK"
        );

        // 13. Negative check D: Real proof with tampered payload byte in step chain fails proving or verification
        let mut tampered_shared = circuit.shared_vals.clone();
        tampered_shared[cred::OFF_SECRET_COMMIT / 4] ^= 0x01; // flip bit in Cx!
        let steps_tampered: Vec<crate::step::CredentialStepCircuit> = (0..4)
            .map(|i| crate::step::CredentialStepCircuit {
                step_idx: i,
                shared_vals: tampered_shared.clone(),
            })
            .collect();
        let mut circuit_tampered = circuit.clone();
        circuit_tampered.shared_vals = tampered_shared;
        let ch_tampered = verifier.issue_challenge();
        let b_tampered_hash = zkpc_core::binding::binding_hash(
            &ch_tampered.nonce,
            &ch_tampered.service_id,
            &ch_tampered.policy_hash,
        );
        circuit_tampered.binding = b_tampered_hash;
        let tampered_rejected = match VegaMcZkSNARK::<T256HyraxEngine>::prep_prove(
            &pk,
            &steps_tampered,
            &circuit_tampered,
            false,
        ) {
            Err(_) => true,
            Ok(prep) => {
                match VegaMcZkSNARK::<T256HyraxEngine>::prove(
                    &pk,
                    &steps_tampered,
                    &circuit_tampered,
                    prep,
                    false,
                ) {
                    Err(_) => true,
                    Ok((proof_tampered, _)) => {
                        let proof_bytes = bincode::serialize(&proof_tampered).unwrap();
                        verifier
                            .verify_presentation(&ch_tampered.nonce, &proof_bytes)
                            .is_err()
                    }
                }
            }
        };
        assert!(
            tampered_rejected,
            "Real proof with tampered payload byte must fail to prove or verify"
        );
        println!("Real proof with tampered payload byte rejected (fails prove or verify): OK");
    }

    #[test]
    fn test_guard_identical_presentation_shared() {
        let (circuit, _, _) =
            build_test_credential_and_sig(3, NOW - 100, NOW + 100, 7, [0x42u8; 32], [0u8; 32]);
        let steps: Vec<crate::step::CredentialStepCircuit> = (0..4)
            .map(|i| crate::step::CredentialStepCircuit {
                step_idx: i,
                shared_vals: circuit.shared_vals.clone(),
            })
            .collect();

        // 1. Matching shared_vals passes guard
        assert!(guard_identical_presentation_shared(&steps, &circuit).is_ok());

        // 2. Diverged shared_vals in one step circuit fails guard
        let mut steps_diverged = steps.clone();
        steps_diverged[0].shared_vals[0] ^= 1;
        assert!(matches!(
            guard_identical_presentation_shared(&steps_diverged, &circuit),
            Err(SynthesisError::Unsatisfiable)
        ));

        // 3. Empty steps fails guard
        assert!(matches!(
            guard_identical_presentation_shared(&[], &circuit),
            Err(SynthesisError::AssignmentMissing)
        ));
    }
}
