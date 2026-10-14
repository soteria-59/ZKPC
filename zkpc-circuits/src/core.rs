//! Core circuit: credential facts + presentation predicates.
//!
//! Public values, in this exact order (see zkpc_core::statement):
//!   0 tier (u8)            3 now (u32)             5 binding_hi (u128)
//!   1 issuer key id, hi    4 min_epoch (u32)       6 binding_lo (u128)
//!   2 issuer key id, lo
//!
//! Proved here (nothing exposes issued_at / expires_at / revocation epoch):
//!   * the tier byte and issuer key id come from the credential words,
//!   * issued_at <= now,  expires_at > now,  revocation_epoch >= min_epoch,
//!   * SHA-256 IV and padding words are pinned (as in the Phase 1 core).
//!
//! In the full presentation circuit, the hardware key signature over `binding`
//! is verified in-circuit, completing cryptographic device binding.
//!
//! Soundness note: the predicates assume the credential words are < 2^32. That
//! holds because the SHA step circuits decompose every payload word; it relies
//! on the shared words really being linked across steps (stage 1.5 test 4).

use crate::{predicates::assert_u32_ge, step::decompose_32};
use bellpepper_core::{
    boolean::Boolean, num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError,
    Variable,
};
use ff::PrimeField;
use vega_prover::traits::{circuit::VegaCircuit, Engine};
use zkpc_core::{binding::split_u128, credential as cred};

pub const NUM_WORDS: usize = 104;

#[derive(Clone, Default)]
pub struct CredentialCoreCircuit {
    /// 104 words (see Phase 1). Empty is allowed only for key-setup shape circuits.
    pub shared_vals: Vec<u32>,
    pub now: u32,
    pub min_epoch: u32,
    pub binding: [u8; 32],
}

pub fn u128_to_scalar<F: PrimeField>(x: u128) -> F {
    let two64 = F::from(u64::MAX) + F::ONE;
    F::from((x >> 64) as u64) * two64 + F::from(x as u64)
}

fn low_u32<F: PrimeField>(v: &F) -> u32 {
    let r = v.to_repr();
    let b = r.as_ref();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
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

impl CredentialCoreCircuit {
    fn words(&self) -> Result<Vec<u32>, SynthesisError> {
        match self.shared_vals.len() {
            0 => Ok(vec![0; NUM_WORDS]),
            NUM_WORDS => Ok(self.shared_vals.clone()),
            _ => Err(SynthesisError::Unsatisfiable),
        }
    }
}

impl<E: Engine> VegaCircuit<E> for CredentialCoreCircuit {
    fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
        let w = self.words()?;
        let tier = (w[cred::OFF_TIER / 4] >> ((3 - (cred::OFF_TIER % 4)) * 8)) & 0xFF;
        let k = cred::OFF_ISSUER_KEY_ID / 4;
        let (hi, lo) = split_u128(&self.binding);
        Ok(vec![
            E::Scalar::from(tier as u64),
            E::Scalar::from(w[k] as u64),
            E::Scalar::from(w[k + 1] as u64),
            E::Scalar::from(self.now as u64),
            E::Scalar::from(self.min_epoch as u64),
            u128_to_scalar::<E::Scalar>(hi),
            u128_to_scalar::<E::Scalar>(lo),
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

        // --- tier byte, taken from its word by bit slicing (bits are LSB first)
        let tier_word = &shared[cred::OFF_TIER / 4];
        let tier_bits = decompose_32::<E, _>(cs.namespace(|| "tier_word"), tier_word)?;
        let byte_lsb = 3 - (cred::OFF_TIER % 4); // 0 = least significant byte
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

        // --- credential facts
        let issued_at = &shared[cred::OFF_ISSUED_AT / 4];
        let expires_at = &shared[cred::OFF_EXPIRES_AT / 4];
        let rev_epoch = &shared[cred::OFF_REVOCATION_EPOCH / 4];
        let key_id_0 = &shared[cred::OFF_ISSUER_KEY_ID / 4];
        let key_id_1 = &shared[cred::OFF_ISSUER_KEY_ID / 4 + 1];

        // --- public parameters of this presentation
        let now_var = AllocatedNum::alloc(cs.namespace(|| "now"), || {
            Ok(E::Scalar::from(self.now as u64))
        })?;
        let min_epoch_var = AllocatedNum::alloc(cs.namespace(|| "min_epoch"), || {
            Ok(E::Scalar::from(self.min_epoch as u64))
        })?;
        let (hi, lo) = split_u128(&self.binding);
        let hi_var = AllocatedNum::alloc(cs.namespace(|| "binding_hi"), || {
            Ok(u128_to_scalar::<E::Scalar>(hi))
        })?;
        let lo_var = AllocatedNum::alloc(cs.namespace(|| "binding_lo"), || {
            Ok(u128_to_scalar::<E::Scalar>(lo))
        })?;

        // --- predicates (nothing about the raw timestamps is revealed)
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

        // --- public inputs: ORDER MUST MATCH public_values / zkpc_core::statement
        tier_var.inputize(cs.namespace(|| "pub tier"))?;
        key_id_0.inputize(cs.namespace(|| "pub key_id_0"))?;
        key_id_1.inputize(cs.namespace(|| "pub key_id_1"))?;
        now_var.inputize(cs.namespace(|| "pub now"))?;
        min_epoch_var.inputize(cs.namespace(|| "pub min_epoch"))?;
        hi_var.inputize(cs.namespace(|| "pub binding_hi"))?;
        lo_var.inputize(cs.namespace(|| "pub binding_lo"))?;

        // --- SHA-256 padding block and IV are fixed by the format
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
        Ok(())
    }
}
