use bellpepper::gadgets::{sha256::sha256_compression_function, uint32::UInt32};
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use vega_prover::traits::circuit::VegaCircuit;
use vega_prover::traits::Engine;

#[derive(Clone)]
pub struct DirectHashBaseline {
    pub credential: Vec<u8>,
}

impl Default for DirectHashBaseline {
    fn default() -> Self {
        Self {
            credential: vec![0u8; 256],
        }
    }
}

impl<E: Engine> VegaCircuit<E> for DirectHashBaseline {
    fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
        Ok(vec![])
    }

    fn shared<CS: ConstraintSystem<E::Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        Ok(vec![])
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
        _shared: &[AllocatedNum<E::Scalar>],
        _precommitted: &[AllocatedNum<E::Scalar>],
        _challenges: Option<&[E::Scalar]>,
    ) -> Result<(), SynthesisError> {
        let iv = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let mut current_hash = vec![];
        for val in iv.iter() {
            current_hash.push(UInt32::constant(*val));
        }

        assert_eq!(self.credential.len(), 256, "Credential must be 256 bytes");

        for block_idx in 0..4 {
            let mut input_bits = vec![];
            for byte_idx in 0..64 {
                let byte = self.credential[block_idx * 64 + byte_idx];
                for bit_idx in (0..8).rev() {
                    let bit = (byte >> bit_idx) & 1 == 1;
                    let alloc_bit = AllocatedBit::alloc(
                        cs.namespace(|| format!("bit_{}_{}_{}", block_idx, byte_idx, bit_idx)),
                        Some(bit),
                    )?;
                    input_bits.push(Boolean::Is(alloc_bit));
                }
            }

            current_hash = sha256_compression_function(
                cs.namespace(|| format!("sha256_block_{}", block_idx)),
                &input_bits,
                &current_hash,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use vega_prover::provider::T256HyraxEngine;
    use vega_prover::traits::snark::R1CSSNARKTrait;
    use vega_prover::vega_sc_zkp::VegaZkSNARK as VegaScZkSNARK;

    #[test]
    fn test_direct_hash_baseline() {
        let cred = vec![0u8; 256];
        let circuit = DirectHashBaseline { credential: cred };

        type E = T256HyraxEngine;
        type S = VegaScZkSNARK<E>;
        type Scalar = <E as Engine>::Scalar;

        let mut cs = TestConstraintSystem::<Scalar>::new();
        <DirectHashBaseline as VegaCircuit<E>>::synthesize(&circuit, &mut cs, &[], &[], None)
            .unwrap();
        println!("Total constraint count: {}", cs.num_constraints());
        assert!(cs.is_satisfied());

        let (pk, vk) = S::setup(circuit.clone()).unwrap();
        let prep_snark = S::prep_prove(&pk, circuit.clone(), false).unwrap();

        let res = S::prove(&pk, circuit.clone(), prep_snark, false);
        assert!(res.is_ok());
        let (snark, _) = res.unwrap();

        let res = snark.verify(&vk);
        assert!(res.is_ok());
    }
}
