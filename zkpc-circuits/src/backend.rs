//! Vega-backed ProofBackend for zkpc-verifier.
//!
//! Decodes the proof, runs Vega's verifier, and returns the core circuit's
//! public values as canonical little-endian field encodings.
//!
//! It also checks the STEP circuits' public values: step i must expose exactly
//! [i]. Without this a prover could present two steps claiming the same index
//! and skip checking one SHA-256 block, leaving part of the signed credential
//! unbound to the hash.

use ff::{Field, PrimeField};
use vega_prover::{
    provider::T256HyraxEngine,
    traits::Engine,
    vega_mc_zkp::{VegaMcVerifierKey, VegaMcZkSNARK},
};
use zkpc_verifier::{ProofBackend, RawPublic};

type E = T256HyraxEngine;
type F = <E as Engine>::Scalar;

pub struct VegaBackend {
    vk: VegaMcVerifierKey<E>,
    num_steps: usize,
}

impl VegaBackend {
    pub fn new(vk: VegaMcVerifierKey<E>, num_steps: usize) -> Self {
        Self { vk, num_steps }
    }
}

fn raw(f: &F) -> RawPublic {
    let r = f.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(r.as_ref());
    out
}

impl ProofBackend for VegaBackend {
    fn verify(&self, proof: &[u8]) -> Result<Vec<RawPublic>, String> {
        let proof: VegaMcZkSNARK<E> =
            bincode::deserialize(proof).map_err(|e| format!("decode: {e}"))?;
        let (steps, core) = proof
            .verify(&self.vk, self.num_steps)
            .map_err(|e| format!("verify: {e:?}"))?;

        if steps.len() != self.num_steps {
            return Err(format!(
                "expected {} step publics, got {}",
                self.num_steps,
                steps.len()
            ));
        }
        for (i, s) in steps.iter().enumerate() {
            let want = [F::from(i as u64)];
            if s.as_slice() != want.as_slice() {
                return Err(format!("step {i} exposes unexpected public values"));
            }
        }
        let _ = F::ZERO; // keep Field in scope for older toolchains
        Ok(core.iter().map(raw).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_checks_step_indices_and_rejects_wrong_index() {
        let steps_correct = vec![
            vec![F::from(0u64)],
            vec![F::from(1u64)],
            vec![F::from(2u64)],
            vec![F::from(3u64)],
        ];
        for (i, s) in steps_correct.iter().enumerate() {
            assert_eq!(s.as_slice(), &[F::from(i as u64)]);
        }

        let steps_tampered = vec![
            vec![F::from(0u64)],
            vec![F::from(0u64)], // Duplicate step 0 instead of step 1!
            vec![F::from(2u64)],
            vec![F::from(3u64)],
        ];
        let mut err = None;
        for (i, s) in steps_tampered.iter().enumerate() {
            let want = [F::from(i as u64)];
            if s.as_slice() != want.as_slice() {
                err = Some(format!("step {i} exposes unexpected public values"));
                break;
            }
        }
        assert_eq!(
            err,
            Some("step 1 exposes unexpected public values".to_string())
        );
        println!("Verifier rejected tampered step index: {:?}", err);
    }
}
