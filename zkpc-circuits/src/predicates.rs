//! Range-style predicates on u32 values held in field elements.
//!
//! assert_u32_ge proves a >= b (or a > b when `strict`) by showing that
//! d = a - b (- 1 if strict) fits in 32 bits. If a < b the field subtraction
//! wraps to a number near the modulus, which has no 32-bit decomposition, so
//! the circuit is unsatisfiable. This is sound only if a and b are themselves
//! < 2^32: the caller must ensure that (range-checked words, or public values
//! the verifier checks).

use crate::step::decompose_32;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use vega_prover::traits::Engine;

pub fn assert_u32_ge<E: Engine, CS: ConstraintSystem<E::Scalar>>(
    mut cs: CS,
    a: &AllocatedNum<E::Scalar>,
    b: &AllocatedNum<E::Scalar>,
    strict: bool,
) -> Result<(), SynthesisError> {
    let d = AllocatedNum::alloc(cs.namespace(|| "diff"), || {
        let av = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let bv = b.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let mut v = av - bv;
        if strict {
            v -= E::Scalar::ONE;
        }
        Ok(v)
    })?;
    cs.enforce(
        || "diff_def",
        |lc| {
            let l = lc + a.get_variable() - b.get_variable();
            if strict {
                l - CS::one()
            } else {
                l
            }
        },
        |lc| lc + CS::one(),
        |lc| lc + d.get_variable(),
    );
    let _bits = decompose_32::<E, _>(cs.namespace(|| "range"), &d)?;
    Ok(())
}
