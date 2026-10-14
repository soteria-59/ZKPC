use bellpepper::gadgets::{sha256::sha256_compression_function, uint32::UInt32};
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::{Field, PrimeField};
use vega_prover::traits::{circuit::VegaCircuit, Engine};

pub fn decompose_32<E: Engine, CS: ConstraintSystem<E::Scalar>>(
    mut cs: CS,
    val: &AllocatedNum<E::Scalar>,
) -> Result<Vec<Boolean>, SynthesisError> {
    let mut bits = vec![];
    let val_val = val.get_value();

    let val_u64 = val_val.map(|v| {
        let repr = v.to_repr();
        let bytes = repr.as_ref();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[0..8]);
        u64::from_le_bytes(arr)
    });

    let mut lc = LinearCombination::zero();
    let mut coeff = E::Scalar::from(1u64);

    for i in 0..32 {
        let bit_val = val_u64.map(|v| ((v >> i) & 1) == 1);
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("bit_{}", i)), bit_val)?;
        bits.push(Boolean::Is(bit.clone()));
        lc = lc + (coeff, bit.get_variable());
        coeff = coeff.double();
    }

    cs.enforce(
        || "check_decompose",
        |lc| lc + val.get_variable(),
        |lc| lc + CS::one(),
        |_| lc,
    );

    Ok(bits)
}

fn multiplex_4<E: Engine, CS: ConstraintSystem<E::Scalar>>(
    mut cs: CS,
    s: &[AllocatedNum<E::Scalar>; 4],
    x: &[AllocatedNum<E::Scalar>; 4],
) -> Result<AllocatedNum<E::Scalar>, SynthesisError> {
    let tmp1 = AllocatedNum::alloc(cs.namespace(|| "tmp1"), || {
        let s1 = s[1].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let x1 = x[1].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let x0 = x[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(s1 * (x1 - x0))
    })?;
    cs.enforce(
        || "tmp1_calc",
        |lc| lc + s[1].get_variable(),
        |lc| lc + x[1].get_variable() - x[0].get_variable(),
        |lc| lc + tmp1.get_variable(),
    );

    let tmp2 = AllocatedNum::alloc(cs.namespace(|| "tmp2"), || {
        let s2 = s[2].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let x2 = x[2].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let x0 = x[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(s2 * (x2 - x0))
    })?;
    cs.enforce(
        || "tmp2_calc",
        |lc| lc + s[2].get_variable(),
        |lc| lc + x[2].get_variable() - x[0].get_variable(),
        |lc| lc + tmp2.get_variable(),
    );

    let tmp3 = AllocatedNum::alloc(cs.namespace(|| "tmp3"), || {
        let s3 = s[3].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let x3 = x[3].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let x0 = x[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(s3 * (x3 - x0))
    })?;
    cs.enforce(
        || "tmp3_calc",
        |lc| lc + s[3].get_variable(),
        |lc| lc + x[3].get_variable() - x[0].get_variable(),
        |lc| lc + tmp3.get_variable(),
    );

    let v = AllocatedNum::alloc(cs.namespace(|| "v"), || {
        let x0 = x[0].get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let t1 = tmp1.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let t2 = tmp2.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        let t3 = tmp3.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        Ok(x0 + t1 + t2 + t3)
    })?;
    cs.enforce(
        || "v_calc",
        |lc| lc + CS::one(),
        |lc| {
            lc + x[0].get_variable()
                + tmp1.get_variable()
                + tmp2.get_variable()
                + tmp3.get_variable()
        },
        |lc| lc + v.get_variable(),
    );

    Ok(v)
}

#[derive(Clone, Default)]
pub struct CredentialStepCircuit {
    pub step_idx: usize,
    pub shared_vals: Vec<u32>, // expected 104 words
}

impl<E: Engine> VegaCircuit<E> for CredentialStepCircuit {
    fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
        Ok(vec![E::Scalar::from(self.step_idx as u64)])
    }

    fn shared<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        let mut shared = Vec::with_capacity(104);
        let vals = if self.shared_vals.is_empty() {
            vec![0u32; 104]
        } else {
            self.shared_vals.clone()
        };
        for (i, v) in vals.iter().enumerate() {
            let num = AllocatedNum::alloc(cs.namespace(|| format!("shared_{}", i)), || {
                Ok(E::Scalar::from(*v as u64))
            })?;
            shared.push(num);
        }
        Ok(shared)
    }

    fn precommitted<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<E::Scalar>],
    ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
        let mut selector = Vec::new();
        for i in 0..4 {
            let is_active = (self.step_idx == i) as u64;
            let bit = AllocatedNum::alloc(cs.namespace(|| format!("sel_{}", i)), || {
                Ok(E::Scalar::from(is_active))
            })?;
            selector.push(bit);
        }
        Ok(selector)
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<E::Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<E::Scalar>],
        precommitted: &[AllocatedNum<E::Scalar>],
        _challenges: Option<&[E::Scalar]>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(shared.len(), 104);
        assert_eq!(precommitted.len(), 4);

        let mut sum_sel = LinearCombination::zero();
        let mut step_idx_lc = LinearCombination::zero();
        for i in 0..4 {
            let sel = &precommitted[i];
            cs.enforce(
                || format!("sel_bool_{}", i),
                |lc| lc + sel.get_variable(),
                |lc| lc + CS::one() - sel.get_variable(),
                |lc| lc,
            );
            sum_sel = sum_sel + sel.get_variable();

            let val = E::Scalar::from(i as u64);
            step_idx_lc = step_idx_lc + (val, sel.get_variable());
        }

        cs.enforce(
            || "sum_sel_is_1",
            |_lc| sum_sel,
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        let step_idx_var = AllocatedNum::alloc(cs.namespace(|| "step_idx"), || {
            Ok(E::Scalar::from(self.step_idx as u64))
        })?;
        cs.enforce(
            || "step_idx_match",
            |lc| lc + step_idx_var.get_variable(),
            |lc| lc + CS::one(),
            |_lc| step_idx_lc,
        );
        step_idx_var.inputize(cs.namespace(|| "inputize step_idx"))?;

        let sel: [AllocatedNum<E::Scalar>; 4] = [
            precommitted[0].clone(),
            precommitted[1].clone(),
            precommitted[2].clone(),
            precommitted[3].clone(),
        ];

        let mut block = Vec::with_capacity(16);
        for j in 0..16 {
            let opts = [
                shared[j].clone(),
                shared[16 + j].clone(),
                shared[32 + j].clone(),
                shared[48 + j].clone(),
            ];
            let v = multiplex_4::<E, _>(cs.namespace(|| format!("mux_block_{}", j)), &sel, &opts)?;
            block.push(v);
        }

        let mut in_state = Vec::with_capacity(8);
        for j in 0..8 {
            let opts = [
                shared[64 + j].clone(),
                shared[64 + 8 + j].clone(),
                shared[64 + 16 + j].clone(),
                shared[64 + 24 + j].clone(),
            ];
            let v =
                multiplex_4::<E, _>(cs.namespace(|| format!("mux_in_state_{}", j)), &sel, &opts)?;
            in_state.push(v);
        }

        let mut input_bits = vec![];
        for j in 0..16 {
            let bits =
                decompose_32::<E, _>(cs.namespace(|| format!("decomp_block_{}", j)), &block[j])?;
            for bit in bits.into_iter().rev() {
                input_bits.push(bit);
            }
        }

        let mut current_hash = vec![];
        for j in 0..8 {
            let bits = decompose_32::<E, _>(
                cs.namespace(|| format!("decomp_in_state_{}", j)),
                &in_state[j],
            )?;
            let mut msb_first = vec![];
            for bit in bits.into_iter().rev() {
                msb_first.push(bit);
            }
            current_hash.push(UInt32::from_bits_be(&msb_first));
        }

        let out_hash = sha256_compression_function(
            cs.namespace(|| "sha256_compress"),
            &input_bits,
            &current_hash,
        )?;

        for j in 0..8 {
            let opts = [
                shared[64 + 8 + j].clone(),
                shared[64 + 16 + j].clone(),
                shared[64 + 24 + j].clone(),
                shared[64 + 32 + j].clone(),
            ];
            let expected_out =
                multiplex_4::<E, _>(cs.namespace(|| format!("mux_out_state_{}", j)), &sel, &opts)?;

            let out_bits = out_hash[j].clone().into_bits_be();
            let mut lc = LinearCombination::zero();
            let mut coeff = E::Scalar::from(1u64);

            for bit in out_bits.into_iter().rev() {
                match bit {
                    Boolean::Is(ref b) => {
                        lc = lc + (coeff, b.get_variable());
                    }
                    Boolean::Not(ref b) => {
                        lc = lc + (coeff, CS::one()) - (coeff, b.get_variable());
                    }
                    Boolean::Constant(b) => {
                        if b {
                            lc = lc + (coeff, CS::one());
                        }
                    }
                }
                coeff = coeff.double();
            }

            cs.enforce(
                || format!("check_out_state_{}", j),
                |lc| lc + expected_out.get_variable(),
                |lc| lc + CS::one(),
                |_| lc,
            );
        }

        Ok(())
    }
}

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn compress(state: [u32; 8], block: &[u32; 16]) -> [u32; 8] {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(block);
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    let mut out = state;
    for (o, v) in out.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *o = o.wrapping_add(v);
    }
    out
}

pub fn build_shared(payload: &[u8; 192]) -> (Vec<u32>, [u32; 8]) {
    let mut msg = payload.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&1536u64.to_be_bytes());
    assert_eq!(msg.len(), 256);

    let words: Vec<u32> = msg
        .chunks(4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    assert_eq!(words.len(), 64);

    let mut states = vec![IV];
    for i in 0..4 {
        let mut blk = [0u32; 16];
        blk.copy_from_slice(&words[16 * i..16 * i + 16]);
        let next = compress(states[i], &blk);
        states.push(next);
    }

    let mut shared = words;
    for s in &states {
        shared.extend_from_slice(s);
    }
    assert_eq!(shared.len(), 104);
    (shared, states[4])
}
