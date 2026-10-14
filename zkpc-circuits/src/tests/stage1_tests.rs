//! Stage 1 tests for zkpc-circuits: `decompose_32`, the SHA-256 step circuit,
//! and the credential core circuit.
//!
//! WIRING (do this once):
//!   1. Save as  zkpc-circuits/src/stage1_tests.rs
//!   2. In zkpc-circuits/src/lib.rs add:   #[cfg(test)] mod stage1_tests;
//!   3. In zkpc-circuits/Cargo.toml add:   [dev-dependencies]  sha2 = "0.10"
//!   4. Run:  cargo test -p zkpc-circuits stage1 -- --nocapture
//!      (add --release if it is too slow; the flip tests synthesize ~260 circuits)
//!
//! NOT COMPILED BY THE AUTHOR. If a path or signature differs from your tree,
//! adjust the `use` lines. Do not weaken an assertion to make a test pass.
//!
//! Layout assumed (taken from the circuits as pasted):
//!   shared = 104 u32 words
//!     words   0..64  : 4 message blocks of 16 words (3 payload blocks + 1 padding block)
//!     words  64..104 : 5 chaining states of 8 words (state 0 = IV, state i+1 = compress(state i, block i))
//!   payload = 192 bytes (48 words); padding block = 0x80000000, zeros, 0x00000600 (1536 bits)

use crate::{
    core::CredentialCoreCircuit,
    step::{decompose_32, CredentialStepCircuit},
};
use bellpepper_core::{num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem};
use ff::PrimeField;
use sha2::{Digest, Sha256};
use vega_prover::{
    provider::T256HyraxEngine,
    traits::{circuit::VegaCircuit, Engine},
};

type E = T256HyraxEngine;
type F = <E as Engine>::Scalar;

const NUM_WORDS: usize = 104;
const NUM_STEPS: usize = 4;

pub(crate) const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ---------------------------------------------------------------------------
// Independent reference implementation (validated against the `sha2` crate below)
// ---------------------------------------------------------------------------

pub(crate) fn compress(state: [u32; 8], block: &[u32; 16]) -> [u32; 8] {
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

/// Builds the 104-word `shared` vector for a 192-byte payload and returns the
/// final chaining state (which must equal SHA-256(payload)).
pub(crate) fn build_shared(payload: &[u8; 192]) -> (Vec<u32>, [u32; 8]) {
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
    for i in 0..NUM_STEPS {
        let mut blk = [0u32; 16];
        blk.copy_from_slice(&words[16 * i..16 * i + 16]);
        let next = compress(states[i], &blk);
        states.push(next);
    }

    let mut shared = words;
    for s in &states {
        shared.extend_from_slice(s);
    }
    assert_eq!(shared.len(), NUM_WORDS);
    (shared, states[NUM_STEPS])
}

pub(crate) fn test_payload() -> [u8; 192] {
    let mut p = [0u8; 192];
    for (i, b) in p.iter_mut().enumerate() {
        *b = (i as u32 * 37 + 11) as u8;
    }
    // Set valid timestamps and revocation epoch for CredentialCoreCircuit predicates when now=0
    p[zkpc_core::credential::OFF_ISSUED_AT..zkpc_core::credential::OFF_ISSUED_AT + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    p[zkpc_core::credential::OFF_EXPIRES_AT..zkpc_core::credential::OFF_EXPIRES_AT + 4]
        .copy_from_slice(&100u32.to_be_bytes());
    p[zkpc_core::credential::OFF_REVOCATION_EPOCH..zkpc_core::credential::OFF_REVOCATION_EPOCH + 4]
        .copy_from_slice(&0u32.to_be_bytes());
    p
}

// ---------------------------------------------------------------------------
// Circuit drivers
// ---------------------------------------------------------------------------

fn run_step(step_idx: usize, shared_vals: &[u32]) -> TestConstraintSystem<F> {
    let c = CredentialStepCircuit {
        step_idx,
        shared_vals: shared_vals.to_vec(),
    };
    let mut cs = TestConstraintSystem::<F>::new();
    let shared = VegaCircuit::<E>::shared(&c, &mut cs).unwrap();
    let pre = VegaCircuit::<E>::precommitted(&c, &mut cs, &shared).unwrap();
    VegaCircuit::<E>::synthesize(&c, &mut cs, &shared, &pre, None).unwrap();
    cs
}

fn run_core(shared_vals: &[u32]) -> (TestConstraintSystem<F>, Vec<F>) {
    let c = CredentialCoreCircuit {
        shared_vals: shared_vals.to_vec(),
        now: 0,
        min_epoch: 0,
        binding: [0; 32],
    };
    let publics = VegaCircuit::<E>::public_values(&c).unwrap();
    let mut cs = TestConstraintSystem::<F>::new();
    let shared = VegaCircuit::<E>::shared(&c, &mut cs).unwrap();
    let pre = VegaCircuit::<E>::precommitted(&c, &mut cs, &shared).unwrap();
    VegaCircuit::<E>::synthesize(&c, &mut cs, &shared, &pre, None).unwrap();
    (cs, publics)
}

fn assert_sat(cs: &TestConstraintSystem<F>, what: &str) {
    assert!(
        cs.is_satisfied(),
        "{what}: expected satisfied, first unsatisfied constraint: {:?}",
        cs.which_is_unsatisfied()
    );
}

fn assert_unsat(cs: &TestConstraintSystem<F>, what: &str) {
    assert!(
        !cs.is_satisfied(),
        "{what}: expected UNSATISFIED but it was satisfied"
    );
}

// ---------------------------------------------------------------------------
// 0. The reference itself must be right, or nothing below means anything
// ---------------------------------------------------------------------------

#[test]
fn stage1_reference_matches_sha2_crate() {
    let payload = test_payload();
    let (_, final_state) = build_shared(&payload);
    let digest = Sha256::digest(payload);
    let mut expected = [0u32; 8];
    for i in 0..8 {
        expected[i] = u32::from_be_bytes([
            digest[4 * i],
            digest[4 * i + 1],
            digest[4 * i + 2],
            digest[4 * i + 3],
        ]);
    }
    assert_eq!(
        final_state, expected,
        "test reference disagrees with the sha2 crate"
    );
}

#[test]
fn stage1_field_repr_is_little_endian() {
    // decompose_32 style code reads the low bytes of to_repr(); that is only
    // valid if the repr is little-endian for this field.
    let r = F::from(0x01020304u64).to_repr();
    assert_eq!(&r.as_ref()[..4], &[4u8, 3, 2, 1]);
}

// ---------------------------------------------------------------------------
// 1. decompose_32: correct bits (LSB first), range-checked
// ---------------------------------------------------------------------------

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn stage1_decompose_32_correct_bits() {
    let mut vals: Vec<u32> = vec![0, 1, 2, 0x8000_0000, 0xFFFF_FFFF, 0x0102_0304, 0xDEAD_BEEF];
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..50 {
        vals.push(xorshift(&mut s) as u32);
    }
    for x in vals {
        let mut cs = TestConstraintSystem::<F>::new();
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(F::from(x as u64))).unwrap();
        let bits = decompose_32::<E, _>(cs.namespace(|| "d"), &v).unwrap();
        assert_eq!(bits.len(), 32, "decompose_32 must return 32 bits");
        for i in 0..32 {
            assert_eq!(
                bits[i].get_value(),
                Some((x >> i) & 1 == 1),
                "value {x:#010x}: bit {i} wrong (expected LSB-first order)"
            );
        }
        assert_sat(&cs, &format!("decompose_32({x:#010x})"));
    }
}

#[test]
fn stage1_decompose_32_rejects_out_of_range() {
    // A value that does not fit in 32 bits must NOT be accepted.
    for x in [1u64 << 32, (1u64 << 32) + 1, 1u64 << 40, u64::MAX] {
        let mut cs = TestConstraintSystem::<F>::new();
        let v = AllocatedNum::alloc(cs.namespace(|| "v"), || Ok(F::from(x))).unwrap();
        let _ = decompose_32::<E, _>(cs.namespace(|| "d"), &v);
        assert_unsat(&cs, &format!("decompose_32 on out-of-range {x:#x}"));
    }
}

// ---------------------------------------------------------------------------
// 2. SHA-256 step circuit
// ---------------------------------------------------------------------------

#[test]
fn stage1_step_accepts_valid_witness() {
    let (shared, _) = build_shared(&test_payload());
    for step in 0..NUM_STEPS {
        let cs = run_step(step, &shared);
        assert_sat(&cs, &format!("step {step} with valid witness"));
    }
}

/// Word indices the step circuit actually constrains for step `i`.
fn active_words(i: usize) -> Vec<usize> {
    let mut w: Vec<usize> = (16 * i..16 * i + 16).collect(); // message block i
    w.extend(64 + 8 * i..64 + 8 * i + 8); // input chaining state
    w.extend(64 + 8 * (i + 1)..64 + 8 * (i + 1) + 8); // output chaining state
    w
}

#[test]
fn stage1_step_rejects_flipped_bits_in_active_slice() {
    let (shared, _) = build_shared(&test_payload());
    for step in 0..NUM_STEPS {
        for &wi in &active_words(step) {
            for bit in [0u32, 31] {
                let mut bad = shared.clone();
                bad[wi] ^= 1u32 << bit;
                let cs = run_step(step, &bad);
                assert_unsat(&cs, &format!("step {step}, word {wi}, bit {bit} flipped"));
            }
        }
    }
}

#[test]
fn stage1_step_ignores_inactive_slices_documented_behavior() {
    // The step circuit only constrains its own slice. Consistency BETWEEN steps
    // must come from the shared-variable linking in Vega MC and from the core
    // circuit. This test documents that; it must not be read as a soundness claim.
    let (shared, _) = build_shared(&test_payload());
    let inactive_block_word = 16 * 3; // block 3, while checking step 0
    let mut other = shared.clone();
    other[inactive_block_word] ^= 1;
    let cs = run_step(0, &other);
    assert_sat(&cs, "step 0 should not look at block 3");
}

// ---------------------------------------------------------------------------
// 3. Core circuit
// ---------------------------------------------------------------------------

#[test]
fn stage1_core_accepts_valid_and_extracts_tier() {
    let mut payload = test_payload();
    payload[zkpc_core::credential::OFF_TIER] = 0x2A;
    let (shared, _) = build_shared(&payload);
    let (cs, publics) = run_core(&shared);
    assert_sat(&cs, "core with valid witness");
    assert_eq!(
        publics[0],
        F::from(0x2Au64),
        "public tier must equal the payload tier byte"
    );
}

#[test]
fn stage1_core_rejects_bad_iv() {
    let (shared, _) = build_shared(&test_payload());
    for i in 0..8 {
        let mut bad = shared.clone();
        bad[64 + i] ^= 1;
        let (cs, _) = run_core(&bad);
        assert_unsat(&cs, &format!("core with IV word {i} altered"));
    }
}

#[test]
fn stage1_core_rejects_bad_padding() {
    let (shared, _) = build_shared(&test_payload());
    let start = zkpc_core::credential::PAYLOAD_SIZE / 4;
    assert_eq!(start, 48, "layout assumption: payload is 192 bytes");
    for i in 0..16 {
        let mut bad = shared.clone();
        bad[start + i] ^= 1;
        let (cs, _) = run_core(&bad);
        assert_unsat(&cs, &format!("core with padding word {i} altered"));
    }
}
