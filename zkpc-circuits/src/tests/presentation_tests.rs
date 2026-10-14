//! Presentation tests: predicates, core circuit, and a real end-to-end presentation.
use crate::{backend::VegaBackend, core::*, predicates::assert_u32_ge};
use bellpepper_core::{
    num::AllocatedNum, test_cs::TestConstraintSystem, ConstraintSystem, SynthesisError,
};
use ff::PrimeField;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};
use vega_prover::{
    provider::T256HyraxEngine,
    traits::{circuit::VegaCircuit, Engine},
    vega_mc_zkp::VegaMcZkSNARK,
};
use zkpc_core::{
    binding::{binding_hash, split_u128},
    credential as cred,
    statement::*,
};
use zkpc_verifier::{Clock, InMemoryNonceStore, Policy, Verifier, VerifyError};

type E = T256HyraxEngine;
type F = <E as Engine>::Scalar;

// ------------------------------------------------------------ predicates

fn ge_sat(a: u64, b: u64, strict: bool) -> bool {
    let mut cs = TestConstraintSystem::<F>::new();
    let av = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(F::from(a))).unwrap();
    let bv = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(F::from(b))).unwrap();
    assert_u32_ge::<E, _>(cs.namespace(|| "ge"), &av, &bv, strict).unwrap();
    cs.is_satisfied()
}

#[test]
fn predicate_ge_table() {
    let m = u32::MAX as u64;
    let cases = [
        (5, 3, false, true),
        (3, 3, false, true),
        (3, 5, false, false),
        (3, 3, true, false),
        (4, 3, true, true),
        (0, 0, false, true),
        (0, 0, true, false),
        (m, 0, false, true),
        (m, 0, true, true),
        (0, m, false, false),
        (m, m, false, true),
        (m, m, true, false),
        (m, m - 1, true, true),
    ];
    for (a, b, strict, want) in cases {
        assert_eq!(ge_sat(a, b, strict), want, "a={a} b={b} strict={strict}");
    }
}

#[test]
fn predicate_random_agrees_with_integers() {
    let mut s = 0x1234_5678_9ABC_DEF1u64;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s as u32 as u64
    };
    for _ in 0..200 {
        let (a, b) = (next(), next());
        assert_eq!(ge_sat(a, b, false), a >= b, "a={a} b={b}");
        assert_eq!(ge_sat(a, b, true), a > b, "a={a} b={b} strict");
    }
}

// ------------------------------------------------------------ core circuit

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

struct Cred {
    tier: u8,
    issued_at: u32,
    expires_at: u32,
    epoch: u32,
    key_id: u64,
}

/// 104-word shared vector: payload words, SHA padding, IV, rest zero.
/// (The core circuit only looks at payload facts, padding and IV.)
fn shared_for(c: &Cred) -> Vec<u32> {
    let mut p = [0u8; 192];
    p[cred::OFF_TIER] = c.tier;
    p[cred::OFF_ISSUED_AT..cred::OFF_ISSUED_AT + 4].copy_from_slice(&c.issued_at.to_be_bytes());
    p[cred::OFF_EXPIRES_AT..cred::OFF_EXPIRES_AT + 4].copy_from_slice(&c.expires_at.to_be_bytes());
    p[cred::OFF_REVOCATION_EPOCH..cred::OFF_REVOCATION_EPOCH + 4]
        .copy_from_slice(&c.epoch.to_be_bytes());
    p[cred::OFF_ISSUER_KEY_ID..cred::OFF_ISSUER_KEY_ID + 8]
        .copy_from_slice(&c.key_id.to_be_bytes());
    let mut w: Vec<u32> = p
        .chunks(4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .collect();
    let mut pad = [0u32; 16];
    pad[0] = 0x8000_0000;
    pad[15] = 0x600;
    w.extend_from_slice(&pad);
    w.extend_from_slice(&IV);
    w.extend(std::iter::repeat(0u32).take(32));
    assert_eq!(w.len(), NUM_WORDS);
    w
}

const NOW: u32 = 1_800_000_000;
const KEY: u64 = (0xAAAA_0001u64 << 32) | 2;

fn good() -> Cred {
    Cred {
        tier: 3,
        issued_at: NOW - 1000,
        expires_at: NOW + 1000,
        epoch: 7,
        key_id: KEY,
    }
}

fn circuit(c: &Cred, now: u32, min_epoch: u32) -> CredentialCoreCircuit {
    CredentialCoreCircuit {
        shared_vals: shared_for(c),
        now,
        min_epoch,
        binding: binding_hash(b"n", b"s", b"p"),
    }
}

fn synth(c: &CredentialCoreCircuit) -> TestConstraintSystem<F> {
    let mut cs = TestConstraintSystem::<F>::new();
    let sh = VegaCircuit::<E>::shared(c, &mut cs).unwrap();
    let pre = VegaCircuit::<E>::precommitted(c, &mut cs, &sh).unwrap();
    VegaCircuit::<E>::synthesize(c, &mut cs, &sh, &pre, None).unwrap();
    cs
}

fn sat(c: &CredentialCoreCircuit) -> bool {
    synth(c).is_satisfied()
}

#[test]
fn core_accepts_valid_credential() {
    let cs = synth(&circuit(&good(), NOW, 7));
    assert!(cs.is_satisfied(), "{:?}", cs.which_is_unsatisfied());
}

#[test]
fn core_public_values_match_layout() {
    let c = circuit(&good(), NOW, 7);
    let p = VegaCircuit::<E>::public_values(&c).unwrap();
    assert_eq!(p.len(), NUM_CORE_PUBLICS);
    assert_eq!(p[IDX_TIER], F::from(3u64));
    assert_eq!(p[IDX_KEY_ID_0], F::from(0xAAAA_0001u64));
    assert_eq!(p[IDX_KEY_ID_1], F::from(2u64));
    assert_eq!(p[IDX_NOW], F::from(NOW as u64));
    assert_eq!(p[IDX_MIN_EPOCH], F::from(7u64));
    let (hi, lo) = split_u128(&c.binding);
    assert_eq!(p[IDX_BINDING_HI], u128_to_scalar::<F>(hi));
    assert_eq!(p[IDX_BINDING_LO], u128_to_scalar::<F>(lo));
}

#[test]
fn u128_to_scalar_is_exact() {
    let x: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
    let f = u128_to_scalar::<F>(x);
    let r = f.to_repr();
    assert_eq!(&r.as_ref()[..16], &x.to_le_bytes());
    assert!(r.as_ref()[16..].iter().all(|b| *b == 0));
}

#[test]
fn core_expiry_boundary() {
    let mut c = good();
    c.expires_at = NOW + 1;
    assert!(sat(&circuit(&c, NOW, 7)), "expires_at = now+1 must pass");
    c.expires_at = NOW;
    assert!(!sat(&circuit(&c, NOW, 7)), "expires_at = now must fail");
    c.expires_at = NOW - 1;
    assert!(!sat(&circuit(&c, NOW, 7)), "already expired must fail");
}

#[test]
fn core_not_before_boundary() {
    let mut c = good();
    c.issued_at = NOW;
    assert!(sat(&circuit(&c, NOW, 7)), "issued_at = now must pass");
    c.issued_at = NOW + 1;
    assert!(!sat(&circuit(&c, NOW, 7)), "issued in the future must fail");
}

#[test]
fn core_epoch_boundary() {
    let c = good(); // epoch 7
    assert!(sat(&circuit(&c, NOW, 7)), "epoch == min passes");
    assert!(sat(&circuit(&c, NOW, 6)), "epoch > min passes");
    assert!(!sat(&circuit(&c, NOW, 8)), "epoch < min fails");
}

#[test]
fn core_pins_iv_and_padding() {
    for i in 0..8 {
        let mut c = circuit(&good(), NOW, 7);
        c.shared_vals[64 + i] ^= 1;
        assert!(!sat(&c), "IV word {i}");
    }
    for i in 0..16 {
        let mut c = circuit(&good(), NOW, 7);
        c.shared_vals[cred::PAYLOAD_SIZE / 4 + i] ^= 1;
        assert!(!sat(&c), "padding word {i}");
    }
}

#[test]
fn core_rejects_wrong_shared_length() {
    let mut c = circuit(&good(), NOW, 7);
    c.shared_vals.pop();
    assert!(matches!(
        VegaCircuit::<E>::public_values(&c),
        Err(SynthesisError::Unsatisfiable)
    ));
}

// ------------------------------------------------------------ end to end

/// Step circuit stand-in: same shared layout, no hashing. It lets this file
/// exercise the core circuit and the backend glue with a real Vega proof.
/// (Replace with CredentialStepCircuit in the real repo: see e2e_real_steps.)
#[derive(Clone, Default)]
struct NullStep {
    idx: usize,
    shared_vals: Vec<u32>,
}

impl VegaCircuit<E> for NullStep {
    fn public_values(&self) -> Result<Vec<F>, SynthesisError> {
        Ok(vec![F::from(self.idx as u64)])
    }
    fn shared<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let w = if self.shared_vals.is_empty() {
            vec![0u32; NUM_WORDS]
        } else {
            self.shared_vals.clone()
        };
        w.iter()
            .enumerate()
            .map(|(i, v)| {
                AllocatedNum::alloc(cs.namespace(|| format!("shared_{i}")), || {
                    Ok(F::from(*v as u64))
                })
            })
            .collect()
    }
    fn precommitted<CS: ConstraintSystem<F>>(
        &self,
        _cs: &mut CS,
        _s: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        _s: &[AllocatedNum<F>],
        _p: &[AllocatedNum<F>],
        _c: Option<&[F]>,
    ) -> Result<(), SynthesisError> {
        let x = AllocatedNum::alloc(cs.namespace(|| "idx"), || Ok(F::from(self.idx as u64)))?;
        cs.enforce(
            || "triv",
            |lc| lc + x.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + x.get_variable(),
        );
        x.inputize(cs.namespace(|| "pub idx"))
    }
}

struct FixedClock(u64);
impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

const STEPS: usize = 4;

struct Rig {
    verifier: Verifier,
    pk: vega_prover::vega_mc_zkp::VegaMcProverKey<E>,
}

fn rig() -> Rig {
    let t = Instant::now();
    let (pk, vk) = VegaMcZkSNARK::<E>::setup(
        &NullStep::default(),
        &CredentialCoreCircuit::default(),
        STEPS,
    )
    .unwrap();
    println!("  setup: {:?}", t.elapsed());
    let policy = Policy {
        min_tier: 3,
        min_epoch: 7,
        trusted_issuer_keys: [KEY].into_iter().collect(),
        trusted_issuer_coords: Default::default(),
        max_skew_secs: 60,
        challenge_ttl_secs: 120,
        quantize_secs: 0,
    };
    let verifier = Verifier::new(
        b"vpn.example".to_vec(),
        policy,
        Box::new(FixedClock(NOW as u64)),
        Box::new(InMemoryNonceStore::default()),
        Box::new(VegaBackend::new(vk, STEPS)),
    );
    Rig { verifier, pk }
}

/// Builds a proof for `cred` against `challenge`-derived binding. `now` and `min_epoch`
/// are chosen by the prover (they are public inputs the verifier will check).
fn prove(
    r: &Rig,
    c: &Cred,
    now: u32,
    min_epoch: u32,
    nonce: &[u8; 32],
    service: &[u8],
    policy_hash: &[u8; 32],
) -> Vec<u8> {
    let shared = shared_for(c);
    let steps: Vec<NullStep> = (0..STEPS)
        .map(|i| NullStep {
            idx: i,
            shared_vals: shared.clone(),
        })
        .collect();
    let core = CredentialCoreCircuit {
        shared_vals: shared,
        now,
        min_epoch,
        binding: binding_hash(nonce, service, policy_hash),
    };
    let t = Instant::now();
    let prep = VegaMcZkSNARK::<E>::prep_prove(&r.pk, &steps, &core, false).unwrap();
    let (proof, _) = VegaMcZkSNARK::<E>::prove(&r.pk, &steps, &core, prep, false).unwrap();
    println!("  prove: {:?}", t.elapsed());
    bincode::serialize(&proof).unwrap()
}

#[test]
fn e2e_honest_presentation_is_accepted() {
    let r = rig();
    let ch = r.verifier.issue_challenge();
    let bytes = prove(
        &r,
        &good(),
        NOW,
        7,
        &ch.nonce,
        &ch.service_id,
        &ch.policy_hash,
    );
    println!("  proof bytes: {}", bytes.len());
    let acc = r
        .verifier
        .verify_presentation(&ch.nonce, &bytes)
        .expect("honest proof must be accepted");
    assert_eq!(acc.tier, 3);
    assert_eq!(acc.issuer_key_id, KEY);
    // replay of the same proof: nonce already used
    assert_eq!(
        r.verifier.verify_presentation(&ch.nonce, &bytes),
        Err(VerifyError::UnknownOrReusedNonce)
    );
}

#[test]
fn e2e_wrong_challenge_binding_is_rejected() {
    let r = rig();
    let ch = r.verifier.issue_challenge();
    let other = [0x55u8; 32];
    let bytes = prove(&r, &good(), NOW, 7, &other, &ch.service_id, &ch.policy_hash);
    assert_eq!(
        r.verifier.verify_presentation(&ch.nonce, &bytes),
        Err(VerifyError::BindingMismatch)
    );
}

#[test]
fn e2e_prover_chosen_clock_and_epoch_are_checked() {
    let r = rig();
    let ch = r.verifier.issue_challenge();
    let mut c = good();
    c.issued_at = (NOW - 4000) as u32;
    let bytes = prove(
        &r,
        &c,
        NOW - 3600,
        7,
        &ch.nonce,
        &ch.service_id,
        &ch.policy_hash,
    );
    let res = r.verifier.verify_presentation(&ch.nonce, &bytes);
    println!("CLOCK SKEW TEST RESULT: {:?}", res);
    assert!(matches!(res, Err(VerifyError::ClockSkew { .. })));

    let ch = r.verifier.issue_challenge();
    let bytes = prove(
        &r,
        &good(),
        NOW,
        6,
        &ch.nonce,
        &ch.service_id,
        &ch.policy_hash,
    );
    assert!(matches!(
        r.verifier.verify_presentation(&ch.nonce, &bytes),
        Err(VerifyError::EpochMismatch { .. })
    ));
}

#[test]
fn e2e_tier_and_issuer_policy_enforced() {
    let r = rig();
    let ch = r.verifier.issue_challenge();
    let mut c = good();
    c.tier = 2;
    let bytes = prove(&r, &c, NOW, 7, &ch.nonce, &ch.service_id, &ch.policy_hash);
    assert!(matches!(
        r.verifier.verify_presentation(&ch.nonce, &bytes),
        Err(VerifyError::TierTooLow { .. })
    ));

    let ch = r.verifier.issue_challenge();
    let mut c = good();
    c.key_id = 99;
    let bytes = prove(&r, &c, NOW, 7, &ch.nonce, &ch.service_id, &ch.policy_hash);
    assert!(matches!(
        r.verifier.verify_presentation(&ch.nonce, &bytes),
        Err(VerifyError::UntrustedIssuer(_))
    ));
}

#[test]
fn e2e_expired_credential_cannot_be_proved() {
    let r = rig();
    let ch = r.verifier.issue_challenge();
    let mut c = good();
    c.expires_at = NOW - 1;
    let res = catch_unwind(AssertUnwindSafe(|| {
        prove(&r, &c, NOW, 7, &ch.nonce, &ch.service_id, &ch.policy_hash)
    }));
    // Either the prover refuses (panic) or the verifier must reject.
    if let Ok(bytes) = res {
        assert!(
            r.verifier.verify_presentation(&ch.nonce, &bytes).is_err(),
            "expired credential was accepted"
        );
    }
}

#[test]
fn e2e_corrupted_proof_bytes_are_rejected() {
    let r = rig();
    let ch = r.verifier.issue_challenge();
    let mut bytes = prove(
        &r,
        &good(),
        NOW,
        7,
        &ch.nonce,
        &ch.service_id,
        &ch.policy_hash,
    );
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    let res = catch_unwind(AssertUnwindSafe(|| {
        r.verifier.verify_presentation(&ch.nonce, &bytes)
    }));
    match res {
        Ok(v) => assert!(v.is_err(), "corrupted proof was accepted"),
        Err(_) => {} // verifier panicked on garbage: not ideal, but not an accept
    }
}
