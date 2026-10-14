use crate::{
    core::CredentialCoreCircuit,
    step::CredentialStepCircuit,
    tests::stage1_tests::{build_shared, compress, test_payload, IV},
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::Instant,
};
use vega_prover::{
    provider::T256HyraxEngine, traits::circuit::VegaCircuit, vega_mc_zkp::VegaMcZkSNARK,
};

type E = T256HyraxEngine;

const NUM_STEPS: usize = 4;

fn steps_for(shared: &[u32]) -> Vec<CredentialStepCircuit> {
    (0..NUM_STEPS)
        .map(|i| CredentialStepCircuit {
            step_idx: i,
            shared_vals: shared.to_vec(),
        })
        .collect()
}

fn core_for(shared: &[u32]) -> CredentialCoreCircuit {
    CredentialCoreCircuit {
        shared_vals: shared.to_vec(),
        now: 0,
        min_epoch: 0,
        binding: [0; 32],
    }
}

/// Same layout as build_shared, but with a caller-chosen initial hash value.
/// Steps stay internally consistent (states are recomputed), so only a check
/// that pins the IV can reject it.
fn build_shared_with_iv(payload: &[u8; 192], iv: [u32; 8]) -> Vec<u32> {
    let (base, _) = build_shared(payload);
    let mut shared = base[..64].to_vec();
    let mut st = iv;
    shared.extend_from_slice(&st);
    for i in 0..NUM_STEPS {
        let mut blk = [0u32; 16];
        blk.copy_from_slice(&shared[16 * i..16 * i + 16]);
        st = compress(st, &blk);
        shared.extend_from_slice(&st);
    }
    assert_eq!(shared.len(), 104);
    shared
}

fn guard_identical_shared(
    steps: &[CredentialStepCircuit],
    core: &CredentialCoreCircuit,
) -> Result<(), String> {
    if steps.is_empty() {
        return Err("steps slice is empty".to_string());
    }
    let s0 = &steps[0].shared_vals;
    for (i, step) in steps.iter().enumerate().skip(1) {
        if &step.shared_vals != s0 {
            return Err(format!("step {i} has divergent shared_vals from step 0"));
        }
    }
    if &core.shared_vals != s0 {
        return Err("core circuit has divergent shared_vals from step 0".to_string());
    }
    Ok(())
}

/// Full pipeline. Ok((step_publics_debug, core_publics_debug)) only if setup,
/// prove AND verify all succeed.
fn prove_verify(
    steps: &[CredentialStepCircuit],
    core: &CredentialCoreCircuit,
) -> Result<(String, String), String> {
    guard_identical_shared(steps, core)?;

    let step_proto = CredentialStepCircuit::default();
    let core_proto = CredentialCoreCircuit::default();

    let t = Instant::now();
    let (pk, vk) = VegaMcZkSNARK::<E>::setup(&step_proto, &core_proto, steps.len())
        .map_err(|e| format!("setup failed: {e:?}"))?;
    println!("  setup:      {:?}", t.elapsed());

    let t = Instant::now();
    let prep = VegaMcZkSNARK::<E>::prep_prove(&pk, steps, core, false)
        .map_err(|e| format!("prep_prove failed: {e:?}"))?;
    println!("  prep_prove: {:?}", t.elapsed());

    let t = Instant::now();
    let (proof, _) = VegaMcZkSNARK::<E>::prove(&pk, steps, core, prep, false)
        .map_err(|e| format!("prove failed: {e:?}"))?;
    println!("  prove:      {:?}", t.elapsed());

    let t = Instant::now();
    let (pv_steps, pv_core) = proof
        .verify(&vk, steps.len())
        .map_err(|e| format!("verify failed: {e:?}"))?;
    println!("  verify:     {:?}", t.elapsed());

    Ok((format!("{pv_steps:?}"), format!("{pv_core:?}")))
}

/// true only if the whole pipeline succeeds. A prover panic (unsatisfied
/// witness) counts as rejection.
fn accepted(steps: &[CredentialStepCircuit], core: &CredentialCoreCircuit) -> bool {
    match catch_unwind(AssertUnwindSafe(|| prove_verify(steps, core))) {
        Ok(Ok(_)) => true,
        Ok(Err(msg)) => {
            println!("  rejected: {msg}");
            false
        }
        Err(_) => {
            println!("  rejected: prover panicked (unsatisfied witness)");
            false
        }
    }
}

#[test]
fn stage15_honest_proof_verifies_and_publics_match() {
    let mut payload = test_payload();
    payload[zkpc_core::credential::OFF_TIER] = 0x2A;
    let (shared, _) = build_shared(&payload);
    let steps = steps_for(&shared);
    let core = core_for(&shared);

    println!("honest proof:");
    let (pv_steps, pv_core) = prove_verify(&steps, &core).expect("honest proof must verify");

    let expected_steps: Vec<_> = steps
        .iter()
        .map(|c| VegaCircuit::<E>::public_values(c).unwrap())
        .collect();
    let expected_core = VegaCircuit::<E>::public_values(&core).unwrap();
    assert_eq!(
        pv_steps,
        format!("{expected_steps:?}"),
        "step public values differ"
    );
    assert_eq!(
        pv_core,
        format!("{expected_core:?}"),
        "core public values differ"
    );
}

#[test]
fn stage15_rejects_corrupted_block_word() {
    let (mut shared, _) = build_shared(&test_payload());
    shared[5] ^= 1; // message word changed, chaining states not recomputed
    println!("corrupted block word:");
    assert!(
        !accepted(&steps_for(&shared), &core_for(&shared)),
        "proof over a message that does not hash to the claimed states was accepted"
    );
}

#[test]
fn stage15_rejects_wrong_iv_even_if_steps_are_self_consistent() {
    let mut iv = IV;
    iv[0] ^= 1;
    let shared = build_shared_with_iv(&test_payload(), iv);
    println!("wrong IV, self-consistent states:");
    assert!(
        !accepted(&steps_for(&shared), &core_for(&shared)),
        "core circuit failed to pin the SHA-256 IV"
    );
}

fn prove_verify_unguarded(
    steps: &[CredentialStepCircuit],
    core: &CredentialCoreCircuit,
) -> Result<
    (
        Vec<Vec<<E as vega_prover::traits::Engine>::Scalar>>,
        Vec<<E as vega_prover::traits::Engine>::Scalar>,
    ),
    String,
> {
    let step_proto = CredentialStepCircuit::default();
    let core_proto = CredentialCoreCircuit::default();

    let (pk, vk) = VegaMcZkSNARK::<E>::setup(&step_proto, &core_proto, steps.len())
        .map_err(|e| format!("setup failed: {e:?}"))?;

    let prep = VegaMcZkSNARK::<E>::prep_prove(&pk, steps, core, false)
        .map_err(|e| format!("prep_prove failed: {e:?}"))?;

    let (proof, _) = VegaMcZkSNARK::<E>::prove(&pk, steps, core, prep, false)
        .map_err(|e| format!("prove failed: {e:?}"))?;

    let (pv_steps, pv_core) = proof
        .verify(&vk, steps.len())
        .map_err(|e| format!("verify failed: {e:?}"))?;

    Ok((pv_steps, pv_core))
}

#[test]
fn stage15_step0_payload_b_core_payload_a_proves_b_never_a() {
    // Architectural reality: in Vega (prep_prove, vega_mc_zkp.rs:1493), the shared
    // witness is synthesized exclusively from step_circuits[0].
    //
    // 1. Host-side guard check: all circuits must present identical shared_vals.
    // When step 0 gets payload B and core has payload A, guard_identical_shared fails loudly.
    let mut a = test_payload();
    a[zkpc_core::credential::OFF_TIER] = 0x11; // Payload A has Tier 0x11
    let mut b = test_payload();
    b[zkpc_core::credential::OFF_TIER] = 0x22; // Payload B has Tier 0x22
    let (shared_a, _) = build_shared(&a);
    let (shared_b, _) = build_shared(&b);

    let steps_b = steps_for(&shared_b);
    let core_a = core_for(&shared_a);

    // Host-side guard fails loudly on divergence:
    let guard_res = guard_identical_shared(&steps_b, &core_a);
    assert!(
        guard_res.is_err(),
        "host-side guard must reject divergent shared_vals between step 0 and core"
    );
    println!(
        "Host-side guard rejected divergent shared_vals: {:?}",
        guard_res.err().unwrap()
    );

    // 2. If the guard is bypassed, the SNARK evaluates against step_circuits[0]'s witness (payload B).
    // The returned public values for the core circuit reveal Tier 0x22 (matching B), NEVER 0x11 (A).
    let (_, core_publics) = prove_verify_unguarded(&steps_b, &core_a)
        .expect("unguarded proof should synthesize witness from step 0 (payload B)");

    let tier_scalar = core_publics[zkpc_core::statement::IDX_TIER];
    assert_eq!(
        tier_scalar,
        <E as vega_prover::traits::Engine>::Scalar::from(0x22u64),
        "public tier MUST match step 0 (payload B)"
    );
    assert_ne!(
        tier_scalar,
        <E as vega_prover::traits::Engine>::Scalar::from(0x11u64),
        "public tier MUST NEVER match core host struct (payload A)"
    );
    println!(
        "Verified proof returned public tier matching Payload B (0x22) and NEVER Payload A (0x11)"
    );
}

#[test]
fn stage15_step0_tampered_payload_rejected_by_constraints() {
    // Prover modifies a payload byte in step 0 shared witness without recomputing hash chain.
    // Constraints must reject it because block words do not match SHA-256 compression output.
    let (mut shared, _) = build_shared(&test_payload());
    shared[0] ^= 0x01; // tamper payload word in step 0 block 0
    let steps = steps_for(&shared);
    let core = core_for(&shared);
    println!("step 0 tampered payload constraint check:");
    assert!(
        !accepted(&steps, &core),
        "tampered payload in step 0 shared witness must be rejected by constraint system"
    );
}
