use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zkpc_core::credential::{OFF_SECRET_COMMIT, SIZE_SECRET_COMMIT};
use zkpc_core::evidence::tpm::{
    compute_composite_pcr_digest, TpmHashAlgorithm, TpmPcrValue, TpmPolicy, TpmQuoteEvidence,
    TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use zkpc_ea::{
    AuthorityError, CredentialIssuer, EnrollmentAuthority, MintParams, TpmPlatformVerifier,
    TpmPosturePolicy,
};

fn build_test_tpms_attest_with_signer(
    signer_id: &[u8],
    extra_data: &[u8],
    pcr_indices: &[u32],
    pcr_digest: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
    bytes.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
    bytes.extend_from_slice(&(signer_id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(signer_id);
    bytes.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(extra_data);
    bytes.extend_from_slice(&1000u64.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.push(1u8);
    bytes.extend_from_slice(&0x0001000200030004u64.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&(TpmHashAlgorithm::Sha256 as u16).to_be_bytes());
    bytes.push(3u8);
    let mut pcr_bytes = [0u8; 3];
    for &idx in pcr_indices {
        if idx < 24 {
            pcr_bytes[(idx / 8) as usize] |= 1 << (idx % 8);
        }
    }
    bytes.extend_from_slice(&pcr_bytes);
    bytes.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
    bytes.extend_from_slice(pcr_digest);
    bytes
}

fn setup_ea() -> (EnrollmentAuthority, SigningKey, VerifyingKey) {
    let issuer_key = SigningKey::random(&mut OsRng);
    let issuer_verifying_key = *issuer_key.verifying_key();
    let issuer = CredentialIssuer::new(issuer_key, [0x01; 8]);
    let ea = EnrollmentAuthority::new(issuer);

    let ak_signing_key = SigningKey::random(&mut OsRng);
    let ak_verifying_key = *ak_signing_key.verifying_key();

    let pcr0_val = vec![0x11; 32];
    let pcr7_val = vec![0x77; 32];

    let posture_policy = TpmPosturePolicy {
        tpm_policy: TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: vec![
                TpmPcrValue {
                    index: 0,
                    digest: pcr0_val,
                },
                TpmPcrValue {
                    index: 7,
                    digest: pcr7_val.clone(),
                },
            ],
            hash_alg: TpmHashAlgorithm::Sha256,
        },
        secure_boot_pcr: 7,
        expected_secure_boot_digest: pcr7_val,
    };

    let tpm_verifier = TpmPlatformVerifier::new(posture_policy);
    tpm_verifier
        .enroll_ak(b"test_device_ak_signer".to_vec(), ak_verifying_key)
        .unwrap();

    ea.register_verifier(1, Box::new(tpm_verifier));

    (ea, ak_signing_key, issuer_verifying_key)
}

fn create_evidence_bytes(nonce: &[u8], ak_key: &SigningKey, kdev: [u8; 64]) -> Vec<u8> {
    let pcr_values = vec![
        TpmPcrValue {
            index: 0,
            digest: vec![0x11; 32],
        },
        TpmPcrValue {
            index: 7,
            digest: vec![0x77; 32],
        },
    ];
    let pcr_digest =
        compute_composite_pcr_digest(pcr_values.clone(), TpmHashAlgorithm::Sha256).unwrap();
    let quoted =
        build_test_tpms_attest_with_signer(b"test_device_ak_signer", nonce, &[0, 7], &pcr_digest);
    let sig: Signature = ak_key.sign(&quoted);

    let evidence = TpmQuoteEvidence {
        quoted,
        signature: sig.to_der().as_bytes().to_vec(),
        pcr_values,
        pcr_alg: TpmHashAlgorithm::Sha256,
        kdev_public: zkpc_core::credential::RawPublicKey(kdev),
    };
    serde_json::to_vec(&evidence).unwrap()
}

#[test]
fn test_ea_enforces_single_commitment_per_kdev() {
    let (ea, ak_key, _) = setup_ea();
    let kdev = [0x55; 64];
    let commit1 = [0x11; 64];
    let commit2 = [0x22; 64];

    let nonce1 = ea.issue_challenge();
    let evidence1 = create_evidence_bytes(&nonce1, &ak_key, kdev);
    let params1 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit1,
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };

    let cred1 = ea
        .enroll(&nonce1, 1, &evidence1, &params1)
        .expect("First enrollment succeeds");
    assert_eq!(
        &cred1[OFF_SECRET_COMMIT..OFF_SECRET_COMMIT + SIZE_SECRET_COMMIT],
        &commit1
    );

    // Attempting a duplicate enrollment with a different commitment for the same enrolled K_dev must fail
    let nonce2 = ea.issue_challenge();
    let evidence2 = create_evidence_bytes(&nonce2, &ak_key, kdev);
    let params2 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit2,
        issued_at: 1005,
        expires_at: 2005,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };

    let err = ea
        .enroll(&nonce2, 1, &evidence2, &params2)
        .expect_err("Duplicate enrollment must fail");
    match err {
        AuthorityError::AlreadyEnrolled(hex) => {
            println!("Duplicate enrollment correctly rejected for K_dev: {}", hex);
        }
        other => panic!("Unexpected error on duplicate enrollment: {:?}", other),
    }
}

#[test]
fn test_ea_refresh_preserves_commitment_and_rejects_replacement() {
    let (ea, ak_key, _) = setup_ea();
    let kdev = [0x66; 64];
    let commit1 = [0x33; 64];
    let commit_tampered = [0x44; 64];

    let nonce1 = ea.issue_challenge();
    let evidence1 = create_evidence_bytes(&nonce1, &ak_key, kdev);
    let params1 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit1,
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };
    ea.enroll(&nonce1, 1, &evidence1, &params1)
        .expect("Enrollment succeeds");

    // 1. Refresh with same commitment succeeds and mints updated credential
    let nonce_ref = ea.issue_challenge();
    let evidence_ref = create_evidence_bytes(&nonce_ref, &ak_key, kdev);
    let params_ref = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit1, // Preserved commitment
        issued_at: 2000,
        expires_at: 3000,
        revocation_epoch: 2,
        issuer_key_id: [0x01; 8],
    };
    let refreshed_cred = ea
        .refresh_credential(&nonce_ref, 1, &evidence_ref, &params_ref)
        .expect("Refresh with preserved commitment must succeed");
    assert_eq!(
        &refreshed_cred[OFF_SECRET_COMMIT..OFF_SECRET_COMMIT + SIZE_SECRET_COMMIT],
        &commit1
    );

    // 2. Refresh attempting to replace commitment must be rejected
    let nonce_bad = ea.issue_challenge();
    let evidence_bad = create_evidence_bytes(&nonce_bad, &ak_key, kdev);
    let params_bad = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit_tampered, // Replaced commitment
        issued_at: 2500,
        expires_at: 3500,
        revocation_epoch: 2,
        issuer_key_id: [0x01; 8],
    };
    let err = ea
        .refresh_credential(&nonce_bad, 1, &evidence_bad, &params_bad)
        .expect_err("Refresh with replaced commitment must fail");
    match err {
        AuthorityError::CommitmentMismatchOnRefresh => {
            println!("Commitment replacement during refresh correctly rejected");
        }
        other => panic!("Unexpected error on refresh replacement: {:?}", other),
    }
}

#[test]
fn test_ea_authorized_rotation_and_old_credential_revocation() {
    let (ea, ak_key, _) = setup_ea();
    let kdev = [0x77; 64];
    let commit1 = [0x55; 64];
    let commit2 = [0x88; 64];

    let nonce1 = ea.issue_challenge();
    let evidence1 = create_evidence_bytes(&nonce1, &ak_key, kdev);
    let params1 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit1,
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };
    let cred1 = ea
        .enroll(&nonce1, 1, &evidence1, &params1)
        .expect("Enrollment succeeds");
    let cred1_hash: [u8; 32] = Sha256::digest(&cred1).into();
    assert!(!ea.is_credential_revoked(&cred1_hash));

    // Authorized rotation: submit fresh attestation + old credential + new commitment
    let nonce_rot = ea.issue_challenge();
    let evidence_rot = create_evidence_bytes(&nonce_rot, &ak_key, kdev);
    let params2 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit2,
        issued_at: 1500,
        expires_at: 2500,
        revocation_epoch: 2,
        issuer_key_id: [0x01; 8],
    };
    let cred2 = ea
        .rotate_commitment(&nonce_rot, 1, &evidence_rot, &cred1, &params2)
        .expect("Authorized rotation succeeds");
    assert_eq!(
        &cred2[OFF_SECRET_COMMIT..OFF_SECRET_COMMIT + SIZE_SECRET_COMMIT],
        &commit2
    );

    // Old credential is now irrevocably revoked
    assert!(ea.is_credential_revoked(&cred1_hash));
    assert_eq!(ea.get_active_commitment(&kdev), Some(commit2));

    // Replay or second rotation attempt using the now-revoked cred1 must fail
    let nonce_rot2 = ea.issue_challenge();
    let evidence_rot2 = create_evidence_bytes(&nonce_rot2, &ak_key, kdev);
    let commit3 = [0x99; 64];
    let params3 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit3,
        issued_at: 1600,
        expires_at: 2600,
        revocation_epoch: 3,
        issuer_key_id: [0x01; 8],
    };
    let err = ea
        .rotate_commitment(&nonce_rot2, 1, &evidence_rot2, &cred1, &params3)
        .expect_err("Rotation with already-revoked old credential must fail");
    match err {
        AuthorityError::InvalidOldCredential => {
            println!("Rotation with stale/revoked credential correctly rejected");
        }
        other => panic!("Unexpected error on stale rotation: {:?}", other),
    }
}

#[test]
fn test_ea_explicit_revocation_prevents_refresh() {
    let (ea, ak_key, _) = setup_ea();
    let kdev = [0x88; 64];
    let commit1 = [0xaa; 64];

    let nonce1 = ea.issue_challenge();
    let evidence1 = create_evidence_bytes(&nonce1, &ak_key, kdev);
    let params1 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit1,
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };
    let cred1 = ea
        .enroll(&nonce1, 1, &evidence1, &params1)
        .expect("Enrollment succeeds");

    // Explicitly revoke credential
    ea.revoke_credential(&cred1).expect("Revocation succeeds");
    let cred1_hash: [u8; 32] = Sha256::digest(&cred1).into();
    assert!(ea.is_credential_revoked(&cred1_hash));
    assert_eq!(ea.get_active_commitment(&kdev), None);

    // Refresh of revoked credential is rejected
    let nonce_ref = ea.issue_challenge();
    let evidence_ref = create_evidence_bytes(&nonce_ref, &ak_key, kdev);
    let params_ref = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit1,
        issued_at: 1500,
        expires_at: 2500,
        revocation_epoch: 2,
        issuer_key_id: [0x01; 8],
    };
    let err = ea
        .refresh_credential(&nonce_ref, 1, &evidence_ref, &params_ref)
        .expect_err("Refresh after revocation must fail");
    match err {
        AuthorityError::CredentialRevoked => {
            println!("Refresh of explicitly revoked credential correctly rejected");
        }
        other => panic!("Unexpected error: {:?}", other),
    }
}

#[test]
fn test_ea_refuses_to_enroll_or_renew_banned_device() {
    let (ea, ak_key, _) = setup_ea();
    let banned_kdev = [0xba; 64];
    let commit1 = [0x12; 64];

    // Ban the device prior to enrollment
    ea.ban_device(&banned_kdev);
    assert!(ea.is_banned(&banned_kdev));

    // Attempting to enroll a banned device must fail immediately
    let nonce1 = ea.issue_challenge();
    let evidence1 = create_evidence_bytes(&nonce1, &ak_key, banned_kdev);
    let params1 = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: commit1,
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };
    let err_enroll = ea
        .enroll(&nonce1, 1, &evidence1, &params1)
        .expect_err("Banned device enrollment must fail");
    match err_enroll {
        AuthorityError::DeviceBanned => {
            println!("Enrollment of banned device correctly rejected");
        }
        other => panic!("Unexpected error on banned enroll: {:?}", other),
    }

    // Now test a device that was enrolled then banned: renewals must be refused
    let active_kdev = [0xbb; 64];
    let nonce2 = ea.issue_challenge();
    let evidence2 = create_evidence_bytes(&nonce2, &ak_key, active_kdev);
    let cred2 = ea
        .enroll(&nonce2, 1, &evidence2, &params1)
        .expect("Enrolling unbanned device succeeds");
    let cred2_hash: [u8; 32] = Sha256::digest(&cred2).into();

    // Ban device
    ea.ban_device(&active_kdev);
    assert!(ea.is_banned(&active_kdev));
    assert!(ea.is_credential_revoked(&cred2_hash));

    // Attempting to refresh banned device must be refused
    let nonce_ref = ea.issue_challenge();
    let evidence_ref = create_evidence_bytes(&nonce_ref, &ak_key, active_kdev);
    let err_ref = ea
        .refresh_credential(&nonce_ref, 1, &evidence_ref, &params1)
        .expect_err("Banned device refresh must fail");
    match err_ref {
        AuthorityError::DeviceBanned => {
            println!("Refresh of banned device correctly rejected");
        }
        other => panic!("Unexpected error on banned refresh: {:?}", other),
    }

    // Attempting to rotate banned device must also be refused
    let nonce_rot = ea.issue_challenge();
    let evidence_rot = create_evidence_bytes(&nonce_rot, &ak_key, active_kdev);
    let params_rot = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x34; 64],
        issued_at: 1100,
        expires_at: 2100,
        revocation_epoch: 2,
        issuer_key_id: [0x01; 8],
    };
    let err_rot = ea
        .rotate_commitment(&nonce_rot, 1, &evidence_rot, &cred2, &params_rot)
        .expect_err("Banned device rotation must fail");
    match err_rot {
        AuthorityError::DeviceBanned => {
            println!("Rotation of banned device correctly rejected");
        }
        other => panic!("Unexpected error on banned rotation: {:?}", other),
    }
}

#[test]
fn test_ea_rotation_rejects_stolen_credential_with_thief_hardware_key() {
    let (ea, ak_key, _) = setup_ea();
    let kdev_alice = [0xAA; 64];
    let kdev_bob = [0xBB; 64];

    // Alice enrolls honestly with commitment C_alice
    let nonce_alice = ea.issue_challenge();
    let evidence_alice = create_evidence_bytes(&nonce_alice, &ak_key, kdev_alice);
    let params_alice = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x11; 64],
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };
    let cred_alice = ea
        .enroll(&nonce_alice, 1, &evidence_alice, &params_alice)
        .expect("Alice honest enrollment succeeds");

    // Bob (the attacker) steals cred_alice.
    // Bob attempts to rotate cred_alice to his own commitment C_bob using his own hardware key K_dev_bob:
    let nonce_bob = ea.issue_challenge();
    let evidence_bob = create_evidence_bytes(&nonce_bob, &ak_key, kdev_bob);
    let params_bob = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x99; 64],
        issued_at: 1050,
        expires_at: 2050,
        revocation_epoch: 2,
        issuer_key_id: [0x01; 8],
    };

    let err = ea
        .rotate_commitment(&nonce_bob, 1, &evidence_bob, &cred_alice, &params_bob)
        .expect_err("Rotation of stolen credential by thief hardware key must fail");

    match err {
        AuthorityError::DeviceKeyMismatch => {
            println!(
                "Stolen credential rotation with thief hardware key correctly rejected: DeviceKeyMismatch"
            );
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    // Confirm Alice's commitment is still active and unchanged
    assert_eq!(ea.get_active_commitment(&kdev_alice), Some([0x11; 64]));
    let alice_cred_hash: [u8; 32] = Sha256::digest(&cred_alice).into();
    assert!(!ea.is_credential_revoked(&alice_cred_hash));
}

#[test]
fn test_ea_concurrent_enroll_rotate_revoke_preserves_one_active_commitment() {
    use std::sync::Arc;
    use std::thread;

    let (ea_raw, ak_key, _) = setup_ea();
    let ea = Arc::new(ea_raw);
    let ak_key = Arc::new(ak_key);

    let kdev = [0x77; 64];

    // Initial honest enrollment
    let nonce0 = ea.issue_challenge();
    let ev0 = create_evidence_bytes(&nonce0, &ak_key, kdev);
    let cred0 = ea
        .enroll(
            &nonce0,
            1,
            &ev0,
            &MintParams {
                fleet_id: [0x42; 16],
                secret_commit: [0x01; 64],
                issued_at: 1000,
                expires_at: 2000,
                revocation_epoch: 1,
                issuer_key_id: [0x01; 8],
            },
        )
        .expect("Initial enrollment");

    let cred0 = Arc::new(cred0);
    let mut handles = Vec::new();

    // Spawn 10 concurrent threads racing to rotate the initial credential
    for i in 0..10u8 {
        let ea_clone = Arc::clone(&ea);
        let ak_clone = Arc::clone(&ak_key);
        let cred_clone = Arc::clone(&cred0);
        handles.push(thread::spawn(move || {
            let nonce = ea_clone.issue_challenge();
            let ev = create_evidence_bytes(&nonce, &ak_clone, kdev);
            let params = MintParams {
                fleet_id: [0x42; 16],
                secret_commit: [0x10 + i; 64],
                issued_at: 1000 + i as u32,
                expires_at: 2000 + i as u32,
                revocation_epoch: 2,
                issuer_key_id: [0x01; 8],
            };
            ea_clone.rotate_commitment(&nonce, 1, &ev, &cred_clone, &params)
        }));
    }

    let mut success_count = 0;
    let mut err_count = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(_) => success_count += 1,
            Err(AuthorityError::InvalidOldCredential) => err_count += 1,
            Err(e) => panic!("Unexpected concurrent rotation error: {:?}", e),
        }
    }

    // Exactly ONE rotation can succeed; the other 9 see InvalidOldCredential because cred0 is revoked
    assert_eq!(
        success_count, 1,
        "Exactly one concurrent rotation must succeed"
    );
    assert_eq!(
        err_count, 9,
        "All racing rotations must see InvalidOldCredential"
    );

    // The initial credential cred0 MUST be revoked
    let cred0_hash: [u8; 32] = Sha256::digest(&*cred0).into();
    assert!(
        ea.is_credential_revoked(&cred0_hash),
        "Rotated-from credential must be revoked"
    );

    // There is still strictly exactly ONE active commitment for kdev
    let active_commit = ea
        .get_active_commitment(&kdev)
        .expect("Must have an active commitment");
    assert_ne!(
        active_commit, [0x01; 64],
        "Active commitment must be the rotated one"
    );
    println!(
        "Concurrent rotation atomicity preserved: 1 success, 9 rejected, exactly 1 active commitment"
    );
}
