use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use zkpc_core::credential::{
    CREDENTIAL_SIZE, OFF_POSTURE, OFF_SIG_R, OFF_SIG_S, OFF_TIER, PAYLOAD_SIZE,
};
use zkpc_core::evidence::tpm::{
    compute_composite_pcr_digest, TpmHashAlgorithm, TpmPcrValue, TpmPolicy, TpmQuoteEvidence,
    TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use zkpc_ea::{
    AuthorityError, CredentialIssuer, EnrollmentAuthority, MintParams, TpmPlatformVerifier,
    TpmPosturePolicy, VerificationError,
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
    bytes.extend_from_slice(&1000u64.to_be_bytes()); // clock
    bytes.extend_from_slice(&1u32.to_be_bytes()); // resetCount
    bytes.extend_from_slice(&0u32.to_be_bytes()); // restartCount
    bytes.push(1u8); // safe
    bytes.extend_from_slice(&0x0001000200030004u64.to_be_bytes()); // firmwareVersion
    bytes.extend_from_slice(&1u32.to_be_bytes()); // pcrSelect count
    bytes.extend_from_slice(&(TpmHashAlgorithm::Sha256 as u16).to_be_bytes());
    bytes.push(3u8); // sizeofSelect
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

fn build_test_tpms_attest(extra_data: &[u8], pcr_indices: &[u32], pcr_digest: &[u8]) -> Vec<u8> {
    build_test_tpms_attest_with_signer(
        b"test_device_ak_signer",
        extra_data,
        pcr_indices,
        pcr_digest,
    )
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

#[test]
fn test_ea_end_to_end_tpm_enrollment_and_credential_minting() {
    let (ea, ak_key, issuer_pub) = setup_ea();

    // 1. Device requests challenge nonce
    let nonce = ea.issue_challenge();

    // 2. Device creates quote and evidence
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
    let quoted = build_test_tpms_attest(&nonce, &[0, 7], &pcr_digest);
    let sig: Signature = ak_key.sign(&quoted);

    let evidence = TpmQuoteEvidence {
        quoted,
        signature: sig.to_der().as_bytes().to_vec(),
        pcr_values,
        pcr_alg: TpmHashAlgorithm::Sha256,
        kdev_public: zkpc_core::credential::RawPublicKey([0x55; 64]),
    };
    let evidence_bytes = serde_json::to_vec(&evidence).unwrap();

    let mint_params = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x99; 64],
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };

    // 3. EA enrolls and mints credential
    let cred = ea
        .enroll(&nonce, 1, &evidence_bytes, &mint_params)
        .expect("Enrollment should succeed");
    assert_eq!(cred.len(), CREDENTIAL_SIZE);
    assert_eq!(cred[OFF_TIER], 3); // T3 Vendor-attested
    assert_eq!(
        u32::from_be_bytes(cred[OFF_POSTURE..OFF_POSTURE + 4].try_into().unwrap()),
        1
    ); // Secure Boot bit set

    // 4. Verify that credential signature verifies under EA Issuer public key
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&cred[OFF_SIG_R..OFF_SIG_R + 32]);
    sig_bytes[32..].copy_from_slice(&cred[OFF_SIG_S..OFF_SIG_S + 32]);
    let cred_signature = Signature::from_slice(&sig_bytes).expect("Valid signature bytes");

    let payload = &cred[..PAYLOAD_SIZE];
    assert!(
        issuer_pub.verify(payload, &cred_signature).is_ok(),
        "Credential signature must verify under EA issuer key"
    );
}

#[test]
fn test_ea_rejects_replayed_nonce() {
    let (ea, ak_key, _) = setup_ea();
    let nonce = ea.issue_challenge();

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
    let quoted = build_test_tpms_attest(&nonce, &[0, 7], &pcr_digest);
    let sig: Signature = ak_key.sign(&quoted);

    let evidence = TpmQuoteEvidence {
        quoted,
        signature: sig.to_der().as_bytes().to_vec(),
        pcr_values,
        pcr_alg: TpmHashAlgorithm::Sha256,
        kdev_public: zkpc_core::credential::RawPublicKey([0x55; 64]),
    };
    let evidence_bytes = serde_json::to_vec(&evidence).unwrap();
    let mint_params = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x99; 64],
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };

    // First use succeeds
    assert!(ea.enroll(&nonce, 1, &evidence_bytes, &mint_params).is_ok());

    // Replay with consumed nonce fails immediately
    let err = ea
        .enroll(&nonce, 1, &evidence_bytes, &mint_params)
        .unwrap_err();
    match err {
        AuthorityError::InvalidNonce => {}
        other => panic!("Expected InvalidNonce on replay, got {:?}", other),
    }
}

#[test]
fn test_ea_rejects_altered_pcr_evidence() {
    let (ea, ak_key, _) = setup_ea();
    let nonce = ea.issue_challenge();

    let mut pcr_values = vec![
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
    let quoted = build_test_tpms_attest(&nonce, &[0, 7], &pcr_digest);
    let sig: Signature = ak_key.sign(&quoted);

    // Adversary tampers with PCR 0 measurement
    pcr_values[0].digest[0] ^= 0xEE;

    let evidence = TpmQuoteEvidence {
        quoted,
        signature: sig.to_der().as_bytes().to_vec(),
        pcr_values,
        pcr_alg: TpmHashAlgorithm::Sha256,
        kdev_public: zkpc_core::credential::RawPublicKey([0x55; 64]),
    };
    let evidence_bytes = serde_json::to_vec(&evidence).unwrap();
    let mint_params = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x99; 64],
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };

    let err = ea
        .enroll(&nonce, 1, &evidence_bytes, &mint_params)
        .unwrap_err();
    match err {
        AuthorityError::VerificationFailed(VerificationError::AlteredMeasurements) => {}
        other => panic!("Expected AlteredMeasurements, got {:?}", other),
    }
}

#[test]
fn test_ea_rejects_unsupported_platform() {
    let (ea, _, _) = setup_ea();
    let nonce = ea.issue_challenge();
    let mint_params = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x99; 64],
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };

    let err = ea.enroll(&nonce, 99, b"{}", &mint_params).unwrap_err();
    match err {
        AuthorityError::UnsupportedPlatform(99) => {}
        other => panic!("Expected UnsupportedPlatform(99), got {:?}", other),
    }
}

#[test]
fn test_ea_multi_ak_trust_boundary() {
    let issuer_key = SigningKey::random(&mut OsRng);
    let issuer = CredentialIssuer::new(issuer_key, [0x01; 8]);
    let ea = EnrollmentAuthority::new(issuer);

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

    // Enroll two distinct devices with distinct AKs
    let ak_a_key = SigningKey::random(&mut OsRng);
    let ak_a_pub = *ak_a_key.verifying_key();
    let signer_a = b"device_alpha_ak".to_vec();
    tpm_verifier.enroll_ak(signer_a.clone(), ak_a_pub).unwrap();

    let ak_b_key = SigningKey::random(&mut OsRng);
    let ak_b_pub = *ak_b_key.verifying_key();
    let signer_b = b"device_beta_ak".to_vec();
    tpm_verifier.enroll_ak(signer_b.clone(), ak_b_pub).unwrap();

    ea.register_verifier(1, Box::new(tpm_verifier));

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

    let mint_params = MintParams {
        fleet_id: [0x42; 16],
        secret_commit: [0x99; 64],
        issued_at: 1000,
        expires_at: 2000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    };

    // Case 1: Device Alpha tries to use a quote signed by Device Beta's AK
    // (Attestation specifies signer_a in qualified_signer, but signature was produced by ak_b_key)
    let nonce1 = ea.issue_challenge();
    let quoted_a = build_test_tpms_attest_with_signer(&signer_a, &nonce1, &[0, 7], &pcr_digest);
    let sig_wrong: Signature = ak_b_key.sign(&quoted_a); // Beta signs Alpha's quote!
    let evidence_mismatch = TpmQuoteEvidence {
        quoted: quoted_a,
        signature: sig_wrong.to_der().as_bytes().to_vec(),
        pcr_values: pcr_values.clone(),
        pcr_alg: TpmHashAlgorithm::Sha256,
        kdev_public: zkpc_core::credential::RawPublicKey([0xAA; 64]),
    };
    let err_mismatch = ea
        .enroll(
            &nonce1,
            1,
            &serde_json::to_vec(&evidence_mismatch).unwrap(),
            &mint_params,
        )
        .unwrap_err();
    match err_mismatch {
        AuthorityError::VerificationFailed(VerificationError::InvalidSignature(_)) => {}
        other => panic!(
            "Expected InvalidSignature when quote is signed by wrong AK, got {:?}",
            other
        ),
    }

    // Case 2: Rogue device with an unenrolled signer ID
    let rogue_key = SigningKey::random(&mut OsRng);
    let rogue_signer = b"rogue_device_ak".to_vec();
    let nonce2 = ea.issue_challenge();
    let quoted_rogue =
        build_test_tpms_attest_with_signer(&rogue_signer, &nonce2, &[0, 7], &pcr_digest);
    let sig_rogue: Signature = rogue_key.sign(&quoted_rogue);
    let evidence_rogue = TpmQuoteEvidence {
        quoted: quoted_rogue,
        signature: sig_rogue.to_der().as_bytes().to_vec(),
        pcr_values: pcr_values.clone(),
        pcr_alg: TpmHashAlgorithm::Sha256,
        kdev_public: zkpc_core::credential::RawPublicKey([0xEE; 64]),
    };
    let err_rogue = ea
        .enroll(
            &nonce2,
            1,
            &serde_json::to_vec(&evidence_rogue).unwrap(),
            &mint_params,
        )
        .unwrap_err();
    match err_rogue {
        AuthorityError::VerificationFailed(VerificationError::UntrustedKey) => {}
        other => panic!(
            "Expected UntrustedKey for unknown signer ID, got {:?}",
            other
        ),
    }

    // Case 3: Device Beta submits its own quote signed by its own enrolled AK -> MUST succeed
    let nonce3 = ea.issue_challenge();
    let quoted_b = build_test_tpms_attest_with_signer(&signer_b, &nonce3, &[0, 7], &pcr_digest);
    let sig_b: Signature = ak_b_key.sign(&quoted_b);
    let evidence_b = TpmQuoteEvidence {
        quoted: quoted_b,
        signature: sig_b.to_der().as_bytes().to_vec(),
        pcr_values: pcr_values.clone(),
        pcr_alg: TpmHashAlgorithm::Sha256,
        kdev_public: zkpc_core::credential::RawPublicKey([0xBB; 64]),
    };
    let cred_b = ea
        .enroll(
            &nonce3,
            1,
            &serde_json::to_vec(&evidence_b).unwrap(),
            &mint_params,
        )
        .expect("Device Beta enrollment must succeed");
    assert_eq!(cred_b.len(), CREDENTIAL_SIZE);
}
