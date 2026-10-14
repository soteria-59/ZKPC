// -----------------------------------------------------------------------------
// ZKPC Platform Adapter Integration Test - swtpm Live Test
//
// File: zkpc-agent/tests/tpm_live_test.rs
// Description: Live integration test proving TPM2_Quote generation, nonce
//              binding, enrolled AK signature verification, PCR digest
//              validation, K_dev proof-of-possession, and credential minting
//              against an active TPM simulator (swtpm), along with all
//              adversarial rejection boundaries.
// -----------------------------------------------------------------------------

#[cfg(feature = "tpm")]
mod live_tpm_tests {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use rand_core::OsRng;
    use zkpc_agent::platform::tpm::TpmAdapter;
    use zkpc_core::credential::{CREDENTIAL_SIZE, OFF_SIG_R, OFF_SIG_S, OFF_TIER, PAYLOAD_SIZE};
    use zkpc_core::evidence::tpm::{TpmHashAlgorithm, TpmPcrValue, TpmPolicy};
    use zkpc_core::evidence::KeyHolder;
    use zkpc_ea::{
        AuthorityError, CredentialIssuer, EnrollmentAuthority, MintParams, TpmPlatformVerifier,
        TpmPosturePolicy, VerificationError,
    };

    fn default_mint_params() -> MintParams {
        MintParams {
            fleet_id: [0x77; 16],
            secret_commit: [0x33; 64],
            issued_at: 1000,
            expires_at: 2000,
            revocation_epoch: 1,
            issuer_key_id: [0x01; 8],
        }
    }

    #[test]
    fn test_live_swtpm_smoke_suite() {
        // 1. Connect to swtpm via TSS2_TCTI environment or fallback
        let mut adapter = match TpmAdapter::new("swtpm:path=/tmp/tpmstate/swtpm.sock") {
            Ok(a) => a,
            Err(e) => {
                panic!("FATAL: could not connect to TPM simulator: {e}");
            }
        };

        // 2. Create restricted AK and unrestricted K_dev
        let (ak_name, ak_pub_raw) = adapter.create_ak().expect("create_ak failed");
        let kdev_pub_raw = adapter.create_kdev().expect("create_kdev failed");

        assert!(!ak_name.is_empty(), "AK name must not be empty");
        assert_eq!(ak_pub_raw.len(), 64);
        assert_eq!(kdev_pub_raw.len(), 64);

        // Convert raw 64-byte AK public key to p256 VerifyingKey
        let mut sec1_ak = vec![0x04];
        sec1_ak.extend_from_slice(&ak_pub_raw);
        let ak_verifying_key =
            VerifyingKey::from_sec1_bytes(&sec1_ak).expect("AK public key must be valid P-256");

        // 3. Inspect PCR 0 and 7 values from swtpm
        let probe_nonce = [0xAA; 32];
        let pre_evidence = adapter
            .quote_pcrs(&probe_nonce, &[0, 7])
            .expect("Pre-quote failed");

        let pcr0_digest = pre_evidence
            .pcr_values
            .iter()
            .find(|p| p.index == 0)
            .unwrap()
            .digest
            .clone();
        let pcr7_digest = pre_evidence
            .pcr_values
            .iter()
            .find(|p| p.index == 7)
            .unwrap()
            .digest
            .clone();

        let posture_policy = TpmPosturePolicy {
            tpm_policy: TpmPolicy {
                required_pcrs: vec![0, 7],
                expected_pcr_values: vec![
                    TpmPcrValue {
                        index: 0,
                        digest: pcr0_digest,
                    },
                    TpmPcrValue {
                        index: 7,
                        digest: pcr7_digest.clone(),
                    },
                ],
                hash_alg: TpmHashAlgorithm::Sha256,
            },
            secure_boot_pcr: 7,
            expected_secure_boot_digest: pcr7_digest,
        };

        // 4. Setup Enrollment Authority (EA)
        let ea_signing_key = SigningKey::random(&mut OsRng);
        let ea_verifying_key = *ea_signing_key.verifying_key();
        let issuer = CredentialIssuer::new(ea_signing_key, [0x01; 8]);
        let ea = EnrollmentAuthority::new(issuer);

        let tpm_verifier = TpmPlatformVerifier::new(posture_policy.clone());
        tpm_verifier
            .enroll_ak(ak_name.clone(), ak_verifying_key)
            .expect("AK enrollment failed");
        ea.register_verifier(1, Box::new(tpm_verifier));

        // ---------------------------------------------------------------------
        // TEST A: Honest End-to-End Flow (Quote -> Verify -> Credential Mint)
        // ---------------------------------------------------------------------
        let challenge_nonce = ea.issue_challenge();
        let evidence = adapter
            .quote_pcrs(&challenge_nonce, &[0, 7])
            .expect("quote_pcrs failed");
        let evidence_bytes = serde_json::to_vec(&evidence).expect("Serialization failed");

        let cred = ea
            .enroll(&challenge_nonce, 1, &evidence_bytes, &default_mint_params())
            .expect("EA enrollment must succeed with authentic TPM quote");

        assert_eq!(cred.len(), CREDENTIAL_SIZE);
        assert_eq!(cred[OFF_TIER], 3); // Tier 3 hardware-attested

        // Verify credential signature against EA Issuer public key
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&cred[OFF_SIG_R..OFF_SIG_R + 32]);
        sig_bytes[32..].copy_from_slice(&cred[OFF_SIG_S..OFF_SIG_S + 32]);
        let cred_signature = Signature::from_slice(&sig_bytes).expect("Valid signature bytes");
        let payload = &cred[..PAYLOAD_SIZE];
        assert!(
            ea_verifying_key.verify(payload, &cred_signature).is_ok(),
            "Credential signature must verify under EA issuer key"
        );

        // Test K_dev proof-of-possession signing
        let binding_message = b"zkpc_presentation_binding_challenge";
        let kdev_sig_bytes = adapter
            .sign_binding(binding_message)
            .expect("sign_binding failed");

        let mut sec1_kdev = vec![0x04];
        sec1_kdev.extend_from_slice(&kdev_pub_raw);
        let kdev_verifying_key = VerifyingKey::from_sec1_bytes(&sec1_kdev)
            .expect("K_dev public key must be valid P-256");
        let kdev_signature =
            Signature::from_slice(&kdev_sig_bytes).expect("Valid K_dev signature bytes");
        assert!(
            kdev_verifying_key
                .verify(binding_message, &kdev_signature)
                .is_ok(),
            "K_dev signature must verify over binding message"
        );

        // ---------------------------------------------------------------------
        // TEST B: Rejection Boundary - Stale / Mismatched Nonce
        // ---------------------------------------------------------------------
        let fresh_nonce = ea.issue_challenge();
        let stale_nonce = [0xFE; 32]; // Adapter signs stale nonce
        let stale_evidence = adapter
            .quote_pcrs(&stale_nonce, &[0, 7])
            .expect("Quote failed");
        let stale_bytes = serde_json::to_vec(&stale_evidence).unwrap();

        let err_nonce = ea
            .enroll(&fresh_nonce, 1, &stale_bytes, &default_mint_params())
            .unwrap_err();
        match err_nonce {
            AuthorityError::VerificationFailed(VerificationError::NonceMismatch) => {}
            other => panic!("Expected NonceMismatch, got {:?}", other),
        }

        // ---------------------------------------------------------------------
        // TEST C: Rejection Boundary - Tampered / Altered PCR Data
        // ---------------------------------------------------------------------
        let nonce_c = ea.issue_challenge();
        let mut tampered_evidence = adapter.quote_pcrs(&nonce_c, &[0, 7]).expect("Quote failed");
        // Adversary alters PCR 0 value after quote was signed
        tampered_evidence.pcr_values[0].digest[0] ^= 0xFF;
        let tampered_bytes = serde_json::to_vec(&tampered_evidence).unwrap();

        let err_pcr = ea
            .enroll(&nonce_c, 1, &tampered_bytes, &default_mint_params())
            .unwrap_err();
        match err_pcr {
            AuthorityError::VerificationFailed(VerificationError::AlteredMeasurements) => {}
            other => panic!("Expected AlteredMeasurements, got {:?}", other),
        }

        // ---------------------------------------------------------------------
        // TEST D: Rejection Boundary - Untrusted / Unenrolled AK
        // ---------------------------------------------------------------------
        let untrusted_ea = EnrollmentAuthority::new(CredentialIssuer::new(
            SigningKey::random(&mut OsRng),
            [0x02; 8],
        ));
        // Register verifier with NO enrolled AKs
        untrusted_ea.register_verifier(1, Box::new(TpmPlatformVerifier::new(posture_policy)));
        let nonce_d = untrusted_ea.issue_challenge();
        let ev_d = adapter.quote_pcrs(&nonce_d, &[0, 7]).expect("Quote failed");
        let ev_d_bytes = serde_json::to_vec(&ev_d).unwrap();

        let err_ak = untrusted_ea
            .enroll(&nonce_d, 1, &ev_d_bytes, &default_mint_params())
            .unwrap_err();
        match err_ak {
            AuthorityError::VerificationFailed(VerificationError::UntrustedKey) => {}
            other => panic!("Expected UntrustedKey, got {:?}", other),
        }
    }
}
