// -----------------------------------------------------------------------------
// ZKPC Enrollment Authority - TPM 2.0 Platform Verifier
//
// File: zkpc-ea/src/verifier/tpm.rs
// Description: Implementation of PlatformVerifier for TPM 2.0 attestation.
//              Validates TPM2_Quote evidence, enrolled AK signatures,
//              and evaluates PCR measurements against platform policy.
// -----------------------------------------------------------------------------

use super::{PlatformVerifier, VerificationError, VerifiedEvidence};
use p256::ecdsa::VerifyingKey;
use std::collections::HashMap;
use std::sync::RwLock;
use zkpc_core::credential::{AssuranceTier, Platform};
use zkpc_core::evidence::tpm::{
    parse_tpms_attest, TpmPolicy, TpmQuoteEvidence, TpmQuoteVerifier, TpmVerificationError,
};

/// Policy mapping PCR states to posture bits.
#[derive(Debug, Clone)]
pub struct TpmPosturePolicy {
    pub tpm_policy: TpmPolicy,
    pub secure_boot_pcr: u32,
    pub expected_secure_boot_digest: Vec<u8>,
}

/// Platform verifier for TPM 2.0 evidence.
pub struct TpmPlatformVerifier {
    /// Registry of enrolled Attestation Key (AK) public keys indexed by AK qualified name / signer ID.
    enrolled_aks: RwLock<HashMap<Vec<u8>, VerifyingKey>>,
    /// Configured platform policy.
    posture_policy: TpmPosturePolicy,
}

impl TpmPlatformVerifier {
    pub fn new(posture_policy: TpmPosturePolicy) -> Self {
        Self {
            enrolled_aks: RwLock::new(HashMap::new()),
            posture_policy,
        }
    }

    /// Enrolls a trusted AK public key for a device by its qualified name.
    pub fn enroll_ak(
        &self,
        signer_id: Vec<u8>,
        ak_key: VerifyingKey,
    ) -> Result<(), VerificationError> {
        let mut map = self
            .enrolled_aks
            .write()
            .map_err(|_| VerificationError::Internal("Enrolled AK lock poisoned".into()))?;
        map.insert(signer_id, ak_key);
        Ok(())
    }
}

impl PlatformVerifier for TpmPlatformVerifier {
    fn verify(
        &self,
        challenge_nonce: &[u8],
        raw_evidence: &[u8],
    ) -> Result<VerifiedEvidence, VerificationError> {
        // 1. Decode TpmQuoteEvidence payload
        let evidence: TpmQuoteEvidence = serde_json::from_slice(raw_evidence).map_err(|e| {
            VerificationError::DecodingFailed(format!("Failed to parse TpmQuoteEvidence JSON: {e}"))
        })?;

        // 2. Parse TPMS_ATTEST without panicking to inspect qualified signer identity
        let parsed = parse_tpms_attest(&evidence.quoted)
            .map_err(|e| VerificationError::DecodingFailed(e.to_string()))?;

        // 3. Look up the specific enrolled AK mapped to this signer identity
        let aks = self
            .enrolled_aks
            .read()
            .map_err(|_| VerificationError::Internal("Enrolled AK lock poisoned".into()))?;

        let enrolled_ak = aks
            .get(&parsed.qualified_signer)
            .ok_or(VerificationError::UntrustedKey)?;

        // 4. Verify quote signature and challenge binding using zkpc-core TpmQuoteVerifier
        let _ = TpmQuoteVerifier::verify_quote(
            &evidence,
            challenge_nonce,
            enrolled_ak,
            &self.posture_policy.tpm_policy,
        )
        .map_err(|e| match e {
            TpmVerificationError::NonceMismatch => VerificationError::NonceMismatch,
            TpmVerificationError::InvalidSignature(s) => VerificationError::InvalidSignature(s),
            TpmVerificationError::AlteredPcrDigest => VerificationError::AlteredMeasurements,
            TpmVerificationError::PolicyViolation(s) => VerificationError::PolicyViolation(s),
            TpmVerificationError::InvalidKey => VerificationError::UntrustedKey,
            other => VerificationError::Internal(other.to_string()),
        })?;

        // 5. Derive posture bits from verified PCR measurements
        let mut posture_bits = 0u32;
        let sb_pcr = evidence
            .pcr_values
            .iter()
            .find(|p| p.index == self.posture_policy.secure_boot_pcr);

        if let Some(pcr) = sb_pcr {
            if pcr.digest == self.posture_policy.expected_secure_boot_digest {
                posture_bits |= 0x00000001; // Bit 0: Secure Boot active & verified
            }
        }

        Ok(VerifiedEvidence {
            platform: Platform::LinuxTpm,
            tier: AssuranceTier::T3VendorAttested,
            flags: 1, // Managed = true
            posture: posture_bits,
            kdev_public: evidence.kdev_public,
        })
    }
}
