// -----------------------------------------------------------------------------
// ZKPC Build - Hardware Attestation Core
//
// File: src/evidence/tpm.rs
// Description: TPM 2.0 Quote evidence representation and platform verifier.
//              Enforces TCG Part 2 structures (TPMS_ATTEST), replay protection,
//              AK signature verification, and PCR composite digest checks.
// -----------------------------------------------------------------------------

use crate::credential::{
    AssuranceTier, Platform, RawPublicKey, CREDENTIAL_SIZE, OFF_EXPIRES_AT, OFF_FLAGS,
    OFF_ISSUED_AT, OFF_KDEV_X, OFF_KDEV_Y, OFF_PLATFORM, OFF_POSTURE, OFF_TIER,
};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// TPM 2.0 Magic value for generated attestation structures (0xFF544347 = "\xFFTCG").
pub const TPM_GENERATED_VALUE: u32 = 0xFF544347;

/// TPM 2.0 Structure Tag for Quote attestation (0x8018 = TPM_ST_ATTEST_QUOTE).
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// TPM Hash Algorithm identifiers (TCG Algorithm Registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum TpmHashAlgorithm {
    Sha1 = 0x0004,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
}

impl TryFrom<u16> for TpmHashAlgorithm {
    type Error = TpmVerificationError;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0004 => Ok(Self::Sha1),
            0x000B => Ok(Self::Sha256),
            0x000C => Ok(Self::Sha384),
            0x000D => Ok(Self::Sha512),
            other => Err(TpmVerificationError::UnsupportedAlgorithm(other)),
        }
    }
}

/// A selected PCR index and its measured digest value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmPcrValue {
    pub index: u32,
    pub digest: Vec<u8>,
}

/// The wire evidence payload produced by the TPM adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmQuoteEvidence {
    /// Raw serialized TPMS_ATTEST structure returned by TPM2_Quote.
    pub quoted: Vec<u8>,
    /// Raw or DER-encoded TPM signature over `quoted`.
    pub signature: Vec<u8>,
    /// Discrete PCR values associated with the quote.
    pub pcr_values: Vec<TpmPcrValue>,
    /// Quoted PCR bank algorithm (e.g., SHA256).
    pub pcr_alg: TpmHashAlgorithm,
    /// Hardware-bound device key K_dev (strictly 64 bytes raw uncompressed X || Y).
    pub kdev_public: RawPublicKey,
}

/// Parsed fields of a TPMS_ATTEST quote.
#[derive(Debug, Clone)]
pub struct ParsedQuote {
    pub magic: u32,
    pub type_: u16,
    pub qualified_signer: Vec<u8>,
    pub extra_data: Vec<u8>,
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
    pub firmware_version: u64,
    pub pcr_select_alg: TpmHashAlgorithm,
    pub pcr_indices: Vec<u32>,
    pub pcr_digest: Vec<u8>,
}

/// Reference attestation policy against which quote evidence is evaluated.
#[derive(Debug, Clone)]
pub struct TpmPolicy {
    /// Expected PCR indices that must be selected in the quote.
    pub required_pcrs: Vec<u32>,
    /// Expected PCR digest or mapping of allowed digests per index.
    pub expected_pcr_values: Vec<TpmPcrValue>,
    /// Expected hash algorithm.
    pub hash_alg: TpmHashAlgorithm,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TpmVerificationError {
    #[error("Malformed TPMS_ATTEST payload: {0}")]
    MalformedAttestation(String),
    #[error("Invalid TPM magic: expected 0x{TPM_GENERATED_VALUE:08X}, got 0x{0:08X}")]
    InvalidMagic(u32),
    #[error("Invalid attestation type: expected 0x{TPM_ST_ATTEST_QUOTE:04X}, got 0x{0:04X}")]
    InvalidAttestationType(u16),
    #[error("Qualifying data mismatch (wrong nonce / stale quote)")]
    NonceMismatch,
    #[error("Unsupported hash algorithm ID: 0x{0:04X}")]
    UnsupportedAlgorithm(u16),
    #[error("PCR selection mismatch against required policy")]
    PcrSelectionMismatch,
    #[error("Composite PCR digest does not match quoted digest (altered PCR values)")]
    AlteredPcrDigest,
    #[error("PCR measurements failed policy satisfaction: {0}")]
    PolicyViolation(String),
    #[error("Invalid AK signature: {0}")]
    InvalidSignature(String),
    #[error("Untrusted or invalid AK public key")]
    InvalidKey,
}

/// Zero-copy, panic-free binary cursor for parsing TPM wire structures.
struct ByteReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], TpmVerificationError> {
        if self.offset + len > self.data.len() {
            return Err(TpmVerificationError::MalformedAttestation(format!(
                "Unexpected EOF: needed {} bytes at offset {}, available {}",
                len,
                self.offset,
                self.data.len()
            )));
        }
        let slice = &self.data[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, TpmVerificationError> {
        let slice = self.read_slice(1)?;
        Ok(slice[0])
    }

    fn read_u16(&mut self) -> Result<u16, TpmVerificationError> {
        let slice = self.read_slice(2)?;
        match slice.try_into() {
            Ok(arr) => Ok(u16::from_be_bytes(arr)),
            Err(_) => Err(TpmVerificationError::MalformedAttestation(
                "Invalid u16 slice".into(),
            )),
        }
    }

    fn read_u32(&mut self) -> Result<u32, TpmVerificationError> {
        let slice = self.read_slice(4)?;
        match slice.try_into() {
            Ok(arr) => Ok(u32::from_be_bytes(arr)),
            Err(_) => Err(TpmVerificationError::MalformedAttestation(
                "Invalid u32 slice".into(),
            )),
        }
    }

    fn read_u64(&mut self) -> Result<u64, TpmVerificationError> {
        let slice = self.read_slice(8)?;
        match slice.try_into() {
            Ok(arr) => Ok(u64::from_be_bytes(arr)),
            Err(_) => Err(TpmVerificationError::MalformedAttestation(
                "Invalid u64 slice".into(),
            )),
        }
    }

    fn read_sized_slice(&mut self) -> Result<&'a [u8], TpmVerificationError> {
        let len = self.read_u16()? as usize;
        self.read_slice(len)
    }
}

/// Parse raw TPMS_ATTEST bytes according to TPM 2.0 Part 2 specification without panicking.
pub fn parse_tpms_attest(bytes: &[u8]) -> Result<ParsedQuote, TpmVerificationError> {
    let mut reader = ByteReader::new(bytes);

    let magic = reader.read_u32()?;
    if magic != TPM_GENERATED_VALUE {
        return Err(TpmVerificationError::InvalidMagic(magic));
    }

    let type_ = reader.read_u16()?;
    if type_ != TPM_ST_ATTEST_QUOTE {
        return Err(TpmVerificationError::InvalidAttestationType(type_));
    }

    // qualifiedSigner (TPM2B_NAME: u16 len + bytes)
    let qualified_signer = reader.read_sized_slice()?.to_vec();

    // extraData (TPM2B_DATA: u16 len + bytes)
    let extra_data = reader.read_sized_slice()?.to_vec();

    // clockInfo (TPMS_CLOCK_INFO: 17 bytes)
    let clock = reader.read_u64()?;
    let reset_count = reader.read_u32()?;
    let restart_count = reader.read_u32()?;
    let safe = reader.read_u8()? != 0;

    // firmwareVersion (u64 = 8 bytes)
    let firmware_version = reader.read_u64()?;

    // TPMS_QUOTE_INFO:
    // pcrSelect: TPML_PCR_SELECTION
    let pcr_select_count = reader.read_u32()? as usize;
    if pcr_select_count == 0 {
        return Err(TpmVerificationError::MalformedAttestation(
            "Empty PCR selections".into(),
        ));
    }

    // First selection
    let hash_alg_raw = reader.read_u16()?;
    let pcr_select_alg = TpmHashAlgorithm::try_from(hash_alg_raw)?;

    let sizeof_select = reader.read_u8()? as usize;
    let pcr_bitmap = reader.read_slice(sizeof_select)?;

    let mut pcr_indices = Vec::new();
    for (byte_idx, &byte_val) in pcr_bitmap.iter().enumerate() {
        for bit in 0..8 {
            if (byte_val & (1 << bit)) != 0 {
                pcr_indices.push((byte_idx * 8 + bit) as u32);
            }
        }
    }

    // Skip any additional selections if count > 1
    for _ in 1..pcr_select_count {
        let _alg = reader.read_u16()?;
        let s = reader.read_u8()? as usize;
        let _ = reader.read_slice(s)?;
    }

    // pcrDigest (TPM2B_DIGEST: u16 len + bytes)
    let pcr_digest = reader.read_sized_slice()?.to_vec();

    Ok(ParsedQuote {
        magic,
        type_,
        qualified_signer,
        extra_data,
        clock,
        reset_count,
        restart_count,
        safe,
        firmware_version,
        pcr_select_alg,
        pcr_indices,
        pcr_digest,
    })
}

/// Compute the composite PCR digest over a sequence of PCR values in ascending order.
/// TPM 2.0 Part 1: digest = Hash(pcr_0 || pcr_1 || ... || pcr_n)
pub fn compute_composite_pcr_digest(
    mut values: Vec<TpmPcrValue>,
    alg: TpmHashAlgorithm,
) -> Result<Vec<u8>, TpmVerificationError> {
    values.sort_by_key(|v| v.index);

    match alg {
        TpmHashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            for pcr in values {
                hasher.update(&pcr.digest);
            }
            Ok(hasher.finalize().to_vec())
        }
        other => Err(TpmVerificationError::UnsupportedAlgorithm(other as u16)),
    }
}

/// Verify TPM Quote Evidence and issue normalized credential fields.
pub struct TpmQuoteVerifier;

impl TpmQuoteVerifier {
    /// Validates TPM quote evidence against expected challenge nonce, enrolled AK key, and policy.
    pub fn verify_quote(
        evidence: &TpmQuoteEvidence,
        challenge_nonce: &[u8],
        enrolled_ak: &VerifyingKey,
        policy: &TpmPolicy,
    ) -> Result<ParsedQuote, TpmVerificationError> {
        // 1. Parse TPMS_ATTEST without panicking
        let parsed = parse_tpms_attest(&evidence.quoted)?;

        // 2. Bind quote to fresh verifier challenge (replay protection)
        if parsed.extra_data != challenge_nonce {
            return Err(TpmVerificationError::NonceMismatch);
        }

        // 3. Verify AK signature over TPMS_ATTEST
        let signature = Signature::from_der(&evidence.signature)
            .or_else(|_| Signature::from_slice(&evidence.signature))
            .map_err(|e| {
                TpmVerificationError::InvalidSignature(format!("Invalid signature encoding: {e}"))
            })?;

        enrolled_ak
            .verify(&evidence.quoted, &signature)
            .map_err(|e| {
                TpmVerificationError::InvalidSignature(format!("Verification failed: {e}"))
            })?;

        // 4. Validate PCR bank and indices against policy
        if parsed.pcr_select_alg != policy.hash_alg || parsed.pcr_indices != policy.required_pcrs {
            return Err(TpmVerificationError::PcrSelectionMismatch);
        }

        // 5. Recompute composite PCR digest and verify against signed quote
        let expected_digest =
            compute_composite_pcr_digest(evidence.pcr_values.clone(), parsed.pcr_select_alg)?;
        if expected_digest != parsed.pcr_digest {
            return Err(TpmVerificationError::AlteredPcrDigest);
        }

        // 6. Evaluate PCR measurements against reference policy
        for expected in &policy.expected_pcr_values {
            let found = evidence
                .pcr_values
                .iter()
                .find(|p| p.index == expected.index);
            match found {
                Some(p) if p.digest == expected.digest => {}
                Some(_) => {
                    return Err(TpmVerificationError::PolicyViolation(format!(
                        "PCR {} measurement deviated from reference value",
                        expected.index
                    )));
                }
                None => {
                    return Err(TpmVerificationError::PolicyViolation(format!(
                        "Required PCR {} not present in measurements",
                        expected.index
                    )));
                }
            }
        }

        Ok(parsed)
    }

    /// Normalizes verified evidence into the byte-exact ZKPC credential format.
    pub fn normalize_to_credential(
        evidence: &TpmQuoteEvidence,
        posture_bits: u32,
        issued_at: u32,
        expires_at: u32,
    ) -> [u8; CREDENTIAL_SIZE] {
        let mut cred = [0u8; CREDENTIAL_SIZE];
        cred[OFF_PLATFORM] = Platform::LinuxTpm as u8;
        cred[OFF_TIER] = AssuranceTier::T3VendorAttested as u8;
        cred[OFF_FLAGS] = 1; // managed = true
        cred[OFF_POSTURE..OFF_POSTURE + 4].copy_from_slice(&posture_bits.to_be_bytes());
        cred[OFF_KDEV_X..OFF_KDEV_X + 32].copy_from_slice(&evidence.kdev_public.0[..32]);
        cred[OFF_KDEV_Y..OFF_KDEV_Y + 32].copy_from_slice(&evidence.kdev_public.0[32..64]);
        cred[OFF_ISSUED_AT..OFF_ISSUED_AT + 4].copy_from_slice(&issued_at.to_be_bytes());
        cred[OFF_EXPIRES_AT..OFF_EXPIRES_AT + 4].copy_from_slice(&expires_at.to_be_bytes());
        cred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    fn build_mock_tpms_attest(
        extra_data: &[u8],
        pcr_indices: &[u32],
        pcr_digest: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        bytes.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        let qs = b"qualified_signer_identity";
        bytes.extend_from_slice(&(qs.len() as u16).to_be_bytes());
        bytes.extend_from_slice(qs);
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

    fn sample_pcr_values() -> (Vec<TpmPcrValue>, Vec<u8>) {
        let pcr0 = TpmPcrValue {
            index: 0,
            digest: vec![0x11; 32],
        };
        let pcr7 = TpmPcrValue {
            index: 7,
            digest: vec![0x77; 32],
        };
        let values = vec![pcr0, pcr7];
        let composite =
            compute_composite_pcr_digest(values.clone(), TpmHashAlgorithm::Sha256).unwrap();
        (values, composite)
    }

    #[test]
    fn test_valid_quote_verification_and_normalization() {
        let (pcr_values, pcr_digest) = sample_pcr_values();
        let challenge_nonce = b"fresh_verifier_challenge_nonce_32b";
        let quoted = build_mock_tpms_attest(challenge_nonce, &[0, 7], &pcr_digest);

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let signature: Signature = signing_key.sign(&quoted);

        let evidence = TpmQuoteEvidence {
            quoted,
            signature: signature.to_der().as_bytes().to_vec(),
            pcr_values: pcr_values.clone(),
            pcr_alg: TpmHashAlgorithm::Sha256,
            kdev_public: RawPublicKey([0xAA; 64]),
        };

        let policy = TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: pcr_values,
            hash_alg: TpmHashAlgorithm::Sha256,
        };

        let parsed =
            TpmQuoteVerifier::verify_quote(&evidence, challenge_nonce, &verifying_key, &policy)
                .expect("Quote should verify");
        assert_eq!(parsed.extra_data, challenge_nonce);
        assert_eq!(parsed.pcr_indices, vec![0, 7]);
        assert_eq!(parsed.pcr_digest, pcr_digest);

        let cred = TpmQuoteVerifier::normalize_to_credential(&evidence, 0x00000001, 1000, 2000);
        assert_eq!(cred[OFF_PLATFORM], Platform::LinuxTpm as u8);
        assert_eq!(cred[OFF_TIER], AssuranceTier::T3VendorAttested as u8);
        assert_eq!(&cred[OFF_KDEV_X..OFF_KDEV_X + 32], &[0xAA; 32]);
    }

    #[test]
    fn test_stale_quote_wrong_nonce_rejected() {
        let (pcr_values, pcr_digest) = sample_pcr_values();
        let old_nonce = b"old_stale_nonce";
        let quoted = build_mock_tpms_attest(old_nonce, &[0, 7], &pcr_digest);

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let signature: Signature = signing_key.sign(&quoted);

        let evidence = TpmQuoteEvidence {
            quoted,
            signature: signature.to_der().as_bytes().to_vec(),
            pcr_values: pcr_values.clone(),
            pcr_alg: TpmHashAlgorithm::Sha256,
            kdev_public: RawPublicKey([0xAA; 64]),
        };

        let policy = TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: pcr_values,
            hash_alg: TpmHashAlgorithm::Sha256,
        };

        let fresh_nonce = b"fresh_challenger_nonce";
        let err = TpmQuoteVerifier::verify_quote(&evidence, fresh_nonce, &verifying_key, &policy)
            .unwrap_err();
        assert_eq!(err, TpmVerificationError::NonceMismatch);
    }

    #[test]
    fn test_altered_pcr_values_rejected() {
        let (mut pcr_values, pcr_digest) = sample_pcr_values();
        let challenge_nonce = b"challenge_nonce";
        let quoted = build_mock_tpms_attest(challenge_nonce, &[0, 7], &pcr_digest);

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let signature: Signature = signing_key.sign(&quoted);

        // Adversary tampers with PCR 7
        pcr_values[1].digest[0] ^= 0xFF;

        let evidence = TpmQuoteEvidence {
            quoted,
            signature: signature.to_der().as_bytes().to_vec(),
            pcr_values: pcr_values.clone(),
            pcr_alg: TpmHashAlgorithm::Sha256,
            kdev_public: RawPublicKey([0xAA; 64]),
        };

        let policy = TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: vec![
                TpmPcrValue {
                    index: 0,
                    digest: vec![0x11; 32],
                },
                TpmPcrValue {
                    index: 7,
                    digest: vec![0x77; 32],
                },
            ],
            hash_alg: TpmHashAlgorithm::Sha256,
        };

        let err =
            TpmQuoteVerifier::verify_quote(&evidence, challenge_nonce, &verifying_key, &policy)
                .unwrap_err();
        assert_eq!(err, TpmVerificationError::AlteredPcrDigest);
    }

    #[test]
    fn test_invalid_ak_signature_rejected() {
        let (pcr_values, pcr_digest) = sample_pcr_values();
        let challenge_nonce = b"challenge_nonce";
        let quoted = build_mock_tpms_attest(challenge_nonce, &[0, 7], &pcr_digest);

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let signature: Signature = signing_key.sign(&quoted);
        let mut sig_bytes = signature.to_der().as_bytes().to_vec();
        let last = sig_bytes.len() - 1;
        sig_bytes[last] ^= 0xFF;

        let evidence = TpmQuoteEvidence {
            quoted,
            signature: sig_bytes,
            pcr_values: pcr_values.clone(),
            pcr_alg: TpmHashAlgorithm::Sha256,
            kdev_public: RawPublicKey([0xAA; 64]),
        };

        let policy = TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: pcr_values,
            hash_alg: TpmHashAlgorithm::Sha256,
        };

        let err =
            TpmQuoteVerifier::verify_quote(&evidence, challenge_nonce, &verifying_key, &policy)
                .unwrap_err();
        match err {
            TpmVerificationError::InvalidSignature(_) => {}
            other => panic!("Expected InvalidSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_untrusted_ak_key_rejected() {
        let (pcr_values, pcr_digest) = sample_pcr_values();
        let challenge_nonce = b"challenge_nonce";
        let quoted = build_mock_tpms_attest(challenge_nonce, &[0, 7], &pcr_digest);

        let attacker_key = SigningKey::random(&mut OsRng);
        let signature: Signature = attacker_key.sign(&quoted);

        let genuine_ak = *SigningKey::random(&mut OsRng).verifying_key();

        let evidence = TpmQuoteEvidence {
            quoted,
            signature: signature.to_der().as_bytes().to_vec(),
            pcr_values: pcr_values.clone(),
            pcr_alg: TpmHashAlgorithm::Sha256,
            kdev_public: RawPublicKey([0xAA; 64]),
        };

        let policy = TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: pcr_values,
            hash_alg: TpmHashAlgorithm::Sha256,
        };

        let err = TpmQuoteVerifier::verify_quote(&evidence, challenge_nonce, &genuine_ak, &policy)
            .unwrap_err();
        match err {
            TpmVerificationError::InvalidSignature(_) => {}
            other => panic!("Expected InvalidSignature, got {:?}", other),
        }
    }

    #[test]
    fn test_unsupported_pcr_selection_rejected() {
        let (pcr_values, pcr_digest) = sample_pcr_values();
        let challenge_nonce = b"challenge_nonce";
        let quoted = build_mock_tpms_attest(challenge_nonce, &[0], &pcr_digest);

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        let signature: Signature = signing_key.sign(&quoted);

        let evidence = TpmQuoteEvidence {
            quoted,
            signature: signature.to_der().as_bytes().to_vec(),
            pcr_values: pcr_values.clone(),
            pcr_alg: TpmHashAlgorithm::Sha256,
            kdev_public: RawPublicKey([0xAA; 64]),
        };

        let policy = TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: pcr_values,
            hash_alg: TpmHashAlgorithm::Sha256,
        };

        let err =
            TpmQuoteVerifier::verify_quote(&evidence, challenge_nonce, &verifying_key, &policy)
                .unwrap_err();
        assert_eq!(err, TpmVerificationError::PcrSelectionMismatch);
    }

    #[test]
    fn test_malformed_attestation_magic_rejected() {
        let (_, pcr_digest) = sample_pcr_values();
        let mut quoted = build_mock_tpms_attest(b"nonce", &[0, 7], &pcr_digest);
        quoted[0] ^= 0x01; // corrupt TPM magic

        let err = parse_tpms_attest(&quoted).unwrap_err();
        match err {
            TpmVerificationError::InvalidMagic(_) => {}
            other => panic!("Expected InvalidMagic, got {:?}", other),
        }
    }
}
