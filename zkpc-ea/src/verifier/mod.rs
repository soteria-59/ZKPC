// -----------------------------------------------------------------------------
// ZKPC Enrollment Authority - Platform Verifier Trait
//
// File: zkpc-ea/src/verifier/mod.rs
// Description: Pluggable platform verifier abstraction for the EA.
//              Separates platform evidence verification from credential issuance.
// -----------------------------------------------------------------------------

pub mod apple;
pub mod tpm;

use thiserror::Error;
use zkpc_core::credential::{AssuranceTier, Platform, RawPublicKey};

/// Normalized evidence verified by a platform-specific verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidence {
    /// Platform enum (Linux/TPM, Windows/TPM, Apple SE).
    pub platform: Platform,
    /// Assurance tier (T3, T2, T1, T0).
    pub tier: AssuranceTier,
    /// Operational flags (e.g. bit 0: managed).
    pub flags: u8,
    /// Posture measurements bitmap (e.g. secure boot active).
    pub posture: u32,
    /// Verified non-exportable hardware device key K_dev (raw X || Y, 64 bytes).
    pub kdev_public: RawPublicKey,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    #[error("Platform evidence decoding failed: {0}")]
    DecodingFailed(String),
    #[error("Replay detected: qualifying data did not match fresh challenge nonce")]
    NonceMismatch,
    #[error("Hardware attestation signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("Untrusted attestation key: key not found in enrollment registry")]
    UntrustedKey,
    #[error("PCR composite digest mismatch (measurements altered or tampered)")]
    AlteredMeasurements,
    #[error("Platform measurements failed required baseline policy: {0}")]
    PolicyViolation(String),
    #[error("Internal verifier failure: {0}")]
    Internal(String),
}

/// Pluggable verifier interface implemented per hardware platform.
pub trait PlatformVerifier: Send + Sync {
    /// Verifies hardware-specific evidence against a verifier challenge nonce.
    fn verify(
        &self,
        challenge_nonce: &[u8],
        raw_evidence: &[u8],
    ) -> Result<VerifiedEvidence, VerificationError>;
}
