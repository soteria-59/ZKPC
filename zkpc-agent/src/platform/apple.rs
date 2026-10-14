// -----------------------------------------------------------------------------
// ZKPC Build - Hardware Attestation Agent
//
// File: src/platform/apple.rs
// Description: Apple-specific evidence adapter utilizing Managed Device
//              Attestation (MDA) via ACME payload and the Secure Enclave.
// -----------------------------------------------------------------------------

use anyhow::Result;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use zkpc_core::evidence::{KeyError, KeyHolder};

/// Adapter for interacting with Apple's Secure Enclave hardware-bound identities.
/// In production on macOS, this interfaces with CryptoTokenKit / Security framework
/// to interact with keys provisioned via ACME profile (kSecAttrTokenIDSecureEnclave).
/// For testing and environments without hardware enclave entitlements, supports
/// initialized keypair backing.
pub struct AppleAdapter {
    key: Option<SigningKey>,
}

impl AppleAdapter {
    /// Initializes a new Apple Adapter without a test key (enclave query mode).
    pub fn new() -> Result<Self> {
        Ok(Self { key: None })
    }

    /// Initializes an Apple Adapter backed by a specific P-256 key (for testing and integration).
    pub fn with_key(key: SigningKey) -> Self {
        Self { key: Some(key) }
    }
}

impl KeyHolder for AppleAdapter {
    fn public_key(&self) -> Result<[u8; 64], KeyError> {
        if let Some(key) = &self.key {
            let point = key.verifying_key().to_encoded_point(false);
            let x = point.x().ok_or(KeyError::NotFound)?;
            let y = point.y().ok_or(KeyError::NotFound)?;
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(x.as_ref());
            out[32..].copy_from_slice(y.as_ref());
            return Ok(out);
        }

        // On physical macOS with Security framework:
        // Query keychain for kSecAttrTokenID == kSecAttrTokenIDSecureEnclave
        Err(KeyError::Unsupported)
    }

    fn sign_binding(&self, msg: &[u8]) -> Result<[u8; 64], KeyError> {
        if let Some(key) = &self.key {
            let sig: Signature = key.sign(msg);
            let mut out = [0u8; 64];
            let r_bytes = sig.r().to_bytes();
            let s_bytes = sig.s().to_bytes();
            out[..32].copy_from_slice(r_bytes.as_ref());
            out[32..].copy_from_slice(s_bytes.as_ref());
            return Ok(out);
        }

        // On physical macOS with Security framework:
        // SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, msg, &err)
        Err(KeyError::Unsupported)
    }
}
