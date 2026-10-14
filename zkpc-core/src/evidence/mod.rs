// -----------------------------------------------------------------------------
// ZKPC Build - Hardware Attestation Agent
//
// File: src/evidence/mod.rs
// Description: Defines the explicit traits for hardware attestation.
//              Splits Apple (KeyHolder only) and TPM (KeyHolder + Collector)
//              and mandates strict, constant-size formats for the ZK circuits.
// -----------------------------------------------------------------------------
pub mod tpm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    NotFound,
    AccessDenied,
    BiometricCancelled,
    Unsupported,
    Hardware(String),
}

/// A standard device key holding interface.
/// Implemented by both TPM (K_dev) and Apple (Secure Enclave).
/// This interface enforces normalized, fixed-size byte formats required by the ZK circuit.
pub trait KeyHolder {
    /// Retrieves the public portion of the hardware-bound device key.
    /// Format MUST be raw X||Y (64 bytes), with no 0x04 prefix.
    fn public_key(&self) -> Result<[u8; 64], KeyError>;

    /// Signs the device-binding message `M` using the hardware-bound key.
    /// The adapter must handle any necessary internal hashing.
    /// Format MUST be raw r||s (64 bytes big-endian), parsed from DER if necessary.
    fn sign_binding(&self, msg: &[u8]) -> Result<[u8; 64], KeyError>;
}

/// Represents the hardware-bound evidence collected by a platform adapter.
pub struct Evidence {
    pub payload: Vec<u8>,
}

pub enum EvidenceError {
    GenerationFailed(String),
    Network(String),
}

/// Evidence collection interface.
/// Implemented ONLY by TPM. (On macOS, the OS natively handles MDA evidence via ACME).
pub trait EvidenceCollector {
    /// Collects hardware evidence (e.g., EK cert, AK certify, Quote) using the EA's nonce.
    fn collect(&self, nonce: &[u8]) -> Result<Evidence, EvidenceError>;
}
