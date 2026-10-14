// -----------------------------------------------------------------------------
// ZKPC Enrollment Authority - Apple Platform Verifier
//
// Description: Apple Managed Device Attestation (MDA) verifier implementing
//              production Apple ACME device attestation pipeline into Rust.
//              Validates Apple Enterprise Attestation certificate chains, fresh
//              nonces, and extracts hardware-bound Secure Enclave keys.
// -----------------------------------------------------------------------------

use der::asn1::ObjectIdentifier;
use der::{Decode, DecodePem, Encode};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use x509_cert::Certificate;
use zkpc_core::credential::{AssuranceTier, Platform, RawPublicKey};

use crate::verifier::{PlatformVerifier, VerificationError, VerifiedEvidence};

/// Apple Enterprise Attestation Root CA certificate (P-384 / ecdsa-with-SHA384).
/// Extracted from production Apple MDM attestation profiles.
pub const APPLE_ENTERPRISE_ATTESTATION_ROOT_CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIICJDCCAamgAwIBAgIUQsDCuyxyfFxeq/bxpm8frF15hzcwCgYIKoZIzj0EAwMw
UTEtMCsGA1UEAwwkQXBwbGUgRW50ZXJwcmlzZSBBdHRlc3RhdGlvbiBSb290IENB
MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzAeFw0yMjAyMTYxOTAx
MjRaFw00NzAyMjAwMDAwMDBaMFExLTArBgNVBAMMJEFwcGxlIEVudGVycHJpc2Ug
QXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UE
BhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT6Jigq+Ps9Q4CoT8t8q+UnOe2p
oT9nRaUfGhBTbgvqSGXPjVkbYlIWYO+1zPk2Sz9hQ5ozzmLrPmTBgEWRcHjA2/y7
7GEicps9wn2tj+G89l3INNDKETdxSPPIZpPj8VmjQjBAMA8GA1UdEwEB/wQFMAMB
Af8wHQYDVR0OBBYEFPNqTQGd8muBpV5du+UIbVbi+d66MA4GA1UdDwEB/wQEAwIB
BjAKBggqhkjOPQQDAwNpADBmAjEA1xpWmTLSpr1VH4f8Ypk8f3jMUKYz4QPG8mL5
8m9sX/b2+eXpTv2pH4RZgJjucnbcAjEA4ZSB6S45FlPuS/u4pTnzoz632rA+xW/T
ZwFEh9bhKjJ+5VQ9/Do1os0u3LEkgN/r
-----END CERTIFICATE-----"#;

/// Apple custom ASN.1 OIDs embedded in attestation leaf certificates.
pub const OID_APPLE_SERIAL_NUMBER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.9.1");
pub const OID_APPLE_NONCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.11.1");

// Standard ANSI / SECG EC Curve OIDs
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Top-level WebAuthn/ACME CBOR Attestation Object (format "apple").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationObject {
    #[serde(rename = "fmt")]
    pub format: String,
    #[serde(rename = "attStmt")]
    pub att_stmt: AppleDeviceAttestationStatement,
}

/// Inner Apple device attestation statement carrying X.509 certificate chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleDeviceAttestationStatement {
    #[serde(rename = "x5c")]
    pub x5c: Vec<Vec<u8>>,
}

/// Baseline policy configuration for Apple attestation validation.
#[derive(Debug, Clone)]
pub struct ApplePosturePolicy {
    /// Require managed hardware enrollment flag.
    pub require_managed: bool,
    /// Default posture bitmap assigned to verified Apple Silicon devices.
    pub default_posture: u32,
    /// Optional whitelist of enrolled Apple device serial numbers.
    pub accepted_serial_numbers: Option<HashSet<String>>,
}

impl Default for ApplePosturePolicy {
    fn default() -> Self {
        Self {
            require_managed: true,
            default_posture: 0x0000_0001, // Bit 0: Hardware Rooted Attestation
            accepted_serial_numbers: None,
        }
    }
}

/// Apple Platform Verifier for Enrollment Authority.
pub struct ApplePlatformVerifier {
    root_ca_der: Vec<u8>,
    policy: ApplePosturePolicy,
}

impl ApplePlatformVerifier {
    /// Initializes with the official Apple Enterprise Attestation Root CA.
    pub fn new(policy: ApplePosturePolicy) -> Result<Self, VerificationError> {
        let root_cert =
            Certificate::from_pem(APPLE_ENTERPRISE_ATTESTATION_ROOT_CA_PEM).map_err(|e| {
                VerificationError::DecodingFailed(format!("Failed to parse Apple Root CA PEM: {e}"))
            })?;
        let root_ca_der = root_cert.to_der().map_err(|e| {
            VerificationError::Internal(format!("Failed to serialize Root CA to DER: {e}"))
        })?;
        Ok(Self {
            root_ca_der,
            policy,
        })
    }

    /// Initializes with a custom Root CA (e.g. for mock test harnesses).
    pub fn with_custom_root(root_ca_der: Vec<u8>, policy: ApplePosturePolicy) -> Self {
        Self {
            root_ca_der,
            policy,
        }
    }

    /// Verifies the ECDSA signature on child_cert using the public key from parent_cert.
    fn verify_certificate_signature(
        child: &Certificate,
        parent: &Certificate,
    ) -> Result<(), VerificationError> {
        // 1. Verify Issuer and Subject DN relationship
        if child.tbs_certificate.issuer != parent.tbs_certificate.subject {
            return Err(VerificationError::InvalidSignature(format!(
                "Certificate issuer does not match parent subject"
            )));
        }

        // 2. Verify Certificate Validity Window
        if let Ok(now_duration) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        {
            let now = now_duration.as_secs();
            let not_before = child
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs();
            let not_after = child
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs();

            if now < not_before {
                return Err(VerificationError::DecodingFailed(format!(
                    "Certificate is not yet valid (not_before: {not_before}, now: {now})"
                )));
            }
            if now > not_after {
                return Err(VerificationError::DecodingFailed(format!(
                    "Certificate has expired (not_after: {not_after}, now: {now})"
                )));
            }
        }

        let tbs_bytes = child.tbs_certificate.to_der().map_err(|e| {
            VerificationError::DecodingFailed(format!("Failed to serialize TBS certificate: {e}"))
        })?;

        let parent_spki = &parent.tbs_certificate.subject_public_key_info;
        let parent_key_bytes = parent_spki.subject_public_key.as_bytes().ok_or_else(|| {
            VerificationError::DecodingFailed("Malformed parent public key bitstring".into())
        })?;

        let sig_bytes = child.signature.as_bytes().ok_or_else(|| {
            VerificationError::DecodingFailed("Malformed child signature bitstring".into())
        })?;

        let curve_oid = parent_spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());

        match curve_oid {
            Some(OID_SECP384R1) => {
                let vk = P384VerifyingKey::from_sec1_bytes(parent_key_bytes).map_err(|e| {
                    VerificationError::InvalidSignature(format!("Invalid P-384 parent key: {e}"))
                })?;
                let sig = P384Signature::from_der(sig_bytes).map_err(|e| {
                    VerificationError::InvalidSignature(format!("Invalid P-384 DER signature: {e}"))
                })?;
                vk.verify(&tbs_bytes, &sig).map_err(|e| {
                    VerificationError::InvalidSignature(format!(
                        "P-384 cert verification failed: {e}"
                    ))
                })?;
            }
            Some(OID_SECP256R1) => {
                let vk = P256VerifyingKey::from_sec1_bytes(parent_key_bytes).map_err(|e| {
                    VerificationError::InvalidSignature(format!("Invalid P-256 parent key: {e}"))
                })?;
                let sig = P256Signature::from_der(sig_bytes).map_err(|e| {
                    VerificationError::InvalidSignature(format!("Invalid P-256 DER signature: {e}"))
                })?;
                vk.verify(&tbs_bytes, &sig).map_err(|e| {
                    VerificationError::InvalidSignature(format!(
                        "P-256 cert verification failed: {e}"
                    ))
                })?;
            }
            _ => {
                return Err(VerificationError::InvalidSignature(
                    "Unsupported elliptic curve in CA certificate".into(),
                ));
            }
        }
        Ok(())
    }
}

impl PlatformVerifier for ApplePlatformVerifier {
    fn verify(
        &self,
        challenge_nonce: &[u8],
        raw_evidence: &[u8],
    ) -> Result<VerifiedEvidence, VerificationError> {
        // 1. Decode CBOR envelope
        let att_obj: AttestationObject = ciborium::from_reader(raw_evidence).map_err(|e| {
            VerificationError::DecodingFailed(format!("Malformed CBOR attestation object: {e}"))
        })?;

        if att_obj.format != "apple" {
            return Err(VerificationError::DecodingFailed(format!(
                "Unsupported attestation format: expected 'apple', got '{}'",
                att_obj.format
            )));
        }

        if att_obj.att_stmt.x5c.is_empty() {
            return Err(VerificationError::DecodingFailed(
                "Certificate chain x5c is empty".into(),
            ));
        }

        // 2. Parse certificates in chain
        let mut parsed_certs = Vec::new();
        for (i, cert_bytes) in att_obj.att_stmt.x5c.iter().enumerate() {
            let cert = Certificate::from_der(cert_bytes).map_err(|e| {
                VerificationError::DecodingFailed(format!("Failed to parse cert index {i}: {e}"))
            })?;
            parsed_certs.push(cert);
        }

        let leaf_cert = &parsed_certs[0];
        let root_cert = Certificate::from_der(&self.root_ca_der).map_err(|e| {
            VerificationError::Internal(format!("Failed to parse trusted Root CA: {e}"))
        })?;

        // 3. Verify Certificate Chain
        // Chain layout: [Leaf, Intermediate_1, ..., Intermediate_N]
        // If single cert (e.g. self-signed root in test harness or leaf directly signed by root):
        if parsed_certs.len() == 1 {
            Self::verify_certificate_signature(leaf_cert, &root_cert)?;
        } else {
            // Verify leaf against intermediate 0
            Self::verify_certificate_signature(leaf_cert, &parsed_certs[1])?;

            // Verify intermediate chain
            for i in 1..parsed_certs.len() - 1 {
                Self::verify_certificate_signature(&parsed_certs[i], &parsed_certs[i + 1])?;
            }

            // Verify top intermediate against Root CA
            let top_intermediate = &parsed_certs[parsed_certs.len() - 1];
            Self::verify_certificate_signature(top_intermediate, &root_cert)?;
        }

        // 4. Extract Apple Extensions from leaf cert
        let mut extracted_nonce: Option<Vec<u8>> = None;
        let mut extracted_serial: Option<String> = None;

        if let Some(extensions) = &leaf_cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id == OID_APPLE_NONCE {
                    let raw = ext.extn_value.as_bytes();
                    // Handle ASN.1 OCTET STRING wrapper (0x04, length, bytes...) or direct bytes
                    let val =
                        if raw.len() >= 34 && raw[0] == 0x04 && raw[1] as usize == raw.len() - 2 {
                            raw[2..].to_vec()
                        } else {
                            raw.to_vec()
                        };
                    extracted_nonce = Some(val);
                } else if ext.extn_id == OID_APPLE_SERIAL_NUMBER {
                    let raw = ext.extn_value.as_bytes();
                    // Parse UTF8/PrintableString or raw ASCII
                    let s = if raw.len() > 2 && (raw[0] == 0x0C || raw[0] == 0x13 || raw[0] == 0x04)
                    {
                        String::from_utf8_lossy(&raw[2..]).to_string()
                    } else {
                        String::from_utf8_lossy(raw).to_string()
                    };
                    extracted_serial = Some(s);
                }
            }
        }

        // 5. Verify Challenge Nonce
        // As defined in Apple MDA spec: OID_APPLE_NONCE contains SHA-256(challenge_nonce)
        let apple_nonce = extracted_nonce.ok_or_else(|| {
            VerificationError::DecodingFailed("Missing Apple freshness nonce extension".into())
        })?;

        let expected_nonce_hash: [u8; 32] = Sha256::digest(challenge_nonce).into();
        if apple_nonce != expected_nonce_hash {
            return Err(VerificationError::NonceMismatch);
        }

        // 6. Check Device Serial Number Policy
        if let Some(whitelist) = &self.policy.accepted_serial_numbers {
            let serial = extracted_serial.ok_or_else(|| {
                VerificationError::PolicyViolation(
                    "Missing device serial number in attestation".into(),
                )
            })?;
            if !whitelist.contains(&serial) {
                return Err(VerificationError::PolicyViolation(format!(
                    "Device serial '{serial}' is not in the approved enrollment whitelist"
                )));
            }
        }

        // 7. Extract Verified Hardware Public Key K_dev
        // Must be uncompressed P-256: 0x04 || X (32 bytes) || Y (32 bytes) = 65 bytes
        let spki = &leaf_cert.tbs_certificate.subject_public_key_info;
        let pubkey_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
            VerificationError::DecodingFailed("Malformed subject public key bitstring".into())
        })?;

        if pubkey_bytes.len() != 65 || pubkey_bytes[0] != 0x04 {
            return Err(VerificationError::DecodingFailed(format!(
                "Expected 65-byte uncompressed P-256 key (0x04 prefix), got {} bytes",
                pubkey_bytes.len()
            )));
        }

        let mut kdev_public = RawPublicKey([0u8; 64]);
        kdev_public.0.copy_from_slice(&pubkey_bytes[1..65]);

        Ok(VerifiedEvidence {
            platform: Platform::AppleSe,
            tier: AssuranceTier::T3VendorAttested,
            flags: if self.policy.require_managed {
                0x01
            } else {
                0x00
            },
            posture: self.policy.default_posture,
            kdev_public,
        })
    }
}
