// -----------------------------------------------------------------------------
// ZKPC Enrollment Authority - Service Authority
//
// File: zkpc-ea/src/authority.rs
// Description: Manages challenge nonces, routes evidence to platform verifiers,
//              coordinates credential minting, and enforces lifecycle policies:
//              single commitment per K_dev, refresh preservation, authorized
//              rotation with old-credential revocation, and authoritative bans.
// -----------------------------------------------------------------------------

use crate::issuer::{CredentialIssuer, MintParams};
use crate::verifier::{PlatformVerifier, VerificationError};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use thiserror::Error;
use zkpc_core::credential::{CREDENTIAL_SIZE, OFF_KDEV_X, OFF_KDEV_Y, SIZE_KDEV_X, SIZE_KDEV_Y};

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("Platform verifier not registered for platform ID: {0}")]
    UnsupportedPlatform(u8),
    #[error("Unknown or expired challenge nonce")]
    InvalidNonce,
    #[error("Platform evidence verification failed: {0}")]
    VerificationFailed(#[from] VerificationError),
    #[error("Device K_dev is banned by Enrollment Authority policy")]
    DeviceBanned,
    #[error("Device K_dev is already enrolled with an active commitment: {0}")]
    AlreadyEnrolled(String),
    #[error("Device K_dev is not enrolled")]
    DeviceNotEnrolled,
    #[error("Active credential for device K_dev has been revoked")]
    CredentialRevoked,
    #[error(
        "Credential refresh rejected: submitted commitment does not match existing commitment"
    )]
    CommitmentMismatchOnRefresh,
    #[error("Rotation rejected: old credential does not match active enrolled credential")]
    InvalidOldCredential,
    #[error("Credential does not belong to specified device")]
    DeviceKeyMismatch,
}

#[derive(Debug, Clone)]
pub struct EnrolledDevice {
    pub kdev_public: [u8; 64],
    pub active_commitment: [u8; 64],
    pub active_credential_hash: [u8; 32],
    pub is_active: bool,
}

/// The complete Enrollment Authority service.
pub struct EnrollmentAuthority {
    issuer: CredentialIssuer,
    verifiers: RwLock<HashMap<u8, Box<dyn PlatformVerifier>>>,
    active_nonces: RwLock<HashSet<Vec<u8>>>,
    enrolled_devices: RwLock<HashMap<[u8; 64], EnrolledDevice>>,
    banned_devices: RwLock<HashSet<[u8; 64]>>,
    revoked_credentials: RwLock<HashSet<[u8; 32]>>,
}

impl EnrollmentAuthority {
    pub fn new(issuer: CredentialIssuer) -> Self {
        Self {
            issuer,
            verifiers: RwLock::new(HashMap::new()),
            active_nonces: RwLock::new(HashSet::new()),
            enrolled_devices: RwLock::new(HashMap::new()),
            banned_devices: RwLock::new(HashSet::new()),
            revoked_credentials: RwLock::new(HashSet::new()),
        }
    }

    /// Registers a platform verifier (e.g. 1 = Linux/TPM, 3 = Apple).
    pub fn register_verifier(&self, platform_id: u8, verifier: Box<dyn PlatformVerifier>) {
        self.verifiers
            .write()
            .unwrap()
            .insert(platform_id, verifier);
    }

    /// Issues a fresh cryptographically random 32-byte challenge nonce.
    pub fn issue_challenge(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        self.active_nonces.write().unwrap().insert(nonce.clone());
        nonce
    }

    /// Bans a device by its hardware public key K_dev.
    /// The EA's refusal to renew or enroll a banned device is the authoritative ban mechanism.
    pub fn ban_device(&self, kdev: &[u8; 64]) {
        self.banned_devices.write().unwrap().insert(*kdev);
        let mut enrolled = self.enrolled_devices.write().unwrap();
        if let Some(record) = enrolled.get_mut(kdev) {
            record.is_active = false;
            self.revoked_credentials
                .write()
                .unwrap()
                .insert(record.active_credential_hash);
        }
    }

    /// Unbans a previously banned device K_dev.
    pub fn unban_device(&self, kdev: &[u8; 64]) {
        self.banned_devices.write().unwrap().remove(kdev);
    }

    /// Checks if a device K_dev is banned.
    pub fn is_banned(&self, kdev: &[u8; 64]) -> bool {
        self.banned_devices.read().unwrap().contains(kdev)
    }

    /// Checks if a credential hash is revoked.
    pub fn is_credential_revoked(&self, cred_hash: &[u8; 32]) -> bool {
        self.revoked_credentials.read().unwrap().contains(cred_hash)
    }

    /// Explicitly revokes an active credential.
    pub fn revoke_credential(&self, cred: &[u8; CREDENTIAL_SIZE]) -> Result<(), AuthorityError> {
        let mut kdev = [0u8; 64];
        kdev[..32].copy_from_slice(&cred[OFF_KDEV_X..OFF_KDEV_X + SIZE_KDEV_X]);
        kdev[32..].copy_from_slice(&cred[OFF_KDEV_Y..OFF_KDEV_Y + SIZE_KDEV_Y]);

        let cred_hash: [u8; 32] = Sha256::digest(cred).into();
        let mut revoked = self.revoked_credentials.write().unwrap();
        let mut enrolled = self.enrolled_devices.write().unwrap();
        revoked.insert(cred_hash);

        if let Some(record) = enrolled.get_mut(&kdev) {
            if record.active_credential_hash == cred_hash {
                record.is_active = false;
            }
        }
        Ok(())
    }

    /// Returns the active commitment C for an enrolled device, if any.
    pub fn get_active_commitment(&self, kdev: &[u8; 64]) -> Option<[u8; 64]> {
        let enrolled = self.enrolled_devices.read().unwrap();
        enrolled.get(kdev).and_then(|rec| {
            if rec.is_active {
                Some(rec.active_commitment)
            } else {
                None
            }
        })
    }

    /// Helper to consume and validate challenge nonce, then verify platform evidence.
    fn verify_evidence_internal(
        &self,
        challenge_nonce: &[u8],
        platform_id: u8,
        raw_evidence: &[u8],
    ) -> Result<crate::verifier::VerifiedEvidence, AuthorityError> {
        // 1. Consume and validate fresh nonce (single-use guarantee)
        {
            let mut nonces = self.active_nonces.write().unwrap();
            if !nonces.remove(challenge_nonce) {
                return Err(AuthorityError::InvalidNonce);
            }
        }

        // 2. Dispatch to registered platform verifier
        let verifiers = self.verifiers.read().unwrap();
        let verifier = verifiers
            .get(&platform_id)
            .ok_or(AuthorityError::UnsupportedPlatform(platform_id))?;

        // 3. Verify platform evidence
        let verified = verifier.verify(challenge_nonce, raw_evidence)?;
        Ok(verified)
    }

    /// Verifies device evidence and mints the canonical ZKPC credential.
    /// Enforces:
    /// - Refusal to enroll banned devices.
    /// - Exactly one active commitment C per enrolled K_dev (rejects duplicate enrollment).
    pub fn enroll(
        &self,
        challenge_nonce: &[u8],
        platform_id: u8,
        raw_evidence: &[u8],
        params: &MintParams,
    ) -> Result<[u8; CREDENTIAL_SIZE], AuthorityError> {
        let verified = self.verify_evidence_internal(challenge_nonce, platform_id, raw_evidence)?;
        let kdev = verified.kdev_public.0;

        // Policy Check 1: Authoritative ban check
        if self.is_banned(&kdev) {
            return Err(AuthorityError::DeviceBanned);
        }

        // Mint and sign credential
        let cred = self.issuer.mint_credential(&verified, params);
        let cred_hash: [u8; 32] = Sha256::digest(&cred).into();

        // Policy Check 2: Exactly one active commitment per enrolled K_dev (atomic check and insert)
        {
            let mut enrolled = self.enrolled_devices.write().unwrap();
            if let Some(record) = enrolled.get(&kdev) {
                if record.is_active {
                    let kdev_hex: String = kdev.iter().map(|b| format!("{:02x}", b)).collect();
                    return Err(AuthorityError::AlreadyEnrolled(kdev_hex));
                }
            }
            enrolled.insert(
                kdev,
                EnrolledDevice {
                    kdev_public: kdev,
                    active_commitment: params.secret_commit,
                    active_credential_hash: cred_hash,
                    is_active: true,
                },
            );
        }

        Ok(cred)
    }

    /// Credential refresh: verifies evidence and mints a refreshed credential.
    /// Enforces:
    /// - Refusal to refresh banned devices.
    /// - Retains the existing commitment C and strictly rejects replacement.
    pub fn refresh_credential(
        &self,
        challenge_nonce: &[u8],
        platform_id: u8,
        raw_evidence: &[u8],
        params: &MintParams,
    ) -> Result<[u8; CREDENTIAL_SIZE], AuthorityError> {
        let verified = self.verify_evidence_internal(challenge_nonce, platform_id, raw_evidence)?;
        let kdev = verified.kdev_public.0;

        // Policy Check 1: Authoritative ban check
        if self.is_banned(&kdev) {
            return Err(AuthorityError::DeviceBanned);
        }

        // Policy Check 2: Device must be enrolled and active
        let existing_commitment = {
            let enrolled = self.enrolled_devices.read().unwrap();
            let record = enrolled
                .get(&kdev)
                .ok_or(AuthorityError::DeviceNotEnrolled)?;
            if !record.is_active {
                return Err(AuthorityError::CredentialRevoked);
            }
            record.active_commitment
        };

        // Policy Check 3: Refresh retains existing commitment, rejects replacement
        if params.secret_commit != existing_commitment {
            return Err(AuthorityError::CommitmentMismatchOnRefresh);
        }

        // Mint refreshed credential
        let cred = self.issuer.mint_credential(&verified, params);
        let cred_hash: [u8; 32] = Sha256::digest(&cred).into();

        // Update active credential hash
        {
            let mut enrolled = self.enrolled_devices.write().unwrap();
            if let Some(record) = enrolled.get_mut(&kdev) {
                record.active_credential_hash = cred_hash;
            }
        }

        Ok(cred)
    }

    /// Commitment rotation: updates commitment C for an enrolled device.
    /// Enforces:
    /// - Refusal to rotate banned devices.
    /// - Authorized re-enrollment requiring proof and revocation of the old credential.
    pub fn rotate_commitment(
        &self,
        challenge_nonce: &[u8],
        platform_id: u8,
        raw_evidence: &[u8],
        old_cred: &[u8; CREDENTIAL_SIZE],
        new_params: &MintParams,
    ) -> Result<[u8; CREDENTIAL_SIZE], AuthorityError> {
        let verified = self.verify_evidence_internal(challenge_nonce, platform_id, raw_evidence)?;
        let kdev = verified.kdev_public.0;

        // Policy Check 1: Authoritative ban check
        if self.is_banned(&kdev) {
            return Err(AuthorityError::DeviceBanned);
        }

        // Policy Check 2: Device key in old credential must match verified evidence K_dev
        let mut old_kdev = [0u8; 64];
        old_kdev[..32].copy_from_slice(&old_cred[OFF_KDEV_X..OFF_KDEV_X + SIZE_KDEV_X]);
        old_kdev[32..].copy_from_slice(&old_cred[OFF_KDEV_Y..OFF_KDEV_Y + SIZE_KDEV_Y]);
        if old_kdev != kdev {
            return Err(AuthorityError::DeviceKeyMismatch);
        }

        // Policy Check 3: Old credential must match active enrolled credential,
        // and rotation must atomically revoke old and activate new.
        let old_hash: [u8; 32] = Sha256::digest(old_cred).into();

        // Mint new credential with rotated commitment
        let new_cred = self.issuer.mint_credential(&verified, new_params);
        let new_hash: [u8; 32] = Sha256::digest(&new_cred).into();

        {
            let mut revoked = self.revoked_credentials.write().unwrap();
            let mut enrolled = self.enrolled_devices.write().unwrap();
            let record = enrolled
                .get_mut(&kdev)
                .ok_or(AuthorityError::DeviceNotEnrolled)?;
            if !record.is_active || record.active_credential_hash != old_hash {
                return Err(AuthorityError::InvalidOldCredential);
            }

            // Atomically revoke old credential and update active enrollment
            revoked.insert(old_hash);
            record.active_commitment = new_params.secret_commit;
            record.active_credential_hash = new_hash;
            record.is_active = true;
        }

        Ok(new_cred)
    }

    pub fn issuer(&self) -> &CredentialIssuer {
        &self.issuer
    }
}
