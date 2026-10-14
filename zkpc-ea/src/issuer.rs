// -----------------------------------------------------------------------------
// ZKPC Enrollment Authority - Credential Issuer
//
// File: zkpc-ea/src/issuer.rs
// Description: Mints and signs the canonical 256-byte ZKPC hardware credential
//              over the 192-byte payload using the EA's P-256 Issuer key.
// -----------------------------------------------------------------------------

use crate::verifier::VerifiedEvidence;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zkpc_core::credential::{
    CREDENTIAL_SIZE, OFF_EXPIRES_AT, OFF_FLAGS, OFF_FLEET_ID, OFF_ISSUED_AT, OFF_ISSUER_KEY_ID,
    OFF_KDEV_X, OFF_KDEV_Y, OFF_PLATFORM, OFF_POSTURE, OFF_REVOCATION_EPOCH, OFF_SECRET_COMMIT,
    OFF_SIG_R, OFF_SIG_S, OFF_TIER, OFF_VERSION, PAYLOAD_SIZE, SIZE_EXPIRES_AT, SIZE_FLEET_ID,
    SIZE_ISSUED_AT, SIZE_ISSUER_KEY_ID, SIZE_KDEV_X, SIZE_KDEV_Y, SIZE_POSTURE,
    SIZE_REVOCATION_EPOCH, SIZE_SECRET_COMMIT,
};

/// Parameters for minting a new credential.
#[derive(Debug, Clone)]
pub struct MintParams {
    pub fleet_id: [u8; 16],
    pub secret_commit: [u8; 64],
    pub issued_at: u32,
    pub expires_at: u32,
    pub revocation_epoch: u32,
    pub issuer_key_id: [u8; 8],
}

/// The Enrollment Authority's signing authority.
pub struct CredentialIssuer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    issuer_key_id: [u8; 8],
}

impl CredentialIssuer {
    pub fn new(signing_key: SigningKey, issuer_key_id: [u8; 8]) -> Self {
        let verifying_key = *signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            issuer_key_id,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    pub fn issuer_key_id(&self) -> [u8; 8] {
        self.issuer_key_id
    }

    /// Mints a signed 256-byte credential from verified hardware evidence and params.
    pub fn mint_credential(
        &self,
        evidence: &VerifiedEvidence,
        params: &MintParams,
    ) -> [u8; CREDENTIAL_SIZE] {
        let mut cred = [0u8; CREDENTIAL_SIZE];

        // 1. Fill 192-byte payload
        cred[OFF_VERSION] = 1;
        cred[OFF_PLATFORM] = evidence.platform as u8;
        cred[OFF_TIER] = evidence.tier as u8;
        cred[OFF_FLAGS] = evidence.flags;
        cred[OFF_POSTURE..OFF_POSTURE + SIZE_POSTURE]
            .copy_from_slice(&evidence.posture.to_be_bytes());
        cred[OFF_KDEV_X..OFF_KDEV_X + SIZE_KDEV_X].copy_from_slice(&evidence.kdev_public.0[..32]);
        cred[OFF_KDEV_Y..OFF_KDEV_Y + SIZE_KDEV_Y].copy_from_slice(&evidence.kdev_public.0[32..64]);
        cred[OFF_FLEET_ID..OFF_FLEET_ID + SIZE_FLEET_ID].copy_from_slice(&params.fleet_id);
        cred[OFF_SECRET_COMMIT..OFF_SECRET_COMMIT + SIZE_SECRET_COMMIT]
            .copy_from_slice(&params.secret_commit);
        cred[OFF_ISSUED_AT..OFF_ISSUED_AT + SIZE_ISSUED_AT]
            .copy_from_slice(&params.issued_at.to_be_bytes());
        cred[OFF_EXPIRES_AT..OFF_EXPIRES_AT + SIZE_EXPIRES_AT]
            .copy_from_slice(&params.expires_at.to_be_bytes());
        cred[OFF_REVOCATION_EPOCH..OFF_REVOCATION_EPOCH + SIZE_REVOCATION_EPOCH]
            .copy_from_slice(&params.revocation_epoch.to_be_bytes());
        cred[OFF_ISSUER_KEY_ID..OFF_ISSUER_KEY_ID + SIZE_ISSUER_KEY_ID]
            .copy_from_slice(&params.issuer_key_id);

        // 2. Hash payload with SHA-256 and sign
        let mut hasher = Sha256::new();
        hasher.update(&cred[..PAYLOAD_SIZE]);

        let signature: Signature = self.signing_key.sign(&cred[..PAYLOAD_SIZE]);
        let (r, s) = signature.split_bytes();

        // 3. Store raw 64-byte r || s at fixed offsets
        cred[OFF_SIG_R..OFF_SIG_R + 32].copy_from_slice(&r);
        cred[OFF_SIG_S..OFF_SIG_S + 32].copy_from_slice(&s);

        cred
    }
}
