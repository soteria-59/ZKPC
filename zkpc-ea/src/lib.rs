// -----------------------------------------------------------------------------
// ZKPC Enrollment Authority (EA)
//
// File: zkpc-ea/src/lib.rs
// Description: Enrollment Authority server library: platform verifiers,
//              replay-protected challenge nonces, and credential issuance.
// -----------------------------------------------------------------------------

pub mod authority;
pub mod issuer;
pub mod verifier;

pub use issuer::{CredentialIssuer, MintParams};
pub use verifier::apple::{ApplePlatformVerifier, ApplePosturePolicy};
pub use verifier::tpm::{TpmPlatformVerifier, TpmPosturePolicy};
pub use verifier::{PlatformVerifier, VerificationError, VerifiedEvidence};

pub use authority::{AuthorityError, EnrollmentAuthority};
