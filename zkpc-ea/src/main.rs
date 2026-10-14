use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use zkpc_core::evidence::tpm::{TpmHashAlgorithm, TpmPolicy};
use zkpc_ea::{CredentialIssuer, EnrollmentAuthority, TpmPlatformVerifier, TpmPosturePolicy};

fn main() {
    tracing_subscriber_init();
    println!("ZKPC Enrollment Authority (EA) initialized");

    let issuer_signing_key = SigningKey::random(&mut OsRng);
    let issuer = CredentialIssuer::new(issuer_signing_key, [1u8; 8]);
    let ea = EnrollmentAuthority::new(issuer);

    let policy = TpmPosturePolicy {
        tpm_policy: TpmPolicy {
            required_pcrs: vec![0, 7],
            expected_pcr_values: vec![],
            hash_alg: TpmHashAlgorithm::Sha256,
        },
        secure_boot_pcr: 7,
        expected_secure_boot_digest: vec![0x77; 32],
    };

    ea.register_verifier(1, Box::new(TpmPlatformVerifier::new(policy)));
    println!("Platform verifiers registered: Linux/TPM (ID: 1)");
}

fn tracing_subscriber_init() {
    // Initializer stub for CLI/server logging
}
