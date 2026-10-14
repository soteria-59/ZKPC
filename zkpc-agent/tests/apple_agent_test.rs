// -----------------------------------------------------------------------------
// ZKPC Agent - Apple Platform Agent Integration Test
//
// File: zkpc-agent/tests/apple_agent_test.rs
// Description: Tests AppleAdapter key-holding and challenge signing operations,
//              verifying raw P-256 public key extraction and ECDSA binding signatures.
// -----------------------------------------------------------------------------

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use zkpc_agent::platform::apple::AppleAdapter;
use zkpc_core::evidence::KeyHolder;

#[test]
fn test_apple_adapter_key_operations_and_binding_signature() {
    let key = SigningKey::random(&mut OsRng);
    let adapter = AppleAdapter::with_key(key);

    // 1. Extract 64-byte uncompressed public key (raw X || Y)
    let pubkey_bytes = adapter.public_key().expect("Extract public key");
    assert_eq!(pubkey_bytes.len(), 64);

    let mut sec1_bytes = [0u8; 65];
    sec1_bytes[0] = 0x04;
    sec1_bytes[1..].copy_from_slice(&pubkey_bytes);

    let verifying_key =
        VerifyingKey::from_sec1_bytes(&sec1_bytes).expect("Reconstruct VerifyingKey from raw X||Y");

    // 2. Sign presentation binding challenge
    let challenge_binding = b"zkpc/binding/v1:vpn.example:challenge123";
    let sig_raw = adapter
        .sign_binding(challenge_binding)
        .expect("Sign binding");
    assert_eq!(sig_raw.len(), 64);

    // 3. Verify signature matches verifying key
    let sig = Signature::from_slice(&sig_raw).expect("Reconstruct Signature from raw r||s");

    verifying_key
        .verify(challenge_binding, &sig)
        .expect("Signature must verify against device public key");
}
