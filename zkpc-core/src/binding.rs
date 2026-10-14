//! Presentation binding: ties a proof to one verifier challenge.
//!
//! binding = SHA-256( DOMAIN || len(nonce)||nonce || len(service_id)||service_id
//!                    || len(policy_hash)||policy_hash )      (lengths are u32 big-endian)
//!
//! Length prefixes make the encoding unambiguous (("ab","c") != ("a","bc")).
//! The 32-byte result is exposed to the circuit as two 128-bit public inputs,
//! because a full 32-byte value can exceed the P-256 base field modulus.
//!
//! Note on binding constraints: the circuit exposes these limbs as public inputs,
//! and hardware-key proof-of-possession binds presentation proofs to the physical device.

use sha2::{Digest, Sha256};

pub const DOMAIN: &[u8] = b"zkpc/binding/v1";
pub const PSEUDONYM_DOMAIN: &[u8] = b"zkpc/pseudonym/v1";

pub fn binding_hash(nonce: &[u8], service_id: &[u8], policy_hash: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    for part in [nonce, service_id, policy_hash] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

pub fn service_pseudonym(software_secret: &[u8; 32], service_id: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PSEUDONYM_DOMAIN);
    h.update((software_secret.len() as u32).to_be_bytes());
    h.update(software_secret);
    h.update((service_id.len() as u32).to_be_bytes());
    h.update(service_id);
    h.finalize().into()
}

/// Splits the hash into (high, low) 128-bit big-endian halves.
pub fn split_u128(b: &[u8; 32]) -> (u128, u128) {
    let hi = u128::from_be_bytes(b[..16].try_into().unwrap());
    let lo = u128::from_be_bytes(b[16..].try_into().unwrap());
    (hi, lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // Vectors computed independently with Python hashlib.
    #[test]
    fn known_answer_vectors() {
        let nonce: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            hex(&binding_hash(&nonce, b"vpn.example", &[0xAB; 32])),
            "ea153f10498eb1797eb06b9f3bb5d68a4a6c1f0f5552175ef4016df083c7b243"
        );
        assert_eq!(
            hex(&binding_hash(b"ab", b"c", b"")),
            "3999f2a4dfae813d1aa335083097531cfbef18fa9f1f944b4388a5a4fb8e8574"
        );
        assert_eq!(
            hex(&binding_hash(b"a", b"bc", b"")),
            "f858838a809d5a48d0fc1f424e75ff0e5e690c6e599e0f389bae5d9f999541e7"
        );
    }

    #[test]
    fn concatenation_is_unambiguous() {
        assert_ne!(
            binding_hash(b"ab", b"c", b""),
            binding_hash(b"a", b"bc", b"")
        );
    }

    #[test]
    fn every_field_matters() {
        let base = binding_hash(b"n", b"s", b"p");
        assert_ne!(base, binding_hash(b"N", b"s", b"p"));
        assert_ne!(base, binding_hash(b"n", b"S", b"p"));
        assert_ne!(base, binding_hash(b"n", b"s", b"P"));
    }

    #[test]
    fn split_roundtrip() {
        let h = binding_hash(b"n", b"s", b"p");
        let (hi, lo) = split_u128(&h);
        let mut back = [0u8; 32];
        back[..16].copy_from_slice(&hi.to_be_bytes());
        back[16..].copy_from_slice(&lo.to_be_bytes());
        assert_eq!(back, h);
    }
}
