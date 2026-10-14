//! Public-value layout of the ZKPC core presentation circuit. Shared by the circuit and the
//! verifier so the two cannot drift apart silently.
//!
//! Version identifier for the presentation statement format:
pub const STATEMENT_VERSION: u32 = 2;

// Core credential facts (indices 0..6)
pub const IDX_TIER: usize = 0;
pub const IDX_KEY_ID_0: usize = 1;
pub const IDX_KEY_ID_1: usize = 2;
pub const IDX_NOW: usize = 3;
pub const IDX_MIN_EPOCH: usize = 4;
pub const IDX_BINDING_HI: usize = 5;
pub const IDX_BINDING_LO: usize = 6;
pub const NUM_CORE_PUBLICS: usize = 7;

// Legacy Presentation Layout V0 (host-computed pseudonym hash limbs)
pub const IDX_V0_PSEUDONYM_HI: usize = 7;
pub const IDX_V0_PSEUDONYM_LO: usize = 8;
pub const NUM_V0_PRESENTATION_PUBLICS: usize = 9;

// Legacy Presentation Layout V1 (in-circuit issuer public key, but old pseudonym limbs)
pub const IDX_V1_ISSUER_PK_X: usize = 9;
pub const IDX_V1_ISSUER_PK_Y: usize = 10;
pub const NUM_V1_FULL_PRESENTATION_PUBLICS: usize = 11;

// Authoritative Presentation Layout V2 (Item 4: In-circuit Issuer Key + RFC 9380 Base + Algebraic Pseudonym)
// Issuer Public Key (P-256 base field Fq)
pub const IDX_ISSUER_PK_X: usize = 7;
pub const IDX_ISSUER_PK_Y: usize = 8;
// Service Base Point P_base = hash_to_curve(DST_svc, service_id) (P-256 base field Fq)
pub const IDX_P_BASE_X: usize = 9;
pub const IDX_P_BASE_Y: usize = 10;
// Service Pseudonym Point P_svc = [s]P_base (P-256 base field Fq)
pub const IDX_P_SVC_X: usize = 11;
pub const IDX_P_SVC_Y: usize = 12;

pub const NUM_PRESENTATION_PUBLICS: usize = 13;
pub const NUM_FULL_PRESENTATION_PUBLICS: usize = 13;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_statement_v2_indices_distinct_and_contiguous() {
        let indices = [
            IDX_TIER,
            IDX_KEY_ID_0,
            IDX_KEY_ID_1,
            IDX_NOW,
            IDX_MIN_EPOCH,
            IDX_BINDING_HI,
            IDX_BINDING_LO,
            IDX_ISSUER_PK_X,
            IDX_ISSUER_PK_Y,
            IDX_P_BASE_X,
            IDX_P_BASE_Y,
            IDX_P_SVC_X,
            IDX_P_SVC_Y,
        ];

        // 1. All statement indices must be distinct
        let mut set = HashSet::new();
        for &idx in &indices {
            assert!(set.insert(idx), "Duplicate statement index found: {idx}");
        }

        // 2. Count must equal NUM_PRESENTATION_PUBLICS
        assert_eq!(indices.len(), NUM_PRESENTATION_PUBLICS);

        // 3. Max index + 1 == public count
        let max_idx = *indices.iter().max().unwrap();
        assert_eq!(
            max_idx + 1,
            NUM_PRESENTATION_PUBLICS,
            "max index + 1 must equal public count"
        );

        // 4. Strictly contiguous 0..NUM_PRESENTATION_PUBLICS
        for i in 0..NUM_PRESENTATION_PUBLICS {
            assert!(set.contains(&i), "Missing index {i} in statement layout");
        }
        println!(
            "Statement V2 indices verified distinct, contiguous, and max_idx + 1 == {}",
            NUM_PRESENTATION_PUBLICS
        );
    }
}
