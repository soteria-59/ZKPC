use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::Group;
use p256::{AffinePoint, NistP256, ProjectivePoint};
use sha2::Sha256;
use thiserror::Error;

/// RFC 9380 Domain Separation Tag (DST) for ZKPC service pseudonym base point derivation.
/// Follows RFC 9380 Section 3.1 recommendation: "<application>-V<version>-<suite_id>".
pub const DST_SERVICE_BASE: &[u8] = b"ZKPC-V1-P256-SHA256-SSWU-RO-";

#[derive(Error, Debug)]
pub enum HashToCurveError {
    #[error("hash to curve failed: {0}")]
    EvaluationError(String),
    #[error("hash to curve returned point at infinity")]
    PointAtInfinity,
    #[error("canonical coordinate extraction failed")]
    EncodingError,
}

/// Hashes an arbitrary message and domain separation tag to a point on NIST P-256
/// using the standard P256_XMD:SHA-256_SSWU_RO_ ciphersuite (RFC 9380).
pub fn hash_to_curve_p256(msg: &[u8], dst: &[u8]) -> Result<ProjectivePoint, HashToCurveError> {
    <NistP256 as GroupDigest>::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[msg], &[dst])
        .map_err(|e| HashToCurveError::EvaluationError(format!("{e:?}")))
}

/// Derives the canonical service base point P_base for a given service identifier.
/// Framing: canonical `service_id` bytes directly (no redundant domain wrapping).
/// Returns (ProjectivePoint, AffinePoint, x_bytes_be, y_bytes_be).
pub fn derive_service_base(
    service_id: &[u8],
) -> Result<(ProjectivePoint, AffinePoint, [u8; 32], [u8; 32]), HashToCurveError> {
    let pt_proj = hash_to_curve_p256(service_id, DST_SERVICE_BASE)?;
    if bool::from(pt_proj.is_identity()) {
        return Err(HashToCurveError::PointAtInfinity);
    }
    let pt_affine = pt_proj.to_affine();
    let encoded = pt_affine.to_encoded_point(false);
    let x_bytes = encoded.x().ok_or(HashToCurveError::EncodingError)?;
    let y_bytes = encoded.y().ok_or(HashToCurveError::EncodingError)?;

    let mut x_arr = [0u8; 32];
    let mut y_arr = [0u8; 32];
    x_arr.copy_from_slice(&x_bytes);
    y_arr.copy_from_slice(&y_bytes);

    Ok((pt_proj, pt_affine, x_arr, y_arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Vector A: RFC 9380 Official Known-Answer Test Vectors (Appendix J.1.1)
    // Suite: P256_XMD:SHA-256_SSWU_RO_
    // DST:   QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_
    // =========================================================================
    const RFC9380_DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

    #[test]
    fn test_rfc9380_kat_vector_empty_msg() {
        let msg = b"";
        let pt = hash_to_curve_p256(msg, RFC9380_DST).expect("hash_to_curve");
        let affine = pt.to_affine();
        let enc = affine.to_encoded_point(false);
        let x_hex = hex::encode(enc.x().unwrap());
        let y_hex = hex::encode(enc.y().unwrap());

        assert_eq!(
            x_hex,
            "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4"
        );
        assert_eq!(
            y_hex,
            "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"
        );
    }

    #[test]
    fn test_rfc9380_kat_vector_abc() {
        let msg = b"abc";
        let pt = hash_to_curve_p256(msg, RFC9380_DST).expect("hash_to_curve");
        let affine = pt.to_affine();
        let enc = affine.to_encoded_point(false);
        let x_hex = hex::encode(enc.x().unwrap());
        let y_hex = hex::encode(enc.y().unwrap());

        assert_eq!(
            x_hex,
            "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f"
        );
        assert_eq!(
            y_hex,
            "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"
        );
    }

    #[test]
    fn test_rfc9380_kat_vector_abcdef0123456789() {
        let msg = b"abcdef0123456789";
        let pt = hash_to_curve_p256(msg, RFC9380_DST).expect("hash_to_curve");
        let affine = pt.to_affine();
        let enc = affine.to_encoded_point(false);
        let x_hex = hex::encode(enc.x().unwrap());
        let y_hex = hex::encode(enc.y().unwrap());

        assert_eq!(
            x_hex,
            "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80"
        );
        assert_eq!(
            y_hex,
            "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"
        );
    }

    // =========================================================================
    // Vector B: ZKPC Service DST Committed Test Vector
    // Suite:     P256_XMD:SHA-256_SSWU_RO_
    // DST:       ZKPC-V1-P256-SHA256-SSWU-RO- (31 bytes)
    // ServiceID: b"vpn.example"
    // =========================================================================
    pub const COMMITTED_VPN_SERVICE_ID: &[u8] = b"vpn.example";

    #[test]
    fn test_zkpc_committed_service_dst_vector() {
        let (_, _, x, y) =
            derive_service_base(COMMITTED_VPN_SERVICE_ID).expect("derive service base");
        let x_hex = hex::encode(x);
        let y_hex = hex::encode(y);
        println!("ZKPC Vector B (vpn.example):");
        println!("  P_base.x = {}", x_hex);
        println!("  P_base.y = {}", y_hex);

        // Compute independently via hash_to_curve_p256 to verify consistency
        let pt2 = hash_to_curve_p256(COMMITTED_VPN_SERVICE_ID, DST_SERVICE_BASE).unwrap();
        let enc2 = pt2.to_affine().to_encoded_point(false);
        assert_eq!(x_hex, hex::encode(enc2.x().unwrap()));
        assert_eq!(y_hex, hex::encode(enc2.y().unwrap()));

        assert_eq!(
            x_hex,
            "cb69da77b90768470a0d74e09e14a5dac93df5f9704968eab098f1d5657ccd40"
        );
        assert_eq!(
            y_hex,
            "de0c639d110a34fe33812a0260d099df20c0b4cd9dacd9be333daf0ad7320237"
        );
    }
}
