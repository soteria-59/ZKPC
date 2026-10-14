// -----------------------------------------------------------------------------
// ZKPC Enrollment Authority - Apple Attestation Integration Tests
//
// Description: Comprehensive test harness for Apple ACME attestation.
//              Verifies honest enrollment, credential minting, and negative rejection
//              paths for nonces, untrusted CAs, and unauthorized serial numbers.
// -----------------------------------------------------------------------------

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use der::asn1::ObjectIdentifier;
use der::asn1::{Any, BitString, OctetString, Utf8StringRef};
use der::Encode;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey as P256SigningKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use zkpc_core::credential::{
    AssuranceTier, Platform, CREDENTIAL_SIZE, OFF_KDEV_X, OFF_KDEV_Y, OFF_PLATFORM, OFF_TIER,
};
use zkpc_ea::issuer::{CredentialIssuer, MintParams};
use zkpc_ea::verifier::apple::{
    AppleDeviceAttestationStatement, ApplePlatformVerifier, ApplePosturePolicy, AttestationObject,
    OID_APPLE_NONCE, OID_APPLE_SERIAL_NUMBER,
};
use zkpc_ea::verifier::VerificationError;
use zkpc_ea::{AuthorityError, EnrollmentAuthority};

const OID_ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

struct TestHarness {
    ca_cert_der: Vec<u8>,
    ca_signing_key: P256SigningKey,
}

impl TestHarness {
    fn new() -> Self {
        let ca_signing_key = P256SigningKey::random(&mut OsRng);
        let subject = Name::from_str("CN=ZKPC Test Apple Attestation CA,O=Apple Inc,C=US").unwrap();
        let serial = SerialNumber::from(1001u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();

        let pub_point = ca_signing_key.verifying_key().to_encoded_point(false);
        let pub_spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: OID_ID_EC_PUBLIC_KEY,
                parameters: Some(Any::from(OID_PRIME256V1)),
            },
            subject_public_key: BitString::from_bytes(pub_point.as_bytes()).unwrap(),
        };

        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_ECDSA_WITH_SHA256,
            parameters: None,
        };

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: serial,
            signature: sig_alg.clone(),
            issuer: subject.clone(),
            validity,
            subject,
            subject_public_key_info: pub_spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let tbs_der = tbs.to_der().expect("Encode TBS CA");
        let sig: Signature = ca_signing_key.sign(&tbs_der);
        let sig_der = sig.to_der();

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(sig_der.as_bytes()).unwrap(),
        };

        let ca_cert_der = cert.to_der().expect("DER encode CA cert");

        Self {
            ca_cert_der,
            ca_signing_key,
        }
    }

    fn build_attestation_payload(
        &self,
        device_signing_key: &P256SigningKey,
        nonce: &[u8],
        serial_number: &str,
    ) -> Vec<u8> {
        let issuer_name =
            Name::from_str("CN=ZKPC Test Apple Attestation CA,O=Apple Inc,C=US").unwrap();
        let subject = Name::from_str("CN=Apple Device Attestation Leaf,OU=Secure Enclave").unwrap();
        let serial = SerialNumber::from(2002u32);
        let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();

        let dev_point = device_signing_key.verifying_key().to_encoded_point(false);
        let dev_spki = SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: OID_ID_EC_PUBLIC_KEY,
                parameters: Some(Any::from(OID_PRIME256V1)),
            },
            subject_public_key: BitString::from_bytes(dev_point.as_bytes()).unwrap(),
        };

        let sig_alg = AlgorithmIdentifierOwned {
            oid: OID_ECDSA_WITH_SHA256,
            parameters: None,
        };

        // 1. Add Apple Nonce Extension: OID 1.2.840.113635.100.8.11.1
        let hashed_nonce: [u8; 32] = Sha256::digest(nonce).into();
        let nonce_inner_octet = OctetString::new(hashed_nonce.as_slice()).unwrap();
        let nonce_der = nonce_inner_octet.to_der().unwrap();
        let nonce_ext = Extension {
            extn_id: OID_APPLE_NONCE,
            critical: false,
            extn_value: OctetString::new(nonce_der).unwrap(),
        };

        // 2. Add Apple Serial Number Extension: OID 1.2.840.113635.100.8.9.1
        let serial_utf8 = Utf8StringRef::new(serial_number).unwrap();
        let serial_der = serial_utf8.to_der().unwrap();
        let serial_ext = Extension {
            extn_id: OID_APPLE_SERIAL_NUMBER,
            critical: false,
            extn_value: OctetString::new(serial_der).unwrap(),
        };

        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: serial,
            signature: sig_alg.clone(),
            issuer: issuer_name,
            validity,
            subject,
            subject_public_key_info: dev_spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![nonce_ext, serial_ext]),
        };

        let tbs_der = tbs.to_der().expect("Encode TBS Leaf");
        let sig: Signature = self.ca_signing_key.sign(&tbs_der);
        let sig_der = sig.to_der();

        let leaf_cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature: BitString::from_bytes(sig_der.as_bytes()).unwrap(),
        };

        let leaf_der = leaf_cert.to_der().expect("DER encode Leaf cert");

        let att_stmt = AppleDeviceAttestationStatement {
            x5c: vec![leaf_der, self.ca_cert_der.clone()],
        };
        let att_obj = AttestationObject {
            format: "apple".to_string(),
            att_stmt,
        };

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&att_obj, &mut cbor_bytes)
            .expect("Failed to encode CBOR attestation object");
        cbor_bytes
    }
}

fn test_mint_params() -> MintParams {
    MintParams {
        fleet_id: [0xAA; 16],
        secret_commit: [0xBB; 64],
        issued_at: 1000,
        expires_at: 5000,
        revocation_epoch: 1,
        issuer_key_id: [0x01; 8],
    }
}

fn setup_ea(harness: &TestHarness, policy: ApplePosturePolicy) -> EnrollmentAuthority {
    let issuer_key = P256SigningKey::random(&mut OsRng);
    let issuer = CredentialIssuer::new(issuer_key, [0x01; 8]);
    let ea = EnrollmentAuthority::new(issuer);
    let verifier = ApplePlatformVerifier::with_custom_root(harness.ca_cert_der.clone(), policy);
    ea.register_verifier(Platform::AppleSe as u8, Box::new(verifier));
    ea
}

#[test]
fn test_ea_apple_honest_enrollment_and_credential_minting() {
    let harness = TestHarness::new();
    let ea = setup_ea(&harness, ApplePosturePolicy::default());

    let nonce = ea.issue_challenge();
    let device_key = P256SigningKey::random(&mut OsRng);
    let serial = "C02G10XYZ123";

    let cbor_evidence = harness.build_attestation_payload(&device_key, &nonce, serial);

    let cred_bytes = ea
        .enroll(
            &nonce,
            Platform::AppleSe as u8,
            &cbor_evidence,
            &test_mint_params(),
        )
        .expect("Honest Apple enrollment must succeed");

    assert_eq!(cred_bytes.len(), CREDENTIAL_SIZE);
    assert_eq!(cred_bytes[OFF_PLATFORM], Platform::AppleSe as u8);
    assert_eq!(cred_bytes[OFF_TIER], AssuranceTier::T3VendorAttested as u8);

    // Verify minted credential public key matches the hardware device key
    let encoded_point = device_key.verifying_key().to_encoded_point(false);
    let expected_x = encoded_point.x().unwrap();
    let expected_y = encoded_point.y().unwrap();

    assert_eq!(&cred_bytes[OFF_KDEV_X..OFF_KDEV_X + 32], &expected_x[..]);
    assert_eq!(&cred_bytes[OFF_KDEV_Y..OFF_KDEV_Y + 32], &expected_y[..]);
}

#[test]
fn test_ea_apple_rejects_replayed_or_mismatched_nonce() {
    let harness = TestHarness::new();
    let ea = setup_ea(&harness, ApplePosturePolicy::default());

    let active_nonce = ea.issue_challenge();
    let foreign_nonce = [0x55u8; 32];
    let device_key = P256SigningKey::random(&mut OsRng);

    // Evidence built for foreign nonce presented against active nonce
    let cbor_evidence =
        harness.build_attestation_payload(&device_key, &foreign_nonce, "C02G10XYZ123");

    let res = ea.enroll(
        &active_nonce,
        Platform::AppleSe as u8,
        &cbor_evidence,
        &test_mint_params(),
    );
    match res {
        Err(AuthorityError::VerificationFailed(VerificationError::NonceMismatch)) => {}
        other => panic!("Expected NonceMismatch, got: {other:?}"),
    }
}

#[test]
fn test_ea_apple_rejects_untrusted_root_ca() {
    let trusted_harness = TestHarness::new();
    let rogue_harness = TestHarness::new(); // Separate untrusted CA

    let ea = setup_ea(&trusted_harness, ApplePosturePolicy::default());
    let nonce = ea.issue_challenge();
    let device_key = P256SigningKey::random(&mut OsRng);

    // Evidence signed by rogue harness
    let cbor_evidence =
        rogue_harness.build_attestation_payload(&device_key, &nonce, "C02G10XYZ123");

    let res = ea.enroll(
        &nonce,
        Platform::AppleSe as u8,
        &cbor_evidence,
        &test_mint_params(),
    );
    match res {
        Err(AuthorityError::VerificationFailed(VerificationError::InvalidSignature(_))) => {}
        other => panic!("Expected InvalidSignature due to untrusted root, got: {other:?}"),
    }
}

#[test]
fn test_ea_apple_rejects_unauthorized_serial_number() {
    let harness = TestHarness::new();
    let mut allowed_serials = HashSet::new();
    allowed_serials.insert("CORP_MAC_ALLOWED_001".to_string());

    let policy = ApplePosturePolicy {
        require_managed: true,
        default_posture: 0x01,
        accepted_serial_numbers: Some(allowed_serials),
    };

    let ea = setup_ea(&harness, policy);
    let nonce = ea.issue_challenge();
    let device_key = P256SigningKey::random(&mut OsRng);

    // Device serial not in whitelist
    let cbor_evidence = harness.build_attestation_payload(&device_key, &nonce, "ROGUE_MAC_999");

    let res = ea.enroll(
        &nonce,
        Platform::AppleSe as u8,
        &cbor_evidence,
        &test_mint_params(),
    );
    match res {
        Err(AuthorityError::VerificationFailed(VerificationError::PolicyViolation(_))) => {}
        other => panic!("Expected PolicyViolation for unauthorized serial, got: {other:?}"),
    }
}

#[test]
fn test_ea_apple_rejects_non_apple_format() {
    let harness = TestHarness::new();
    let ea = setup_ea(&harness, ApplePosturePolicy::default());
    let nonce = ea.issue_challenge();

    let invalid_obj = AttestationObject {
        format: "android-key".to_string(),
        att_stmt: AppleDeviceAttestationStatement { x5c: vec![] },
    };
    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&invalid_obj, &mut cbor_bytes).unwrap();

    let res = ea.enroll(
        &nonce,
        Platform::AppleSe as u8,
        &cbor_bytes,
        &test_mint_params(),
    );
    match res {
        Err(AuthorityError::VerificationFailed(VerificationError::DecodingFailed(_))) => {}
        other => panic!("Expected DecodingFailed for wrong format, got: {other:?}"),
    }
}

#[test]
fn test_ea_apple_rejects_mismatched_issuer_name() {
    let harness = TestHarness::new();
    let ea = setup_ea(&harness, ApplePosturePolicy::default());
    let nonce = ea.issue_challenge();
    let device_key = P256SigningKey::random(&mut OsRng);

    // Build leaf with forged issuer name (doesn't match CA subject)
    let fake_issuer = Name::from_str("CN=Rogue Issuer Authority,O=Unknown Corp,C=US").unwrap();
    let subject = Name::from_str("CN=Apple Device Attestation Leaf,OU=Secure Enclave").unwrap();
    let serial = SerialNumber::from(3003u32);
    let validity = Validity::from_now(Duration::from_secs(3600)).unwrap();

    let dev_point = device_key.verifying_key().to_encoded_point(false);
    let dev_spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID_ID_EC_PUBLIC_KEY,
            parameters: Some(Any::from(OID_PRIME256V1)),
        },
        subject_public_key: BitString::from_bytes(dev_point.as_bytes()).unwrap(),
    };

    let sig_alg = AlgorithmIdentifierOwned {
        oid: OID_ECDSA_WITH_SHA256,
        parameters: None,
    };

    let hashed_nonce: [u8; 32] = Sha256::digest(&nonce).into();
    let nonce_inner_octet = OctetString::new(hashed_nonce.as_slice()).unwrap();
    let nonce_der = nonce_inner_octet.to_der().unwrap();
    let nonce_ext = Extension {
        extn_id: OID_APPLE_NONCE,
        critical: false,
        extn_value: OctetString::new(nonce_der).unwrap(),
    };

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: sig_alg.clone(),
        issuer: fake_issuer, // Mismatched!
        validity,
        subject,
        subject_public_key_info: dev_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![nonce_ext]),
    };

    let tbs_der = tbs.to_der().expect("Encode TBS Leaf");
    let sig: Signature = harness.ca_signing_key.sign(&tbs_der);
    let sig_der = sig.to_der();

    let leaf_cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(sig_der.as_bytes()).unwrap(),
    };

    let leaf_der = leaf_cert.to_der().expect("DER encode Leaf cert");
    let att_stmt = AppleDeviceAttestationStatement {
        x5c: vec![leaf_der, harness.ca_cert_der.clone()],
    };
    let att_obj = AttestationObject {
        format: "apple".to_string(),
        att_stmt,
    };

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&att_obj, &mut cbor_bytes).unwrap();

    let res = ea.enroll(
        &nonce,
        Platform::AppleSe as u8,
        &cbor_bytes,
        &test_mint_params(),
    );
    match res {
        Err(AuthorityError::VerificationFailed(VerificationError::InvalidSignature(_))) => {}
        other => panic!("Expected InvalidSignature for mismatched issuer, got: {other:?}"),
    }
}
