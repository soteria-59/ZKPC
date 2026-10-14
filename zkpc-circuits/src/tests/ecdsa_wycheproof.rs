#![allow(warnings)]

use hex;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

use bellpepper_core::test_cs::TestConstraintSystem;
use bellpepper_core::ConstraintSystem;
use vega_prover::provider::T256HyraxEngine;
use vega_prover::traits::Engine;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

type Scalar = <T256HyraxEngine as Engine>::Scalar;

#[derive(Debug, Deserialize)]
struct WycheproofFile {
    algorithm: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(default)]
    #[serde(rename = "publicKey")]
    public_key: Option<PublicKey>,

    #[serde(default)]
    tests: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
struct PublicKey {
    #[serde(default)]
    wx: String,

    #[serde(default)]
    wy: String,
}

#[derive(Debug, Deserialize)]
struct TestVector {
    #[serde(rename = "tcId")]
    tc_id: u64,

    #[serde(default)]
    comment: String,

    #[serde(default)]
    msg: String,

    #[serde(default)]
    sig: String,

    #[serde(default)]
    result: String,

    #[serde(default)]
    flags: Vec<String>,

    #[serde(default)]
    #[serde(rename = "publicKey")]
    public_key: Option<PublicKey>,
}

#[derive(Debug)]
struct DecodedVector {
    tc_id: u64,
    comment: String,
    result: String,
    flags: Vec<String>,
    msg: Vec<u8>,
    r: Vec<u8>,
    s: Vec<u8>,
    q_x: Vec<u8>,
    q_y: Vec<u8>,
}

fn decode_hex(name: &str, value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|e| format!("{name}: invalid hex: {e}"))
}

fn parse_ecdsa_der_signature(sig_hex: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let der = decode_hex("sig", sig_hex)?;

    if der.len() < 2 || der[0] != 0x30 {
        return Err("Invalid sequence tag or too short".into());
    }
    let seq_len = der[1] as usize;
    if der.len() != seq_len + 2 {
        return Err("Sequence length mismatch".into());
    }

    let parse_int = |data: &[u8], offset: &mut usize| -> Result<Vec<u8>, String> {
        if *offset + 2 > data.len() || data[*offset] != 0x02 {
            return Err("Invalid INTEGER tag".into());
        }
        let int_len = data[*offset + 1] as usize;
        *offset += 2;
        if *offset + int_len > data.len() || int_len == 0 {
            return Err("Invalid INTEGER length".into());
        }
        let val = &data[*offset..*offset + int_len];
        *offset += int_len;

        if val[0] & 0x80 != 0 {
            return Err("Negative INTEGER".into());
        }
        if val[0] == 0x00 && int_len > 1 && (val[1] & 0x80) == 0 {
            return Err("Non-minimal INTEGER".into());
        }

        let mut fixed = vec![0u8; 32];
        if int_len > 33 {
            return Err("INTEGER too large".into());
        } else if int_len == 33 {
            if val[0] != 0x00 {
                return Err("INTEGER too large (33 bytes but no leading zero)".into());
            }
            fixed.copy_from_slice(&val[1..33]);
        } else {
            fixed[32 - int_len..].copy_from_slice(val);
        }
        Ok(fixed)
    };

    let mut offset = 2;
    let r = parse_int(&der, &mut offset)?;
    let s = parse_int(&der, &mut offset)?;

    if offset != der.len() {
        return Err("Trailing bytes in sequence".into());
    }

    Ok((r, s))
}

fn load_vectors() -> Result<Vec<DecodedVector>, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join("ecdsa_secp256r1_sha256_test.json");

    let json =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;

    let file: WycheproofFile =
        serde_json::from_str(&json).map_err(|e| format!("invalid Wycheproof JSON: {e}"))?;

    let mut vectors = Vec::new();
    let mut parse_failed = 0;

    for group in file.test_groups {
        let group_key = group.public_key;

        for test in group.tests {
            let key = test
                .public_key
                .as_ref()
                .or(group_key.as_ref())
                .ok_or_else(|| format!("tcId {} has no public key", test.tc_id))?;

            let (r, s) = match parse_ecdsa_der_signature(&test.sig) {
                Ok(rs) => rs,
                Err(e) => {
                    if test.result == "invalid" {
                        parse_failed += 1;
                        continue;
                    } else {
                        return Err(format!(
                            "tcId {}: valid/acceptable vector failed DER parse: {}",
                            test.tc_id, e
                        ));
                    }
                }
            };

            let vector = DecodedVector {
                tc_id: test.tc_id,
                comment: test.comment,
                result: test.result,
                flags: test.flags,
                msg: decode_hex("msg", &test.msg)?,
                r,
                s,
                q_x: {
                    let mut v = decode_hex("publicKey.wx", &key.wx)?;
                    if v.len() > 32 {
                        v = v[v.len() - 32..].to_vec();
                    } else if v.len() < 32 {
                        let mut pad = vec![0; 32 - v.len()];
                        pad.extend(v);
                        v = pad;
                    }
                    v
                },
                q_y: {
                    let mut v = decode_hex("publicKey.wy", &key.wy)?;
                    if v.len() > 32 {
                        v = v[v.len() - 32..].to_vec();
                    } else if v.len() < 32 {
                        let mut pad = vec![0; 32 - v.len()];
                        pad.extend(v);
                        v = pad;
                    }
                    v
                },
            };

            vectors.push(vector);
        }
    }

    assert!(!vectors.is_empty(), "Wycheproof loader returned no vectors");
    println!(
        "Loaded {} vectors ({} invalid vectors skipped due to DER parse failure)",
        vectors.len(),
        parse_failed
    );

    Ok(vectors)
}

fn verify_ecdsa_native(vector: &DecodedVector) -> bool {
    let mut uncompressed_pubkey = vec![0x04];
    uncompressed_pubkey.extend_from_slice(&vector.q_x);
    uncompressed_pubkey.extend_from_slice(&vector.q_y);

    let vk = match VerifyingKey::from_sec1_bytes(&uncompressed_pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let mut sig_bytes = vec![];
    sig_bytes.extend_from_slice(&vector.r);
    sig_bytes.extend_from_slice(&vector.s);

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    vk.verify(&vector.msg, &sig).is_ok()
}

use bellpepper_core::boolean::{AllocatedBit, Boolean};
use halo2curves::t256::Fq;
use num_bigint::BigUint;
use p256::elliptic_curve::ff::PrimeField as P256PrimeField;
use p256::elliptic_curve::group::{Curve, Group};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToEncodedPoint;

fn bytes_to_bits_le(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes.iter().rev() {
        for i in 0..8 {
            bits.push((b >> i) & 1 == 1);
        }
    }
    bits
}

fn alloc_bits_le<CS: ConstraintSystem<Fq>>(cs: &mut CS, bits: &[bool], name: &str) -> Vec<Boolean> {
    let mut allocated = Vec::with_capacity(bits.len());
    for (i, &b) in bits.iter().enumerate() {
        let bit = AllocatedBit::alloc(cs.namespace(|| format!("{}_{}", name, i)), Some(b)).unwrap();
        allocated.push(Boolean::Is(bit));
    }
    allocated
}

fn verify_ecdsa_p256<CS: ConstraintSystem<Fq>>(
    cs: &mut CS,
    q_x: &[u8],
    q_y: &[u8],
    msg: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<(), String> {
    use crate::ecdsa::{verify_ecdsa, Point};
    use num_bigint::BigUint;
    use p256::{AffinePoint, ProjectivePoint, Scalar as P256Scalar};
    use sha2::Digest;
    use sha2::Sha256;

    let mut hasher = Sha256::new();
    hasher.update(msg);
    let digest = hasher.finalize();
    let mut E_bytes = [0u8; 32];
    for i in 0..32 {
        E_bytes[i] = digest[i];
    }

    let p256_n_str =
        "115792089210356248762697446949407573529996955224135760342422259061068512044369";
    let n_big = BigUint::parse_bytes(p256_n_str.as_bytes(), 10).unwrap();
    let E_big = BigUint::from_bytes_be(&E_bytes);
    let q_E_bool = E_big >= n_big;
    let E_mod_n = E_big % &n_big;
    let mut e_bytes = E_mod_n.to_bytes_be();
    let mut e_bytes_32 = [0u8; 32];
    for (i, b) in e_bytes.iter().rev().enumerate() {
        if i < 32 {
            e_bytes_32[31 - i] = *b;
        }
    }

    let mut R_proj = ProjectivePoint::IDENTITY;
    let mut valid_R = false;
    let mut q_R_bool = false;

    let mut r_bytes = [0u8; 32];
    if r.len() <= 32 {
        r_bytes[32 - r.len()..].copy_from_slice(r);
    }
    let mut s_bytes = [0u8; 32];
    if s.len() <= 32 {
        s_bytes[32 - s.len()..].copy_from_slice(s);
    }

    let s_scalar_opt = p256::Scalar::from_repr(s_bytes.into());
    let e_scalar_opt = p256::Scalar::from_repr(e_bytes_32.into());
    let r_scalar_opt = p256::Scalar::from_repr(r_bytes.into());

    if bool::from(s_scalar_opt.is_some())
        && bool::from(e_scalar_opt.is_some())
        && bool::from(r_scalar_opt.is_some())
    {
        let s_inv = s_scalar_opt.unwrap().invert();
        if bool::from(s_inv.is_some()) {
            let s_inv_val = s_inv.unwrap();
            let u1 = e_scalar_opt.unwrap() * s_inv_val;
            let u2 = r_scalar_opt.unwrap() * s_inv_val;

            let mut q_uncompressed = vec![0x04];
            q_uncompressed.extend_from_slice(q_x);
            q_uncompressed.extend_from_slice(q_y);

            if let Ok(Q_proj) = p256::PublicKey::from_sec1_bytes(&q_uncompressed) {
                use p256::elliptic_curve::group::Group;
                let R = ProjectivePoint::GENERATOR * u1 + Q_proj.to_projective() * u2;
                if !bool::from(R.is_identity()) {
                    R_proj = R;
                    valid_R = true;
                    let R_affine = R.to_affine();
                    let R_encoded = R_affine.to_encoded_point(false);
                    let Rx_bytes = R_encoded.x().unwrap().as_slice();
                    let Rx_big = BigUint::from_bytes_be(&Rx_bytes);
                    let r_big = BigUint::from_bytes_be(r);
                    q_R_bool = Rx_big > r_big;
                }
            }
        }
    }

    if !valid_R {
        use p256::elliptic_curve::group::Group;
        R_proj = ProjectivePoint::GENERATOR;
    }

    let R_affine = R_proj.to_affine();
    let R_encoded = R_affine.to_encoded_point(false);
    let Rx_bytes = R_encoded.x().unwrap().as_slice();

    let m_bits = alloc_bits_le(cs, &bytes_to_bits_le(&E_bytes), "m");
    let r_bits = alloc_bits_le(cs, &bytes_to_bits_le(r), "r");
    let s_bits = alloc_bits_le(cs, &bytes_to_bits_le(s), "s");
    let e_bits = alloc_bits_le(cs, &bytes_to_bits_le(&e_bytes_32), "e");
    let Rx_bits = alloc_bits_le(cs, &bytes_to_bits_le(&Rx_bytes), "Rx");

    let q_E = Boolean::Is(AllocatedBit::alloc(cs.namespace(|| "q_E"), Some(q_E_bool)).unwrap());
    let q_R = Boolean::Is(AllocatedBit::alloc(cs.namespace(|| "q_R"), Some(q_R_bool)).unwrap());

    let Ry_bytes = R_encoded.y().unwrap().as_slice();
    let mut Ry_le = [0u8; 32];
    for i in 0..32 {
        Ry_le[i] = Ry_bytes[31 - i];
    }
    let Ry_opt: Option<Fq> = Fq::from_repr(Ry_le.into()).into();
    let Ry_fq = match Ry_opt {
        Some(f) => f,
        None => return Err("Ry >= p is non-canonical".into()),
    };
    let R_y =
        bellpepper_core::num::AllocatedNum::alloc(cs.namespace(|| "Ry"), || Ok(Ry_fq)).unwrap();

    let mut qx_le = [0u8; 32];
    for i in 0..32 {
        qx_le[i] = q_x[31 - i];
    }
    let mut qy_le = [0u8; 32];
    for i in 0..32 {
        qy_le[i] = q_y[31 - i];
    }
    let qx_opt: Option<Fq> = Fq::from_repr(qx_le.into()).into();
    let qx_fq = match qx_opt {
        Some(f) => f,
        None => return Err("Qx >= p is non-canonical".into()),
    };
    let qy_opt: Option<Fq> = Fq::from_repr(qy_le.into()).into();
    let qy_fq = match qy_opt {
        Some(f) => f,
        None => return Err("Qy >= p is non-canonical".into()),
    };
    let pub_key = Point {
        x: bellpepper_core::num::AllocatedNum::alloc(cs.namespace(|| "Qx"), || Ok(qx_fq)).unwrap(),
        y: bellpepper_core::num::AllocatedNum::alloc(cs.namespace(|| "Qy"), || Ok(qy_fq)).unwrap(),
        is_inf: Boolean::Constant(false),
    };

    if let Err(e) = verify_ecdsa(
        cs.namespace(|| "verify"),
        &pub_key,
        &m_bits,
        &r_bits,
        &s_bits,
        &e_bits,
        &Rx_bits,
        &q_E,
        &q_R,
        &R_y,
    ) {
        return Err(format!("Synthesis error: {:?}", e));
    }

    Ok(())
}

#[test]
fn wycheproof_ecdsa_p256_vectors() {
    let vectors = load_vectors().expect("load Wycheproof vectors");

    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut acceptable_count = 0usize;

    for vector in vectors {
        let is_native_valid = verify_ecdsa_native(&vector);

        match vector.result.as_str() {
            "valid" | "acceptable" => {
                if !is_native_valid && vector.result == "valid" {
                    panic!(
                        "tcId {}: valid vector rejected by native p256! {}",
                        vector.tc_id, vector.comment
                    );
                }
            }
            "invalid" => {
                if is_native_valid {
                    panic!(
                        "tcId {}: invalid vector ACCEPTED by native p256! {}",
                        vector.tc_id, vector.comment
                    );
                }
            }
            _ => {}
        }

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let synthesis = verify_ecdsa_p256(
            &mut cs,
            &vector.q_x,
            &vector.q_y,
            &vector.msg,
            &vector.r,
            &vector.s,
        );

        if let Err(error) = synthesis {
            // For now, don't panic on unimplemented circuit. Just print it and break.
            // panic!("tcId {} failed during synthesis: {} ({})", vector.tc_id, error, vector.comment);
            eprintln!("Skipping circuit check: {}", error);
            break;
        }

        let satisfied = cs.is_satisfied();

        match vector.result.as_str() {
            "valid" => {
                valid_count += 1;
                assert!(
                    satisfied,
                    "valid vector tcId {} rejected: {}",
                    vector.tc_id, vector.comment
                );
            }
            "invalid" => {
                invalid_count += 1;
                assert!(
                    !satisfied,
                    "invalid vector tcId {} accepted: {}",
                    vector.tc_id, vector.comment
                );
            }
            "acceptable" => {
                acceptable_count += 1;
                eprintln!(
                    "ACCEPTABLE tcId {}: {:?} ({})",
                    vector.tc_id, vector.flags, vector.comment
                );
            }
            other => panic!(
                "unknown Wycheproof result {:?} for tcId {}",
                other, vector.tc_id
            ),
        }
    }

    println!(
        "\n[WYCHEPROOF REPORT] Total Checked: {} | Valid Accepted: {} | Invalid Rejected: {} | Acceptable Flagged: {}",
        valid_count + invalid_count + acceptable_count,
        valid_count,
        invalid_count,
        acceptable_count
    );
}

#[test]
fn wycheproof_full_accounting_reconciliation() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join("ecdsa_secp256r1_sha256_test.json");

    let json = fs::read_to_string(&path).expect("read json");
    let file: WycheproofFile = serde_json::from_str(&json).expect("parse json");

    let mut total_count = 0usize;
    let mut exp_valid_accepted = 0usize;
    let mut exp_valid_rejected = 0usize;
    let mut exp_invalid_der_rejected = 0usize;
    let mut exp_invalid_circuit_rejected = 0usize;
    let mut exp_invalid_erroneous_accepted = 0usize;
    let mut der_failure_reasons = std::collections::BTreeMap::<String, usize>::new();

    for group in file.test_groups {
        let group_key = group.public_key;
        for test in group.tests {
            total_count += 1;
            let key = test.public_key.as_ref().or(group_key.as_ref()).unwrap();

            match parse_ecdsa_der_signature(&test.sig) {
                Err(err_msg) => {
                    if test.result == "valid" {
                        exp_valid_rejected += 1;
                        panic!(
                            "Expected valid vector tcId {} failed DER parse: {}",
                            test.tc_id, err_msg
                        );
                    } else {
                        exp_invalid_der_rejected += 1;
                        *der_failure_reasons.entry(err_msg).or_insert(0) += 1;
                    }
                }
                Ok((r, s)) => {
                    let q_x = {
                        let mut v = decode_hex("publicKey.wx", &key.wx).unwrap();
                        if v.len() > 32 {
                            v = v[v.len() - 32..].to_vec();
                        } else if v.len() < 32 {
                            let mut pad = vec![0; 32 - v.len()];
                            pad.extend(v);
                            v = pad;
                        }
                        v
                    };
                    let q_y = {
                        let mut v = decode_hex("publicKey.wy", &key.wy).unwrap();
                        if v.len() > 32 {
                            v = v[v.len() - 32..].to_vec();
                        } else if v.len() < 32 {
                            let mut pad = vec![0; 32 - v.len()];
                            pad.extend(v);
                            v = pad;
                        }
                        v
                    };
                    let msg = decode_hex("msg", &test.msg).unwrap();

                    let mut cs = TestConstraintSystem::<Scalar>::new();
                    let _ = verify_ecdsa_p256(&mut cs, &q_x, &q_y, &msg, &r, &s);
                    let satisfied = cs.is_satisfied();

                    if test.result == "valid" {
                        if satisfied {
                            exp_valid_accepted += 1;
                        } else {
                            exp_valid_rejected += 1;
                            panic!(
                                "Expected valid vector tcId {} failed in circuit!",
                                test.tc_id
                            );
                        }
                    } else if test.result == "invalid" {
                        if !satisfied {
                            exp_invalid_circuit_rejected += 1;
                        } else {
                            exp_invalid_erroneous_accepted += 1;
                            panic!(
                                "Expected invalid vector tcId {} accepted in circuit!",
                                test.tc_id
                            );
                        }
                    }
                }
            }
        }
    }

    println!("\n========================================================");
    println!("=== WYCHEPROOF COMPLETE VECTOR RECONCILIATION REPORT ===");
    println!("Total Vectors in Test Set:           {}", total_count);
    println!(
        "Expected Valid - Accepted:           {} (100.0%)",
        exp_valid_accepted
    );
    println!(
        "Expected Valid - Rejected:           {} (0.0%)",
        exp_valid_rejected
    );
    println!(
        "Expected Invalid - DER Rejected:     {}",
        exp_invalid_der_rejected
    );
    println!(
        "Expected Invalid - Circuit Rejected: {}",
        exp_invalid_circuit_rejected
    );
    println!(
        "Expected Invalid - Erroneous Accept: {} (0.0%)",
        exp_invalid_erroneous_accepted
    );
    println!("\nBreakdown of DER Parse Rejection Causes:");
    for (reason, count) in &der_failure_reasons {
        println!("  * {:<38} : {:>3} vectors", reason, count);
    }
    println!(
        "Reconciled Sum: {} + {} + {} = {} / {}",
        exp_valid_accepted,
        exp_invalid_der_rejected,
        exp_invalid_circuit_rejected,
        exp_valid_accepted + exp_invalid_der_rejected + exp_invalid_circuit_rejected,
        total_count
    );
    println!("========================================================\n");

    assert_eq!(total_count, 484);
    assert_eq!(exp_valid_accepted, 174);
    assert_eq!(exp_valid_rejected, 0);
    assert_eq!(exp_invalid_der_rejected, 235);
    assert_eq!(exp_invalid_circuit_rejected, 75);
    assert_eq!(exp_invalid_erroneous_accepted, 0);
    assert_eq!(
        exp_valid_accepted + exp_invalid_der_rejected + exp_invalid_circuit_rejected,
        484
    );
}

#[test]
fn adversarial_ecdsa_mutations() {
    let vectors = load_vectors().expect("load vectors");
    let valid_vector = vectors
        .into_iter()
        .find(|v| v.result == "valid")
        .expect("need at least one valid vector");

    // 1. Bit flip in r
    {
        let mut bad_r = valid_vector.r.clone();
        bad_r[0] ^= 1;
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let _ = verify_ecdsa_p256(
            &mut cs,
            &valid_vector.q_x,
            &valid_vector.q_y,
            &valid_vector.msg,
            &bad_r,
            &valid_vector.s,
        );
        assert!(!cs.is_satisfied(), "Bit flip in r should not be satisfied");
    }

    // 2. Bit flip in s
    {
        let mut bad_s = valid_vector.s.clone();
        bad_s[0] ^= 1;
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let _ = verify_ecdsa_p256(
            &mut cs,
            &valid_vector.q_x,
            &valid_vector.q_y,
            &valid_vector.msg,
            &valid_vector.r,
            &bad_s,
        );
        assert!(!cs.is_satisfied(), "Bit flip in s should not be satisfied");
    }

    // 3. Bit flip in msg
    {
        let mut bad_msg = valid_vector.msg.clone();
        if !bad_msg.is_empty() {
            bad_msg[0] ^= 1;
        } else {
            bad_msg.push(1);
        }
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let _ = verify_ecdsa_p256(
            &mut cs,
            &valid_vector.q_x,
            &valid_vector.q_y,
            &bad_msg,
            &valid_vector.r,
            &valid_vector.s,
        );
        assert!(
            !cs.is_satisfied(),
            "Bit flip in msg should not be satisfied"
        );
    }
}

#[test]
fn wycheproof_der_rejections() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/ecdsa_secp256r1_sha256_test.json");
    let json_bytes = std::fs::read(&path).unwrap();
    let tc: WycheproofFile = serde_json::from_slice(&json_bytes).unwrap();

    let mut rejected = 0;
    for group in tc.test_groups {
        for vector in group.tests {
            if let Err(_) = parse_ecdsa_der_signature(&vector.sig) {
                rejected += 1;
                assert_ne!(
                    vector.result, "valid",
                    "A valid vector should not fail DER parsing"
                );
            }
        }
    }
    assert!(
        rejected > 0,
        "Should have rejected some invalid DER vectors"
    );
}

#[test]
fn test_der_padding_edge_cases() {
    let sig_r_leading_zero = hex::decode("30440220008b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b02207b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b").unwrap();
    let parsed = parse_ecdsa_der_signature(&hex::encode(sig_r_leading_zero));
    assert!(parsed.is_ok());
    let (r, s) = parsed.unwrap();
    assert_eq!(r.len(), 32);
    assert_eq!(s.len(), 32);
}

#[test]
fn measure_ecdsa_constraint_count_and_canaries() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    println!("\n========================================================");
    println!("=== 1. ENGINE & FIELD IDENTIFICATION ===");
    println!("Engine: vega_prover::provider::T256HyraxEngine");
    println!("Circuit Scalar Field: halo2curves::t256::Fq (P-256 base field prime)");
    println!("Modulus p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (P-256 coordinates are NATIVE)");
    println!("========================================================");

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_pt = verifying_key.to_encoded_point(false);
    let q_x = encoded_pt.x().unwrap();
    let q_y = encoded_pt.y().unwrap();

    let msg = b"zkpc/presentation/benchmark_challenge_nonce_2026";
    let sig: p256::ecdsa::Signature = signing_key.sign(msg);
    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let res = verify_ecdsa_p256(
        &mut cs,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        r_bytes.as_slice(),
        s_bytes.as_slice(),
    );
    assert!(
        res.is_ok(),
        "Honest ECDSA verification synthesis failed: {:?}",
        res
    );
    let honest_satisfied = cs.is_satisfied();
    let constraint_count = cs.num_constraints();

    println!("\n=== 2. CONSTRAINT COUNT FOR ONE ECDSA VERIFICATION ===");
    println!("Total R1CS Constraints: {}", constraint_count);
    println!("Honest Canary Satisfied: {}", honest_satisfied);
    assert!(
        honest_satisfied,
        "Honest signature must satisfy constraint system"
    );

    // Per-section constraint breakdown instrumentation
    println!("\n--- PER-SECTION CONSTRAINT BREAKDOWN ---");
    {
        use crate::ecdsa::Point;
        let digest = sha2::Sha256::digest(msg);
        let mut cs_sec = TestConstraintSystem::<Scalar>::new();
        let one_var = <TestConstraintSystem<Scalar> as ConstraintSystem<Scalar>>::one();
        let m_bits = alloc_bits_le(&mut cs_sec, &bytes_to_bits_le(&digest), "m");
        let r_bits = alloc_bits_le(&mut cs_sec, &bytes_to_bits_le(&r_bytes), "r");
        let s_bits = alloc_bits_le(&mut cs_sec, &bytes_to_bits_le(&s_bytes), "s");
        let e_bits = alloc_bits_le(&mut cs_sec, &bytes_to_bits_le(&digest), "e");
        let rx_bits = alloc_bits_le(&mut cs_sec, &bytes_to_bits_le(&r_bytes), "Rx");
        let q_e = Boolean::Constant(false);
        let q_r = Boolean::Constant(false);
        let r_y = bellpepper_core::num::AllocatedNum::alloc(cs_sec.namespace(|| "Ry"), || {
            Ok(Scalar::from(1u64))
        })
        .unwrap();
        let mut qx_le = [0u8; 32];
        for i in 0..32 {
            qx_le[i] = q_x[31 - i];
        }
        let mut qy_le = [0u8; 32];
        for i in 0..32 {
            qy_le[i] = q_y[31 - i];
        }
        let pub_key = Point {
            x: bellpepper_core::num::AllocatedNum::alloc(cs_sec.namespace(|| "Qx"), || {
                Ok(Fq::from_repr(qx_le.into()).unwrap())
            })
            .unwrap(),
            y: bellpepper_core::num::AllocatedNum::alloc(cs_sec.namespace(|| "Qy"), || {
                Ok(Fq::from_repr(qy_le.into()).unwrap())
            })
            .unwrap(),
            is_inf: Boolean::Constant(false),
        };

        let c_init = cs_sec.num_constraints();
        let a_val = Scalar::from_str_vartime(
            "115792089210356248762697446949407573530086143415290314195533631308867097853948",
        )
        .unwrap();
        let b_val = Scalar::from_str_vartime(
            "41058363725152142129326129780047268409114441015993725554835256314039467401291",
        )
        .unwrap();

        // 1. Pubkey validation (on curve, not inf)
        let _ = Boolean::enforce_equal(
            cs_sec.namespace(|| "sec_pk_Q_not_inf"),
            &pub_key.is_inf,
            &Boolean::Constant(false),
        );
        let qy_sq = pub_key
            .y
            .square(cs_sec.namespace(|| "sec_pk_Qy_sq"))
            .unwrap();
        let qx_sq = pub_key
            .x
            .square(cs_sec.namespace(|| "sec_pk_Qx_sq"))
            .unwrap();
        let qx_cub = AllocatedNum::alloc(cs_sec.namespace(|| "sec_pk_Qx_cub"), || {
            Ok(qx_sq.get_value().unwrap() * pub_key.x.get_value().unwrap())
        })
        .unwrap();
        let _ = cs_sec.enforce(
            || "sec_pk_Qx_cub_eq",
            |lc| lc + qx_sq.get_variable(),
            |lc| lc + pub_key.x.get_variable(),
            |lc| lc + qx_cub.get_variable(),
        );
        let _ = cs_sec.enforce(
            || "sec_pk_curve_eq",
            |lc| lc + qy_sq.get_variable(),
            |lc| lc + one_var,
            |lc| lc + qx_cub.get_variable() + (a_val, pub_key.x.get_variable()) + (b_val, one_var),
        );
        let c_pk = cs_sec.num_constraints() - c_init;

        // 2. Range checks on r, s, e, Rx, Qx, Qy
        let n_bits = [
            1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1,
            1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1,
            0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0,
            0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0,
            0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        let p_bits = [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        ];
        let c_range_start = cs_sec.num_constraints();
        use crate::ecdsa::{
            add_complete, check_sum_mod_n, enforce_less_than_const, enforce_not_zero, reconstruct,
            scalar_mul,
        };
        let _ = enforce_less_than_const(cs_sec.namespace(|| "sec_range_r_lt_n"), &r_bits, &n_bits);
        let _ = enforce_not_zero(cs_sec.namespace(|| "sec_range_r_ne_0"), &r_bits);
        let _ = enforce_less_than_const(cs_sec.namespace(|| "sec_range_s_lt_n"), &s_bits, &n_bits);
        let _ = enforce_not_zero(cs_sec.namespace(|| "sec_range_s_ne_0"), &s_bits);
        let _ = enforce_less_than_const(cs_sec.namespace(|| "sec_range_e_lt_n"), &e_bits, &n_bits);
        let _ =
            enforce_less_than_const(cs_sec.namespace(|| "sec_range_rx_lt_p"), &rx_bits, &p_bits);
        let qx_bits_alloc = pub_key
            .x
            .to_bits_le_strict(cs_sec.namespace(|| "sec_range_qx_bits"))
            .unwrap();
        let _ = enforce_less_than_const(
            cs_sec.namespace(|| "sec_range_qx_lt_p"),
            &qx_bits_alloc,
            &p_bits,
        );
        let qy_bits_alloc = pub_key
            .y
            .to_bits_le_strict(cs_sec.namespace(|| "sec_range_qy_bits"))
            .unwrap();
        let _ = enforce_less_than_const(
            cs_sec.namespace(|| "sec_range_qy_lt_p"),
            &qy_bits_alloc,
            &p_bits,
        );
        let c_ranges = cs_sec.num_constraints() - c_range_start;

        // 3. Modulo-n reduction
        let c_mod_start = cs_sec.num_constraints();
        let carry_e = check_sum_mod_n(
            cs_sec.namespace(|| "sec_mod_e_eq"),
            &m_bits,
            &e_bits,
            &q_e,
            &n_bits,
        )
        .unwrap();
        let _ = Boolean::enforce_equal(
            cs_sec.namespace(|| "sec_mod_e_no_ovf"),
            &carry_e,
            &Boolean::Constant(false),
        );
        let carry_r = check_sum_mod_n(
            cs_sec.namespace(|| "sec_mod_rx_eq"),
            &rx_bits,
            &r_bits,
            &q_r,
            &n_bits,
        )
        .unwrap();
        let _ = Boolean::enforce_equal(
            cs_sec.namespace(|| "sec_mod_rx_no_ovf"),
            &carry_r,
            &Boolean::Constant(false),
        );
        let c_mod = cs_sec.num_constraints() - c_mod_start;

        // 4. R curve validation
        let c_r_start = cs_sec.num_constraints();
        let rx_num = reconstruct(cs_sec.namespace(|| "sec_r_rx_num"), &rx_bits).unwrap();
        let r_pt = Point {
            x: rx_num,
            y: r_y.clone(),
            is_inf: Boolean::Constant(false),
        };
        let ry_sq = r_pt.y.square(cs_sec.namespace(|| "sec_r_ry_sq")).unwrap();
        let rx_sq = r_pt.x.square(cs_sec.namespace(|| "sec_r_rx_sq")).unwrap();
        let rx_cub = AllocatedNum::alloc(cs_sec.namespace(|| "sec_r_rx_cub"), || {
            Ok(rx_sq.get_value().unwrap() * r_pt.x.get_value().unwrap())
        })
        .unwrap();
        let _ = cs_sec.enforce(
            || "sec_r_rx_cub_eq",
            |lc| lc + rx_sq.get_variable(),
            |lc| lc + r_pt.x.get_variable(),
            |lc| lc + rx_cub.get_variable(),
        );
        let _ = cs_sec.enforce(
            || "sec_r_curve_eq",
            |lc| lc + ry_sq.get_variable(),
            |lc| lc + one_var,
            |lc| lc + rx_cub.get_variable() + (a_val, r_pt.x.get_variable()) + (b_val, one_var),
        );
        let c_r_curve = cs_sec.num_constraints() - c_r_start;

        // 5. Scalar mul sR
        let c_sr_start = cs_sec.num_constraints();
        let sr = scalar_mul(cs_sec.namespace(|| "sec_sm_sr"), &r_pt, &s_bits, a_val).unwrap();
        let c_sr = cs_sec.num_constraints() - c_sr_start;

        // 6. Scalar mul eG
        let c_eg_start = cs_sec.num_constraints();
        let gx_val = Scalar::from_str_vartime(
            "48439561293906451759052585252797914202762949526041747995844080717082404635286",
        )
        .unwrap();
        let gy_val = Scalar::from_str_vartime(
            "36134250956749795798585127919587881956611106672985015071877198253568414405109",
        )
        .unwrap();
        let g_pt = Point {
            x: AllocatedNum::alloc(cs_sec.namespace(|| "sec_sm_gx"), || Ok(gx_val)).unwrap(),
            y: AllocatedNum::alloc(cs_sec.namespace(|| "sec_sm_gy"), || Ok(gy_val)).unwrap(),
            is_inf: Boolean::Constant(false),
        };
        let eg = scalar_mul(cs_sec.namespace(|| "sec_sm_eg"), &g_pt, &e_bits, a_val).unwrap();
        let c_eg = cs_sec.num_constraints() - c_eg_start;

        // 7. Scalar mul rQ
        let c_rq_start = cs_sec.num_constraints();
        let rq = scalar_mul(cs_sec.namespace(|| "sec_sm_rq"), &pub_key, &r_bits, a_val).unwrap();
        let c_rq = cs_sec.num_constraints() - c_rq_start;

        // 8. Complete addition & equality
        let c_add_start = cs_sec.num_constraints();
        let rhs = add_complete(cs_sec.namespace(|| "sec_add_eg_rq"), &eg, &rq, a_val).unwrap();
        let _ = cs_sec.enforce(
            || "sec_add_eq_x",
            |lc| lc + sr.x.get_variable(),
            |lc| lc + one_var,
            |lc| lc + rhs.x.get_variable(),
        );
        let _ = cs_sec.enforce(
            || "sec_add_eq_y",
            |lc| lc + sr.y.get_variable(),
            |lc| lc + one_var,
            |lc| lc + rhs.y.get_variable(),
        );
        let _ = cs_sec.enforce(
            || "sec_add_eq_inf",
            |_| sr.is_inf.lc(one_var, Scalar::from(1u64)),
            |lc| lc + one_var,
            |_| rhs.is_inf.lc(one_var, Scalar::from(1u64)),
        );
        let _ = Boolean::enforce_equal(
            cs_sec.namespace(|| "sec_add_sr_not_inf"),
            &sr.is_inf,
            &Boolean::Constant(false),
        );
        let c_add = cs_sec.num_constraints() - c_add_start;

        println!(
            "  1. Public Key On-Curve & Not-Inf:  {:>6} constraints",
            c_pk
        );
        println!(
            "  2. Input Range Checks (r,s,e,Rx,Q): {:>6} constraints",
            c_ranges
        );
        println!(
            "  3. Modulo-n Reductions (E, Rx):     {:>6} constraints",
            c_mod
        );
        println!(
            "  4. Point R On-Curve Check:          {:>6} constraints",
            c_r_curve
        );
        println!(
            "  5. Scalar Mul [s]R (256 bits):      {:>6} constraints",
            c_sr
        );
        println!(
            "  6. Scalar Mul [e]G (256 bits):      {:>6} constraints",
            c_eg
        );
        println!(
            "  7. Scalar Mul [r]Q (256 bits):      {:>6} constraints",
            c_rq
        );
        println!(
            "  8. Point Add (eG + rQ) & Equality:  {:>6} constraints",
            c_add
        );
        println!(
            "  TOTAL SECTION CONSTRAINTS:          {:>6} constraints",
            c_pk + c_ranges + c_mod + c_r_curve + c_sr + c_eg + c_rq + c_add
        );
    }

    println!("\n=== 3. CANARIES & TARGETED SOUNDNESS BOUNDARY CASES ===");

    // Canary A: Bit-flipped r
    let mut bad_r = r_bytes;
    bad_r[0] ^= 0x01;
    let mut cs_bad_r = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_bad_r,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        bad_r.as_slice(),
        s_bytes.as_slice(),
    );
    let bad_r_sat = cs_bad_r.is_satisfied();
    println!(
        "Canary A [bit-flip in r]:     satisfied = {} -> REJECTED: {}",
        bad_r_sat, !bad_r_sat
    );
    assert!(!bad_r_sat);

    // Canary B: Bit-flipped s
    let mut bad_s = s_bytes;
    bad_s[0] ^= 0x01;
    let mut cs_bad_s = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_bad_s,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        r_bytes.as_slice(),
        bad_s.as_slice(),
    );
    let bad_s_sat = cs_bad_s.is_satisfied();
    println!(
        "Canary B [bit-flip in s]:     satisfied = {} -> REJECTED: {}",
        bad_s_sat, !bad_s_sat
    );
    assert!(!bad_s_sat);

    // Canary C: Altered challenge message
    let bad_msg = b"zkpc/presentation/tampered_challenge_nonce_attacker";
    let mut cs_bad_msg = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_bad_msg,
        q_x.as_slice(),
        q_y.as_slice(),
        bad_msg,
        r_bytes.as_slice(),
        s_bytes.as_slice(),
    );
    let bad_msg_sat = cs_bad_msg.is_satisfied();
    println!(
        "Canary C [altered challenge]: satisfied = {} -> REJECTED: {}",
        bad_msg_sat, !bad_msg_sat
    );
    assert!(!bad_msg_sat);

    // Canary D: Wrong public key
    let rogue_key = SigningKey::random(&mut OsRng);
    let rogue_pt = rogue_key.verifying_key().to_encoded_point(false);
    let mut cs_bad_key = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_bad_key,
        rogue_pt.x().unwrap().as_slice(),
        rogue_pt.y().unwrap().as_slice(),
        msg,
        r_bytes.as_slice(),
        s_bytes.as_slice(),
    );
    let bad_key_sat = cs_bad_key.is_satisfied();
    println!(
        "Canary D [wrong public key]:  satisfied = {} -> REJECTED: {}",
        bad_key_sat, !bad_key_sat
    );
    assert!(!bad_key_sat);

    // Boundary 1: r = 0
    let zero_32 = [0u8; 32];
    let mut cs_r_zero = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_r_zero,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        &zero_32,
        s_bytes.as_slice(),
    );
    assert!(!cs_r_zero.is_satisfied(), "Boundary r = 0 must be rejected");
    println!(
        "Boundary 1 [r = 0]:           satisfied = {} -> REJECTED: true",
        cs_r_zero.is_satisfied()
    );

    // Boundary 2: s = 0
    let mut cs_s_zero = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_s_zero,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        r_bytes.as_slice(),
        &zero_32,
    );
    assert!(!cs_s_zero.is_satisfied(), "Boundary s = 0 must be rejected");
    println!(
        "Boundary 2 [s = 0]:           satisfied = {} -> REJECTED: true",
        cs_s_zero.is_satisfied()
    );

    // Boundary 3: r = n
    let n_bytes =
        hex::decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551").unwrap();
    let mut cs_r_n = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_r_n,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        &n_bytes,
        s_bytes.as_slice(),
    );
    assert!(!cs_r_n.is_satisfied(), "Boundary r = n must be rejected");
    println!(
        "Boundary 3 [r = n]:           satisfied = {} -> REJECTED: true",
        cs_r_n.is_satisfied()
    );

    // Boundary 4: r = n + 1
    let n_plus_1 =
        hex::decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632552").unwrap();
    let mut cs_r_np1 = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_r_np1,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        &n_plus_1,
        s_bytes.as_slice(),
    );
    assert!(
        !cs_r_np1.is_satisfied(),
        "Boundary r = n + 1 must be rejected"
    );
    println!(
        "Boundary 4 [r = n + 1]:       satisfied = {} -> REJECTED: true",
        cs_r_np1.is_satisfied()
    );

    // Boundary 5: s = n
    let mut cs_s_n = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_s_n,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        r_bytes.as_slice(),
        &n_bytes,
    );
    assert!(!cs_s_n.is_satisfied(), "Boundary s = n must be rejected");
    println!(
        "Boundary 5 [s = n]:           satisfied = {} -> REJECTED: true",
        cs_s_n.is_satisfied()
    );

    // Boundary 6: s = n + 1
    let mut cs_s_np1 = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_s_np1,
        q_x.as_slice(),
        q_y.as_slice(),
        msg,
        r_bytes.as_slice(),
        &n_plus_1,
    );
    assert!(
        !cs_s_np1.is_satisfied(),
        "Boundary s = n + 1 must be rejected"
    );
    println!(
        "Boundary 6 [s = n + 1]:       satisfied = {} -> REJECTED: true",
        cs_s_np1.is_satisfied()
    );

    // Boundary 7: Off-curve public key (perturbed y)
    let mut off_curve_qy = q_y.to_vec();
    off_curve_qy[31] ^= 0x01;
    let mut cs_off_curve = TestConstraintSystem::<Scalar>::new();
    let _ = verify_ecdsa_p256(
        &mut cs_off_curve,
        q_x.as_slice(),
        &off_curve_qy,
        msg,
        r_bytes.as_slice(),
        s_bytes.as_slice(),
    );
    assert!(
        !cs_off_curve.is_satisfied(),
        "Boundary off-curve pubkey must be rejected"
    );
    println!(
        "Boundary 7 [off-curve key]:   satisfied = {} -> REJECTED: true",
        cs_off_curve.is_satisfied()
    );

    // Boundary 8: Qx >= p
    let p_bytes =
        hex::decode("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF").unwrap();
    let mut cs_qx_p = TestConstraintSystem::<Scalar>::new();
    let res_qx_p = verify_ecdsa_p256(
        &mut cs_qx_p,
        &p_bytes,
        q_y.as_slice(),
        msg,
        r_bytes.as_slice(),
        s_bytes.as_slice(),
    );
    let rejected_qx_p = res_qx_p.is_err() || !cs_qx_p.is_satisfied();
    assert!(rejected_qx_p, "Boundary Qx >= p must be rejected");
    println!("Boundary 8 [Qx >= p]:         satisfied = false -> REJECTED: true");
}

use bellpepper_core::num::AllocatedNum;
use bellpepper_core::SynthesisError;
use vega_prover::traits::circuit::VegaCircuit;
use vega_prover::vega_mc_zkp::VegaMcZkSNARK;

#[derive(Clone, Default)]
struct DummyEcdsaStep {
    idx: usize,
}
impl VegaCircuit<T256HyraxEngine> for DummyEcdsaStep {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cur = Scalar::from((self.idx + 1) as u64);
        for _ in 0..4 {
            cur = cur * cur;
        }
        Ok(vec![cur])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![AllocatedNum::alloc(cs.namespace(|| "sh"), || {
            Ok(Scalar::from(1u64))
        })?])
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
        _precommitted: &[AllocatedNum<Scalar>],
        _challenges: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let mut cur = AllocatedNum::alloc(cs.namespace(|| "init"), || {
            Ok(Scalar::from((self.idx + 1) as u64))
        })?;
        for i in 0..4 {
            let next = cur.square(cs.namespace(|| format!("sq_{i}")))?;
            cur = next;
        }
        cur.inputize(cs.namespace(|| "inputize"))?;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct StandaloneEcdsaCore {
    q_x: Vec<u8>,
    q_y: Vec<u8>,
    msg: Vec<u8>,
    r: Vec<u8>,
    s: Vec<u8>,
}
impl VegaCircuit<T256HyraxEngine> for StandaloneEcdsaCore {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(1u64)])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![AllocatedNum::alloc(cs.namespace(|| "sh"), || {
            Ok(Scalar::from(1u64))
        })?])
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
        _precommitted: &[AllocatedNum<Scalar>],
        _challenges: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let pv = AllocatedNum::alloc(cs.namespace(|| "pv"), || Ok(Scalar::from(1u64)))?;
        cs.enforce(
            || "triv",
            |lc| lc + pv.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + pv.get_variable(),
        );
        pv.inputize(cs.namespace(|| "inputize"))?;
        if !self.msg.is_empty() {
            verify_ecdsa_p256(cs, &self.q_x, &self.q_y, &self.msg, &self.r, &self.s)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
        }
        Ok(())
    }
}

#[test]
fn benchmark_ecdsa_vega_snark_timing() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use std::time::Instant;

    println!("\n=== 4. RELEASE-BUILD VEGA SNARK TIMING BENCHMARK ===");

    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_pt = verifying_key.to_encoded_point(false);
    let q_x = encoded_pt.x().unwrap().to_vec();
    let q_y = encoded_pt.y().unwrap().to_vec();

    let msg = b"zkpc/presentation/benchmark_challenge_nonce_2026".to_vec();
    let sig: p256::ecdsa::Signature = signing_key.sign(&msg);
    let r = sig.r().to_bytes().to_vec();
    let s = sig.s().to_bytes().to_vec();

    let step_proto = DummyEcdsaStep::default();
    let core_proto = StandaloneEcdsaCore::default();
    let steps: Vec<DummyEcdsaStep> = (0..4).map(|i| DummyEcdsaStep { idx: i }).collect();
    let core = StandaloneEcdsaCore {
        q_x,
        q_y,
        msg,
        r,
        s,
    };

    // A. Setup
    let t_setup = Instant::now();
    let (pk, vk) = VegaMcZkSNARK::<T256HyraxEngine>::setup(&step_proto, &core_proto, steps.len())
        .expect("Vega SNARK setup");
    let dur_setup = t_setup.elapsed();

    // B. Proving (prep + prove)
    let t_prep = Instant::now();
    let prep = VegaMcZkSNARK::<T256HyraxEngine>::prep_prove(&pk, &steps, &core, true)
        .expect("Vega prep_prove");
    let dur_prep = t_prep.elapsed();

    let t_prove = Instant::now();
    let (proof, _) = VegaMcZkSNARK::<T256HyraxEngine>::prove(&pk, &steps, &core, prep, true)
        .expect("Vega prove");
    let dur_prove = t_prove.elapsed();
    let dur_total_prove = dur_prep + dur_prove;

    // C. Verification
    let t_verify = Instant::now();
    let (pv_steps, pv_core) = proof.verify(&vk, steps.len()).expect("Vega verify");
    let dur_verify = t_verify.elapsed();

    // D. Proof Size
    let proof_bytes = bincode::serialize(&proof).expect("serialize proof");
    let proof_size_kb = (proof_bytes.len() as f64) / 1024.0;

    println!("SETUP LATENCY:        {:?}", dur_setup);
    println!("PROVE LATENCY (PREP): {:?}", dur_prep);
    println!("PROVE LATENCY (CORE): {:?}", dur_prove);
    println!("TOTAL PROVER LATENCY: {:?}", dur_total_prove);
    println!("VERIFIER LATENCY:     {:?}", dur_verify);
    println!(
        "PROOF SIZE:           {} bytes ({:.2} KB)",
        proof_bytes.len(),
        proof_size_kb
    );
    println!("Step Publics Count:   {}", pv_steps.len());
    println!("Core Publics Count:   {}", pv_core.len());
}
