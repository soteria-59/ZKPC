// -----------------------------------------------------------------------------
// ZKPC Platform Adapter - TPM 2.0
//
// File: zkpc-agent/src/platform/tpm.rs
// Description: TPM 2.0 platform adapter using tss-esapi.
//              Handles restricted Attestation Key (AK) generation,
//              unrestricted K_dev generation, TPM2_Quote execution over PCRs
//              (configurable, default PCR 0 and 7 for platform baseline),
//              and binding signature generation.
// -----------------------------------------------------------------------------

use anyhow::{anyhow, Context, Result};
use sha2::{Digest as ShaDigest, Sha256};
use std::sync::Mutex;
use tracing::{debug, info};
use tss_esapi::{
    abstraction::nv::read_full,
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::{EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        reserved_handles::{Hierarchy, NvAuth},
        session_handles::AuthSession,
    },
    structures::{
        Data, Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme, PcrSelectionListBuilder,
        PcrSlot, Public, PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme,
        SymmetricDefinitionObject,
    },
    tcti_ldr::TctiNameConf,
    traits::Marshall,
    Context as TpmContext,
};
use zkpc_core::credential::RawPublicKey;
use zkpc_core::evidence::tpm::{TpmHashAlgorithm, TpmPcrValue, TpmQuoteEvidence};
use zkpc_core::evidence::{Evidence, EvidenceCollector, EvidenceError, KeyError, KeyHolder};

/// Map numeric PCR index to TSS PcrSlot.
pub fn pcr_slot_from_index(idx: u32) -> Result<PcrSlot> {
    match idx {
        0 => Ok(PcrSlot::Slot0),
        1 => Ok(PcrSlot::Slot1),
        2 => Ok(PcrSlot::Slot2),
        3 => Ok(PcrSlot::Slot3),
        4 => Ok(PcrSlot::Slot4),
        5 => Ok(PcrSlot::Slot5),
        6 => Ok(PcrSlot::Slot6),
        7 => Ok(PcrSlot::Slot7),
        8 => Ok(PcrSlot::Slot8),
        9 => Ok(PcrSlot::Slot9),
        10 => Ok(PcrSlot::Slot10),
        11 => Ok(PcrSlot::Slot11),
        12 => Ok(PcrSlot::Slot12),
        13 => Ok(PcrSlot::Slot13),
        14 => Ok(PcrSlot::Slot14),
        15 => Ok(PcrSlot::Slot15),
        16 => Ok(PcrSlot::Slot16),
        17 => Ok(PcrSlot::Slot17),
        18 => Ok(PcrSlot::Slot18),
        19 => Ok(PcrSlot::Slot19),
        20 => Ok(PcrSlot::Slot20),
        21 => Ok(PcrSlot::Slot21),
        22 => Ok(PcrSlot::Slot22),
        23 => Ok(PcrSlot::Slot23),
        other => Err(anyhow!("Unsupported PCR index: {}", other)),
    }
}

fn create_ecc_public_template(restricted: bool) -> Result<Public> {
    let obj_attrs = ObjectAttributesBuilder::new()
        .with_restricted(restricted)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .build()
        .map_err(|e| anyhow!("Failed to build object attributes: {e}"))?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_ecc_scheme(
            EccScheme::create(
                EccSchemeAlgorithm::EcDsa,
                Some(HashingAlgorithm::Sha256),
                None,
            )
            .map_err(|e| anyhow!("Failed to create ECC scheme: {e}"))?,
        )
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|e| anyhow!("Failed to build ECC parameters: {e}"))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| anyhow!("Failed to build ECC public template: {e}"))
}

fn extract_raw_public_key(public: &Public) -> Result<[u8; 64]> {
    match public {
        Public::Ecc { unique, .. } => {
            let x_bytes = unique.x().as_bytes();
            let y_bytes = unique.y().as_bytes();
            if x_bytes.len() != 32 || y_bytes.len() != 32 {
                return Err(anyhow!(
                    "Unexpected coordinate length: x={}, y={}",
                    x_bytes.len(),
                    y_bytes.len()
                ));
            }
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(x_bytes);
            out[32..].copy_from_slice(y_bytes);
            Ok(out)
        }
        _ => Err(anyhow!("Expected Public::Ecc, found other algorithm")),
    }
}

pub struct TpmAdapter {
    ctx: Mutex<TpmContext>,
    ak_handle: Option<KeyHandle>,
    kdev_handle: Option<KeyHandle>,
    ak_name: Option<Vec<u8>>,
    ak_pub: Option<[u8; 64]>,
    kdev_pub: Option<[u8; 64]>,
}

impl TpmAdapter {
    /// Creates a new adapter, initializing connection to TPM via environment or default URI.
    pub fn new(tcti_uri: &str) -> Result<Self> {
        let conf = TctiNameConf::from_environment_variable()
            .unwrap_or_else(|_| tcti_uri.parse().expect("Invalid TCTI URI"));
        let mut ctx = TpmContext::new(conf).context("Failed to connect to TPM")?;
        ctx.set_sessions((Some(AuthSession::Password), None, None));
        Ok(Self {
            ctx: Mutex::new(ctx),
            ak_handle: None,
            kdev_handle: None,
            ak_name: None,
            ak_pub: None,
            kdev_pub: None,
        })
    }

    /// Read ECC Endorsement Key certificate from standard NV index.
    pub fn read_ek_cert(&self) -> Result<Vec<u8>> {
        let mut ctx = self.ctx.lock().map_err(|_| anyhow!("TPM lock poisoned"))?;
        let ecc_index = NvIndexTpmHandle::new(0x01C0000A).context("Invalid ECC EK index")?;
        read_full(&mut ctx, NvAuth::Owner, ecc_index).context("Failed to read ECC EK cert")
    }

    /// Creates a restricted P-256 Attestation Key (AK) under Owner hierarchy.
    pub fn create_ak(&mut self) -> Result<(Vec<u8>, [u8; 64])> {
        debug!("Creating restricted ECC P-256 AK");
        let mut ctx = self.ctx.lock().map_err(|_| anyhow!("TPM lock poisoned"))?;
        let ak_template = create_ecc_public_template(true)?;

        let res = ctx
            .create_primary(Hierarchy::Owner, ak_template, None, None, None, None)
            .context("Failed to create AK primary key")?;

        let key_handle = res.key_handle;
        let (_pub, _name, qualified_name) = ctx
            .execute_without_session(|c| c.read_public(key_handle))
            .context("Failed to read AK qualified name")?;
        let ak_name = qualified_name.value().to_vec();
        let ak_pub = extract_raw_public_key(&res.out_public)?;

        self.ak_handle = Some(key_handle);
        self.ak_name = Some(ak_name.clone());
        self.ak_pub = Some(ak_pub);

        info!("Created AK with signer name ({} bytes)", ak_name.len());
        Ok((ak_name, ak_pub))
    }

    /// Creates an unrestricted P-256 device key (K_dev) under Owner hierarchy.
    pub fn create_kdev(&mut self) -> Result<[u8; 64]> {
        debug!("Creating unrestricted ECC P-256 K_dev");
        let mut ctx = self.ctx.lock().map_err(|_| anyhow!("TPM lock poisoned"))?;
        let kdev_template = create_ecc_public_template(false)?;

        let res = ctx
            .create_primary(Hierarchy::Owner, kdev_template, None, None, None, None)
            .context("Failed to create K_dev primary key")?;

        let key_handle = res.key_handle;
        let kdev_pub = extract_raw_public_key(&res.out_public)?;

        self.kdev_handle = Some(key_handle);
        self.kdev_pub = Some(kdev_pub);

        info!("Created K_dev public key");
        Ok(kdev_pub)
    }

    pub fn ak_name(&self) -> Option<&[u8]> {
        self.ak_name.as_deref()
    }

    pub fn ak_public(&self) -> Option<[u8; 64]> {
        self.ak_pub
    }

    pub fn kdev_public(&self) -> Option<[u8; 64]> {
        self.kdev_pub
    }

    /// Executes TPM2_Quote over specified PCRs and binds to the challenge nonce.
    pub fn quote_pcrs(&self, nonce: &[u8], pcr_indices: &[u32]) -> Result<TpmQuoteEvidence> {
        let mut ctx = self.ctx.lock().map_err(|_| anyhow!("TPM lock poisoned"))?;
        let ak_handle = self
            .ak_handle
            .ok_or_else(|| anyhow!("AK has not been created"))?;
        let kdev_pub = self
            .kdev_pub
            .ok_or_else(|| anyhow!("K_dev has not been created"))?;

        let mut slots = Vec::new();
        for &idx in pcr_indices {
            slots.push(pcr_slot_from_index(idx)?);
        }

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &slots)
            .build()
            .map_err(|e| anyhow!("Failed to build PCR selection: {e}"))?;

        let qualifying_data = Data::from_bytes(nonce)
            .map_err(|e| anyhow!("Invalid qualifying data/nonce for TPM: {e}"))?;

        // 1. TPM2_Quote
        let (attest, signature) = ctx
            .quote(
                ak_handle,
                qualifying_data,
                SignatureScheme::Null,
                pcr_selection_list.clone(),
            )
            .context("TPM2_Quote execution failed")?;

        // 2. Read discrete PCR values (PCR_Read requires NO_SESSIONS)
        let (_counter, _sel_out, digests) = ctx
            .execute_without_session(|c| c.pcr_read(pcr_selection_list))
            .context("TPM2_PCR_Read failed")?;

        let pcr_digests = digests.value();
        if pcr_digests.len() != pcr_indices.len() {
            return Err(anyhow!(
                "PCR read count mismatch: requested {}, got {}",
                pcr_indices.len(),
                pcr_digests.len()
            ));
        }

        let mut pcr_values = Vec::new();
        for (i, &idx) in pcr_indices.iter().enumerate() {
            pcr_values.push(TpmPcrValue {
                index: idx,
                digest: pcr_digests[i].as_bytes().to_vec(),
            });
        }

        // 3. Marshall TPMS_ATTEST wire bytes
        let quoted_bytes = attest
            .marshall()
            .map_err(|e| anyhow!("Failed to marshal TPMS_ATTEST: {e}"))?;

        // 4. Extract quote signature
        let sig_bytes = match signature {
            Signature::EcDsa(ecc_sig) => {
                let r = ecc_sig.signature_r().as_bytes();
                let s = ecc_sig.signature_s().as_bytes();
                let mut raw_sig = [0u8; 64];
                let r_offset = 32usize.saturating_sub(r.len());
                let s_offset = 32usize.saturating_sub(s.len());
                raw_sig[r_offset..32].copy_from_slice(r);
                raw_sig[32 + s_offset..64].copy_from_slice(s);
                raw_sig.to_vec()
            }
            other => {
                return Err(anyhow!(
                    "Unexpected quote signature algorithm: {:?}",
                    other.algorithm()
                ))
            }
        };

        Ok(TpmQuoteEvidence {
            quoted: quoted_bytes,
            signature: sig_bytes,
            pcr_values,
            pcr_alg: TpmHashAlgorithm::Sha256,
            kdev_public: RawPublicKey(kdev_pub),
        })
    }
}

impl KeyHolder for TpmAdapter {
    fn public_key(&self) -> Result<[u8; 64], KeyError> {
        self.kdev_pub.ok_or(KeyError::NotFound)
    }

    fn sign_binding(&self, msg: &[u8]) -> Result<[u8; 64], KeyError> {
        let mut ctx = self
            .ctx
            .lock()
            .map_err(|e| KeyError::Hardware(e.to_string()))?;
        let kdev_handle = self.kdev_handle.ok_or(KeyError::NotFound)?;

        let digest_bytes: [u8; 32] = Sha256::digest(msg).into();
        let digest = Digest::from(digest_bytes);

        let signature = ctx
            .sign(kdev_handle, digest, SignatureScheme::Null, None)
            .map_err(|e| KeyError::Hardware(format!("TPM sign failed: {e}")))?;

        match signature {
            Signature::EcDsa(ecc_sig) => {
                let r = ecc_sig.signature_r().as_bytes();
                let s = ecc_sig.signature_s().as_bytes();
                let mut raw_sig = [0u8; 64];
                let r_offset = 32usize.saturating_sub(r.len());
                let s_offset = 32usize.saturating_sub(s.len());
                raw_sig[r_offset..32].copy_from_slice(r);
                raw_sig[32 + s_offset..64].copy_from_slice(s);
                Ok(raw_sig)
            }
            _ => Err(KeyError::Hardware(
                "Unexpected signature algorithm from TPM".into(),
            )),
        }
    }
}

impl EvidenceCollector for TpmAdapter {
    fn collect(&self, nonce: &[u8]) -> Result<Evidence, EvidenceError> {
        // Collect PCR 0 and 7 baseline measurements
        let evidence = self
            .quote_pcrs(nonce, &[0, 7])
            .map_err(|e| EvidenceError::GenerationFailed(e.to_string()))?;
        let payload = serde_json::to_vec(&evidence)
            .map_err(|e| EvidenceError::GenerationFailed(e.to_string()))?;
        Ok(Evidence { payload })
    }
}
