//! zkpc-verifier: challenge issuing, single-use nonces, and checks on the
//! public values that a proof backend returns.
//!
//! The verifier never trusts public values just because a proof verified: a
//! proof is valid *for the values inside it*, so every one of them is compared
//! with what this verifier expects (its own clock, nonce record, policy).
//!
//! Device binding: presentation proofs bind to the physical hardware through
//! in-circuit verification of the live device key signature over the bound challenge.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use zkpc_core::{
    binding::{binding_hash, split_u128},
    statement::*,
};

// ---------------------------------------------------------------- clock

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// ---------------------------------------------------------------- nonces

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: [u8; 32],
    pub service_id: Vec<u8>,
    pub policy_hash: [u8; 32],
    pub expires_at: u64,
}

pub trait NonceStore: Send + Sync {
    fn put(&self, c: Challenge);
    /// Atomically removes and returns the challenge. A nonce can be taken once.
    fn take(&self, nonce: &[u8; 32]) -> Option<Challenge>;
    /// Drops expired entries; returns how many were removed.
    fn purge_expired(&self, now: u64) -> usize;
}

#[derive(Default)]
pub struct InMemoryNonceStore(Mutex<HashMap<[u8; 32], Challenge>>);

impl InMemoryNonceStore {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], Challenge>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl NonceStore for InMemoryNonceStore {
    fn put(&self, c: Challenge) {
        self.map().insert(c.nonce, c);
    }
    fn take(&self, nonce: &[u8; 32]) -> Option<Challenge> {
        self.map().remove(nonce)
    }
    fn purge_expired(&self, now: u64) -> usize {
        let mut m = self.map();
        let before = m.len();
        m.retain(|_, c| c.expires_at >= now);
        before - m.len()
    }
}

// ---------------------------------------------------------------- policy

#[derive(Clone, Debug)]
pub struct Policy {
    pub min_tier: u8,
    pub min_epoch: u32,
    /// Trusted issuer key ids: (key_id_0 << 32) | key_id_1.
    pub trusted_issuer_keys: BTreeSet<u64>,
    /// Pinned issuer public key coordinates: issuer_key_id -> (pk_x, pk_y) in big-endian bytes.
    pub trusted_issuer_coords: BTreeMap<u64, ([u8; 32], [u8; 32])>,
    /// Allowed difference between the prover's `now` and ours.
    pub max_skew_secs: u64,
    pub challenge_ttl_secs: u64,
    /// Prover clock timestamp quantization quantum in seconds (e.g. 60).
    /// If non-zero, prover `now` must satisfy `now % quantize_secs == 0` to mitigate clock fingerprinting.
    pub quantize_secs: u64,
}

impl Policy {
    /// Hash of the security-relevant fields (not the operational timings).
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"zkpc/policy/v1");
        h.update([self.min_tier]);
        h.update(self.min_epoch.to_be_bytes());
        h.update((self.trusted_issuer_keys.len() as u32).to_be_bytes());
        for k in &self.trusted_issuer_keys {
            h.update(k.to_be_bytes());
        }
        h.update((self.trusted_issuer_coords.len() as u32).to_be_bytes());
        for (k, (x, y)) in &self.trusted_issuer_coords {
            h.update(k.to_be_bytes());
            h.update(x);
            h.update(y);
        }
        h.finalize().into()
    }
}

// ---------------------------------------------------------------- backend

/// Canonical little-endian encoding of one field element.
pub type RawPublic = [u8; 32];

/// Something that verifies proof bytes and returns the core circuit's public
/// values (in the order defined in `zkpc_core::statement`).
pub trait ProofBackend: Send + Sync {
    fn verify(&self, proof: &[u8]) -> Result<Vec<RawPublic>, String>;
}

// ---------------------------------------------------------------- errors

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    UnknownOrReusedNonce,
    ChallengeExpired,
    PolicyChangedSinceChallenge,
    ProofRejected(String),
    WrongPublicCount { got: usize },
    NonCanonical(&'static str),
    OutOfRange(&'static str),
    ClockSkew { proof_now: u32, our_now: u32 },
    NonQuantizedTimestamp { got: u32, quantum: u64 },
    EpochMismatch { proof: u32, expected: u32 },
    BindingMismatch,
    TierTooLow { got: u8, need: u8 },
    UntrustedIssuer(u64),
    UntrustedIssuerKey(u64),
    ClockOutOfRange,
    ServiceBaseMismatch,
    InvalidPseudonymPoint(&'static str),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for VerifyError {}

#[derive(Debug, PartialEq, Eq)]
pub struct Accepted {
    pub tier: u8,
    pub issuer_key_id: u64,
    pub pseudonym: Option<[u8; 32]>,
    pub pseudonym_point: Option<([u8; 32], [u8; 32])>,
}

// ---------------------------------------------------------------- parsing

fn small(raw: &RawPublic, max: u64, what: &'static str) -> Result<u64, VerifyError> {
    if raw[8..].iter().any(|b| *b != 0) {
        return Err(VerifyError::NonCanonical(what));
    }
    let v = u64::from_le_bytes(raw[..8].try_into().unwrap());
    if v > max {
        return Err(VerifyError::OutOfRange(what));
    }
    Ok(v)
}

fn limb128(raw: &RawPublic, what: &'static str) -> Result<u128, VerifyError> {
    if raw[16..].iter().any(|b| *b != 0) {
        return Err(VerifyError::NonCanonical(what));
    }
    Ok(u128::from_le_bytes(raw[..16].try_into().unwrap()))
}

fn raw_to_be(raw: &RawPublic) -> [u8; 32] {
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = raw[31 - i];
    }
    be
}

fn validate_p256_coordinate(raw: &RawPublic, what: &'static str) -> Result<[u8; 32], VerifyError> {
    let be = raw_to_be(raw);
    let p_bytes: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ];
    if be >= p_bytes {
        return Err(VerifyError::NonCanonical(what));
    }
    Ok(be)
}

// ---------------------------------------------------------------- verifier

pub struct Verifier {
    pub service_id: Vec<u8>,
    pub policy: Policy,
    policy_hash: [u8; 32],
    clock: Box<dyn Clock>,
    store: Box<dyn NonceStore>,
    backend: Box<dyn ProofBackend>,
}

impl Verifier {
    pub fn new(
        service_id: Vec<u8>,
        policy: Policy,
        clock: Box<dyn Clock>,
        store: Box<dyn NonceStore>,
        backend: Box<dyn ProofBackend>,
    ) -> Self {
        let policy_hash = policy.hash();
        Self {
            service_id,
            policy,
            policy_hash,
            clock,
            store,
            backend,
        }
    }

    pub fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }

    pub fn issue_challenge(&self) -> Challenge {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let c = Challenge {
            nonce,
            service_id: self.service_id.clone(),
            policy_hash: self.policy_hash,
            expires_at: self.clock.now_unix() + self.policy.challenge_ttl_secs,
        };
        self.store.put(c.clone());
        c
    }

    /// The nonce is consumed first and stays consumed whatever happens next,
    /// so a failed attempt cannot be retried against the same challenge.
    pub fn verify_presentation(
        &self,
        nonce: &[u8; 32],
        proof: &[u8],
    ) -> Result<Accepted, VerifyError> {
        let ch = self
            .store
            .take(nonce)
            .ok_or(VerifyError::UnknownOrReusedNonce)?;
        let now = self.clock.now_unix();
        if now > ch.expires_at {
            return Err(VerifyError::ChallengeExpired);
        }
        if ch.policy_hash != self.policy_hash {
            return Err(VerifyError::PolicyChangedSinceChallenge);
        }

        let p = self
            .backend
            .verify(proof)
            .map_err(VerifyError::ProofRejected)?;
        if p.len() != NUM_CORE_PUBLICS && p.len() != NUM_PRESENTATION_PUBLICS {
            return Err(VerifyError::WrongPublicCount { got: p.len() });
        }

        let tier = small(&p[IDX_TIER], 255, "tier")? as u8;
        let kid0 = small(&p[IDX_KEY_ID_0], u32::MAX as u64, "key_id_0")?;
        let kid1 = small(&p[IDX_KEY_ID_1], u32::MAX as u64, "key_id_1")?;
        let issuer_key_id = (kid0 << 32) | kid1;
        let proof_now = small(&p[IDX_NOW], u32::MAX as u64, "now")? as u32;
        let proof_epoch = small(&p[IDX_MIN_EPOCH], u32::MAX as u64, "min_epoch")? as u32;
        let hi = limb128(&p[IDX_BINDING_HI], "binding_hi")?;
        let lo = limb128(&p[IDX_BINDING_LO], "binding_lo")?;

        let (pseudonym, pseudonym_point) = if p.len() == NUM_PRESENTATION_PUBLICS {
            let iss_x = validate_p256_coordinate(&p[IDX_ISSUER_PK_X], "issuer_pk_x")?;
            let iss_y = validate_p256_coordinate(&p[IDX_ISSUER_PK_Y], "issuer_pk_y")?;

            // Authenticate issuer public key coordinates against verifier policy pin
            if let Some((exp_x, exp_y)) = self.policy.trusted_issuer_coords.get(&issuer_key_id) {
                if iss_x != *exp_x || iss_y != *exp_y {
                    return Err(VerifyError::UntrustedIssuerKey(issuer_key_id));
                }
            }

            // 1. Verify Service Base matches independently derived RFC 9380 P_base for ch.service_id
            let p_base_x = validate_p256_coordinate(&p[IDX_P_BASE_X], "p_base_x")?;
            let p_base_y = validate_p256_coordinate(&p[IDX_P_BASE_Y], "p_base_y")?;
            let (_, _, exp_bx, exp_by) = zkpc_core::hash2curve::derive_service_base(&ch.service_id)
                .map_err(|_| VerifyError::ServiceBaseMismatch)?;
            if p_base_x != exp_bx || p_base_y != exp_by {
                return Err(VerifyError::ServiceBaseMismatch);
            }

            // 2. Verify Service Pseudonym Point P_svc is canonical and on curve
            let p_svc_x = validate_p256_coordinate(&p[IDX_P_SVC_X], "p_svc_x")?;
            let p_svc_y = validate_p256_coordinate(&p[IDX_P_SVC_Y], "p_svc_y")?;

            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&p_svc_x);
            sec1.extend_from_slice(&p_svc_y);
            let pt = p256::PublicKey::from_sec1_bytes(&sec1)
                .map_err(|_| VerifyError::InvalidPseudonymPoint("off_curve_or_invalid_sec1"))?;
            use p256::elliptic_curve::group::Group;
            if bool::from(pt.to_projective().is_identity()) {
                return Err(VerifyError::InvalidPseudonymPoint("point_at_infinity"));
            }

            // Derived canonical 32-byte pseudonym hash for verifier records
            let mut hasher = Sha256::new();
            hasher.update(b"ZKPC-PSEUDONYM-V1");
            hasher.update(&p_svc_x);
            hasher.update(&p_svc_y);
            let p_hash: [u8; 32] = hasher.finalize().into();

            (Some(p_hash), Some((p_svc_x, p_svc_y)))
        } else {
            (None, None)
        };

        let our_now = u32::try_from(now).map_err(|_| VerifyError::ClockOutOfRange)?;
        if self.policy.quantize_secs > 0 && (proof_now as u64 % self.policy.quantize_secs) != 0 {
            return Err(VerifyError::NonQuantizedTimestamp {
                got: proof_now,
                quantum: self.policy.quantize_secs,
            });
        }
        if proof_now.abs_diff(our_now) as u64 > self.policy.max_skew_secs {
            return Err(VerifyError::ClockSkew { proof_now, our_now });
        }
        if proof_epoch != self.policy.min_epoch {
            return Err(VerifyError::EpochMismatch {
                proof: proof_epoch,
                expected: self.policy.min_epoch,
            });
        }
        let expected = split_u128(&binding_hash(&ch.nonce, &ch.service_id, &ch.policy_hash));
        if (hi, lo) != expected {
            return Err(VerifyError::BindingMismatch);
        }
        if tier < self.policy.min_tier {
            return Err(VerifyError::TierTooLow {
                got: tier,
                need: self.policy.min_tier,
            });
        }
        if !self.policy.trusted_issuer_keys.contains(&issuer_key_id) {
            return Err(VerifyError::UntrustedIssuer(issuer_key_id));
        }
        Ok(Accepted {
            tier,
            issuer_key_id,
            pseudonym,
            pseudonym_point,
        })
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::PrimeField;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    struct FakeClock(Arc<AtomicU64>);
    impl Clock for FakeClock {
        fn now_unix(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Test-only backend: returns whatever it is given. cfg(test) keeps it out of builds.
    struct FakeBackend(Mutex<Result<Vec<RawPublic>, String>>);
    impl ProofBackend for FakeBackend {
        fn verify(&self, _proof: &[u8]) -> Result<Vec<RawPublic>, String> {
            self.0.lock().unwrap().clone()
        }
    }

    const T0: u64 = 1_800_000_000;
    const ISSUER: u64 = (0xAAAA_0001u64 << 32) | 0x0000_0002;

    fn enc(v: u128) -> RawPublic {
        let mut r = [0u8; 32];
        r[..16].copy_from_slice(&v.to_le_bytes());
        r
    }

    fn policy() -> Policy {
        let gx_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let gy_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let mut gx_be = [0u8; 32];
        let mut gy_be = [0u8; 32];
        hex::decode_to_slice(gx_hex, &mut gx_be).unwrap();
        hex::decode_to_slice(gy_hex, &mut gy_be).unwrap();

        let mut trusted_coords = BTreeMap::new();
        trusted_coords.insert(ISSUER, (gx_be, gy_be));

        Policy {
            min_tier: 3,
            min_epoch: 7,
            trusted_issuer_keys: [ISSUER].into_iter().collect(),
            trusted_issuer_coords: trusted_coords,
            max_skew_secs: 60,
            challenge_ttl_secs: 120,
            quantize_secs: 0,
        }
    }

    fn good_publics(ch: &Challenge, now: u32, tier: u8, issuer: u64, epoch: u32) -> Vec<RawPublic> {
        let (hi, lo) = split_u128(&binding_hash(&ch.nonce, &ch.service_id, &ch.policy_hash));
        let mut p = vec![[0u8; 32]; NUM_CORE_PUBLICS];
        p[IDX_TIER] = enc(tier as u128);
        p[IDX_KEY_ID_0] = enc((issuer >> 32) as u128);
        p[IDX_KEY_ID_1] = enc((issuer & 0xFFFF_FFFF) as u128);
        p[IDX_NOW] = enc(now as u128);
        p[IDX_MIN_EPOCH] = enc(epoch as u128);
        p[IDX_BINDING_HI] = enc(hi);
        p[IDX_BINDING_LO] = enc(lo);
        p
    }

    struct Rig {
        v: Verifier,
        clock: Arc<AtomicU64>,
        backend: Arc<FakeBackend>,
    }

    struct SharedBackend(Arc<FakeBackend>);
    impl ProofBackend for SharedBackend {
        fn verify(&self, proof: &[u8]) -> Result<Vec<RawPublic>, String> {
            self.0.verify(proof)
        }
    }

    fn rig(policy: Policy) -> Rig {
        let clock = Arc::new(AtomicU64::new(T0));
        let backend = Arc::new(FakeBackend(Mutex::new(Err("unset".into()))));
        let v = Verifier::new(
            b"vpn.example".to_vec(),
            policy,
            Box::new(FakeClock(clock.clone())),
            Box::new(InMemoryNonceStore::default()),
            Box::new(SharedBackend(backend.clone())),
        );
        Rig { v, clock, backend }
    }

    fn set(r: &Rig, p: Result<Vec<RawPublic>, String>) {
        *r.backend.0.lock().unwrap() = p;
    }

    #[test]
    fn happy_path() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        set(&r, Ok(good_publics(&ch, T0 as u32, 3, ISSUER, 7)));
        let a = r.v.verify_presentation(&ch.nonce, b"proof").unwrap();
        assert_eq!(
            a,
            Accepted {
                tier: 3,
                issuer_key_id: ISSUER,
                pseudonym: None,
                pseudonym_point: None,
            }
        );
    }

    #[test]
    fn happy_path_with_pseudonym() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let secret = [0x42u8; 32];
        let pubs = good_v2_presentation_publics(&ch, T0 as u32, 3, ISSUER, 7, secret);
        set(&r, Ok(pubs));
        let a = r.v.verify_presentation(&ch.nonce, b"proof").unwrap();
        assert_eq!(a.tier, 3);
        assert_eq!(a.issuer_key_id, ISSUER);
        assert!(a.pseudonym.is_some());
        assert!(a.pseudonym_point.is_some());
    }

    #[test]
    fn nonce_is_single_use_even_after_success() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        set(&r, Ok(good_publics(&ch, T0 as u32, 3, ISSUER, 7)));
        assert!(r.v.verify_presentation(&ch.nonce, b"p").is_ok());
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::UnknownOrReusedNonce)
        );
    }

    #[test]
    fn failed_attempt_still_burns_the_nonce() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        set(&r, Err("bad proof".into()));
        assert!(matches!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::ProofRejected(_))
        ));
        set(&r, Ok(good_publics(&ch, T0 as u32, 3, ISSUER, 7)));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::UnknownOrReusedNonce)
        );
    }

    #[test]
    fn unknown_nonce_rejected() {
        let r = rig(policy());
        assert_eq!(
            r.v.verify_presentation(&[9u8; 32], b"p"),
            Err(VerifyError::UnknownOrReusedNonce)
        );
    }

    #[test]
    fn expired_challenge_rejected() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        r.clock.store(T0 + 121, Ordering::SeqCst);
        set(&r, Ok(good_publics(&ch, (T0 + 121) as u32, 3, ISSUER, 7)));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::ChallengeExpired)
        );
    }

    #[test]
    fn proof_for_another_challenge_rejected() {
        let r = rig(policy());
        let a = r.v.issue_challenge();
        let b = r.v.issue_challenge();
        set(&r, Ok(good_publics(&a, T0 as u32, 3, ISSUER, 7))); // bound to A
        assert_eq!(
            r.v.verify_presentation(&b.nonce, b"p"),
            Err(VerifyError::BindingMismatch)
        );
    }

    #[test]
    fn proof_for_another_service_rejected() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let mut other = ch.clone();
        other.service_id = b"other.example".to_vec();
        set(&r, Ok(good_publics(&other, T0 as u32, 3, ISSUER, 7)));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::BindingMismatch)
        );
    }

    #[test]
    fn proof_for_another_policy_hash_rejected() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let mut other = ch.clone();
        other.policy_hash = [1u8; 32];
        set(&r, Ok(good_publics(&other, T0 as u32, 3, ISSUER, 7)));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::BindingMismatch)
        );
    }

    #[test]
    fn clock_skew_boundaries() {
        for (delta, ok) in [
            (0i64, true),
            (60, true),
            (-60, true),
            (61, false),
            (-61, false),
        ] {
            let r = rig(policy());
            let ch = r.v.issue_challenge();
            let pn = (T0 as i64 + delta) as u32;
            set(&r, Ok(good_publics(&ch, pn, 3, ISSUER, 7)));
            let res = r.v.verify_presentation(&ch.nonce, b"p");
            assert_eq!(res.is_ok(), ok, "delta {delta}: {res:?}");
        }
    }

    #[test]
    fn epoch_must_equal_our_policy() {
        for e in [6u32, 8] {
            let r = rig(policy());
            let ch = r.v.issue_challenge();
            set(&r, Ok(good_publics(&ch, T0 as u32, 3, ISSUER, e)));
            assert_eq!(
                r.v.verify_presentation(&ch.nonce, b"p"),
                Err(VerifyError::EpochMismatch {
                    proof: e,
                    expected: 7
                })
            );
        }
    }

    #[test]
    fn tier_floor_enforced() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        set(&r, Ok(good_publics(&ch, T0 as u32, 2, ISSUER, 7)));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::TierTooLow { got: 2, need: 3 })
        );
    }

    #[test]
    fn untrusted_issuer_rejected() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let other = (0xBBBBu64 << 32) | 1;
        set(&r, Ok(good_publics(&ch, T0 as u32, 3, other, 7)));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::UntrustedIssuer(other))
        );
    }

    #[test]
    fn wrong_public_count_rejected() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let mut p = good_publics(&ch, T0 as u32, 3, ISSUER, 7);
        p.pop();
        set(&r, Ok(p));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::WrongPublicCount { got: 6 })
        );
    }

    #[test]
    fn non_canonical_and_out_of_range_values_rejected() {
        // high bytes set on a small value
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let mut p = good_publics(&ch, T0 as u32, 3, ISSUER, 7);
        p[IDX_TIER][31] = 1;
        set(&r, Ok(p));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::NonCanonical("tier"))
        );

        // tier does not fit in a byte
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let mut p = good_publics(&ch, T0 as u32, 3, ISSUER, 7);
        p[IDX_TIER] = enc(256);
        set(&r, Ok(p));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::OutOfRange("tier"))
        );

        // binding limb wider than 128 bits
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let mut p = good_publics(&ch, T0 as u32, 3, ISSUER, 7);
        p[IDX_BINDING_HI][20] = 1;
        set(&r, Ok(p));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::NonCanonical("binding_hi"))
        );

        // now strictly exceeding u32::MAX (e.g. 2^33)
        // In-circuit bounds allow now - issued_at up to ~2^33, so verifier range check is critical
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let mut p = good_publics(&ch, T0 as u32, 3, ISSUER, 7);
        let val_2_pow_33 = 1u128 << 33;
        p[IDX_NOW] = enc(val_2_pow_33);
        set(&r, Ok(p));
        assert_eq!(
            r.v.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::OutOfRange("now"))
        );
    }

    #[test]
    fn now_quantization_enforced() {
        let mut pol = policy();
        pol.quantize_secs = 60;
        let r = rig(pol);
        let ch = r.v.issue_challenge();

        // T0 = 1_800_000_000 is divisible by 60
        assert_eq!(T0 % 60, 0);
        set(&r, Ok(good_publics(&ch, T0 as u32, 3, ISSUER, 7)));
        assert!(r.v.verify_presentation(&ch.nonce, b"p").is_ok());

        // Non-quantized timestamp (e.g. T0 + 17) must be rejected to prevent clock offset fingerprinting
        let ch2 = r.v.issue_challenge();
        set(&r, Ok(good_publics(&ch2, (T0 + 17) as u32, 3, ISSUER, 7)));
        assert_eq!(
            r.v.verify_presentation(&ch2.nonce, b"p"),
            Err(VerifyError::NonQuantizedTimestamp {
                got: (T0 + 17) as u32,
                quantum: 60,
            })
        );
    }

    #[test]
    fn policy_change_between_issue_and_verify_rejected() {
        // Build a verifier, issue a challenge, then verify with a verifier whose
        // policy differs but which shares the same store.
        let store = Arc::new(InMemoryNonceStore::default());
        struct SharedStore(Arc<InMemoryNonceStore>);
        impl NonceStore for SharedStore {
            fn put(&self, c: Challenge) {
                self.0.put(c)
            }
            fn take(&self, n: &[u8; 32]) -> Option<Challenge> {
                self.0.take(n)
            }
            fn purge_expired(&self, now: u64) -> usize {
                self.0.purge_expired(now)
            }
        }
        let clock = Arc::new(AtomicU64::new(T0));
        let backend = Arc::new(FakeBackend(Mutex::new(Err("unset".into()))));
        let mk = |p: Policy| {
            Verifier::new(
                b"vpn.example".to_vec(),
                p,
                Box::new(FakeClock(clock.clone())),
                Box::new(SharedStore(store.clone())),
                Box::new(SharedBackend(backend.clone())),
            )
        };
        let v1 = mk(policy());
        let ch = v1.issue_challenge();
        let mut p2 = policy();
        p2.min_epoch = 8;
        let v2 = mk(p2);
        *backend.0.lock().unwrap() = Ok(good_publics(&ch, T0 as u32, 3, ISSUER, 8));
        assert_eq!(
            v2.verify_presentation(&ch.nonce, b"p"),
            Err(VerifyError::PolicyChangedSinceChallenge)
        );
    }

    #[test]
    fn policy_hash_properties() {
        let a = policy();
        let mut b = policy();
        b.min_epoch = 8;
        assert_ne!(a.hash(), b.hash());
        let mut c = policy();
        c.trusted_issuer_keys.insert(5);
        assert_ne!(a.hash(), c.hash());
        let mut d = policy();
        d.max_skew_secs = 999; // operational only
        assert_eq!(a.hash(), d.hash());
    }

    #[test]
    fn purge_removes_only_expired() {
        let s = InMemoryNonceStore::default();
        let mk = |n: u8, exp: u64| Challenge {
            nonce: [n; 32],
            service_id: vec![],
            policy_hash: [0; 32],
            expires_at: exp,
        };
        s.put(mk(1, 100));
        s.put(mk(2, 200));
        assert_eq!(s.purge_expired(150), 1);
        assert!(s.take(&[1; 32]).is_none());
        assert!(s.take(&[2; 32]).is_some());
    }

    fn be_to_raw(be: &[u8; 32]) -> RawPublic {
        let mut raw = [0u8; 32];
        for i in 0..32 {
            raw[i] = be[31 - i];
        }
        raw
    }

    fn good_v2_presentation_publics(
        ch: &Challenge,
        now: u32,
        tier: u8,
        issuer: u64,
        epoch: u32,
        secret: [u8; 32],
    ) -> Vec<RawPublic> {
        let (hi, lo) = split_u128(&binding_hash(&ch.nonce, &ch.service_id, &ch.policy_hash));
        let mut p = vec![[0u8; 32]; NUM_PRESENTATION_PUBLICS];
        p[IDX_TIER] = enc(tier as u128);
        p[IDX_KEY_ID_0] = enc((issuer >> 32) as u128);
        p[IDX_KEY_ID_1] = enc((issuer & 0xFFFF_FFFF) as u128);
        p[IDX_NOW] = enc(now as u128);
        p[IDX_MIN_EPOCH] = enc(epoch as u128);
        p[IDX_BINDING_HI] = enc(hi);
        p[IDX_BINDING_LO] = enc(lo);

        // Dummy issuer public key (P-256 generator coordinates)
        let gx_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let gy_hex = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let mut gx_be = [0u8; 32];
        let mut gy_be = [0u8; 32];
        hex::decode_to_slice(gx_hex, &mut gx_be).unwrap();
        hex::decode_to_slice(gy_hex, &mut gy_be).unwrap();
        p[IDX_ISSUER_PK_X] = be_to_raw(&gx_be);
        p[IDX_ISSUER_PK_Y] = be_to_raw(&gy_be);

        // Derived P_base for ch.service_id
        let (p_base_proj, _, bx, by) =
            zkpc_core::hash2curve::derive_service_base(&ch.service_id).unwrap();
        p[IDX_P_BASE_X] = be_to_raw(&bx);
        p[IDX_P_BASE_Y] = be_to_raw(&by);

        // P_svc = [s]P_base
        let s_scalar = p256::Scalar::from_repr(secret.into()).unwrap();
        let p_svc_proj = p_base_proj * s_scalar;
        let p_svc_aff = p_svc_proj.to_affine();
        let enc_svc = p_svc_aff.to_encoded_point(false);
        let mut sx = [0u8; 32];
        let mut sy = [0u8; 32];
        sx.copy_from_slice(&enc_svc.x().unwrap()[..]);
        sy.copy_from_slice(&enc_svc.y().unwrap()[..]);
        p[IDX_P_SVC_X] = be_to_raw(&sx);
        p[IDX_P_SVC_Y] = be_to_raw(&sy);

        p
    }

    #[test]
    fn test_verifier_accepts_valid_v2_presentation() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let secret = [0x42u8; 32];
        let publics = good_v2_presentation_publics(&ch, T0 as u32, 3, ISSUER, 7, secret);
        set(&r, Ok(publics));

        let res = r.v.verify_presentation(&ch.nonce, b"proof_bytes");
        assert!(res.is_ok(), "Valid V2 presentation must be accepted");
        let accepted = res.unwrap();
        assert_eq!(accepted.tier, 3);
        assert_eq!(accepted.issuer_key_id, ISSUER);
        assert!(accepted.pseudonym.is_some());
        assert!(accepted.pseudonym_point.is_some());
    }

    #[test]
    fn test_verifier_rejects_old_layout_with_wrong_public_count() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        // Old layout had 11 public values
        let old_publics = vec![[0u8; 32]; 11];
        set(&r, Ok(old_publics));

        let res = r.v.verify_presentation(&ch.nonce, b"proof_bytes");
        assert_eq!(res, Err(VerifyError::WrongPublicCount { got: 11 }));
    }

    #[test]
    fn test_verifier_rejects_substituted_service_base() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let secret = [0x42u8; 32];
        let mut publics = good_v2_presentation_publics(&ch, T0 as u32, 3, ISSUER, 7, secret);

        // Attacker substitutes P_base with an unrelated point (e.g. generator G)
        let gx_hex = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
        let mut gx_be = [0u8; 32];
        hex::decode_to_slice(gx_hex, &mut gx_be).unwrap();
        publics[IDX_P_BASE_X] = be_to_raw(&gx_be);

        set(&r, Ok(publics));
        let res = r.v.verify_presentation(&ch.nonce, b"proof_bytes");
        assert_eq!(res, Err(VerifyError::ServiceBaseMismatch));
    }

    #[test]
    fn test_verifier_rejects_cross_service_presentation() {
        let r = rig(policy());
        let ch_service_a = r.v.issue_challenge(); // issued for b"vpn.example"
        let secret = [0x42u8; 32];

        // Attacker presents a proof prepared for Service B (b"banking.example")
        let ch_service_b = Challenge {
            nonce: ch_service_a.nonce,
            service_id: b"banking.example".to_vec(),
            policy_hash: ch_service_a.policy_hash,
            expires_at: ch_service_a.expires_at,
        };
        let publics_service_b =
            good_v2_presentation_publics(&ch_service_b, T0 as u32, 3, ISSUER, 7, secret);

        set(&r, Ok(publics_service_b));
        let res = r.v.verify_presentation(&ch_service_a.nonce, b"proof_bytes");
        // Must be rejected because expected binding / P_base for Service A differs from Service B!
        assert!(res.is_err());
    }

    #[test]
    fn test_verifier_rejects_malformed_and_off_curve_pseudonym_points() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let secret = [0x42u8; 32];

        // Case 1: Non-canonical coordinate (x >= p, e.g. all 0xFF bytes)
        let mut publics_noncanonical =
            good_v2_presentation_publics(&ch, T0 as u32, 3, ISSUER, 7, secret);
        publics_noncanonical[IDX_P_SVC_X] = [0xFF; 32];
        set(&r, Ok(publics_noncanonical));
        let res1 = r.v.verify_presentation(&ch.nonce, b"p");
        assert_eq!(res1, Err(VerifyError::NonCanonical("p_svc_x")));

        // Case 2: Off-curve point
        let ch2 = r.v.issue_challenge();
        let mut publics_offcurve =
            good_v2_presentation_publics(&ch2, T0 as u32, 3, ISSUER, 7, secret);
        // Modifying y coordinate puts point off-curve
        publics_offcurve[IDX_P_SVC_Y][0] ^= 0x01;
        set(&r, Ok(publics_offcurve));
        let res2 = r.v.verify_presentation(&ch2.nonce, b"p");
        assert_eq!(
            res2,
            Err(VerifyError::InvalidPseudonymPoint(
                "off_curve_or_invalid_sec1"
            ))
        );
    }

    #[test]
    fn test_verifier_rejects_untrusted_issuer_key_coordinates() {
        let r = rig(policy());
        let ch = r.v.issue_challenge();
        let secret = [0x42u8; 32];
        let mut publics = good_v2_presentation_publics(&ch, T0 as u32, 3, ISSUER, 7, secret);
        // Tamper issuer public key coordinate (e.g. flip a byte)
        publics[IDX_ISSUER_PK_X][0] ^= 0x01;
        set(&r, Ok(publics));

        let res = r.v.verify_presentation(&ch.nonce, b"proof_bytes");
        assert_eq!(res, Err(VerifyError::UntrustedIssuerKey(ISSUER)));
    }
}
