// -----------------------------------------------------------------------------
// ZKPC Build - Hardware Attestation Agent
//
// File: src/credential.rs
// Description: Byte-exact layout for the hardware attestation credential.
// -----------------------------------------------------------------------------

pub const CREDENTIAL_SIZE: usize = 256;
pub const PAYLOAD_SIZE: usize = 192;

// Fixed field offsets
pub const OFF_VERSION: usize = 0;
pub const SIZE_VERSION: usize = 1;

pub const OFF_PLATFORM: usize = 1;
pub const SIZE_PLATFORM: usize = 1;

pub const OFF_TIER: usize = 2;
pub const SIZE_TIER: usize = 1;

pub const OFF_FLAGS: usize = 3;
pub const SIZE_FLAGS: usize = 1;

pub const OFF_POSTURE: usize = 4;
pub const SIZE_POSTURE: usize = 4;

pub const OFF_KDEV_X: usize = 8;
pub const SIZE_KDEV_X: usize = 32;

pub const OFF_KDEV_Y: usize = 40;
pub const SIZE_KDEV_Y: usize = 32;

pub const OFF_FLEET_ID: usize = 72;
pub const SIZE_FLEET_ID: usize = 16;

// EC Commitment (64 bytes: X||Y)
pub const OFF_SECRET_COMMIT: usize = 88;
pub const SIZE_SECRET_COMMIT: usize = 64;

pub const OFF_ISSUED_AT: usize = 152;
pub const SIZE_ISSUED_AT: usize = 4;

pub const OFF_EXPIRES_AT: usize = 156;
pub const SIZE_EXPIRES_AT: usize = 4;

pub const OFF_REVOCATION_EPOCH: usize = 160;
pub const SIZE_REVOCATION_EPOCH: usize = 4;

pub const OFF_RESERVED: usize = 164;
pub const SIZE_RESERVED: usize = 20;

pub const OFF_ISSUER_KEY_ID: usize = 184;
pub const SIZE_ISSUER_KEY_ID: usize = 8;

pub const OFF_SIG_R: usize = 192;
pub const SIZE_SIG_R: usize = 32;

pub const OFF_SIG_S: usize = 224;
pub const SIZE_SIG_S: usize = 32;

/// Supported hardware attestation platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Platform {
    LinuxTpm = 1,
    WindowsTpm = 2,
    AppleSe = 3,
}

impl TryFrom<u8> for Platform {
    type Error = &'static str;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::LinuxTpm),
            2 => Ok(Self::WindowsTpm),
            3 => Ok(Self::AppleSe),
            _ => Err("Invalid platform identifier"),
        }
    }
}

/// Hardware assurance tiers defined by the ZKPC attestation model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum AssuranceTier {
    T0Software = 0,
    T1HwBoundUnattested = 1,
    T2AppAttested = 2,
    T3VendorAttested = 3,
}

impl TryFrom<u8> for AssuranceTier {
    type Error = &'static str;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Self::T0Software),
            1 => Ok(Self::T1HwBoundUnattested),
            2 => Ok(Self::T2AppAttested),
            3 => Ok(Self::T3VendorAttested),
            _ => Err("Invalid assurance tier"),
        }
    }
}

/// A strictly sized 64-byte raw uncompressed public key (X || Y).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RawPublicKey(pub [u8; 64]);

impl std::fmt::Debug for RawPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawPublicKey(0x{})", hex::encode(&self.0))
    }
}

impl serde::Serialize for RawPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for RawPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RawPublicKey;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-byte raw public key")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 64 {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(v);
                    Ok(RawPublicKey(arr))
                } else {
                    Err(E::invalid_length(v.len(), &self))
                }
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for i in 0..64 {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(RawPublicKey(arr))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

/// Zero-copy safe accessor for the 256-byte credential.
pub struct CredentialView<'a> {
    raw: &'a [u8; CREDENTIAL_SIZE],
}

impl<'a> CredentialView<'a> {
    pub fn new(raw: &'a [u8; CREDENTIAL_SIZE]) -> Self {
        Self { raw }
    }

    pub fn version(&self) -> u8 {
        self.raw[OFF_VERSION]
    }

    pub fn platform(&self) -> Result<Platform, &'static str> {
        Platform::try_from(self.raw[OFF_PLATFORM])
    }

    pub fn tier(&self) -> Result<AssuranceTier, &'static str> {
        AssuranceTier::try_from(self.raw[OFF_TIER])
    }

    pub fn posture_bits(&self) -> u32 {
        u32::from_be_bytes(self.raw[OFF_POSTURE..OFF_POSTURE + 4].try_into().unwrap())
    }

    pub fn kdev_x(&self) -> &[u8; 32] {
        self.raw[OFF_KDEV_X..OFF_KDEV_X + 32].try_into().unwrap()
    }

    pub fn kdev_y(&self) -> &[u8; 32] {
        self.raw[OFF_KDEV_Y..OFF_KDEV_Y + 32].try_into().unwrap()
    }

    pub fn raw_payload(&self) -> &[u8] {
        &self.raw[..PAYLOAD_SIZE]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_specification() {
        assert_eq!(OFF_PLATFORM, OFF_VERSION + SIZE_VERSION);
        assert_eq!(OFF_TIER, OFF_PLATFORM + SIZE_PLATFORM);
        assert_eq!(OFF_FLAGS, OFF_TIER + SIZE_TIER);
        assert_eq!(OFF_POSTURE, OFF_FLAGS + SIZE_FLAGS);
        assert_eq!(OFF_KDEV_X, OFF_POSTURE + SIZE_POSTURE);
        assert_eq!(OFF_KDEV_Y, OFF_KDEV_X + SIZE_KDEV_X);
        assert_eq!(OFF_FLEET_ID, OFF_KDEV_Y + SIZE_KDEV_Y);
        assert_eq!(OFF_SECRET_COMMIT, OFF_FLEET_ID + SIZE_FLEET_ID);
        assert_eq!(OFF_ISSUED_AT, OFF_SECRET_COMMIT + SIZE_SECRET_COMMIT);
        assert_eq!(OFF_EXPIRES_AT, OFF_ISSUED_AT + SIZE_ISSUED_AT);
        assert_eq!(OFF_REVOCATION_EPOCH, OFF_EXPIRES_AT + SIZE_EXPIRES_AT);
        assert_eq!(OFF_RESERVED, OFF_REVOCATION_EPOCH + SIZE_REVOCATION_EPOCH);
        assert_eq!(OFF_ISSUER_KEY_ID, OFF_RESERVED + SIZE_RESERVED);
        assert_eq!(OFF_SIG_R, OFF_ISSUER_KEY_ID + SIZE_ISSUER_KEY_ID);
        assert_eq!(OFF_SIG_S, OFF_SIG_R + SIZE_SIG_R);

        assert_eq!(PAYLOAD_SIZE, OFF_SIG_R);
        assert_eq!(CREDENTIAL_SIZE, OFF_SIG_S + SIZE_SIG_S);
    }
}
