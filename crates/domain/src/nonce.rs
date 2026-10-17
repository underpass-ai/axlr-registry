//! The nonce of a signed request: 16 random bytes, base64 on the wire,
//! never accepted twice for the same key.

use base64::Engine as _;

use crate::DomainError;

/// A request nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 16]);

impl Nonce {
    /// How many bytes a nonce holds.
    pub const LEN: usize = 16;

    /// Wraps random bytes the caller drew.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Reads the base64 form from a header.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(raw.trim()).map_err(|_| DomainError::invalid("nonce", "base64"))?;
        let bytes: [u8; Self::LEN] = bytes.try_into().map_err(|_| DomainError::invalid("nonce", "16 bytes"))?;
        Ok(Self(bytes))
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The base64 form: what the header carries and the signed message
    /// contains.
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

#[cfg(test)]
mod tests {
    use super::Nonce;

    #[test]
    fn round_trips_base64_and_refuses_other_lengths() {
        let nonce = Nonce::from_bytes([7; 16]);
        assert_eq!(nonce.to_base64(), "BwcHBwcHBwcHBwcHBwcHBw==");
        assert_eq!(Nonce::parse(&nonce.to_string()).unwrap(), nonce);
        assert!(Nonce::parse("BwcHBwcHBw==").is_err(), "8 bytes");
        assert!(Nonce::parse("!!").is_err(), "not base64");
    }
}
