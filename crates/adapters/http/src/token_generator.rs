//! Makes tokens: 32 random bytes from the operating system, in hex.

use rand::RngCore as _;

/// Generates tokens.
pub struct TokenGenerator;

impl TokenGenerator {
    /// A fresh 64-character hex token.
    pub fn generate() -> String {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::TokenGenerator;

    #[test]
    fn tokens_are_long_hex_and_distinct() {
        let a = TokenGenerator::generate();
        let b = TokenGenerator::generate();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
