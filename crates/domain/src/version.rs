//! A semantic version `MAJOR.MINOR.PATCH`, ordered numerically.

use crate::DomainError;

/// A version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Version {
    /// Parses `MAJOR.MINOR.PATCH` with no leading zeros.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let parts: Vec<&str> = raw.split('.').collect();
        if parts.len() != 3 {
            return Err(DomainError::invalid("version", "MAJOR.MINOR.PATCH"));
        }
        let mut numbers = [0u64; 3];
        for (i, part) in parts.iter().enumerate() {
            let canonical = part.parse::<u64>().ok().filter(|n| n.to_string() == *part);
            numbers[i] = canonical.ok_or_else(|| DomainError::invalid("version", "MAJOR.MINOR.PATCH"))?;
        }
        Ok(Self { major: numbers[0], minor: numbers[1], patch: numbers[2] })
    }
}

impl TryFrom<String> for Version {
    type Error = DomainError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Version> for String {
    fn from(value: Version) -> Self {
        value.to_string()
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn parses_and_orders() {
        assert!(Version::parse("1.10.0").unwrap() > Version::parse("1.9.9").unwrap());
        assert_eq!(Version::parse("2.0.1").unwrap().to_string(), "2.0.1");
        assert!(Version::parse("1.0").is_err());
        assert!(Version::parse("01.0.0").is_err());
        assert!(Version::parse("1.0.0-rc1").is_err());
    }
}
