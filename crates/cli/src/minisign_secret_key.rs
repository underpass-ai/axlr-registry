//! A minisign secret key file (`minisign -G` writes it): the format the
//! operator keeps the registry's index key in.

use std::path::Path;

use base64::Engine as _;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest as _};
use ed25519_dalek::SigningKey;

use crate::{read_file, CliError};

/// The decoded key: `Ed`, a KDF (`Sc` scrypt or none), a `B2` checksum,
/// a 32-byte salt, the scrypt limits, then 104 bytes of key id, 64-byte
/// secret key and BLAKE2b-256 checksum, XORed with the scrypt stream when
/// encrypted. See `minisign.h` in the minisign sources.
#[derive(Clone)]
pub struct MinisignSecretKey {
    key_id: [u8; 8],
    key: SigningKey,
}

const SIG_ALG: &[u8; 2] = b"Ed";
const KDF_SCRYPT: &[u8; 2] = b"Sc";
const KDF_NONE: &[u8; 2] = b"\0\0";
const CHK_ALG: &[u8; 2] = b"B2";
const KEYNUM_SK_LEN: usize = 8 + 64 + 32;
const TOTAL_LEN: usize = 2 + 2 + 2 + 32 + 8 + 8 + KEYNUM_SK_LEN;

impl std::fmt::Debug for MinisignSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MinisignSecretKey({})", hex::encode(self.key_id))
    }
}

impl MinisignSecretKey {
    /// Reads and decrypts a key file. `password` is asked for only when
    /// the key is encrypted.
    pub fn load(path: &Path, password: impl FnOnce() -> Result<String, CliError>) -> Result<Self, CliError> {
        let text = String::from_utf8(read_file(path)?).map_err(|_| CliError::Invalid(format!("{}: not text", path.display())))?;
        Self::parse(&text, password).map_err(|e| CliError::Invalid(format!("{}: {e}", path.display())))
    }

    /// Parses the file's text: an untrusted comment line and the base64.
    pub fn parse(text: &str, password: impl FnOnce() -> Result<String, CliError>) -> Result<Self, CliError> {
        let invalid = |what: &str| CliError::Invalid(format!("not a minisign secret key: {what}"));
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
            .ok_or_else(|| invalid("no key line"))?;
        let raw = base64::engine::general_purpose::STANDARD.decode(line).map_err(|_| invalid("key line is not base64"))?;
        if raw.len() != TOTAL_LEN {
            return Err(invalid(&format!("{} bytes, expected {TOTAL_LEN}", raw.len())));
        }
        if &raw[0..2] != SIG_ALG || &raw[4..6] != CHK_ALG {
            return Err(invalid("algorithm is not Ed with a B2 checksum"));
        }
        let mut keynum_sk = [0u8; KEYNUM_SK_LEN];
        keynum_sk.copy_from_slice(&raw[54..]);
        match &raw[2..4] {
            k if k == KDF_NONE => {}
            k if k == KDF_SCRYPT => {
                let opslimit = u64::from_le_bytes(raw[38..46].try_into().expect("8 bytes"));
                let memlimit = u64::from_le_bytes(raw[46..54].try_into().expect("8 bytes"));
                let stream = scrypt_stream(password()?.as_bytes(), &raw[6..38], opslimit, memlimit)?;
                for (byte, s) in keynum_sk.iter_mut().zip(stream) {
                    *byte ^= s;
                }
            }
            _ => return Err(invalid("unknown key derivation")),
        }
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(&keynum_sk[..8]);
        let sk: [u8; 64] = keynum_sk[8..72].try_into().expect("64 bytes");
        let chk: [u8; 32] = keynum_sk[72..].try_into().expect("32 bytes");
        if checksum(&key_id, &sk) != chk {
            return Err(CliError::Invalid("the password is wrong or the key file is damaged (checksum mismatch)".to_owned()));
        }
        let key = SigningKey::from_keypair_bytes(&sk).map_err(|_| invalid("the public half does not match the secret"))?;
        Ok(Self { key_id, key })
    }

    /// Encodes a key as minisign would write it: encrypted with scrypt
    /// under `password` and the given limits, or in the clear with
    /// `None` (`minisign -G -W`). The tests use it; the operator uses
    /// `minisign -G`.
    pub fn to_text(&self, password: Option<(&str, u64, u64)>, salt: [u8; 32]) -> Result<String, CliError> {
        let mut keynum_sk = Vec::with_capacity(KEYNUM_SK_LEN);
        keynum_sk.extend_from_slice(&self.key_id);
        keynum_sk.extend_from_slice(&self.key.to_keypair_bytes());
        keynum_sk.extend_from_slice(&checksum(&self.key_id, &self.key.to_keypair_bytes()));
        let mut raw = Vec::with_capacity(TOTAL_LEN);
        raw.extend_from_slice(SIG_ALG);
        match password {
            Some((password, opslimit, memlimit)) => {
                raw.extend_from_slice(KDF_SCRYPT);
                raw.extend_from_slice(CHK_ALG);
                raw.extend_from_slice(&salt);
                raw.extend_from_slice(&opslimit.to_le_bytes());
                raw.extend_from_slice(&memlimit.to_le_bytes());
                let stream = scrypt_stream(password.as_bytes(), &salt, opslimit, memlimit)?;
                for (byte, s) in keynum_sk.iter_mut().zip(stream) {
                    *byte ^= s;
                }
            }
            None => {
                raw.extend_from_slice(KDF_NONE);
                raw.extend_from_slice(CHK_ALG);
                raw.extend_from_slice(&[0u8; 32 + 8 + 8]);
            }
        }
        raw.extend_from_slice(&keynum_sk);
        Ok(format!("untrusted comment: minisign secret key\n{}\n", base64::engine::general_purpose::STANDARD.encode(raw)))
    }

    /// minisign's default scrypt limits (`minisign -G`).
    pub const OPSLIMIT: u64 = 33_554_432;
    /// See `OPSLIMIT`.
    pub const MEMLIMIT: u64 = 1_073_741_824;

    /// A key with a random id.
    pub fn generate() -> Self {
        let mut key_id = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_id);
        Self { key_id, key: SigningKey::generate(&mut rand::rngs::OsRng) }
    }

    /// The 8-byte key id minisign puts in signatures and public keys.
    pub fn key_id(&self) -> &[u8; 8] {
        &self.key_id
    }

    /// The Ed25519 key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    /// The public key file's base64 line: `Ed`, the key id and the key.
    pub fn public_key_base64(&self) -> String {
        let mut bytes = SIG_ALG.to_vec();
        bytes.extend_from_slice(&self.key_id);
        bytes.extend_from_slice(self.key.verifying_key().as_bytes());
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}

/// BLAKE2b-256 over the algorithm, the key id and the secret key.
fn checksum(key_id: &[u8; 8], sk: &[u8; 64]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(SIG_ALG);
    hasher.update(key_id);
    hasher.update(sk);
    hasher.finalize().into()
}

/// libsodium's `crypto_pwhash_scryptsalsa208sha256` with minisign's
/// parameter choice: `N`, `r` and `p` derived from the ops and memory
/// limits stored in the file (`pickparams` in libsodium).
fn scrypt_stream(password: &[u8], salt: &[u8], opslimit: u64, memlimit: u64) -> Result<[u8; KEYNUM_SK_LEN], CliError> {
    let opslimit = opslimit.max(32768);
    let r: u64 = 8;
    let mut n_log2: u8 = 1;
    let p: u32;
    if opslimit < memlimit / 32 {
        p = 1;
        let max_n = opslimit / (r * 4);
        while n_log2 < 63 && (1u64 << n_log2) <= max_n / 2 {
            n_log2 += 1;
        }
    } else {
        let max_n = memlimit / (r * 128);
        while n_log2 < 63 && (1u64 << n_log2) <= max_n / 2 {
            n_log2 += 1;
        }
        let max_rp = ((opslimit / 4) / (1u64 << n_log2)).min(0x3fff_ffff);
        p = u32::try_from(max_rp / r).expect("bounded above");
    }
    if n_log2 > 20 {
        return Err(CliError::Invalid("scrypt parameters too high for this tool (N over 2^20)".to_owned()));
    }
    let params = scrypt::Params::new(n_log2, u32::try_from(r).expect("8"), p.max(1))
        .map_err(|e| CliError::Invalid(format!("scrypt parameters: {e}")))?;
    let mut stream = [0u8; KEYNUM_SK_LEN];
    scrypt::scrypt(password, salt, &params, &mut stream).map_err(|e| CliError::Invalid(format!("scrypt: {e}")))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::MinisignSecretKey;
    use crate::CliError;

    /// Fast scrypt limits for tests; the file carries them, so any
    /// reader derives the same parameters.
    pub(crate) const FAST: (u64, u64) = (32768, 16 * 1024 * 1024);

    fn no_password() -> Result<String, CliError> {
        panic!("password asked for an unencrypted key")
    }

    #[test]
    fn round_trips_encrypted_and_clear_keys() {
        let key = MinisignSecretKey::generate();
        let clear = key.to_text(None, [0; 32]).unwrap();
        let back = MinisignSecretKey::parse(&clear, no_password).unwrap();
        assert_eq!(back.key_id(), key.key_id());
        assert_eq!(back.signing_key().to_bytes(), key.signing_key().to_bytes());
        let encrypted = key.to_text(Some(("hunter2", FAST.0, FAST.1)), [7; 32]).unwrap();
        let back = MinisignSecretKey::parse(&encrypted, || Ok("hunter2".to_owned())).unwrap();
        assert_eq!(back.public_key_base64(), key.public_key_base64());
        let wrong = MinisignSecretKey::parse(&encrypted, || Ok("letmein".to_owned()));
        assert!(wrong.unwrap_err().to_string().contains("password"));
        assert!(MinisignSecretKey::parse("untrusted comment: x\n", no_password).is_err());
        assert!(MinisignSecretKey::parse("AAAA\n", no_password).is_err());
        assert!(format!("{key:?}").starts_with("MinisignSecretKey("));
    }

    #[test]
    fn interoperates_with_the_minisign_crate() {
        // A key the reference implementation generated and encrypted.
        let pair = minisign::KeyPair::generate_encrypted_keypair(Some("pw".to_owned())).unwrap();
        let text = pair.sk.to_box(None).unwrap().into_string();
        let ours = MinisignSecretKey::parse(&text, || Ok("pw".to_owned())).unwrap();
        assert_eq!(ours.public_key_base64(), pair.pk.to_base64());
        // And one we wrote, read by it.
        let key = MinisignSecretKey::generate();
        let text = key.to_text(Some(("pw", FAST.0, FAST.1)), [9; 32]).unwrap();
        let theirs = minisign::SecretKeyBox::from_string(&text).unwrap().into_secret_key(Some("pw".to_owned())).unwrap();
        assert_eq!(minisign::PublicKey::from_secret_key(&theirs).unwrap().to_base64(), key.public_key_base64());
        let clear = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let ours = MinisignSecretKey::parse(&clear.sk.to_box(None).unwrap().into_string(), no_password).unwrap();
        assert_eq!(ours.public_key_base64(), clear.pk.to_base64());
    }
}
