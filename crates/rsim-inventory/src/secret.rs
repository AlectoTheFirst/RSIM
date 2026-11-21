//! The secret key of the managed credentials and the sealed form of their
//! secrets: ChaCha20-Poly1305 with a random nonce, and the credential name
//! and kind as the associated data, so that a sealed secret does not open
//! under another name or kind.

use std::fmt;
use std::path::Path;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::CredentialKind;

/// The environment variable of the file of the secret key.
pub const KEY_FILE_VAR: &str = "RSIM_SECRET_KEY_FILE";

/// The first byte of a sealed secret: the format version.
const FORMAT: u8 = 1;

/// The largest secret value in bytes.
pub const MAX_SECRET: usize = 16 * 1024;

/// The secret of a managed credential as a PUT body gives it. No answer
/// gives it back.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretInput {
    /// The password, the private key in the OpenSSH or PEM form, or the API
    /// key, by the kind of the credential.
    #[schemars(extend("writeOnly" = true))]
    pub value: String,
    /// The passphrase of a private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("writeOnly" = true))]
    pub passphrase: Option<String>,
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretInput(..)")
    }
}

impl SecretInput {
    /// The check of the secret for its kind.
    pub fn check(&self, kind: CredentialKind) -> Result<(), String> {
        if self.value.is_empty() {
            return Err("the secret is empty".into());
        }
        if self.value.len() > MAX_SECRET
            || self
                .passphrase
                .as_ref()
                .is_some_and(|p| p.len() > MAX_SECRET)
        {
            return Err(format!("the secret is longer than {MAX_SECRET} bytes"));
        }
        match kind {
            CredentialKind::SshKey => {
                let v = self.value.trim();
                if !(v.starts_with("-----BEGIN ") && v.contains("PRIVATE KEY-----")) {
                    return Err(
                        "an ssh-key secret is a private key in the OpenSSH or PEM form".into(),
                    );
                }
            }
            CredentialKind::Password | CredentialKind::ApiKey => {
                if self.passphrase.is_some() {
                    return Err(format!("a {kind} secret has no passphrase"));
                }
            }
        }
        Ok(())
    }
}

/// A secret sealed by a secret key, with the id of the key.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: String,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sealed {{ key_id: {}, .. }}", self.key_id)
    }
}

/// The key that seals and opens the secrets of the managed credentials:
/// 32 bytes, written as 64 hex digits.
pub struct SecretKey {
    key: LessSafeKey,
    id: String,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey {{ id: {} }}", self.id)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn aad(name: &str, kind: CredentialKind) -> Vec<u8> {
    let mut a = b"rsim-credential\0".to_vec();
    a.extend_from_slice(name.as_bytes());
    a.push(0);
    a.extend_from_slice(kind.word().as_bytes());
    a
}

impl SecretKey {
    /// The key of 64 hex digits, with spaces and line ends around them.
    pub fn parse(text: &str) -> Result<SecretKey, String> {
        let t = text.trim();
        if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("a secret key is 64 hex digits".into());
        }
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16).expect("hex digits"))
            .collect();
        let id = hex(&digest(&SHA256, &bytes).as_ref()[..8]);
        let key = UnboundKey::new(&CHACHA20_POLY1305, &bytes)
            .map_err(|_| "the secret key is not a ChaCha20-Poly1305 key".to_string())?;
        Ok(SecretKey {
            key: LessSafeKey::new(key),
            id,
        })
    }

    /// The key of a file.
    pub fn read(path: &Path) -> Result<SecretKey, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        SecretKey::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// The text of a new random key.
    pub fn generate() -> Result<String, String> {
        let mut bytes = [0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| "no random bytes".to_string())?;
        Ok(hex(&bytes))
    }

    /// The id of the key: the first 8 bytes of its SHA-256 in hex. The id
    /// names the key and does not give it.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Seals the secret of the credential `name` of `kind`.
    pub fn seal(
        &self,
        name: &str,
        kind: CredentialKind,
        secret: &SecretInput,
    ) -> Result<Sealed, String> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "no random bytes".to_string())?;
        let mut data = serde_json::to_vec(secret).map_err(|e| e.to_string())?;
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(name, kind)),
                &mut data,
            )
            .map_err(|_| "the secret cannot be sealed".to_string())?;
        let mut bytes = Vec::with_capacity(1 + NONCE_LEN + data.len());
        bytes.push(FORMAT);
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&data);
        Ok(Sealed {
            key_id: self.id.clone(),
            bytes,
        })
    }

    /// Opens the sealed secret of the credential `name` of `kind`.
    pub fn open(
        &self,
        name: &str,
        kind: CredentialKind,
        sealed: &Sealed,
    ) -> Result<SecretInput, String> {
        if sealed.key_id != self.id {
            return Err(format!(
                "the secret is sealed by the key {} and the secret key is {}",
                sealed.key_id, self.id
            ));
        }
        let b = &sealed.bytes;
        if b.len() < 1 + NONCE_LEN || b[0] != FORMAT {
            return Err("the sealed secret has an unknown format".into());
        }
        let nonce: [u8; NONCE_LEN] = b[1..1 + NONCE_LEN].try_into().expect("nonce length");
        let mut data = b[1 + NONCE_LEN..].to_vec();
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad(name, kind)),
                &mut data,
            )
            .map_err(|_| "the sealed secret does not open with the secret key".to_string())?;
        serde_json::from_slice(plain).map_err(|_| "the sealed secret is not a secret".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SecretKey {
        SecretKey::parse(&SecretKey::generate().unwrap()).unwrap()
    }

    fn password(v: &str) -> SecretInput {
        SecretInput {
            value: v.into(),
            passphrase: None,
        }
    }

    #[test]
    fn a_sealed_secret_opens_only_with_its_key_name_and_kind() {
        let k = key();
        let s = k
            .seal("lab", CredentialKind::Password, &password("hunter2"))
            .unwrap();
        assert_eq!(s.key_id, k.id());
        assert!(!s.bytes.windows(7).any(|w| w == b"hunter2"));
        assert_eq!(
            k.open("lab", CredentialKind::Password, &s).unwrap(),
            password("hunter2")
        );
        assert!(k.open("other", CredentialKind::Password, &s).is_err());
        assert!(k.open("lab", CredentialKind::ApiKey, &s).is_err());
        let other = key();
        let e = other.open("lab", CredentialKind::Password, &s).unwrap_err();
        assert!(e.contains("sealed by the key"), "{e}");
        let forged = Sealed {
            key_id: other.id().to_string(),
            bytes: s.bytes.clone(),
        };
        assert!(
            other
                .open("lab", CredentialKind::Password, &forged)
                .is_err()
        );
        let mut flipped = s.clone();
        *flipped.bytes.last_mut().unwrap() ^= 1;
        assert!(k.open("lab", CredentialKind::Password, &flipped).is_err());
    }

    #[test]
    fn two_seals_of_one_secret_differ() {
        let k = key();
        let a = k
            .seal("lab", CredentialKind::Password, &password("p"))
            .unwrap();
        let b = k
            .seal("lab", CredentialKind::Password, &password("p"))
            .unwrap();
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn a_key_is_64_hex_digits_and_no_debug_form_gives_a_secret() {
        assert!(SecretKey::parse("00").is_err());
        assert!(SecretKey::parse(&"g".repeat(64)).is_err());
        let text = format!(" {}\n", "ab".repeat(32));
        let k = SecretKey::parse(&text).unwrap();
        assert_eq!(k.id().len(), 16);
        assert!(!format!("{k:?}").contains("abab"));
        assert_eq!(format!("{:?}", password("hunter2")), "SecretInput(..)");
    }

    #[test]
    fn the_check_of_a_secret_follows_its_kind() {
        assert!(password("").check(CredentialKind::Password).is_err());
        assert!(password("p").check(CredentialKind::Password).is_ok());
        assert!(password("p").check(CredentialKind::SshKey).is_err());
        let key = SecretInput {
            value: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
                .into(),
            passphrase: Some("x".into()),
        };
        assert!(key.check(CredentialKind::SshKey).is_ok());
        assert!(key.check(CredentialKind::ApiKey).is_err());
        assert!(
            password(&"x".repeat(MAX_SECRET + 1))
                .check(CredentialKind::ApiKey)
                .is_err()
        );
    }
}
