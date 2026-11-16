//! The encrypted form of a raw section.
//!
//! ```text
//! magic "RSB1" | wrap nonce (24) | wrapped data key (48) | data nonce (24) | ciphertext and tag
//! ```
//!
//! The cipher is XChaCha20-Poly1305, the form of ChaCha20-Poly1305 with a
//! 24-byte nonce, so random nonces are safe. Each blob has its own random
//! data key, which the wrap key encrypts. The blob name is the associated
//! data of both encryptions, so a blob does not decrypt under another name.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

use crate::{Hash, Keys, StoreError};

const MAGIC: &[u8; 4] = b"RSB1";
const NONCE: usize = 24;
const WRAPPED: usize = 32 + 16;
const HEADER: usize = MAGIC.len() + NONCE + WRAPPED + NONCE;

/// A source of random bytes for data keys and nonces.
pub trait Entropy: Send {
    fn fill(&mut self, buf: &mut [u8]);
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(*key).into())
}

fn seal(key: &[u8; 32], nonce: &[u8; NONCE], aad: &[u8], msg: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(&(*nonce).into(), Payload { msg, aad })
        .expect("the message is shorter than the limit of the cipher")
}

fn open(key: &[u8; 32], nonce: &[u8], aad: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let nonce: [u8; NONCE] = nonce.try_into().ok()?;
    cipher(key)
        .decrypt(&nonce.into(), Payload { msg, aad })
        .ok()
}

pub(crate) fn encrypt(
    keys: &Keys,
    name: &Hash,
    plain: &[u8],
    entropy: &mut dyn Entropy,
) -> Vec<u8> {
    let mut data_key = [0u8; 32];
    let mut wrap_nonce = [0u8; NONCE];
    let mut data_nonce = [0u8; NONCE];
    entropy.fill(&mut data_key);
    entropy.fill(&mut wrap_nonce);
    entropy.fill(&mut data_nonce);
    let aad = &name.0;
    let wrapped = seal(keys.wrap_key(), &wrap_nonce, aad, &data_key);
    let body = seal(&data_key, &data_nonce, aad, plain);
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&wrap_nonce);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(&data_nonce);
    out.extend_from_slice(&body);
    out
}

pub(crate) fn decrypt(keys: &Keys, name: &Hash, bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    let bad = |what: &str| StoreError::Integrity(format!("blob {name}: {what}"));
    if bytes.len() < HEADER + 16 || &bytes[..4] != MAGIC {
        return Err(bad("not a blob"));
    }
    let (wrap_nonce, rest) = bytes[4..].split_at(NONCE);
    let (wrapped, rest) = rest.split_at(WRAPPED);
    let (data_nonce, body) = rest.split_at(NONCE);
    let aad = &name.0;
    let data_key: [u8; 32] = open(keys.wrap_key(), wrap_nonce, aad, wrapped)
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| bad("the wrap key does not open the data key"))?;
    let plain = open(&data_key, data_nonce, aad, body)
        .ok_or_else(|| bad("the data key does not open the content"))?;
    if keys.hash(&plain) != *name {
        return Err(bad("the content does not have the name of the blob"));
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u8);
    impl Entropy for Counter {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
        }
    }

    #[test]
    fn a_blob_decrypts_only_with_its_keys_and_its_name() {
        let keys = Keys::new([1; 32], [2; 32]);
        let plain = b"interfaces { ethernet eth0 }";
        let name = keys.hash(plain);
        let blob = encrypt(&keys, &name, plain, &mut Counter(0));
        assert!(!blob.windows(plain.len()).any(|w| w == plain));
        assert_eq!(decrypt(&keys, &name, &blob).unwrap(), plain);

        let wrong_wrap = Keys::new([1; 32], [3; 32]);
        assert!(decrypt(&wrong_wrap, &name, &blob).is_err());
        let other = keys.hash(b"other");
        assert!(decrypt(&keys, &other, &blob).is_err());
        let mut flipped = blob.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(decrypt(&keys, &name, &flipped).is_err());
        assert!(decrypt(&keys, &name, &blob[..10]).is_err());
    }
}
