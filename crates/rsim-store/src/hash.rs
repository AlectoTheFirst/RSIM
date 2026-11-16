use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::StoreError;

/// A keyed BLAKE3 hash. It names blobs and device manifests, and it is the
/// change hash of a section.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({self})")
    }
}

impl FromStr for Hash {
    type Err = StoreError;

    fn from_str(s: &str) -> Result<Hash, StoreError> {
        Ok(Hash(hex::<32>(s)?))
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Hash, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn hex<const N: usize>(s: &str) -> Result<[u8; N], StoreError> {
    let bad = || StoreError::Invalid(format!("{s:?} is not {N} bytes of lower-case hex"));
    if s.len() != 2 * N {
        return Err(bad());
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        let pair = s.get(2 * i..2 * i + 2).ok_or_else(bad)?;
        if pair.bytes().any(|c| c.is_ascii_uppercase()) {
            return Err(bad());
        }
        *o = u8::from_str_radix(pair, 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// The 2 keys of a store. Both are outside the store. The hash key makes
/// the names of blobs and manifests. The wrap key encrypts the data key of
/// each blob.
#[derive(Clone)]
pub struct Keys {
    hash: [u8; 32],
    wrap: [u8; 32],
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys(..)")
    }
}

impl Keys {
    pub fn new(hash: [u8; 32], wrap: [u8; 32]) -> Keys {
        Keys { hash, wrap }
    }

    /// Reads the keys from 2 lines of 64 hex digits: the hash key, then the
    /// wrap key.
    pub fn from_hex(text: &str) -> Result<Keys, StoreError> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let mut next = || {
            lines
                .next()
                .ok_or_else(|| StoreError::Invalid("the key text needs 2 lines".into()))
        };
        let hash = hex::<32>(next()?)?;
        let wrap = hex::<32>(next()?)?;
        if hash == wrap {
            return Err(StoreError::Invalid(
                "the hash key and the wrap key must be different".into(),
            ));
        }
        Ok(Keys { hash, wrap })
    }

    /// The keyed BLAKE3 hash of the bytes.
    pub fn hash(&self, bytes: &[u8]) -> Hash {
        Hash(*blake3::keyed_hash(&self.hash, bytes).as_bytes())
    }

    pub(crate) fn wrap_key(&self) -> &[u8; 32] {
        &self.wrap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_has_a_hex_text_form() {
        let k = Keys::new([1; 32], [2; 32]);
        let h = k.hash(b"abc");
        assert_eq!(h.to_string().parse::<Hash>().unwrap(), h);
        assert!("AB".repeat(32).parse::<Hash>().is_err());
        assert_ne!(Keys::new([3; 32], [2; 32]).hash(b"abc"), h);
    }

    #[test]
    fn keys_come_from_2_hex_lines() {
        let text = format!("{}\n{}\n", "01".repeat(32), "02".repeat(32));
        let k = Keys::from_hex(&text).unwrap();
        assert_eq!(k.hash(b"x"), Keys::new([1; 32], [2; 32]).hash(b"x"));
        assert!(Keys::from_hex(&"01".repeat(32)).is_err());
        let same = format!("{}\n{}\n", "01".repeat(32), "01".repeat(32));
        assert!(Keys::from_hex(&same).is_err());
    }
}
