//! The query identifier: the canonical JSON text of the query arguments,
//! without the twin, in URL-safe base64 with no padding. Above a length
//! limit, the identifier is a hash of the text, and the server keeps the
//! text under it.

/// The longest canonical text that the identifier holds itself.
pub const MAX_INLINE: usize = 1024;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// URL-safe base64 with no padding.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// The bytes of URL-safe base64 with no padding, or `None`.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let value = |c: u8| ALPHABET.iter().position(|a| *a == c).map(|p| p as u32);
    for chunk in text.as_bytes().chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= value(*c)? << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((n >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

/// A 128-bit FNV-1a hash in hexadecimal: stable across runs and versions.
pub fn hash(text: &str) -> String {
    let mut h: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    for b in text.bytes() {
        h ^= u128::from(b);
        h = h.wrapping_mul(0x0000_0000_0100_0000_0000_0000_0000_013b);
    }
    format!("{h:032x}")
}

/// The identifier of a canonical query text: `q<base64>`, or `h<hash>`
/// above the length limit.
pub fn of(text: &str) -> String {
    if text.len() <= MAX_INLINE {
        format!("q{}", encode(text.as_bytes()))
    } else {
        format!("h{}", hash(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_round_trips_through_base64() {
        for t in ["", "a", "ab", "abc", "abcd", "{\"source.ip\":\"10.0.0.1\"}"] {
            assert_eq!(decode(&encode(t.as_bytes())).unwrap(), t.as_bytes(), "{t}");
        }
        assert_eq!(encode(b"Man"), "TWFu");
        assert_eq!(encode(b"\xfb\xff"), "-_8");
        assert!(decode("a").is_none());
        assert!(decode("a*bc").is_none());
    }

    #[test]
    fn a_long_text_gets_a_stable_hash() {
        let long = "x".repeat(MAX_INLINE + 1);
        assert!(of(&long).starts_with('h'));
        assert_eq!(of(&long), of(&long));
        assert_eq!(hash(""), "6c62272e07bb014262b821756295c58d");
        assert!(of("{}").starts_with('q'));
    }
}
