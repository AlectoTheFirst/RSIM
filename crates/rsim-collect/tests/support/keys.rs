//! The store keys of the tests: random, made one time in each test process.

use std::sync::OnceLock;

use rsim_store::Keys;

/// The hash key and the wrap key of the test process.
pub fn keys() -> Keys {
    static KEYS: OnceLock<[[u8; 32]; 2]> = OnceLock::new();
    let k = KEYS.get_or_init(|| {
        let mut k = [[0u8; 32]; 2];
        for b in &mut k {
            getrandom::fill(b).unwrap();
        }
        k
    });
    Keys::new(k[0], k[1])
}
