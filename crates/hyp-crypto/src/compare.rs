//! Shared comparison for authentication tokens and integrity digests.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

/// Compares bytes through constant-time HMAC digest verification using a fresh random key.
/// Returns false if OS randomness is unavailable; never short-circuits on input lengths.
pub fn constant_time_eq(expected: &[u8], candidate: &[u8]) -> bool {
    let mut random_key = Zeroizing::new([0u8; 32]);
    if SystemRandom::new().fill(&mut *random_key).is_err() {
        return false;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, &*random_key);
    let tag = hmac::sign(&key, expected);
    hmac::verify(&key, candidate, tag.as_ref()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn byte_equality_and_nearby_differences() {
        for size in [0, 1, 31, 32, 64, 65, 2048] {
            let bytes: Vec<u8> = (0..size).map(|index| (index % 256) as u8).collect();
            assert!(constant_time_eq(&bytes, &bytes));
            let mut longer = bytes.clone();
            longer.push(0);
            assert!(!constant_time_eq(&bytes, &longer));
            assert!(!constant_time_eq(&longer, &bytes));
            for index in 0..size {
                let mut changed = bytes.clone();
                changed[index] ^= 0x80;
                assert!(
                    !constant_time_eq(&bytes, &changed),
                    "size={size} index={index}"
                );
            }
        }
    }
}
