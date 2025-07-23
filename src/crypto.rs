use rand::{TryRngCore, rngs::OsRng};
use subtle::ConstantTimeEq;

/// constant_time_eq compares two byte slices using constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// generate_salt generates a random salt of a given size
pub fn generate_salt(length: usize) -> Vec<u8> {
    // Instantiate salt vec
    let mut salt = vec![0u8; length];

    // Fill with random bytes
    let _ = OsRng.try_fill_bytes(&mut salt);

    salt
}
