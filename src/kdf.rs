use anyhow::{Result, anyhow};
use pbkdf2::pbkdf2_hmac;
use rand::{TryRngCore, rngs::OsRng};
use sha2::Sha256;

use crate::cli::KdfAlgorithm;

// Default values for iterations and salt
const DEFAULT_SALT_LENGTH: usize = 16;
const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;
const MIN_PBKDF2_ITERATIONS: u32 = 100_000;

/// DeriveOptions represents available options provided to all
/// key derivation functions
pub struct DeriveOptions {
    pub method: KdfAlgorithm,
    pub iterations: Option<u32>,
    pub length_bits: usize,
    pub memory_kb: Option<u32>,
}

/// derive_key generates a random salt, parses the provided KDF and calls
/// the appropriate KDF function
pub fn derive_key(password: &str, options: DeriveOptions) -> Result<(Vec<u8>, Vec<u8>)> {
    let salt: [u8; DEFAULT_SALT_LENGTH] = generate_salt();

    let key = match options.method {
        KdfAlgorithm::Pbkdf2 => derive_pbkdf2(password, &salt, options),
        KdfAlgorithm::Argon2i => return Err(anyhow!("Argon2i not yet implemented")),
        KdfAlgorithm::Argon2id => return Err(anyhow!("Argon2id not yet implemented")),
        KdfAlgorithm::Scrypt => return Err(anyhow!("Scrypt not yet implemented")),
    };

    Ok((salt.to_vec(), key))
}

/// pbkdf2_hash calculates a derived key using the PBKDF2 KDF given a
/// random salt
pub fn derive_pbkdf2(password: &str, salt: &[u8], options: DeriveOptions) -> Vec<u8> {
    // Get iterations or use default
    let iterations = options.iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);

    if iterations < MIN_PBKDF2_ITERATIONS {
        eprintln!(
            "[WARN] {} iterations is below the recommended minimum of {}",
            iterations, MIN_PBKDF2_ITERATIONS
        );
    }

    let length_bytes = options.length_bits / 8;

    let mut hash = vec![0u8; length_bytes];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut hash);

    hash
}

/// generate_salt generates a random salt of a given size
pub fn generate_salt<const N: usize>() -> [u8; N] {
    let mut salt = [0u8; N];
    let _ = OsRng.try_fill_bytes(&mut salt);
    salt
}
