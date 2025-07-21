use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use rand::{TryRngCore, rngs::OsRng};
use scrypt::scrypt;
use sha2::Sha256;

use crate::cli::KdfAlgorithm;

// Default PBKDF2 values
const DEFAULT_SALT_LENGTH: usize = 16;
const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;
const MIN_PBKDF2_ITERATIONS: u32 = 100_000;

// Default scrypt values
const DEFAULT_SCRYPT_N: u32 = 32768; // 2^15
const DEFAULT_SCRYPT_R: u32 = 8;
const DEFAULT_SCRYPT_P: u32 = 1;

// Default argon2 values
const DEFAULT_ARGON2_TIME: u32 = 3;
const DEFAULT_ARGON2_MEMORY: u32 = 65536; // 64 MB
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;

/// DeriveOptions represents available options provided to all
/// key derivation functions
pub struct DeriveOptions {
    pub method: KdfAlgorithm,
    pub iterations: Option<u32>,
    pub length_bits: usize,
    pub memory_kb: Option<u32>,
    pub parallelism: Option<u32>,
}

/// derive_key generates a random salt, parses the provided KDF and calls
/// the appropriate KDF function
pub fn derive_key(password: &str, options: DeriveOptions) -> Result<(Vec<u8>, Vec<u8>)> {
    let salt: [u8; DEFAULT_SALT_LENGTH] = generate_salt();

    let key = match options.method {
        KdfAlgorithm::Pbkdf2 => derive_pbkdf2(password, &salt, options)?,
        KdfAlgorithm::Argon2i => derive_argon2(password, &salt, options, Algorithm::Argon2i)?,
        KdfAlgorithm::Argon2id => derive_argon2(password, &salt, options, Algorithm::Argon2id)?,
        KdfAlgorithm::Scrypt => derive_scrypt(password, &salt, options)?,
    };

    Ok((salt.to_vec(), key))
}

/// derive_pbkdf2 calculates a derived key using the PBKDF2 KDF given a
/// random salt
pub fn derive_pbkdf2(password: &str, salt: &[u8], options: DeriveOptions) -> Result<Vec<u8>> {
    // Get iterations or use default
    let iterations = options.iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);

    // Ensure we have the minimum number of iterations (100_000)
    if iterations < MIN_PBKDF2_ITERATIONS {
        eprintln!(
            "[WARN] {} iterations is below the recommended minimum of {}",
            iterations, MIN_PBKDF2_ITERATIONS
        );
    }

    // Convert length in bytes to length in bits
    let length_bytes = options.length_bits / 8;

    // Generate key
    let mut hash = vec![0u8; length_bytes];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut hash);

    Ok(hash)
}

/// derive_scrypt calculates a derived key using the scrypt KDF given a random salt
pub fn derive_scrypt(password: &str, salt: &[u8], options: DeriveOptions) -> Result<Vec<u8>> {
    // Set CPU/memory cost
    let n = options
        .memory_kb
        .map(|mem| (mem * 1024 / 128).next_power_of_two())
        .unwrap_or(DEFAULT_SCRYPT_N);

    // Set block size
    let r = DEFAULT_SCRYPT_R;

    // Set parallelism
    let p = options.parallelism.unwrap_or(DEFAULT_SCRYPT_P);

    // Convert length in bits to length in bytes
    let length_bytes = options.length_bits / 8;

    // Instantiate scrypt params
    let params = scrypt::Params::new(n.trailing_zeros() as u8, r, p, length_bytes)
        .map_err(|e| anyhow!("[ERR] invalid scrypt parameters: {:?}", e))?;

    // Generate key
    let mut hash = vec![0u8; length_bytes];
    scrypt(password.as_bytes(), salt, &params, &mut hash)
        .map_err(|e| anyhow!("[ERR] scrypt failed: {}", e))?;

    Ok(hash)
}

/// derive_argon2 calculates a derived key using the Argon2id KDF given a random salt
pub fn derive_argon2(
    password: &str,
    salt: &[u8],
    options: DeriveOptions,
    variant: Algorithm,
) -> Result<Vec<u8>> {
    let time = options.iterations.unwrap_or(DEFAULT_ARGON2_TIME);
    let memory = options.memory_kb.unwrap_or(DEFAULT_ARGON2_MEMORY);
    let parallelism = options.parallelism.unwrap_or(DEFAULT_ARGON2_PARALLELISM);

    // Convert length in bits to length in bytes
    let length_bytes = options.length_bits / 8;

    // Instantiate argon2 parameters
    let params = Params::new(memory, time, parallelism, Some(length_bytes))
        .map_err(|e| anyhow!("[ERR] invalid argon2 parameters: {}", e))?;

    // Instantiate argon2id algorithm
    let argon2 = Argon2::new(variant, Version::V0x13, params);

    // Generate key
    let mut hash = vec![0u8; length_bytes];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut hash)
        .map_err(|e| anyhow!("[ERR] argon2 failed: {}", e))?;

    Ok(hash)
}

/// generate_salt generates a random salt of a given size
pub fn generate_salt<const N: usize>() -> [u8; N] {
    let mut salt = [0u8; N];
    let _ = OsRng.try_fill_bytes(&mut salt);
    salt
}
