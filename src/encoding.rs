use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::{
    cli::{InputFormat, KdfAlgorithm, OutputFormat},
    kdf::{self, DeriveOptions},
};

/// decode_input decodes input from the user provided a desired InputFormat: base64 or hex
pub fn decode_input(input: &str, format: InputFormat) -> Result<Vec<u8>> {
    // Match on InputFormat and decode accordingly
    match format {
        InputFormat::Hex => {
            hex::decode(input).map_err(|e| anyhow!("[ERR] failed to decode hex: {}", e))
        }
        InputFormat::Base64 => BASE64
            .decode(input)
            .map_err(|e| anyhow!("[ERR] failed to decode base64: {}", e)),
    }
}

/// print_output prints the resulting salt and key from a KDF operation in the desired OutputFormat
pub fn print_output(salt: &[u8], key: &[u8], format: OutputFormat, options: &DeriveOptions) {
    // Match on OutputFormat, encode and print
    match format {
        OutputFormat::Hex => {
            println!("Salt (hex):  {}", hex::encode(salt));
            println!("Key (hex):   {}", hex::encode(key));
        }
        OutputFormat::Base64 => {
            println!("Salt (base64):  {}", BASE64.encode(salt));
            println!("Key (base64):   {}", BASE64.encode(key));
        }
        OutputFormat::Phc => {
            let phc = encode_phc(salt, key, options);
            println!("PHC: {phc}");
        }
    }
}

// PHC string encoding specification: $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]
/// encode_phc encodes the resulting hash, salt, and parameters into a Password Hashing Competition
/// (PHC) string
pub fn encode_phc(salt: &[u8], key: &[u8], options: &DeriveOptions) -> String {
    let salt_b64 = BASE64.encode(salt);
    let key_b64 = BASE64.encode(key);

    match options.method {
        KdfAlgorithm::Argon2i => {
            let m = options.memory_kb.unwrap_or(kdf::DEFAULT_ARGON2_MEMORY);
            let t = options.iterations.unwrap_or(kdf::DEFAULT_ARGON2_TIME);
            let p = options
                .parallelism
                .unwrap_or(kdf::DEFAULT_ARGON2_PARALLELISM);
            format!("$argon2i$v=19$m={m},t={t},p={p}${salt_b64}${key_b64}")
        }
        KdfAlgorithm::Argon2id => {
            let m = options.memory_kb.unwrap_or(kdf::DEFAULT_ARGON2_MEMORY);
            let t = options.iterations.unwrap_or(kdf::DEFAULT_ARGON2_TIME);
            let p = options
                .parallelism
                .unwrap_or(kdf::DEFAULT_ARGON2_PARALLELISM);
            format!("$argon2id$v=19$m={m},t={t},p={p}${salt_b64}${key_b64}")
        }
        KdfAlgorithm::Pbkdf2 => {
            let i = options.iterations.unwrap_or(kdf::DEFAULT_PBKDF2_ITERATIONS);
            format!("$pbkdf2-sha256$i={i}${salt_b64}${key_b64}")
        }
        KdfAlgorithm::Scrypt => {
            let n = options
                .memory_kb
                .map(|mem| (mem * 1024 / 128).next_power_of_two())
                .unwrap_or(kdf::DEFAULT_SCRYPT_N);
            let ln = n.trailing_zeros();
            let r = kdf::DEFAULT_SCRYPT_R;
            let p = options.parallelism.unwrap_or(kdf::DEFAULT_SCRYPT_P);
            format!("$scrypt$ln={ln},r={r},p={p}${salt_b64}${key_b64}")
        }
    }
}
