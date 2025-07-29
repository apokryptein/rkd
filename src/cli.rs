use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

use crate::crypto::constant_time_eq;
use crate::encoding::{self, print_output};
use crate::kdf::{self, DeriveOptions};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Derive {
        /// Password
        #[arg(long, short)]
        password: String,

        /// Desired algorithm: PBKDF2, Argon2
        #[arg(long, short, value_enum, default_value = "pbkdf2")]
        method: KdfAlgorithm,

        /// Number of iterations
        #[arg(long, short)]
        iterations: Option<u32>,

        /// Key length in bits
        #[arg(long, default_value = "256")]
        length: usize,

        /// Memory cost in KB (Argon2/scrypt)
        #[arg(long)]
        memory: Option<u32>,

        /// Parallelism factor (Argon2/scrypt)
        #[arg(long)]
        parallel: Option<u32>,

        /// Output format
        #[arg(long, short, value_enum, default_value = "hex")]
        format: OutputFormat,
    },
    Verify {
        /// Password to verify
        #[arg(long, short)]
        password: String,

        /// Hash (hex or base64)
        #[arg(long)]
        hash: String,

        /// Salt (hex or base64)
        #[arg(long)]
        salt: String,

        /// KDF algorithm
        #[arg(long, short, value_enum, default_value = "pbkdf2")]
        method: KdfAlgorithm,

        /// Parameters used (if different from defaults)
        #[arg(long, short)]
        iterations: Option<u32>,

        #[arg(long)]
        memory: Option<u32>,

        #[arg(long, default_value = "256")]
        length: usize,

        #[arg(long)]
        parallel: Option<u32>,

        /// Input format
        #[arg(long, short, value_enum, default_value = "hex")]
        format: InputFormat,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum KdfAlgorithm {
    Pbkdf2,
    Argon2i,
    Argon2id,
    Scrypt,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum InputFormat {
    Hex,
    Base64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum OutputFormat {
    Hex,
    Base64,
    Phc,
}

/// handle_command instantiates DeriveOptions using provided CLI
/// values, passes them to kdf::derive_key and returns the result
pub fn handle_command(command: Commands) -> Result<()> {
    match command {
        Commands::Derive {
            password,
            method,
            iterations,
            length,
            memory,
            parallel,
            format,
        } => {
            let options = DeriveOptions {
                method,
                iterations,
                length_bits: length,
                memory_kb: memory,
                parallelism: parallel,
                salt: None,
            };

            // Derive key
            let (salt, key) = kdf::derive_key(&password, &options)?;

            // Alert user
            print_output(&salt, &key, format, &options);

            Ok(())
        }
        Commands::Verify {
            password,
            hash,
            salt,
            method,
            iterations,
            memory,
            length,
            parallel,
            format,
        } => {
            // Decode salt and hash bytes provided by user
            let expected_hash = encoding::decode_input(&hash, format)?;
            let salt_bytes = encoding::decode_input(&salt, format)?;

            // Set options
            let options = DeriveOptions {
                method,
                iterations,
                length_bits: length,
                memory_kb: memory,
                parallelism: parallel,
                salt: Some(salt_bytes),
            };

            // Generate key using provided salt and options
            let (_, key) = kdf::derive_key(&password, &options)?;

            // Compare with provided hash
            match constant_time_eq(&expected_hash as &[u8], &key as &[u8]) {
                true => {
                    println!("[SUCCESS] Password verified");
                    Ok(())
                }
                false => {
                    println!("[FAIL] Password verification failed");
                    std::process::exit(1);
                }
            }
        }
    }
}
