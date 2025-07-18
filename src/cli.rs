use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

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
        // will change default to argon2id after
        // implementation
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
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum KdfAlgorithm {
    Pbkdf2,
    Argon2i,
    Argon2id,
    Scrypt,
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
        } => {
            let options = DeriveOptions {
                method,
                iterations,
                length_bits: length,
                memory_kb: memory,
            };

            let (salt, key) = kdf::derive_key(&password, options)?;

            // Alert user
            // TODO: impelement formatting package
            println!("Salt: {}", hex::encode(salt));
            println!("Key:  {}", hex::encode(key));

            Ok(())
        }
    }
}
