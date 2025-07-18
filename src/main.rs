use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use pbkdf2::pbkdf2_hmac;
use rand::{TryRngCore, rngs::OsRng};
use sha2::Sha256;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
enum KdfAlgorithm {
    Pbkdf2,
    Argon2i,
    Argon2id,
    Scrypt,
}

const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Derive {
            password,
            method,
            iterations,
            length,
            memory,
        } => {
            match method {
                KdfAlgorithm::Pbkdf2 => {
                    // DEBUG
                    println!("[INFO] Hashing password using PBKDF2");

                    // Get iterations or use default
                    let iterations = iterations.unwrap_or(DEFAULT_PBKDF2_ITERATIONS);

                    // Generate random 16-byte salte
                    let salt: [u8; 16] = generate_salt();

                    // Generate key
                    let hash = pbkdf2_hash(&password, &salt, iterations, length);

                    // Alert user
                    println!("Salt: {}", hex::encode(salt));
                    println!("key:  {}", hex::encode(hash));
                }
                KdfAlgorithm::Argon2i => println!("Argon2i not yet implemented"),
                KdfAlgorithm::Argon2id => println!("Argon2id not yet implemented"),
                KdfAlgorithm::Scrypt => println!("Scrypt not yet implemented"),
            }
        }
    }
    Ok(())
}

// pbkdf2_hash calculates a derived key using the PBKDF2 KDF given a
// random salt
fn pbkdf2_hash(password: &str, salt: &[u8], iterations: u32, length_bits: usize) -> Vec<u8> {
    let mut hash = vec![0u8; length_bits / 8];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut hash);

    hash
}

// generate_salt generates a random salt of a given size
fn generate_salt<const N: usize>() -> [u8; N] {
    let mut salt = [0u8; N];
    let _ = OsRng.try_fill_bytes(&mut salt);
    salt
}
