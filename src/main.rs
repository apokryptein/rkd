use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

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
            println!("Calling derive command");
            println!(
                "{} {:?} {:?} {} {:?}",
                password, method, iterations, length, memory
            );
        }
    }
    Ok(())
}
