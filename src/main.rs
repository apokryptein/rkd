mod cli;
mod crypto;
mod encoding;
mod kdf;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    // Parse cli flags and hand off to handle_command
    let cli = cli::Cli::parse();
    cli::handle_command(cli.command)
}
