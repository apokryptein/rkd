use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::cli::{InputFormat, OutputFormat};

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
pub fn print_output(salt: &[u8], key: &[u8], format: OutputFormat) {
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
    }
}
