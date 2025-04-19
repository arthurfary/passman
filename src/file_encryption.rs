use std::fs::File;
use std::io::prelude::*;

pub fn create_encrypted_file(
    filename: &str,
    b64_salt: &String,
    nonce: &[u8],
    b64_content: &[u8],
) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(b64_content)?;

    Ok(())
}

fn decrypt_file() {}
