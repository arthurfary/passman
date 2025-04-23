use base64::prelude::*;
use chacha20poly1305::aead::generic_array::GenericArray;
use std::fs::{File, create_dir_all, read_to_string};
use std::io::prelude::*;

use chacha20poly1305::aead::Aead;

use crate::error::PassmanError;
use crate::passman_encryption;

const OUTPUT_PATH: &str = "./test/";

pub fn create_encrypted_file(
    filename: &str,
    pwd: &str,
    service_name: &str,
    content: &[u8],
) -> Result<(), PassmanError> {
    // creates path if it doesnt exist
    create_dir_all(OUTPUT_PATH).unwrap();

    let mut file = File::create(OUTPUT_PATH.to_owned() + filename)?;
    let (cypher, salt, nonce) = passman_encryption::gen_new_cipher(pwd.as_bytes())?;
    let encrypted_content = cypher.encrypt(&nonce, content.as_ref())?;

    // Encode everything with base64 to avoid separator confusion
    let salt_b64 = BASE64_STANDARD.encode(salt);
    let nonce_b64 = BASE64_STANDARD.encode(nonce);
    let service_name_b64 = BASE64_STANDARD.encode(service_name);
    let content_b64 = BASE64_STANDARD.encode(encrypted_content);

    // Write to file with separator
    let file_content = format!(
        "{}|{}|{}|{}",
        salt_b64, nonce_b64, service_name_b64, content_b64
    );
    file.write_all(file_content.as_bytes())?;

    Ok(())
}

pub fn read_encrypted_file(filename: &str, pwd: &str) -> Result<(String, String), PassmanError> {
    let content = read_to_string(filename)?;
    let parts: Vec<&str> = content.split('|').collect();

    // Decode from base64
    let salt = BASE64_STANDARD.decode(parts[0])?;
    let nonce = BASE64_STANDARD.decode(parts[1])?;
    let service_name = BASE64_STANDARD.decode(parts[2])?;
    let encrypted_content = BASE64_STANDARD.decode(parts[3])?;

    let nonce = GenericArray::clone_from_slice(&nonce);

    // Recreate the cipher from the password and salt
    let cypher = passman_encryption::gen_decrypt_cipher(pwd.as_bytes(), &salt)?;

    // Decrypt the content
    let decrypted_content = cypher.decrypt(&nonce, encrypted_content.as_ref())?;

    Ok((
        String::from_utf8(service_name)?,
        String::from_utf8(decrypted_content)?,
    ))
}
