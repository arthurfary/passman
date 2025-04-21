use base64::prelude::*;
use chacha20poly1305::aead::generic_array::GenericArray;
use std::fs::File;
use std::io::prelude::*;

use chacha20poly1305::aead::Aead;

use crate::error::PassmanError;
use crate::passman_encryption;

pub fn create_encrypted_file(
    filename: &str,
    pwd: &str,
    content: &[u8],
) -> Result<(), PassmanError> {
    let mut file = File::create(filename)?;

    let (cypher, salt, nonce) = passman_encryption::gen_new_cipher(pwd.as_bytes())?;

    let encrypted_content = cypher.encrypt(&nonce, content.as_ref())?;

    // Encode everything with base64
    let salt_b64 = BASE64_STANDARD.encode(salt);
    let nonce_b64 = BASE64_STANDARD.encode(nonce);
    let content_b64 = BASE64_STANDARD.encode(encrypted_content);

    // Write to file with minimal headers
    let file_content = format!("S:{}\nN:{}\nC:{}", salt_b64, nonce_b64, content_b64);

    file.write_all(file_content.as_bytes())?;
    Ok(())
}

pub fn decrypt_file(filename: &str, pass: &[u8]) -> Result<String, PassmanError> {
    let mut file = File::open(filename)?;
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)?;

    let file_content = file_content.splitn(3, "\n");

    let file_content: Vec<&str> = file_content.collect();

    let salt = BASE64_STANDARD.decode(&(String::from(file_content[0]))[2..])?;
    let nonce = BASE64_STANDARD.decode(&(String::from(file_content[1]))[2..])?;
    let content = BASE64_STANDARD.decode(&(String::from(file_content[2]))[2..])?;

    // convert nonce to generic array
    let nonce = GenericArray::clone_from_slice(&nonce);

    let decrypt_cipher = passman_encryption::gen_decrypt_cipher(pass, &salt)?;

    //TODO: need to find a way of handeling wrong pass
    let decrypted_content = decrypt_cipher.decrypt(&nonce, content.as_ref())?;

    let decrypted_text = String::from_utf8(decrypted_content).map_err(PassmanError::Utf8Error)?;

    Ok(decrypted_text)
}
