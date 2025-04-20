use base64::prelude::*;
use chacha20poly1305::aead::generic_array::GenericArray;
use std::fs::File;
use std::io::prelude::*;

use argon2::Argon2;
use argon2::password_hash::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305, Key};

use crate::error::PassmanError;

pub fn create_encrypted_file(
    filename: &str,
    salt_bytes: &[u8],
    nonce: &[u8],
    content_bytes: &[u8],
) -> Result<(), PassmanError> {
    let mut file = File::create(filename)?;

    // Encode everything with base64
    let salt_b64 = BASE64_STANDARD.encode(salt_bytes);
    let nonce_b64 = BASE64_STANDARD.encode(nonce);
    let content_b64 = BASE64_STANDARD.encode(content_bytes);

    // Write to file with minimal headers
    let file_content = format!("S:{}\nN:{}\nC:{}", salt_b64, nonce_b64, content_b64);

    file.write_all(file_content.as_bytes())?;
    Ok(())
}

pub fn decrypt_file(filename: &str, pass: &[u8]) -> Result<(), PassmanError> {
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

    let mut decrypt_key = [0u8; 32];

    Argon2::default().hash_password_into(pass, &salt, &mut decrypt_key)?;
    let decrypt_cipher = ChaCha20Poly1305::new(Key::from_slice(&decrypt_key));

    let decrypted_content = decrypt_cipher.decrypt(&nonce, content.as_ref())?;

    let decrypted_text = &String::from_utf8(decrypted_content).map_err(PassmanError::Utf8Error)?;
    println!("Decrypted: {}", decrypted_text);

    Ok(())
}
