use argon2::Argon2;
use argon2::password_hash::rand_core::RngCore;
use chacha20poly1305::aead::{KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key};

use crate::error::PassmanError;

pub fn gen_new_cipher(pwd: &[u8]) -> Result<(ChaCha20Poly1305, [u8; 16], [u8; 12]), PassmanError> {
    // Generate a random salt for key derivation
    let mut random_salt = [0u8; 16];
    OsRng.fill_bytes(&mut random_salt);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // let nonce = chacha20poly1305::Nonce::from_slice(&nonce);

    // Derive encryption key using Argon2
    let mut output_key = [0u8; 32];
    Argon2::default().hash_password_into(pwd, &random_salt, &mut output_key)?;

    // Create and return the cipher
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&output_key));
    Ok((cipher, random_salt, nonce))
}

pub fn gen_decrypt_cipher(pwd: &[u8], salt: &[u8]) -> Result<ChaCha20Poly1305, PassmanError> {
    let mut decrypt_key = [0u8; 32];

    Argon2::default().hash_password_into(pwd, salt, &mut decrypt_key)?;

    Ok(ChaCha20Poly1305::new(Key::from_slice(&decrypt_key)))
}
