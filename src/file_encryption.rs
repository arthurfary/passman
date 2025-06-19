use base64::prelude::*;
use chacha20poly1305::aead::generic_array::GenericArray;
use std::env;
use std::fs::{File, create_dir_all, read_to_string};
use std::io::prelude::*;
use std::path::PathBuf;

use chacha20poly1305::aead::Aead;

use crate::error::PassmanError;
use crate::passman_encryption;

//TODO: Make so the funcitons in this file dont use
// a filename and a service name,
// instead, filename should be service name

#[cfg(target_family = "unix")]
pub fn get_output_path() -> PathBuf {
    let mut path = PathBuf::from(env::var_os("HOME").unwrap_or_default());
    path.push(PathBuf::from(".passwords/"));
    path
}

#[cfg(target_family = "windows")]
pub fn get_output_path() -> PathBuf {
    let mut path = PathBuf::from(env::var_os("USERPROFILE").unwrap_or_default());
    path.push(PathBuf::from("\\Documents\\Passwords\\"));
    path
}

pub fn get_password_file_path(filename: &str) -> PathBuf {
    get_output_path().join(filename)
}

pub fn create_encrypted_file(
    pwd: &str,
    service_name: &str,
    content: &[u8],
) -> Result<(), PassmanError> {
    // creates path if it doesnt exist
    create_dir_all(get_output_path()).unwrap();

    let file_path = get_password_file_path(service_name);

    let mut file = File::create(file_path)?;
    let (cypher, salt, nonce) = passman_encryption::gen_new_cipher(pwd.as_bytes())?;

    let encrypted_content = cypher.encrypt(
        chacha20poly1305::Nonce::from_slice(&nonce),
        content.as_ref(),
    )?;

    let salt_b64 = BASE64_STANDARD.encode(salt);
    let nonce_b64 = BASE64_STANDARD.encode(nonce);
    // let service_name_b64 = BASE64_STANDARD.encode(service_name);
    let content_b64 = BASE64_STANDARD.encode(encrypted_content);

    let file_content = format!("{}|{}|{}", salt_b64, nonce_b64, content_b64);

    file.write_all(file_content.as_bytes())?;

    Ok(())
}

pub fn read_encrypted_file(file_path: PathBuf, pwd: &str) -> Result<String, PassmanError> {
    let content = read_to_string(file_path)?;
    let parts: Vec<&str> = content.split('|').collect();

    // Decode from base64
    let salt = BASE64_STANDARD.decode(parts[0])?;
    let nonce = BASE64_STANDARD.decode(parts[1])?;
    let encrypted_content = BASE64_STANDARD.decode(parts[2])?;

    let nonce = GenericArray::clone_from_slice(&nonce);

    let cypher = passman_encryption::gen_decrypt_cipher(pwd.as_bytes(), &salt)?;

    let decrypted_content = cypher.decrypt(&nonce, encrypted_content.as_ref())?;

    Ok(String::from_utf8(decrypted_content)?)
}
