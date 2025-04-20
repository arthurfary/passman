mod file_encryption;

use argon2::Argon2;
use argon2::password_hash::rand_core::RngCore;
use base64::prelude::*;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key};

mod error;
use error::PassmanError;

//TODO: Add better, general error handling
//add notes on whats happening excalty
//print encrypted as string

fn main() -> Result<(), PassmanError> {
    // setting salt and pass manualy here for testing
    let pass = b"password";
    // let salt = b"randomsalt";
    let message = b"service:github\npass:dummypass";

    // random salt
    let mut random_salt = [0u8; 16];
    OsRng.fill_bytes(&mut random_salt);

    print!("random salt {:?}", random_salt);

    let mut output_key = [0u8; 32];

    Argon2::default().hash_password_into(pass, &random_salt, &mut output_key)?;
    println!("Key: {:?}", output_key);

    let cypher = ChaCha20Poly1305::new(Key::from_slice(&output_key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let cyphertext = cypher.encrypt(&nonce, message.as_ref())?;
    println!("Cyphertext: {:?}", cyphertext);

    // encode to bas64
    let b64_text = BASE64_STANDARD.encode(&cyphertext);
    let b64_salt = BASE64_STANDARD.encode(random_salt);
    println!(
        "TEXT THAT WILL GO IN FILE:\nSALT: {}\nCONTENT:{}",
        b64_salt, b64_text
    );
    // -------------
    // THIS PART IS FOR THE FILE ENCRYPTION
    file_encryption::create_encrypted_file("test", &random_salt, &nonce, &cyphertext)?;
    file_encryption::decrypt_file("test", pass)?;
    // -------------

    let mut key_bytes_decrypt = [0u8; 32];
    Argon2::default().hash_password_into(pass, &random_salt, &mut key_bytes_decrypt)?;

    let cipher_decrypt = ChaCha20Poly1305::new(Key::from_slice(&key_bytes_decrypt));
    let decrypted_bytes = cipher_decrypt.decrypt(&nonce, cyphertext.as_ref())?;

    let dec_str = String::from_utf8(decrypted_bytes);

    println!("FROM FILE{:?}", dec_str);

    Ok(())
}
