use argon2::Argon2;
use argon2::password_hash::Error;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

//TODO: Add better, general error handling
//add notes on whats happening excalty
//print encrypted as string

fn main() {
    let pass = b"test";
    let salt = b"randomsalt";
    let mut output_key = [0u8; 32];

    if let Err(e) = Argon2::default().hash_password_into(pass, salt, &mut output_key) {
        eprintln!("Argon2 error: {:?}", e);
        return;
    }
    println!("Key: {:?}", output_key);

    let cypher = ChaCha20Poly1305::new(Key::from_slice(&output_key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let message = b"test message";

    let cyphertext = match cypher.encrypt(&nonce, message.as_ref()) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("Encryption error: {:?}", e);
            return;
        }
    };
    println!("Cyphertext: {:?}", cyphertext);

    let mut key_bytes_decrypt = [0u8; 32];
    if let Err(e) = Argon2::default().hash_password_into(pass, salt, &mut key_bytes_decrypt) {
        eprintln!("Argon2 error: {:?}", e);
        return;
    }

    let cipher_decrypt = ChaCha20Poly1305::new(Key::from_slice(&key_bytes_decrypt));
    let decrypted_bytes = match cipher_decrypt.decrypt(&nonce, cyphertext.as_ref()) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Decryption error: {:?}", e);
            return;
        }
    };

    let decrypted_text = match String::from_utf8(decrypted_bytes) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("UTF-8 conversion error: {}", e);
            return;
        }
    };

    println!("Decrypted: {}", decrypted_text);
}
