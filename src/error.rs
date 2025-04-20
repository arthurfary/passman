// src/error.rs
use std::fmt;

/// Custom error type for the Passman application
/// This enum represents all possible errors that can occur in our password manager
#[derive(Debug)]
pub enum PassmanError {
    /// Represents errors from file operations, network operations, etc.
    IoError(std::io::Error),

    /// Represents errors when decoding Base64 content
    Base64Error(base64::DecodeError),

    /// Represents errors from the Argon2
    ArgonError(argon2::Error),

    /// Represents general encryption/decryption errors with a custom message
    DecryptionError(String),

    ChaChaError(chacha20poly1305::Error),

    Utf8Error(std::string::FromUtf8Error),
}

/// Implement Display trait for our error type
/// This allows our error to be printed in a user-friendly way
impl fmt::Display for PassmanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassmanError::IoError(e) => write!(f, "I/O error: {}", e),
            PassmanError::Base64Error(e) => write!(f, "Base64 decoding error: {}", e),
            PassmanError::ArgonError(e) => write!(f, "Argon2 error: {:?}", e),
            PassmanError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            PassmanError::ChaChaError(e) => write!(f, "ChaChaError: {}", e),
            PassmanError::Utf8Error(e) => write!(f, "Utf8Error? {}", e),
        }
    }
}

/// Implement the standard Error trait
/// This makes our custom error compatible with the standard library error handling
impl std::error::Error for PassmanError {}

/// Convert from std::io::Error to our PassmanError
/// This allows us to use the ? operator with functions that return std::io::Error
/// Example: let file = File::open("file.txt")?;
impl From<std::io::Error> for PassmanError {
    fn from(err: std::io::Error) -> Self {
        // Wrap the io::Error in our IoError variant
        PassmanError::IoError(err)
    }
}

/// Convert from base64::DecodeError to our PassmanError
/// This allows us to use the ? operator with base64 decoding functions
/// Example: let decoded = BASE64_STANDARD.decode(encoded_string)?;
impl From<base64::DecodeError> for PassmanError {
    fn from(err: base64::DecodeError) -> Self {
        // Wrap the base64::DecodeError in our Base64Error variant
        PassmanError::Base64Error(err)
    }
}

/// Convert from argon2::Error to our PassmanError
/// This allows us to use the ? operator with Argon2 functions
/// Example: Argon2::default().hash_password_into(pass, &salt, &mut output_key)?;
impl From<argon2::Error> for PassmanError {
    fn from(err: argon2::Error) -> Self {
        // Wrap the Argon2 error in our ArgonError variant
        PassmanError::ArgonError(err)
    }
}

impl From<chacha20poly1305::Error> for PassmanError {
    fn from(err: chacha20poly1305::Error) -> Self {
        PassmanError::ChaChaError(err)
    }
}

impl From<std::string::FromUtf8Error> for PassmanError {
    fn from(value: std::string::FromUtf8Error) -> Self {
        PassmanError::Utf8Error(value)
    }
}
