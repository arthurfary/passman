use std::fmt::{self, Display};

#[derive(Debug)]
pub enum PassmanError {
    IoError(std::io::Error),
    ChaChaPoly(chacha20poly1305::Error),
    Base64Decode(base64::DecodeError),
    FromUtf8(std::string::FromUtf8Error),
    Argon2(argon2::Error),
    InvalidFileFormat,
    UnsupportedVersion,
}

impl Display for PassmanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PassmanError::IoError(io_error) => {
                write!(f, "{}", io_error)
            }
            PassmanError::ChaChaPoly(chacha_error) => {
                write!(f, "{}", chacha_error)
            }
            PassmanError::Base64Decode(b64_error) => {
                write!(f, "{}", b64_error)
            }
            PassmanError::FromUtf8(fromutf8_error) => {
                write!(f, "{}", fromutf8_error)
            }
            PassmanError::Argon2(argon2_error) => {
                write!(f, "{}", argon2_error)
            }
            PassmanError::InvalidFileFormat => {
                write!(
                    f,
                    "Invalid file format: Header check failed or file is corrupted."
                )
            }
            PassmanError::UnsupportedVersion => {
                write!(f, "Unsupported file version.")
            }
        }
    }
}

impl std::error::Error for PassmanError {}

// convert std io error to IoError
impl From<std::io::Error> for PassmanError {
    fn from(err: std::io::Error) -> Self {
        PassmanError::IoError(err)
    }
}

impl From<chacha20poly1305::Error> for PassmanError {
    fn from(err: chacha20poly1305::Error) -> Self {
        PassmanError::ChaChaPoly(err)
    }
}

impl From<base64::DecodeError> for PassmanError {
    fn from(err: base64::DecodeError) -> Self {
        PassmanError::Base64Decode(err)
    }
}

impl From<std::string::FromUtf8Error> for PassmanError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PassmanError::FromUtf8(err)
    }
}

impl From<argon2::Error> for PassmanError {
    fn from(err: argon2::Error) -> Self {
        PassmanError::Argon2(err)
    }
}
