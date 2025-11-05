mod error;
mod file_encryption;
mod passman_commands;
mod passman_encryption;
mod passman_utils;

use error::PassmanError;
use passman_commands::CommandType;
use std::env;

fn print_error(error: &PassmanError) {
    let message = match error {
        PassmanError::IoError(e) => format!("File access error: {}", e),
        PassmanError::ChaChaPoly(_) => "Encryption error. Wrong master password?".to_string(),
        PassmanError::Base64Decode(_) => "Invalid password file format.".to_string(),
        PassmanError::FromUtf8(_) => "Invalid password file contents.".to_string(),
        PassmanError::Argon2(_) => "Password hashing error.".to_string(),
        PassmanError::InvalidFileFormat => "Invalid password file format.".to_string(),
        PassmanError::UnsupportedVersion => "Unsupported file version.".to_string(),
    };

    eprintln!("Error: {}", message);
}

fn run_app(args: &[String]) -> Result<(), PassmanError> {
    if args.len() == 1 {
        passman_utils::print_help();
        return Ok(());
    }

    let command = CommandType::parse(args)?;

    if command.requires_auth() {
        command.execute_with_auth()?;
    } else {
        command.execute_public()?;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if let Err(error) = run_app(&args) {
        print_error(&error);
        std::process::exit(1);
    }
}

