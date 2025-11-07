mod cli;
mod commands;
mod crypto;
mod error;
mod storage;
mod gui;

use commands::CommandType;
use error::PassmanError;
use std::env;

fn print_error(error: &PassmanError) {
    const DEBUG: bool = true; // set to true for full debug info

    if DEBUG {
        eprintln!("Full error debug: {:#?}", error);
    }

    let message = match error {
        PassmanError::IoError(e) => format!("File access error: {}", e),
        PassmanError::ChaChaPoly(_) => "Encryption error. Wrong master password?".to_string(),
        PassmanError::FromUtf8(_) => "Invalid password file contents.".to_string(),
        PassmanError::Argon2(_) => "Password hashing error.".to_string(),
        PassmanError::InvalidFileFormat => "Invalid password file format.".to_string(),
        PassmanError::UnsupportedVersion => "Unsupported file version.".to_string(),
    };

    eprintln!("Error: {}", message);
}

fn run_app(args: &[String]) -> Result<(), PassmanError> {
    if args.len() == 1 {
        cli::print_help();
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

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "PassMan GUI",
        native_options,
        Box::new(|_cc| Ok(Box::new(gui::PassmanGui::default()))),
    )
}