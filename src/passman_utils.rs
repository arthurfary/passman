use crate::error::PassmanError;
use crate::file_encryption::PassmanStorage;
use arboard::Clipboard;
use rand::Rng;
use std::io::{self, Write};

pub fn list_all_services() -> Result<Vec<String>, PassmanError> {
    let storage_path = PassmanStorage::get_default_path();

    if !storage_path.exists() {
        return Ok(Vec::new());
    }

    let mut services = Vec::new();
    let entries = std::fs::read_dir(&storage_path)?;

    for entry in entries {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str() {
            services.push(name.to_string());
        }
    }

    services.sort();
    Ok(services)
}

pub fn prompt_service_selection(services: &[String]) -> Result<String, PassmanError> {
    println!("Available services:");
    for (i, service) in services.iter().enumerate() {
        println!("  {}. {}", i + 1, service);
    }

    let input = prompt_input("Enter number", false)?;
    let index: usize = input.trim().parse().map_err(|_| {
        PassmanError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid number",
        ))
    })?;

    if index == 0 || index > services.len() {
        return Err(PassmanError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Number out of range",
        )));
    }

    Ok(services[index - 1].clone())
}

pub fn prompt_input(message: &str, is_password: bool) -> Result<String, PassmanError> {
    print!("{}: ", message);
    io::stdout().flush()?;

    let input = if is_password {
        rpassword::read_password()?
    } else {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer)?;
        buffer
    };

    Ok(input.trim().to_string())
}

pub fn prompt_master_password() -> Result<String, PassmanError> {
    Ok(self::prompt_master_password_with_text("Master password")?)
}

pub fn prompt_master_password_with_text(text: &str) -> Result<String, PassmanError> {
    let password = prompt_input(text, true)?;

    if password.is_empty() {
        return Err(PassmanError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Master password cannot be empty",
        )));
    }

    Ok(password)
}

pub fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut rng = rand::rng();
    (0..length)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
}

pub fn copy_to_clipboard(text: &str) -> Result<(), PassmanError> {
    let mut clipboard = Clipboard::new().map_err(|e| {
        PassmanError::IoError(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to access clipboard: {}", e),
        ))
    })?;

    clipboard.set_text(text).map_err(|e| {
        PassmanError::IoError(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to copy to clipboard: {}", e),
        ))
    })?;

    Ok(())
}

pub fn print_help() {
    println!("USAGE:");
    println!("    passman <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    new <service>     Create new random password for a service");
    println!("    get [service]     Retrieve password (copies to clipboard)");
    println!("    list              List all stored services");
    println!("    help              Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    passman new github");
    println!("    passman get github");
    println!("    passman get              # Interactive selection");
    println!("    passman list");
}

