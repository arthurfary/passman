mod error;
mod file_encryption;
mod passman_encryption;

use arboard::Clipboard;
use error::PassmanError;
use file_encryption::PassmanStorage;
use rand::Rng;
use std::env;
use std::io::{self, Write};

pub struct PassmanSession {
    storage: PassmanStorage,
}

impl PassmanSession {
    pub fn new() -> Result<Self, PassmanError> {
        let master_pwd = prompt_master_password()?;
        let storage = PassmanStorage::new(master_pwd);
        Ok(Self { storage })
    }

    /// Execute a command that requires authentication
    fn execute(&self, command: &CommandType) -> Result<(), PassmanError> {
        match command {
            CommandType::New { service } => self.cmd_new(service),
            CommandType::Get { service } => self.cmd_get(service),
            _ => unreachable!("Only authenticated commands should reach here"),
        }
    }

    fn cmd_new(&self, service: &str) -> Result<(), PassmanError> {
        if self.storage.has_service(service) {
            println!("Service '{}' already exists.", service);
            return Ok(());
        }

        let password = generate_random_password(16);
        self.storage.store(service, &password)?;

        copy_to_clipboard(&password)?;
        println!("✓ New password created for '{}'", service);
        println!("Password copied to clipboard!");

        Ok(())
    }

    fn cmd_get(&self, service_opt: &Option<String>) -> Result<(), PassmanError> {
        let service = match service_opt {
            Some(name) => {
                if !self.storage.has_service(name) {
                    println!("Service '{}' not found.", name);
                    return Ok(());
                }
                name.clone()
            }
            None => {
                let services = list_all_services()?;
                if services.is_empty() {
                    println!("No passwords stored yet. Use 'new' to create one.");
                    return Ok(());
                }
                prompt_service_selection(&services)?
            }
        };

        let password = self.storage.retrieve(&service)?;
        copy_to_clipboard(&password)?;
        println!("✓ Password for '{}' copied to clipboard!", service);

        Ok(())
    }
}

enum CommandType {
    New { service: String },
    Get { service: Option<String> },
    List,
    Help,
}

impl CommandType {
    /// Parse command line arguments into a CommandType
    fn parse(args: &[String]) -> Result<Self, PassmanError> {
        if args.len() < 2 {
            return Err(PassmanError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No command provided",
            )));
        }

        let cmd = args[1].as_str();

        match cmd {
            "new" => {
                let service = args
                    .get(2)
                    .ok_or_else(|| {
                        PassmanError::IoError(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Service name required for 'new' command",
                        ))
                    })?
                    .clone();
                Ok(CommandType::New { service })
            }
            "get" => {
                let service = args.get(2).cloned();
                Ok(CommandType::Get { service })
            }
            "list" | "ls" => Ok(CommandType::List),
            "help" | "--help" | "-h" => Ok(CommandType::Help),
            _ => Err(PassmanError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unknown command: '{}'", cmd),
            ))),
        }
    }

    /// Check if this command requires authentication
    fn requires_auth(&self) -> bool {
        matches!(self, CommandType::New { .. } | CommandType::Get { .. })
    }

    /// Execute a command that doesn't require authentication
    fn execute_public(&self) -> Result<(), PassmanError> {
        match self {
            CommandType::List => cmd_list(),
            CommandType::Help => {
                print_help();
                Ok(())
            }
            _ => unreachable!("Only public commands should reach here"),
        }
    }
}

fn cmd_list() -> Result<(), PassmanError> {
    let services = list_all_services()?;
    println!("Stored services ({}):", services.len());

    if services.is_empty() {
        println!("  (none)");
    } else {
        for (i, service) in services.iter().enumerate() {
            println!("  {}. {}", i + 1, service);
        }
    }

    Ok(())
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

fn list_all_services() -> Result<Vec<String>, PassmanError> {
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

fn prompt_service_selection(services: &[String]) -> Result<String, PassmanError> {
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

fn prompt_input(message: &str, is_password: bool) -> Result<String, PassmanError> {
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

fn prompt_master_password() -> Result<String, PassmanError> {
    let password = prompt_input("Master password", true)?;

    if password.is_empty() {
        return Err(PassmanError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Master password cannot be empty",
        )));
    }

    Ok(password)
}

fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut rng = rand::rng();
    (0..length)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
}

fn copy_to_clipboard(text: &str) -> Result<(), PassmanError> {
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

fn print_help() {
    println!("Passman - Secure Password Manager (MVP)");
    println!();
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
    println!();
    println!("NOTES:");
    println!("    - Master password is required for new/get commands");
    println!("    - Passwords are automatically copied to clipboard");
    println!("    - 16-character random passwords are generated");
}

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
        print_help();
        return Ok(());
    }

    let command = CommandType::parse(args)?;

    if command.requires_auth() {
        let session = PassmanSession::new()?;
        session.execute(&command)?;
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
