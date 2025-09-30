mod error;
mod file_encryption;
mod passman_encryption;

use arboard::Clipboard;
use error::PassmanError;
use file_encryption::PassmanStorage;
use rand::Rng;
use std::env;
use std::io::{self, Write};

/// Session wrapper for CLI operations
pub struct PassmanSession {
    storage: PassmanStorage,
}

impl PassmanSession {
    /// Initialize a new session by prompting for master password once
    pub fn new() -> Result<Self, PassmanError> {
        let master_pwd = read_master_password()?;
        let storage = PassmanStorage::new(master_pwd);
        Ok(Self { storage })
    }

    /// Create a new random password for a service
    pub fn create_password(&self, service: Option<String>) -> Result<(), PassmanError> {
        let service_name = get_service_name(service)?;

        // Check if service already exists
        if self.storage.has_service(&service_name) {
            println!(
                "Service '{}' already exists. Use 'update' to change it.",
                service_name
            );
            return Ok(());
        }

        let random_password = generate_random_password(16);
        self.storage.store(&service_name, &random_password)?;

        println!("✓ New password created for '{}'", service_name);
        println!("Password copied to clipboard!");

        copy_to_clipboard(&random_password)?;
        Ok(())
    }

    /// Retrieve and copy password to clipboard
    pub fn get_password(&self, service: Option<String>) -> Result<(), PassmanError> {
        let service_name = match service {
            Some(name) => {
                // Check if service exists exactly
                if self.storage.has_service(&name) {
                    name
                } else {
                    println!("Service '{}' not found.", name);
                    return Ok(());
                }
            }
            None => {
                // Show all services and let user choose
                let services = self.storage.list_services()?;
                if services.is_empty() {
                    println!("No passwords stored yet. Use 'new' to create one.");
                    return Ok(());
                }
                self.select_from_list(services)?
            }
        };

        let password = self.storage.retrieve(&service_name)?;
        copy_to_clipboard(&password)?;

        println!("✓ Password for '{}' copied to clipboard!", service_name);
        Ok(())
    }

    /// Register an existing password for a service
    pub fn register_password(
        &self,
        service: Option<String>,
        password: Option<String>,
    ) -> Result<(), PassmanError> {
        let service_name = get_service_name(service)?;

        if self.storage.has_service(&service_name) {
            println!(
                "Service '{}' already exists. Use 'update' to change it.",
                service_name
            );
            return Ok(());
        }

        let service_password = match password {
            Some(pwd) => pwd,
            None => read_input("Enter existing password", true)?,
        };

        self.storage.store(&service_name, &service_password)?;
        println!("✓ Password registered for '{}'", service_name);

        Ok(())
    }

    /// Update an existing password
    pub fn update_password(
        &self,
        service: Option<String>,
        password: Option<String>,
    ) -> Result<(), PassmanError> {
        let service_name = get_service_name(service)?;

        if !self.storage.has_service(&service_name) {
            println!(
                "Service '{}' not found. Use 'new' or 'register' to create it.",
                service_name
            );
            return Ok(());
        }

        let new_password = match password {
            Some(pwd) => pwd,
            None => {
                println!("Choose an option:");
                println!("1. Generate random password");
                println!("2. Enter custom password");
                let choice = read_input("Enter choice (1 or 2)", false)?;

                match choice.trim() {
                    "1" => generate_random_password(16),
                    "2" => read_input("Enter new password", true)?,
                    _ => {
                        println!("Invalid choice. Using random password.");
                        generate_random_password(16)
                    }
                }
            }
        };

        self.storage.store(&service_name, &new_password)?;
        println!("✓ Password updated for '{}'", service_name);

        Ok(())
    }

    /// Delete a service
    pub fn delete_service(&self, service: Option<String>) -> Result<(), PassmanError> {
        let service_name = get_service_name(service)?;

        if !self.storage.has_service(&service_name) {
            println!("Service '{}' not found.", service_name);
            return Ok(());
        }

        // Confirm deletion
        let confirm = read_input(
            &format!("Delete password for '{}'? (y/N)", service_name),
            false,
        )?;
        if confirm.to_lowercase() != "y" && confirm.to_lowercase() != "yes" {
            println!("Deletion cancelled.");
            return Ok(());
        }

        self.storage.delete_service(&service_name)?;
        println!("✓ Password for '{}' deleted", service_name);

        Ok(())
    }

    /// List all stored services
    pub fn list_services(&self) -> Result<(), PassmanError> {
        let services = self.storage.list_services()?;

        if services.is_empty() {
            println!("No passwords stored yet. Use 'new' to create one.");
            return Ok(());
        }

        println!("Stored services ({}):", services.len());
        for (i, service) in services.iter().enumerate() {
            println!("  {}. {}", i + 1, service);
        }

        Ok(())
    }

    // Helper method for interactive selection
    fn select_from_list(&self, services: Vec<String>) -> Result<String, PassmanError> {
        println!("Available services:");
        for (i, service) in services.iter().enumerate() {
            println!("  {}. {}", i + 1, service);
        }

        let choice = read_input("Enter number", false)?;
        let index: usize = choice
            .trim()
            .parse()
            // TODO: Add InvalidInput variant to PassmanError enum
            .map_err(|_| {
                PassmanError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid input",
                ))
            })?;

        if index == 0 || index > services.len() {
            // TODO: Add InvalidInput variant to PassmanError enum
            return Err(PassmanError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid input",
            )));
        }

        Ok(services[index - 1].clone())
    }
}

/// Command structure for parsing CLI arguments
#[derive(Debug)]
struct Command {
    name: String,
    service: Option<String>,
    extra_arg: Option<String>,
}

impl Command {
    fn parse(args: &[String]) -> Result<Self, PassmanError> {
        if args.len() < 2 {
            // TODO: Add InvalidInput variant to PassmanError enum
            return Err(PassmanError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid input",
            )));
        }

        let name = args[1].clone();
        let service = args.get(2).cloned();
        let extra_arg = args.get(3).cloned();

        Ok(Command {
            name,
            service,
            extra_arg,
        })
    }
}

// Utility functions

fn read_input(prompt: &str, is_password: bool) -> Result<String, PassmanError> {
    print!("{}: ", prompt);
    io::stdout().flush()?;

    let input = if is_password {
        rpassword::read_password()?
    } else {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        input
    };

    Ok(input.trim().to_string())
}

fn read_master_password() -> Result<String, PassmanError> {
    loop {
        let password = read_input("Master password", true)?;
        let confirm = read_input("Confirm master password", true)?;

        if password == confirm {
            if password.is_empty() {
                println!("Master password cannot be empty!");
                continue;
            }
            return Ok(password);
        } else {
            println!("Passwords do not match, try again.");
        }
    }
}

fn get_service_name(service: Option<String>) -> Result<String, PassmanError> {
    match service {
        Some(name) => {
            if name.is_empty() {
                // TODO: Add InvalidInput variant to PassmanError enum
                Err(PassmanError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid input",
                )))
            } else {
                Ok(name)
            }
        }
        None => read_input("Enter service name", false),
    }
}

fn generate_random_password(length: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn copy_to_clipboard(text: &str) -> Result<(), PassmanError> {
    // TODO: Add ClipboardError variant to PassmanError enum
    let mut clipboard = Clipboard::new().map_err(|_| {
        PassmanError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Clipboard error",
        ))
    })?;
    clipboard.set_text(text).map_err(|_| {
        PassmanError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Clipboard error",
        ))
    })?;
    Ok(())
}

fn print_usage() {
    println!("Passman - Secure Password Manager");
    println!();
    println!("USAGE:");
    println!("    passman <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    new [service]                 Create new random password");
    println!("    get [service]                 Retrieve password (copies to clipboard)");
    println!("    register [service] [password] Register existing password");
    println!("    update [service] [password]   Update existing password");
    println!("    delete [service]              Delete a password");
    println!("    list                          List all stored services");
    println!("    search <pattern>              Search for services by name");
    println!("    help                          Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    passman new github");
    println!("    passman get github");
    println!("    passman register gmail mypassword123");
    println!("    passman update github");
    println!("    passman search git");
    println!("    passman delete oldservice");
    println!();
    println!("NOTES:");
    println!("    - Master password is required on first use");
    println!("    - Passwords are automatically copied to clipboard");
    println!("    - Service names must match exactly for retrieval");
}

fn handle_error(error: PassmanError) {
    let message = match error {
        PassmanError::IoError(_) => "File access error. Check permissions and try again.",
        PassmanError::ChaChaPoly(_) => "Encryption error. Wrong master password?",
        PassmanError::Base64Decode(_) => "Invalid password file format.",
        PassmanError::FromUtf8(_) => "Invalid password file contents.",
        PassmanError::Argon2(_) => "Password hashing error.",
        PassmanError::InvalidFileFormat => "aaa",
        PassmanError::UnsupportedVersion => "bbb", // TODO: Add these error variants to PassmanError enum
                                                   // PassmanError::ClipboardError => "Failed to copy to clipboard.",
                                                   // PassmanError::InvalidInput => "Invalid input provided.",
                                                   // PassmanError::ServiceNotFound => "Service not found.",
                                                   // PassmanError::InvalidFileFormat => "Invalid password file format.",
    };

    eprintln!("Error: {}", message);
}

fn run_command(command: Command) -> Result<(), PassmanError> {
    // Create session - master password prompted once here
    let session = PassmanSession::new()?;

    match command.name.as_str() {
        "new" => session.create_password(command.service),
        "get" => session.get_password(command.service),
        "register" => session.register_password(command.service, command.extra_arg),
        "update" => session.update_password(command.service, command.extra_arg),
        "delete" | "del" | "rm" => session.delete_service(command.service),
        "list" | "ls" => session.list_services(),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            println!("Unknown command: '{}'", command.name);
            println!("Use 'passman help' for usage information.");
            Ok(())
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        print_usage();
        return;
    }

    let command = match Command::parse(&args) {
        Ok(cmd) => cmd,
        Err(_) => {
            print_usage();
            return;
        }
    };

    if let Err(error) = run_command(command) {
        handle_error(error);
        std::process::exit(1);
    }
}
