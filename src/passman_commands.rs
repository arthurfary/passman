use crate::error::PassmanError;
use crate::file_encryption::PassmanStorage;
use crate::passman_utils::{
    copy_to_clipboard, generate_random_password, list_all_services, print_help,
    prompt_master_password, prompt_master_password_with_text, prompt_service_selection,
};
use std::io;

pub struct PassmanSession {
    storage: PassmanStorage,
}

impl PassmanSession {
    pub fn new(master_pwd: String) -> Result<Self, PassmanError> {
        let storage = PassmanStorage::new(master_pwd);
        Ok(Self { storage })
    }

    fn cmd_new(&self, service: &str) -> Result<(), PassmanError> {
        if self.storage.has_service(service) {
            println!("Service '{}' already exists.", service);
            return Ok(());
        }

        let password = generate_random_password(20);
        self.storage.store(service, &password)?;

        copy_to_clipboard(&password)?;
        println!("✓ New password created for '{}'", service);
        println!("Password copied to clipboard!");

        Ok(())
    }

    fn cmd_get(&self, service: &str) -> Result<(), PassmanError> {
        let password = self.storage.retrieve(service)?;
        copy_to_clipboard(&password)?;
        println!("✓ Password for '{}' copied to clipboard!", service);

        Ok(())
    }
}

pub enum CommandType {
    New { service: String },
    Get { service: Option<String> },
    List,
    Help,
}

impl CommandType {
    pub fn parse(args: &[String]) -> Result<Self, PassmanError> {
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

    pub fn requires_auth(&self) -> bool {
        matches!(self, CommandType::New { .. } | CommandType::Get { .. })
    }

    pub fn execute_public(&self) -> Result<(), PassmanError> {
        match self {
            CommandType::List => cmd_list(),
            CommandType::Help => {
                print_help();
                Ok(())
            }
            _ => unreachable!("Only public commands should reach here"),
        }
    }

    pub fn execute_with_auth(&self) -> Result<(), PassmanError> {
        match self {
            CommandType::New { service } => cmd_new_with_auth(service),
            CommandType::Get { service } => cmd_get_with_auth(service.as_deref()),
            _ => unreachable!("Only authenticated commands should reach here"),
        }
    }
}

fn cmd_new_with_auth(service: &str) -> Result<(), PassmanError> {
    let master_pwd = prompt_master_password()?;
    let confirm_master_pwd = prompt_master_password_with_text("Retype master password")?;

    if master_pwd != confirm_master_pwd {
        println!("Master passwords do not match");
        return Ok(());
    }

    let session = PassmanSession::new(master_pwd)?;
    session.cmd_new(service)
}

fn cmd_get_with_auth(service: Option<&str>) -> Result<(), PassmanError> {
    match service {
        Some(service) => {
            let master_pwd = prompt_master_password()?;
            let session = PassmanSession::new(master_pwd)?;

            if !session.storage.has_service(service) {
                println!("Service '{}' not found.", service);
                return Ok(());
            }

            session.cmd_get(service)
        }
        None => {
            let services = list_all_services()?;
            if services.is_empty() {
                println!("No passwords stored yet. Use 'new' to create one.");
                return Ok(());
            }

            let selected_service = prompt_service_selection(&services)?;

            let master_pwd = prompt_master_password()?;

            let session = PassmanSession::new(master_pwd)?;

            session.cmd_get(&selected_service)
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

