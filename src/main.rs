mod error;
mod file_encryption;
mod passman_encryption;
use arboard::Clipboard;
use error::PassmanError;
use file_encryption::get_password_file_path;
use rand::{Rng, rng};
use std::env;
use std::fs;
use std::io::{self, Write};

//TODO:
// - Find a better way of handeling user input (same bit of code repeation)

fn read_input(prompt: &str, is_pass: bool) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let input = if is_pass {
        let mut temp = String::new();
        temp.push_str(&rpassword::read_password().unwrap());
        temp
    } else {
        let mut temp = String::new();
        io::stdin().read_line(&mut temp).unwrap();
        temp
    };
    input.trim().to_string()
}

fn read_master_pwd() -> String {
    loop {
        let pwd = read_input("Master password", true);
        let confirm_pwd = read_input("Confirm master password", true);

        if pwd == confirm_pwd {
            break pwd;
        } else {
            println!("Passwords do not match, try again.")
        }
    }
}

fn create_random_password(length: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~`!@#$%^&*()_-+={[}]|\\:;\"'<,>.?/";

    let mut rng = rng();
    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            char::from(CHARSET[idx])
        })
        .collect()
}

fn create_new_password(command: Command) -> Result<(), PassmanError> {
    let master_pwd = read_master_pwd();
    let random_pass = create_random_password(16);

    let service_name = match command.service {
        Some(s) => s,
        None => read_input("Enter service name", false),
    };

    file_encryption::create_encrypted_file(&master_pwd, &service_name, random_pass.as_bytes())?;

    println!("Password file created for {}", service_name);

    Ok(())
}

fn get_password(command: Command) -> Result<(), PassmanError> {
    let service_name = match command.service {
        Some(s) => s,
        None => read_input("Enter service name", false),
    };
    let file_path = get_password_file_path(&service_name);

    // add fuzzy finding here

    let master_pwd = read_input("Enter master password", true);

    let service_password = file_encryption::read_encrypted_file(file_path, &master_pwd)?;

    println!("{}", &service_password);

    let mut clip = Clipboard::new().unwrap();

    clip.set_text(service_password).unwrap();

    Ok(())
}

fn register_password(command: Command) -> Result<(), PassmanError> {
    let master_pwd = read_input("Master password", true);

    let service_name = match command.service {
        Some(s) => s,
        None => read_input("Enter service name", false),
    };

    let service_pwd = match command.existing_password {
        Some(pwd) => pwd,
        None => read_input("Paste or Type existing password", true),
    };

    file_encryption::create_encrypted_file(&master_pwd, &service_name, service_pwd.as_bytes())?;

    println!(
        "Password file {} created for {}",
        service_name, service_name
    );

    Ok(())
}

fn list_files() -> Result<(), PassmanError> {
    let password_files = fs::read_dir(file_encryption::get_path()).unwrap();

    for file in password_files {
        println!("{}", file.unwrap().path().display())
    }

    Ok(())
}

fn print_usage() {
    println!("Passman password manager");
    println!("Usage:");
    println!("  new [service]                 - Create new password for a service");
    println!("  get [service]                 - Get a password for a service");
    println!("  register [service] [password] - Register existing password for a service");
    println!("  list                          - List all passwords files in password folder");
    println!("  help                          - Show this help message\n");
    println!("Examples:");
    println!("  passman new github");
    println!("  passman register");
}

struct Command {
    name: String,
    service: Option<String>,
    existing_password: Option<String>,
}

impl Command {
    fn new(args: &[String]) -> Command {
        let name = args[1].clone();
        let service = if args.len() > 2 {
            Some(args[2].clone())
        } else {
            None
        };
        let existing_password = if args.len() > 3 {
            Some(args[3].clone())
        } else {
            None
        };

        Command {
            name,
            service,
            existing_password,
        }
    }
}

fn run_command(command: Command) -> Result<(), PassmanError> {
    match command.name.as_str() {
        "new" => create_new_password(command)?,
        "get" => get_password(command)?,
        "register" => register_password(command)?,
        "list" => list_files()?,
        "help" => print_usage(),
        _ => {
            println!("Unknown command: {}", command.name.as_str());
            print_usage();
            return Ok(());
        }
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect(); // skip binary name

    if args.len() == 1 {
        // if no args
        print_usage();
        return;
    }

    let command = Command::new(&args);

    match run_command(command) {
        Ok(_) => (),
        Err(err) => match err {
            PassmanError::IoError(_) => {
                println!("Error accessing the file (Io Error).")
            }
            PassmanError::ChaChaPoly(_) => {
                println!("Encryption error. Wrong password?")
            }
            PassmanError::Base64Decode(_) => {
                println!("Base64 decoding error: Invalid base64 in password file")
            }
            PassmanError::FromUtf8(_) => {
                println!("Error converting to Utf8. Invalid base64 contents?")
            }
            PassmanError::Argon2(_) => {
                println!("Error hashing the password. Invalid salt or nonce?")
            }
        },
    }
}
