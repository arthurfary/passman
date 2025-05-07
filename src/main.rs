mod error;
mod file_encryption;
mod passman_encryption;
use error::PassmanError;
use rand::{Rng, rng};
use rpassword;
use std::ffi::OsString;
use std::io::{self, Write};
use std::{env, fs};

//TODO:
// - Find a better way of handeling the master password (Should be a parameter probably)
// - Astract awaya all logic that doesn't need to be in this main, cli file
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

fn create_random_string(length: usize, charset: &[u8]) -> String {
    let mut rng = rng();
    (0..length)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            char::from(charset[idx])
        })
        .collect()
}

fn create_random_file_name(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    create_random_string(length, CHARSET)
}

fn create_random_password(length: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~`!@#$%^&*()_-+={[}]|\\:;\"'<,>.?/";
    create_random_string(length, CHARSET)
}

fn create_new_password(command: Command) -> Result<(), PassmanError> {
    let master_pwd = loop {
        let pwd = read_input("Master password", true);
        let confirm_pwd = read_input("Confirm master password", true);

        if pwd == confirm_pwd {
            break pwd;
        } else {
            println!("Passwords do not match, try again.")
        }
    };

    let random_pass = create_random_password(16);

    let service_name = match command.service {
        Some(s) => s,
        None => read_input("Enter service name", false),
    };

    println!("{}", random_pass);

    // let gen_random_name = read_input("Generate random name? ([y]/n)", false).to_lowercase();

    // let filename = if gen_random_name != "n" {
    //     create_random_file_name(8)
    // } else {
    //     service_name.clone()
    // };

    file_encryption::create_encrypted_file(
        &OsString::from(&service_name),
        &master_pwd,
        &service_name,
        random_pass.as_bytes(),
    )?;

    println!("Password file created for {}", service_name);

    Ok(())
}
fn get_password(command: Command) -> Result<(), PassmanError> {
    let master_pwd = read_input("Enter master password", true);

    let service_name = match command.service {
        Some(s) => s,
        None => read_input("Enter service name", false),
    };

    let password_files = fs::read_dir(file_encryption::get_output_path()).unwrap();

    for file in password_files {
        let (file_service_name, service_password) =
            file_encryption::read_encrypted_file(&file?.file_name(), &master_pwd)?;
        if file_service_name == service_name {
            println!("{}: {}", service_name, service_password);
            return Ok(());
        }
    }

    // no service found
    println!("No service of name {} in passwords.", service_name);

    Ok(())
}

fn register_password(command: Command) -> Result<(), PassmanError> {
    let master_pwd = read_input("Master password", true);

    let service_name = match command.service {
        Some(s) => s,
        None => read_input("Enter service name", false),
    };

    let service_pwd = match command.existing_password {
        Some(s) => s,
        None => read_input("Paste or Type existing password", true),
    };

    let gen_random_name = read_input("Generate random name? ([y]/n)", false).to_lowercase();

    let filename = if gen_random_name != "n" {
        create_random_file_name(8)
    } else {
        service_name.clone()
    };

    file_encryption::create_encrypted_file(
        &OsString::from(&filename),
        &master_pwd,
        &service_name,
        service_pwd.as_bytes(),
    )?;

    println!("Password file {} created for {}", filename, service_name);

    Ok(())
}

fn list_files() -> Result<(), PassmanError> {
    let password_files = fs::read_dir(file_encryption::get_output_path()).unwrap();

    for file in password_files {
        println!("{}", file.unwrap().path().display())
    }

    Ok(())
}

fn list_service_names() -> Result<(), PassmanError> {
    let master_pwd = read_input("Enter master password", true);

    let password_files = fs::read_dir(file_encryption::get_output_path()).unwrap();

    let mut service_names: Vec<(String, String)> = Vec::new();

    for file in password_files {
        let (file_service_name, service_password) =
            file_encryption::read_encrypted_file(&file?.file_name(), &master_pwd)?;
        service_names.push((file_service_name, service_password));
    }

    if service_names.is_empty() {
        println!("No services found.");
    } else {
        println!("Available services:");
        for name_password in service_names {
            println!("{}: {}", name_password.0, name_password.1);
        }
    }

    Ok(())
}

fn decrypt_file_prompt(filename: String) -> Result<(), PassmanError> {
    let master_pwd = read_input("Master Password:", true);

    let filename = if filename.is_empty() {
        read_input("Enter service name", false)
    } else {
        filename
    };

    let (service_name, service_password) =
        file_encryption::read_encrypted_file(&OsString::from(filename), &master_pwd)?;

    println!("{}: {}", service_name, service_password);

    Ok(())
}

fn print_usage() {
    println!("Passman password manager");
    println!("Usage:");
    println!("  new       - Create new password for a service");
    // println!("  decrypt   - Decrypt a file manually");
    println!("  get       - Get a password for a service");
    println!("  register  - Register existing password for a service");
    println!("  list      - List all passwords files in password folder");
    // println!("  dall      - Decrypt all");
    println!("  help      - Show this help message\n");
    println!("Examples:");
    println!("  passman new");
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

fn main() {
    let mut args: Vec<String> = env::args().collect(); // skip binary name

    if args.len() == 1 {
        // if no args
        print_usage();
        return;
    }

    let command = Command::new(&mut args);

    if let Err(error) = run_command(command) {
        eprintln!("Error: {}", error);
        std::process::exit(1); // if error print error then exit with code 1
    }
}

fn run_command(command: Command) -> Result<(), PassmanError> {
    match command.name.as_str() {
        "new" => create_new_password(command)?,
        "get" => get_password(command)?,
        //"decrypt" => decrypt_file_prompt(command)?,  // Will be replaced with file reading
        "register" => register_password(command)?,
        //"dall" => list_service_names(command?)    // Will be replaced with file reading,
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
