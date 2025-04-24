mod error;
mod file_encryption;
mod passman_encryption;
use error::PassmanError;
use rand::{Rng, RngCore, rng};
use std::io::{self, Write};
use std::{env, fs};

//TODO:
// - Find a better way of handeling the master password (Should be a parameter probably)
// - Astract awaya all logic that doesn't need to be in this main, cli file

fn read_input(prompt: &str, is_pass: bool) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
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

fn create_new_password(service_name: String) -> Result<(), PassmanError> {
    let master_pwd = read_input("Master password", false);
    let random_pass = create_random_password(16);

    let service_name = if service_name.is_empty() {
        read_input("Enter service name", false)
    } else {
        service_name
    };

    println!("{}", random_pass);

    let gen_random_name = read_input("Generate random name? ([y]/n)", false).to_lowercase();

    let filename = if gen_random_name != "n" {
        create_random_file_name(8)
    } else {
        service_name.clone()
    };

    file_encryption::create_encrypted_file(
        &filename,
        &master_pwd,
        &service_name,
        random_pass.as_bytes(),
    )?;

    println!("Password file {} created for {}", filename, service_name);

    Ok(())
}

fn get_password(service_name: String) -> Result<(), PassmanError> {
    let master_pwd = read_input("Enter master password", false);

    let service_name = if service_name.is_empty() {
        read_input("Enter service name", false)
    } else {
        service_name
    };

    let password_files = fs::read_dir(file_encryption::OUTPUT_PATH).unwrap();

    for file in password_files {
        let (file_service_name, service_password) = file_encryption::read_encrypted_file(
            //FIXME: remove unwrap spam
            &file.unwrap().path().file_name().unwrap().to_str().unwrap(),
            &master_pwd,
        )?;
        if file_service_name == service_name {
            println!("{}: {}", service_name, service_password);
            return Ok(());
        }
    }

    // no service found
    println!("No service of name {} in passwords.", service_name);

    Ok(())
}

fn register_password(service_name: String, service_pwd: String) -> Result<(), PassmanError> {
    let master_pwd = read_input("Master password", true);

    let service_name = if service_name.is_empty() {
        read_input("Enter service name", false)
    } else {
        service_name
    };

    let service_pwd = if service_pwd.is_empty() {
        read_input("Enter password", true)
    } else {
        service_pwd
    };

    let gen_random_name = read_input("Generate random name? ([y]/n)", false).to_lowercase();

    let filename = if gen_random_name != "n" {
        create_random_file_name(8)
    } else {
        service_name.clone()
    };

    file_encryption::create_encrypted_file(
        &filename,
        &master_pwd,
        &service_name,
        service_pwd.as_bytes(),
    )?;

    println!("Password file {} created for {}", filename, service_name);

    Ok(())
}

fn list_files() -> Result<(), PassmanError> {
    let password_files = fs::read_dir(file_encryption::OUTPUT_PATH).unwrap();

    for file in password_files {
        println!("{}", file.unwrap().path().display())
    }

    Ok(())
}

fn list_service_names() -> Result<(), PassmanError> {
    let master_pwd = read_input("Enter master password", true);

    let password_files = fs::read_dir(file_encryption::OUTPUT_PATH).unwrap();

    let mut service_names: Vec<(String, String)> = Vec::new();

    for file in password_files {
        let (file_service_name, service_password) = file_encryption::read_encrypted_file(
            //FIXME: remove unwrap spam
            &file.unwrap().path().file_name().unwrap().to_str().unwrap(),
            &master_pwd,
        )?;
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
        file_encryption::read_encrypted_file(&filename, &master_pwd)?;

    println!("{}: {}", service_name, service_password);

    Ok(())
}

fn print_usage() {
    println!("Passman password manager");
    println!("Usage:");
    println!("  new       - Create new password for a service");
    println!("  decrypt   - Decrypt a file manually");
    println!("  get       - Get a password for a service");
    println!("  register  - Register existing password for a service");
    println!("  list      - List all passwords files in password folder");
    println!("  dall      - Decrypt all");
    println!("  help      - Show this help message\n");
    println!("Examples:");
    println!("  passman new");
    println!("  passman register");
}

fn main() -> Result<(), PassmanError> {
    let mut args = env::args().skip(1); // skip binary name

    match args.next().as_deref() {
        Some("new") => create_new_password(args.next().unwrap_or_default())?,
        Some("get") => get_password(args.next().unwrap_or_default())?,
        Some("decrypt") => decrypt_file_prompt(args.next().unwrap_or_default())?,
        Some("register") => register_password(
            args.next().unwrap_or_default(),
            args.next().unwrap_or_default(),
        )?,
        Some("dall") => list_service_names()?,
        Some("list") => list_files()?,
        Some("help") => print_usage(),
        Some(cmd) => {
            println!("Unknown command: {}", cmd);
            print_usage();
            return Ok(());
        }
        None => {
            print_usage();
            return Ok(());
        }
    }

    Ok(())
}
