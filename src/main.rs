mod error;
mod file_encryption;
mod passman_encryption;
use error::PassmanError;
use rand::{Rng, rng};
use std::env;
use std::fs::read;
use std::future::poll_fn;
use std::io::{self, Write};

fn print_usage() {
    println!("Password Manager CLI");
    println!("Usage:");
    println!("  create    - Create new password for a service");
    println!("  register  - Register existing password for a service");
    println!("  change    - Change password for a service");
    println!("  help      - Show this help message\n");
    println!("Examples:");
    println!("  passman create");
    println!("  passman register");
    println!("  passman change");
}

fn read_input(prompt: &str) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn read_password(prompt: &str) -> String {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
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

fn create_new_password() -> Result<(), PassmanError> {
    let master_pwd = read_password("Master password:");
    let service_name = read_input("Service name:");
    let random_pass = create_random_password(16);

    println!("{}", random_pass);

    let gen_random_name = read_input("Generate random name? ([y]/n)");

    if gen_random_name != "n" {
        println!()
    } else {
    }

    file_encryption::create_encrypted_file(
        filename,
        &master_pwd,
        &service_name,
        random_pass.as_bytes(),
    );

    Ok(())
}

fn get_password() -> Result<(), PassmanError> {
    let master_pwd = read_password("Enter master password");
    let service_name = read_input("Enter service name");

    Ok(())
}

fn register_password() -> Result<(), PassmanError> {
    Ok(())
}

fn change_password() -> Result<(), PassmanError> {
    Ok(())
}

fn main() -> Result<(), PassmanError> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    match args[1].as_str() {
        "new" => create_new_password()?,
        "get" => get_password()?,
        "register" => register_password()?,
        "change" => change_password()?,
        "help" => {
            print_usage();
            return Ok(());
        }
        _ => {
            println!("Unknown command: {}", args[1]);
            print_usage();
            return Ok(());
        }
    }

    Ok(())
}
