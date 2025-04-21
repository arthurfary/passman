mod error;
mod file_encryption;
mod passman_encryption;

use error::PassmanError;

fn main() -> Result<(), PassmanError> {
    let mut pwd = String::new();
    let mut service_name = String::new();
    let mut service_pwd = String::new();

    println!("Enter master pass:");
    std::io::stdin().read_line(&mut pwd).unwrap();

    println!("Enter service_name:");
    std::io::stdin().read_line(&mut service_name).unwrap();

    println!("Enter service_pwd:");
    std::io::stdin().read_line(&mut service_pwd).unwrap();

    // Trim newlines and whitespace
    let pwd = pwd.trim();
    let service_name = service_name.trim();
    let service_pwd = service_pwd.trim();

    file_encryption::create_encrypted_file(
        service_name,
        pwd,
        service_name,
        service_pwd.as_bytes(),
    )?;

    // DECRYPT
    let mut pass = String::new();

    println!("Enter master pass:");

    std::io::stdin().read_line(&mut pass).unwrap();

    let pass = pass.trim();

    println!("mp: {}", &pass);

    let (service_name, content_str) = file_encryption::read_encrypted_file(service_name, pass)?;

    println!("{}: {}", service_name, content_str);

    Ok(())
}
