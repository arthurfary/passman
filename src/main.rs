mod error;
mod file_encryption;
mod passman_encryption;

use error::PassmanError;

fn main() -> Result<(), PassmanError> {
    let mut pwd = String::new();

    println!("Enter master pass:");

    std::io::stdin().read_line(&mut pwd).unwrap();

    println!("mp: {}", &pwd);

    let message = b"service:github\npass:dummypass";

    file_encryption::create_encrypted_file("test", &pwd, message)?;

    // DECRYPT
    let mut pass = String::new();

    println!("Enter master pass:");

    std::io::stdin().read_line(&mut pass).unwrap();

    println!("mp: {}", &pass);

    let content_str = file_encryption::decrypt_file("test", pass.as_bytes())?;

    println!("{}", content_str);

    Ok(())
}
