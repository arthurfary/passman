use argon2::Version;
use chacha20poly1305::aead::generic_array::GenericArray;
use std::fs::{self, File, create_dir_all};
use std::io::prelude::*;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::env;

use crate::crypto::{self, KdfParameters};
use crate::error::PassmanError;
use chacha20poly1305::aead::Aead;

const FILE_MAGIC_NUMBER: &[u8; 4] = b"PMAN";
const CURRENT_FILE_VERSION: u8 = 0x01;
const KDF_ARGON2ID: u8 = 0x01;
const ENCRYPTION_CHACHA20POLY1305: u8 = 0x01;

pub struct PassmanStorage {
    pub(crate) master_password: String,
    pub(crate) storage_path: PathBuf,
}

impl PassmanStorage {
    pub fn get_default_path() -> PathBuf {
        // 1. Env var override — highest priority
        if let Ok(custom_path) = env::var("PASSMAN_STORAGE_DIR") {
            let path = PathBuf::from(custom_path);
            if let Err(e) = create_dir_all(&path) {
                eprintln!("Warning: failed to create custom storage folder: {}", e);
            }
            return fs::canonicalize(&path).unwrap_or(path);
        }

        // 2. Config file override — second priority
        if let Some(config_path) = Self::read_config_path() {
            if let Err(e) = create_dir_all(&config_path) {
                eprintln!("Warning: failed to create configured storage folder: {}", e);
            }
            return fs::canonicalize(&config_path).unwrap_or(config_path);
        }

        // 3. Platform default — fallback
        let base = Self::platform_default_dir();
        if let Err(e) = create_dir_all(&base) {
            eprintln!("Warning: failed to create default storage folder: {}", e);
        }
        fs::canonicalize(&base).unwrap_or(base)
    }

    fn platform_default_dir() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            // %APPDATA%\Passman  (e.g. C:\Users\Alice\AppData\Roaming\Passman)
            env::var("APPDATA")
                .map(|p| PathBuf::from(p).join("Passman"))
                .unwrap_or_else(|_| PathBuf::from(".").join("Passman"))
        }

        #[cfg(target_os = "linux")]
        {
            // $XDG_DATA_HOME/passman  or  ~/.local/share/passman
            let base = env::var("XDG_DATA_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    env::var("HOME")
                        .map(|h| PathBuf::from(h).join(".local").join("share"))
                        .unwrap_or_else(|_| PathBuf::from("."))
                });
            base.join("passman")
        }

        #[cfg(target_os = "macos")]
        {
            // ~/Library/Application Support/Passman
            env::var("HOME")
                .map(|h| {
                    PathBuf::from(h)
                        .join("Library")
                        .join("Application Support")
                        .join("Passman")
                })
                .unwrap_or_else(|_| PathBuf::from(".").join("Passman"))
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            PathBuf::from(".").join("passman")
        }
    }

    fn read_config_path() -> Option<PathBuf> {
        let config_file = env::current_exe()
            .ok()?
            .parent()?
            .to_path_buf()
            .join("passman.conf");

        let content = fs::read_to_string(config_file).ok()?;
        let line = content.lines().next()?.trim();

        if line.is_empty() {
            return None;
        }

        Some(PathBuf::from(line))
    }

    pub fn new(master_password: String) -> Self {
        Self {
            master_password,
            storage_path: Self::get_default_path(),
        }
    }

    pub fn with_path(master_password: String, storage_path: PathBuf) -> Self {
        Self {
            master_password,
            storage_path,
        }
    }

    pub fn has_service(&self, service_name: &str) -> bool {
        self.get_service_file_path(service_name).exists()
    }

    pub fn store(
        &self,
        service_name: &str,
        content: &String,
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<(), PassmanError> {
        self.ensure_storage_dir()?;

        let file_path = self.get_service_file_path(service_name);
        let encrypted_data = self.encrypt_content(content.as_bytes(), m_cost, t_cost, p_cost)?;

        let mut file = File::create(file_path)?;
        file.write_all(&encrypted_data)?;

        Ok(())
    }

    pub fn retrieve(&self, service_name: &str) -> Result<String, PassmanError> {
        let file_path = self.get_service_file_path(service_name);
        let mut file = File::open(file_path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        self.decrypt_content(&content)
    }

    fn ensure_storage_dir(&self) -> Result<(), PassmanError> {
        create_dir_all(&self.storage_path)?;
        Ok(())
    }

    fn get_service_file_path(&self, service_name: &str) -> PathBuf {
        self.storage_path.join(service_name)
    }

    fn encrypt_content(
        &self,
        content: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<Vec<u8>, PassmanError> {
        let (cipher, kdf_params, nonce) =
            crypto::gen_new_cipher(self.master_password.as_bytes(), m_cost, t_cost, p_cost)?;

        let encrypted_content =
            cipher.encrypt(chacha20poly1305::Nonce::from_slice(&nonce), content)?;

        let mut file_data = Vec::new();

        // Write the Header
        file_data.extend_from_slice(FILE_MAGIC_NUMBER);
        file_data.push(CURRENT_FILE_VERSION);
        file_data.push(KDF_ARGON2ID);
        file_data.extend_from_slice(&kdf_params.salt);
        file_data.extend_from_slice(&kdf_params.m_cost.to_le_bytes());
        file_data.extend_from_slice(&kdf_params.t_cost.to_le_bytes());
        file_data.extend_from_slice(&kdf_params.p_cost.to_le_bytes());
        file_data.push(ENCRYPTION_CHACHA20POLY1305);
        file_data.extend_from_slice(&nonce);

        // Write the encrypted body (ciphertext and tag are combined)
        file_data.extend_from_slice(&encrypted_content);

        Ok(file_data)
    }

    fn decrypt_content(&self, file_content: &[u8]) -> Result<String, PassmanError> {
        let mut cursor = Cursor::new(file_content);

        // Read and validate the Header
        let mut magic_number = [0u8; 4];
        cursor.read_exact(&mut magic_number)?;
        if magic_number != *FILE_MAGIC_NUMBER {
            return Err(PassmanError::InvalidFileFormat);
        }

        let mut version_byte = [0u8; 1];
        cursor.read_exact(&mut version_byte)?;
        if version_byte[0] != CURRENT_FILE_VERSION {
            return Err(PassmanError::UnsupportedVersion);
        }

        let mut kdf_type_byte = [0u8; 1];
        cursor.read_exact(&mut kdf_type_byte)?;
        // For now, we only support Argon2id. Add logic here for other KDFs later.
        if kdf_type_byte[0] != KDF_ARGON2ID {
            return Err(PassmanError::InvalidFileFormat);
        }

        let mut salt = [0u8; 16];
        cursor.read_exact(&mut salt)?;
        let mut m_cost_bytes = [0u8; 4];
        cursor.read_exact(&mut m_cost_bytes)?;
        let m_cost = u32::from_le_bytes(m_cost_bytes);
        let mut t_cost_bytes = [0u8; 4];
        cursor.read_exact(&mut t_cost_bytes)?;
        let t_cost = u32::from_le_bytes(t_cost_bytes);
        let mut p_cost_bytes = [0u8; 4];
        cursor.read_exact(&mut p_cost_bytes)?;
        let p_cost = u32::from_le_bytes(p_cost_bytes);

        let kdf_params = KdfParameters {
            salt,
            version: Version::V0x13,
            m_cost,
            t_cost,
            p_cost,
        };

        let mut encryption_type_byte = [0u8; 1];
        cursor.read_exact(&mut encryption_type_byte)?;
        if encryption_type_byte[0] != ENCRYPTION_CHACHA20POLY1305 {
            return Err(PassmanError::InvalidFileFormat);
        }

        let mut nonce = [0u8; 12];
        cursor.read_exact(&mut nonce)?;

        let mut encrypted_content = Vec::new();
        cursor.read_to_end(&mut encrypted_content)?;

        let nonce = GenericArray::clone_from_slice(&nonce);
        let cipher = crypto::gen_decrypt_cipher(self.master_password.as_bytes(), &kdf_params)?;

        let decrypted_content = cipher.decrypt(&nonce, encrypted_content.as_ref())?;

        Ok(String::from_utf8(decrypted_content)?)
    }
}
