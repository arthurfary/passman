use crate::error::PassmanError;
use argon2::{Argon2, Params, Version};
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Key};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use rand::RngCore;

pub struct KdfParameters {
    pub salt: [u8; 16],
    pub version: Version,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

pub fn gen_new_cipher(
    pwd: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<(ChaCha20Poly1305, KdfParameters, [u8; 12]), PassmanError> {
    let mut rng = ChaCha20Rng::from_os_rng();

    let mut random_salt = [0u8; 16];
    rng.fill_bytes(&mut random_salt);

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let kdf_params = KdfParameters {
        salt: random_salt,
        version: Version::V0x13,
        m_cost,
        t_cost,
        p_cost,
    };

    let params = Params::new(m_cost, t_cost, p_cost, None)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut output_key = [0u8; 32];
    argon2.hash_password_into(pwd, &random_salt, &mut output_key)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&output_key));
    Ok((cipher, kdf_params, nonce))
}

pub fn gen_decrypt_cipher(
    pwd: &[u8],
    params: &KdfParameters,
) -> Result<ChaCha20Poly1305, PassmanError> {
    let mut decrypt_key = [0u8; 32];

    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, None)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, params.version, argon2_params);

    argon2.hash_password_into(pwd, &params.salt, &mut decrypt_key)?;

    Ok(ChaCha20Poly1305::new(Key::from_slice(&decrypt_key)))
}
