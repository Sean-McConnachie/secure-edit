/// File format:
/// `<[Salt; 128][Blocks]>`
use super::{PBKDF2_ITERS, SALT_BYTES};
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};
use anyhow::{anyhow, Result};
use pbkdf2::pbkdf2_hmac_array;
use rand_core::{OsRng, RngCore};
use sha2::Sha512;

fn pad_zeroes<const N: usize>(arr: &[u8]) -> [u8; N] {
    let mut ret = [0; N];
    ret[..arr.len()].copy_from_slice(&arr);
    ret
}

pub fn generate_salt() -> [u8; SALT_BYTES] {
    let mut salt = [0u8; SALT_BYTES];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn generate_key(pwd: &str, salt: &[u8]) -> [u8; 32] {
    let hash = pbkdf2_hmac_array::<Sha512, 20>(pwd.as_bytes(), salt, PBKDF2_ITERS);
    pad_zeroes(&hash)
}

pub fn encrypt_data(key: [u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(data.len());
    let mut block = GenericArray::from([0u8; 16]);
    let cipher =
        Aes256::new_from_slice(&key).map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

    let mut handle_chunk = |chunk: &[u8]| {
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        output.extend_from_slice(&block);
    };

    let chunks = data.chunks_exact(16);
    let remainder = chunks.remainder();
    for block_data in chunks {
        handle_chunk(block_data);
    }
    if !remainder.is_empty() {
        let block_data = pad_zeroes::<16>(remainder);
        handle_chunk(&block_data);
    }

    Ok(output)
}

pub fn decrypt_data(key: [u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() % 16 != 0 {
        return Err(anyhow!("Data length is not a multiple of 16"));
    }
    let mut output = Vec::with_capacity(data.len());
    let mut block = GenericArray::from([0u8; 16]);
    let cipher =
        Aes256::new_from_slice(&key).map_err(|e| anyhow!("Failed to create AES cipher: {}", e))?;

    let mut handle_chunk = |chunk: &[u8]| {
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        output.extend_from_slice(&block);
    };

    let chunks = data.chunks_exact(16);
    for block_data in chunks {
        handle_chunk(block_data);
    }

    Ok(output)
}

pub fn encrypt_data_formatted(pwd: &str, salt: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut input = Vec::with_capacity(SALT_BYTES + data.len());
    let mut output = Vec::with_capacity(SALT_BYTES + data.len());
    input.extend_from_slice(&(data.len() as u64).to_le_bytes());
    input.extend_from_slice(data);
    output.extend_from_slice(salt);
    let key = generate_key(pwd, salt);
    let encrypted_data = encrypt_data(key, &input)?;
    output.extend_from_slice(&encrypted_data);
    Ok(output)
}

pub fn decrypt_data_formatted(pwd: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < SALT_BYTES {
        return Err(anyhow!("Data is too short"));
    }
    let salt = &data[..SALT_BYTES];
    let key = generate_key(pwd, salt);
    let decrypted_data = decrypt_data(key, &data[SALT_BYTES..])?;
    let len_bytes = &decrypted_data[..8];
    let len = u64::from_le_bytes(len_bytes.try_into()?) as usize;
    Ok(decrypted_data[8..8 + len].to_vec())
}
