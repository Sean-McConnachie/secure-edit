#[cfg(test)]
mod tests {
    use super::super::secure::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let encrypted = encrypt_data(key.clone(), data).unwrap();
        let decrypted = decrypt_data(key, &encrypted).unwrap();
        assert_eq!(data, &decrypted.as_slice()[..data.len()]);
    }

    #[test]
    fn test_encrypt_decrypt_formatted() {
        let pwd = "password";
        let salt = generate_salt();
        let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let encrypted = encrypt_data_formatted(pwd, &salt, data).unwrap();
        let decrypted = decrypt_data_formatted(pwd, &encrypted).unwrap();
        assert_eq!(data, &decrypted.as_slice()[..data.len()]);
    }
}
