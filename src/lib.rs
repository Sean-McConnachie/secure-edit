pub mod cli;
pub mod secure;
pub mod tests;

const SECURE_EDIT_DIR: &str = ".secure_edit";
const SECURE_FILE_EXT: &str = ".secure";
const PBKDF2_ITERS: u32 = 600_000;
const SALT_BYTES: usize = 32;
