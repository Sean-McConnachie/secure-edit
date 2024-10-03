use super::secure;
use super::{SALT_BYTES, SECURE_EDIT_DIR, SECURE_FILE_EXT};
use anyhow::{anyhow, Result};
use clap::Parser;
use std::path::PathBuf;
use std::{fs, process};

type Version = u32;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub dir: Option<PathBuf>,
}

fn write_message(message: &str) -> Result<()> {
    use std::io::{self, Write};
    io::stdout().write_all(message.as_bytes())?;
    Ok(())
}

fn should_proceed(message: &str) -> Result<bool> {
    use std::io::{self, Write};
    print!("{} (y/n): ", message);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase() == "y")
}

fn user_input(message: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{} > ", message);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let dir = args.dir.unwrap_or_else(|| PathBuf::from("."));
    if is_secure_edit_dir(&dir)? {
        edit_secure_dir(&dir)?;
    } else {
        if !should_proceed(&format!(
            "Create secure edit directory in `{}`?",
            dir.display()
        ))? {
            write_message("Goodbye!\n")?;
            return Ok(());
        }
        create_secure_dir(&dir)?;
    }
    Ok(())
}

fn is_secure_edit_dir(dir: &PathBuf) -> Result<bool> {
    if !dir.exists() {
        return Ok(false);
    }
    if !dir.is_dir() {
        return Err(anyhow!("Path is not a directory"));
    }
    let secure_edit_fp = dir.join(SECURE_EDIT_DIR);
    Ok(secure_edit_fp.exists())
}

fn secure_file_fp(dir: &PathBuf, version: Version) -> PathBuf {
    dir.join(format!(".{version}{SECURE_FILE_EXT}"))
}

fn create_secure_dir(dir: &PathBuf) -> Result<()> {
    write_message("Creating secure edit directory\n")?;
    if !dir.exists() {
        fs::create_dir(&dir)?;
    }
    let secure_edit_fp = dir.join(SECURE_EDIT_DIR);
    fs::write(&secure_edit_fp, "")?;
    write_message(&format!(
        "Secure edit directory created at `{}`\n",
        secure_edit_fp.display()
    ))?;
    let new_secure_version = create_secure_file(&dir)?;
    edit_secure_file(
        &secure_file_fp(dir, new_secure_version),
        &secure_file_fp(dir, new_secure_version + 1),
    )?;
    Ok(())
}

fn edit_secure_dir(dir: &PathBuf) -> Result<()> {
    write_message("Editing secure directory\n")?;
    let mut secure_files = Vec::new();
    for entry in dir.read_dir()? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if file_name.ends_with(".secure") {
            let version = file_name[1..].trim_end_matches(SECURE_FILE_EXT);
            let version = version.parse::<Version>()?;
            secure_files.push(version);
        }
    }
    secure_files.sort();
    if secure_files.is_empty() {
        let new_secure_version = create_secure_file(dir)?;
        secure_files.push(new_secure_version);
    }
    let latest_version = *secure_files.last().unwrap();
    edit_secure_file(
        &secure_file_fp(dir, latest_version),
        &secure_file_fp(dir, latest_version + 1),
    )?;
    Ok(())
}

fn create_secure_file(dir: &PathBuf) -> Result<Version> {
    write_message("No secure files found. Creating one now!\n")?;
    let version = 0;
    let secure_fp = secure_file_fp(dir, version);
    let pwd1 = user_input("Enter password")?;
    let pwd2 = user_input("Re-enter password")?;
    if pwd1 != pwd2 {
        return Err(anyhow!("Passwords do not match"));
    }
    let salt = secure::generate_salt();
    let encrypted_data = secure::encrypt_data_formatted(&pwd1, &salt, &[])?;
    fs::write(&secure_fp, &encrypted_data)?;
    Ok(version)
}

fn edit_secure_file(open_fp: &PathBuf, write_fp: &PathBuf) -> Result<()> {
    use std::io::Write;
    write_message(&format!("Editing secure file at `{}`\n", open_fp.display()))?;
    let pwd = user_input("Enter password")?;
    let data = fs::read(open_fp)?;
    let decrypted_data = secure::decrypt_data_formatted(&pwd, &data)?;

    let cmd = process::Command::new("vipe")
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .spawn()?;
    let mut stdin = cmd.stdin.as_ref().unwrap();
    stdin.write_all(&decrypted_data)?;
    let output = cmd.wait_with_output()?;
    if !output.status.success() {
        return Err(anyhow!("Failed to edit file"));
    }

    write_message(&format!(
        "Saving new secure file at `{}`\n",
        write_fp.display()
    ))?;
    let new_data = output.stdout;
    let encrypted_data = secure::encrypt_data_formatted(&pwd, &data[..SALT_BYTES], &new_data)?;
    fs::write(write_fp, &encrypted_data)?;
    Ok(())
}
