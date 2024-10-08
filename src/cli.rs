use super::secure;
use super::{SALT_BYTES, SECURE_EDIT_DIR, SECURE_FILE_EXT};
use anyhow::{anyhow, Result};
use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;
use std::{fs, process};

type Version = u32;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub dir: Option<PathBuf>,
    #[arg(short, long)]
    pub version: Option<Version>,
}

fn user_input(message: &str, align: Option<usize>, sensitive: bool) -> Result<String> {
    use std::io::{self, Write};
    print!("{message}");
    if let Some(pad) = align {
        print!("{:width$}", " ", width = pad);
    }
    print!("{}", " > ".blink().purple());
    io::stdout().flush()?;
    let mut input = String::new();
    if sensitive {
        input = rpassword::read_password()?;
    } else {
        io::stdin().read_line(&mut input)?;
    }
    Ok(input.trim().to_string())
}

fn should_proceed(message: &str) -> Result<bool> {
    Ok(user_input(
        &format!("{} ({}/{})", message, "y".green(), "n".red()),
        None,
        false,
    )?
    .trim()
    .to_lowercase()
        == "y")
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let dir = args.dir.unwrap_or_else(|| PathBuf::from("."));
    if is_secure_edit_dir(&dir)? {
        edit_secure_dir(&dir, args.version)?;
    } else {
        if !should_proceed(&format!(
            "{} `{}`{}",
            "Create secure edit directory in".bold().blue(),
            dir.display().to_string().italic(),
            "?".bold().blue()
        ))? {
            println!("{}\n", "Goodbye!".bold().italic().blue());
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
    println!("{}", "Creating secure edit directory".green());
    if !dir.exists() {
        fs::create_dir(&dir)?;
    }
    let secure_edit_fp = dir.join(SECURE_EDIT_DIR);
    fs::write(&secure_edit_fp, "")?;
    println!(
        "{} `{}`",
        "Secure edit directory created at".green().bold(),
        secure_edit_fp.display().to_string().italic()
    );
    let new_secure_version = create_secure_file(&dir)?;
    edit_secure_file(
        &secure_file_fp(dir, new_secure_version),
        &secure_file_fp(dir, new_secure_version + 1),
    )?;
    Ok(())
}

fn edit_secure_dir(dir: &PathBuf, version: Option<Version>) -> Result<()> {
    println!("{}", "Editing secure directory".green());
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
    let open_version = version.unwrap_or(latest_version);
    edit_secure_file(
        &secure_file_fp(dir, open_version),
        &secure_file_fp(dir, latest_version + 1),
    )?;
    Ok(())
}

fn create_secure_file(dir: &PathBuf) -> Result<Version> {
    println!(
        "{} {}",
        "No secure files found.".yellow(),
        "Creating secure file".green()
    );
    let version = 0;
    let secure_fp = secure_file_fp(dir, version);
    let pwd1 = user_input(
        &format!("{}", "Enter password".blue().bold()),
        Some(3),
        true,
    )?;
    let pwd2 = user_input(
        &format!("{}", "Re-enter password".blue().bold()),
        None,
        true,
    )?;
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
    println!(
        "{} `{}`",
        "Opening secure file".green(),
        open_fp.display().to_string().italic()
    );

    if !open_fp.exists() {
        return Err(anyhow!(
            "Secure file to read at `{}` does not exist",
            open_fp.display()
        ));
    }
    if write_fp.exists() {
        return Err(anyhow!(
            "Secure file to write at `{}` already exists",
            write_fp.display()
        ));
    }

    let pwd = user_input(&format!("{}", "Enter password".blue().bold()), None, true)?;
    let data = fs::read(open_fp)?;
    let decrypted_data = secure::decrypt_data_formatted(&pwd, &data)
        .map_err(|_| anyhow!("Failed to decrypt file. Wrong password?"))?;

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

    println!(
        "{} `{}`",
        "Saving new secure file at".bold().green(),
        write_fp.display().to_string().italic()
    );
    let new_data = output.stdout;
    let encrypted_data = secure::encrypt_data_formatted(&pwd, &data[..SALT_BYTES], &new_data)?;
    fs::write(write_fp, &encrypted_data)?;
    Ok(())
}
