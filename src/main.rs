use anyhow::Result;

fn is_vipe_installed() -> Result<()> {
    use std::process::Command;
    if !Command::new("which").arg("vipe").output()?.status.success() {
        eprintln!("vipe is not installed. Please install `moreutils` package.");
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> Result<()> {
    is_vipe_installed()?;

    use clap::Parser;
    use secure_edit::cli;

    let args = cli::Args::parse();
    cli::run(args)?;
    Ok(())
}
