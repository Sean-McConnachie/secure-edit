use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use secure_edit::cli;

    let mut args = cli::Args::parse();

    let test_dir = PathBuf::from("test");
    if test_dir.exists() {
        std::fs::remove_dir_all(&test_dir)?;
    }
    args.dir = Some(test_dir);

    cli::run(args)?;
    Ok(())
}
