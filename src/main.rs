fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use secure_edit::cli;

    let args = cli::Args::parse();
    cli::run(args)?;
    Ok(())
}
