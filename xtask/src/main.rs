use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::fs::{copy, create_dir_all, read_to_string, remove_dir_all};

use theseus::TheseusPlatform;

#[derive(Debug, Parser)]
#[command(version,about,long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, clap::Subcommand)]
enum Commands {
    /// Build the project
    Build {
        /// Target platform
        target: TheseusPlatform,
    },

    /// Clean build artifacts
    Clean,

    /// Test the project
    Test,
}


fn workspace_root() -> String {
    std::path::Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn out_dir() -> String {
    if let Ok(env_target) = std::env::var("CARGO_TARGET_DIR") {
        return env_target;
    };

    String::from("target")
}

fn bin_dir() -> String {
  format!("{}/bins", out_dir())
}

fn version() -> String {
    read_to_string(format!("{}/theseus/Cargo.toml", workspace_root()))
        .expect("Can find theseus/Cargo.toml")
        .lines()
        .inspect(|l| eprintln!("{}", l))
        .find(|ln| ln.starts_with("version = "))
        .inspect(|l| eprintln!("{}", l))
        .expect("Cargo.toml contains version string")
        .split("\"")
        .inspect(|l| eprintln!("{}", l))
        .nth(1)
        .expect("Version string is in \"\"")
        .to_string()
}

fn move_binaries(target: TheseusPlatform) -> Result<()> {
    let out_dir = out_dir();
    let ver = version();
    let bin_dir = bin_dir();
    let wiz_from = format!("{}/{}/release/theseus", out_dir, target);
    let gol_from = format!("{}/{}/release/theseusg", out_dir, target);

    let wiz_to = format!("{}/theseus:{}:{}", bin_dir, ver, target);
    let gol_to = format!("{}/theseusg:{}:{}", bin_dir, ver, target);

    create_dir_all(bin_dir).context("create bin dir")?;

    copy(wiz_from, &wiz_to).context("copy wizard")?;
    copy(gol_from, &gol_to).context("copy golem")?;

    std::println!("Copied wizard to {wiz_to}");
    std::println!("Copied golem to {gol_to}");

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { target } => {
            let out_dir = out_dir();

            std::process::Command::new("cross")
                .args([
                    "build",
                    "--package",
                    "theseus",
                    "--release",
                    &format!("--target-dir={out_dir}"),
                    &format!("--target={target}"),
                ])
                .status()?
                .success()
                .then_some(())
                .ok_or(anyhow!("cross build failed"))?;
            move_binaries(target)?;
        }
        Commands::Clean => {
            std::process::Command::new("cross")
                .args(["clean"])
                .status()?
                .success()
                .then_some(())
                .ok_or(anyhow!("cross clean failed"))?;

            remove_dir_all(bin_dir()).context("clean up bin dir")?;
        }
        Commands::Test => {
            std::process::Command::new("cross")
                .args(["test"])
                .status()?
                .success()
                .then_some(())
                .ok_or(anyhow!("cross test failed"))?;
        }
    }

    Ok(())
}
