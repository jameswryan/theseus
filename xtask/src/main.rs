use anyhow::{Context, Result};
use clap::Parser;
use std::fs;

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
}

const BIN_DIR: &str = "bins";

fn get_out_dir() -> String {
    if let Ok(env_target) = std::env::var("CARGO_TARGET_DIR") {
        return env_target;
    };

    String::from("target")
}

fn move_binaries(target: TheseusPlatform) -> Result<()> {
    let out_dir = get_out_dir();
    let bin_dir = String::from(BIN_DIR);
    let wiz_from =
        out_dir.clone() + "/" + &target.to_string() + "/release/theseus";
    let gol_from =
        out_dir.clone() + "/" + &target.to_string() + "/release/theseusg";

    let wiz_to = bin_dir.clone() + "/theseus:" + &target.to_string();
    let gol_to = bin_dir.clone() + "/theseusg:" + &target.to_string();

    fs::create_dir_all(bin_dir).context("create bin dir")?;

    fs::copy(wiz_from, &wiz_to).context("copy wizard")?;
    fs::copy(gol_from, &gol_to).context("copy golem")?;

    std::println!("Copied wizard to {wiz_to}");
    std::println!("Copied golem to {gol_to}");

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build { target } => {
            let out_dir = get_out_dir();

            std::process::Command::new("cargo")
                .args([
                    "build",
                    "--release",
                    &format!("--target-dir={out_dir}"),
                    &format!("--target={target}"),
                ])
                .status()?;
            move_binaries(target)?;
        }
        Commands::Clean => {
            std::process::Command::new("cargo")
                .args(["clean"])
                .status()?;

            std::fs::remove_dir_all(BIN_DIR).context("clean up bin dir")?;
        }
    }

    Ok(())
}
