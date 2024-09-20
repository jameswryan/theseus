// Copyright 2024 James Ryan

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    io::Write,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
};

use anyhow::Result;

use log::{info, trace};

use theseus::ball::*;
use theseus::error::*;
use theseus::msg::*;
use theseus::target::*;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(arg_required_else_help = true)]
struct WizardArgs {
    #[arg(short, help="verbosity level 0-4", action=clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Apply the plan on a remote theseus server
    Apply {
        /// Address of theseus server
        #[arg(short, long, required = true)]
        address: String,
        /// Port on remote theseus server
        #[arg(short, long, default_value = "6666")]
        port: u16,
    },
    /// Upload a plan to a theseus server
    Upload {
        /// Address of theseus server
        #[arg(short, long, required = true)]
        address: String,
        /// Directory containing a plan
        #[arg(required = true)]
        input: String,
        /// Port on remote theseus server
        #[arg(short, long, required = true)]
        port: u16,
    },
    /// Validate a plan
    Validate {
        /// Directory containing a plan
        #[arg(required = true)]
        input: String,
    },
}

/// Reads a plan from a directory and checks for errors
/// Does not check that the target _destinations_ are valid,
/// but does check that the plan is properly formed
fn validate_plan(dir: &Path) -> Result<(), TheseusError> {
    let _plan = plan_from_dir(dir)?;
    Ok(())
}

fn upload_plan(server: impl ToSocketAddrs, dir: &Path) -> anyhow::Result<()> {
    let ball = dir_to_ball(dir)?;
    let md = BallMd::new(&ball);
    info!("send_dir ballmd {}", md);

    let mut stream = TcpStream::connect(server)?;
    let recv_err = TheseusRequest::Receive(md)
        .write(&mut stream)
        .map_err(|e| TheseusError::WriteRequest(e.to_string()))?
        .inspect(|_| info!("Ok to transmit"));
    match recv_err {
        Ok(_) => {
            trace!("Want to write {}", ball.len());
            stream
                .write_all(&ball)
                .map_err(|e| TheseusError::WriteBall(e.to_string()))?;
        }
        Err(DaemonError::BallExists) => {
            info!("No need to transmit, ball exists");
            return Ok(());
        }
        Err(e) => return Err(anyhow::anyhow!(e)),
    }

    Ok(Result::<(), DaemonError>::read(&mut stream)??)
}

fn apply_plan(server: impl ToSocketAddrs) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(server)?;
    info!("Connected!");
    let rsp = TheseusRequest::Apply.write(&mut stream)?;
    info!("{:?}", rsp);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = WizardArgs::parse();

    env_logger::builder()
        .filter_level(match args.verbose {
            0 => log::LevelFilter::Error,
            1 => log::LevelFilter::Warn,
            2 => log::LevelFilter::Info,
            3 => log::LevelFilter::Debug,
            4.. => log::LevelFilter::Trace,
        })
        .init();

    match args.command {
        Some(Command::Validate { input }) => {
            validate_plan(Path::new(&input))?;
            println!("Plan {} is valid", &input);
            Ok(())
        }
        Some(Command::Upload {
            address,
            input,
            port,
        }) => upload_plan((address, port), Path::new(&input)),
        Some(Command::Apply { address, port }) => apply_plan((address, port)),
        None => unreachable!(),
    }
}
