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

use std::io::Write;
use std::net::{IpAddr, TcpListener};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{self, Path, PathBuf};

use clap::{Parser, Subcommand};
use log::{debug, error, info, trace, warn};
use serde::{Deserialize, Serialize};

use theseus::ball::*;
use theseus::error::*;
use theseus::msg::*;
use theseus::plan::*;
use theseus::target::*;

#[derive(Debug, Parser)]
#[command(arg_required_else_help = true)]
struct DaemonArgs {
    #[arg(short, help = "verbosity level 0-4", action=clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Just validate the configuration
    Validate {
        /// Path to a configuration file
        #[arg(required = true)]
        config: PathBuf,
    },

    /// Just print an example configuration
    PrintConfig,

    /// Run the theseus daemon
    #[command(arg_required_else_help = true)]
    Run {
        /// Path to a configuration file
        #[arg(required = true)]
        config: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct DaemonConfig {
    /// Where the daemon will store and save balls
    #[serde(default = "theseus::theseusd_default_workdir")]
    work_dir: PathBuf,
    /// Address to listen on
    #[serde(default = "theseus::theseusd_default_addr")]
    address: IpAddr,
    /// port to listen on
    #[serde(default = "theseus::theseusd_default_port")]
    port: u16,
}

// The Thesus daemon handles requests to update and deploy a set of files
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Daemon {
    work_dir: PathBuf,
    // Recomputing these paths every time would be faster, but this is easier to
    // keep track of
    ball_dir: PathBuf,
    ball_root: PathBuf,
    save_root: PathBuf,
    addr_port: (IpAddr, u16),
}

impl Daemon {
    /// Creates a new [`Daemon`].
    /// `config` is the path to the configuration file
    pub fn create(config: &Path) -> anyhow::Result<Self> {
        let config_str = std::fs::read_to_string(path::absolute(config)?)?;
        trace!("read as config {}", config.display());
        let cfg = toml::from_str(&config_str)?;

        let DaemonConfig {
            work_dir,
            address,
            port,
        } = cfg;
        debug!(
            "work_dir: {}, address: {}, port: {}",
            work_dir.display(),
            address,
            port
        );
        let addr_port = (address, port);

        let ball_dir = work_dir.join("balls");
        let ball_root = work_dir.join("ball_root");
        let save_root = work_dir.join("save_root");

        trace!("Creating work directory structure..");
        std::fs::create_dir_all(&ball_dir)?;
        std::fs::create_dir_all(&ball_root)?;
        std::fs::create_dir_all(&save_root)?;
        trace!("Done");

        Ok(Daemon {
            work_dir,
            ball_dir,
            ball_root,
            save_root,
            addr_port,
        })
    }

    /// Run the theseus daemon
    /// This function should never return, unless a fatal error occurs
    pub fn run(&mut self) -> Result<(), TheseusError> {
        let listener =
            TcpListener::bind(self.addr_port).map_err(|e| TheseusError::Bind(e.kind()))?;

        info!("Listening on {}:{}", self.addr_port.0, self.addr_port.1);

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    error!("Connection error {e}",);
                    continue;
                }
            };
            self.conn_handler(stream);
        }
        Err(TheseusError::Server("no more connections".into()))
    }

    /// Handle a new connection
    // Doesn't return a `Result`, but does log encountered errors and responds
    /// to the client with appropriate responses
    fn conn_handler<C: std::io::Read + std::io::Write>(&mut self, mut conn: C) -> Option<()> {
        let req = TheseusRequest::read(&mut conn)
            .inspect_err(|e| error!("Read request {e}"))
            .ok()?;

        let rsp = match req {
            TheseusRequest::Receive(md) => self.handle_recv(md, &mut conn),
            TheseusRequest::Apply => self.handle_apply(),
        }
        .inspect_err(|e| error!("{e}"));

        rsp.write_log(&mut conn);
        Some(())
    }

    /// Handle a TheseusRecieve request
    /// A receive request involves two messages
    /// The first is the receive request, which contains the size and checksum
    /// of the tarball to be sent. If the tarball is not too large then the
    /// daemon will send `TheseusResonse::Ok`, and the client will send the raw
    /// tarball. If the tarball is too large, the server can send
    /// `TheseusResponse::BallSize()` to end the connection
    /// Otherwise, the client then sends the raw tarball, and the server writes
    /// it to disk
    fn handle_recv<C: std::io::Read + std::io::Write>(
        &self,
        md: BallMd,
        conn: &mut C,
    ) -> Result<(), DaemonError> {
        trace!("handle_recv");
        /* recieve ball (if necessary) */
        let ballbuf = match self.recv_ball(md, conn) {
            Ok(buf) => buf,
            Err(DaemonError::BallExists) => {
                /* inform client */
                Err(DaemonError::BallExists).write_log(conn);
                std::fs::read(self.ball_dir.join(md.to_string()))
                    .map_err(|e| DaemonError::ServerError(e.to_string()))?
            }
            Err(e) => return Err(e),
        };

        /* Unball mf */
        assert_ne!(
            self.ball_root.as_os_str(),
            "/",
            "self.ball_root is not root"
        );
        std::fs::remove_dir_all(&self.ball_root)
            .map_err(|e| DaemonError::ServerError(e.to_string()))?;
        std::fs::create_dir(&self.ball_root)
            .map_err(|e| DaemonError::ServerError(e.to_string()))?;
        ball_to_dir(&self.ball_root, &ballbuf)
            .map_err(|e| DaemonError::ServerError(e.to_string()))?;
        trace!("unballed {}", md.to_string());
        Ok(())
    }

    /// Recieve a new ball from a theseus wizard
    fn recv_ball<C: std::io::Read + std::io::Write>(
        &self,
        md: BallMd,
        conn: &mut C,
    ) -> Result<Vec<u8>, DaemonError> {
        let tname = md.to_string();
        let tpath = self.ball_dir.join(&tname);
        trace!("handle_recv::md {}", tname);

        /* Check whether ball with that hash exists */
        if tpath.exists() {
            let mut hasher = blake3::Hasher::new();
            let tf =
                std::fs::File::open(&tpath).map_err(|e| DaemonError::ServerError(e.to_string()))?;
            hasher
                .update_reader(&tf)
                .map_err(|e| DaemonError::ServerError(e.to_string()))?;
            let _ck = hasher.finalize();

            if _ck == md.checksum {
                return Err(DaemonError::BallExists);
            }

            warn!("ball at {} corrupted, checksum is {:?}", tname, _ck);
            warn!("Accepting new ball");
        }

        /* Allocate file space */
        let mut f = std::fs::OpenOptions::new()
            .mode(0o0600)
            .write(true)
            .truncate(true)
            .create(true)
            .open(tpath)
            .map_err(|e| DaemonError::ServerError(e.to_string()))?;
        f.set_len(md.size)
            .map_err(|e| DaemonError::ServerError(e.to_string()))?;

        let mut buf = vec![0; md.size as usize];

        /* Send Ok */
        Result::<(), DaemonError>::Ok(()).write_log(conn);

        trace!("Want to read {}", md.size);
        /* Read Ball into f */
        conn.read_exact(&mut buf)
            .map_err(|e| DaemonError::ServerError(e.to_string()))?;

        /* Verify checksum */
        let _ck = blake3::hash(&buf[..]);
        /* Constant time since Hash implements From<[u8; 32]> */
        if _ck != md.checksum {
            return Err(DaemonError::BallChecksum);
        }
        trace!("Checksum consistent");

        /* Write ball to disk */
        f.write_all(&buf)
            .map_err(|e| DaemonError::ServerError(e.to_string()))?;

        trace!("Wrote to disk");
        Ok(buf)
    }

    fn handle_apply(&self) -> Result<(), DaemonError> {
        trace!("handle_apply");

        let plan =
            plan_from_dir(&self.ball_root).map_err(|e| DaemonError::ServerError(e.to_string()))?;
        trace!("read plan of length {}", plan.len());
        plan.into_iter()
            .execute_plan(&self.save_root)
            .map_err(|e| DaemonError::ServerError(e.identify()))?;

        trace!("apply successful");
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let args = DaemonArgs::parse();
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
        Some(Command::Validate { config }) => {
            let _ = Daemon::create(&config)?;
            Ok(())
        }
        Some(Command::PrintConfig) => {
            let dconf = DaemonConfig {
                work_dir: Path::new("/var/lib/theseus/").to_path_buf(),
                address: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                port: 6666,
            };
            println!("{}", toml::to_string(&dconf).unwrap());
            Ok(())
        }
        Some(Command::Run { config }) => {
            let _ = Daemon::create(&config)?.run();
            /* ??? */
            unreachable!()
        }
        None => {
            unreachable!()
        }
    }
}
