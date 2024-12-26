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

use std::io::Read;
use std::{io::Write, net::TcpStream, os::unix::fs::OpenOptionsExt, path::PathBuf};

use clap::Parser;
use tracing::{debug, error, info, trace, warn};

use theseus::ball::*;
use theseus::crypto::*;
use theseus::error::*;
use theseus::msg::*;
use theseus::plan::*;
use theseus::target::*;

/// The Theseus Golem
#[derive(Debug, Parser)]
#[clap(name = "Golem")]
#[command(version, about, long_about=None)]
struct GolemArgs {
    /// Port to listen on
    #[arg(short, default_value = "6666")]
    port: u16,

    /// Verbosity level 0-4
    #[arg(short, action=clap::ArgAction::Count)]
    verbose: u8,

    /// Where the daemon will store and save balls
    #[arg(short, default_value = "/var/tmp/theseus/")]
    work_dir: PathBuf,

    /// Directory in which to store logs
    #[arg(short, default_value = "/tmp")]
    log_dir: PathBuf,
}

// The Thesus golem handles requests to update and deploy a set of files
#[derive(Debug, PartialEq, Eq, Clone)]
struct Golem {
    work_dir: PathBuf,
    port: u16,
    // Recomputing these paths every time would be faster, but this is easier to
    // keep track of
    ball_dir: PathBuf,
    ball_root: PathBuf,
    save_root: PathBuf,
}

impl Golem {
    /// Creates a new [`Golem`].
    /// `config` is the path to the configuration file
    pub fn create(port: u16, work_dir: PathBuf) -> anyhow::Result<Self> {
        debug!("work_dir: {}, port: {}", work_dir.display(), port);

        let ball_dir = work_dir.join("balls");
        let ball_root = work_dir.join("ball_root");
        let save_root = work_dir.join("save_root");

        debug!("Creating work directory structure...");
        trace!("Creating {}", ball_dir.display());
        std::fs::create_dir_all(&ball_dir)?;
        trace!("Creating {}", ball_root.display());
        std::fs::create_dir_all(&ball_root)?;
        trace!("Creating {}", save_root.display());
        std::fs::create_dir_all(&save_root)?;
        trace!("Done");

        Ok(Golem {
            work_dir,
            ball_dir,
            ball_root,
            save_root,
            port,
        })
    }

    /// Run the theseus golem
    pub fn run(&mut self) -> Result<(), TheseusError> {
        let stream = TcpStream::connect(("localhost", self.port))?;
        self.conn_handler(stream)?;
        Ok(())
    }

    /// Handle a new connection
    // Doesn't return a `Result`, but does log encountered errors and responds
    /// to the client with appropriate responses
    fn conn_handler<C: std::io::Read + std::io::Write>(
        &mut self,
        mut conn: C,
    ) -> anyhow::Result<()> {
        loop {
            let req = GolemRequest::read(&mut conn)?;

            let rsp = match req {
                GolemRequest::Receive(md) => self.handle_recv(md, &mut conn),
                GolemRequest::Apply => self.handle_apply(),
                GolemRequest::Kill => {
                    /* TODO: Should we clean up the working directories? */
                    Ok(()).write_log(&mut conn);
                    break;
                }
                GolemRequest::Ping => {
                    info!("Recieved PING from wizard");
                    Ok(())
                }
            };

            rsp.write_log(&mut conn);
        }
        Ok(())
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
    ) -> Result<(), GolemError> {
        trace!("handle_recv");
        /* recieve ball (if necessary) */
        let ballbuf = match self.recv_ball(md, conn) {
            Ok(buf) => buf,
            Err(GolemError::BallExists) => {
                /* inform client */
                Err(GolemError::BallExists).write_log(conn);
                std::fs::read(self.ball_dir.join(md.to_string()))
                    .map_err(|e| GolemError::ServerError(e.to_string()))?
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
            .map_err(|e| GolemError::ServerError(e.to_string()))?;
        std::fs::create_dir(&self.ball_root).map_err(|e| GolemError::ServerError(e.to_string()))?;
        ball_to_dir(&self.ball_root, &ballbuf)
            .map_err(|e| GolemError::ServerError(e.to_string()))?;
        trace!("unballed {}", md.to_string());
        Ok(())
    }

    /// Recieve a new ball from a theseus wizard
    fn recv_ball<C: std::io::Read + std::io::Write>(
        &self,
        md: BallMd,
        conn: &mut C,
    ) -> Result<Vec<u8>, GolemError> {
        let tname = md.to_string();
        let tpath = self.ball_dir.join(&tname);
        trace!("handle_recv::md {}", tname);

        /* Check whether ball with that hash exists */
        if tpath.exists() {
            let mut tfb = Vec::new();
            let mut tf =
                std::fs::File::open(&tpath).map_err(|e| GolemError::ServerError(e.to_string()))?;
            tf.read_to_end(&mut tfb)
                .map_err(|e| GolemError::ServerError(e.to_string()))?;
            let ck = crypto_hash(&tfb);

            if ck == md.checksum {
                return Err(GolemError::BallExists);
            }

            warn!("ball at {} corrupted, checksum is {:?}", tname, ck);
            warn!("Accepting new ball");
        }

        /* Allocate file space */
        let mut f = std::fs::OpenOptions::new()
            .mode(0o0600)
            .write(true)
            .truncate(true)
            .create(true)
            .open(tpath)
            .map_err(|e| GolemError::ServerError(e.to_string()))?;
        f.set_len(md.size)
            .map_err(|e| GolemError::ServerError(e.to_string()))?;

        let mut buf = vec![0; md.size as usize];

        /* Send Ok */
        Result::<(), GolemError>::Ok(()).write_log(conn);

        trace!("Want to read {}", md.size);
        /* Read Ball into f */
        conn.read_exact(&mut buf)
            .map_err(|e| GolemError::ServerError(e.to_string()))?;

        /* Verify checksum */
        let ck = crypto_hash(&buf[..]);

        if ck != md.checksum {
            return Err(GolemError::BallChecksum);
        }
        trace!("Checksum consistent");

        /* Write ball to disk */
        f.write_all(&buf)
            .map_err(|e| GolemError::ServerError(e.to_string()))?;

        trace!("Wrote to disk");
        Ok(buf)
    }

    fn handle_apply(&self) -> Result<(), GolemError> {
        trace!("handle_apply");

        let plan =
            plan_from_root(&self.ball_root).map_err(|e| GolemError::ServerError(e.to_string()))?;
        trace!("read plan of length {}", plan.len());
        plan.execute_dependencies()
            .map_err(|e| GolemError::DependencyError(e.identify()))?;
        plan.into_iter()
            .execute_plan(Some(&self.save_root))
            .map_err(|e| GolemError::PlanError(e.identify()))?;

        trace!("apply successful");
        Ok(())
    }
}

fn try_main(args: GolemArgs) -> anyhow::Result<()> {
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(args.log_dir.join("golem.log"))?;

    let tracer = tracing_subscriber::fmt()
        .without_time()
        .compact()
        .with_ansi(false)
        .with_max_level(match args.verbose {
            0 => tracing::Level::ERROR,
            1 => tracing::Level::WARN,
            2 => tracing::Level::INFO,
            3 => tracing::Level::DEBUG,
            4.. => tracing::Level::TRACE,
        })
        .with_writer(log_file)
        .finish();
    tracing::subscriber::set_global_default(tracer)?;

    Ok(Golem::create(args.port, args.work_dir)?.run()?)
}

fn main() {
    let args = GolemArgs::parse();
    match try_main(args) {
        Ok(_) => {}
        Err(e) => error!("{e:#}"),
    }
}
