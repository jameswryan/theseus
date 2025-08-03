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
    collections::HashMap,
    ffi::OsStr,
    fmt::Debug,
    fs::{exists, File},
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{self, Child, Output, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
// TODO: Use Argh because it seems nicer and produces smaller binaries
use clap::{CommandFactory, Parser, Subcommand};
use nix::sys::{
    signal::{kill, Signal},
    stat::Mode,
};
use plan::{DependentPlan, PlanItem};
use tracing::{debug, error, info, instrument, trace};
use walkdir::WalkDir;

use theseus::{
    ball::*, crypto::*, error::*, is_golem, msg::*, provider::theseus_keygen,
    target::*, TheseusPlatform, TmpDir,
};

#[derive(Debug, Parser)]
#[command(arg_required_else_help = true, version, about, long_about=None)]
struct WizardArgs {
    /// Verbosity level 0-4
    #[arg(short, action=clap::ArgAction::Count, global=true)]
    verbose: u8,
    /// Comma separated list of paths to search for golems
    #[arg(short, value_delimiter = ',', num_args=1..)]
    golem_paths: Vec<String>,

    /// Optional key provider used for encryption
    #[arg(short, global = true)]
    key_provider: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Apply a plan on a machine
    Apply {
        /// Address of theseus server
        #[arg(short, required = true)]
        address: String,

        /// Directory containing plan to apply
        #[arg(short, required = true)]
        dir: PathBuf,

        /// Port on remote theseus server
        #[arg(short, default_value = "6666")]
        port: u16,

        /// Username on remote machine
        #[arg(short, default_value = "root")]
        username: String,
    },

    /// Validate a plan
    Validate {
        /// Directory containing a plan
        #[arg(required = true)]
        dir: String,
    },

    /// Construct a golem on a remote machine
    ConstructGolem {
        /// Hostname or address
        #[arg(short, required = true)]
        address: String,

        /// Port used by theseus on remote machine
        #[arg(short, default_value = "6666")]
        port: u16,

        /// Username on remote machine
        #[arg(short, default_value = "root")]
        username: String,
    },

    /// List available golems
    ListGolems {},

    /// Change the target user/group of a path
    /// Append -R to recurse
    Chown {
        /// Recurse
        #[arg(short = 'R', default_value = "false")]
        recurse: bool,

        /// Target user:group
        #[arg(required = true)]
        usergroup: String,

        /// Target
        #[arg(required = true)]
        path: PathBuf,
    },

    /// Change the target mode of a path
    /// Append -R to recurse
    Chmod {
        /// Recurse
        #[arg(short = 'R', default_value = "false")]
        recurse: bool,

        /// Target mode
        #[arg(required = true)]
        mode: String,

        /// Target
        #[arg(required = true)]
        path: PathBuf,
    },

    /// Open a file in $EDITOR
    Open {
        /// File to open
        #[arg(required = true)]
        file: PathBuf,
    },

    /// Deal with crypto
    #[warn(
        incomplete_features,
        reason = "crypto interface is unstable and will change"
    )]
    Crypto {
        #[command(subcommand)]
        action: CryptoAction,
    },
}

#[derive(Debug, Subcommand)]
enum CryptoAction {
    /// Decrypt an encrypted file in-place
    Decrypt {
        #[arg(required = true)]
        path: PathBuf,
    },
    /// Encrypt a file in-place
    Encrypt {
        #[arg(required = true)]
        path: PathBuf,
    },
    /// Create a new `file://` key
    Keygen {
        #[arg(required = true)]
        path: PathBuf,
    },
    /// Change the key provider for a file
    Rekey {
        #[arg(required = true)]
        path: PathBuf,

        #[arg(required = true)]
        from: String,

        #[arg(required = true)]
        to: String,
    },
}

/// If `p` exists, read and return the contents
/// Otherwise, return nothing
fn open_if_exists(p: &Path) -> Result<Vec<u8>> {
    let mut fc = Vec::new();
    if !exists(p)? {
        return Ok(fc);
    }
    File::open(p)?.read_to_end(&mut fc)?;
    Ok(fc)
}

/// Open a file in $EDITOR
fn wizard_open(p: &Path, mkey: Option<&TheseusKey>) -> Result<()> {
    trace!(
        "open {} with{} key",
        p.display(),
        if mkey.is_some() { "" } else { "out" }
    );
    let _contents = open_if_exists(p)?;
    let mut contents = if is_encrypted(&_contents[..], mkey)? {
        trace!("encrypted");
        let mkey = mkey.expect("no key for encrypted file");
        encfile_read(&_contents[..], mkey)?
    } else {
        trace!("unencrypted");
        _contents
    };

    let ck0 = crypto_hash(&contents);
    debug!("opened {} got ck {}", p.display(), ck0);

    let td = TmpDir::new()?;
    let tp = td.as_ref().join("editing");
    File::create(&tp)?.write_all(&contents)?;
    contents.clear();
    debug!("wrote to tmpfile {}", tp.display());

    let ed = std::env::var("EDITOR")?;
    std::process::Command::new(ed)
        .arg(&tp)
        .stdin(process::Stdio::inherit())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit())
        .output()?;

    File::open(tp)?.read_to_end(&mut contents)?;
    let ck1 = crypto_hash(&contents);
    debug!("new ck {}", ck1);
    if ck0 == ck1 {
        info!("checksum unchanged");
        return Ok(());
    }

    info!("checksum changed, rewriting");
    let mut fout = File::create(p)?;
    if let Some(mkey) = mkey {
        info!("Writing encrypted {}", p.display());
        encfile_write(fout, mkey, contents)?
    } else {
        info!("Writing unencrypted {}", p.display());
        fout.write_all(&contents)?;
    }

    info!("Wrote {}", p.display());

    Ok(())
}

/// Performs a crypto action
fn wizard_crypto(act: CryptoAction, mkey: Option<&TheseusKey>) -> Result<()> {
    let Some(mkey) = mkey else {
        return Err(TheseusError::NoKey("".to_string()))
            .context("for {act:?}")?;
    };
    match act {
        CryptoAction::Decrypt { path } => Ok(encrypt_in_place(&path, mkey)?),
        CryptoAction::Encrypt { path } => Ok(decrypt_in_place(&path, mkey)?),
        CryptoAction::Keygen { path } => {
            Ok(theseus_keygen(&format!("file://{}", path.display()))?)
        }
        CryptoAction::Rekey { path, from, to } => {
            let from = TheseusKey::from_provider(from)?;
            let to = TheseusKey::from_provider(to)?;
            rekey_in_place(&path, &from, &to)?;
            Ok(())
        }
    }
}

/// Reads a plan from a directory and checks for errors
/// Does not check that the target _destinations_ are valid,
/// but does check that the plan is properly formed
fn validate_plan(dir: &Path) -> Result<Vec<FileTarget>, TheseusError> {
    plan_from_root(dir)
}

/// Replace `p` with `f p`.
/// If `r` is true, do this recursively
fn path_map(
    f: impl Fn(&str) -> anyhow::Result<String>,
    p: &Path,
    r: bool,
) -> anyhow::Result<()> {
    trace!(
        "{}path map {}",
        if r { "recursive " } else { "" },
        p.display(),
    );

    for e in WalkDir::new(p).contents_first(false) {
        let e = e?;
        let ne = f(e
            .path()
            .to_str()
            .unwrap_or_else(|| panic!("{} is not UTF-8", p.display())))?;

        trace!("rename {} to {ne}", e.path().display());
        std::fs::rename(e.path(), ne)?;
    }
    Ok(())
}

/// Replace `owner:group` in p with `own:grp`
fn pchown(own: &str, grp: &str, p: &str) -> anyhow::Result<String> {
    let mut ps = p.split(':');
    let nm = ps
        .next()
        .ok_or(TheseusError::MissingFilename(p.to_string()))?;
    let mut attr = Attributes::parse(ps);
    attr.own = Some(own.to_owned());
    attr.grp = Some(grp.to_owned());

    Ok(nm.to_owned() + ":" + &attr.to_string())
}

/// Replace `mode` in p with `mode`
fn pchmod(mode: Mode, p: &str) -> anyhow::Result<String> {
    let mut ps = p.split(':');
    let nm = ps
        .next()
        .ok_or(TheseusError::MissingFilename(p.to_string()))?;
    let mut attr = Attributes::parse(ps);
    attr.mode = Some(mode);

    Ok(nm.to_owned() + ":" + &attr.to_string())
}

fn find_golems(
    search_paths: impl Iterator<Item = String>,
) -> Result<HashMap<TheseusPlatform, PathBuf>> {
    // TODO: better
    let syspath = &std::env::var("PATH")?;

    let search_paths = search_paths
        .chain([
            "/var/lib/theseus/golems".to_owned(),
            "./data/golems".to_owned(),
        ])
        .chain(
            std::env::split_paths(&syspath)
                .map(|p| p.to_string_lossy().into_owned()),
        );
    let mut golems = HashMap::new();
    for sp in search_paths.filter(|p| Path::new(p).exists()) {
        debug!("Looking for golem in {sp}");
        for ent in std::fs::read_dir(sp)? {
            let ent = ent?;
            if ent.file_type()?.is_file() {
                if let Some(p) = is_golem(ent.path()) {
                    golems.insert(p, ent.path());
                }
            }
        }
    }
    Ok(golems)
}

fn copy_golem_to(
    host_user: &(impl AsRef<str>, impl AsRef<str>),
    gpath: &Path,
    rpath: &Path,
) -> Result<Output> {
    if !rpath.is_absolute() {
        bail!("{} must be an absolute path", rpath.display());
    }

    // Crates exist that don't require us to manually shell out to scp, but
    // they are extra dependencies, and RemoteGolem -ing already requires
    // interaction-free connection. This is ok for now
    let scpargs = [
        gpath.display().to_string(),
        format!(
            "{}@{}:{}",
            host_user.1.as_ref(),
            host_user.0.as_ref(),
            rpath.display()
        ),
    ];
    let mut cmd = std::process::Command::new("scp");
    cmd.args(scpargs)
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit());
    let out = cmd.output()?;
    trace!(
        "Ran {} {:?} with {}",
        cmd.get_program().to_string_lossy(),
        cmd.get_args(),
        String::from_utf8_lossy(&out.stdout)
    );
    Ok(out)
}

trait Golem: std::io::Read + std::io::Write {
    /// Instruct the golem to apply the currently loaded plan
    fn apply_plan(&mut self) -> anyhow::Result<()> {
        let rsp = GolemRequest::Apply.write(self)?;
        match rsp {
            Ok(()) => info!("plan applied successfully!"),
            Err(ge) => match ge {
                GolemError::BallExists => unreachable!(),
                GolemError::BallChecksum => unreachable!(),
                GolemError::ServerError(e) => {
                    error!("Golem internal error: {e}")
                }
                GolemError::DependencyError(e) => {
                    error!("Golem dependency error: {e}")
                }
                GolemError::PlanError(e) => error!("Golem plan error: {e}"),
                GolemError::InvalidRequest => error!("Transmission error!"),
            },
        }
        Ok(())
    }

    /// Send the golem a new Ball
    fn upload(&mut self, ball: Ball) -> anyhow::Result<()> {
        let (md, data) = ball.split();

        info!("send ballmd {}", md);

        let recv_err = GolemRequest::Receive(md)
            .write(self)
            .map_err(|e| TheseusError::WriteRequest(e.to_string()))?
            .inspect(|_| info!("ok to transmit"));
        match recv_err {
            Ok(_) => {
                trace!("Want to write {}", data.len());
                self.write_all(&data)
                    .map_err(|e| TheseusError::WriteBall(e.to_string()))?;
            }
            Err(GolemError::BallExists) => {
                info!("No need to transmit, ball exists");
                return Ok(());
            }
            Err(e) => return Err(e).context("sending receive request"),
        }

        Ok(Result::<(), GolemError>::read(self)??)
    }

    /// Kill the golem
    fn kill(self: Box<Self>) -> anyhow::Result<()>;
}

struct LocalGolem {
    stream: TcpStream,
    golem: std::process::Child,
}

impl LocalGolem {
    fn construct(
        port: u16,
        golem_paths: impl Iterator<Item = String>,
    ) -> Result<Self> {
        /* Panic if current platform not supported */
        let platform =
            TheseusPlatform::new(current_platform::CURRENT_PLATFORM).unwrap();
        debug!("Looking for golems for {platform}");
        let golems =
            find_golems(golem_paths).context("while finding golems")?;
        let golem_path =
            golems.get(&platform).ok_or(anyhow!("no golems found"))?;
        debug!("Found golem at {}", golem_path.display());

        info!("Copying golem to /tmp/thesesug");
        std::fs::copy(golem_path, Path::new("/tmp/theseusg"))
            .context("copying golem")?;
        debug!("Copied");

        info!("Starting golem",);
        let golem = std::process::Command::new("/tmp/theseusg")
            .args(["-vvvv"])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("while spawning golem")?;
        debug!("Started");

        info!("Connecting to golem");
        let mut stream = std::net::TcpListener::bind(("localhost", port))
            .context("bind to localhost:{port}")?
            .accept()
            .context("accept connection")?
            .0;
        debug!("Connected");

        info!("Testing golem communication");
        GolemRequest::Ping
            .write(&mut stream)
            .context("while pinging golem")?
            .context("in response to ping")?;
        debug!("Communication working");

        Ok(Self { stream, golem })
    }
}

impl std::io::Read for LocalGolem {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl std::io::Write for LocalGolem {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Golem for LocalGolem {
    fn kill(mut self: Box<Self>) -> anyhow::Result<()> {
        info!("Killing golem");
        GolemRequest::Kill
            .write(&mut self.stream)
            .context("while sending golem kill")?
            .unwrap_or_else(|e| error!("Golem refuses to die because: {}", e));
        debug!("Killed");

        self.golem.wait()?;
        // self.golem.kill()?;

        Ok(())
    }
}

pub fn over_ssh<I, S>(host: &str, user: &str, cmd: I) -> process::Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut sshcmd = process::Command::new("ssh");
    sshcmd.args([&format!("{user}@{host}")]);
    cmd.into_iter().for_each(|c| {
        sshcmd.arg(c);
    });
    sshcmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    sshcmd
}

struct RemoteGolem {
    fwd_handle: Child,
    golem_handle: Child,
    stream: TcpStream,
}

impl RemoteGolem {
    fn construct(
        host: &str,
        user: &str,
        port: u16,
        golem_paths: impl Iterator<Item = String>,
    ) -> Result<Self> {
        info!("Getting {host} platform");
        let platform = Self::get_remote_platform(host, user)
            .context("getting remote platform")?;
        info!("Platform is {platform}");

        debug!("Looking for golems for {platform}");
        let golems =
            find_golems(golem_paths).context("while finding golems")?;
        let golem_path =
            golems.get(&platform).ok_or(anyhow!("no golems found"))?;
        debug!("Found golem at {}", golem_path.display());

        info!("Forwarding remote port {port} to local port {port}");
        let fwd_handle = process::Command::new("ssh")
            .args([
                &format!("{user}@{host}"),
                "-N",
                &format!("-R{port}:localhost:{port}"),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("creating port forward")?;
        debug!("Forwarded");

        info!("Copying golem to {host}",);
        copy_golem_to(&(host, user), golem_path, Path::new("/tmp/theseusg"))
            .context("copying golem")?;

        over_ssh(host, user, ["chmod", "700", "/tmp/theseusg"])
            .spawn()
            .context("chmod golem")?
            .wait()
            .context("chmod golem")?;
        debug!("Copied");

        let listener = std::net::TcpListener::bind(("localhost", port))
            .context("bind to localhost:{port}")?;

        info!("Starting golem on {host}",);
        // In theory it would be nice to keep a handle to the golem. However,
        // we can't actually kill it properly. Instead, we can use our stream
        // to send it a 'Kill' request when we're finished
        let golem_handle = over_ssh(host, user, ["/tmp/theseusg", "-vvvv"])
            .spawn()
            .context("spawning golem")?;
        debug!("Started");

        info!("Waiting for golem to connect");
        let mut stream = listener.accept().context("accept connection")?.0;
        debug!("Connected");

        info!("Testing golem communication");
        GolemRequest::Ping
            .write(&mut stream)
            .context("while pinging golem")?
            .context("in response to ping")?;
        debug!("Communication working");

        Ok(Self {
            stream,
            fwd_handle,
            golem_handle,
        })
    }

    fn get_remote_platform(host: &str, user: &str) -> Result<TheseusPlatform> {
        let uname = ["uname", "-sm"];
        let outv = over_ssh(host, user, uname)
            .spawn()
            .context("spawn remote uname")?
            .wait_with_output()
            .context("remote uname output")?
            .stdout;
        let out = String::from_utf8_lossy(&outv);
        if out.contains("Linux x86_64") {
            Ok(TheseusPlatform::Amd64Linux)
        } else if out.contains("Linux aarch64") {
            Ok(TheseusPlatform::Arm64Linux)
        } else if out.contains("FreeBSD amd64") {
            Ok(TheseusPlatform::Amd64FreeBsd)
        } else if out.contains("FreeBSD arm64") {
            Ok(TheseusPlatform::Arm64FreeBsd)
        } else if out.contains("SunOS i86pc") {
            // TODO: Does this get confused with Oracle Solaris 11?
            // BIKESHED: did anyone ask?
            Ok(TheseusPlatform::Amd64Illumos)
        } else if out.contains("Darwin arm64") {
            Ok(TheseusPlatform::Arm64Darwin)
        } else {
            Err(anyhow!(TheseusError::Platform(out.to_string())))
        }
    }
}

impl std::io::Read for RemoteGolem {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}
impl std::io::Write for RemoteGolem {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Golem for RemoteGolem {
    fn kill(mut self: Box<Self>) -> anyhow::Result<()> {
        info!("Killing golem");
        GolemRequest::Kill
            .write(&mut self.stream)
            .context("while sending golem kill")?
            .unwrap_or_else(|e| error!("Golem refuses to die because: {}", e));
        debug!("Killed");

        info!("Closing port forward");
        let fwpid = nix::unistd::Pid::from_raw(self.fwd_handle.id() as i32);
        kill(fwpid, Signal::SIGTERM).context("SIGTERM to fwd ssh")?;
        self.fwd_handle.wait().context("while fwd ssh dies")?;
        debug!("Closed");

        info!("Closing golem handle");
        let gpid = nix::unistd::Pid::from_raw(self.golem_handle.id() as i32);
        kill(gpid, Signal::SIGTERM).context("SIGTERM to golem ssh")?;
        self.golem_handle.wait().context("while golem ssh dies")?;
        debug!("Closed");

        Ok(())
    }
}

fn construct_golem(
    addr: &str,
    user: &str,
    port: u16,
    golem_paths: impl Iterator<Item = String>,
) -> anyhow::Result<Box<dyn Golem>> {
    match addr {
        "localhost" | "127.0.0.1" => {
            Ok(Box::new(LocalGolem::construct(port, golem_paths)?))
        }
        _ => Ok(Box::new(RemoteGolem::construct(
            addr,
            user,
            port,
            golem_paths,
        )?)),
    }
}

fn try_main() -> anyhow::Result<()> {
    let args = WizardArgs::try_parse()?;

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
        .finish();
    tracing::subscriber::set_global_default(tracer)?;

    let mkey = if let Some(prov) = args.key_provider {
        let k = Some(TheseusKey::from_provider(&prov)?);
        trace!("provider {} had key", prov);
        k
    } else {
        trace!("no provider");
        None
    };

    match args.command {
        Some(Command::Validate { dir }) => {
            let plan = validate_plan(Path::new(&dir))?;
            println!("Plan {} is valid", &dir);
            println!("Contains");
            plan.iter().for_each(|it| println!("\t{}", it.identify()));
            println!("Depends on");
            plan.dependencies()
                .iter()
                .for_each(|dep| println!("\t{}", dep.identify()));
            Ok(())
        }

        Some(Command::Apply {
            address,
            username,
            port,
            dir,
        }) => {
            let mut golem = construct_golem(
                &address,
                &username,
                port,
                args.golem_paths.into_iter(),
            )?;

            let _plan_valid = validate_plan(&dir)?;
            info!("plan at {} is valid", dir.display());
            let ball = Ball::from_dir(&dir, mkey.as_ref())?;
            golem.upload(ball)?;
            info!("upload successful");
            golem.apply_plan()?;

            golem.kill()?;
            Ok(())
        }

        Some(Command::ConstructGolem {
            address,
            username,
            port,
        }) => {
            let golem = construct_golem(
                &address,
                &username,
                port,
                args.golem_paths.into_iter(),
            )?;

            golem.kill()?;
            Ok(())
        }
        Some(Command::ListGolems {}) => {
            println!("Found golems for");
            find_golems(args.golem_paths.into_iter())?
                .keys()
                .for_each(|p| println!("\t{p}"));
            Ok(())
        }
        Some(Command::Chown {
            recurse,
            usergroup,
            path,
        }) => {
            let ug: Vec<_> = usergroup.split(':').take(2).collect();
            let (user, group) = (
                ug.first().expect("Missing user").to_string(),
                ug.get(1).expect("Missing group").to_string(),
            );

            path_map(|p| pchown(&user, &group, p), &path, recurse)
        }
        Some(Command::Chmod {
            recurse,
            mode,
            path,
        }) => {
            let mode = string_to_mode(&mode)?;

            path_map(|p| pchmod(mode, p), &path, recurse)
        }
        Some(Command::Open { file }) => wizard_open(&file, mkey.as_ref()),
        Some(Command::Crypto { action }) => {
            wizard_crypto(action, mkey.as_ref())
        }
        None => WizardArgs::command().print_help().context("no args"),
    }
}

#[instrument]
fn main() {
    match try_main() {
        Ok(_) => {}
        Err(e) => eprintln!("{e:?}"),
    }
}
