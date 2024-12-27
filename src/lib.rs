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

use std::{fmt::Display, str::FromStr};

pub mod ball;
pub mod crypto;
pub mod error;
pub mod lvrw;
pub mod msg;
pub mod plan;
pub mod provider;
pub mod target;

pub const THESEUSD_DEFAULT_ADDR: std::net::Ipv4Addr =
    std::net::Ipv4Addr::LOCALHOST;
pub const THESEUSD_DEFAULT_PORT: u16 = 6666;
pub const THESEUSD_DEFAULT_WORKDIR: &str = "/var/lib/theseus";

pub const fn theseusd_default_port() -> u16 {
    THESEUSD_DEFAULT_PORT
}

pub fn theseusd_default_addr() -> std::net::IpAddr {
    std::net::IpAddr::V4(THESEUSD_DEFAULT_ADDR)
}

pub fn theseusd_default_workdir() -> std::path::PathBuf {
    std::path::Path::new(THESEUSD_DEFAULT_WORKDIR).to_owned()
}

const THESEUS_PLATFORM_AMD64LINUX: &str = "x86_64-unknown-linux-musl";
const THESEUS_PLATFORM_ARM64LINUX: &str = "aarch64-unknown-linux-musl";
const THESEUS_PLATFORM_AMD64FREEBSD: &str = "x86_64-unknown-freebsd";
const THESEUS_PLATFORM_ARM64FREEBSD: &str = "aarch64-unknown-freebsd";
const THESEUS_PLATFORM_AMD64ILLUMOS: &str = "x86_64-unknown-illumos";
const THESEUS_PLATFORM_ARM64DARWIN: &str = "aarch64-apple-darwin";

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum TheseusPlatform {
    Amd64Linux,
    Arm64Linux,
    Amd64FreeBsd,
    Arm64FreeBsd,
    Amd64Illumos,
    Arm64Darwin,
}

impl TheseusPlatform {
    pub fn new(s: &str) -> Option<Self> {
        match s {
            THESEUS_PLATFORM_AMD64LINUX => Some(Self::Amd64Linux),
            THESEUS_PLATFORM_ARM64LINUX => Some(Self::Arm64Linux),
            THESEUS_PLATFORM_AMD64FREEBSD => Some(Self::Amd64FreeBsd),
            THESEUS_PLATFORM_ARM64FREEBSD => Some(Self::Arm64FreeBsd),
            THESEUS_PLATFORM_AMD64ILLUMOS => Some(Self::Amd64Illumos),
            THESEUS_PLATFORM_ARM64DARWIN => Some(Self::Arm64Darwin),
            _ => None,
        }
    }

    pub fn current() -> Self {
        let c = current_platform::CURRENT_PLATFORM;
        Self::new(c).unwrap_or_else(|| panic!("{c} not supported"))
    }
}
impl FromStr for TheseusPlatform {
    type Err = error::TheseusError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            THESEUS_PLATFORM_AMD64LINUX => Ok(Self::Amd64Linux),
            THESEUS_PLATFORM_ARM64LINUX => Ok(Self::Arm64Linux),
            THESEUS_PLATFORM_AMD64FREEBSD => Ok(Self::Amd64FreeBsd),
            THESEUS_PLATFORM_ARM64FREEBSD => Ok(Self::Arm64FreeBsd),
            THESEUS_PLATFORM_AMD64ILLUMOS => Ok(Self::Amd64Illumos),
            THESEUS_PLATFORM_ARM64DARWIN => Ok(Self::Arm64Darwin),
            s => Err(Self::Err::Platform(s.to_string())),
        }
    }
}

impl Display for TheseusPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TheseusPlatform::Amd64Linux => THESEUS_PLATFORM_AMD64LINUX,
                TheseusPlatform::Arm64Linux => THESEUS_PLATFORM_ARM64LINUX,
                TheseusPlatform::Amd64FreeBsd => THESEUS_PLATFORM_AMD64FREEBSD,
                TheseusPlatform::Arm64FreeBsd => THESEUS_PLATFORM_ARM64FREEBSD,
                TheseusPlatform::Amd64Illumos => THESEUS_PLATFORM_AMD64ILLUMOS,
                TheseusPlatform::Arm64Darwin => THESEUS_PLATFORM_ARM64DARWIN,
            }
        )
    }
}

/// Check that a string is a well-formed name for a golem binary
///
/// A well-formed name has the format
///     `theseusg:<theseus-platform-triple>`
/// where `<theseus-platform-triple>` is a rust target triple identifying a
/// platform supported by theseus
///
/// If the name is well-formed, returns the `TheseusPlatform` supported by
/// a golem with that name
pub fn is_golem<S: AsRef<str>>(s: S) -> Option<TheseusPlatform> {
    let mut sp = s.as_ref().split(':');
    /*`theseusg:`*/
    sp.next().and_then(|n| (n == "theseusg").then_some(()))?;
    /*:<theseus-platform-triple>*/
    let p = sp.next().and_then(TheseusPlatform::new)?;
    Some(p)
}
