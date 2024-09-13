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

pub mod ball;
pub mod error;
pub mod lvrw;
pub mod msg;
pub mod plan;
pub mod target;

pub const THESEUSD_DEFAULT_ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::LOCALHOST;
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
