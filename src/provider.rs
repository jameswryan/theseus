// Copyright James Ryan

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt::Display;
use std::process::{Command, Stdio};

use crate::crypto::*;
use crate::error::*;

#[derive(Debug)]
enum TheseusProviderProtocol {
    File,
    Shell,
}

impl Display for TheseusProviderProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TheseusProviderProtocol::File => "file",
                TheseusProviderProtocol::Shell => "shell",
            }
        )
    }
}

fn parse_protocol(
    s: &str,
) -> Result<(TheseusProviderProtocol, &str), TheseusError> {
    let mut sp = s.split("://");
    let prot = sp.next().expect("at least one &str from a split");
    let uri = sp.next().ok_or(TheseusError::NoUri(s.to_string()))?;

    match prot {
        "file" => Ok((TheseusProviderProtocol::File, uri)),
        "shell" => Ok((TheseusProviderProtocol::Shell, uri)),
        _ => Err(TheseusError::UnknownProtocol(uri.to_string())),
    }
}

fn file_getkey(uri: &str) -> std::io::Result<Vec<u8>> {
    std::path::absolute(uri).and_then(std::fs::read)
}

fn file_keygen(uri: &str) -> Result<(), TheseusError> {
    let key = TheseusKey::from_entropy()?.to_hex();
    Ok(std::fs::write(uri, key)?)
}

fn shell_getkey(uri: &str) -> std::io::Result<Vec<u8>> {
    let cmd: Vec<_> =
        uri.split_whitespace().filter(|ss| !ss.is_empty()).collect();
    Ok(Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::piped())
        .output()?
        .stdout)
}

/// Get a key from `url`.
///
/// `urls` have the form `<protocol><uri>`, where `<protocol>` is one of
/// `file://`, `shell://`
///
/// The form of a `uri` depends on the protocol.
/// For the `file://` protocol, the `uri` is a path.
/// For the `shell://` protocol, the `uri` is a shell command.
pub fn theseus_getkey(url: &str) -> Result<Vec<u8>, TheseusError> {
    match parse_protocol(url)? {
        (TheseusProviderProtocol::File, rst) => Ok(file_getkey(rst)?),
        (TheseusProviderProtocol::Shell, rst) => Ok(shell_getkey(rst)?),
    }
}

/// Generate a new key at `url`
///
/// Some protocols do not support key generation, in this case the function
/// will return `Err(TheseusError::KeyGen)`
///
/// Otherwise, a key with security strength of 128 bits will be generated and
/// placed at `url`
pub fn theseus_keygen(url: &str) -> Result<(), TheseusError> {
    match parse_protocol(url)? {
        (TheseusProviderProtocol::File, rst) => file_keygen(rst),
        (TheseusProviderProtocol::Shell, _) => Err(TheseusError::NoKeyGen(
            TheseusProviderProtocol::Shell.to_string(),
        )),
    }
}
