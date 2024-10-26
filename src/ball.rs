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

use std::{fmt::Display, io::Write, path::Path};

use serde::{Deserialize, Serialize};

use crate::crypto::*;
use crate::error::TheseusError;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
pub struct BallMd {
    pub size: u64,
    pub checksum: TheseusChecksum,
}

impl BallMd {
    pub fn new(ball: &[u8]) -> Self {
        let size = ball.len() as u64;
        let checksum = crypto_checksum(ball);
        Self { size, checksum }
    }
}

impl Display for BallMd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.checksum)
    }
}

/// Ball up directory at `dir`, with compression level `level`
/// Returns a litany of errors if anything fails
pub fn dir_to_ball(dir: &Path) -> Result<Vec<u8>, TheseusError> {
    let mut ball = Vec::new();
    let ze = snap::write::FrameEncoder::new(&mut ball);
    let mut baller = tar::Builder::new(ze);
    baller.mode(tar::HeaderMode::Deterministic);
    baller
        .append_dir_all(".", dir)
        .map_err(|e| TheseusError::Archive(e.to_string()))?;
    baller
        .into_inner()
        .map_err(|e| TheseusError::Archive(e.to_string()))?
        .flush()
        .map_err(|e| TheseusError::Compression(e.to_string()))?;
    Ok(ball)
}

/// Unball `ball` into dir
/// Returns a litany of errors if anything fails
pub fn ball_to_dir(dir: &Path, ball: &[u8]) -> Result<(), TheseusError> {
    let zd = snap::read::FrameDecoder::new(ball);
    let mut unballer = tar::Archive::new(zd);
    unballer
        .unpack(dir)
        .map_err(|e| TheseusError::Archive(e.to_string()))?;

    Ok(())
}
