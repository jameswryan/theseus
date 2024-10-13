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

use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use crate::ball::*;
use crate::error::*;
use crate::lvrw::*;

pub trait GolemResponse {
    /// Read a response from r
    fn read<R: std::io::Read + ?Sized>(r: &mut R) -> Result<Self, TheseusError>
    where
        Self: std::marker::Sized;

    /// Write a response to w
    fn write<W: std::io::Write + ?Sized>(&self, w: &mut W) -> Result<(), TheseusError>;

    /// Write a response to w
    /// If an error occurs, log but do not return it
    fn write_log(&self, w: &mut impl std::io::Write);
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Error)]
pub enum GolemError {
    #[error("already have this ball")]
    BallExists,
    #[error("ball invalid checksum")]
    BallChecksum,

    #[error("server error {0}")]
    ServerError(String),

    #[error("dependency {0}")]
    DependencyError(String),

    #[error("dependency {0}")]
    PlanError(String),

    #[error("invalid request")]
    InvalidRequest,
}

impl GolemResponse for Result<(), GolemError> {
    /// Read a response from r
    /// Log if error encountered
    fn read<R: std::io::Read + ?Sized>(r: &mut R) -> Result<Self, TheseusError> {
        let buf = lvr(r).map_err(|e| TheseusError::ReadResponse(e.to_string()))?;
        from_bytes(&buf).map_err(|e| TheseusError::ReadResponse(e.to_string()))
    }

    /// Write a response to w
    fn write<W: std::io::Write + ?Sized>(&self, w: &mut W) -> Result<(), TheseusError> {
        let to_w = to_stdvec(self)?;
        Ok(lvw(w, &to_w)?)
    }

    /// Write a response to w
    /// If an error occurs, log but do not return it
    fn write_log(&self, w: &mut impl std::io::Write) {
        let _ = self.write(w).inspect_err(|e| error!("Write response {e}"));
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GolemRequest {
    /// Receive a new set of files
    /// Completely replaces the old set of files
    Receive(BallMd),
    /// Apply a new set of files
    Apply,

    /// Kill the golem
    Kill,

    /// Ping the golem to ensure connectivity
    Ping,
}

impl GolemRequest {
    /// Read a request from r
    /// If invalid, log an error and send over w
    pub fn read<RW: std::io::Read + std::io::Write + ?Sized>(
        rw: &mut RW,
    ) -> Result<Self, TheseusError> {
        let buf = lvr(rw).map_err(|e| TheseusError::ReadRequest(e.to_string()))?;
        from_bytes(&buf).map_err(|e| {
            match Err(GolemError::InvalidRequest).write(rw) {
                Ok(_) => {}
                Err(e) => return TheseusError::WriteResponse(format!("{e:#}")),
            };
            TheseusError::ReadRequest(format!("{e:#}"))
        })
    }

    /// Write a request to w
    /// If a valid `TheseusResponse` is received, returns `Ok(.)`
    /// Otherwise, returns `Err(.)`
    pub fn write<RW: std::io::Read + std::io::Write + ?Sized>(
        &self,
        rw: &mut RW,
    ) -> Result<Result<(), GolemError>, TheseusError> {
        // let mut ser = Serializer::new(w);
        let to_w = to_stdvec(self).map_err(|e| TheseusError::WriteRequest(e.to_string()))?;
        lvw(rw, &to_w).map_err(|e| TheseusError::WriteRequest(e.to_string()))?;

        GolemResponse::read(rw)
    }
}
