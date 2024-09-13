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

use log::error;
use postcard::{from_bytes, to_stdvec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ball::*;
use crate::error::*;
use crate::lvrw::*;

pub trait DaemonResponse {
    /// Read a response from r
    fn read(r: &mut impl std::io::Read) -> Result<Self, TheseusError>
    where
        Self: std::marker::Sized;

    /// Write a response to w
    fn write(&self, w: &mut impl std::io::Write) -> Result<(), TheseusError>;

    /// Write a response to w
    /// If an error occurs, log but do not return it
    fn write_log(&self, w: &mut impl std::io::Write);
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Error)]
pub enum DaemonError {
    #[error("already have this ball")]
    BallExists,
    #[error("ball invalid checksum")]
    BallChecksum,

    #[error("server error {0}")]
    ServerError(String),

    #[error("invalid request")]
    InvalidRequest,
}

impl DaemonResponse for Result<(), DaemonError> {
    /// Read a response from r
    /// Log if error encountered
    fn read(r: &mut impl std::io::Read) -> Result<Self, TheseusError> {
        let buf = lvr(r).map_err(|e| TheseusError::ReadResponse(e.to_string()))?;
        from_bytes(&buf).map_err(|e| TheseusError::ReadResponse(e.to_string()))
    }

    /// Write a response to w
    fn write(&self, w: &mut impl std::io::Write) -> Result<(), TheseusError> {
        let to_w = to_stdvec(self).map_err(|e| TheseusError::WriteResponse(e.to_string()))?;
        lvw(w, &to_w).map_err(|e| TheseusError::WriteResponse(e.to_string()))
    }

    /// Write a response to w
    /// If an error occurs, log but do not return it
    fn write_log(&self, w: &mut impl std::io::Write) {
        let _ = self.write(w).inspect_err(|e| error!("Write response {e}"));
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TheseusRequest {
    /// Receive a new set of files
    /// Completely replaces the old set of files
    Receive(BallMd),
    /// Apply a new set of files
    Apply,
}

impl TheseusRequest {
    /// Read a request from r
    /// If invalid, log an error and send over w
    pub fn read<RW: std::io::Read + std::io::Write>(rw: &mut RW) -> Result<Self, TheseusError> {
        let buf = lvr(rw).map_err(|e| TheseusError::ReadRequest(e.to_string()))?;
        from_bytes(&buf).map_err(|e| {
            match Err(DaemonError::InvalidRequest).write(rw) {
                Ok(_) => {}
                Err(e) => return TheseusError::WriteResponse(e.to_string()),
            };
            TheseusError::ReadRequest(e.to_string())
        })
    }

    /// Write a request to w
    /// If a valid `TheseusResponse` is received, returns `Ok(.)`
    /// Otherwise, returns `Err(.)`
    pub fn write<RW: std::io::Read + std::io::Write>(
        &self,
        rw: &mut RW,
    ) -> Result<Result<(), DaemonError>, TheseusError> {
        // let mut ser = Serializer::new(w);
        let to_w = to_stdvec(self).map_err(|e| TheseusError::WriteRequest(e.to_string()))?;
        lvw(rw, &to_w).map_err(|e| TheseusError::WriteRequest(e.to_string()))?;

        DaemonResponse::read(rw)
    }
}
