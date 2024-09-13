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

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TheseusError {
    #[error("stat {0} {1}")]
    Stat(String, String),
    #[error("cannot resolve {0} since {1}")]
    Absolute(String, String),
    #[error("missing uid in {0}")]
    MissingUid(String),
    #[error("invalid uid {0}")]
    InvalidUid(String),
    #[error("missing dst in {0}")]
    MissingDst(String),
    #[error("missing own in {0}")]
    MissingOwn(String),
    #[error("missing gid in {0}")]
    MissingGid(String),
    #[error("Get group {0}")]
    GetGrp(String),
    #[error("missing group {0}")]
    MissingGrp(String),
    #[error("invalid gid {0}")]
    InvalidGid(String),
    #[error("missing prm {0}")]
    MissingPrm(String),
    #[error("invalid prm {0}")]
    InvalidPrm(String),
    #[error("missing user {0}")]
    MissingUser(String),
    #[error("get user {0}")]
    GetUser(String),
    #[error("missing host in {0}")]
    MissingHost(String),

    #[error("invalid permission string length in {0}")]
    PermLen(String),
    #[error("invalid owner permissions {0}")]
    PermOwn(char),
    #[error("invalid group permissions {0}")]
    PermGrp(char),
    #[error("invalid world permissions {0}")]
    PermWld(char),

    #[error("not a directory {0}")]
    NotDir(String),
    #[error("not utf8 {0}")]
    NotUtf8(String),

    #[error("directory read {0}")]
    DirRead(io::ErrorKind),
    #[error("directory entry {0}")]
    DirEntry(io::ErrorKind),
    #[error("unexpected directory {0}")]
    DirDir(String),
    #[error("canonicalization {0}")]
    Canonicalize(io::ErrorKind),

    #[error("write request {0}")]
    WriteRequest(String),
    #[error("read request {0}")]
    ReadRequest(String),

    #[error("write response {0}")]
    WriteResponse(String),
    #[error("read response {0}")]
    ReadResponse(String),

    #[error("write ball {0}")]
    WriteBall(String),

    #[error("socket binding {0}")]
    Bind(io::ErrorKind),
    #[error("fatal server {0}")]
    Server(String),

    #[error("compression {0}")]
    Compression(String),
    #[error("archive {0}")]
    Archive(String),
}
