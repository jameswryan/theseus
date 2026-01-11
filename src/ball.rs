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

use std::ffi::OsString;
use std::io::Read;
use std::{fmt::Display, io::Write, path::Path};

use serde::{Deserialize, Serialize};

use crate::crypto::*;
use crate::error::TheseusError;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
/// Metadata (size, checksum) about a ball of files
pub struct BallMd {
    pub size: u64,
    pub checksum: TheseusHash,
}

impl BallMd {
    pub fn new(ball: &[u8]) -> Self {
        let size = ball.len() as u64;
        let checksum = crypto_hash(ball);
        Self { size, checksum }
    }
}

impl Display for BallMd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.checksum)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
/// A file entry in a ball
struct BallEntry {
    /// File parent
    parent: OsString,
    /// File basename
    basename: OsString,
    /// File contents
    contents: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct Ball {
    /// Ball Metadata
    md: BallMd,
    /// Ball entries, stored compressed
    data: Vec<u8>,
}

impl Ball {
    /// Create a new ball from
    pub fn from_raw_parts(md: BallMd, data: Vec<u8>) -> Self {
        Self { md, data }
    }

    /// Pack a directory into a ball
    ///
    /// If some files are encrypted, attempt to decrypt them with `mkey`. If
    /// that fails, an error is returned.
    pub fn from_dir(
        dir: &Path,
        mkey: Option<&TheseusKey>,
    ) -> Result<Self, TheseusError> {
        let ze = snap::write::FrameEncoder::new(Vec::new());
        let ze = ball(ze, dir, mkey)?;
        let data = ze
            .into_inner()
            .map_err(|e| TheseusError::Compression(e.to_string()))?;
        let md = BallMd::new(&data);
        Ok(Self { md, data })
    }

    /// Unpack a ball into `dir`
    pub fn to_dir(self, dir: &Path) -> Result<(), TheseusError> {
        let mut entries_bytes = Vec::new();
        snap::read::FrameDecoder::new(&self.data[..])
            .read_to_end(&mut entries_bytes)?;
        let entries: Vec<BallEntry> = postcard::from_bytes(&entries_bytes)?;
        for ent in entries {
            std::fs::create_dir_all(dir.join(&ent.parent))?;
            std::fs::write(
                dir.join(ent.parent).join(ent.basename),
                ent.contents,
            )?;
        }
        Ok(())
    }
    /// Split the ball into metadata and compressed entries
    pub fn split(self) -> (BallMd, Vec<u8>) {
        (self.md, self.data)
    }

    /// Get the length (in bytes) of the compressed entries
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Read files from `dir` and write to `baller`.
///
/// If a file is encrypted, attampt to decrypt with `mkey`.
fn ball<W: Write>(
    baller: W,
    dir: &Path,
    mkey: Option<&TheseusKey>,
) -> Result<W, TheseusError> {
    let mut entries = Vec::new();

    for dirent in walkdir::WalkDir::new(dir) {
        let ent = dirent.map_err(|e| TheseusError::DirDir(e.to_string()))?;
        if ent.path().is_dir() {
            continue;
        }
        let _contents = std::fs::read(ent.path())?;
        let contents = if is_encrypted(&_contents[..], mkey)? {
            let mkey = mkey.expect("no key provided");
            encfile_read(&_contents[..], mkey)?
        } else {
            _contents
        };
        let parent = ent
            .path()
            .parent()
            .expect("can't ball root")
            .strip_prefix(dir)
            .expect("dir is prefix")
            .into();
        let basename =
            ent.path().file_name().expect("can't ball directory").into();
        entries.push(BallEntry {
            parent,
            basename,
            contents,
        });
    }

    let baller = postcard::to_io(&entries, baller)?;
    Ok(baller)
}
