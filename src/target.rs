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

use std::fmt::Display;
use std::fs::copy;
use std::path::{self, Path, PathBuf};

use crate::error::*;
use crate::plan::*;

use log::{error, trace};
use nix::unistd::{Gid, Uid};
use nix::{
    sys::stat::{fchmodat, FchmodatFlags, Mode},
    unistd::{chown, Group, User},
};
use serde::Serialize;

fn to_rwx(p: u32) -> String {
    match p {
        0b000 => "---",
        0b001 => "-wx",
        0b010 => "-wx",
        0b011 => "--x",
        0b100 => "r--",
        0b101 => "r-x",
        0b110 => "rw-",
        0b111 => "rwx",
        _ => unreachable!(),
    }
    .to_string()
}

fn mode_to_string(m: Mode) -> String {
    let m = m.bits();
    let o = (m >> 6) & 7;
    let g = (m >> 3) & 7;
    let w = m & 7;

    format!(
        "{}{}{}",
        to_rwx(o as u32),
        to_rwx(g as u32),
        to_rwx(w as u32)
    )
}

fn string_to_mode(s: &str) -> Result<Mode, TheseusError> {
    let bits = nix::libc::mode_t::from_str_radix(s, 8)
        .map_err(|e| TheseusError::InvalidPrm(e.to_string()))?;
    Ok(Mode::from_bits_truncate(bits))
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileTarget {
    src: PathBuf,
    dst: PathBuf,
    own: String,
    grp: String,
    mode: Mode,
    saved: bool,
}

impl Display for FileTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DirTarget{{ {}, {}, {}, {}, {}}}",
            self.src.display(),
            self.dst.display(),
            self.own,
            self.grp,
            mode_to_string(self.mode),
        )
    }
}

impl Serialize for FileTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!(
            "{}:{}:{}:{}",
            self.dst.display(),
            self.own,
            self.grp,
            mode_to_string(self.mode),
        ))
    }
}

/// If `str` is a `u32`, return the associated `u32`
fn num_if(s: &str, radix: u32) -> Option<u32> {
    u32::from_str_radix(s, radix).ok()
}

impl FileTarget {
    /// Parse a DirTarget from it's serialized form
    /// A serialized FileTarget has the following structure:
    /// `/src/path/dst_path:own:grp:prm`
    /// The src of the FT is the path to the serialized FT
    /// The dst of the FT is the name of the serialized FT
    /// The own of the FT is the string after the first colon
    /// The grp of the FT is the string after the second colon
    /// The prm of the FT is the octal string after the third colon
    pub fn parse(src: &Path, s: &str) -> Result<Self, TheseusError> {
        let src = path::absolute(PathBuf::from(src))
            .map_err(|e| TheseusError::Absolute(src.display().to_string(), e.to_string()))?;
        let mut rst = s.split(':');
        let dst = rst
            .next()
            .ok_or(TheseusError::MissingDst(s.to_string()))
            .map(|t| PathBuf::from(t.replace("_", "/")))?;
        let own = rst
            .next()
            .ok_or(TheseusError::MissingOwn(s.to_string()))?
            .to_string();
        let grp = rst
            .next()
            .ok_or(TheseusError::MissingGid(s.to_string()))?
            .to_string();
        let mode = rst
            .next()
            .ok_or(TheseusError::MissingPrm(s.to_string()))
            .map(string_to_mode)??;
        trace!("read target {}", src.display());
        Ok(Self {
            src,
            dst,
            own,
            grp,
            mode,
            saved: false,
        })
    }

    /// Get uid/gid of DirTarget
    /// If stored user/group are uid/gid, then return them. Otherwise, find the
    /// uid/gid associated with the user/group
    fn ids(&self) -> Result<(Uid, Gid), TheseusError> {
        if let (Some(uid), Some(gid)) = (num_if(&self.own, 10), num_if(&self.grp, 10)) {
            Ok((uid.into(), gid.into()))
        } else {
            let uid = User::from_name(&self.own)
                .map_err(|e| TheseusError::GetUser(e.to_string()))?
                .ok_or(TheseusError::MissingUser(self.own.to_owned()))?
                .uid;
            let gid = Group::from_name(&self.grp)
                .map_err(|e| TheseusError::GetGrp(e.to_string()))?
                .ok_or(TheseusError::MissingGrp(self.grp.to_owned()))?
                .gid;
            Ok((uid, gid))
        }
    }
}

#[inline]
fn compute_save(p: &Path, prefix: &Path) -> Result<Option<FileTarget>, TheseusError> {
    if !p.exists() {
        return Ok(None);
    }
    let st = nix::sys::stat::stat(p)
        .map_err(|e| TheseusError::Stat(p.display().to_string(), e.to_string()))?;
    let dst = path::absolute(p)
        .map_err(|e| TheseusError::Absolute(p.display().to_string(), e.to_string()))?;
    let own = User::from_uid(st.st_uid.into())
        .map_err(|e| TheseusError::GetUser(e.to_string()))?
        .map_or_else(|| st.st_uid.to_string(), |usr| usr.name);
    let grp = Group::from_gid(st.st_gid.into())
        .map_err(|e| TheseusError::GetGrp(e.to_string()))?
        .map_or_else(|| st.st_gid.to_string(), |grp| grp.name);
    let mode = Mode::from_bits_truncate(st.st_mode);

    let src = prefix.join(dst.display().to_string().replace("/", "_"));
    Ok(Some(FileTarget {
        src,
        dst,
        own,
        grp,
        mode,
        saved: true,
    }))
}

impl PlanItem for FileTarget {
    fn execute(self, save: &Path) -> Option<Self> {
        trace!("execute {}", self.src.display());
        let (uid, gid) = self.ids().map_err(|e| error!("{e}")).ok()?;

        let save = compute_save(&self.dst, save)
            .map_err(|e| error!("{e}"))
            .ok()?;
        if let Some(save) = save.as_ref() {
            /* Unwrap safe here */
            copy(&self.dst, &save.src).map_err(|e| error!("{e}")).ok()?;
        }

        copy(&self.src, &self.dst).map_err(|e| error!("{e}")).ok()?;

        fchmodat(None, &self.src, self.mode, FchmodatFlags::FollowSymlink)
            .map_err(|e| error!("{e}"))
            .ok()?;

        chown(&self.src, Some(uid), Some(gid))
            .map_err(|e| error!("{e}"))
            .ok()?;

        save.or(Some(self))
    }

    fn unwind(&self) {
        /* Remove emplaced file */
        nix::unistd::unlink(&self.dst)
            .unwrap_or_else(|_| panic!("Can remove written {}", self.src.display()));

        /* Only need to restore if src was saved */
        if self.saved {
            copy(&self.src, &self.dst).unwrap_or_else(|e| {
                panic!(
                    "can copy {} to {}: {}",
                    self.dst.display(),
                    self.src.display(),
                    e
                )
            });
        }
    }

    fn identify(&self) -> String {
        self.dst.display().to_string()
    }
}

/// Read a theseus plan from a path
/// The `dir` argument should be
pub fn plan_from_dir(dir: &Path) -> Result<Vec<FileTarget>, TheseusError> {
    if !dir.is_dir() {
        return Err(TheseusError::NotDir(dir.to_string_lossy().to_string()));
    }
    let fts = std::fs::read_dir(dir)
        .map_err(|e| TheseusError::DirRead(e.kind()))?
        .map(|entry| {
            let entry = entry.map_err(|e| TheseusError::DirEntry(e.kind()))?;
            // Unwrap is safe since p was a directory entry
            if entry.file_type().unwrap().is_dir() {
                return Err(TheseusError::DirDir(
                    entry.path().to_string_lossy().to_string(),
                ));
            }
            let src_path = entry
                .path()
                .canonicalize()
                .map_err(|e| TheseusError::Canonicalize(e.kind()))?;
            let f_name = entry
                .file_name()
                .into_string()
                .map_err(|_| TheseusError::NotUtf8(entry.path().to_string_lossy().to_string()))?;
            FileTarget::parse(&src_path, &f_name)
        })
        .collect::<Result<Vec<FileTarget>, TheseusError>>()?;

    Ok(fts)
}
