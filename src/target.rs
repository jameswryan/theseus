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
#![allow(refining_impl_trait)]

use std::fmt::Display;
use std::fs::copy;
use std::path::{self, Path, PathBuf};

use crate::error::*;
use crate::plan::*;

use nix::NixPath;
use nix::{
    sys::stat::{fchmodat, stat, FchmodatFlags, Mode},
    unistd::{chown, getgid, getuid, Gid, Group, Uid, User},
};
use tracing::{debug, error, trace};
use walkdir::WalkDir;

fn mode_to_string(m: Mode) -> String {
    let m = m.bits();
    let o = (m >> 6) & 7;
    let g = (m >> 3) & 7;
    let w = m & 7;

    format!("{o:o}{g:o}{w:o}",)
}

pub fn string_to_mode(s: &str) -> Result<Mode, TheseusError> {
    let bits = nix::libc::mode_t::from_str_radix(s, 8)
        .map_err(|e| TheseusError::InvalidPrm(e.to_string()))?;
    Ok(Mode::from_bits_truncate(bits))
}

/// Attributes are attributes of a filesystem entry
/// They may be unspecified, and so are optional
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Attributes {
    /// The owner
    /// May be a uid or the name of a user
    pub own: Option<String>,
    /// The group
    /// May be a gid or the name of a group
    pub grp: Option<String>,
    /// The mode
    /// Must be in `rwxrwxrwx` format
    pub mode: Option<Mode>,
}

impl Attributes {
    /// Convert an `Iterator<Item = String>` to an `Attributes`
    /// If any of `own`, `grp`, or `mode` are `*`, they are treated as
    /// unspecified
    pub fn parse<'a, S: Iterator<Item = &'a str> + std::fmt::Debug>(mut s: S) -> Self {
        let own = s.next().and_then(Self::from_star);
        let grp = s.next().and_then(Self::from_star);
        let mode = s.next().and_then(|m| string_to_mode(m).ok());

        Self { own, grp, mode }
    }

    /// Get the `Attributes` of a path
    pub fn from_path(p: &Path) -> Result<Self, TheseusError> {
        let st = stat(p)
            .map_err(|e| TheseusError::Stat(e.to_string(), p.to_string_lossy().into_owned()))?;

        Ok(Self {
            own: Some(st.st_uid.to_string()),
            grp: Some(st.st_gid.to_string()),
            mode: Some(Mode::from_bits_truncate(st.st_mode)),
        })
    }

    /// Create an `Attributes` with all attributes unspecified
    pub fn unspecified() -> Self {
        Self {
            own: None,
            grp: None,
            mode: None,
        }
    }

    fn from_star(s: &str) -> Option<String> {
        match s == "*" {
            true => None,
            false => Some(s.to_owned()),
        }
    }

    /// Returns the uid of the user in the attribute
    /// If a numeric uid is stored, return it.
    /// If the system has no user with the stored name, return TheseusError::MissingUser
    /// If no user/uid is stored, return the current user
    pub fn get_uid(&self) -> Result<Uid, TheseusError> {
        if self.own.is_none() {
            return Ok(getuid());
        }
        let own = self.own.as_ref().unwrap();
        match num_if(own, 10) {
            /* A uid */
            Some(uid) => Ok(Uid::from_raw(uid)),
            /* A username */
            None => Ok(User::from_name(own)
                .map_err(|e| TheseusError::GetUser(e.to_string()))?
                .ok_or(TheseusError::MissingUser(own.to_owned()))?
                .uid),
        }
    }

    /// Returns the gid of the group in the attribute
    /// If a numeric gid is stored, return it.
    /// If the system has no group with the stored name, return TheseusError::MissingGroup
    /// If no group;gid is stored, return the current group
    pub fn get_gid(&self) -> Result<Gid, TheseusError> {
        if self.grp.is_none() {
            return Ok(getgid());
        }
        let grp = self.grp.as_ref().unwrap();
        match num_if(grp, 10) {
            /* A gid */
            Some(uid) => Ok(Gid::from_raw(uid)),
            /* A group name */
            None => Ok(Group::from_name(grp)
                .map_err(|e| TheseusError::GetGrp(e.to_string()))?
                .ok_or(TheseusError::MissingGrp(grp.to_owned()))?
                .gid),
        }
    }

    /// Returns the mode in the attribute
    /// If no mode is specified, returns `0o600` as the mode
    pub fn get_mode(&self) -> Mode {
        match self.mode {
            Some(m) => m,
            None => Mode::from_bits_truncate(0o600),
        }
    }
}

impl Display for Attributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = match self.mode {
            Some(m) => mode_to_string(m),
            None => "*".into(),
        };
        write!(
            f,
            "{}:{}:{}",
            self.own.as_ref().map_or("*", |o| o),
            self.grp.as_ref().map_or("*", |g| g),
            m,
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DirTarget {
    path: PathBuf,
    attr: Attributes,
    created: bool,
}

impl DirTarget {
    /// Create a new DirTarget from a path
    /// Returns `None` if `dir` is not an absolute path or is empty
    pub fn new(dir: &Path) -> Option<DirTarget> {
        if dir.is_empty() {
            return None;
        }

        let mut dit = dir.to_str().expect("Utf-8 path").split(':').peekable();
        /* Unwrap safe since split must have at least one element */
        let path = PathBuf::from(dit.next().unwrap());
        let attr = match dit.peek() {
            Some(_) => Attributes::parse(dit),
            None => Attributes::unspecified(),
        };
        match dir.is_absolute() {
            true => Some(Self {
                path,
                attr,
                created: false,
            }),
            false => None,
        }
    }
}

impl Display for DirTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

impl PartialOrd<DirTarget> for DirTarget {
    fn partial_cmp(&self, other: &DirTarget) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DirTarget {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.path.cmp(&other.path)
    }
}

impl PlanItem<()> for DirTarget {
    type Error = TheseusError;

    fn execute(self, _: Option<&()>) -> Result<Self, TheseusError> {
        trace!("executing DirTarget {}", self.path.display());
        if self.path.exists() && self.path.is_dir() {
            return Ok(Self {
                path: self.path,
                attr: self.attr,
                created: false,
            });
        }
        std::fs::create_dir(&self.path)
            .map_err(|e| TheseusError::Create(self.to_string(), e.to_string()))?;
        debug!("created {}", self.path.display());
        Ok(DirTarget {
            path: self.path,
            attr: self.attr,
            created: true,
        })
    }

    fn unwind(&self) {
        if self.created {
            std::fs::remove_dir(&self.path)
                .unwrap_or_else(|e| error!("removing {} {}", self.path.display(), e));
        }
    }

    fn identify(&self) -> String {
        self.to_string()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileTarget {
    src: PathBuf,
    dst: PathBuf,
    attr: Attributes,
    saved: bool,
}

impl Display for FileTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FileTarget{{ {}, {}, attr: {}}}",
            self.src.display(),
            self.dst.display(),
            self.attr,
        )
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
        let mut rst = s.split(':').peekable();
        let dst = path::absolute(
            rst.next()
                .ok_or(TheseusError::MissingDst(s.to_string()))
                .map(|t| PathBuf::from(t.replace('_', "/")))?,
        )
        .map_err(|e| TheseusError::Absolute(src.display().to_string(), e.to_string()))?;
        let attr = match rst.peek() {
            Some(_) => Attributes::parse(rst),
            None => Attributes::unspecified(),
        };
        trace!("read target {}", src.display());
        Ok(Self {
            src,
            dst,
            attr,
            saved: false,
        })
    }

    /// Read a FileTarget from a path
    /// `p` is a local path, like ./bin/sh:root:root:755
    /// The destination is `/bin/sh`
    pub fn from_path(p: &Path, prefix: &Path) -> Result<Self, TheseusError> {
        if !p.try_exists()? {
            return Err(TheseusError::PathExist(p.to_string_lossy().to_string()));
        }
        let src = path::absolute(PathBuf::from(p))
            .map_err(|e| TheseusError::Absolute(p.display().to_string(), e.to_string()))?;
        let dst_aparent = p
            .strip_prefix(prefix)
            .unwrap_or(p)
            .parent()
            .ok_or(TheseusError::MissingParent(p.display().to_string()))?;
        /* Satisfy ownership */
        let rst_t = p
            .file_name()
            .ok_or(TheseusError::MissingFilename(p.display().to_string()))?
            .to_string_lossy()
            .into_owned();
        let mut rst = rst_t.split(':').peekable();
        let dst_fname = rst
            .next()
            .ok_or(TheseusError::MissingDst(p.display().to_string()))?;
        let attr = match rst.peek() {
            Some(_) => Attributes::parse(rst),
            None => Attributes::unspecified(),
        };
        trace!("read target {}", src.display());

        let dst = PathBuf::from("/").join(dst_aparent).join(dst_fname);
        Ok(Self {
            src,
            dst,
            attr,
            saved: false,
        })
    }

    /// Get uid/gid of a FileTarget
    /// If stored user/group are uid/gid, then return them.
    /// If they are names, find the associated uids/gids
    /// Otherwise, use the current user/group
    fn ids(&self) -> Result<(Uid, Gid), TheseusError> {
        Ok((self.attr.get_uid()?, self.attr.get_gid()?))
    }
}

#[inline]
fn compute_save(p: &Path, prefix: Option<&Path>) -> Result<Option<FileTarget>, TheseusError> {
    if !p.exists() || prefix.is_none() {
        return Ok(None);
    }
    let prefix = prefix.unwrap();
    let st = nix::sys::stat::stat(p)
        .map_err(|e| TheseusError::Stat(e.to_string(), p.to_string_lossy().into_owned()))?;
    let dst = path::absolute(p)
        .map_err(|e| TheseusError::Absolute(p.display().to_string(), e.to_string()))?;
    let own = User::from_uid(st.st_uid.into())
        .map_err(|e| TheseusError::GetUser(e.to_string()))?
        .map_or_else(|| st.st_uid.to_string(), |usr| usr.name);
    let grp = Group::from_gid(st.st_gid.into())
        .map_err(|e| TheseusError::GetGrp(e.to_string()))?
        .map_or_else(|| st.st_gid.to_string(), |grp| grp.name);
    let mode = Mode::from_bits_truncate(st.st_mode);

    let src = prefix.join(dst.display().to_string().replace('/', "_"));
    Ok(Some(FileTarget {
        src,
        dst,
        attr: Attributes {
            own: Some(own),
            grp: Some(grp),
            mode: Some(mode),
        },
        saved: true,
    }))
}

impl PlanItem<Path> for FileTarget {
    type Error = TheseusError;

    fn execute(self, savepath: Option<&Path>) -> Result<Self, TheseusError> {
        trace!("execute {}", self.src.display());
        let (uid, gid) = self.ids()?;

        let save = compute_save(&self.dst, savepath)?;
        if let Some(save) = save.as_ref() {
            copy(&self.dst, &save.src)
                .map_err(|e| TheseusError::Copy(save.src.display().to_string(), e.kind()))?;
        }
        copy(&self.src, &self.dst)
            .map_err(|e| TheseusError::Copy(self.src.display().to_string(), e.kind()))?;

        let m = self.attr.get_mode();
        fchmodat(None, &self.src, m, FchmodatFlags::FollowSymlink)
            .map_err(|e| TheseusError::Chmod(self.src.display().to_string(), e.to_string()))?;

        chown(&self.src, Some(uid), Some(gid))
            .map_err(|e| TheseusError::Chown(self.src.display().to_string(), e.to_string()))?;

        Ok(save.unwrap_or(self))
    }

    fn unwind(&self) {
        /* Remove emplaced file */
        nix::unistd::unlink(&self.dst)
            .unwrap_or_else(|_| panic!("remove written {}", self.src.display()));

        /* Only need to restore if src was saved */
        if self.saved {
            copy(&self.src, &self.dst).unwrap_or_else(|e| {
                panic!(
                    "copy {} to {}: {}",
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

impl HasDeps<Path, ()> for FileTarget {
    type Dep = DirTarget;

    fn dependencies(&self) -> impl IntoIterator<Item = DirTarget> {
        assert!(
            self.dst.is_absolute(),
            "{} is an absolute path",
            self.dst.display()
        );
        self.dst
            .parent()
            .unwrap_or_else(|| panic!("{} is not root", self.dst.display()))
            .ancestors()
            .map(|a| DirTarget {
                path: a.to_owned(),
                attr: Attributes::parse(
                    a.to_str().expect("Only UTF-8 paths").split(':').peekable(),
                ),
                created: false,
            })
            .collect::<Vec<_>>()
    }
}

impl DependentPlan<(), Path, DirTarget, Vec<DirTarget>, FileTarget> for Vec<FileTarget> {
    fn dependencies(&self) -> Vec<DirTarget> {
        /* Dependency trees should be small, so performance doesn't really matter */
        /* But still, vec + sort + dedup is probably faster than ordered set for small data */
        let mut deps: Vec<_> = self.iter().flat_map(|ft| ft.dependencies()).collect();
        deps.sort();
        deps.dedup();
        deps
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

/// Read a plan from a filesystem with root at `root`
pub fn plan_from_root(root: &Path) -> Result<Vec<FileTarget>, TheseusError> {
    // TODO: This would be nice to do with iterators.
    // However, that require lifting nested `Iterator<Item = Result<T,E>>` to
    // Result<Iterator<Item = T>, E>, i.e.,
    // `Iterator<Item = Result<Result<Result<T,E0>,E1>,E2>` to
    // `Result<Iterator<Item = T`
    // itertools::process_result should be able to handle it, but the lifetime
    // requirements make it hard
    // let (files, _): (Vec<_>, Vec<_>) = itertools::process_results(WalkDir::new(root), |walker| {
    //     walker.partition(|p| !p.path().is_dir())
    // })
    // .map_err(|e| TheseusError::DirDir(e.to_string()))?;
    // itertools::process_results(
    //     files
    //         .iter()
    //         .map(walkdir::DirEntry::path)
    //         .map(std::fs::canonicalize)
    //         .map(|p| p.map_err(|e| TheseusError::DirEntry(e.kind()))),
    //     |files| files.map(|p| FileTarget::from_path(&p)),
    // )?;
    let mut plan = Vec::new();
    for entry in WalkDir::new(root) {
        let entry = entry.map_err(|e| TheseusError::DirDir(e.to_string()))?;
        trace!("Entry {}", entry.path().display());
        if !entry.path().is_dir() {
            let ft = FileTarget::from_path(entry.path(), root)?;
            debug!("FileTarget {}", ft.src.display());
            plan.push(ft);
        }
    }
    Ok(plan)
}
