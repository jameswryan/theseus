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

use nix::NixPath;
use nix::{
    sys::stat::{fchmodat, stat, FchmodatFlags, Mode},
    unistd::{chown, getgid, getuid, Gid, Group, Uid, User},
};
use plan::*;
use tracing::{debug, error, trace};
use walkdir::WalkDir;

/// Convert a file mode to an octal string
///
/// ```
/// use nix::sys::stat::Mode;
/// use theseus::target::mode_to_string;
/// assert_eq!(mode_to_string(Mode::from_bits_truncate(0o777)), "777");
/// ```
pub fn mode_to_string(m: Mode) -> String {
    let m = m.bits();
    let o = (m >> 6) & 7;
    let g = (m >> 3) & 7;
    let w = m & 7;

    format!("{o:o}{g:o}{w:o}",)
}

/// Convert an octal string to a file mode
///
/// ```
/// use nix::sys::stat::Mode;
/// use theseus::error::*;
/// use theseus::target::string_to_mode;
/// fn main() -> Result<(), TheseusError> {
///     assert_eq!(string_to_mode("777")?, Mode::from_bits_truncate(0o777));
///     Ok(())
/// }
/// ```
pub fn string_to_mode(s: &str) -> Result<Mode, TheseusError> {
    let bits = nix::libc::mode_t::from_str_radix(s, 8)
        .map_err(|e| TheseusError::InvalidPrm(e.to_string()))?;
    Ok(Mode::from_bits_truncate(bits))
}

/// Attributes are attributes of a filesystem entry
///
/// They may be unspecified, and so are optional
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Attributes {
    /// The owner
    ///
    /// May be a uid or the name of a user
    pub own: Option<String>,
    /// The group
    ///
    /// May be a gid or the name of a group
    pub grp: Option<String>,
    /// The mode
    ///
    /// Must be in `rwxrwxrwx` format
    pub mode: Option<Mode>,
}

impl Attributes {
    /// Convert an `Iterator<Item = String>` to an `Attributes`.
    ///
    /// If any of `own`, `grp`, or `mode` are `*`, they are treated as
    /// unspecified.
    ///
    /// ```
    /// use theseus::target::*;
    /// let attr0 = Attributes {own: None, grp: None, mode: None};
    /// let attr1 = Attributes::parse("*:*:*".split(":"));
    /// assert_eq!(attr0,attr1);
    /// ```
    pub fn parse<'a, S: Iterator<Item = &'a str> + std::fmt::Debug>(
        mut s: S,
    ) -> Self {
        let own = s.next().and_then(Self::from_star);
        let grp = s.next().and_then(Self::from_star);
        let mode = s.next().and_then(|m| string_to_mode(m).ok());

        Self { own, grp, mode }
    }

    /// Get the `Attributes` of a path
    pub fn from_path(p: &Path) -> Result<Self, TheseusError> {
        let st = stat(p).map_err(|e| {
            TheseusError::Stat(e.to_string(), p.to_string_lossy().into_owned())
        })?;

        Ok(Self {
            own: Some(st.st_uid.to_string()),
            grp: Some(st.st_gid.to_string()),
            mode: Some(Mode::from_bits_truncate(st.st_mode)),
        })
    }

    /// Create an `Attributes` with all attributes unspecified
    ///
    /// ```
    /// use theseus::target::*;
    /// let attr0 = Attributes {own: None, grp: None, mode: None};
    /// let attr1 = Attributes::unspecified();
    /// assert_eq!(attr0,attr1);
    /// ```
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

    /// Returns the uid of the user in the attribute.
    ///
    /// If a numeric uid is stored, return it.
    /// If the system has no user with the stored name, return TheseusError::MissingUser.
    /// If no user/uid is stored, return the current user.
    ///
    /// ```
    /// use theseus::target::*;
    /// use theseus::error::*;
    /// fn main() -> Result<(), TheseusError> {
    ///     let attr = Attributes {own: Some("0".to_string()), grp: None, mode: None};
    ///     assert_eq!(attr.get_uid()?, 0.into());
    ///     Ok(())
    /// }
    /// ```
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
    ///
    /// If a numeric gid is stored, return it.
    /// If the system has no group with the stored name, return TheseusError::MissingGroup
    /// If no group/gid is stored, return the current group
    ///
    /// ```
    /// use theseus::target::*;
    /// use theseus::error::*;
    /// fn main() -> Result<(), TheseusError> {
    ///     let attr = Attributes {own: None, grp: Some("0".to_string()), mode: None};
    ///     assert_eq!(attr.get_gid()?, 0.into());
    ///     Ok(())
    /// }
    /// ```
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
    ///
    /// If no mode is specified, returns `0o600` as the mode
    ///
    /// ```
    /// use theseus::target::*;
    /// use nix::sys::stat::Mode;
    /// let attr0 = Attributes {own: None, grp: None, mode: None};
    /// assert_eq!(attr0.get_mode(),Mode::from_bits_truncate(0o600));
    /// ```
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
    ///
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

    fn execute(&self, _: Option<&()>) -> Result<(), TheseusError> {
        trace!("executing DirTarget {}", self.path.display());
        if self.path.exists() && self.path.is_dir() {
            return Ok(());
        }
        std::fs::create_dir(&self.path).map_err(|e| {
            TheseusError::Create(self.to_string(), e.to_string())
        })?;
        debug!("created {}", self.path.display());
        Ok(())
    }

    fn unwind(&self, _: Option<&()>) {
        if self.created {
            std::fs::remove_dir(&self.path).unwrap_or_else(|e| {
                error!("removing {} {}", self.path.display(), e)
            });
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
#[inline(always)]
fn num_if(s: &str, radix: u32) -> Option<u32> {
    u32::from_str_radix(s, radix).ok()
}

impl FileTarget {
    /// Read a FileTarget from a path
    ///
    /// `p` is a path, like `./bin/sh:root:root:755`.
    /// The destination is `/bin/sh`.
    /// The prefix `prefix` is stripped before computing the destination
    ///
    fn from_path(p: &Path, prefix: &Path) -> Result<Self, TheseusError> {
        if !p.try_exists()? {
            return Err(TheseusError::PathExist(
                p.to_string_lossy().to_string(),
            ));
        }
        let src = path::absolute(PathBuf::from(p)).map_err(|e| {
            TheseusError::Absolute(p.display().to_string(), e.to_string())
        })?;
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
        Ok(Self { src, dst, attr })
    }

    /// Read a FileTarget from a flattened path
    ///
    /// `p` is a flattend path, like `./_bin_sh:root:root:755`.
    /// The destination is `/bin/sh`.
    fn from_flat_path(p: &Path) -> Result<Self, TheseusError> {
        if !p.try_exists()? {
            return Err(TheseusError::PathExist(
                p.to_string_lossy().to_string(),
            ));
        }
        let src = path::absolute(PathBuf::from(p)).map_err(|e| {
            TheseusError::Absolute(p.display().to_string(), e.to_string())
        })?;
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

        let dst = PathBuf::from("/").join(from_flat_path(dst_fname));
        Ok(Self { src, dst, attr })
    }

    /// Get uid/gid of a FileTarget
    ///
    /// If stored user/group are uid/gid, then return them.
    /// If they are names, find the associated uids/gids.
    /// Otherwise, use the current user/group.
    fn ids(&self) -> Result<(Uid, Gid), TheseusError> {
        Ok((self.attr.get_uid()?, self.attr.get_gid()?))
    }
}

/// Compute the journaled path of a FileTarget
///
/// The journaled path is a serialized FileTarget, except occurances of `/`
/// are replaced with `_`
#[inline]
fn journaled_path_of(
    p: &Path,
    prefix: Option<&Path>,
) -> Result<Option<PathBuf>, TheseusError> {
    if !p.exists() || prefix.is_none() {
        return Ok(None);
    }
    let prefix = prefix.unwrap();
    let st = nix::sys::stat::stat(p).map_err(|e| {
        TheseusError::Stat(e.to_string(), p.to_string_lossy().into_owned())
    })?;
    let dst = path::absolute(p).map_err(|e| {
        TheseusError::Absolute(p.display().to_string(), e.to_string())
    })?;
    let own = User::from_uid(st.st_uid.into())
        .map_err(|e| TheseusError::GetUser(e.to_string()))?
        .map_or_else(|| st.st_uid.to_string(), |usr| usr.name);
    let grp = Group::from_gid(st.st_gid.into())
        .map_err(|e| TheseusError::GetGrp(e.to_string()))?
        .map_or_else(|| st.st_gid.to_string(), |grp| grp.name);
    let mode = Mode::from_bits_truncate(st.st_mode);

    Ok(Some(prefix.to_path_buf().join(PathBuf::from(format!(
        "{}:{}:{}:{}",
        dst.display().to_string().replace('/', "_"),
        own,
        grp,
        mode_to_string(mode)
    )))))
}

#[inline(always)]
fn to_flat_path(p: impl AsRef<Path>) -> String {
    p.as_ref().to_string_lossy().replace("/", "_")
}

#[inline]
fn from_flat_path(p: impl AsRef<Path>) -> String {
    p.as_ref().to_string_lossy().replace("_", "/")
}

impl PlanItem<Path> for FileTarget {
    type Error = TheseusError;

    fn execute(&self, journal: Option<&Path>) -> Result<(), TheseusError> {
        trace!("execute {}", self.src.display());
        let (uid, gid) = self.ids()?;

        let save = journaled_path_of(&self.dst, journal)?;
        if let Some(save) = save.as_ref() {
            copy(&self.dst, save).map_err(|e| {
                TheseusError::Copy(save.display().to_string(), e.kind())
            })?;
        }
        copy(&self.src, &self.dst).map_err(|e| {
            TheseusError::Copy(self.src.display().to_string(), e.kind())
        })?;

        let m = self.attr.get_mode();
        fchmodat(None, &self.dst, m, FchmodatFlags::FollowSymlink).map_err(
            |e| {
                TheseusError::Chmod(
                    self.src.display().to_string(),
                    e.to_string(),
                )
            },
        )?;

        chown(&self.dst, Some(uid), Some(gid)).map_err(|e| {
            TheseusError::Chown(self.src.display().to_string(), e.to_string())
        })?;

        Ok(())
    }

    fn unwind(&self, journal: Option<&Path>) {
        /* Remove emplaced file */
        nix::unistd::unlink(&self.dst).unwrap_or_else(|_| {
            panic!("remove written {}", self.src.display())
        });

        /* Only need to restore if self was saved and we have a journal */
        /* If we don't have a journal, we can't possibly have saved anything */
        if let Some(journal) = journal {
            let flat_dst = to_flat_path(self.dst.clone());
            for ent in journal.read_dir().expect("Reading from journal") {
                let ent = ent.expect("Reading journal entry");
                if ent
                    .file_name()
                    .to_string_lossy()
                    .split(':')
                    .next()
                    .unwrap()
                    .starts_with(&flat_dst)
                {
                    /* Isn't this convienient :) */
                    let ent_target = FileTarget::from_flat_path(&ent.path())
                        .expect("journal entries are flat_path FileTargets");
                    ent_target
                        .execute(None)
                        .expect("Can restore journal entries");
                }
            }
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

impl DependentPlan<(), Path, DirTarget, Vec<DirTarget>, FileTarget>
    for Vec<FileTarget>
{
    fn dependencies(&self) -> Vec<DirTarget> {
        /* Dependency trees should be small, so performance doesn't really matter */
        /* But still, vec + sort + dedup is probably faster than ordered set for small data */
        let mut deps: Vec<_> =
            self.iter().flat_map(|ft| ft.dependencies()).collect();
        deps.sort();
        deps.dedup();
        deps
    }
}

/// Read a plan from a filesystem with root at `root`
pub fn plan_from_root(root: &Path) -> Result<Vec<FileTarget>, TheseusError> {
    // TODO: This would be nice to do with iterators.
    // However, that require lifting nested `Iterator<Item = Result<T,E>>` to
    // Result<Iterator<Item = T>, E>, i.e.,
    // `Iterator<Item = Result<Result<Result<T,E0>,E1>,E2>` to
    // `Result<Iterator<Item = T>, E0 | E1 | E2>`
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

#[cfg(test)]
mod test {
    use super::*;

    use crate::TmpDir;

    fn build_valid_successful_plan() -> TmpDir {
        let tmpdir = TmpDir::new().expect("create tmpdir");

        let c1 = vec![1; 128];
        let c2 = vec![2; 256];
        let c3 = vec![3; 384];
        let plandir = tmpdir
            .inner
            .join("plan")
            .join(tmpdir.inner.strip_prefix("/").unwrap())
            .join("target");

        let journaldir = tmpdir.inner.join("journal");
        std::fs::create_dir_all(journaldir).expect("create journaldir");

        std::fs::create_dir_all(plandir.join("dir1/dir2/dir3"))
            .expect("create directories");
        std::fs::write(plandir.join("f1:*:*:600"), c1).expect("write ones");
        std::fs::write(plandir.join("dir1").join("f2:*:*:755"), c2)
            .expect("write twos");
        std::fs::write(plandir.join("dir1/dir2/dir3").join("f3:*:*:644"), c3)
            .expect("write threes");

        tmpdir
    }

    fn build_valid_failure_plan() -> TmpDir {
        let tmpdir = TmpDir::new().expect("create tmpdir");

        let ca = [b'a'; 128];
        let cb = [b'b'; 256];
        let cc = [b'c'; 384];
        let cd = [b'd'; 512];
        let plandir = tmpdir
            .inner
            .join("plan")
            .join(tmpdir.inner.strip_prefix("/").unwrap())
            .join("target");

        let journaldir = tmpdir.inner.join("journal");
        std::fs::create_dir_all(journaldir).expect("create journaldir");

        std::fs::create_dir_all(plandir.join("dir1/dir2/dir3"))
            .expect("create directories");
        std::fs::write(plandir.join("f1:*:*:600:"), ca).expect("write as");
        std::fs::write(
            plandir.join("dir1").join("f2:not-a-real-user:*:755"),
            cb,
        )
        .expect("write bs");
        std::fs::write(plandir.join("dir1/dir2/dir3").join("f3:*:*:644"), cc)
            .expect("write cs");

        std::fs::create_dir(tmpdir.inner.join("target"))
            .expect("create target dir");
        std::fs::write(tmpdir.inner.join("target/f1"), cd).expect("write ds");
        /* Ensure consistent mode */
        nix::sys::stat::fchmodat(
            None,
            &tmpdir.inner.join("target/f1"),
            Mode::from_bits_truncate(0o755),
            FchmodatFlags::FollowSymlink,
        )
        .expect("chmod");

        tmpdir
    }

    #[test]
    fn valid_successful_plan_is_valid() {
        let tmpdir = build_valid_successful_plan();

        plan_from_root(&tmpdir.inner.join("plan"))
            .expect("valid plan is invalid?");
    }

    #[test]
    fn valid_successful_plan_executes_successfully() {
        /* Build test */
        let tmpdir = build_valid_successful_plan();
        let journal = tmpdir.inner.join("journal");
        let plan = plan_from_root(&tmpdir.inner.join("plan"))
            .expect("valid_plan is valid?");

        /* Dependencies */
        let failed_dep = plan.execute_dependencies().err();
        assert_eq!(failed_dep, None);

        /* Executes without errors */
        let failed = plan.clone().execute_plan(Some(&journal)).err();
        assert_eq!(failed, None);

        /* Sets metadata correctly */
        for item in plan {
            let FileTarget {
                src: _src,
                dst,
                attr,
            } = item;

            let st = stat(&dst).unwrap();
            if let Some(attr_mode) = attr.mode {
                let st_mode = Mode::from_bits_truncate(st.st_mode);
                assert_eq!(st_mode, attr_mode);
            }
            assert_eq!(st.st_gid, attr.get_gid().unwrap().as_raw());
            assert_eq!(st.st_uid, attr.get_uid().unwrap().as_raw());
        }
    }

    #[test]
    fn valid_failure_plan_fails_safe() {
        let tmpdir = build_valid_failure_plan();
        let journal = tmpdir.inner.join("journal");
        let plan = plan_from_root(&tmpdir.inner.join("plan"))
            .expect("valid_failure_plan is valid?");

        /* Dependencies */
        let failed_dep = plan.execute_dependencies().err();
        assert_eq!(failed_dep, None);

        /* Fails execution on correct item */
        let failed_src = tmpdir
            .inner
            .join("plan")
            .join(tmpdir.inner.strip_prefix("/").unwrap())
            .join("target/dir1/f2:not-a-real-user:*:755");
        let failed_exp = FileTarget {
            src: failed_src.clone(),
            dst: tmpdir.inner.join("target/dir1/f2"),
            attr: Attributes {
                own: Some("not-a-real-user".to_owned()),
                grp: None,
                mode: Some(string_to_mode("755").unwrap()),
            },
        };
        let failed = plan
            .clone()
            .execute_plan(Some(&journal))
            .expect_err("failure_plan_succeeded?");
        assert_eq!(failed, failed_exp);

        /* Exactly one journal entry*/
        let mut reader = journal.read_dir().expect("read journal");
        let j_ent = reader
            .next()
            .expect("journal has entry")
            .expect("read journal entry");
        assert!(reader.next().is_none(), "more than one journal entry?");

        /* Journal entry has correct contents */
        let j_ent_cntnts =
            std::fs::read_to_string(j_ent.path()).expect("read journal entry");
        let j_ent_exp_cntnts = String::from_utf8(vec![b'd'; 512]).unwrap();
        assert_eq!(j_ent_cntnts, j_ent_exp_cntnts);

        /* Correctly unwinds execution of successfully completed items */
        let act_c14_file = tmpdir.inner.join("target/f1");
        let act_c4_contents =
            std::fs::read_to_string(act_c14_file).expect("read c14 file");
        assert_eq!(act_c4_contents, j_ent_cntnts);
    }
}
