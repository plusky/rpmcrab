//! `PkgFile` — one file in a package, mirroring rpmlint's `PkgFile`
//! (`rpmlint/pkgfile.py`).

/// `RPMFILE_*` file flags (stable rpm ABI, `/usr/include/rpm/rpmfiles.h`).
pub const RPMFILE_CONFIG: u32 = 1 << 0;
pub const RPMFILE_DOC: u32 = 1 << 1;
pub const RPMFILE_ICON: u32 = 1 << 2;
pub const RPMFILE_MISSINGOK: u32 = 1 << 3;
pub const RPMFILE_NOREPLACE: u32 = 1 << 4;
pub const RPMFILE_SPECFILE: u32 = 1 << 5;
pub const RPMFILE_GHOST: u32 = 1 << 6;
pub const RPMFILE_LICENSE: u32 = 1 << 7;
pub const RPMFILE_README: u32 = 1 << 8;
pub const RPMFILE_PUBKEY: u32 = 1 << 11;
pub const RPMFILE_ARTIFACT: u32 = 1 << 12;

/// A single file entry, mirroring rpmlint's `PkgFile`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PkgFile {
    /// Package-relative path.
    pub name: String,
    /// The on-disk path: `normpath(dir_name + "/" + name)` when extracted;
    /// otherwise just `name`. rpmlint keeps the real path here.
    pub path: String,
    /// `RPMFILE_*` bitmask.
    pub flags: u32,
    /// Raw `st_mode` bits (type + permissions).
    pub mode: u32,
    pub user: String,
    pub group: String,
    /// Symlink target, normalised; empty for non-symlinks.
    pub linkto: String,
    pub size: Option<u64>,
    /// Hex digest from the header (`FILEMD5S`; rpm 4.20 stores SHA-256, 64 hex).
    pub md5: Option<String>,
    pub mtime: u64,
    pub rdev: u32,
    pub inode: u32,
    pub lang: String,
    /// libmagic description (`_calc_magic`); starts as the header's `FILECLASS`.
    pub magic: String,
    pub filecaps: Option<String>,
    /// Per-file `Requires` (from `FILEREQUIRE`), parsed.
    pub requires: Vec<crate::pkg::dep::DepInfo>,
    /// Per-file `Provides` (from `FILEPROVIDE`), parsed.
    pub provides: Vec<crate::pkg::dep::DepInfo>,
}

impl PkgFile {
    pub fn is_config(&self) -> bool {
        self.flags & RPMFILE_CONFIG != 0
    }
    pub fn is_doc(&self) -> bool {
        self.flags & RPMFILE_DOC != 0
    }
    pub fn is_ghost(&self) -> bool {
        self.flags & RPMFILE_GHOST != 0
    }
    pub fn is_noreplace(&self) -> bool {
        self.flags & RPMFILE_NOREPLACE != 0
    }
    pub fn is_missingok(&self) -> bool {
        self.flags & RPMFILE_MISSINGOK != 0
    }
}

/// File-type predicates mirroring Python's `stat` module (the checks use these
/// on `mode`). `S_IFMT`/`S_IFDIR`/`S_IFLNK`/`S_IFREG` from POSIX.
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;

pub fn is_dir(mode: u32) -> bool {
    mode & S_IFMT == S_IFDIR
}
pub fn is_symlink(mode: u32) -> bool {
    mode & S_IFMT == S_IFLNK
}
pub fn is_reg(mode: u32) -> bool {
    mode & S_IFMT == S_IFREG
}

/// Python `stat.filemode(mode)` — the `-rwxr-xr-x` style string.
pub fn filemode(mode: u32) -> String {
    let mut c: Vec<char> = Vec::with_capacity(10);
    c.push(match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        0o010000 => 'p',
        0o020000 => 'c',
        0o060000 => 'b',
        0o140000 => 's',
        _ => '-',
    });
    for (bit, ch) in [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ] {
        c.push(if mode & bit != 0 { ch } else { '-' });
    }
    if mode & 0o4000 != 0 {
        c[3] = if c[3] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o2000 != 0 {
        c[6] = if c[6] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o1000 != 0 {
        c[9] = if c[9] == 'x' { 't' } else { 'T' };
    }
    c.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filemode_matches_stat() {
        // python3: stat.filemode(0o100755) == '-rwxr-xr-x'
        assert_eq!(filemode(0o100755), "-rwxr-xr-x");
        // stat.filemode(0o40755) == 'drwxr-xr-x'
        assert_eq!(filemode(0o40755), "drwxr-xr-x");
        // stat.filemode(0o120777) == 'lrwxrwxrwx'
        assert_eq!(filemode(0o120777), "lrwxrwxrwx");
        // stat.filemode(0o104755) == '-rwsr-xr-x' (setuid)
        assert_eq!(filemode(0o104755), "-rwsr-xr-x");
    }

    #[test]
    fn type_predicates() {
        assert!(is_dir(0o40755));
        assert!(is_symlink(0o120777));
        assert!(is_reg(0o100644));
        assert!(!is_reg(0o40755));
    }
}
