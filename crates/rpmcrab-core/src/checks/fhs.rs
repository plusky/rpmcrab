//! `FHSCheck` — validate that files are packaged according to the FHS.
//!
//! Ported from `rpmlint/checks/FHSCheck.py`. Two findings, both warnings:
//! `non-standard-dir-in-usr` and `non-standard-dir-in-var`.

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

/// Allowed subdirectories of `/usr`: the FHS 3.0 list (chapters 4.2 and
/// 4.3), plus the first components the distro treats as standard in
/// practice - `etc` (the vendor-default config tree), the MinGW
/// cross-toolchain sysroots and `X11R6` - which FilelistCheck's
/// GoodPrefixes likewise model as good (ledgered divergence, issue #582).
/// The additions are appended so the reference's twelve stay in order at
/// the head of the list (and of the generated description).
const FHS_USR_SUBDIRS: &[&str] = &[
    "bin",
    "lib",
    "local",
    "sbin",
    "share",
    "games",
    "include",
    "libexec",
    "lib64",
    "src",
    "spool",
    "tmp",
    "etc",
    "i686-w64-mingw32",
    "x86_64-w64-mingw32",
    "X11R6",
];

/// Cross-toolchain target sysroots: the first components under `/usr`
/// that are target names of the distro's cross compilers - the
/// `*-suse-linux` triples and the bare-metal targets. Each names the
/// sysroot its toolchain installs into, so the check treats them as
/// standard in practice. They stay out of `FHS_USR_SUBDIRS`: that list
/// names the standard directories in the generated description, while
/// this set is the measured Factory population (issue #582), not a
/// pattern - any other first component still fires. FilelistCheck
/// and FilesCheck consult the same set through
/// `cross_sysroot_matches`, so a sysroot one check treats as standard
/// is standard for all of them.
pub(crate) const FHS_USR_CROSS_SYSROOTS: &[&str] = &[
    "aarch64-suse-linux",
    "amdgcn-amdhsa",
    "arm-none-eabi",
    "arm-suse-linux-gnueabi",
    "avr",
    "bpf-none",
    "epiphany-elf",
    "hppa-suse-linux",
    "hppa64-suse-linux",
    "i586-suse-linux",
    "ia64-suse-linux",
    "loongarch64-suse-linux",
    "m68k-suse-linux",
    "mips-suse-linux",
    "nvptx-none",
    "powerpc-suse-linux",
    "powerpc64-suse-linux",
    "powerpc64le-suse-linux",
    "pru",
    "riscv64-elf",
    "riscv64-suse-linux",
    "rx-elf",
    "s390-suse-linux",
    "s390x-suse-linux",
    "sparc-suse-linux",
    "sparc64-suse-linux",
    "spu",
    "x86_64-suse-linux",
    "xtensa-suse-linux",
];

/// Whether `path` lies under a cross-toolchain target sysroot: its
/// first component under `/usr` is one of the measured target sysroots
/// in `FHS_USR_CROSS_SYSROOTS`. The sysroot name must lead the path -
/// the same name deeper in the tree sanctions nothing.
pub(crate) fn cross_sysroot_matches(path: &str) -> bool {
    path.strip_prefix("/usr/")
        .map(|rest| rest.split('/').next().unwrap_or(""))
        .is_some_and(|first| FHS_USR_CROSS_SYSROOTS.contains(&first))
}

/// Allowed subdirectories of `/var` (FHS 3.0, chapters 5.2 and 5.3).
/// `adm` is standard in distro practice: it is the OS's own admin
/// directory, shipped by the filesystem package itself and hosting
/// SUSE's fillup templates (`/var/adm/fillup-templates`), so no
/// package-side remedy exists for shipping it.
const FHS_VAR_SUBDIRS: &[&str] = &[
    "cache", "lib", "local", "lock", "log", "opt", "run", "spool", "tmp", "account", "crash",
    "games", "mail", "yp", "adm",
];

pub struct FHSCheck;

impl FHSCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// Returns `(dir_type, subdir)` for each non-standard top-level subdir
    /// found under `/usr` or `/var`, deduplicated. `dir_type` is `"usr"` or
    /// `"var"`.
    fn non_standard_dirs<'a>(files: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
        let mut seen_usr = Vec::new();
        let mut seen_var = Vec::new();
        let mut out = Vec::new();

        for fname in files {
            if let Some(rest) = fname.strip_prefix("/usr/") {
                let subdir: &str = rest.split('/').next().unwrap_or("");
                if !subdir.is_empty()
                    && !FHS_USR_SUBDIRS.contains(&subdir)
                    && !FHS_USR_CROSS_SYSROOTS.contains(&subdir)
                    && !seen_usr.contains(&subdir)
                {
                    seen_usr.push(subdir);
                    out.push(("usr".to_string(), subdir.to_string()));
                }
            } else if let Some(rest) = fname.strip_prefix("/var/") {
                let subdir: &str = rest.split('/').next().unwrap_or("");
                if !subdir.is_empty()
                    && !FHS_VAR_SUBDIRS.contains(&subdir)
                    && !seen_var.contains(&subdir)
                {
                    seen_var.push(subdir);
                    out.push(("var".to_string(), subdir.to_string()));
                }
            }
        }
        out
    }
}

impl Check for FHSCheck {
    fn name(&self) -> &'static str {
        "FHSCheck"
    }

    /// This check only ever emits warnings (every `add_info` call site
    /// passes `Level::Warning`), so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        // `-v`/`--explain` descriptions, mirroring the reference's
        // `fhs_details_dict` which `__init__` installs unconditionally.
        Self::register_error_details(out);
        let names: Vec<&str> = pkg.files.iter().map(|f| f.name.as_str()).collect();
        for (dir_type, subdir) in Self::non_standard_dirs(names.into_iter()) {
            let check = format!("non-standard-dir-in-{dir_type}");
            add_info(out, Level::Warning, pkg, &check, &[&subdir]);
        }
    }
}

impl FHSCheck {
    /// `error_details` for `--explain`, mirroring the reference's
    /// `fhs_details_dict` (`FHSCheck.py:79-88`) installed in `__init__`.
    pub fn register_error_details(out: &mut Filter) {
        out.set_error_detail(
            "non-standard-dir-in-usr",
            format!(
                "Your package is creating a non-standard subdirectory in /usr. The standard\ndirectories are:\n{}.",
                FHS_USR_SUBDIRS.join(", ")
            ),
        );
        out.set_error_detail(
            "non-standard-dir-in-var",
            format!(
                "Your package is creating a non-standard subdirectory in /var. The standard\ndirectories are:\n{}.",
                FHS_VAR_SUBDIRS.join(", ")
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_dirs_are_quiet() {
        let dirs = FHSCheck::non_standard_dirs(
            [
                "/usr/bin/foo",
                "/usr/share/doc/bar",
                "/var/log/baz",
                "/var/lib/qux",
            ]
            .into_iter(),
        );
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[test]
    fn non_standard_usr_dir_is_reported() {
        let dirs = FHSCheck::non_standard_dirs(["/usr/weird/tool"].into_iter());
        assert_eq!(dirs, vec![("usr".to_string(), "weird".to_string())]);
    }

    #[test]
    fn sanctioned_usr_dirs_are_quiet() {
        // /usr/etc (vendor-default config tree), the MinGW sysroots and
        // /usr/X11R6 are standard in distro practice: FilelistCheck's
        // GoodPrefixes model all of them as good (issue #582).
        let dirs = FHSCheck::non_standard_dirs(
            [
                "/usr/etc/profile.d/alias.ash",
                "/usr/etc/skel/.bashrc",
                "/usr/i686-w64-mingw32/sys-root/mingw/bin/cpp.exe",
                "/usr/x86_64-w64-mingw32/sys-root/mingw/bin/cpp.exe",
                "/usr/X11R6/bin/xterm",
            ]
            .into_iter(),
        );
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[test]
    fn cross_toolchain_sysroots_are_quiet() {
        // The cross compilers' target sysroots - *-suse-linux triples
        // and the bare-metal targets - are standard in distro practice
        // (issue #582).
        let dirs = FHSCheck::non_standard_dirs(
            [
                "/usr/riscv64-suse-linux/bin/ld",
                "/usr/aarch64-suse-linux/bin/ld",
                "/usr/arm-suse-linux-gnueabi/bin/ld",
                "/usr/x86_64-suse-linux/bin/ld",
                "/usr/avr/bin/avr-gcc",
                "/usr/amdgcn-amdhsa/lib/libclang_rt.builtins.a",
                "/usr/rx-elf/bin/rx-elf-gcc",
                "/usr/nvptx-none/bin/nvptx-none-ld",
                "/usr/bpf-none/bin/bpf-none-clang",
                "/usr/pru/bin/pru-gcc",
                "/usr/arm-none-eabi/bin/arm-none-eabi-gcc",
                "/usr/epiphany-elf/bin/epiphany-elf-gcc",
                "/usr/riscv64-elf/bin/riscv64-elf-gcc",
                "/usr/spu/bin/spu-gcc",
            ]
            .into_iter(),
        );
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[test]
    fn every_measured_cross_sysroot_is_quiet() {
        // Pin the whole measured set: an entry dropped from
        // FHS_USR_CROSS_SYSROOTS must fail here.
        assert_eq!(FHS_USR_CROSS_SYSROOTS.len(), 29);
        for sysroot in FHS_USR_CROSS_SYSROOTS {
            let path = format!("/usr/{sysroot}/bin/tool");
            let dirs = FHSCheck::non_standard_dirs([path.as_str()].into_iter());
            assert!(dirs.is_empty(), "{sysroot}: {dirs:?}");
        }
    }

    #[test]
    fn novel_usr_dir_still_fires() {
        let dirs = FHSCheck::non_standard_dirs(["/usr/frobnicate/bin/tool"].into_iter());
        assert_eq!(dirs, vec![("usr".to_string(), "frobnicate".to_string())]);
    }

    #[test]
    fn non_standard_var_dir_is_reported() {
        let dirs = FHSCheck::non_standard_dirs(["/var/custom/data"].into_iter());
        assert_eq!(dirs, vec![("var".to_string(), "custom".to_string())]);
    }

    #[test]
    fn var_adm_is_quiet() {
        // /var/adm is the OS's own admin directory: shipped by the
        // filesystem package itself and hosting SUSE's fillup
        // templates, so no package-side remedy exists for shipping it.
        let dirs =
            FHSCheck::non_standard_dirs(["/var/adm/fillup-templates/sysconfig.foo"].into_iter());
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[test]
    fn var_samba_still_fires() {
        // The one clearly package-side case on the audited row:
        // samba state normally lives under /var/lib/samba.
        let dirs = FHSCheck::non_standard_dirs(["/var/samba/locks/foo"].into_iter());
        assert_eq!(dirs, vec![("var".to_string(), "samba".to_string())]);
    }

    #[test]
    fn duplicates_are_deduplicated() {
        let dirs = FHSCheck::non_standard_dirs(
            ["/usr/weird/a", "/usr/weird/b", "/var/custom/c"].into_iter(),
        );
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn cross_sysroot_matches_needs_the_leading_component() {
        assert!(cross_sysroot_matches("/usr/avr"));
        assert!(cross_sysroot_matches("/usr/avr/"));
        assert!(cross_sysroot_matches("/usr/aarch64-suse-linux/bin/ld"));
        assert!(!cross_sysroot_matches("/usr"));
        assert!(!cross_sysroot_matches("/usr/"));
        assert!(!cross_sysroot_matches("/usr/avr2/bin/tool"));
        assert!(!cross_sysroot_matches("/usr/share/avr/bin/tool"));
        assert!(!cross_sysroot_matches("/opt/avr/bin/tool"));
    }

    #[test]
    fn non_usr_var_paths_are_ignored() {
        let dirs = FHSCheck::non_standard_dirs(["/etc/foo", "/opt/bar"].into_iter());
        assert!(dirs.is_empty(), "{dirs:?}");
    }
}
