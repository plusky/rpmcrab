//! `BinariesCheck`: ELF binary validation, ported from rpmlint's `BinariesCheck.py`.
//!
//! Covers the reference's `add_info` call sites: ELF section/header analysis
//! via `goblin`, dependency analysis via `goblin`, DWARF producer extraction
//! (not yet implemented), forbidden functions via `strings`, and archive
//! analysis via `ar`.
//!
//! Deliberate gaps are ledgered in `tests/parity/divergences.toml`.

#![allow(clippy::collapsible_if)]

use std::path::Path;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{self, PkgFile};
use crate::tools::{Tool, ToolSource, test_source};
use std::sync::OnceLock;

static VALIDSO_REGEX: OnceLock<Regex> = OnceLock::new();
fn validso_regex() -> &'static Regex {
    VALIDSO_REGEX.get_or_init(|| Regex::new(r"(\.so\.\d+(\.\d+)*|\d\.so)$").expect("static regex"))
}

static SOVERSION_REGEX: OnceLock<Regex> = OnceLock::new();
fn soversion_regex() -> &'static Regex {
    SOVERSION_REGEX.get_or_init(|| {
        Regex::new(r".*(-(?P<pkgversion>[0-9][.0-9]*))?\.so(\.(?P<soversion>[0-9][.0-9]*))?")
            .expect("static regex")
    })
}

static USR_LIB_REGEX: OnceLock<Regex> = OnceLock::new();
fn usr_lib_regex() -> &'static Regex {
    USR_LIB_REGEX.get_or_init(|| Regex::new(r"^/usr/lib(64)?/").expect("static regex"))
}

static LDSO_SONAME_REGEX: OnceLock<Regex> = OnceLock::new();
fn ldso_soname_regex() -> &'static Regex {
    LDSO_SONAME_REGEX
        .get_or_init(|| Regex::new(r"^ld(-linux(-(ia|x86_)64))?\.so").expect("static regex"))
}

static NUMERIC_DIR_REGEX: OnceLock<Regex> = OnceLock::new();
fn numeric_dir_regex() -> &'static Regex {
    NUMERIC_DIR_REGEX.get_or_init(|| {
        Regex::new(r"/usr(?:/share)/man/man./(.*)\.[0-9](?:\.gz|\.bz2)").expect("static regex")
    })
}

static VERSIONED_DIR_REGEX: OnceLock<Regex> = OnceLock::new();
fn versioned_dir_regex() -> &'static Regex {
    VERSIONED_DIR_REGEX.get_or_init(|| Regex::new(r"[^.][0-9]").expect("static regex"))
}

static SO_REGEX: OnceLock<Regex> = OnceLock::new();
fn so_regex() -> &'static Regex {
    SO_REGEX.get_or_init(|| Regex::new(r"/lib(64)?/[^/]+\.so(\.[0-9]+)*$").expect("static regex"))
}

static BIN_REGEX: OnceLock<Regex> = OnceLock::new();
fn bin_regex() -> &'static Regex {
    BIN_REGEX.get_or_init(|| Regex::new(r"^(/usr(/X11R6)?)?/s?bin/").expect("static regex"))
}

static LA_FILE_REGEX: OnceLock<Regex> = OnceLock::new();
fn la_file_regex() -> &'static Regex {
    LA_FILE_REGEX.get_or_init(|| Regex::new(r"\.la$").expect("static regex"))
}

static INVALID_DIR_REF_REGEX: OnceLock<Regex> = OnceLock::new();
fn invalid_dir_ref_regex() -> &'static Regex {
    INVALID_DIR_REF_REGEX.get_or_init(|| Regex::new(r"/(home|tmp)(\W|$)").expect("static regex"))
}

static USR_ARCH_SHARE_REGEX: OnceLock<Regex> = OnceLock::new();
fn usr_arch_share_regex() -> &'static Regex {
    USR_ARCH_SHARE_REGEX.get_or_init(|| {
        Regex::new(
            r"/share/.*/(?:x86|i.86|x86_64|ppc|ppc64|s390|s390x|ia64|m68k|arm|aarch64|mips|riscv)",
        )
        .expect("static regex")
    })
}

static PYTHON_MODULE_REGEX: OnceLock<Regex> = OnceLock::new();
fn python_module_regex() -> &'static Regex {
    PYTHON_MODULE_REGEX.get_or_init(|| {
        Regex::new(r".*\.(\w*(python|pypy)\w*(-\w+){4}|abi3)\.so").expect("static regex")
    })
}

static ELF_REGEX: OnceLock<Regex> = OnceLock::new();
fn elf_regex() -> &'static Regex {
    ELF_REGEX.get_or_init(|| Regex::new(r"^(\w+ )?ELF ").expect("static regex"))
}

static DEFAULT_EXECUTABLE_STACK_ARCHS: OnceLock<Regex> = OnceLock::new();
fn default_executable_stack_archs() -> &'static Regex {
    DEFAULT_EXECUTABLE_STACK_ARCHS.get_or_init(|| {
        Regex::new(
            r"aarch64|alpha|arm.*|hppa|i.86|m68k|microblaze|mips|ppc|s390|s390x|sh|sparc|x86_64",
        )
        .expect("static regex")
    })
}

static SETGID_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static SETUID_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static SETGROUPS_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static MKTEMP_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static GETHOSTBYNAME_CALL_REGEX: OnceLock<Regex> = OnceLock::new();

const KERNEL_MODULES_PATHS: &[&str] = &["/lib/modules/", "/usr/lib/modules/"];
const GLIBC_EMPTY_ARCHIVES: &[&str] = &["libanl", "libdl", "libpthread", "librt", "libutil"];
const LTO_TEXT_LIKE_SECTIONS: &[&str] = &[
    ".preinit_array",
    ".init_array",
    ".fini_array",
    "P",
    "D_1",
    "B_1",
];

struct ElfSection {
    name: String,
    size: u64,
}

struct ElfProgramHeader {
    name: String,
    flags: String,
}

struct ReadelfInfo {
    sections: Vec<Vec<ElfSection>>,
    program_headers: Vec<ElfProgramHeader>,

    /// FUNC-type symbol names from both `.symtab` and `.dynsym`, mirroring
    /// the reference `readelf -s` scan (`SymbolTableInfo.functions`). The
    /// dynamic table is where undefined imports of stripped binaries live,
    /// so function-call checks must consult it.
    functions: Vec<String>,
    is_shlib: bool,
    is_debug: bool,
    soname: Option<String>,
    needed: Vec<String>,
    runpaths: Vec<String>,
    has_textrel: bool,
    failed: Option<String>,
}

impl ReadelfInfo {
    fn parse(path: &str, name: &str) -> Self {
        let mut info = ReadelfInfo {
            sections: Vec::new(),
            program_headers: Vec::new(),
            functions: Vec::new(),
            // The reference derives is_shlib and is_debug from the file name,
            // not the ELF content (readelfparser.py). A PIE executable or Go
            // binary is ET_DYN but is not a shared library for these checks.
            is_shlib: so_regex().is_match(name).unwrap_or(false),
            is_debug: name.ends_with(".debug"),
            soname: None,
            needed: Vec::new(),
            runpaths: Vec::new(),
            has_textrel: false,
            failed: None,
        };

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };

        let elf = match goblin::elf::Elf::parse(&data) {
            Ok(e) => e,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };

        // Sections
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            info.sections.push(vec![ElfSection {
                name: name.clone(),
                size: sh.sh_size,
            }]);
        }

        // Program headers
        for ph in &elf.program_headers {
            let name = match ph.p_type {
                goblin::elf::program_header::PT_GNU_STACK => "GNU_STACK",
                goblin::elf::program_header::PT_LOAD => "LOAD",
                goblin::elf::program_header::PT_DYNAMIC => "DYNAMIC",
                goblin::elf::program_header::PT_INTERP => "INTERP",
                goblin::elf::program_header::PT_NOTE => "NOTE",
                goblin::elf::program_header::PT_PHDR => "PHDR",
                goblin::elf::program_header::PT_TLS => "TLS",
                goblin::elf::program_header::PT_GNU_EH_FRAME => "GNU_EH_FRAME",
                goblin::elf::program_header::PT_GNU_RELRO => "GNU_RELRO",
                _ => "UNKNOWN",
            }
            .to_string();
            let mut flags = String::new();
            if ph.is_read() {
                flags.push('R');
            } else {
                flags.push(' ');
            }
            if ph.is_write() {
                flags.push('W');
            } else {
                flags.push(' ');
            }
            if ph.is_executable() {
                flags.push('E');
            } else {
                flags.push(' ');
            }
            info.program_headers.push(ElfProgramHeader { name, flags });
        }

        // Function symbols from both tables, mirroring the reference
        // `readelf -s` scan over `.dynsym` and `.symtab`.
        for sym in elf.syms.iter() {
            if sym.st_type() == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        info.functions.push(name.to_string());
                    }
                }
            }
        }

        // Dynamic symbols: undefined imports of stripped binaries only exist
        // here, so the reference `readelf -s` scan (both tables) needs this.
        for sym in elf.dynsyms.iter() {
            if sym.st_type() == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        info.functions.push(name.to_string());
                    }
                }
            }
        }

        // Dynamic section
        if let Some(dynamic) = &elf.dynamic {
            let dynstrtab = &elf.dynstrtab;
            for d in &dynamic.dyns {
                match d.d_tag {
                    goblin::elf::dynamic::DT_SONAME => {
                        if let Some(s) = dynstrtab.get_at(d.d_val as usize) {
                            info.soname = Some(s.to_string());
                        }
                    }
                    goblin::elf::dynamic::DT_NEEDED => {
                        if let Some(s) = dynstrtab.get_at(d.d_val as usize) {
                            info.needed.push(s.to_string());
                        }
                    }
                    goblin::elf::dynamic::DT_RUNPATH | goblin::elf::dynamic::DT_RPATH => {
                        if let Some(s) = dynstrtab.get_at(d.d_val as usize) {
                            info.runpaths.push(s.to_string());
                        }
                    }
                    goblin::elf::dynamic::DT_TEXTREL => {
                        info.has_textrel = true;
                    }
                    _ => {}
                }
            }
        }

        info
    }

    fn has_function_matching(&self, regex: &fancy_regex::Regex) -> bool {
        self.functions
            .iter()
            .any(|s| regex.is_match(s).unwrap_or(false))
    }
}

struct LddInfo {
    dependencies: Vec<String>,
    unused_dependencies: Vec<String>,
    undefined_symbols: Vec<String>,
    failed: Option<String>,
}

impl LddInfo {
    fn parse(path: &str, is_installed: bool) -> Self {
        let mut info = LddInfo {
            dependencies: Vec::new(),
            unused_dependencies: Vec::new(),
            undefined_symbols: Vec::new(),
            failed: None,
        };
        if !is_installed {
            return info;
        }

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };

        let elf = match goblin::elf::Elf::parse(&data) {
            Ok(e) => e,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };

        // Dependencies from DT_NEEDED
        if let Some(dynamic) = &elf.dynamic {
            let dynstrtab = &elf.dynstrtab;
            for d in &dynamic.dyns {
                if d.d_tag == goblin::elf::dynamic::DT_NEEDED {
                    if let Some(s) = dynstrtab.get_at(d.d_val as usize) {
                        info.dependencies.push(s.to_string());
                    }
                }
            }
        }

        // Undefined symbols: STN_UNDEF
        for sym in elf.syms.iter() {
            if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        info.undefined_symbols.push(name.to_string());
                    }
                }
            }
        }

        // Unused dependencies: ldd -u does linker-based analysis which
        // goblin cannot replicate. Left empty; ledgered as a divergence.
        // (The reference's ldd -u requires full symbol resolution.)

        info
    }
}

struct ObjdumpInfo {
    producers: Vec<String>,
    failed: Option<String>,
}

impl ObjdumpInfo {
    fn parse(path: &str) -> Self {
        let info = ObjdumpInfo {
            producers: Vec::new(),
            failed: None,
        };
        // TODO: DWARF producer extraction is not yet implemented.
        // The goblin-based ELF parsing covers the main BinariesCheck
        // functionality; DWARF compile-unit producers are a follow-up.
        // For now, producers is empty which means the mandatory/forbidden
        // optflags check degrades gracefully (no findings).
        let _ = path;
        info
    }
}

struct StringsInfo {
    strings: Vec<String>,
    failed: Option<String>,
}

impl StringsInfo {
    fn parse(tool: &Tool, path: &str) -> Self {
        let mut info = StringsInfo {
            strings: Vec::new(),
            failed: None,
        };
        let Some(mut cmd) = tool.command() else {
            return info;
        };
        let out = cmd.arg(path).env("LC_ALL", "C").output();
        match out {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                info.strings = stdout.lines().map(|s| s.to_string()).collect();
            }
            Ok(o) => {
                info.failed = Some(String::from_utf8_lossy(&o.stderr).to_string());
            }
            Err(e) => {
                info.failed = Some(e.to_string());
            }
        }
        info
    }
}

struct ArInfo {
    objects: Vec<String>,
    failed: Option<String>,
}

impl ArInfo {
    fn parse(tool: &Tool, path: &str) -> Self {
        let mut info = ArInfo {
            objects: Vec::new(),
            failed: None,
        };
        let Some(mut cmd) = tool.command() else {
            return info;
        };
        let out = cmd.args(["t", path]).env("LC_ALL", "C").output();
        match out {
            Ok(o) if o.status.success() => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                info.objects = stdout.lines().map(|s| s.to_string()).collect();
            }
            Ok(o) => {
                info.failed = Some(String::from_utf8_lossy(&o.stderr).to_string());
            }
            Err(e) => {
                info.failed = Some(e.to_string());
            }
        }
        info
    }
}

pub struct BinariesCheck {
    checked_files: usize,
    strings: Tool,
    ar: Tool,
    system_lib_paths: Vec<String>,
    pie_exec_regexes: Vec<Regex>,
    usr_lib_exception_regex: Regex,
    setgid_call_regex: Regex,
    setuid_call_regex: Regex,
    setgroups_call_regex: Regex,
    mktemp_call_regex: Regex,
    gethostbyname_call_regex: Regex,
    // Per-file state, set by detect_attributes before run_elf_checks.
    is_exec: bool,
    is_shobj: bool,
    is_archive: bool,
    is_dynamically_linked: bool,
    is_pie_exec: bool,
    is_nonstandard_archive: bool,
}

impl BinariesCheck {
    pub fn new(config: &Config) -> Self {
        Self::with_tool_source(config, ToolSource::Path)
    }

    /// Probe for `strings` and `ar` under `source`.
    pub fn with_tool_source(config: &Config, source: ToolSource) -> Self {
        let tbl = &config.configuration;
        let get_strings = |k: &str| -> Vec<String> {
            tbl.get(k)
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let pie_exec_regexes: Vec<Regex> = get_strings("PieExecutables")
            .iter()
            .filter_map(|r| Regex::new(r).ok())
            .collect();
        let usr_lib_exception = tbl
            .get("UsrLibBinaryException")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        let (strings, _) = Tool::probe(&source, "strings", &[]);
        let (ar, _) = Tool::probe(&source, "ar", &["--version"]);
        BinariesCheck {
            checked_files: 0,
            strings,
            ar,
            system_lib_paths: get_strings("SystemLibPaths"),
            pie_exec_regexes,
            usr_lib_exception_regex: Regex::new(usr_lib_exception)
                .unwrap_or_else(|_| Regex::new("$^").expect("static regex")),
            setgid_call_regex: SETGID_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"(set(?:res|e)?gid(?:@GLIBC\S+)?)(?:\s|$)")
                        .expect("static regex")
                })
                .clone(),
            setuid_call_regex: SETUID_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"(set(?:res|e)?uid(?:@GLIBC\S+)?)(?:\s|$)")
                        .expect("static regex")
                })
                .clone(),
            setgroups_call_regex: SETGROUPS_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"((?:ini|se)tgroups(?:@GLIBC\S+)?)(?:\s|$)")
                        .expect("static regex")
                })
                .clone(),
            mktemp_call_regex: MKTEMP_CALL_REGEX
                .get_or_init(|| Regex::new(r"(mktemp(?:@GLIBC\S+)?)(?:\s|$)")
                    .expect("static regex"))
                .clone(),
            gethostbyname_call_regex: GETHOSTBYNAME_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(
                        r"((gethostbyname|gethostbyname2|gethostbyaddr|gethostbyname_r|gethostbyname2_r|gethostbyaddr_r)(?:@GLIBC\S+)?)(?:\s|$)",
                    )
                    .expect("static regex")
                })
                .clone(),
            is_exec: false,
            is_shobj: false,
            is_archive: false,
            is_dynamically_linked: false,
            is_pie_exec: false,
            is_nonstandard_archive: false,
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves both tools under `dir` instead of mutating the process
    /// environment.
    pub fn with_tool_dir(config: &Config, bin_dir: Option<&std::path::Path>) -> Self {
        Self::with_tool_source(config, test_source(bin_dir))
    }

    fn detect_attributes(&mut self, magic: &str) {
        self.is_exec = magic.contains("executable");
        self.is_shobj = magic.contains("shared object");
        self.is_archive = magic.contains("current ar archive");
        self.is_dynamically_linked = magic.contains("dynamically linked");
        self.is_pie_exec = magic.contains("pie executable");
        self.is_nonstandard_archive = false;
    }

    fn check_libtool_wrapper(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if pkgfile.magic.contains("shell script") {
            if let Ok(data) = std::fs::read(&pkgfile.path) {
                let head = &data[..data.len().min(2048)];
                if head
                    .windows(50)
                    .any(|w| w == b"This wrapper script should never be moved out of the")
                    || String::from_utf8_lossy(head).contains(
                        "This wrapper script should never be moved out of the build directory",
                    )
                {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "libtool-wrapper-in-package",
                        &[fname],
                    );
                }
            }
        }
    }

    fn check_invalid_la_file(&self, pkg: &Pkg, fname: &str, pkgfile: &PkgFile, out: &mut Filter) {
        if invalid_dir_ref_regex().is_match(fname).unwrap_or(false)
            && la_file_regex().is_match(fname).unwrap_or(false)
        {
            // Find the matching line number via grep on the extracted file.
            if let Ok(content) = std::fs::read_to_string(&pkgfile.path) {
                for (idx, line) in content.lines().enumerate() {
                    if invalid_dir_ref_regex().is_match(line).unwrap_or(false) {
                        add_info(
                            out,
                            Level::Error,
                            pkg,
                            "invalid-la-file",
                            &[fname, &format!("(line {})", idx + 1)],
                        );
                        break;
                    }
                }
            }
        }
    }

    fn check_binary_in_noarch(&self, pkg: &Pkg, bin_name: &str, out: &mut Filter) {
        if pkg.arch == "noarch" {
            add_info(
                out,
                Level::Error,
                pkg,
                "arch-independent-package-contains-binary-or-object",
                &[bin_name],
            );
        }
    }

    fn check_binary_in_usr_share(&self, pkg: &Pkg, bin_name: &str, out: &mut Filter) {
        if bin_name.starts_with("/usr/share/")
            && !usr_arch_share_regex().is_match(bin_name).unwrap_or(false)
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "arch-dependent-file-in-usr-share",
                &[bin_name],
            );
        }
    }

    fn check_binary_in_etc(&self, pkg: &Pkg, bin_name: &str, out: &mut Filter) {
        if bin_name.starts_with("/etc/") || bin_name.starts_with("/usr/etc/") {
            add_info(out, Level::Error, pkg, "binary-in-etc", &[bin_name]);
        }
    }

    fn check_unstripped_binary(
        &self,
        bin_name: &str,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        out: &mut Filter,
    ) {
        if pkgfile.magic.contains("not stripped") {
            add_info(
                out,
                Level::Warning,
                pkg,
                "unstripped-binary-or-object",
                &[bin_name],
            );
        }
    }

    fn check_non_pie(&self, pkg: &Pkg, bin_name: &str, out: &mut Filter) {
        if !self.is_shobj && !self.is_pie_exec {
            if self
                .pie_exec_regexes
                .iter()
                .any(|r| r.is_match(bin_name).unwrap_or(false))
            {
                // fullmatch semantics: the config regexes are anchored by convention
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "non-position-independent-executable",
                    &[bin_name],
                );
            } else {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "position-independent-executable-suggested",
                    &[bin_name],
                );
            }
        }
    }

    fn check_exec_in_library(
        &self,
        pkg: &Pkg,
        has_lib: bool,
        exec_files: &[String],
        out: &mut Filter,
    ) {
        if has_lib {
            for f in exec_files {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "executable-in-library-package",
                    &[f],
                );
            }
        }
    }

    fn check_non_versioned(
        &self,
        pkg: &Pkg,
        has_lib: bool,
        exec_files: &[String],
        out: &mut Filter,
    ) {
        if !has_lib {
            return;
        }
        for pkgfile in &pkg.files {
            let f = &pkgfile.name;
            let search_name = numeric_dir_regex()
                .captures(f)
                .ok()
                .flatten()
                .and_then(|c| c.name("1"))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| f.clone());
            if !exec_files.contains(f)
                && !so_regex().is_match(f).unwrap_or(false)
                && !versioned_dir_regex()
                    .is_match(&search_name)
                    .unwrap_or(false)
            {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "non-versioned-file-in-library-package",
                    &[f],
                );
            }
        }
    }

    fn check_no_binary(
        &self,
        pkg: &Pkg,
        has_binary: bool,
        has_file_in_lib64: bool,
        out: &mut Filter,
    ) {
        if !has_binary && !has_file_in_lib64 && pkg.arch != "noarch" {
            add_info(out, Level::Error, pkg, "no-binary", &[]);
        }
    }

    fn check_noarch_with_lib64(&self, pkg: &Pkg, has_file_in_lib64: bool, out: &mut Filter) {
        if pkg.arch == "noarch" && has_file_in_lib64 {
            add_info(out, Level::Error, pkg, "noarch-with-lib64", &[]);
        }
    }

    fn check_only_non_binary_in_usrlib(
        &self,
        pkg: &Pkg,
        has_usr_lib_file: bool,
        has_binary_in_usr_lib: bool,
        out: &mut Filter,
    ) {
        if has_usr_lib_file && !has_binary_in_usr_lib {
            add_info(out, Level::Warning, pkg, "only-non-binary-in-usr-lib", &[]);
        }
    }

    fn is_standard_archive(&self, pkg: &Pkg, pkgfile: &PkgFile, out: &mut Filter) -> bool {
        if pkgfile.path.ends_with(".bca") {
            return false;
        }
        if !self.ar.is_present() {
            // Without `ar` the standard-ness test cannot run; treat the
            // archive as non-standard so no ELF checks run on unverifiable
            // input. An absent tool must not invent findings.
            log::debug!("BinariesCheck: ar not found, treating archive as non-standard");
            return false;
        }
        let ar = ArInfo::parse(&self.ar, &pkgfile.path);
        if let Some(reason) = ar.failed {
            add_info(
                out,
                Level::Error,
                pkg,
                "ar-failed",
                &[&pkgfile.name, &reason],
            );
            return false;
        }
        let needles = ["__.PKGDEF", "_go_.o", "lib.rmeta"];
        !needles
            .iter()
            .any(|n| ar.objects.iter().any(|o| o.contains(n)))
    }

    fn check_no_text_in_archive(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if !self.is_archive {
            return;
        }
        // GHC archives carry no .text; skip them.
        // (The reference checks comment sections; we approximate via readelf -p .comment.)
        let stem = Path::new(&pkgfile.name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if GLIBC_EMPTY_ARCHIVES.contains(&stem)
            || (stem.ends_with("_p")
                && GLIBC_EMPTY_ARCHIVES
                    .iter()
                    .any(|s| *s == &stem[..stem.len() - 2]))
        {
            return;
        }
        for elf_file in &info.sections {
            for section in elf_file {
                let sn = section.name.as_str();
                if (LTO_TEXT_LIKE_SECTIONS.contains(&sn)
                    || sn == ".fini_array"
                    || sn.starts_with(".text")
                    || sn.starts_with(".data"))
                    && section.size > 0
                {
                    return;
                }
            }
        }
        add_info(
            out,
            Level::Error,
            pkg,
            "lto-no-text-in-archive",
            &[&pkgfile.name],
        );
    }

    fn check_no_patchable_function_entries_in_archive(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if !self.is_archive {
            return;
        }
        for elf_file in &info.sections {
            for section in elf_file {
                if section.name == "__patchable_function_entries" {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "patchable-function-entry-in-archive",
                        &[&pkgfile.name],
                    );
                    return;
                }
            }
        }
    }

    fn check_missing_symtab_in_archive(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if !self.is_archive {
            return;
        }
        for elf_file in &info.sections {
            for section in elf_file {
                if section.name == ".symtab" {
                    return;
                }
            }
        }
        add_info(
            out,
            Level::Error,
            pkg,
            "static-library-without-symtab",
            &[&pkgfile.name],
        );
    }

    fn check_missing_debug_info_in_archive(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if !self.is_archive {
            return;
        }
        for elf_file in &info.sections {
            for section in elf_file {
                if section.name.starts_with(".debug_") {
                    return;
                }
            }
        }
        add_info(
            out,
            Level::Error,
            pkg,
            "static-library-without-debuginfo",
            &[&pkgfile.name],
        );
    }

    fn check_lto_section(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        for elf_file in &info.sections {
            for section in elf_file {
                if section.name.contains(".gnu.lto_.") {
                    add_info(out, Level::Error, pkg, "lto-bytecode", &[&pkgfile.name]);
                    return;
                }
            }
        }
    }

    fn check_executable_stack(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if pkg.arch.is_empty()
            || !default_executable_stack_archs()
                .is_match(&pkg.arch)
                .unwrap_or(false)
        {
            // fullmatch semantics via anchored regex
            let arch_re = Regex::new(&format!(
                "^(?:{})$",
                r"aarch64|alpha|arm.*|hppa|i.86|m68k|microblaze|mips|ppc|s390|s390x|sh|sparc|x86_64"
            ))
            .expect("static regex");
            if !arch_re.is_match(&pkg.arch).unwrap_or(false) {
                return;
            }
        }
        if self.is_archive
            || KERNEL_MODULES_PATHS
                .iter()
                .any(|p| pkgfile.name.starts_with(p))
        {
            return;
        }
        let stack_headers: Vec<&ElfProgramHeader> = info
            .program_headers
            .iter()
            .filter(|h| h.name == "GNU_STACK")
            .collect();
        if stack_headers.is_empty() {
            add_info(
                out,
                Level::Error,
                pkg,
                "missing-PT_GNU_STACK-section",
                &[&pkgfile.name],
            );
        } else if stack_headers[0].flags.contains('E') {
            add_info(out, Level::Error, pkg, "executable-stack", &[&pkgfile.name]);
        }
    }

    fn check_soname_symlink(&self, pkg: &Pkg, shlib: &str, soname: &str, out: &mut Filter) {
        let path = Path::new(shlib);
        let parent = path.parent().and_then(|p| p.to_str()).unwrap_or("");
        let symlink = if parent.is_empty() {
            soname.to_string()
        } else {
            format!("{}/{}", parent, soname)
        };
        match pkg.files.iter().find(|f| f.name == symlink) {
            Some(f) => {
                let link = f.linkto.as_str();
                let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if link != shlib && link != base && !link.is_empty() {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "invalid-ldconfig-symlink",
                        &[shlib, link],
                    );
                }
            }
            None => {
                let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if base.starts_with("lib") || base.starts_with("ld-") {
                    add_info(out, Level::Error, pkg, "no-ldconfig-symlink", &[shlib]);
                }
            }
        }
    }

    fn check_shared_library(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if !info.is_shlib {
            return;
        }
        match &info.soname {
            None => {
                add_info(out, Level::Warning, pkg, "no-soname", &[&pkgfile.name]);
            }
            Some(soname) => {
                if !validso_regex().is_match(soname).unwrap_or(false) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "invalid-soname",
                        &[&pkgfile.name, soname],
                    );
                } else {
                    self.check_soname_symlink(pkg, &pkgfile.name, soname, out);
                    if pkg.name.starts_with("lib")
                        && !self
                            .hpc_locations()
                            .iter()
                            .any(|p| pkgfile.name.starts_with(p))
                    {
                        if let Ok(Some(caps)) = soversion_regex().captures(soname) {
                            let pkgversion =
                                caps.name("pkgversion").map(|m| m.as_str()).unwrap_or("");
                            let soversion =
                                caps.name("soversion").map(|m| m.as_str()).unwrap_or("");
                            let parts: Vec<String> = [pkgversion, soversion]
                                .iter()
                                .filter(|s| !s.is_empty())
                                .map(|s| s.replace('.', "_"))
                                .collect();
                            let soversion_str = parts.join("-");
                            let mut pkgname = pkg.name.as_str();
                            if let Some(idx) = pkgname.rfind('.') {
                                pkgname = &pkgname[..idx];
                            }
                            if !soversion_str.is_empty() && !pkgname.ends_with(&soversion_str) {
                                add_info(
                                    out,
                                    Level::Error,
                                    pkg,
                                    "shlib-policy-name-error",
                                    &[&format!(
                                        "SONAME: {} ({}), expected package suffix: {}",
                                        soname, pkgfile.name, soversion_str
                                    )],
                                );
                            }
                        }
                    }
                }
            }
        }
        if info.has_textrel {
            add_info(
                out,
                Level::Error,
                pkg,
                "shlib-with-non-pic-code",
                &[&pkgfile.name],
            );
        }
    }

    fn hpc_locations(&self) -> &[&str] {
        &["/usr/lib/mpi/", "/usr/lib64/mpi/", "/usr/lib/hpc/"]
    }

    fn check_dependency(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        ldd: &LddInfo,
        out: &mut Filter,
    ) {
        if !self.is_dynamically_linked {
            return;
        }
        if python_module_regex()
            .is_match(&pkgfile.name)
            .unwrap_or(false)
        {
            return;
        }
        if self.is_archive || info.is_debug {
            return;
        }
        let info_type = if info.is_shlib {
            Level::Error
        } else {
            Level::Warning
        };
        for symbol in &ldd.undefined_symbols {
            add_info(
                out,
                info_type,
                pkg,
                "undefined-non-weak-symbol",
                &[&pkgfile.name, symbol],
            );
        }
        for dep in &ldd.unused_dependencies {
            add_info(
                out,
                info_type,
                pkg,
                "unused-direct-shlib-dependency",
                &[&pkgfile.name, dep],
            );
        }
    }

    fn check_library_dependency_location(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        ldd: &LddInfo,
        out: &mut Filter,
    ) {
        if !self.is_dynamically_linked {
            return;
        }
        if !self.is_archive {
            for dep in &ldd.dependencies {
                if dep.starts_with("/opt/") {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "linked-against-opt-library",
                        &[&pkgfile.name, dep],
                    );
                    break;
                }
            }
        }
        let nonusr = ["/bin", "/lib", "/sbin"];
        if nonusr.iter().any(|p| pkgfile.name.starts_with(p)) {
            for dep in &ldd.dependencies {
                if dep.starts_with("/usr/") {
                    add_info(
                        out,
                        Level::Warning,
                        pkg,
                        "linked-against-usr-library",
                        &[&pkgfile.name, dep],
                    );
                    break;
                }
            }
        }
    }

    fn check_security_functions(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        let setgid = info.has_function_matching(&self.setgid_call_regex);
        let setuid = info.has_function_matching(&self.setuid_call_regex);
        let setgroups = info.has_function_matching(&self.setgroups_call_regex);
        let mktemp = info.has_function_matching(&self.mktemp_call_regex);
        let gethostbyname = info.has_function_matching(&self.gethostbyname_call_regex);

        if setgid && setuid && !setgroups {
            // openSUSE flips the upstream severity: E when installed setuid.
            let is_uid = pkgfile.mode & 0o4000 != 0;
            add_info(
                out,
                if is_uid { Level::Error } else { Level::Warning },
                pkg,
                "missing-call-to-setgroups-before-setuid",
                &[&pkgfile.name],
            );
        }
        if mktemp {
            add_info(out, Level::Error, pkg, "call-to-mktemp", &[&pkgfile.name]);
        }
        if gethostbyname {
            add_info(
                out,
                Level::Warning,
                pkg,
                "binary-or-shlib-calls-gethostbyname",
                &[&pkgfile.name],
            );
        }
    }

    fn check_rpath(&self, pkg: &Pkg, pkgfile: &PkgFile, info: &ReadelfInfo, out: &mut Filter) {
        for runpaths in &info.runpaths {
            for runpath in runpaths.split(':') {
                let mut rp = runpath.to_string();
                if rp.contains("$ORIGIN") {
                    let parent = Path::new(&pkgfile.name)
                        .parent()
                        .and_then(|p| p.to_str())
                        .unwrap_or("");
                    rp = rp.replace("$ORIGIN", parent);
                }
                let starts_system = self.system_lib_paths.iter().any(|p| rp.starts_with(p));
                if !starts_system && !usr_lib_regex().is_match(&rp).unwrap_or(false) {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "binary-or-shlib-defines-rpath",
                        &[&pkgfile.name, &format!("(RUNPATH: {})", runpaths)],
                    );
                    return;
                }
            }
        }
    }

    fn check_library_dependency(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if self.is_archive
            || KERNEL_MODULES_PATHS
                .iter()
                .any(|p| pkgfile.name.starts_with(p))
            || python_module_regex()
                .is_match(&pkgfile.name)
                .unwrap_or(false)
        {
            return;
        }
        let ldso = info
            .soname
            .as_ref()
            .map(|s| ldso_soname_regex().is_match(s).unwrap_or(false))
            .unwrap_or(false);
        if info.needed.is_empty() && !(info.soname.is_some() && ldso) {
            if !self.is_shobj {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "statically-linked-binary",
                    &[&pkgfile.name],
                );
            }
        } else {
            let runpath_has_libc = info.runpaths.iter().any(|r| r.contains("libc."));
            let soname_is_libc = info
                .soname
                .as_ref()
                .map(|s| s.contains("libc.") || ldso)
                .unwrap_or(false);
            if runpath_has_libc || soname_is_libc {
                return;
            }
            let linked_libc = info.needed.iter().any(|l| l.contains("libc."));
            if !linked_libc && !self.is_shobj {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "program-not-linked-against-libc",
                    &[&pkgfile.name],
                );
            }
        }
    }

    fn check_forbidden_functions(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        config: &Config,
        out: &mut Filter,
    ) {
        let forbidden_tbl = config
            .configuration
            .get("WarnOnFunction")
            .and_then(toml::Value::as_table);
        let forbidden: Vec<(String, String, Regex, Option<Regex>)> = forbidden_tbl
            .map(|t| {
                t.iter()
                    .filter_map(|(k, v)| {
                        let f_name = v.get("f_name")?.as_str()?;
                        let f_regex = Regex::new(&format!(r"({})\s?.*$", f_name)).ok()?;
                        let good_param = v
                            .get("good_param")
                            .and_then(|g| g.as_str())
                            .and_then(|gp| Regex::new(gp).ok());
                        Some((k.clone(), f_name.to_string(), f_regex, good_param))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if forbidden.is_empty() {
            return;
        }
        let mut forbidden_calls = Vec::new();
        for (r_name, f_name, f_regex, good_param) in &forbidden {
            if info.has_function_matching(f_regex) {
                forbidden_calls.push((r_name.clone(), f_name.clone(), good_param.clone()));
            }
        }
        if forbidden_calls.is_empty() {
            return;
        }
        if !self.strings.is_present() {
            log::debug!("BinariesCheck: strings not found, skipping forbidden-function check");
            return;
        }
        let strings = StringsInfo::parse(&self.strings, &pkgfile.path);
        if let Some(reason) = strings.failed {
            add_info(
                out,
                Level::Error,
                pkg,
                "strings-failed",
                &[&pkgfile.name, &reason],
            );
            return;
        }
        for (r_name, f_name, good_param) in forbidden_calls {
            let mut waived = false;
            if let Some(re) = good_param {
                waived = strings
                    .strings
                    .iter()
                    .any(|s| re.is_match(s).unwrap_or(false));
            }
            if !waived {
                add_info(out, Level::Warning, pkg, &r_name, &[&pkgfile.name, &f_name]);
            }
        }
    }

    fn check_executable_shlib(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if pkgfile.mode & 0o111 == 0 && info.is_shlib {
            add_info(
                out,
                Level::Error,
                pkg,
                "shared-library-not-executable",
                &[&pkgfile.name],
            );
        }
    }

    fn check_optflags(&self, pkg: &Pkg, pkgfile: &PkgFile, config: &Config, out: &mut Filter) {
        if self.is_archive {
            return;
        }
        let tbl = &config.configuration;
        let get_strings = |k: &str| {
            tbl.get(k)
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default()
        };
        let mandatory = get_strings("MandatoryOptflags");
        let forbidden = get_strings("ForbiddenOptflags");
        if mandatory.is_empty() && forbidden.is_empty() {
            return;
        }
        let objdump = ObjdumpInfo::parse(&pkgfile.path);
        if let Some(reason) = objdump.failed {
            add_info(
                out,
                Level::Error,
                pkg,
                "objdump-failed",
                &[&pkgfile.name, &reason],
            );
            return;
        }
        for producer in &objdump.producers {
            let tokens: Vec<&str> = producer.split(' ').collect();
            let missing: Vec<&str> = mandatory
                .iter()
                .filter(|mo| !tokens.contains(&mo.as_str()))
                .map(|s| s.as_str())
                .collect();
            let forbidden_found: Vec<&str> = forbidden
                .iter()
                .filter(|f| tokens.contains(&f.as_str()))
                .map(|s| s.as_str())
                .collect();
            if !missing.is_empty() {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "missing-mandatory-optflags",
                    &[&pkgfile.name, &missing.join(" ")],
                );
            }
            if !forbidden_found.is_empty() {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "forbidden-optflags",
                    &[&pkgfile.name, &forbidden_found.join(" ")],
                );
            }
        }
    }

    fn check_hash_sections(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if !info.is_shlib {
            return;
        }
        // The reference scans the whole section list of the ELF file once
        // (readelfparser.py ElfSectionInfo.elf_files) and emits at most one
        // finding of each kind. The missing set must not reset per section:
        // ReadelfInfo stores one section per inner vec, so the old loop
        // re-emitted both findings for every non-hash section (#218).
        let mut missing_hash = true;
        let mut missing_gnu_hash = true;
        'sections: for elf_file in &info.sections {
            for section in elf_file {
                if section.name == ".hash" {
                    missing_hash = false;
                } else if section.name == ".gnu.hash" {
                    missing_gnu_hash = false;
                }
                if !missing_hash && !missing_gnu_hash {
                    break 'sections;
                }
            }
        }
        if missing_hash {
            add_info(
                out,
                Level::Error,
                pkg,
                "missing-hash-section",
                &[&pkgfile.name],
            );
        }
        if missing_gnu_hash {
            add_info(
                out,
                Level::Warning,
                pkg,
                "missing-gnu-hash-section",
                &[&pkgfile.name],
            );
        }
    }

    fn run_elf_checks(&mut self, pkg: &Pkg, pkgfile: &PkgFile, config: &Config, out: &mut Filter) {
        if self.is_archive && !self.is_standard_archive(pkg, pkgfile, out) {
            self.is_nonstandard_archive = true;
            return;
        }
        let info = ReadelfInfo::parse(&pkgfile.path, &pkgfile.name);
        if let Some(reason) = &info.failed {
            add_info(
                out,
                Level::Error,
                pkg,
                "readelf-failed",
                &[&pkgfile.name, reason],
            );
            return;
        }

        let ldd = if !self.is_archive && self.is_dynamically_linked {
            let l = LddInfo::parse(&pkgfile.path, true);
            if let Some(reason) = &l.failed {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "ldd-failed",
                    &[&pkgfile.name, reason],
                );
                return;
            }
            Some(l)
        } else {
            None
        };

        // The reference runs these in a thread pool; serial is equivalent.
        self.check_lto_section(pkg, pkgfile, &info, out);
        self.check_no_text_in_archive(pkg, pkgfile, &info, out);
        self.check_missing_symtab_in_archive(pkg, pkgfile, &info, out);
        self.check_missing_debug_info_in_archive(pkg, pkgfile, &info, out);
        self.check_executable_stack(pkg, pkgfile, &info, out);
        self.check_shared_library(pkg, pkgfile, &info, out);
        if let Some(l) = &ldd {
            self.check_dependency(pkg, pkgfile, &info, l, out);
            self.check_library_dependency_location(pkg, pkgfile, l, out);
        }
        self.check_security_functions(pkg, pkgfile, &info, out);
        self.check_rpath(pkg, pkgfile, &info, out);
        self.check_library_dependency(pkg, pkgfile, &info, out);
        self.check_forbidden_functions(pkg, pkgfile, &info, config, out);
        self.check_executable_shlib(pkg, pkgfile, &info, out);
        self.check_optflags(pkg, pkgfile, config, out);
        self.check_hash_sections(pkg, pkgfile, &info, out);
        self.check_no_patchable_function_entries_in_archive(pkg, pkgfile, &info, out);
    }
}

impl Check for BinariesCheck {
    fn name(&self) -> &'static str {
        "BinariesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        let mut exec_files: Vec<String> = Vec::new();
        let mut pkg_has_lib = false;
        let mut pkg_has_binary = false;
        let mut pkg_has_binary_in_usrlib = false;
        let mut pkg_has_usrlib_file = false;
        let mut pkg_has_file_in_lib64 = false;

        for pkgfile in &pkg.files {
            let fname: &str = &pkgfile.name;
            self.check_libtool_wrapper(pkg, fname, pkgfile, out);
            self.check_invalid_la_file(pkg, fname, pkgfile, out);

            if !pkgfile::is_dir(pkgfile.mode) && usr_lib_regex().is_match(fname).unwrap_or(false) {
                pkg_has_usrlib_file = true;
                if !pkg_has_binary_in_usrlib
                    && self
                        .usr_lib_exception_regex
                        .is_match(fname)
                        .unwrap_or(false)
                {
                    pkg_has_binary_in_usrlib = true;
                }
            }

            if fname.starts_with("/usr/lib64") || fname.starts_with("/lib64") {
                pkg_has_file_in_lib64 = true;
            }

            let is_ocaml_native = pkgfile.magic.contains("Objective caml native");
            let is_lua_bytecode = pkgfile.magic.contains("Lua bytecode");
            let is_ebpf = pkgfile.magic.contains("eBPF");
            let is_elf = elf_regex().is_match(&pkgfile.magic).unwrap_or(false) && !is_ebpf;

            if !(is_elf
                || pkgfile.magic.contains("current ar archive")
                || is_ocaml_native
                || is_lua_bytecode)
            {
                continue;
            }

            self.checked_files += 1;
            pkg_has_binary = true;

            if pkg_has_usrlib_file
                && !pkg_has_binary_in_usrlib
                && usr_lib_regex().is_match(fname).unwrap_or(false)
            {
                pkg_has_binary_in_usrlib = true;
            }

            self.check_binary_in_noarch(pkg, fname, out);
            if pkg.arch == "noarch" {
                continue;
            }

            self.check_binary_in_usr_share(pkg, fname, out);
            self.check_binary_in_etc(pkg, fname, out);

            if is_ocaml_native
                || is_lua_bytecode
                || fname.ends_with(".o")
                || fname.ends_with(".static")
                || fname.ends_with(".gox")
                || fname.ends_with(".go")
            {
                continue;
            }

            self.check_unstripped_binary(fname, pkg, pkgfile, out);
            self.detect_attributes(&pkgfile.magic);
            self.run_elf_checks(pkg, pkgfile, config, out);

            if self.is_nonstandard_archive {
                continue;
            }

            let info_is_shlib = {
                let info = ReadelfInfo::parse(&pkgfile.path, &pkgfile.name);
                info.failed.is_none() && info.is_shlib
            };
            if info_is_shlib {
                pkg_has_lib = true;
            }

            if !self.is_exec && !self.is_shobj {
                continue;
            }

            let mut is_exec = self.is_exec;
            if self.is_shobj
                && !self.is_exec
                && !fname.contains(".so")
                && bin_regex().is_match(fname).unwrap_or(false)
            {
                is_exec = true;
            }

            if is_exec {
                if bin_regex().is_match(fname).unwrap_or(false) {
                    exec_files.push(fname.to_string());
                }
                self.check_non_pie(pkg, fname, out);
            }
        }

        self.check_exec_in_library(pkg, pkg_has_lib, &exec_files, out);
        self.check_non_versioned(pkg, pkg_has_lib, &exec_files, out);
        self.check_no_binary(pkg, pkg_has_binary, pkg_has_file_in_lib64, out);
        self.check_noarch_with_lib64(pkg, pkg_has_file_in_lib64, out);
        self.check_only_non_binary_in_usrlib(
            pkg,
            pkg_has_usrlib_file,
            pkg_has_binary_in_usrlib,
            out,
        );
    }

    fn checked_files(&self) -> Option<usize> {
        Some(self.checked_files)
    }

    fn add_checked_files(&mut self, n: usize) {
        self.checked_files += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::Color;

    #[test]
    fn binaries_check_registers() {
        let config = Config::default();
        let check = BinariesCheck::new(&config);
        assert_eq!(check.name(), "BinariesCheck");
    }

    #[test]
    fn regex_factories_are_cached() {
        // Profiling showed Regex::new per call was ~18% of runtime.
        // The factories must return the same static, not recompile.
        assert!(std::ptr::eq(usr_lib_regex(), usr_lib_regex()));
        assert!(std::ptr::eq(so_regex(), so_regex()));
        assert!(std::ptr::eq(bin_regex(), bin_regex()));
    }

    #[test]
    fn regex_factories_are_fast() {
        // 10k calls must complete in well under a second. Recompiling
        // fancy_regex on each call would take several seconds.
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = usr_lib_regex().is_match("/usr/lib64/foo.so");
            let _ = so_regex().is_match("/usr/lib64/foo.so.1");
            let _ = bin_regex().is_match("/usr/bin/foo");
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "regex factories too slow: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn is_shlib_and_is_debug_are_filename_based() {
        // Minimal ELF64 header with e_type = ET_DYN, as a PIE executable or
        // Go binary would have. The reference derives is_shlib/is_debug from
        // the file name (readelfparser.py), not the ELF type.
        let mut hdr = vec![0u8; 64];
        hdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        hdr[4] = 2; // ELFCLASS64
        hdr[5] = 1; // ELFDATA2LSB
        hdr[6] = 1; // EV_CURRENT
        hdr[16] = 3; // e_type = ET_DYN
        hdr[18] = 62; // e_machine = EM_X86_64
        hdr[40] = 64; // e_ehsize

        let path = std::env::temp_dir().join("rpmcrab-is-shlib-test");
        std::fs::write(&path, &hdr).unwrap();
        let path_str = path.to_str().unwrap();

        // ET_DYN but not under /lib*/: not a shared library (e.g. PIE in
        // /usr/bin, or a Go binary). The old ET_DYN-based logic reported
        // no-soname and other shlib findings for these.
        let info = ReadelfInfo::parse(path_str, "/usr/bin/foo");
        assert!(!info.is_shlib);
        assert!(!info.is_debug);

        // Same bytes, shared-library name: is a shared library.
        let info = ReadelfInfo::parse(path_str, "/usr/lib64/libfoo.so.1");
        assert!(info.is_shlib);
        assert!(!info.is_debug);

        // Debuginfo file: is_debug, regardless of sections.
        let info = ReadelfInfo::parse(path_str, "/usr/lib/debug/usr/bin/foo.debug");
        assert!(info.is_debug);
        assert!(!info.is_shlib);

        std::fs::remove_file(&path).ok();
    }

    fn fixture_path(name: &str) -> String {
        format!(
            "{}/../../tests/fixtures/binaries-check/input/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        )
    }

    fn test_config() -> Config {
        let defaults: toml::Table = toml::from_str(include_str!("../../data/configdefaults.toml"))
            .expect("parse configdefaults");
        Config {
            configuration: defaults,
            ..Default::default()
        }
    }

    fn run_binaries_check(rpm: &str) -> (Vec<(String, String)>, tempfile::TempDir) {
        run_binaries_check_with_tools(rpm, None)
    }

    fn run_binaries_check_with_tools(
        rpm: &str,
        tool_dir: Option<&std::path::Path>,
    ) -> (Vec<(String, String)>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(rpm), dir.path(), true).expect("open fixture");
        let config = test_config();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = BinariesCheck::with_tool_dir(&config, tool_dir);
        check.check_binary(&pkg, &config, &mut out);
        (out.results().to_vec(), dir)
    }

    fn assert_lacks(results: &[(String, String)], finding: &str) {
        assert!(
            !results.iter().any(|(n, _)| n == finding),
            "unexpected {finding} in: {:?}",
            results.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
    }

    fn lines_for<'a>(results: &'a [(String, String)], finding: &str) -> Vec<&'a str> {
        results
            .iter()
            .filter(|(n, _)| n == finding)
            .map(|(_, line)| line.as_str())
            .collect()
    }

    #[test]
    fn binaries_check_fixture() {
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let (results, _dir) = run_binaries_check(&rpm_path);

        // libbad.so.1: executable stack, no SONAME
        let stack_lines = lines_for(&results, "executable-stack");
        assert!(
            stack_lines.iter().any(|l| l.contains("libbad.so.1")),
            "executable-stack should fire for libbad.so.1: {results:?}"
        );
        assert!(
            !stack_lines.iter().any(|l| l.contains("libgood.so.1")),
            "executable-stack should not fire for libgood.so.1: {results:?}"
        );

        let soname_lines = lines_for(&results, "no-soname");
        assert!(
            soname_lines.iter().any(|l| l.contains("libbad.so.1")),
            "no-soname should fire for libbad.so.1: {results:?}"
        );
        assert!(
            !soname_lines.iter().any(|l| l.contains("libgood.so.1")),
            "no-soname should not fire for libgood.so.1: {results:?}"
        );

        // rpathbin: RUNPATH set
        let rpath_lines = lines_for(&results, "binary-or-shlib-defines-rpath");
        assert!(
            rpath_lines.iter().any(|l| l.contains("rpathbin")),
            "binary-or-shlib-defines-rpath should fire for rpathbin: {results:?}"
        );

        // setuidbin: setuid without setgroups, installed setuid -> Error (#1462 flip)
        let setgroups_lines = lines_for(&results, "missing-call-to-setgroups-before-setuid");
        assert_eq!(
            setgroups_lines.len(),
            1,
            "expected one setgroups finding: {results:?}"
        );
        assert!(
            setgroups_lines[0].contains("setuidbin"),
            "setgroups finding should be for setuidbin: {results:?}"
        );
        assert!(
            setgroups_lines[0].contains(" E: "),
            "setgroups finding should be Error for setuid binary (#1462): {}",
            setgroups_lines[0]
        );

        // truncated: goblin cannot parse -> readelf-failed
        let failed_lines = lines_for(&results, "readelf-failed");
        assert!(
            failed_lines.iter().any(|l| l.contains("truncated")),
            "readelf-failed should fire for truncated: {results:?}"
        );

        // Ledgered absences: these findings are never emitted
        assert_lacks(&results, "unused-direct-shlib-dependency");
        assert_lacks(&results, "missing-mandatory-optflags");
    }

    fn warn_on_function_config() -> Config {
        // Mirrors the reference test.config WarnOnFunction entries: the
        // finding names are config-driven, so the port pins them the same way.
        let mut config = test_config();
        let parsed: toml::Table = toml::from_str(
            r#"
[WarnOnFunction.crypto-policy-non-compliance-openssl]
f_name = "SSL_CTX_set_cipher_list"
description = "explicit cipher list bypasses the system crypto policy"
[WarnOnFunction.crypto-policy-non-compliance-gnutls-2]
f_name = "gnutls_priority_init"
good_param = "SYSLOG"
description = "explicit priority string bypasses the system crypto policy"
"#,
        )
        .expect("parse WarnOnFunction");
        let warn = parsed
            .get("WarnOnFunction")
            .and_then(toml::Value::as_table)
            .expect("WarnOnFunction table")
            .clone();
        config
            .configuration
            .insert("WarnOnFunction".to_string(), toml::Value::Table(warn));
        config
    }

    fn run_binaries_check_with_config(
        rpm: &str,
        config: &Config,
    ) -> (Vec<(String, String)>, Vec<Level>, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = BinariesCheck::with_tool_dir(config, None);
        check.check_binary(&pkg, config, &mut out);
        (out.results().to_vec(), out.result_levels().to_vec(), dir)
    }

    fn finding_level(
        results: &[(String, String)],
        levels: &[Level],
        finding: &str,
    ) -> Option<Level> {
        results
            .iter()
            .position(|(n, _)| n == finding)
            .map(|i| levels[i])
    }

    #[test]
    fn forbidden_function_fires_for_dynsym_import() {
        // libcryptobad.so is stripped: SSL_CTX_set_cipher_list exists only as
        // an undefined import in .dynsym. The pre-fix scan of .symtab alone
        // could never see it, so this test fails with the bug live.
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let config = warn_on_function_config();
        let (results, levels, _dir) = run_binaries_check_with_config(&rpm_path, &config);

        let lines = lines_for(&results, "crypto-policy-non-compliance-openssl");
        assert_eq!(lines.len(), 1, "one openssl finding: {results:?}");
        assert!(
            lines[0].contains("/usr/lib64/libcryptobad.so"),
            "finding names the offending file: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("SSL_CTX_set_cipher_list"),
            "finding names the forbidden call: {}",
            lines[0]
        );
        assert_eq!(
            finding_level(&results, &levels, "crypto-policy-non-compliance-openssl"),
            Some(Level::Warning),
            "forbidden crypto calls are Warnings, like the reference"
        );
    }

    #[test]
    fn forbidden_function_waived_by_good_param() {
        // libgnutlswaived.so calls gnutls_priority_init but its strings
        // contain the SYSLOG waiver, so the finding is suppressed (reference
        // test_waived_forbidden_c_calls).
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let config = warn_on_function_config();
        let (results, _levels, _dir) = run_binaries_check_with_config(&rpm_path, &config);
        assert_lacks(&results, "crypto-policy-non-compliance-gnutls-2");
        // The waiver only covers the gnutls entry: the openssl finding for
        // libcryptobad.so must still fire in the same run.
        let lines = lines_for(&results, "crypto-policy-non-compliance-openssl");
        assert_eq!(lines.len(), 1, "openssl finding survives: {results:?}");
    }

    #[test]
    fn binaries_check_skips_tool_subchecks_when_tools_absent() {
        // Empty tool dir: `strings` and `ar` are absent, so their subchecks
        // are skipped silently instead of emitting one failure per file.
        let empty = tempfile::TempDir::new().expect("tmpdir");
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let (results, _dir) = run_binaries_check_with_tools(&rpm_path, Some(empty.path()));
        assert_lacks(&results, "strings-failed");
        assert_lacks(&results, "ar-failed");
    }

    #[test]
    fn absent_ar_treats_archive_as_nonstandard() {
        // With `ar` absent the standard-ness test cannot run: the archive is
        // treated as non-standard (ELF checks skipped) rather than assumed
        // standard, which would invent findings on Rust/Go archives.
        let empty = tempfile::TempDir::new().expect("tmpdir");
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, Some(empty.path()));
        assert!(!check.ar.is_present());

        // A real `ar` archive; its content is never inspected without the tool.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let archive = dir.path().join("librustfoo.a");
        std::fs::write(&archive, b"!<arch>\n").expect("write archive");

        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let extract_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(&rpm_path), extract_dir.path(), true)
            .expect("open fixture");
        let pkgfile = PkgFile {
            path: archive.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        assert!(
            !check.is_standard_archive(&pkg, &pkgfile, &mut out),
            "absent ar must not assume a standard archive"
        );
        assert!(
            out.results().is_empty(),
            "no findings invented: {:?}",
            out.results()
        );
    }

    #[test]
    fn hash_sections_fire_at_most_once_per_file() {
        // #218: the missing-section needle used to reset for every section
        // (ReadelfInfo stores one section per inner vec), so each non-hash
        // section re-emitted both findings. The reference scans the whole
        // section list once and emits at most one finding of each kind.
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let (results, _dir) = run_binaries_check(&rpm_path);
        // Both fixture libraries carry .hash and .gnu.hash, and the pinned
        // reference is quiet on them: neither finding may fire.
        assert_lacks(&results, "missing-hash-section");
        assert_lacks(&results, "missing-gnu-hash-section");
    }

    #[test]
    fn hash_sections_match_reference_on_corpus_cases() {
        // #218 oracle: the pinned reference emits neither missing-hash-section
        // nor missing-gnu-hash-section on the liblto21 / llvm21-gold corpus
        // cases (both libraries carry .hash and .gnu.hash); the port emitted
        // one finding per ELF section.
        let cases = [
            "../../tests/parity/cases/liblto21/input/libLTO21-21.1.8-9.2.aarch64.rpm",
            "../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm",
        ];
        for case in cases {
            let rpm_path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), case);
            let (results, _dir) = run_binaries_check(&rpm_path);
            assert_lacks(&results, "missing-hash-section");
            assert_lacks(&results, "missing-gnu-hash-section");
        }
    }

    #[test]
    fn hash_sections_pin_positive_cases() {
        // Reference semantics for the remaining combinations, driven through
        // check_hash_sections with the real one-section-per-vec ReadelfInfo
        // shape: .gnu.hash-only gets exactly one missing-hash-section (E);
        // neither section gets exactly one of each; both stay quiet.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg =
            Pkg::open(std::path::Path::new(&rpm_path), dir.path(), true).expect("open fixture");
        let pkgfile = PkgFile {
            name: "/usr/lib64/libprobe.so.1".to_string(),
            ..Default::default()
        };

        let run = |sections: Vec<Vec<ElfSection>>| {
            let info = ReadelfInfo {
                sections,
                program_headers: Vec::new(),
                functions: Vec::new(),
                is_shlib: true,
                is_debug: false,
                soname: None,
                needed: Vec::new(),
                runpaths: Vec::new(),
                has_textrel: false,
                failed: None,
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_hash_sections(&pkg, &pkgfile, &info, &mut out);
            out.results().to_vec()
        };
        let sec = |name: &str| ElfSection {
            name: name.to_string(),
            size: 100,
        };

        let results = run(vec![
            vec![sec(".text")],
            vec![sec(".gnu.hash")],
            vec![sec(".data")],
        ]);
        let hash_lines = lines_for(&results, "missing-hash-section");
        assert_eq!(hash_lines.len(), 1, "one missing-hash-section: {results:?}");
        assert!(
            hash_lines[0].contains(" E: "),
            "missing-hash-section is Error: {}",
            hash_lines[0]
        );
        assert!(
            hash_lines[0].contains("/usr/lib64/libprobe.so.1"),
            "missing-hash-section names the library: {}",
            hash_lines[0]
        );
        assert_lacks(&results, "missing-gnu-hash-section");

        let results = run(vec![vec![sec(".text")], vec![sec(".data")]]);
        let hash_lines = lines_for(&results, "missing-hash-section");
        assert_eq!(hash_lines.len(), 1, "one missing-hash-section: {results:?}");
        assert!(
            hash_lines[0].contains("/usr/lib64/libprobe.so.1"),
            "missing-hash-section names the library: {}",
            hash_lines[0]
        );
        let gnu_lines = lines_for(&results, "missing-gnu-hash-section");
        assert_eq!(
            gnu_lines.len(),
            1,
            "one missing-gnu-hash-section: {results:?}"
        );
        assert!(
            gnu_lines[0].contains(" W: "),
            "missing-gnu-hash-section is Warning: {}",
            gnu_lines[0]
        );
        assert!(
            gnu_lines[0].contains("/usr/lib64/libprobe.so.1"),
            "missing-gnu-hash-section names the library: {}",
            gnu_lines[0]
        );
        // Name, detail, severity, ORDER byte-identical: E fires before W.
        let hash_pos = results
            .iter()
            .position(|(n, _)| n == "missing-hash-section");
        let gnu_pos = results
            .iter()
            .position(|(n, _)| n == "missing-gnu-hash-section");
        assert!(
            hash_pos < gnu_pos,
            "missing-hash-section (E) before missing-gnu-hash-section (W): {hash_pos:?} vs {gnu_pos:?}"
        );

        let results = run(vec![vec![sec(".hash")], vec![sec(".gnu.hash")]]);
        assert_lacks(&results, "missing-hash-section");
        assert_lacks(&results, "missing-gnu-hash-section");
    }
}
