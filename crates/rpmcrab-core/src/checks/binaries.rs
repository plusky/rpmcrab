//! `BinariesCheck`: ELF binary validation, ported from rpmlint's `BinariesCheck.py`.
//!
//! Covers the reference's `add_info` call sites: ELF section/header analysis
//! via `goblin`, dependency analysis via `goblin`, DWARF producer extraction
//! via `gimli`, forbidden functions via `strings`, and archive analysis via
//! `ar`.
//!
//! Deliberate gaps are ledgered in `tests/parity/divergences.toml`.

#![allow(clippy::collapsible_if)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use fancy_regex::Regex;
use rayon::prelude::*;

use crate::check::{Check, add_info, basename};
use crate::checks::shared::is_64bit_arch;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::PkgFile;
use crate::tools::{Tool, ToolSource, spawn_with_retry, test_source};
use std::sync::OnceLock;

static VALIDSO_REGEX: OnceLock<Regex> = OnceLock::new();
fn validso_regex() -> &'static Regex {
    VALIDSO_REGEX.get_or_init(|| Regex::new(r"(\.so\.\d+(\.\d+)*|\d\.so)$").expect("static regex"))
}

static SOVERSION_REGEX: OnceLock<Regex> = OnceLock::new();
fn soversion_regex() -> &'static Regex {
    SOVERSION_REGEX.get_or_init(|| {
        Regex::new(r".*?(-(?P<pkgversion>[0-9][.0-9]*))?\.so(\.(?P<soversion>[0-9][.0-9]*))?")
            .expect("static regex")
    })
}

static USR_LIB_REGEX: OnceLock<Regex> = OnceLock::new();
fn usr_lib_regex() -> &'static Regex {
    USR_LIB_REGEX.get_or_init(|| Regex::new(r"^/usr/lib(64)?/").expect("static regex"))
}

/// Lexically collapse `.` and `..` components of an absolute path, mirroring
/// `pathlib.Path.resolve()` for paths that need not exist on disk.
fn normalize_dotdot(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

static LDSO_SONAME_REGEX: OnceLock<Regex> = OnceLock::new();
fn ldso_soname_regex() -> &'static Regex {
    LDSO_SONAME_REGEX
        .get_or_init(|| Regex::new(r"^ld(-linux(-(ia|x86_)64))?\.so").expect("static regex"))
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

/// Parse ELF bytes, tolerating a dangling DT_GNU_HASH: stripping hash
/// sections with objcopy leaves the dynamic entry behind, which fails
/// goblin's strict parse. The reference never inspects the hash table, so
/// retry permissively and let the sections read as missing instead of
/// failing the whole file.
pub(crate) fn parse_elf(data: &[u8]) -> Result<goblin::elf::Elf<'_>, goblin::error::Error> {
    match goblin::elf::Elf::parse(data) {
        Ok(elf) => Ok(elf),
        Err(goblin::error::Error::Malformed(msg)) if msg.starts_with("Invalid DT_GNU_HASH:") => {
            goblin::elf::Elf::parse_with_opts(data, &goblin::options::ParseOptions::permissive())
        }
        Err(e) => Err(e),
    }
}

/// `NT_GNU_PROPERTY_TYPE_0` note type.
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// Property type of `GNU_PROPERTY_X86_FEATURE_1_AND`.
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
/// `GNU_PROPERTY_X86_FEATURE_1_AND` bit: indirect branch tracking.
const X86_FEATURE_1_IBT: u32 = 1 << 0;
/// `GNU_PROPERTY_X86_FEATURE_1_AND` bit: shadow stack.
const X86_FEATURE_1_SHSTK: u32 = 1 << 1;

/// Both control-flow features a `-fcf-protection` build records in
/// `GNU_PROPERTY_X86_FEATURE_1_AND` (IBT and SHSTK together).
const X86_FEATURE_1_IBT_SHSTK: u32 = X86_FEATURE_1_IBT | X86_FEATURE_1_SHSTK;
/// `ENDBR64`: the instruction `-fcf-protection` emits at every
/// indirect-branch target — the code-level record that the flag
/// reached the compiler, independent of the merged property note.
const ENDBR64: [u8; 4] = [0xf3, 0x0f, 0x1e, 0xfa];

/// State of `GNU_PROPERTY_X86_FEATURE_1_AND` in an ELF's
/// `.note.gnu.property`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum X86Feature1And {
    /// No such property entry in any GNU property note.
    #[default]
    Absent,
    /// The property's value (see `X86_FEATURE_1_IBT`/`X86_FEATURE_1_SHSTK`).
    Present(u32),
    /// A property entry exists but is truncated or undersized, so its
    /// value cannot be read and absence of the features is not proven.
    Unreadable,
}

/// Extract the `GNU_PROPERTY_X86_FEATURE_1_AND` state from one
/// `.note.gnu.property` section's bytes. Note entries are 4-byte
/// aligned; property entries inside a `GNU` property note are 8-byte
/// aligned in ELF64 and 4-byte aligned in ELF32.
fn parse_x86_feature_1_and(section: &[u8], is_64: bool) -> X86Feature1And {
    let u32_at = |b: &[u8], off: usize| -> Option<u32> {
        b.get(off..off + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    };
    let align = |v: usize, a: usize| v.div_ceil(a) * a;
    let mut off = 0;
    while off + 12 <= section.len() {
        let Some(namesz) = u32_at(section, off) else {
            break;
        };
        let Some(descsz) = u32_at(section, off + 4) else {
            break;
        };
        let Some(n_type) = u32_at(section, off + 8) else {
            break;
        };
        let namesz = namesz as usize;
        let descsz = descsz as usize;
        let name_at = off + 12;
        let desc_at = name_at + align(namesz, 4);
        let is_gnu_property = n_type == NT_GNU_PROPERTY_TYPE_0
            && section.get(name_at..name_at + namesz) == Some(b"GNU\0".as_slice());
        if desc_at + descsz > section.len() {
            // A truncated GNU property note may have carried the
            // property in its lost tail; its absence is not proven.
            if is_gnu_property {
                return X86Feature1And::Unreadable;
            }
            break;
        }
        if is_gnu_property {
            let desc = &section[desc_at..desc_at + descsz];
            let prop_align = if is_64 { 8 } else { 4 };
            let mut poff = 0;
            while poff + 8 <= desc.len() {
                let Some(pr_type) = u32_at(desc, poff) else {
                    break;
                };
                let Some(pr_datasz) = u32_at(desc, poff + 4) else {
                    break;
                };
                let pr_datasz = pr_datasz as usize;
                if pr_type == GNU_PROPERTY_X86_FEATURE_1_AND {
                    // The entry exists; a value that is cut off or too
                    // small to hold the feature word is unreadable,
                    // not absent.
                    if pr_datasz < 4 {
                        return X86Feature1And::Unreadable;
                    }
                    return match u32_at(desc, poff + 8) {
                        Some(v) => X86Feature1And::Present(v),
                        None => X86Feature1And::Unreadable,
                    };
                }
                if poff + 8 + pr_datasz > desc.len() {
                    // A non-feature entry overrunning the desc ends
                    // the walk here; the feature entry could have sat
                    // in the lost tail, so absence is not proven.
                    return X86Feature1And::Unreadable;
                }
                poff += align(8 + pr_datasz, prop_align);
            }
        }
        off = desc_at + align(descsz, 4);
    }
    X86Feature1And::Absent
}

struct ReadelfInfo {
    sections: Vec<Vec<ElfSection>>,
    program_headers: Vec<ElfProgramHeader>,

    /// FUNC-type symbol names from both `.symtab` and `.dynsym`, mirroring
    /// the reference `readelf -s` scan (`SymbolTableInfo.functions`). The
    /// dynamic table is where undefined imports of stripped binaries live,
    /// so function-call checks must consult it.
    functions: Vec<String>,
    /// Undefined symbols from `.dynsym` (STT_FUNC and STT_NOTYPE): the
    /// binary's external imports. The hardening predicates read this set:
    /// it is the binary's imports, complete across symbol types, with no
    /// defined exports mixed in.
    undefined_functions: Vec<String>,
    is_shlib: bool,
    is_debug: bool,
    /// True when the binary was produced by the Rust toolchain.
    /// Computed during parse; see `detect_rust_binary`.
    is_rust: bool,
    /// True when the binary was produced by the Zig toolchain.
    /// Computed during parse; see `detect_zig_binary`.
    is_zig: bool,
    soname: Option<String>,
    needed: Vec<String>,
    runpaths: Vec<String>,
    has_textrel: bool,
    /// Raw `e_type` from the ELF header. ET_EXEC versus ET_DYN is the
    /// ground truth for the hardening checks where the file name cannot
    /// tell a PIE executable from a shared object. An ar archive carries
    /// no single `e_type`: members can mix types, so it stays `ET_NONE`
    /// (first-member or unanimous would invent semantics).
    elf_type: u16,
    /// Raw `e_machine` from the ELF header. The RELRO gate keys the
    /// AMDGPU exclusion on it: GPU code objects are loaded by the GPU
    /// runtime, never by the dynamic linker.
    elf_machine: u16,
    /// DF_BIND_NOW (DT_FLAGS) or DF_1_NOW (DT_FLAGS_1). Together with a
    /// GNU_RELRO segment this is the full-versus-partial RELRO distinction.
    bind_now: bool,
    /// The ELF has a dynamic section (PT_DYNAMIC). Static binaries do not;
    /// RELRO/BIND_NOW are dynamic-linker features meaningless without one.
    has_dynamic: bool,
    /// A non-weak undefined dynamic symbol exists: the object really
    /// references external code, so an empty DT_NEEDED is suspicious.
    /// Weak-only undefined symbols are the optional crt references that
    /// resolve to NULL; they are not real dependencies.
    has_nonweak_undefined: bool,
    /// The dynamic symbol table defines `main`: an executable-entry shim
    /// linked into binaries, not a regular shared library.
    defines_main: bool,
    /// `GNU_PROPERTY_X86_FEATURE_1_AND` state from
    /// `.note.gnu.property` (x86_64 only).
    x86_feature_1_and: X86Feature1And,
    /// The binary's `.text` contains an `ENDBR64` instruction: code
    /// compiled with `-fcf-protection` is present, whatever the merged
    /// property note records.
    has_endbr64: bool,
    failed: Option<String>,
}

/// ar archive magic: `!<arch>` followed by a newline.
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

impl ReadelfInfo {
    fn empty(name: &str) -> Self {
        ReadelfInfo {
            sections: Vec::new(),
            program_headers: Vec::new(),
            functions: Vec::new(),
            undefined_functions: Vec::new(),
            // The reference derives is_shlib and is_debug from the file name,
            // not the ELF content (readelfparser.py). A PIE executable or Go
            // binary is ET_DYN but is not a shared library for these checks.
            is_shlib: so_regex().is_match(name).unwrap_or(false),
            is_debug: name.ends_with(".debug"),
            is_rust: false,
            is_zig: false,
            soname: None,
            needed: Vec::new(),
            runpaths: Vec::new(),
            has_textrel: false,
            has_nonweak_undefined: false,
            defines_main: false,
            elf_type: goblin::elf::header::ET_NONE,
            elf_machine: goblin::elf::header::EM_NONE,
            bind_now: false,
            has_dynamic: false,
            x86_feature_1_and: X86Feature1And::Absent,
            has_endbr64: false,
            failed: None,
        }
    }

    fn parse(path: &str, name: &str) -> Self {
        let mut info = Self::empty(name);

        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };

        // Archives are containers, not ELFs: the reference runs readelf
        // over the whole file and readelf iterates the members itself.
        // goblin would reject the archive magic ("Invalid magic number"),
        // so enumerate the members explicitly and merge their metadata
        // the way readelf's per-member output merges.
        if data.starts_with(AR_MAGIC) {
            return Self::parse_archive(&data, name);
        }

        let elf = match parse_elf(&data) {
            Ok(e) => e,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };
        info.fill_from_elf(&elf, &data);
        info.elf_type = elf.header.e_type;
        info.elf_machine = elf.header.e_machine;
        info
    }

    /// Parse an ar archive member by member, mirroring readelf run over
    /// the archive. A member that is not a parseable ELF fails the whole
    /// file, exactly like readelf's nonzero exit does for the reference.
    fn parse_archive(data: &[u8], name: &str) -> Self {
        let mut info = Self::empty(name);
        let archive = match goblin::archive::Archive::parse(data) {
            Ok(a) => a,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };
        for i in 0..archive.len() {
            let Some(member) = archive.get_at(i) else {
                continue;
            };
            let end = member.offset.saturating_add(member.size() as u64) as usize;
            let bytes = match data.get(member.offset as usize..end) {
                Some(b) => b,
                None => {
                    info.failed = Some(format!("{}: member out of range", member.extended_name()));
                    return info;
                }
            };
            match parse_elf(bytes) {
                Ok(elf) => info.fill_from_elf(&elf, bytes),
                Err(e) => {
                    info.failed = Some(format!("{}: {e}", member.extended_name()));
                    return info;
                }
            }
        }
        info
    }

    /// Merge one parsed ELF's metadata, mirroring readelf's output.
    /// Archive members are merged by appending: each member's sections
    /// land in `sections` the same way readelf's per-member output does.
    fn fill_from_elf(&mut self, elf: &goblin::elf::Elf, data: &[u8]) {
        // Sections
        for sh in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            self.sections.push(vec![ElfSection {
                name: name.clone(),
                size: sh.sh_size,
            }]);
        }

        // x86 control-flow protection data (consumed by
        // check_hardening's missing-cf-protection): the merged
        // FEATURE_1_AND property state and the code-level ENDBR64
        // record. Properties are an x86 concept here; other
        // architectures' notes are not read.
        if elf.header.e_machine == goblin::elf::header::EM_X86_64 {
            for sh in &elf.section_headers {
                let start = sh.sh_offset as usize;
                let end = start.saturating_add(sh.sh_size as usize).min(data.len());
                let Some(bytes) = data.get(start..end) else {
                    continue;
                };
                match elf.shdr_strtab.get_at(sh.sh_name) {
                    Some(".note.gnu.property") => {
                        let state = parse_x86_feature_1_and(bytes, elf.is_64);
                        if self.x86_feature_1_and == X86Feature1And::Absent {
                            self.x86_feature_1_and = state;
                        }
                    }
                    Some(".text") => {
                        self.has_endbr64 =
                            self.has_endbr64 || bytes.windows(4).any(|w| w == ENDBR64);
                    }
                    _ => {}
                }
            }
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
            self.program_headers.push(ElfProgramHeader { name, flags });
        }

        // Function symbols from both tables, mirroring the reference
        // `readelf -s` scan over `.dynsym` and `.symtab`.
        for sym in elf.syms.iter() {
            if sym.st_type() == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        self.functions.push(name.to_string());
                    }
                }
            }
        }

        // Dynamic symbols: undefined imports of stripped binaries only exist
        // here, so the reference `readelf -s` scan (both tables) needs this.
        // Undefined imports are collected for STT_NOTYPE symbols too: modern
        // toolchains emit many of them as NOTYPE (`__cxa_finalize` is one),
        // and the loader-shim predicate over `undefined_functions` must see
        // the binary's full import set.
        for sym in elf.dynsyms.iter() {
            let ty = sym.st_type();
            if ty != goblin::elf::sym::STT_FUNC && ty != goblin::elf::sym::STT_NOTYPE {
                continue;
            }
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    if ty == goblin::elf::sym::STT_FUNC {
                        self.functions.push(name.to_string());
                    }
                    if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
                        self.undefined_functions.push(name.to_string());
                    }
                }
            }
        }

        // Undefined-symbol shape for the shared-library dependency check.
        // Only the binding matters, not the type. Entry 0 is the null
        // symbol, not a real reference.
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if i == 0 {
                continue;
            }
            if sym.st_shndx == 0 {
                if sym.st_bind() != goblin::elf::sym::STB_WEAK {
                    self.has_nonweak_undefined = true;
                }
            } else if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                // Dynamic table only, deliberately: only an exported `main`
                // marks the object as an executable entry to the loader,
                // while a symtab-only (hidden-visibility) `main` is an
                // internal detail -- and `.symtab` is stripped from shipped
                // binaries anyway.
                if name == "main" {
                    self.defines_main = true;
                }
            }
        }

        // Dynamic section
        if let Some(dynamic) = &elf.dynamic {
            self.has_dynamic = true;
            // BIND_NOW lives in DT_FLAGS or DT_FLAGS_1; goblin folds both
            // into DynamicInfo during the parse.
            if dynamic.info.flags & goblin::elf::dynamic::DF_BIND_NOW != 0
                || dynamic.info.flags_1 & goblin::elf::dynamic::DF_1_NOW != 0
            {
                self.bind_now = true;
            }
            let dynstrtab = &elf.dynstrtab;
            for d in &dynamic.dyns {
                match d.d_tag {
                    goblin::elf::dynamic::DT_SONAME => {
                        if let Some(s) = dynstrtab.get_at(d.d_val as usize) {
                            self.soname = Some(s.to_string());
                        }
                    }
                    goblin::elf::dynamic::DT_NEEDED => {
                        if let Some(s) = dynstrtab.get_at(d.d_val as usize) {
                            self.needed.push(s.to_string());
                        }
                    }
                    goblin::elf::dynamic::DT_RUNPATH | goblin::elf::dynamic::DT_RPATH => {
                        if let Some(s) = dynstrtab.get_at(d.d_val as usize) {
                            self.runpaths.push(s.to_string());
                        }
                    }
                    goblin::elf::dynamic::DT_TEXTREL => {
                        self.has_textrel = true;
                    }
                    _ => {}
                }
            }
        }
        // OR across archive members: any Rust member marks the whole file.
        self.is_rust = self.is_rust || detect_rust_binary(elf, data, &self.functions);
        self.is_zig = self.is_zig || detect_zig_binary(elf, data);
    }
    fn has_function_matching(&self, regex: &fancy_regex::Regex) -> bool {
        self.functions
            .iter()
            .any(|s| regex.is_match(s).unwrap_or(false))
    }

    /// Go toolchain output carries a `.note.go.buildid` section, but
    /// some builds (e.g. openSUSE Go packages) lack it. `.gopclntab`
    /// (the runtime function table) is present in every Go binary.
    /// Go binaries are ET_DYN with no DT_NEEDED, but they are not shared
    /// objects missing dependency information.
    fn is_go_binary(&self) -> bool {
        self.sections
            .iter()
            .flatten()
            .any(|s| s.name == ".note.go.buildid" || s.name == ".gopclntab")
    }

    /// Rust toolchain output carries none of the C-hardening artifacts:
    /// `_FORTIFY_SOURCE` is a glibc C-header feature rustc does not
    /// implement, and stack-protector instrumentation is not default
    /// rustc behavior.
    fn is_rust_binary(&self) -> bool {
        self.is_rust
    }

    /// Zig toolchain output carries none of the C-hardening artifacts:
    /// `_FORTIFY_SOURCE` is a glibc C-header feature Zig does not
    /// implement, stack-protector instrumentation requires libc
    /// (`-fstack-protector` errors with "enabling stack protection
    /// requires libc"), which the default static Zig build does not link,
    /// and Zig's linker emits no GNU_RELRO segment (verified on real
    /// Zig-built dynamic binaries: bun, opencode, waylock).
    fn is_zig_binary(&self) -> bool {
        self.is_zig
    }

    /// Haskell toolchain output links the Haskell runtime libraries:
    /// every GHC-produced executable and library carries a `libHS*`
    /// DT_NEEDED (at minimum `libHSrts`), and the libraries are
    /// themselves `libHS*` by SONAME (`libHSrts` links only system
    /// libraries, so its SONAME is its only signal). GHC emits no
    /// stack-protector or `_FORTIFY_SOURCE` instrumentation for
    /// Haskell code — the buffer-shaped imports arrive via the
    /// runtime — so the C-compiler findings would be noise. A C
    /// program that merely ships alongside (GHC's hp2ps, unlit)
    /// carries neither signal and is still checked. Known
    /// limitation: the signal cannot distinguish GHC output from a
    /// C host embedding Haskell (the documented `hs_init` /
    /// `-no-hs-main` FFI pattern links `libHSrts`), so such a host
    /// is skipped the same way; detection is conservative only in
    /// the miss direction (a missed detection stays checked).
    fn is_haskell_binary(&self) -> bool {
        self.soname
            .as_deref()
            .is_some_and(|s| s.starts_with("libHS"))
            || self.needed.iter().any(|n| n.starts_with("libHS"))
    }

    /// OCaml toolchain output carries the runtime entry point or
    /// module-qualified symbols of OCaml-generated code (see
    /// `is_ocaml_symbol`). ocamlopt emits no stack-protector or
    /// `_FORTIFY_SOURCE` instrumentation for OCaml code — the
    /// buffer-shaped imports belong to the runtime — so the
    /// C-compiler findings would be noise.
    ///
    /// Only defined symbols count: `functions` also carries
    /// undefined dynsym entries (every `STT_FUNC` import), so an
    /// imported OCaml symbol must not classify the binary. A C
    /// program embedding OCaml merely imports `caml_startup` (the
    /// documented embedding pattern: a C `main` calls it and links
    /// the runtime) with zero defined OCaml symbols, and its own C
    /// buffer calls stay checked.
    fn is_ocaml_binary(&self) -> bool {
        self.functions.iter().any(|s| {
            is_ocaml_symbol(s)
                && !self
                    .undefined_functions
                    .iter()
                    .any(|u| symbol_base(u) == symbol_base(s))
        })
    }

    /// A shared object for which an empty DT_NEEDED is legitimate, not
    /// "missing dependency information": a dlopen-only plugin (no
    /// DT_SONAME, so never DT_NEEDED-linked), a fully self-contained
    /// object (no non-weak undefined symbols), or an executable-entry
    /// shim (defines `main`).
    fn is_plugin_like(&self) -> bool {
        self.soname.is_none() || !self.has_nonweak_undefined || self.defines_main
    }
}

/// True when the ELF was produced by the Rust toolchain. No single
/// signal survives every strip level, so several are combined:
/// `.rustc` section (only rustc emits it; gone after any strip),
/// Rust runtime symbols, `.debug_gdb_scripts` containing "rust" as a
/// token component (rustc's GDB pretty-printer hook; gone after `strip -g`), and
/// `.rodata` containing `panicked at` (rustc's panic location format,
/// which survives even a full strip). Conservative on purpose: an
/// unrecognized binary is treated as C, so a missed detection only
/// keeps the current behavior.
/// A Rust toolchain symbol: runtime entry points, never emitted for
/// C/C++ code. `_ZN` alone is not enough (Itanium C++ mangling shares
/// the prefix), so only unambiguous Rust runtime names count here.
fn is_rust_symbol(name: &str) -> bool {
    // Strip a @VERSION suffix like is_fortify_symbol does: .dynsym names
    // may carry one, and the base name is what identifies the runtime.
    let base = name.split('@').next().unwrap_or(name);
    base == "rust_begin_unwind" || base == "rust_eh_personality" || base.starts_with("__rust_")
}

/// The base name of a symbol: the name with any `@VERSION` suffix
/// (carried by `.dynsym` entries) stripped.
fn symbol_base(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

/// An OCaml toolchain symbol: the native-code runtime entry point
/// `caml_startup`, linked into every ocamlopt-produced executable
/// (and exported there because OCaml links executables so their
/// symbols stay visible to dynamically loaded code), or a
/// module-qualified name of OCaml-generated code: `caml` directly
/// followed by the capitalised module name (`camlStdlib__List`,
/// `camlUnix__entry`). The runtime's own C functions and the OCaml
/// C stub libraries use `caml_` + lowercase primitives instead
/// (`caml_alloc`, `caml_main`), which never match: ocamlrun and the
/// `dll*_stubs.so` libraries are compiled C and stay checked.
fn is_ocaml_symbol(name: &str) -> bool {
    // Strip a @VERSION suffix like is_rust_symbol does: .dynsym names
    // may carry one, and the base name is what identifies the runtime.
    let base = name.split('@').next().unwrap_or(name);
    if base == "caml_startup" {
        return true;
    }
    match base.strip_prefix("caml") {
        Some(rest) => rest
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_uppercase()),
        None => false,
    }
}

fn detect_rust_binary(elf: &goblin::elf::Elf, data: &[u8], functions: &[String]) -> bool {
    if functions.iter().any(|s| is_rust_symbol(s)) {
        return true;
    }
    for sh in &elf.section_headers {
        let sec_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        if sec_name == ".rustc" {
            return true;
        }
        let is_gdb_scripts = sec_name == ".debug_gdb_scripts";
        let is_rodata = sec_name == ".rodata" || sec_name.starts_with(".rodata.");
        if !is_gdb_scripts && !is_rodata {
            continue;
        }
        let start = sh.sh_offset as usize;
        let end = start.saturating_add(sh.sh_size as usize);
        let bytes = match data.get(start..end) {
            Some(b) => b,
            None => continue,
        };
        if is_gdb_scripts {
            // "rust" must start a token component: preceded by an ASCII
            // letter it is embedded in a longer word ("Trust", "crust").
            // rustc emits `gdb_load_rust_pretty_printers.py` ("_rust_").
            if bytes.windows(4).enumerate().any(|(i, w)| {
                w.eq_ignore_ascii_case(b"rust") && (i == 0 || !bytes[i - 1].is_ascii_alphabetic())
            }) {
                return true;
            }
        } else if bytes
            .windows(b"panicked at".len())
            .any(|w| w == b"panicked at")
        {
            return true;
        }
    }
    false
}
/// True when the ELF was produced by the Zig toolchain. Two signals are
/// combined: the .comment section identifying Zig's LLD fork, and read-only
/// data sections (.rodata, .data.rel.ro) containing the Zig panic message
/// for unreachable, which survives strip. Conservative on purpose: an
/// unrecognized binary is treated as C.
fn detect_zig_binary(elf: &goblin::elf::Elf, data: &[u8]) -> bool {
    for sh in &elf.section_headers {
        let sec_name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
        let is_comment = sec_name == ".comment";
        let is_rodata = sec_name == ".rodata"
            || sec_name.starts_with(".rodata.")
            || sec_name == ".data.rel.ro"
            || sec_name.starts_with(".data.rel.ro.");
        if !is_comment && !is_rodata {
            continue;
        }
        let start = sh.sh_offset as usize;
        let end = start.saturating_add(sh.sh_size as usize);
        let bytes = match data.get(start..end) {
            Some(b) => b,
            None => continue,
        };
        if is_comment {
            if bytes.windows(b"ziglang".len()).any(|w| w == b"ziglang") {
                return true;
            }
        } else if bytes
            .windows(b"reached unreachable".len())
            .any(|w| w == b"reached unreachable")
        {
            return true;
        }
    }
    false
}

struct LddInfo {
    dependencies: Vec<String>,
    unused_dependencies: Vec<String>,
    undefined_symbols: Vec<String>,
    /// Symbols this file defines in `.dynsym`; the provider side of
    /// the DT_NEEDED closure resolution in `resolve_undefined_symbols`.
    defined_symbols: Vec<String>,
    /// ELF class of the file (`Some(true)` = 64-bit), once parsed;
    /// system-library providers are matched against it so a 32-bit
    /// consumer never resolves against a 64-bit library or vice versa.
    is_64: Option<bool>,
    /// DT_RPATH entries, colon-split, in order. The loader honours
    /// these only when the file carries no DT_RUNPATH at all.
    rpath: Vec<String>,
    /// DT_RUNPATH entries, colon-split, in order.
    runpath: Vec<String>,
    /// A DT_RUNPATH tag is present at all, even when its value is
    /// empty or all its segments are empty. The loader suppresses
    /// DT_RPATH on tag presence, not on content, so this presence
    /// bit -- not `runpath.is_empty()` -- gates DT_RPATH use.
    has_runpath: bool,
    failed: Option<String>,
}

impl LddInfo {
    fn parse(path: &str, is_installed: bool) -> Self {
        let mut info = LddInfo {
            dependencies: Vec::new(),
            unused_dependencies: Vec::new(),
            undefined_symbols: Vec::new(),
            defined_symbols: Vec::new(),
            is_64: None,
            rpath: Vec::new(),
            runpath: Vec::new(),
            has_runpath: false,
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

        let elf = match parse_elf(&data) {
            Ok(e) => e,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };
        info.is_64 = Some(elf.is_64);

        // Dependencies from DT_NEEDED; search paths from DT_RPATH /
        // DT_RUNPATH, which locate the providers of those
        // dependencies in `resolve_undefined_symbols`.
        if let Some(dynamic) = &elf.dynamic {
            let dynstrtab = &elf.dynstrtab;
            for d in &dynamic.dyns {
                let tag = d.d_tag;
                if tag != goblin::elf::dynamic::DT_NEEDED
                    && tag != goblin::elf::dynamic::DT_RPATH
                    && tag != goblin::elf::dynamic::DT_RUNPATH
                {
                    continue;
                }
                let Some(s) = dynstrtab.get_at(d.d_val as usize) else {
                    continue;
                };
                if tag == goblin::elf::dynamic::DT_NEEDED {
                    info.dependencies.push(s.to_string());
                } else {
                    // Tag presence alone suppresses DT_RPATH in
                    // the loader, even for an empty value whose
                    // segments are all dropped below.
                    if tag == goblin::elf::dynamic::DT_RUNPATH {
                        info.has_runpath = true;
                    }
                    // An empty segment names the loader's working
                    // directory; the resolver has no working
                    // directory to substitute, so empty segments
                    // are dropped here rather than searched.
                    let target = if tag == goblin::elf::dynamic::DT_RPATH {
                        &mut info.rpath
                    } else {
                        &mut info.runpath
                    };
                    target.extend(
                        s.split(':')
                            .filter(|seg| !seg.is_empty())
                            .map(str::to_string),
                    );
                }
            }
        }

        // Undefined and defined symbols from .dynsym, the dynamic
        // loader's view of the file -- the reference's model is the
        // real `ldd -r`, which resolves .dynsym references. The
        // .symtab set is deliberately not used: its UND entries
        // include references the loader never resolves, and stripped
        // libraries (the norm) have no .symtab at all, so scanning it
        // fired almost only on symtab-carrying libraries
        // (plusky/rpmcrab#467).
        for sym in elf.dynsyms.iter() {
            let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
                // Weak undefined symbols resolve to zero at load
                // time, so ldd -r stays silent on them and the
                // reference never reports them. A name can repeat
                // across version references; report it once.
                if goblin::elf::sym::st_bind(sym.st_info) != goblin::elf::sym::STB_WEAK
                    && !info.undefined_symbols.iter().any(|u| u == name)
                {
                    info.undefined_symbols.push(name.to_string());
                }
            } else {
                info.defined_symbols.push(name.to_string());
            }
        }

        // Unused dependencies: ldd -u does linker-based analysis which
        // goblin cannot replicate. Left empty; ledgered as a divergence.
        // (The reference's ldd -u requires full symbol resolution.)

        info
    }
}

/// A library acting as a symbol provider for DT_NEEDED closure
/// resolution: the dynamic symbols it defines and its own DT_NEEDED
/// entries. Providers come from the checked package first and from
/// the system the check runs on (`SystemLibraries`) second.
struct SymbolProvider {
    defined: HashSet<String>,
    needs: Vec<String>,
    /// The directory the providing object is installed in: the
    /// base for `$ORIGIN` expansion in its search-path entries.
    origin: PathBuf,
    /// The object's DT_RPATH entries (raw, colon-split).
    rpath: Vec<String>,
    /// The object's DT_RUNPATH entries (raw, colon-split).
    runpath: Vec<String>,
    /// A DT_RUNPATH tag is present at all (see `LddInfo`).
    has_runpath: bool,
}

/// Lookup key for symbol providers: a SONAME plus the ELF class
/// of the consumer asking (`None` when the class is unknown).
type ProviderKey = (String, Option<bool>);

/// Lookup key for directory-scoped provider lookups: the SONAME,
/// the consumer's ELF class, and the directory list searched.
type DirProviderKey = (String, Option<bool>, Vec<PathBuf>);

/// Symbol providers from the system rpmcrab runs on: the fallback
/// half of undefined-symbol resolution. The reference resolves with
/// the real `ldd -r` against the installed system; rpmcrab by
/// default runs inside a jailed container / OBS build root, so the
/// libraries of the environment it runs in are the checked
/// packages' own install target and resolving against them mirrors
/// the reference. A SONAME is located through the ldconfig cache
/// when one is readable, else by scanning the standard library
/// directories; the located file is parsed like any other library
/// and contributes only the symbols it actually defines in
/// `.dynsym` -- never a name-based allowance -- and a symbol no
/// located provider defines keeps firing.
struct SystemLibraries {
    /// Directories scanned for a SONAME, in search order.
    dirs: Vec<PathBuf>,
    /// The ldconfig cache consulted before the directories.
    cache_path: Option<PathBuf>,
    /// Lazily parsed cache: SONAME -> candidate paths, in cache order.
    cache: Mutex<Option<HashMap<String, Vec<PathBuf>>>>,
    /// Memoised lookups per (SONAME, ELF class): the located,
    /// parsed provider, or `None` when no candidate parses.
    providers: Mutex<HashMap<ProviderKey, Option<Arc<SymbolProvider>>>>,
    /// Memoised lookups per (SONAME, ELF class, directory list)
    /// for `provider_in_dirs`.
    dir_providers: Mutex<HashMap<DirProviderKey, Option<Arc<SymbolProvider>>>>,
}

impl SystemLibraries {
    /// The live system: the standard library directories (plus any
    /// multiarch triplet directories under them) and the default
    /// ldconfig cache.
    fn system() -> Self {
        let mut dirs: Vec<PathBuf> = ["/lib64", "/usr/lib64", "/lib", "/usr/lib"]
            .iter()
            .map(PathBuf::from)
            .collect();
        // Multiarch systems keep the real libraries in triplet
        // directories (x86_64-linux-gnu, aarch64-linux-gnu, ...)
        // directly under /usr/lib and /lib.
        let mut multiarch: Vec<PathBuf> = Vec::new();
        for base in ["/usr/lib", "/lib"] {
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let is_triplet = entry.file_name().to_str().is_some_and(|n| n.contains('-'));
                    if is_triplet && path.is_dir() {
                        multiarch.push(path);
                    }
                }
            }
        }
        multiarch.sort();
        dirs.extend(multiarch);
        Self::with_roots(dirs, Some(PathBuf::from("/etc/ld.so.cache")))
    }

    /// No system at all: resolution behaves exactly as if the
    /// fallback did not exist.
    fn empty() -> Self {
        Self::with_roots(Vec::new(), None)
    }

    fn with_roots(dirs: Vec<PathBuf>, cache_path: Option<PathBuf>) -> Self {
        SystemLibraries {
            dirs,
            cache_path,
            cache: Mutex::new(None),
            providers: Mutex::new(HashMap::new()),
            dir_providers: Mutex::new(HashMap::new()),
        }
    }

    fn is_empty(&self) -> bool {
        self.dirs.is_empty() && self.cache_path.is_none()
    }

    /// The provider for `soname` on this system, if any: the first
    /// located candidate that parses as an ELF library of the
    /// requested class (`is_64` = the consumer's class, when known).
    fn provider(&self, soname: &str, is_64: Option<bool>) -> Option<Arc<SymbolProvider>> {
        let key = (soname.to_string(), is_64);
        if let Some(hit) = self.providers.lock().unwrap().get(&key) {
            return hit.clone();
        }
        let found = self
            .locate(soname)
            .into_iter()
            .find_map(|path| Self::parse_provider(&path, is_64));
        self.providers.lock().unwrap().insert(key, found.clone());
        found
    }

    /// Parse a located candidate file into a provider, when it is
    /// an ELF library of the consumer's class (`is_64`, when known).
    fn parse_provider(path: &Path, is_64: Option<bool>) -> Option<Arc<SymbolProvider>> {
        let ldd = LddInfo::parse(path.to_str()?, true);
        if ldd.failed.is_some() {
            return None;
        }
        if let (Some(want), Some(got)) = (is_64, ldd.is_64)
            && want != got
        {
            return None;
        }
        Some(Arc::new(SymbolProvider {
            defined: ldd.defined_symbols.iter().cloned().collect(),
            needs: ldd.dependencies.clone(),
            origin: path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/")),
            rpath: ldd.rpath.clone(),
            runpath: ldd.runpath.clone(),
            has_runpath: ldd.has_runpath,
        }))
    }

    /// The provider for `soname` in an explicit directory list --
    /// a needing object's expanded DT_RPATH/DT_RUNPATH -- searched
    /// in order. Independent of this instance's own roots and
    /// cache, so it also works on the empty test seam: the
    /// directories are the checked objects' own, wherever they
    /// point in the filesystem rpmcrab runs on. A `soname`
    /// containing a slash is a direct path for the loader and is
    /// never directory-searched.
    fn provider_in_dirs(
        &self,
        soname: &str,
        is_64: Option<bool>,
        dirs: &[PathBuf],
    ) -> Option<Arc<SymbolProvider>> {
        if soname.contains('/') || dirs.is_empty() {
            return None;
        }
        let key: DirProviderKey = (soname.to_string(), is_64, dirs.to_vec());
        if let Some(hit) = self.dir_providers.lock().unwrap().get(&key) {
            return hit.clone();
        }
        let found = dirs.iter().find_map(|dir| {
            let candidate = dir.join(soname);
            if candidate.is_file() {
                Self::parse_provider(&candidate, is_64)
            } else {
                None
            }
        });
        self.dir_providers
            .lock()
            .unwrap()
            .insert(key, found.clone());
        found
    }

    /// Candidate paths for `soname`: the ldconfig cache's entries
    /// first (the loader's own map), then a same-named file in each
    /// search directory. A `soname` containing a slash is a direct
    /// path (the loader loads it by path, with no search): the path
    /// itself is a candidate, and the cache and the search
    /// directories are also consulted by its basename, since a
    /// provider shipped under that basename defines the same
    /// symbols however the consumer spelled the dependency.
    fn locate(&self, soname: &str) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        if soname.contains('/') {
            let direct = PathBuf::from(soname);
            if direct.is_file() && !out.contains(&direct) {
                out.push(direct);
            }
        }
        {
            let mut cache = self.cache.lock().unwrap();
            if cache.is_none() {
                *cache = Some(
                    self.cache_path
                        .as_ref()
                        .and_then(|p| std::fs::read(p).ok())
                        .and_then(|data| parse_ld_so_cache(&data))
                        .unwrap_or_default(),
                );
            }
            if let Some(cache) = cache.as_ref() {
                if let Some(paths) = cache.get(soname) {
                    out.extend(paths.iter().cloned());
                }
                let base = basename(soname);
                if base != soname {
                    if let Some(paths) = cache.get(base) {
                        for path in paths {
                            if !out.contains(path) {
                                out.push(path.clone());
                            }
                        }
                    }
                }
            }
        }
        for dir in &self.dirs {
            let candidate = dir.join(soname);
            if candidate.is_file() && !out.contains(&candidate) {
                out.push(candidate);
            }
            let base = basename(soname);
            if base != soname {
                let candidate = dir.join(base);
                if candidate.is_file() && !out.contains(&candidate) {
                    out.push(candidate);
                }
            }
        }
        out
    }
}

/// Parse an `ld.so.cache` image into SONAME -> candidate paths.
/// Two layouts are recognised: glibc >= 2.32 (48-byte header,
/// 24-byte entries, key/value as absolute file offsets) and the
/// original format (32-byte header, 12-byte entries, offsets into
/// the trailing string table). A layout is accepted only when
/// nearly every entry decodes to a plausible SONAME and an absolute
/// path; anything else is treated as "no cache", so a format this
/// parser does not understand degrades to directory scanning
/// instead of resolving against garbage.
fn parse_ld_so_cache(data: &[u8]) -> Option<HashMap<String, Vec<PathBuf>>> {
    if data.len() < 48 || &data[0..17] != b"glibc-ld.so.cache" || &data[17..20] != b"1.1" {
        return None;
    }
    let nlibs = u32::from_le_bytes(data[20..24].try_into().ok()?) as usize;
    if nlibs == 0 {
        return None;
    }
    let word = |off: usize| -> Option<usize> {
        data.get(off..off + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
    };
    let string = |off: usize| -> Option<String> {
        let bytes = data.get(off..)?;
        let end = bytes.iter().position(|&b| b == 0)?;
        String::from_utf8(bytes[..end].to_vec()).ok()
    };
    // (header size, entry size, offsets relative to file start?)
    for (header, entry, absolute) in [(48usize, 24usize, true), (32, 12, false)] {
        let strtab = header + nlibs * entry;
        if strtab > data.len() {
            continue;
        }
        let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let mut plausible = 0usize;
        for i in 0..nlibs {
            let at = header + i * entry;
            let (Some(key), Some(value)) = (word(at + 4), word(at + 8)) else {
                break;
            };
            let (key, value) = if absolute {
                (string(key), string(value))
            } else {
                (string(strtab + key), string(strtab + value))
            };
            if let (Some(key), Some(value)) = (key, value)
                && key.contains(".so")
                && value.starts_with('/')
            {
                plausible += 1;
                let paths = map.entry(key).or_default();
                let path = PathBuf::from(value);
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
        if plausible * 10 >= nlibs * 9 {
            return Some(map);
        }
    }
    None
}

/// Memoisation key for DT_NEEDED closures: a file's direct
/// dependency list, its ELF class, and its search context (system
/// candidates are class-matched, and the provided set depends on
/// the directories the file's own entries are searched in).
type ClosureKey = (Vec<String>, Option<bool>, SearchContext);

/// The directory the loader treats an object as installed in:
/// the parent of its package path, made absolute. This is the
/// base for `$ORIGIN` expansion in the object's search paths.
fn installed_dir(name: &str) -> PathBuf {
    match Path::new(name).parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            if parent.is_absolute() {
                parent.to_path_buf()
            } else {
                Path::new("/").join(parent)
            }
        }
        _ => PathBuf::from("/"),
    }
}

/// Expand one object's raw DT_RPATH/DT_RUNPATH entries into the
/// directory list the loader would search: `$ORIGIN` (and the
/// braced `${ORIGIN}`) expands to the object's installed
/// directory, and `.`/`..` collapse lexically. Only entries that
/// are absolute after `$ORIGIN` expansion are kept, and that test
/// runs before normalisation: a relative entry is relative to
/// the loader's working directory, which this model does not
/// have, and normalising it first would invent a host-absolute
/// path (`lib` becoming `/lib`) that gets searched on the host.
fn expand_search_dirs(entries: &[String], origin: &Path) -> Vec<PathBuf> {
    let origin = origin.to_string_lossy();
    entries
        .iter()
        .map(|entry| {
            entry
                .replace("${ORIGIN}", &origin)
                .replace("$ORIGIN", &origin)
        })
        .filter(|entry| entry.starts_with('/'))
        .map(|entry| normalize_dotdot(&entry))
        .map(PathBuf::from)
        .collect()
}

/// Search context for DT_NEEDED entries issued by one object:
/// the directories the loader searches for them, on top of the
/// package index and the system fallback.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SearchContext {
    /// The needing object's expanded DT_RUNPATH: searched for
    /// its own entries only (RUNPATH is not transitive).
    runpath_dirs: Vec<PathBuf>,
    /// Expanded DT_RPATH lists of the needing object and its
    /// loaders, nearest first (RPATH is transitive). An object
    /// contributes its list only when it carries no DT_RUNPATH:
    /// the loader ignores DT_RPATH entirely in that case.
    rpath_chain: Vec<Vec<PathBuf>>,
}

impl SearchContext {
    /// The context for entries issued by an object with the given
    /// search paths, loaded under `inherited` (the RPATH chain of
    /// the object that issued the entry which loaded it; empty
    /// for the checked file itself).
    fn for_object(
        rpath: &[String],
        runpath: &[String],
        has_runpath: bool,
        origin: &Path,
        inherited: &[Vec<PathBuf>],
    ) -> Self {
        let mut rpath_chain: Vec<Vec<PathBuf>> = Vec::new();
        if !has_runpath {
            let dirs = expand_search_dirs(rpath, origin);
            if !dirs.is_empty() {
                rpath_chain.push(dirs);
            }
        }
        // A loader already in the chain does not extend it again:
        // the same directory list appearing twice adds no new
        // search location, and deduplicating on it keeps a cyclic
        // dependency graph's chains finite.
        for dirs in inherited {
            if !rpath_chain.contains(dirs) {
                rpath_chain.push(dirs.clone());
            }
        }
        SearchContext {
            runpath_dirs: expand_search_dirs(runpath, origin),
            rpath_chain,
        }
    }
}

/// Resolve undefined symbols the way the reference's `ldd -r`
/// does: a file's undefined symbol is satisfied when a library in
/// its DT_NEEDED closure -- the file itself included, as in the
/// loader's lookup order -- defines it. The closure is formed from
/// the libraries shipped in the same package first; a DT_NEEDED
/// entry the package does not ship is then located the way the
/// loader locates it: in the needing object's DT_RPATH chain and
/// DT_RUNPATH (with `$ORIGIN` expansion, against the filesystem
/// rpmcrab runs on), then on the system (`SystemLibraries`), whose
/// libraries join the closure with their own DT_NEEDED entries in
/// turn. Resolution only ever subtracts symbols a located library
/// actually defines, so a symbol with no provider anywhere keeps
/// firing (no silent allowlisting).
fn resolve_undefined_symbols(
    analyses: &mut [Option<ElfAnalysis>],
    files: &[PkgFile],
    system: &SystemLibraries,
) {
    // Index providers by every name a DT_NEEDED entry can carry: the
    // library's SONAME and its file basename. The two are equal for
    // most libraries; when a package file is a symlink, the real file
    // behind it carries the SONAME. Duplicate providers under one key
    // (e.g. /lib64 and /usr/lib64 copies of one library) merge.
    let mut providers: HashMap<String, SymbolProvider> = HashMap::new();
    for (analysis, pkgfile) in analyses.iter().zip(files.iter()) {
        let Some(analysis) = analysis else { continue };
        let Some(ldd) = &analysis.ldd else { continue };
        if ldd.failed.is_some() {
            continue;
        }
        let mut keys = vec![basename(&pkgfile.name).to_string()];
        if let Some(soname) = &analysis.info.soname {
            if !keys.contains(soname) {
                keys.push(soname.clone());
            }
        }
        for key in keys {
            // Duplicate providers merged under one key keep the
            // first file's search paths: the copies are the same
            // library (e.g. /lib64 and /usr/lib64), and their
            // defined symbols and DT_NEEDED entries merge below
            // regardless.
            let entry = providers.entry(key).or_insert_with(|| SymbolProvider {
                defined: HashSet::new(),
                needs: Vec::new(),
                origin: installed_dir(&pkgfile.name),
                rpath: ldd.rpath.clone(),
                runpath: ldd.runpath.clone(),
                has_runpath: ldd.has_runpath,
            });
            entry.defined.extend(ldd.defined_symbols.iter().cloned());
            for need in &ldd.dependencies {
                if !entry.needs.contains(need) {
                    entry.needs.push(need.clone());
                }
            }
        }
    }
    if providers.is_empty() && system.is_empty() {
        return;
    }
    let providers: HashMap<String, Arc<SymbolProvider>> = providers
        .into_iter()
        .map(|(k, v)| (k, Arc::new(v)))
        .collect();

    // Walk each file's DT_NEEDED closure. Most libraries in a package
    // share the same direct dependencies and search paths, so
    // memoise the provided set on the direct-dependency list, the
    // file's ELF class (system candidates are class-matched), and
    // the file's search context.
    let mut closures: HashMap<ClosureKey, std::rc::Rc<HashSet<String>>> = HashMap::new();
    for (analysis, pkgfile) in analyses.iter_mut().zip(files.iter()) {
        let Some(analysis) = analysis else { continue };
        let Some(ldd) = &mut analysis.ldd else {
            continue;
        };
        if ldd.failed.is_some() || ldd.undefined_symbols.is_empty() {
            continue;
        }
        let direct = ldd.dependencies.clone();
        let is_64 = ldd.is_64;
        let root_ctx = SearchContext::for_object(
            &ldd.rpath,
            &ldd.runpath,
            ldd.has_runpath,
            &installed_dir(&pkgfile.name),
            &[],
        );
        let provided = closures
            .entry((direct.clone(), is_64, root_ctx.clone()))
            .or_insert_with(|| {
                let mut provided: HashSet<String> = HashSet::new();
                let mut visited: HashSet<(String, SearchContext)> = HashSet::new();
                let mut stack: Vec<(String, SearchContext)> = direct
                    .iter()
                    .cloned()
                    .map(|need| (need, root_ctx.clone()))
                    .collect();
                while let Some((soname, ctx)) = stack.pop() {
                    if !visited.insert((soname.clone(), ctx.clone())) {
                        continue;
                    }
                    let provider = providers
                        .get(&soname)
                        .or_else(|| providers.get(basename(&soname)))
                        .cloned()
                        .or_else(|| {
                            // The loader's order: the RPATH chain
                            // (the needing object's own RPATH
                            // first, then its loaders'), then the
                            // needing object's RUNPATH, then the
                            // system fallback (ldconfig cache, then
                            // the standard directories).
                            let chain_dirs: Vec<PathBuf> =
                                ctx.rpath_chain.iter().flatten().cloned().collect();
                            system
                                .provider_in_dirs(&soname, is_64, &chain_dirs)
                                .or_else(|| {
                                    system.provider_in_dirs(&soname, is_64, &ctx.runpath_dirs)
                                })
                        })
                        .or_else(|| system.provider(&soname, is_64));
                    if let Some(provider) = provider {
                        provided.extend(provider.defined.iter().cloned());
                        let child_ctx = SearchContext::for_object(
                            &provider.rpath,
                            &provider.runpath,
                            provider.has_runpath,
                            &provider.origin,
                            &ctx.rpath_chain,
                        );
                        stack.extend(
                            provider
                                .needs
                                .iter()
                                .cloned()
                                .map(|need| (need, child_ctx.clone())),
                        );
                    }
                }
                Rc::new(provided)
            })
            .clone();
        ldd.undefined_symbols
            .retain(|sym| !provided.contains(sym) && !ldd.defined_symbols.contains(sym));
    }
}

struct ObjdumpInfo {
    producers: Vec<String>,
    failed: Option<String>,
}

impl ObjdumpInfo {
    fn parse(path: &str) -> Self {
        let mut info = ObjdumpInfo {
            producers: Vec::new(),
            failed: None,
        };
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };
        let elf = match parse_elf(&data) {
            Ok(e) => e,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };
        match dwarf_producers(&elf, &data) {
            Ok(producers) => info.producers = producers,
            Err(e) => info.failed = Some(e.to_string()),
        }
        info
    }
}

/// Expensive per-file ELF metadata, parsed in parallel (rayon) before the
/// sequential finding-emission loop in `check_binary`.
///
/// Parsing is pure -- goblin over the file bytes, no shared state -- so it
/// parallelizes cleanly. Finding *emission* stays sequential in file order,
/// keeping the output bytes frozen.
struct ElfAnalysis {
    info: ReadelfInfo,
    ldd: Option<LddInfo>,
}

impl ElfAnalysis {
    /// Parse a file's ELF metadata. Called from the parallel pre-pass for
    /// every file that can reach the deep ELF checks; must stay
    /// side-effect free.
    fn parse(pkgfile: &PkgFile) -> Self {
        let info = ReadelfInfo::parse(&pkgfile.path, &pkgfile.name);
        // Mirrors the `run_elf_checks` gate: ldd info only for non-archives
        // that are dynamically linked.
        let ldd = if !pkgfile.magic.contains("current ar archive")
            && pkgfile.magic.contains("dynamically linked")
        {
            Some(LddInfo::parse(&pkgfile.path, true))
        } else {
            None
        };
        Self { info, ldd }
    }

    /// Whether this file can reach the deep ELF checks: the cheap,
    /// magic-based gates from `check_binary`, minus the package-level
    /// `noarch` gate (passed in). Erring on the side of parsing is safe --
    /// extra parses only cost time, never correctness.
    fn wants_analysis(pkgfile: &PkgFile, is_noarch: bool) -> bool {
        // Ghost files are in the header but not in the payload: there
        // is nothing on disk to parse.
        if pkgfile.is_ghost() {
            return false;
        }
        let magic = &pkgfile.magic;
        let is_ebpf = magic.contains("eBPF");
        let is_elf = elf_regex().is_match(magic).unwrap_or(false) && !is_ebpf;
        if !(is_elf || magic.contains("current ar archive")) || is_noarch {
            return false;
        }
        let name = &pkgfile.name;
        !(magic.contains("Objective caml native")
            || magic.contains("Lua bytecode")
            || name.ends_with(".o")
            || name.ends_with(".static")
            || name.ends_with(".gox")
            || name.ends_with(".go"))
    }
}

/// Raw bytes of a DWARF section, with linker compression undone.
///
/// gimli never decompresses debug sections: the crate contains no inflate,
/// zlib, zstd or SHF_COMPRESSED handling, and upstream gimli-rs/gimli#195
/// (open since 2017) shows no intent to add any -- gimli stays no_std and
/// dependency-light by design, so the caller owns decompression. gcc/binutils
/// emit three compressed forms, all unwrapped here so the gimli loader stays
/// untouched:
/// * `SHF_COMPRESSED` sections with `ELFCOMPRESS_ZLIB`: an `Elf_Chdr` header
///   followed by the zlib stream;
/// * `SHF_COMPRESSED` sections with `ELFCOMPRESS_ZSTD`: same header, zstd
///   stream;
/// * legacy GNU `.zdebug_*` sections (looked up when `<name>` is absent):
///   "ZLIB\0" magic, 8-byte big-endian uncompressed size, zlib stream.
///
/// Uncompressed sections pass through unchanged.
fn dwarf_section_bytes(
    elf: &goblin::elf::Elf<'_>,
    data: &[u8],
    name: &str,
) -> Result<Vec<u8>, gimli::Error> {
    use goblin::elf::compression_header::{ELFCOMPRESS_ZLIB, ELFCOMPRESS_ZSTD};
    use goblin::elf::section_header::SHF_COMPRESSED;

    // Legacy GNU zlib sections rename `.debug_*` to `.zdebug_*`.
    let gnu_name = name
        .strip_prefix(".debug")
        .map(|rest| format!(".zdebug{rest}"));
    let sh = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(name))
        .or_else(|| {
            gnu_name.as_deref().and_then(|gnu| {
                elf.section_headers
                    .iter()
                    .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(gnu))
            })
        });
    let Some(sh) = sh else {
        return Ok(Vec::new());
    };
    let start = sh.sh_offset as usize;
    let end = start.saturating_add(sh.sh_size as usize);
    let raw = data.get(start..end).unwrap_or(&[]);

    let int = |bytes: &[u8]| -> Result<u32, gimli::Error> {
        bytes
            .try_into()
            .map(|w: [u8; 4]| {
                if elf.little_endian {
                    u32::from_le_bytes(w)
                } else {
                    u32::from_be_bytes(w)
                }
            })
            .map_err(|_| gimli::Error::Io)
    };

    if sh.sh_flags & u64::from(SHF_COMPRESSED) != 0 {
        // Elf_Chdr is ch_type u32, then ch_size/ch_addralign as u32 (32-bit)
        // or u32 padding + u64/u64 (64-bit), all in the file's endianness.
        let chdr_len = if elf.is_64 { 24 } else { 12 };
        let (hdr, stream) = raw.split_at_checked(chdr_len).ok_or(gimli::Error::Io)?;
        return match int(&hdr[..4])? {
            ELFCOMPRESS_ZLIB => {
                use std::io::Read;
                let mut out = Vec::new();
                flate2::read::ZlibDecoder::new(stream)
                    .read_to_end(&mut out)
                    .map_err(|_| gimli::Error::Io)?;
                Ok(out)
            }
            ELFCOMPRESS_ZSTD => zstd::decode_all(stream).map_err(|_| gimli::Error::Io),
            // Unknown to us is unknown to objdump too: surface the failure
            // instead of guessing at the bytes.
            _ => Err(gimli::Error::Io),
        };
    }
    if elf
        .shdr_strtab
        .get_at(sh.sh_name)
        .is_some_and(|n| n.starts_with(".zdebug_"))
    {
        let (hdr, stream) = raw.split_at_checked(13).ok_or(gimli::Error::Io)?;
        if &hdr[..5] != b"ZLIB\0".as_slice() {
            return Err(gimli::Error::Io);
        }
        use std::io::Read;
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(stream)
            .read_to_end(&mut out)
            .map_err(|_| gimli::Error::Io)?;
        return Ok(out);
    }
    Ok(raw.to_vec())
}

/// `DW_AT_producer` of every DWARF compilation unit, in section order.
/// Pure-Rust replacement for the reference's `objdump --dwarf=info` parse.
/// One deliberate departure: the reference keeps the text after the last `:`
/// of the `DW_AT_producer` line, truncating a producer that itself contains a
/// colon; the port keeps the full attribute string (ledgered).
fn dwarf_producers(elf: &goblin::elf::Elf<'_>, data: &[u8]) -> Result<Vec<String>, gimli::Error> {
    use std::borrow::Cow;

    use gimli::{DwarfSections, EndianSlice, RunTimeEndian, SectionId};

    let endian = if elf.little_endian {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let dwarf_sections =
        DwarfSections::load(|id: SectionId| -> Result<Cow<'_, [u8]>, gimli::Error> {
            Ok(Cow::Owned(dwarf_section_bytes(elf, data, id.name())?))
        })?;
    let borrow_section: &dyn for<'a> Fn(&'a Cow<[u8]>) -> EndianSlice<'a, RunTimeEndian> =
        &|s| EndianSlice::new(s, endian);
    let dwarf = dwarf_sections.borrow(borrow_section);

    let mut producers = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        let Some(entry) = entries.next_dfs()? else {
            continue;
        };
        let Some(attr) = entry.attr(gimli::DW_AT_producer) else {
            continue;
        };
        if let Ok(producer) = dwarf.attr_string(&unit, attr.value()) {
            producers.push(String::from_utf8_lossy(producer.slice()).into_owned());
        }
    }
    Ok(producers)
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
        cmd.arg(path).env("LC_ALL", "C");
        // The spawn retries transient fork/exec failures, like the
        // probe's: one transient failure on a loaded runner must not
        // read as a strings failure.
        let out = spawn_with_retry(|| cmd.output());
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
        cmd.args(["t", path]).env("LC_ALL", "C");
        // Same transient-spawn retry as `StringsInfo::parse`.
        let out = spawn_with_retry(|| cmd.output());
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
    system_libraries: SystemLibraries,
    pie_exec_regexes: Vec<Regex>,
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

/// A `_FORTIFY_SOURCE` wrapper from libc, i.e. a `__foo_chk` symbol
/// (`__memcpy_chk`, `__sprintf_chk`, ...). Symbol names may carry a
/// `@VERSION` suffix in `.dynsym`; strip it before matching.
/// The `__*_chk` shape is deliberately broad: glibc fortifies any
/// function, present or future, so an allowlist would rot. The failure
/// mode of over-matching is a missed warning on the package's own
/// binary, which is low severity.
fn is_fortify_symbol(name: &str) -> bool {
    let base = name.split('@').next().unwrap_or(name);
    base.starts_with("__") && base.ends_with("_chk")
}

/// A pure dynamic-loader shim: every undefined function import is a
/// dynamic-loader entry point (`dlopen`, `dlsym`, `dlclose`, `dlerror`,
/// `dladdr`) or CRT boilerplate (`__cxa_finalize`, `_ITM_*`,
/// `__gmon_start__`). Such a binary only forwards calls into libraries
/// loaded at runtime; it implements no logic of its own and therefore has
/// no stack buffers for `-fstack-protector` to protect. `missing-stack-protector`
/// stays quiet for these. A binary with no undefined imports at all (e.g.
/// static) is not a shim. Symbol names may carry a `@VERSION` suffix in
/// `.dynsym`; strip it before matching.
fn is_pure_loader_shim(undefined_functions: &[String]) -> bool {
    // No undefined imports at all (e.g. a static binary) is not a shim:
    // it has real code, just no external calls.
    if undefined_functions.is_empty() {
        return false;
    }
    undefined_functions.iter().all(|name| {
        let base = name.split('@').next().unwrap_or(name);
        matches!(
            base,
            "dlopen"
                | "dlsym"
                | "dlclose"
                | "dlerror"
                | "dladdr"
                | "__cxa_finalize"
                | "__gmon_start__"
        ) || base.starts_with("_ITM_")
    })
}

/// The call set a hardening predicate judges a binary on. A dynamic
/// binary is judged on its undefined imports: a defined export of a name
/// is the binary's own code, not a call, and a NOTYPE import is still an
/// import. A static binary has no imports at all, so its function
/// symbols are the call set.
fn hardening_call_set(info: &ReadelfInfo) -> &[String] {
    if info.has_dynamic {
        &info.undefined_functions
    } else {
        &info.functions
    }
}

/// Whether a hardening finding applies to this binary: the binary must have
/// "something to protect". Each check defines its own predicate over the
/// binary's symbols; the mechanism is shared so the two checks stay in sync.
///
/// The fortify predicate counts *distinct* fortifiable imports and
/// requires at least three. glibc redirects a call to its `__*_chk`
/// wrapper only when the destination object size is compile-time known,
/// so a binary with one or two distinct fortifiable imports and no
/// `__*_chk` symbol is just as consistent with a fortified build whose
/// calls all have runtime-sized destinations as with an unfortified
/// build: the evidence cannot tell the two apart, and the finding would
/// be unactionable for that shape (rpmcrab#529).
fn is_fortify_applicable(info: &ReadelfInfo) -> bool {
    let mut distinct: Vec<&str> = Vec::new();
    for name in hardening_call_set(info) {
        if !is_fortifiable_import(name) {
            continue;
        }
        let base = name.split('@').next().unwrap_or(name);
        if !distinct.contains(&base) {
            distinct.push(base);
            if distinct.len() >= 3 {
                return true;
            }
        }
    }
    false
}

fn is_stack_protector_applicable(info: &ReadelfInfo) -> bool {
    // Pure loader shims implement no logic of their own (rpmcrab#447),
    // and a binary importing no SSP-relevant call has no buffer-shaped
    // stack data for a canary to guard (rpmcrab#452).
    !is_pure_loader_shim(&info.undefined_functions)
        && hardening_call_set(info)
            .iter()
            .any(|s| is_ssp_relevant_import(s))
}

/// A libc function that `_FORTIFY_SOURCE` can instrument. `missing-fortify`
/// fires only when a binary imports at least three distinct functions
/// from this set without any `__*_chk` symbol (see
/// `is_fortify_applicable`): below that count the absence of `__*_chk`
/// symbols proves nothing about how the binary was built. Symbol names
/// may carry a `@VERSION` suffix in `.dynsym`; strip it before matching.
///
/// The set is the base name of every `__*_chk` symbol glibc exports
/// (glibc 2.39-2.44), i.e. every function the headers redirect to a
/// checked wrapper under `_FORTIFY_SOURCE`. Two deliberate exclusions:
/// `__fdelt_chk` backs the `FD_SET` macro and has no importable base
/// name, and `memccpy` has no `__memccpy_chk` in glibc's dynamic symbol
/// table (calls stay plain under `_FORTIFY_SOURCE`).
fn is_fortifiable_import(name: &str) -> bool {
    let base = name.split('@').next().unwrap_or(name);
    matches!(
        base,
        // string.h
        "memcpy"
            | "memmove"
            | "mempcpy"
            | "memset"
            | "memset_explicit"
            | "explicit_bzero"
            | "strcpy"
            | "strncpy"
            | "stpcpy"
            | "stpncpy"
            | "strcat"
            | "strncat"
            | "strlcpy"
            | "strlcat"
            // stdio.h
            | "printf"
            | "fprintf"
            | "vprintf"
            | "vfprintf"
            | "sprintf"
            | "vsprintf"
            | "snprintf"
            | "vsnprintf"
            | "dprintf"
            | "vdprintf"
            | "asprintf"
            | "vasprintf"
            | "obstack_printf"
            | "obstack_vprintf"
            | "fgets"
            | "fgets_unlocked"
            | "fread"
            | "fread_unlocked"
            | "gets"
            // wchar.h: formatted I/O
            | "wprintf"
            | "fwprintf"
            | "vwprintf"
            | "vfwprintf"
            | "swprintf"
            | "vswprintf"
            | "fgetws"
            | "fgetws_unlocked"
            // wchar.h: string functions
            | "wmemcpy"
            | "wmemmove"
            | "wmempcpy"
            | "wmemset"
            | "wcscpy"
            | "wcpcpy"
            | "wcsncpy"
            | "wcpncpy"
            | "wcscat"
            | "wcsncat"
            | "wcslcpy"
            | "wcslcat"
            // stdlib.h / wchar.h: conversions
            | "mbstowcs"
            | "wcstombs"
            | "wctomb"
            | "wcrtomb"
            | "mbsrtowcs"
            | "wcsrtombs"
            | "mbsnrtowcs"
            | "wcsnrtombs"
            // unistd.h
            | "read"
            | "pread"
            | "pread64"
            | "readlink"
            | "readlinkat"
            | "getcwd"
            | "getwd"
            | "realpath"
            | "confstr"
            | "getgroups"
            | "gethostname"
            | "getdomainname"
            | "getlogin_r"
            | "ttyname_r"
            | "ptsname_r"
            // poll.h
            | "poll"
            | "ppoll"
            // sys/socket.h
            | "recv"
            | "recvfrom"
            // arpa/inet.h
            | "inet_ntop"
            | "inet_pton"
            // syslog.h
            | "syslog"
            | "vsyslog"
            // setjmp.h
            | "longjmp"
    )
}

/// A libc call that manipulates buffer-shaped data in a way a stack
/// canary exists to guard. `missing-stack-protector` fires only when a
/// binary imports at least one of these without `__stack_chk_fail`
/// (rpmcrab#452): `-fstack-protector-strong` instruments functions with
/// stack arrays and address-taken locals, and imports are the only
/// ELF-visible proxy for "this file manipulates buffer-shaped data at
/// all". A binary importing none of them has, as far as the artifact
/// can tell, nothing for a canary to guard, so the finding would be
/// unactionable noise. Symbol names may carry a `@VERSION` suffix in
/// `.dynsym`; strip it before matching.
///
/// The plain set is the one ground-truthed against the Factory corpus
/// in the rpmcrab#452 sweep audit (the audited genuine catches --
/// apparmor, apfsprogs, mjpg-streamer -- all import plain members of
/// it), completed by family so no same-risk class is split by spelling:
/// the raw buffer fills cover the read/recv families in their plain,
/// positioned and vectored/message forms and every path function that
/// writes into a caller buffer, and the string copies include the
/// bounded `strl*` spellings. One deliberate boundary call: stdio
/// buffered readers (`fread`, `fgets`) are out (zoo's `fiz` reads into
/// heap buffers; its finding was never actionable, and including them
/// re-admits it).
fn is_ssp_relevant_import(name: &str) -> bool {
    let base = name.split('@').next().unwrap_or(name);
    if is_ssp_relevant_plain(base) {
        return true;
    }
    // A fortified spelling names the same buffer operation as the plain
    // call: `__strcpy_chk` is `strcpy` with a size check, and a
    // `-D_FORTIFY_SOURCE` binary without a canary is exactly the silent
    // `-fstack-protector` downgrade shape this check exists to catch.
    // Strip the `_chk` suffix (and the wrapper's leading `__`) and
    // judge the plain name; a spelling whose plain form is out of the
    // set (`__fgets_chk`, `__printf_chk`) stays out with it.
    match base.strip_suffix("_chk") {
        Some(inner) => {
            is_ssp_relevant_plain(inner)
                || inner.strip_prefix("__").is_some_and(is_ssp_relevant_plain)
        }
        None => false,
    }
}

/// The plain (unfortified) spelling half of `is_ssp_relevant_import`:
/// `base` is a symbol name with any `@VERSION` suffix already stripped.
fn is_ssp_relevant_plain(base: &str) -> bool {
    matches!(
        base,
        // string.h: string/memory copies and fills
        "memcpy"
            | "memmove"
            | "mempcpy"
            | "memset"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "stpcpy"
            | "stpncpy"
            // The bounded spellings of the same copies (glibc >= 2.38)
            | "strlcpy"
            | "strlcat"
            // OpenBSD's fortified spelling, in the audited set
            | "strcpy_chk"
            // stdio.h: formatted output into caller buffers
            | "sprintf"
            | "vsprintf"
            | "snprintf"
            | "vsnprintf"
            // stdio.h: unformatted input (the scanf family, including
            // the `__isoc99_` spellings glibc has emitted since 2.7 and
            // the `__isoc23_` spellings that replaced them in 2.38)
            | "gets"
            | "scanf"
            | "fscanf"
            | "sscanf"
            | "vscanf"
            | "vfscanf"
            | "vsscanf"
            | "__isoc99_scanf"
            | "__isoc99_fscanf"
            | "__isoc99_sscanf"
            | "__isoc99_vscanf"
            | "__isoc99_vfscanf"
            | "__isoc99_vsscanf"
            | "__isoc23_scanf"
            | "__isoc23_fscanf"
            | "__isoc23_sscanf"
            | "__isoc23_vscanf"
            | "__isoc23_vfscanf"
            | "__isoc23_vsscanf"
            // alloca.h
            | "alloca"
            | "__alloca"
            // unistd.h / sys/socket.h: raw buffer fills -- the read and
            // recv families in their plain, positioned and vectored /
            // message forms, and the path functions that write into a
            // caller buffer in both spellings
            | "read"
            | "pread"
            | "pread64"
            | "readv"
            | "preadv"
            | "preadv64"
            | "recv"
            | "recvfrom"
            | "recvmsg"
            | "readlink"
            | "readlinkat"
            | "getcwd"
            | "getwd"
            | "realpath"
    )
}

/// The stack-protector failure handler. Both `-fstack-protector` and
/// `-fstack-protector-strong` emit this symbol, so presence alone cannot
/// distinguish basic from strong protection.
fn is_stack_protector_symbol(name: &str) -> bool {
    name.split('@').next().unwrap_or(name) == "__stack_chk_fail"
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
        let (strings, _) = Tool::probe(&source, "strings", &[]);
        let (ar, _) = Tool::probe(&source, "ar", &["--version"]);
        BinariesCheck {
            checked_files: 0,
            strings,
            ar,
            system_lib_paths: get_strings("SystemLibPaths"),
            system_libraries: SystemLibraries::system(),
            pie_exec_regexes,
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
        let mut check = Self::with_tool_source(config, test_source(bin_dir));
        // Tests are hermetic: undefined symbols never resolve against
        // the host's libraries unless a test installs fixture roots
        // in `system_libraries` itself.
        check.system_libraries = SystemLibraries::empty();
        check
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
                // A 50-byte window could never equal the 52-byte marker
                // prefix; the substring search alone matches the reference.
                if String::from_utf8_lossy(head).contains(
                    "This wrapper script should never be moved out of the build directory",
                ) {
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

    fn check_no_binary(
        &self,
        pkg: &Pkg,
        has_binary: bool,
        has_file_in_libdir: bool,
        out: &mut Filter,
    ) {
        if !has_binary && !has_file_in_libdir && pkg.arch != "noarch" {
            add_info(out, Level::Warning, pkg, "no-binary", &[]);
        }
    }

    fn check_noarch_with_lib64(&self, pkg: &Pkg, has_file_in_lib64: bool, out: &mut Filter) {
        if pkg.arch == "noarch" && has_file_in_lib64 {
            add_info(out, Level::Error, pkg, "noarch-with-lib64", &[]);
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

    /// checksec-style verification of the effective hardening state of the
    /// artifact, from the ELF headers and symbol tables rather than the
    /// compile flags: flag soup cannot catch silent downgrades (e.g. a
    /// `-fstack-protector` appended after `%{optflags}` downgrading strong
    /// to basic SSP while presence checks pass).
    ///
    /// FORTIFY is the presence of `__*_chk` symbols, SSP the presence of
    /// `__stack_chk_fail`. Both basic and strong SSP emit that symbol, so
    /// the check is presence-only: telling the two apart needs per-function
    /// canary-coverage analysis, which is out of scope here.
    ///
    /// RELRO is the GNU_RELRO segment plus BIND_NOW (full) or without it
    /// (partial). PIE stays with the existing `check_non_pie`: DYN is normal
    /// for shared objects, so the check only makes sense for executables.
    ///
    /// Go and Zig binaries are skipped: neither toolchain emits any of
    /// these C-hardening artifacts, so every finding would be noise. Rust,
    /// Haskell and OCaml binaries skip only the two C-compiler findings
    /// below (see `is_rust_binary`, `is_haskell_binary`,
    /// `is_ocaml_binary`); the linker-level RELRO checks still apply.
    /// AMDGPU code objects skip the RELRO findings: no dynamic linker
    /// ever loads them, so BIND_NOW has nothing to govern.
    fn check_hardening(&self, pkg: &Pkg, pkgfile: &PkgFile, info: &ReadelfInfo, out: &mut Filter) {
        use goblin::elf::header::{ET_DYN, ET_EXEC};
        if self.is_archive || info.is_go_binary() || info.is_zig_binary() {
            return;
        }
        // Separate debuginfo files are never executed or loaded by the
        // dynamic linker: hardening findings on them are unactionable noise.
        // `is_debug` covers the `.debug` name suffix; the path covers the
        // rest of the canonical debuginfo location (e.g. ovmf's GdbSyms.dll).
        if info.is_debug || pkgfile.name.starts_with("/usr/lib/debug/") {
            return;
        }
        if info.elf_type != ET_EXEC && info.elf_type != ET_DYN {
            return;
        }
        // Rust, Haskell and OCaml emit neither `_FORTIFY_SOURCE`
        // instrumentation nor default stack-protector instrumentation
        // for their own code: both findings would be noise. When in
        // doubt the binary is treated as C.
        let is_rust = info.is_rust_binary();
        let is_haskell = info.is_haskell_binary();
        let is_ocaml = info.is_ocaml_binary();
        // Each finding applies only when the binary has "something to
        // protect" (rpmcrab#447): a binary that imports fewer than three
        // distinct fortifiable libc functions cannot be told apart from
        // a fortified build whose fortifiable calls all have
        // runtime-sized destinations (rpmcrab#529), and a
        // pure loader shim implements no logic of its own and therefore
        // has no stack buffers for `-fstack-protector` to protect. Since
        // rpmcrab#452 the stack-protector finding additionally requires
        // an SSP-relevant import: a binary whose calls are none of the
        // buffer-shaped ones has nothing for a canary to guard either.
        // In all these cases the finding would be unactionable noise.
        // Presence counts defined symbols and imports alike: an imported
        // `__*_chk` wrapper (FUNC or NOTYPE) is the fortified call, and a
        // defined one is the binary's own fortification.
        let has_fortify_symbol = info
            .functions
            .iter()
            .chain(&info.undefined_functions)
            .any(|s| is_fortify_symbol(s));
        if !is_rust
            && !is_haskell
            && !is_ocaml
            && is_fortify_applicable(info)
            && !has_fortify_symbol
        {
            add_info(
                out,
                Level::Warning,
                pkg,
                "missing-fortify",
                &[&pkgfile.name],
            );
        }
        let has_ssp_symbol = info
            .functions
            .iter()
            .chain(&info.undefined_functions)
            .any(|s| is_stack_protector_symbol(s));
        if !is_rust
            && !is_haskell
            && !is_ocaml
            && is_stack_protector_applicable(info)
            && !has_ssp_symbol
        {
            add_info(
                out,
                Level::Warning,
                pkg,
                "missing-stack-protector",
                &[&pkgfile.name],
            );
        }
        // RELRO and BIND_NOW are dynamic-linker features: a static binary
        // has no lazy binding for them to protect, so neither finding is
        // meaningful without a dynamic section. AMDGPU code objects are
        // gated out on the same basis: the GPU runtime loads them, the
        // dynamic linker never does, and the amdgcn link emits no FLAGS
        // for BIND_NOW to attach to (rpmcrab#509).
        if info.has_dynamic && info.elf_machine != goblin::elf::header::EM_AMDGPU {
            let has_relro = info.program_headers.iter().any(|h| h.name == "GNU_RELRO");
            if !has_relro {
                add_info(out, Level::Warning, pkg, "missing-relro", &[&pkgfile.name]);
            } else if !info.bind_now {
                add_info(out, Level::Warning, pkg, "partial-relro", &[&pkgfile.name]);
            }
        }
        // Control-flow protection (rpmcrab#667): openSUSE's
        // `%{optflags}` carry `-fcf-protection` on x86_64, which makes
        // the compiler record the IBT and SHSTK features in
        // `.note.gnu.property` and emit ENDBR64 at indirect-branch
        // targets. The finding requires both records to fall short.
        // The property alone does not prove a flagless build: it is
        // the bitwise AND over all link inputs, so one input carrying no
        // property (a hand-written assembly or prebuilt object) clears
        // it for the whole binary, and rebuilding changes nothing
        // there — the merged note is what `-z cet-report` reports on.
        // Measured over the Factory corpus (51,589 RPMs; 69,894 x86_64
        // ET_EXEC/ET_DYN ELFs): 59,022 (84.4%) carry both bits, 10,845
        // (15.5%) carry no FEATURE_1_AND at all and 27 carry exactly
        // one bit — but of the 9,664 no-property ELFs outside the Go
        // and debuginfo gates, 9,551 (98.8%) carry an ENDBR64 record
        // in `.text`, as do all 27 one-bit ELFs (the asm-heavy FFmpeg
        // family). The record is applicability evidence, not
        // attribution: it shows the flag reached some of the code,
        // not which link input contributed it — flag-built CRT glue
        // lands in `.text` too. The ENDBR64 absence is this
        // finding's applicability evidence, in the sense of
        // rpmcrab#447: only a binary whose code also shows no trace of
        // the flag is reported. Like the fortify and stack-protector
        // findings above it applies to C binaries only — Rust, Haskell
        // and OCaml emit neither the property nor ENDBR64 for their
        // own code. A truncated property entry is Unreadable, not
        // absent: damage proves nothing either way.
        let cf_unprotected = match info.x86_feature_1_and {
            X86Feature1And::Present(f) => f & X86_FEATURE_1_IBT_SHSTK != X86_FEATURE_1_IBT_SHSTK,
            X86Feature1And::Absent => true,
            X86Feature1And::Unreadable => false,
        };
        if info.elf_machine == goblin::elf::header::EM_X86_64
            && !is_rust
            && !is_haskell
            && !is_ocaml
            && !info.has_endbr64
            && cf_unprotected
        {
            add_info(
                out,
                Level::Warning,
                pkg,
                "missing-cf-protection",
                &[&pkgfile.name],
            );
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
        if pkg.files.iter().all(|f| f.name != symlink) {
            let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if base.starts_with("lib") || base.starts_with("ld-") {
                add_info(out, Level::Error, pkg, "no-ldconfig-symlink", &[shlib]);
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
                            // A baselibs package carries the version
                            // before a trailing -32bit or -64bit.
                            let pkgname = pkgname
                                .strip_suffix("-32bit")
                                .or_else(|| pkgname.strip_suffix("-64bit"))
                                .unwrap_or(pkgname);
                            // A name matches when either limb accepts
                            // it:
                            //
                            // (A) It equals a name derived from the
                            // SONAME itself, per the SLPP construction:
                            // the stem ('.' folded to '_') plus the
                            // version, glued (libfoo.so.1 -> libfoo1)
                            // or dash-separated (libbz2.so.1 ->
                            // libbz2-1); stem + '-' + soversion when
                            // the SONAME carries a -<pkgversion>
                            // (libgame2-1.9.so.10.0.0 ->
                            // libgame2-1_9-10_0_0). Comparing whole
                            // derived names is what tells a digit that
                            // belongs to the stem (libx11.so.1 ->
                            // libx111) from a longer version run
                            // (libkdecorations3private11 for .so.1,
                            // bsc#1237372).
                            //
                            // (B) It ends with the expected suffix at a
                            // non-digit boundary: the trailing version
                            // run matches as a whole, but the stem is
                            // not policed. A package legitimately ships
                            // libraries whose stems its name does not
                            // derive from (libopenssl3 ships
                            // libssl.so.3, libicu73 ships
                            // libicuuc.so.73), and the reference stays
                            // quiet there.
                            //
                            // Both limbs are tried on the name as-is and
                            // once more with a trailing
                            // -<letters><digits> flavour segment
                            // (libgfortran5-gcc15, libnetcdf22-openmpi5)
                            // stripped: the version sits before the
                            // flavour tail, which is not part of the
                            // name.
                            let stem = match soname.split_once(".so") {
                                Some((head, _)) => head,
                                None => soname,
                            }
                            .replace('.', "_");
                            let soversion_pkgform = soversion.replace('.', "_");
                            let expected: Vec<String> = if pkgversion.is_empty() {
                                vec![
                                    format!("{stem}{soversion_pkgform}"),
                                    format!("{stem}-{soversion_pkgform}"),
                                ]
                            } else if soversion.is_empty() {
                                vec![stem]
                            } else {
                                vec![format!("{stem}-{soversion_pkgform}")]
                            };
                            fn strip_flavour(name: &str) -> Option<&str> {
                                let (head, tail) = name.rsplit_once('-')?;
                                if !head.is_empty()
                                    && tail.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                                    && tail.chars().last().is_some_and(|c| c.is_ascii_digit())
                                    && tail.chars().all(|c| c.is_ascii_alphanumeric())
                                {
                                    Some(head)
                                } else {
                                    None
                                }
                            }
                            fn whole_suffix(name: &str, suffix: &str) -> bool {
                                name.strip_suffix(suffix).is_some_and(|prefix| {
                                    prefix
                                        .chars()
                                        .next_back()
                                        .is_none_or(|c| !c.is_ascii_digit())
                                })
                            }
                            let accepts = |name: &str| {
                                expected.iter().any(|e| e == name)
                                    || whole_suffix(name, &soversion_str)
                            };
                            let name_matches =
                                accepts(pkgname) || strip_flavour(pkgname).is_some_and(accepts);
                            if !soversion_str.is_empty() && !name_matches {
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
        // undefined-non-weak-symbol is meaningful for shared libraries only:
        // in an executable the undefined symbols resolve at load time, so the
        // reference's `ldd -r` stays silent there while a raw UND scan fires
        // hundreds of bogus hits.
        // The level is Warning TEMPORARILY (issue #699, pending #701): the
        // resolver's provider universe is the same package plus ambient
        // system libraries, so a symbol provided by another package in the
        // dependency closure reads as undefined; the #701 investigation
        // sampled the Factory corpus and found 97.6% of findings resolve
        // within the closure. #701 tightens the resolver (provider
        // universe = the whole invocation's package set); the residue
        // returns to Error there.
        if info.is_shlib {
            for symbol in &ldd.undefined_symbols {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "undefined-non-weak-symbol",
                    &[&pkgfile.name, symbol],
                );
            }
        }
        let info_type = if info.is_shlib {
            Level::Error
        } else {
            Level::Warning
        };
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
            // Deliberate divergence (#593): always an error. The
            // reference splits the level on the setuid bit (E when
            // installed setuid, W otherwise); privilege-drop
            // correctness is security-critical and the check is
            // high-precision, so the level does not split.
            add_info(
                out,
                Level::Error,
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
            // The reference readelf parser only records non-empty
            // `Library runpath: [...]` matches, so an empty entry never
            // reaches its check.
            if runpaths.is_empty() {
                continue;
            }
            for runpath in runpaths.split(':') {
                let mut rp = runpath.to_string();
                if rp.contains("$ORIGIN") {
                    let parent = Path::new(&pkgfile.name)
                        .parent()
                        .and_then(|p| p.to_str())
                        .unwrap_or("");
                    rp = rp.replace("$ORIGIN", parent);
                    // Mirror the reference `Path(runpath).resolve()`: collapse
                    // `.` and `..` lexically, without touching the filesystem.
                    rp = normalize_dotdot(&rp);
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
            } else if !info.is_go_binary() && !info.is_plugin_like() {
                // Go binaries are ET_DYN with no DT_NEEDED, and plugin-like
                // objects legitimately carry none; only genuine shared
                // objects are missing dependency information here.
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "shared-library-without-dependency-information",
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
        let forbidden = get_strings("ForbiddenOptflags");
        if forbidden.is_empty() {
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
            let forbidden_found: Vec<&str> = forbidden
                .iter()
                .filter(|f| tokens.contains(&f.as_str()))
                .map(|s| s.as_str())
                .collect();
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

    fn run_elf_checks(
        &mut self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        config: &Config,
        out: &mut Filter,
        pre: Option<&ElfAnalysis>,
    ) {
        if self.is_archive && !self.is_standard_archive(pkg, pkgfile, out) {
            self.is_nonstandard_archive = true;
            return;
        }
        // The parallel pre-pass in `check_binary` parses every file that can
        // reach this point; parse inline if the gates ever drift (correct,
        // just serial).
        let owned;
        let analysis = match pre {
            Some(a) => a,
            None => {
                owned = ElfAnalysis::parse(pkgfile);
                &owned
            }
        };
        let info = &analysis.info;
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

        if let Some(ldd) = analysis.ldd.as_ref() {
            if let Some(reason) = &ldd.failed {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "ldd-failed",
                    &[&pkgfile.name, reason],
                );
                return;
            }
        }

        // The reference runs these in a thread pool; serial is equivalent.
        self.check_lto_section(pkg, pkgfile, info, out);
        self.check_no_text_in_archive(pkg, pkgfile, info, out);
        self.check_missing_symtab_in_archive(pkg, pkgfile, info, out);
        self.check_missing_debug_info_in_archive(pkg, pkgfile, info, out);
        self.check_executable_stack(pkg, pkgfile, info, out);
        self.check_hardening(pkg, pkgfile, info, out);
        self.check_shared_library(pkg, pkgfile, info, out);
        if let Some(l) = analysis.ldd.as_ref() {
            self.check_dependency(pkg, pkgfile, info, l, out);
            self.check_library_dependency_location(pkg, pkgfile, l, out);
        }
        self.check_security_functions(pkg, pkgfile, info, out);
        self.check_rpath(pkg, pkgfile, info, out);
        self.check_library_dependency(pkg, pkgfile, info, out);
        self.check_forbidden_functions(pkg, pkgfile, info, config, out);
        self.check_optflags(pkg, pkgfile, config, out);
        self.check_hash_sections(pkg, pkgfile, info, out);
        self.check_no_patchable_function_entries_in_archive(pkg, pkgfile, info, out);
    }
}

impl Check for BinariesCheck {
    fn name(&self) -> &'static str {
        "BinariesCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, config: &Config, out: &mut Filter) {
        let mut pkg_has_binary = false;
        let mut pkg_has_file_in_lib64 = false;
        // The no-binary exemption covers the package's native libdir only:
        // /usr/lib64 + /lib64 on 64-bit arches, /usr/lib + /lib on 32-bit
        // ones. A hwcaps subarch (x86_64_v3) takes its base arch's libdir.
        // On 32-bit %_libdir is /usr/lib, so a devel subpackage there
        // is just as arch-bound as one in /usr/lib64; content under the
        // other word size's libdir (e.g. /usr/lib/systemd on x86_64) does
        // not exempt.
        let mut pkg_has_file_in_libdir = false;
        let native_libdir_is_lib64 = is_64bit_arch(&pkg.arch);

        // Parse the expensive per-file ELF metadata in parallel (rayon).
        // Finding emission stays in the sequential loop below, in file
        // order, so the output bytes are unchanged.
        let is_noarch = pkg.arch == "noarch";
        let mut analyses: Vec<Option<ElfAnalysis>> = pkg
            .files
            .par_iter()
            .map(|pkgfile| {
                ElfAnalysis::wants_analysis(pkgfile, is_noarch).then(|| ElfAnalysis::parse(pkgfile))
            })
            .collect();
        // Model `ldd -r`'s provider resolution before emission:
        // subtract the undefined symbols each file's DT_NEEDED
        // closure defines, looking providers up in the package
        // first and on the system second (plusky/rpmcrab#467).
        resolve_undefined_symbols(&mut analyses, &pkg.files, &self.system_libraries);

        for (idx, pkgfile) in pkg.files.iter().enumerate() {
            let fname: &str = &pkgfile.name;
            self.check_libtool_wrapper(pkg, fname, pkgfile, out);
            self.check_invalid_la_file(pkg, fname, pkgfile, out);

            // Trailing slashes on every prefix: a file under the libdir is
            // required. A slash-less prefix would also match the bare
            // directory entry itself (owning the libdir is not shipping a
            // library) and non-libdir prefixes such as /usr/libexec.
            if fname.starts_with("/usr/lib64/") || fname.starts_with("/lib64/") {
                pkg_has_file_in_lib64 = true;
                if native_libdir_is_lib64 {
                    pkg_has_file_in_libdir = true;
                }
            } else if fname.starts_with("/usr/lib/") || fname.starts_with("/lib/") {
                if !native_libdir_is_lib64 {
                    pkg_has_file_in_libdir = true;
                }
            }

            let is_ocaml_native = pkgfile.magic.contains("Objective caml native");
            let is_lua_bytecode = pkgfile.magic.contains("Lua bytecode");
            let is_ebpf = pkgfile.magic.contains("eBPF");
            let is_elf = elf_regex().is_match(&pkgfile.magic).unwrap_or(false) && !is_ebpf;

            let is_binary_class = is_elf
                || pkgfile.magic.contains("current ar archive")
                || is_ocaml_native
                || is_lua_bytecode;
            if !is_binary_class {
                continue;
            }

            // Ghost files are in the header but not in the payload:
            // there is nothing on disk for the ELF checks to read. The
            // header class still counts for the package-level binary
            // accounting.
            if pkgfile.is_ghost() {
                pkg_has_binary = true;
                continue;
            }

            self.checked_files += 1;
            pkg_has_binary = true;

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
            self.run_elf_checks(pkg, pkgfile, config, out, analyses[idx].as_ref());

            if self.is_nonstandard_archive {
                continue;
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
                self.check_non_pie(pkg, fname, out);
            }
        }

        self.check_no_binary(pkg, pkg_has_binary, pkg_has_file_in_libdir, out);
        self.check_noarch_with_lib64(pkg, pkg_has_file_in_lib64, out);
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

    /// Pins `add_checked_files`: the run-lifetime counter feeds `-t`.
    #[test]
    fn add_checked_files_accumulates() {
        let config = Config::default();
        let mut check = BinariesCheck::new(&config);
        assert_eq!(check.checked_files(), Some(0));
        check.add_checked_files(3);
        assert_eq!(check.checked_files(), Some(3));
        check.add_checked_files(2);
        assert_eq!(check.checked_files(), Some(5));
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

    /// Craft a minimal ET_DYN ELF64 for `ReadelfInfo::parse`.
    ///
    /// `go_note` adds a `.note.go.buildid` section (the Go toolchain
    /// marker). `needed` adds a DT_NEEDED entry, `soname` a DT_SONAME
    /// entry, and `dynsyms` a `.dynsym` section plus the DT_SYMTAB /
    /// DT_HASH trio goblin needs to expose it, so `ReadelfInfo` fills
    /// the way goblin fills it for real linked libraries.
    /// Each dynsym is (name, bind, type, shndx); shndx 0 is an import.
    fn craft_shlib_elf(
        go_note: bool,
        needed: Option<&str>,
        soname: Option<&str>,
        dynsyms: &[(&str, u8, u8, u16)],
    ) -> Vec<u8> {
        craft_shlib_elf_paths(
            go_note,
            &needed.into_iter().collect::<Vec<_>>(),
            soname,
            None,
            None,
            dynsyms,
        )
    }

    /// `craft_shlib_elf` with several DT_NEEDED entries and optional
    /// DT_RPATH / DT_RUNPATH entries (single strings, colon-joined
    /// when they name several directories).
    fn craft_shlib_elf_paths(
        go_note: bool,
        needed: &[&str],
        soname: Option<&str>,
        rpath: Option<&str>,
        runpath: Option<&str>,
        dynsyms: &[(&str, u8, u8, u16)],
    ) -> Vec<u8> {
        const SHSTRTAB: &[u8] =
            b"\0.shstrtab\0.dynamic\0.dynstr\0.note.go.buildid\0.dynsym\0.hash\0";
        // SHSTRTAB name offsets: .shstrtab=1, .dynamic=11, .dynstr=20,
        // .note.go.buildid=28, .dynsym=45, .hash=53.
        struct Sec {
            name_off: u32,
            stype: u32,
            flags: u64,
            data: Vec<u8>,
            align: u64,
            link: u32,
            info: u32,
            entsize: u64,
        }
        let mut secs: Vec<Sec> = vec![Sec {
            name_off: 1,
            stype: 3, // SHT_STRTAB
            flags: 0,
            data: SHSTRTAB.to_vec(),
            align: 1,
            link: 0,
            info: 0,
            entsize: 0,
        }];

        // .dynstr carries the soname, the DT_NEEDED entry and every dynamic
        // symbol name; their offsets feed the .dynamic and .dynsym sections.
        let mut dynstr = vec![0u8];
        let mut push_str = |s: &str| {
            let off = dynstr.len();
            dynstr.extend_from_slice(s.as_bytes());
            dynstr.push(0);
            off
        };
        let soname_off = soname.map(&mut push_str);
        let needed_offs: Vec<usize> = needed.iter().map(|n| push_str(n)).collect();
        let rpath_off = rpath.map(&mut push_str);
        let runpath_off = runpath.map(&mut push_str);
        let sym_name_offs: Vec<usize> = dynsyms.iter().map(|(n, _, _, _)| push_str(n)).collect();
        secs.push(Sec {
            name_off: 20,
            stype: 3,
            flags: 0,
            data: dynstr,
            align: 1,
            link: 0,
            info: 0,
            entsize: 0,
        });
        // Section-header index of .dynstr (NULL entry is index 0).
        let dynstr_idx = secs.len() as u32;

        // .dynamic; entries are patched once section offsets are known.
        // Pre-sized: DT_SONAME?, DT_NEEDED*, DT_RPATH?, DT_RUNPATH?,
        // DT_HASH?, DT_SYMTAB?, DT_SYMENT?, DT_STRTAB, DT_STRSZ, DT_NULL.
        let dynamic_idx = secs.len();
        let dynamic_entries = 3
            + soname.is_some() as usize
            + needed.len()
            + rpath.is_some() as usize
            + runpath.is_some() as usize
            + if dynsyms.is_empty() { 0 } else { 3 };
        secs.push(Sec {
            name_off: 11,
            stype: 6, // SHT_DYNAMIC
            flags: 2, // SHF_ALLOC
            data: vec![0u8; 16 * dynamic_entries],
            align: 8,
            link: dynstr_idx,
            info: 0,
            entsize: 16,
        });

        // .dynsym: null entry plus one 24-byte entry per symbol.
        // (name, bind, type, shndx); shndx 0 is SHN_UNDEF, an import.
        let mut dynsym_idx: u32 = 0;
        if !dynsyms.is_empty() {
            let mut symtab = vec![0u8; 24];
            for (i, (_, bind, typ, shndx)) in dynsyms.iter().enumerate() {
                let mut e = vec![0u8; 24];
                e[0..4].copy_from_slice(&(sym_name_offs[i] as u32).to_le_bytes());
                e[4] = (bind << 4) | typ;
                e[6..8].copy_from_slice(&shndx.to_le_bytes());
                symtab.extend(e);
            }
            dynsym_idx = secs.len() as u32;
            secs.push(Sec {
                name_off: 45,
                stype: 11, // SHT_DYNSYM
                flags: 2,  // SHF_ALLOC
                data: symtab,
                align: 8,
                link: dynstr_idx,
                info: 1, // one local symbol: the null entry
                entsize: 24,
            });
            // SysV hash so goblin finds the symbol count via DT_HASH;
            // without it goblin leaves elf.dynsyms empty.
            let n = 1 + dynsyms.len();
            let mut hash = Vec::new();
            hash.extend_from_slice(&1u32.to_le_bytes()); // nbucket
            hash.extend_from_slice(&(n as u32).to_le_bytes()); // nchain
            hash.extend_from_slice(&1u32.to_le_bytes()); // bucket[0]
            for i in 0..n {
                let next = if i + 1 < n { (i + 1) as u32 } else { 0 };
                hash.extend_from_slice(&next.to_le_bytes());
            }
            secs.push(Sec {
                name_off: 53,
                stype: 5, // SHT_HASH
                flags: 2, // SHF_ALLOC
                data: hash,
                align: 4,
                link: dynsym_idx,
                info: 0,
                entsize: 4,
            });
        }
        if go_note {
            // Minimal SHT_NOTE payload; only the section name matters.
            let mut note = Vec::new();
            note.extend_from_slice(&4u32.to_le_bytes());
            note.extend_from_slice(&0u32.to_le_bytes());
            note.extend_from_slice(&1u32.to_le_bytes());
            note.extend_from_slice(b"Go\0\0");
            secs.push(Sec {
                name_off: 28,
                stype: 7, // SHT_NOTE
                flags: 2, // SHF_ALLOC
                data: note,
                align: 4,
                link: 0,
                info: 0,
                entsize: 0,
            });
        }

        let mut buf: Vec<u8> = vec![0; 64]; // ELF header placeholder
        let phoff = buf.len() as u64;
        buf.extend(vec![0u8; 56 * 2]); // PT_LOAD + PT_DYNAMIC

        // Section data blobs, in section order.
        let mut offs: Vec<u64> = Vec::new();
        for s in &secs {
            offs.push(buf.len() as u64);
            buf.extend(&s.data);
        }

        // Patch .dynamic now that the .dynstr file offset is known.
        // PT_LOAD maps VA == file offset, so DT_STRTAB takes it directly.
        let mut dyns: Vec<u8> = Vec::new();
        let mut entry = |tag: i64, val: u64| {
            dyns.extend_from_slice(&tag.to_le_bytes());
            dyns.extend_from_slice(&val.to_le_bytes());
        };
        if let Some(off) = soname_off {
            entry(14, off as u64); // DT_SONAME
        }
        for off in &needed_offs {
            entry(1, *off as u64); // DT_NEEDED
        }
        if let Some(off) = rpath_off {
            entry(15, off as u64); // DT_RPATH
        }
        if let Some(off) = runpath_off {
            entry(29, off as u64); // DT_RUNPATH
        }
        if !dynsyms.is_empty() {
            // .hash is the last section pushed above when dynsyms exist.
            let hash_idx = secs.len() - 1;
            entry(4, offs[hash_idx]); // DT_HASH
            entry(6, offs[dynsym_idx as usize]); // DT_SYMTAB
            entry(11, 24); // DT_SYMENT
        }
        entry(5, offs[dynstr_idx as usize - 1]); // DT_STRTAB
        entry(10, secs[dynstr_idx as usize - 1].data.len() as u64); // DT_STRSZ
        entry(0, 0); // DT_NULL
        let at = offs[dynamic_idx] as usize;
        assert_eq!(
            dyns.len(),
            16 * dynamic_entries,
            "dynamic entry count drifted from pre-sized blob"
        );
        buf[at..at + dyns.len()].copy_from_slice(&dyns);

        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        let shoff = buf.len() as u64;
        let shnum = secs.len() + 1;
        let total = shoff + 64 * shnum as u64;

        // Program headers. PT_LOAD covers the whole file so goblin's
        // vm_to_offset resolves DT_STRTAB to a file offset.
        let ph = |ptype: u32, flags: u32, off: u64, filesz: u64| {
            let mut h = Vec::new();
            h.extend_from_slice(&ptype.to_le_bytes());
            h.extend_from_slice(&flags.to_le_bytes());
            h.extend_from_slice(&off.to_le_bytes()); // p_offset
            h.extend_from_slice(&off.to_le_bytes()); // p_vaddr
            h.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
            h.extend_from_slice(&filesz.to_le_bytes());
            h.extend_from_slice(&filesz.to_le_bytes()); // p_memsz
            h.extend_from_slice(&0x1000u64.to_le_bytes());
            h
        };
        let load = ph(1, 5, 0, total);
        let dynamic = ph(2, 6, offs[dynamic_idx], dyns.len() as u64);
        let at = phoff as usize;
        buf[at..at + 56].copy_from_slice(&load);
        buf[at + 56..at + 112].copy_from_slice(&dynamic);

        // Section headers; entry 0 is NULL.
        let mut shdrs: Vec<u8> = vec![0; 64];
        for (i, s) in secs.iter().enumerate() {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&s.name_off.to_le_bytes());
            h[4..8].copy_from_slice(&s.stype.to_le_bytes());
            h[8..16].copy_from_slice(&s.flags.to_le_bytes());
            h[24..32].copy_from_slice(&offs[i].to_le_bytes());
            h[32..40].copy_from_slice(&(s.data.len() as u64).to_le_bytes());
            h[40..44].copy_from_slice(&s.link.to_le_bytes());
            h[44..48].copy_from_slice(&s.info.to_le_bytes());
            h[48..56].copy_from_slice(&s.align.to_le_bytes());
            h[56..64].copy_from_slice(&s.entsize.to_le_bytes());
            shdrs.extend(h);
        }
        buf.extend(shdrs);

        // ELF header.
        let mut ehdr = vec![0u8; 64];
        ehdr[0..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 2; // ELFCLASS64
        ehdr[5] = 1; // ELFDATA2LSB
        ehdr[6] = 1; // EV_CURRENT
        ehdr[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        ehdr[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        ehdr[32..40].copy_from_slice(&phoff.to_le_bytes());
        ehdr[40..48].copy_from_slice(&shoff.to_le_bytes());
        ehdr[52..54].copy_from_slice(&64u16.to_le_bytes());
        ehdr[54..56].copy_from_slice(&56u16.to_le_bytes());
        ehdr[56..58].copy_from_slice(&2u16.to_le_bytes()); // phnum
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes());
        ehdr[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
        ehdr[62..64].copy_from_slice(&1u16.to_le_bytes()); // .shstrtab
        buf[0..64].copy_from_slice(&ehdr);
        buf
    }

    fn shlib_libdep_results(
        id: &str,
        go_note: bool,
        needed: Option<&str>,
        is_shobj: bool,
        soname: Option<&str>,
        dynsyms: &[(&str, u8, u8, u16)],
    ) -> Vec<(String, String)> {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = is_shobj;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: "/usr/lib64/libnodep.so.1".to_string(),
            ..Default::default()
        };
        let bytes = craft_shlib_elf(go_note, needed, soname, dynsyms);
        // Each caller gets its own fixture file: the id and pid in the
        // name keep parallel `cargo test` runners from racing
        // write/parse/delete on a shared path (a fixed-/tmp- collision
        // flake).
        let path =
            std::env::temp_dir().join(format!("rpmcrab-shlib-nodep-{id}-{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), &pkgfile.name);
        // The crafted bytes must parse the way the check consumes them;
        // a malformed fixture would pass vacuously.
        assert!(info.failed.is_none(), "crafted ELF must parse");
        assert_eq!(info.is_go_binary(), go_note, "go marker detection");
        match needed {
            Some(lib) => assert_eq!(
                info.needed,
                vec![lib.to_string()],
                "DT_NEEDED visible through goblin"
            ),
            None => assert!(info.needed.is_empty(), "no DT_NEEDED"),
        }
        match soname {
            Some(s) => assert_eq!(
                info.soname.as_deref(),
                Some(s),
                "DT_SONAME visible through goblin"
            ),
            None => assert!(info.soname.is_none(), "no DT_SONAME"),
        }
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        std::fs::remove_file(&path).ok();
        results
    }

    #[test]
    fn shlib_without_dependency_information_fires() {
        // Genuine shape: linkable library (DT_SONAME) with a real
        // external reference and no DT_NEEDED.
        let results = shlib_libdep_results(
            "fires",
            false,
            None,
            true,
            Some("libnodep.so.1"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
        );
        let lines = lines_for(&results, "shared-library-without-dependency-information");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libnodep.so.1"),
            "detail: {}",
            lines[0]
        );
    }

    #[test]
    fn shlib_without_dependency_information_skips_go() {
        // Go binaries are ET_DYN with no DT_NEEDED; the exemption keeps
        // them quiet instead of flagging them as dependency-less. SONAME
        // plus a real non-weak undefined import (and no `main`) means the
        // plugin-like path cannot silence this fixture -- only the Go
        // marker can.
        let results = shlib_libdep_results(
            "go",
            true,
            None,
            true,
            Some("libnodep.so.1"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
        );
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert!(results.is_empty(), "Go shlib must be quiet: {results:?}");
    }

    #[test]
    fn shlib_without_dependency_information_skips_self_contained() {
        // Only the optional crt weak references: genuinely self-contained,
        // there is no dependency information to be missing.
        let results = shlib_libdep_results(
            "weak",
            false,
            None,
            true,
            Some("libnodep.so.1"),
            &[(
                "__cxa_finalize",
                goblin::elf::sym::STB_WEAK,
                goblin::elf::sym::STT_NOTYPE,
                0,
            )],
        );
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert!(
            results.is_empty(),
            "self-contained shlib must be quiet: {results:?}"
        );
    }

    #[test]
    fn shlib_without_dependency_information_skips_soname_less_plugin() {
        // No DT_SONAME: a dlopen-only plugin, never DT_NEEDED-linked.
        let results = shlib_libdep_results(
            "nosoname",
            false,
            None,
            true,
            None,
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
        );
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert!(
            results.is_empty(),
            "soname-less plugin must be quiet: {results:?}"
        );
    }

    #[test]
    fn shlib_without_dependency_information_skips_main_shim() {
        // Defines `main`: an executable-entry shim linked into binaries,
        // not a regular shared library. The real non-weak undefined import
        // means only the `defines_main` disjunct can silence this fixture --
        // dropping that disjunct must fail this test.
        let results = shlib_libdep_results(
            "main",
            false,
            None,
            true,
            Some("libnodep.so.1"),
            &[
                (
                    "main",
                    goblin::elf::sym::STB_GLOBAL,
                    goblin::elf::sym::STT_FUNC,
                    1,
                ),
                (
                    "external_func",
                    goblin::elf::sym::STB_GLOBAL,
                    goblin::elf::sym::STT_FUNC,
                    0,
                ),
            ],
        );
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert!(results.is_empty(), "main shim must be quiet: {results:?}");
    }

    #[test]
    fn shlib_with_needed_stays_quiet() {
        let results = shlib_libdep_results(
            "needed",
            false,
            Some("libc.so.6"),
            true,
            Some("libnodep.so.1"),
            &[],
        );
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert_lacks(&results, "statically-linked-binary");
    }

    #[test]
    fn non_shlib_without_needed_still_statically_linked() {
        // Existing behavior for non-shared objects is unchanged.
        let results = shlib_libdep_results("nonshlib", false, None, false, None, &[]);
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert_lacks(&results, "shared-library-without-dependency-information");
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

    /// Exact rendered line for one hardening finding on one fixture binary.
    /// Pins name, severity (`W:`) and count (exactly one per variant): flipping
    /// the level in `check_hardening` must fail this.
    fn assert_hardening_line(results: &[(String, String)], finding: &str, bin: &str) {
        let suffix = format!("/usr/bin/{bin}");
        let lines: Vec<&str> = lines_for(results, finding)
            .into_iter()
            .filter(|l| l.ends_with(suffix.as_str()))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "{finding} should fire exactly once for {bin}: {results:?}"
        );
        assert_eq!(
            lines[0],
            format!("rpmcrab-binaries-fixture.aarch64: W: {finding} {suffix}"),
            "{finding} rendered line mismatch: {results:?}"
        );
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

        // setuidbin: setuid without setgroups, installed setuid -> Error
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
            "setgroups finding should be Error for setuid binary: {}",
            setgroups_lines[0]
        );

        // truncated: goblin cannot parse -> readelf-failed
        let failed_lines = lines_for(&results, "readelf-failed");
        assert!(
            failed_lines.iter().any(|l| l.contains("truncated")),
            "readelf-failed should fire for truncated: {results:?}"
        );

        // Absent under the default config: the forbidden optflags list is
        // empty there, so the check returns before touching DWARF.
        assert_lacks(&results, "unused-direct-shlib-dependency");
        assert_lacks(&results, "missing-mandatory-optflags");
    }

    // $ORIGIN-relative RUNPATHs that resolve into system library paths stay
    // silent, mirroring the reference Path.resolve() after $ORIGIN
    // substitution; empty RUNPATH entries stay silent, mirroring the reference
    // readelf parser which only records non-empty Library runpath matches.
    // (#383)
    #[test]
    fn rpath_origin_dotdot_and_empty_are_silent() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg =
            Pkg::open(std::path::Path::new(&rpm_path), dir.path(), true).expect("open fixture");

        let run = |name: &str, runpaths: Vec<String>| {
            let info = ReadelfInfo {
                x86_feature_1_and: X86Feature1And::Absent,
                has_endbr64: false,
                sections: Vec::new(),
                program_headers: Vec::new(),
                functions: Vec::new(),
                undefined_functions: Vec::new(),
                is_shlib: false,
                is_debug: false,
                is_rust: false,
                is_zig: false,
                soname: None,
                needed: Vec::new(),
                runpaths,
                has_textrel: false,
                has_nonweak_undefined: false,
                defines_main: false,
                elf_type: goblin::elf::header::ET_EXEC,
                elf_machine: goblin::elf::header::EM_X86_64,
                bind_now: false,
                has_dynamic: false,
                failed: None,
            };
            let pkgfile = PkgFile {
                name: name.to_string(),
                ..Default::default()
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_rpath(&pkg, &pkgfile, &info, &mut out);
            out.results().to_vec()
        };

        // Real Factory shapes: $ORIGIN/../lib64 from /usr/bin/* resolves to
        // /usr/lib64, a system path.
        for rp in [
            "$ORIGIN/../lib64",
            "$ORIGIN/../lib",
            "$ORIGIN/../lib64/",
            "$ORIGIN/../lib64/audacity",
            "$ORIGIN/../lib:/usr/lib64",
        ] {
            let results = run("/usr/bin/adios2_remote_server", vec![rp.to_string()]);
            assert_lacks(&results, "binary-or-shlib-defines-rpath");
        }
        // Empty RUNPATH entry (meson links -rpath with an empty value): silent.
        let results = run("/usr/libexec/x.so", vec!["".to_string()]);
        assert_lacks(&results, "binary-or-shlib-defines-rpath");

        // Bare $ORIGIN resolving outside system paths still fires.
        let results = run("/usr/bin/foo", vec!["$ORIGIN".to_string()]);
        assert_eq!(
            lines_for(&results, "binary-or-shlib-defines-rpath").len(),
            1,
            "bare $ORIGIN under /usr/bin should fire: {results:?}"
        );
        // Genuinely non-system rpath still fires.
        let results = run("/usr/bin/foo", vec!["/opt/foo/lib".to_string()]);
        assert_eq!(
            lines_for(&results, "binary-or-shlib-defines-rpath").len(),
            1,
            "/opt/foo/lib rpath should fire: {results:?}"
        );
    }
    /// rpmcrab#17: checksec-style hardening verification. Each fixture
    /// binary misses exactly one protection; hardenedbin misses none.
    #[test]
    fn hardening_findings() {
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let (results, _dir) = run_binaries_check(&rpm_path);

        let has =
            |finding: &str, bin: &str| lines_for(&results, finding).iter().any(|l| l.contains(bin));

        // Fully hardened: silent on all five.
        for finding in [
            "missing-fortify",
            "missing-stack-protector",
            "missing-cf-protection",
            "missing-relro",
            "partial-relro",
        ] {
            assert!(
                !has(finding, "hardenedbin"),
                "{finding} should not fire for hardenedbin: {results:?}"
            );
        }

        // Built without -D_FORTIFY_SOURCE: only missing-fortify.
        assert_hardening_line(&results, "missing-fortify", "nofortifybin");
        for finding in ["missing-stack-protector", "missing-relro", "partial-relro"] {
            assert!(
                !has(finding, "nofortifybin"),
                "{finding} should not fire for nofortifybin: {results:?}"
            );
        }

        // Built with -fno-stack-protector: only missing-stack-protector.
        assert_hardening_line(&results, "missing-stack-protector", "nosspbin");
        for finding in ["missing-fortify", "missing-relro", "partial-relro"] {
            assert!(
                !has(finding, "nosspbin"),
                "{finding} should not fire for nosspbin: {results:?}"
            );
        }

        // Linked -z norelro: only missing-relro.
        assert_hardening_line(&results, "missing-relro", "norelrobin");
        for finding in [
            "missing-fortify",
            "missing-stack-protector",
            "partial-relro",
        ] {
            assert!(
                !has(finding, "norelrobin"),
                "{finding} should not fire for norelrobin: {results:?}"
            );
        }

        // Linked -z relro -z lazy: only partial-relro.
        assert_hardening_line(&results, "partial-relro", "partialrelrobin");
        for finding in [
            "missing-fortify",
            "missing-stack-protector",
            "missing-relro",
        ] {
            assert!(
                !has(finding, "partialrelrobin"),
                "{finding} should not fire for partialrelrobin: {results:?}"
            );
        }

        // Linked -no-pie: the existing PIE finding fires, none of the new ones.
        assert!(
            has("position-independent-executable-suggested", "nonpiebin"),
            "position-independent-executable-suggested should fire for nonpiebin: {results:?}"
        );
        for finding in [
            "missing-fortify",
            "missing-stack-protector",
            "missing-cf-protection",
            "missing-relro",
            "partial-relro",
        ] {
            assert!(
                !has(finding, "nonpiebin"),
                "{finding} should not fire for nonpiebin: {results:?}"
            );
        }
        assert!(
            !has("position-independent-executable-suggested", "hardenedbin"),
            "position-independent-executable-suggested should not fire for hardenedbin: {results:?}"
        );
    }

    /// Minimal ET_EXEC ELF with the given `(name, data)` sections, for
    /// language-detection tests. Only section headers are emitted.
    fn craft_elf_sections(sections: &[(&str, &[u8])]) -> Vec<u8> {
        let mut shstrtab = vec![0u8];
        let mut name_offs = Vec::new();
        for (name, _) in sections {
            name_offs.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }
        let shstrtab_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut buf = vec![0u8; 64]; // ELF header placeholder
        let mut offs = Vec::new();
        for (_, data) in sections {
            offs.push(buf.len() as u64);
            buf.extend_from_slice(data);
        }
        let shstrtab_off = buf.len() as u64;
        buf.extend_from_slice(&shstrtab);
        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        let shoff = buf.len() as u64;

        // Section headers: NULL + sections + shstrtab.
        let mut shdrs = vec![0u8; 64];
        for (i, (_, data)) in sections.iter().enumerate() {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name_offs[i].to_le_bytes());
            h[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
            h[24..32].copy_from_slice(&offs[i].to_le_bytes());
            h[32..40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            h[48..56].copy_from_slice(&1u64.to_le_bytes());
            shdrs.extend(h);
        }
        {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&shstrtab_name_off.to_le_bytes());
            h[4..8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
            h[24..32].copy_from_slice(&shstrtab_off.to_le_bytes());
            h[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
            h[48..56].copy_from_slice(&1u64.to_le_bytes());
            shdrs.extend(h);
        }
        buf.extend(shdrs);

        let shnum = (sections.len() + 2) as u16;
        let mut ehdr = vec![0u8; 64];
        ehdr[0..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 2; // ELFCLASS64
        ehdr[5] = 1; // ELFDATA2LSB
        ehdr[6] = 1; // EV_CURRENT
        ehdr[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        ehdr[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        ehdr[40..48].copy_from_slice(&shoff.to_le_bytes());
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        ehdr[60..62].copy_from_slice(&shnum.to_le_bytes());
        ehdr[62..64].copy_from_slice(&(shnum - 1).to_le_bytes()); // shstrndx
        buf[0..64].copy_from_slice(&ehdr);
        buf
    }

    fn parse_crafted_sections(tag: &str, sections: &[(&str, &[u8])]) -> ReadelfInfo {
        let bytes = craft_elf_sections(sections);
        // Unique per test: parallel cargo test threads share the process.
        let path = std::env::temp_dir().join(format!(
            "rpmcrab-rust-detect-{}-{}",
            tag,
            std::process::id()
        ));
        std::fs::write(&path, &bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/bin/probe");
        assert!(info.failed.is_none(), "crafted ELF must parse");
        std::fs::remove_file(&path).ok();
        info
    }

    #[test]
    fn rust_detection_rustc_section() {
        let info = parse_crafted_sections("rustc", &[(".rustc", b"rustc version 1.0")]);
        assert!(info.is_rust_binary(), ".rustc section must detect Rust");
    }

    #[test]
    fn rust_detection_rodata_panic_string() {
        // Fully-stripped Rust binary: no .rustc, no symbols; only the
        // panic location format string survives in .rodata.
        let info = parse_crafted_sections(
            "rodata",
            &[(".rodata", b"\0panicked at 'oops', src/main.rs:1:1\0")],
        );
        assert!(
            info.is_rust_binary(),
            ".rodata panic string must detect Rust"
        );
    }

    #[test]
    fn rust_detection_debug_gdb_scripts() {
        let info = parse_crafted_sections(
            "gdb",
            &[(
                ".debug_gdb_scripts",
                b"\x01gdb_load_rust_pretty_printers.py\0",
            )],
        );
        assert!(info.is_rust_binary(), "rust gdb scripts must detect Rust");
    }

    #[test]
    fn rust_detection_debug_gdb_scripts_embedded_rust_is_not_rust() {
        // "Trust" embeds "rust" but is not a rustc marker.
        let info = parse_crafted_sections(
            "trust",
            &[(".debug_gdb_scripts", b"\x01Trust the process\0")],
        );
        assert!(
            !info.is_rust_binary(),
            "embedded 'rust' must not detect Rust"
        );
    }

    #[test]
    fn rust_detection_negative_plain_elf() {
        let info = parse_crafted_sections("plain", &[(".text", b"\0"), (".rodata", b"hello\0")]);
        assert!(!info.is_rust_binary(), "plain ELF must not detect Rust");
    }

    #[test]
    fn zig_detection_comment_section() {
        let info = parse_crafted_sections(
            "zigcomment",
            &[(
                ".comment",
                b"Linker: LLD 20.1.2 (https://github.com/ziglang/zig-bootstrap 7ef74e6)\0",
            )],
        );
        assert!(info.is_zig_binary(), ".comment ziglang must detect Zig");
    }

    #[test]
    fn zig_detection_rodata_unreachable_string() {
        // Fully-stripped Zig binary: no .comment, no symbols; only the
        // panic message for `unreachable` survives in .rodata.
        let info = parse_crafted_sections("zigrodata", &[(".rodata", b"\0reached unreachable\0")]);
        assert!(
            info.is_zig_binary(),
            ".rodata unreachable string must detect Zig"
        );
    }

    #[test]
    fn zig_detection_data_rel_ro_unreachable_string() {
        // waylock keeps the Zig panic message in .data.rel.ro, not .rodata.
        let info = parse_crafted_sections(
            "zigdatarelro",
            &[(".data.rel.ro", b"\0reached unreachable\0")],
        );
        assert!(
            info.is_zig_binary(),
            ".data.rel.ro unreachable string must detect Zig"
        );
    }

    #[test]
    fn zig_detection_negative_plain_elf() {
        let info = parse_crafted_sections("zigplain", &[(".text", b"\0"), (".rodata", b"hello\0")]);
        assert!(!info.is_zig_binary(), "plain ELF must not detect Zig");
        assert!(!info.is_rust_binary(), "plain ELF must not detect Rust");
    }

    #[test]
    fn rust_symbol_detection() {
        assert!(is_rust_symbol("rust_begin_unwind"));
        assert!(is_rust_symbol("rust_eh_personality"));
        assert!(is_rust_symbol("__rust_alloc"));
        // `_ZN` alone is Itanium C++ mangling too; only unambiguous
        // Rust runtime names count.
        assert!(!is_rust_symbol("_ZN3foo3barE"));
        assert!(!is_rust_symbol("memcpy"));
        assert!(!is_rust_symbol("__stack_chk_fail"));
        // @VERSION suffixes (from .dynsym) are stripped before matching.
        assert!(is_rust_symbol("rust_begin_unwind@RUST_1.0"));
        assert!(is_rust_symbol("__rust_alloc@@RUST_1.0"));
        assert!(!is_rust_symbol("memcpy@GLIBC_2.17"));
    }

    #[test]
    fn ocaml_symbol_detection() {
        assert!(is_ocaml_symbol("caml_startup"));
        assert!(is_ocaml_symbol("camlStdlib__List"));
        assert!(is_ocaml_symbol("camlUnix__entry"));
        // @VERSION suffixes (from .dynsym) are stripped before matching.
        assert!(is_ocaml_symbol("camlStdlib__Bytes@@OCaml_5.0"));
        // The runtime's and stub libraries' C primitives never match.
        assert!(!is_ocaml_symbol("caml_alloc"));
        assert!(!is_ocaml_symbol("caml_main"));
        assert!(!is_ocaml_symbol("caml_named_value"));
        assert!(!is_ocaml_symbol("caml_copy_string@GLIBC_2.17"));
        assert!(!is_ocaml_symbol("memcpy"));
        assert!(!is_ocaml_symbol("caml"));
    }

    fn hardening_results_for(
        is_rust: bool,
        is_zig: bool,
        functions: &[&str],
        undefined_functions: &[&str],
    ) -> Vec<(String, String)> {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/probe", "ELF 64-bit LSB pie executable");
        let mut info = syn_info();
        info.is_rust = is_rust;
        info.is_zig = is_zig;
        info.functions = functions.iter().map(|s| s.to_string()).collect();
        info.undefined_functions = undefined_functions.iter().map(|s| s.to_string()).collect();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn hardening_debuginfo_file_is_skipped() {
        // Separate debuginfo files are never executed or loaded by the
        // dynamic linker: hardening findings on them (e.g. ovmf's 568
        // missing-relro lines) are unactionable noise. `is_debug` is what
        // `ReadelfInfo::parse` derives from the `.debug` name suffix; the
        // /usr/lib/debug path covers the rest (e.g. ovmf's GdbSyms.dll).
        for (name, is_debug) in [
            ("/usr/lib/debug/usr/bin/probe.debug", true),
            ("/usr/lib/debug/ovmf-x86_64/DEBUG/GdbSyms.dll", false),
        ] {
            let config = test_config();
            let check = BinariesCheck::with_tool_dir(&config, None);
            let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
            let pkgfile = syn_file(name, "ELF 64-bit LSB executable");
            let mut info = syn_info();
            info.is_debug = is_debug;
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_hardening(&pkg, &pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            for finding in [
                "missing-fortify",
                "missing-stack-protector",
                "missing-cf-protection",
                "missing-relro",
                "partial-relro",
            ] {
                assert!(
                    lines_for(&results, finding).is_empty(),
                    "{finding} must not fire for debuginfo {name}: {results:?}"
                );
            }
        }
    }

    #[test]
    fn hardening_rust_binary_skips_fortify_and_ssp() {
        let results = hardening_results_for(true, false, &["memcpy"], &[]);
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire for Rust: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for Rust: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-cf-protection").is_empty(),
            "missing-cf-protection must not fire for Rust: {results:?}"
        );
        // Linker-level RELRO checks still apply to Rust binaries.
        assert_eq!(
            lines_for(&results, "missing-relro").len(),
            1,
            "missing-relro must still fire for Rust: {results:?}"
        );
    }

    fn hardening_results_with(
        needed: &[&str],
        soname: Option<&str>,
        functions: &[&str],
        undefined_functions: &[&str],
    ) -> Vec<(String, String)> {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/probe", "ELF 64-bit LSB pie executable");
        let mut info = syn_info();
        info.needed = needed.iter().map(|s| s.to_string()).collect();
        info.soname = soname.map(|s| s.to_string());
        info.functions = functions.iter().map(|s| s.to_string()).collect();
        info.undefined_functions = undefined_functions.iter().map(|s| s.to_string()).collect();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn hardening_haskell_executable_skips_fortify_and_ssp() {
        // A GHC-produced executable links the Haskell runtime libraries;
        // the buffer-shaped call (memcpy) arrives via the RTS/FFI, and
        // GHC emits no canary or fortify instrumentation for it.
        let results = hardening_results_with(
            &[
                "libHSrts-1.0.3-ghc9.12.4.so",
                "libHSbase-4.21.2.0-9c1f-ghc9.12.4.so",
                "libc.so.6",
            ],
            None,
            &[],
            &["memcpy"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire for Haskell: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for Haskell: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-cf-protection").is_empty(),
            "missing-cf-protection must not fire for Haskell: {results:?}"
        );
        // Linker-level RELRO checks still apply to Haskell binaries.
        assert_eq!(
            lines_for(&results, "missing-relro").len(),
            1,
            "missing-relro must still fire for Haskell: {results:?}"
        );
    }

    #[test]
    fn hardening_haskell_library_by_soname_skips_fortify_and_ssp() {
        // libHSrts itself links only system libraries; its own SONAME
        // is the Haskell signal.
        let results = hardening_results_with(
            &["libc.so.6", "libffi.so.8"],
            Some("libHSrts-1.0.3-ghc9.12.4.so"),
            &[],
            &["memcpy"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire for libHSrts: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for libHSrts: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-cf-protection").is_empty(),
            "missing-cf-protection must not fire for libHSrts: {results:?}"
        );
    }

    #[test]
    fn hardening_ocaml_executable_skips_fortify_and_ssp() {
        // A native OCaml executable statically links the runtime and
        // exports its entry point; ocamlopt emits no canary or fortify
        // instrumentation for OCaml code.
        let results = hardening_results_with(
            &["libzstd.so.1", "libc.so.6"],
            None,
            &["caml_startup", "camlStdlib__List"],
            &["memcpy"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire for OCaml: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for OCaml: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-cf-protection").is_empty(),
            "missing-cf-protection must not fire for OCaml: {results:?}"
        );
        // Linker-level RELRO checks still apply to OCaml binaries.
        assert_eq!(
            lines_for(&results, "missing-relro").len(),
            1,
            "missing-relro must still fire for OCaml: {results:?}"
        );
    }

    #[test]
    fn hardening_ocaml_plugin_skips_fortify_and_ssp() {
        // A native plugin (.cmxs) carries module-qualified symbols of
        // OCaml-generated code and imports the runtime from the host.
        let results = hardening_results_with(
            &["libc.so.6"],
            None,
            &["camlUnix__entry", "camlStdlib__Bytes", "memcpy"],
            &["caml_alloc", "caml_named_value", "memcpy"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire for an OCaml plugin: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for an OCaml plugin: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-cf-protection").is_empty(),
            "missing-cf-protection must not fire for an OCaml plugin: {results:?}"
        );
    }

    #[test]
    fn hardening_ocaml_c_stub_still_flagged() {
        // A C stub library for OCaml bindings is compiled C: it defines
        // and imports only `caml_` primitives (and the runtime's
        // `caml_main` shape is C too, e.g. ocamlrun). Neither the
        // runtime entry point of native executables nor
        // module-qualified generated-code symbols are present, so the
        // findings must still fire.
        let results = hardening_results_with(
            &["libc.so.6"],
            None,
            &[
                "caml_main",
                "caml_alloc",
                "caml_named_value",
                "memcpy",
                "memset",
                "strcpy",
            ],
            &[
                "caml_copy_string",
                "caml_raise_not_found",
                "memcpy",
                "memset",
                "strcpy",
            ],
        );
        assert_eq!(
            lines_for(&results, "missing-fortify").len(),
            1,
            "missing-fortify must still fire for a C stub library: {results:?}"
        );
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must still fire for a C stub library: {results:?}"
        );
    }

    #[test]
    fn hardening_ocaml_embedder_importing_caml_startup_still_flagged() {
        // Negative pin: a C program embedding OCaml merely imports
        // `caml_startup` (the documented embedding pattern: a C
        // `main` calls it and links the runtime). `fill_from_elf`
        // records every STT_FUNC dynsym entry in `functions`,
        // imports included, so the symbol appears in both lists;
        // with zero defined OCaml symbols the binary is compiled C
        // and both findings must still fire on its buffer calls.
        let results = hardening_results_with(
            &["libc.so.6"],
            None,
            &["caml_startup", "main", "memcpy", "memset", "strcpy"],
            &["caml_startup", "memcpy", "memset", "strcpy"],
        );
        assert_eq!(
            lines_for(&results, "missing-fortify").len(),
            1,
            "missing-fortify must still fire for a C embedder importing caml_startup: {results:?}"
        );
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must still fire for a C embedder importing caml_startup: {results:?}"
        );
    }

    #[test]
    fn hardening_ocaml_imported_module_symbol_still_flagged() {
        // Negative pin for the module-qualified shape: a defined-only
        // rule must not special-case `caml_startup`. A binary that
        // only imports a module-qualified symbol of OCaml-generated
        // code (defined in the host it plugs into) defines no OCaml
        // code itself and stays checked.
        let results = hardening_results_with(
            &["libc.so.6"],
            None,
            &["camlStdlib__List", "memcpy", "memset", "strcpy"],
            &["camlStdlib__List", "memcpy", "memset", "strcpy"],
        );
        assert_eq!(
            lines_for(&results, "missing-fortify").len(),
            1,
            "missing-fortify must still fire when the OCaml symbol is only imported: {results:?}"
        );
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must still fire when the OCaml symbol is only imported: {results:?}"
        );
    }

    #[test]
    fn hardening_haskell_embedder_skipped_known_limitation() {
        // Pinned known limitation (ledgered in
        // tests/parity/divergences.toml, rpmcrab#525): a C host
        // embedding Haskell (the documented `hs_init` / `-no-hs-main`
        // FFI pattern) links `libHSrts`, so it carries the same
        // `libHS*` DT_NEEDED signal as GHC output and is skipped the
        // same way, even though its own code is compiled C importing
        // plain buffer calls. At DT_NEEDED granularity there is no
        // cheap precise signal separating the two, so Haskell
        // detection is conservative only in the miss direction.
        // This test pins the current behaviour deliberately: any
        // future precise signal must update it on purpose.
        let results = hardening_results_with(
            &["libHSrts-1.0.3-ghc9.12.4.so", "libc.so.6"],
            None,
            &["main", "memcpy"],
            &["hs_init", "memcpy"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify is currently skipped for a Haskell embedder (known limitation): {results:?}"
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector is currently skipped for a Haskell embedder (known limitation): {results:?}"
        );
    }

    #[test]
    fn hardening_go_binary_without_buildid_note_is_skipped() {
        // openSUSE Go packages (e.g. kind) lack `.note.go.buildid`;
        // `.gopclntab` is the universal Go marker. The whole hardening
        // check must stay silent for them.
        let info = parse_crafted_sections(
            "go-pclntab",
            &[(".gopclntab", b"\x00\x01\x02"), (".text", b"\x90")],
        );
        assert!(info.is_go_binary(), "gopclntab must mark Go");
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/goprog", "ELF 64-bit LSB pie executable");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        for finding in [
            "missing-fortify",
            "missing-stack-protector",
            "missing-cf-protection",
            "missing-relro",
            "partial-relro",
        ] {
            assert!(
                lines_for(&results, finding).is_empty(),
                "{finding} must not fire for Go: {results:?}"
            );
        }
    }

    #[test]
    fn hardening_static_binary_skips_relro() {
        // A static binary has no dynamic section: BIND_NOW is meaningless
        // and RELRO findings would be unactionable noise.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/sbin/staticbin", "ELF 64-bit LSB executable");
        let mut info = syn_info();
        info.has_dynamic = false;
        // Static binary with real code: fortifiable functions present,
        // no undefined imports (static), so both findings still apply.
        info.functions = vec![
            "main".to_string(),
            "memcpy".to_string(),
            "memset".to_string(),
            "strcpy".to_string(),
        ];
        info.program_headers = vec![ElfProgramHeader {
            name: "GNU_RELRO".to_string(),
            flags: "R".to_string(),
        }];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        for finding in ["missing-relro", "partial-relro"] {
            assert!(
                lines_for(&results, finding).is_empty(),
                "{finding} must not fire for static binaries: {results:?}"
            );
        }
        // Fortify and stack-protector are compile-time instrumentations,
        // not dynamic-linker features, so they still fire for static.
        for finding in ["missing-fortify", "missing-stack-protector"] {
            assert_eq!(
                lines_for(&results, finding).len(),
                1,
                "{finding} must still fire for static binaries: {results:?}"
            );
        }
    }

    #[test]
    fn hardening_amdgpu_code_object_skips_relro() {
        // AMDGPU code objects (.hsaco/.co) are loaded by the GPU runtime
        // into GPU memory; the host dynamic linker never processes them
        // and the amdgcn link emits no FLAGS, so BIND_NOW has nothing to
        // govern. Their GNU_RELRO segment covers exactly the vestigial
        // dynamic section. Both RELRO findings are category errors here
        // (rpmcrab#509).
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("rocblas", "x86_64", vec![]);
        let pkgfile = syn_file(
            "/usr/lib64/rocblas/library/Kernels.so-000-gfx1010.hsaco",
            "ELF 64-bit LSB shared object, AMD GPU",
        );
        let mut info = syn_info();
        info.elf_type = goblin::elf::header::ET_DYN;
        info.elf_machine = goblin::elf::header::EM_AMDGPU;
        // With GNU_RELRO present, partial-relro fires without the gate.
        info.program_headers = vec![ElfProgramHeader {
            name: "GNU_RELRO".to_string(),
            flags: "R".to_string(),
        }];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        for finding in ["missing-relro", "partial-relro"] {
            assert!(
                lines_for(&results, finding).is_empty(),
                "{finding} must not fire for AMDGPU code objects: {results:?}"
            );
        }
        // Without GNU_RELRO, missing-relro is gated by the same exclusion.
        info.program_headers = Vec::new();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        for finding in ["missing-relro", "partial-relro"] {
            assert!(
                lines_for(&results, finding).is_empty(),
                "{finding} must not fire for AMDGPU code objects: {results:?}"
            );
        }
    }

    #[test]
    fn hardening_zig_binary_skips_everything() {
        // Zig emits none of the C-hardening artifacts: no _FORTIFY_SOURCE,
        // no stack-protector without libc, and no GNU_RELRO from its linker
        // (verified on bun, opencode, waylock). Every finding would be noise.
        let results = hardening_results_for(false, true, &["memcpy"], &[]);
        for finding in [
            "missing-fortify",
            "missing-stack-protector",
            "missing-cf-protection",
            "missing-relro",
            "partial-relro",
        ] {
            assert!(
                lines_for(&results, finding).is_empty(),
                "{finding} must not fire for Zig: {results:?}"
            );
        }
    }

    #[test]
    fn hardening_c_binary_still_fires() {
        // Negative case for the Zig skip pin: a plain non-Zig ELF must
        // still produce every hardening finding the fixture can emit.
        // The fortifiable imports are load-bearing: below three distinct
        // ones the fortify finding stays quiet (rpmcrab#447, rpmcrab#529).
        let results = hardening_results_for(
            false,
            false,
            &["memcpy", "memset", "strcpy"],
            &["memcpy", "memset", "strcpy"],
        );
        assert_eq!(
            lines_for(&results, "missing-fortify").len(),
            1,
            "missing-fortify must fire for C: {results:?}"
        );
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must fire for C: {results:?}"
        );
        assert_eq!(
            lines_for(&results, "missing-cf-protection").len(),
            1,
            "missing-cf-protection must fire for C: {results:?}"
        );
        // Linker-level RELRO checks apply to plain C binaries too; the
        // Zig skip must not swallow them for non-Zig input.
        assert_eq!(
            lines_for(&results, "missing-relro").len(),
            1,
            "missing-relro must fire for C: {results:?}"
        );
    }

    #[test]
    fn hardening_fortify_quiet_without_fortifiable_import() {
        // rpmcrab#447: a binary that imports no fortifiable libc function
        // has nothing to fortify; the finding stays quiet even without
        // any `__*_chk` symbol. The `__isoc99_sscanf` import is not
        // fortifiable either, but it is SSP-relevant (rpmcrab#452), so
        // the stack-protector finding below still applies.
        let results = hardening_results_for(
            false,
            false,
            &["malloc", "strlen", "__isoc99_sscanf"],
            &["malloc", "strlen", "__isoc99_sscanf"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire without a fortifiable import: {results:?}"
        );
        // The other hardening findings are unaffected by the import set.
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must still fire: {results:?}"
        );
    }

    #[test]
    fn hardening_fortify_fires_with_three_distinct_fortifiable_imports() {
        // rpmcrab#529: three distinct fortifiable imports without any
        // `__*_chk` are evidence of a build without _FORTIFY_SOURCE.
        let results = hardening_results_for(
            false,
            false,
            &["memcpy@GLIBC_2.14", "memset", "strcpy"],
            &["memcpy@GLIBC_2.14", "memset", "strcpy"],
        );
        assert_eq!(
            lines_for(&results, "missing-fortify").len(),
            1,
            "missing-fortify must fire for three distinct fortifiable imports: {results:?}"
        );
        // ...but stays quiet once a fortified wrapper is present.
        let results = hardening_results_for(
            false,
            false,
            &["memcpy", "memset", "strcpy", "__memcpy_chk"],
            &["memcpy", "memset", "strcpy"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire with __*_chk present: {results:?}"
        );
    }

    #[test]
    fn hardening_fortify_quiet_below_three_distinct_imports() {
        // rpmcrab#529: with one or two distinct fortifiable imports, the
        // absence of `__*_chk` cannot distinguish an unfortified build
        // from a fortified build whose calls all have runtime-sized
        // destinations (glibc emits `__*_chk` only for compile-time-known
        // object sizes), so the finding stays quiet.
        for imports in [
            &["memcpy"][..],
            &["memcpy", "memset"][..],
            // Three imports but only two distinct names: duplicates are
            // one piece of evidence, not several.
            &["memcpy", "memcpy@GLIBC_2.14", "memset"][..],
        ] {
            let results = hardening_results_for(false, false, imports, imports);
            assert!(
                lines_for(&results, "missing-fortify").is_empty(),
                "missing-fortify must not fire for imports {imports:?}: {results:?}"
            );
        }
    }

    #[test]
    fn hardening_fortify_applicability_reads_imports_not_exports() {
        // A defined export of a fortifiable name is not an import: with no
        // fortifiable import there is nothing for `_FORTIFY_SOURCE` to
        // redirect, so the finding stays quiet.
        let results = hardening_results_for(false, false, &["memcpy"], &["malloc"]);
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire for a defined export alone: {results:?}"
        );
        // An imported `__*_chk` counts as presence even when it never
        // lands in `functions` (a NOTYPE import parses only into
        // `undefined_functions`). The binary imports three distinct
        // fortifiable functions, so the quiet outcome pins presence
        // detection rather than passing via inapplicability.
        let results = hardening_results_for(
            false,
            false,
            &["memcpy", "memset", "strcpy"],
            &["memcpy", "memset", "strcpy", "__memcpy_chk"],
        );
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire with an imported __*_chk: {results:?}"
        );
    }

    #[test]
    fn hardening_ssp_quiet_with_imported_stack_chk_fail() {
        // `__stack_chk_fail` present only as an import (a NOTYPE import
        // parses only into `undefined_functions`) still counts as
        // presence: the binary is protector-instrumented. The `memcpy` /
        // `strcpy` imports make the binary SSP-applicable (rpmcrab#452),
        // so the quiet outcome pins presence detection rather than
        // passing via inapplicability.
        let results = hardening_results_for(
            false,
            false,
            &["malloc"],
            &["malloc", "memcpy", "strcpy", "__stack_chk_fail"],
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire with an imported __stack_chk_fail: {results:?}"
        );
    }

    #[test]
    fn hardening_ssp_quiet_for_loader_shim() {
        // rpmcrab#447: a pure dynamic-loader shim (only dlopen/dlsym/dlclose
        // + CRT boilerplate imports) implements no logic of its own, so it
        // has no stack buffers for -fstack-protector to protect.
        let results = hardening_results_for(
            false,
            false,
            &["dlopen", "dlsym", "dlclose", "__cxa_finalize"],
            &[
                "dlopen@GLIBC_2.34",
                "dlsym@GLIBC_2.34",
                "dlclose@GLIBC_2.34",
                "__cxa_finalize",
            ],
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for a loader shim: {results:?}"
        );
    }

    #[test]
    fn hardening_ssp_fires_for_real_code() {
        // rpmcrab#447: a binary importing any non-loader function still
        // fires when __stack_chk_fail is absent.
        let results =
            hardening_results_for(false, false, &["malloc", "memcpy"], &["malloc", "memcpy"]);
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must fire for real code: {results:?}"
        );
        // ...but stays quiet once the protector is present. `memcpy` /
        // `strcpy` keep the binary SSP-applicable (rpmcrab#452), so the
        // quiet outcome pins `__stack_chk_fail` detection rather than
        // passing via inapplicability.
        let results = hardening_results_for(
            false,
            false,
            &["malloc", "__stack_chk_fail"],
            &["malloc", "memcpy", "strcpy"],
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire with __stack_chk_fail: {results:?}"
        );
    }

    #[test]
    fn hardening_ssp_quiet_without_relevant_import() {
        // rpmcrab#452: a binary whose imports contain no buffer-shaped
        // call has nothing for a stack canary to guard (the babl
        // pixel-loop shape: allocator, math and measurement calls only);
        // the finding stays quiet even without `__stack_chk_fail`.
        let results = hardening_results_for(
            false,
            false,
            &["malloc", "exp", "strlen"],
            &["malloc", "exp", "strlen"],
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire without an SSP-relevant import: {results:?}"
        );
    }

    #[test]
    fn hardening_ssp_fires_with_relevant_import() {
        // rpmcrab#452: a plain buffer call without a canary still fires:
        // the apparmor_parser / apfsck shape.
        let results = hardening_results_for(false, false, &["strcpy"], &["strcpy@GLIBC_2.17"]);
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must fire for a plain strcpy import: {results:?}"
        );
    }

    #[test]
    fn hardening_ssp_fires_with_fortified_import() {
        // rpmcrab#452: a fortified spelling is the same buffer operation
        // as the plain call, so a `-D_FORTIFY_SOURCE` binary whose only
        // string call is fortified stays in scope: without a canary it
        // fires (the silent `-fstack-protector` downgrade shape).
        let results = hardening_results_for(
            false,
            false,
            &["__memcpy_chk"],
            &["__memcpy_chk@GLIBC_2.3.4"],
        );
        assert_eq!(
            lines_for(&results, "missing-stack-protector").len(),
            1,
            "missing-stack-protector must fire for a fortified-only import: {results:?}"
        );
    }

    #[test]
    fn hardening_ssp_quiet_for_stdio_readers_only() {
        // rpmcrab#452 boundary: stdio buffered readers (`fread`, `fgets`)
        // are deliberately not SSP-relevant -- zoo's `fiz` reads into heap
        // buffers and its finding was never actionable. They ARE
        // fortifiable, and with `printf` (fortifiable, not SSP-relevant)
        // the file clears the fortify evidence threshold, so
        // missing-fortify still fires for the same file: the two gates
        // have different sets on purpose.
        let results = hardening_results_for(
            false,
            false,
            &["fread", "fgets", "printf"],
            &["fread@GLIBC_2.2.5", "fgets@GLIBC_2.2.5", "printf"],
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for fread/fgets only: {results:?}"
        );
        assert_eq!(
            lines_for(&results, "missing-fortify").len(),
            1,
            "missing-fortify must still fire for fread/fgets/printf: {results:?}"
        );
    }

    #[test]
    fn ssp_relevant_import_matching() {
        // The set from the rpmcrab#452 sweep audit: string/memory calls,
        // formatted output into caller buffers, unformatted input,
        // `alloca`, raw buffer fills. @VERSION suffixes are stripped.
        for name in [
            "strcpy",
            "strncpy@GLIBC_2.2.5",
            "strcat",
            "strncat",
            "stpcpy",
            "stpncpy",
            "memcpy",
            "memmove",
            "mempcpy",
            "memset",
            "sprintf",
            "vsprintf",
            "snprintf",
            "vsnprintf",
            "gets",
            "scanf",
            "fscanf",
            "sscanf",
            "vscanf",
            "vfscanf",
            "vsscanf",
            "__isoc99_scanf",
            "__isoc99_fscanf",
            "__isoc99_sscanf@GLIBC_2.7",
            "__isoc99_vscanf",
            "__isoc99_vfscanf",
            "__isoc99_vsscanf",
            "__isoc23_scanf",
            "__isoc23_sscanf@GLIBC_2.38",
            "alloca",
            "__alloca",
            "read",
            "pread",
            "pread64",
            "readv",
            "preadv",
            "preadv64",
            "recv",
            "recvfrom",
            "recvmsg",
            "readlink",
            "readlinkat",
            "getcwd",
            "getwd",
            "realpath",
            "strlcpy",
            "strlcat",
            "strcpy_chk",
            // Fortified spellings normalise to the plain call.
            "__memcpy_chk@GLIBC_2.3.4",
            "__strcpy_chk",
            "__strcat_chk",
            "__snprintf_chk",
            "__read_chk",
            "__pread64_chk",
            "__readlinkat_chk",
            "__getwd_chk",
            "__realpath_chk",
            "__recvfrom_chk",
            "__strlcpy_chk",
            "__isoc99_vsscanf_chk",
        ] {
            assert!(is_ssp_relevant_import(name), "{name} must be SSP-relevant");
        }
        for name in [
            // The deliberate boundary: stdio buffered readers are out.
            "fread",
            "fread_unlocked",
            "fgets",
            "fgets_unlocked",
            // Fortified spellings of out-of-set calls stay out with
            // their plain forms.
            "__fgets_chk",
            "__fread_chk",
            "__printf_chk",
            "__poll_chk",
            "__stack_chk_fail",
            // Measurement / comparison / allocation calls guard nothing.
            "strlen",
            "strcmp",
            "strstr",
            "malloc",
            "free",
            "printf",
            "fprintf",
            "dlopen",
        ] {
            assert!(
                !is_ssp_relevant_import(name),
                "{name} must not be SSP-relevant"
            );
        }
    }

    #[test]
    fn parser_collects_notype_undefined_imports() {
        // Modern toolchains emit undefined imports as STT_NOTYPE, not
        // STT_FUNC (`__cxa_finalize` is NOTYPE in real binaries). The
        // parser must collect them into `undefined_functions`: the
        // loader-shim predicate reads only that vector, so a NOTYPE-blind
        // parser leaves the shim check blind. (name, bind, type, shndx);
        // STB_GLOBAL = 1, STT_NOTYPE = 0, STT_FUNC = 2, SHN_UNDEF = 0.
        let dynsyms: &[(&str, u8, u8, u16)] = &[
            ("dlopen", 1, 0, 0),
            ("__cxa_finalize", 1, 0, 0),
            ("dlsym", 1, 2, 0),
            ("memcpy", 1, 2, 0),
            ("exported_fn", 1, 2, 1),
            ("some_data", 1, 0, 1),
        ];
        let bytes = craft_shlib_elf(false, None, None, dynsyms);
        let path =
            std::env::temp_dir().join(format!("rpmcrab-notype-parse-{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libprobe.so");
        std::fs::remove_file(&path).ok();
        assert!(info.failed.is_none(), "crafted ELF must parse");
        for name in ["dlopen", "__cxa_finalize", "dlsym", "memcpy"] {
            assert!(
                info.undefined_functions.iter().any(|u| u == name),
                "undefined_functions must contain {name}: {:?}",
                info.undefined_functions
            );
        }
        // Only STT_FUNC symbols land in `functions`; defined symbols are
        // never undefined imports.
        assert!(info.functions.iter().any(|f| f == "memcpy"));
        assert!(info.functions.iter().any(|f| f == "exported_fn"));
        assert!(!info.functions.iter().any(|f| f == "__cxa_finalize"));
        assert!(!info.undefined_functions.iter().any(|u| u == "some_data"));

        // End to end through the parsed vector: a shim whose imports are
        // all NOTYPE is still a shim, so the stack-protector finding
        // stays quiet for it.
        let shim_syms: &[(&str, u8, u8, u16)] = &[
            ("dlopen", 1, 0, 0),
            ("dlsym", 1, 0, 0),
            ("dlclose", 1, 0, 0),
            ("__cxa_finalize", 1, 0, 0),
        ];
        let bytes = craft_shlib_elf(false, None, None, shim_syms);
        let path = std::env::temp_dir().join(format!("rpmcrab-notype-shim-{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libshim.so");
        std::fs::remove_file(&path).ok();
        assert!(info.failed.is_none(), "crafted ELF must parse");
        assert!(
            !is_stack_protector_applicable(&info),
            "NOTYPE-only loader shim must not be stack-protector applicable: {:?}",
            info.undefined_functions
        );
    }

    #[test]
    fn parser_notype_imports_feed_hardening_predicates() {
        // (name, bind, type, shndx); STB_GLOBAL = 1, STT_NOTYPE = 0,
        // SHN_UNDEF = 0. Every import here is NOTYPE, so none of them
        // land in `functions`; the hardening predicates must still see
        // them through `undefined_functions`.
        let dynsyms: &[(&str, u8, u8, u16)] = &[
            ("memcpy", 1, 0, 0),
            ("memset", 1, 0, 0),
            ("strcpy", 1, 0, 0),
            ("__memcpy_chk", 1, 0, 0),
            ("__stack_chk_fail", 1, 0, 0),
        ];
        let bytes = craft_shlib_elf(false, None, None, dynsyms);
        let path =
            std::env::temp_dir().join(format!("rpmcrab-notype-hardening-{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libprobe.so");
        std::fs::remove_file(&path).ok();
        assert!(info.failed.is_none(), "crafted ELF must parse");
        assert!(
            info.functions.is_empty(),
            "NOTYPE imports stay out of functions: {:?}",
            info.functions
        );
        assert!(
            is_fortify_applicable(&info),
            "NOTYPE memcpy import must be fortify-applicable: {:?}",
            info.undefined_functions
        );

        // End to end: the imported wrappers count as presence, so neither
        // hardening finding fires on this hardened binary.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libprobe.so", "ELF 64-bit LSB shared object");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        for finding in ["missing-fortify", "missing-stack-protector"] {
            assert!(
                lines_for(&results, finding).is_empty(),
                "{finding} must not fire for NOTYPE-import presence: {results:?}"
            );
        }
    }

    /// Build one `.note.gnu.property` section body carrying the given
    /// `(pr_type, value)` properties, ELF64 layout (entries padded to
    /// 8 bytes).
    fn gnu_property_note(props: &[(u32, u32)]) -> Vec<u8> {
        let mut desc = Vec::new();
        for (pr_type, value) in props {
            desc.extend_from_slice(&pr_type.to_le_bytes());
            desc.extend_from_slice(&4u32.to_le_bytes());
            desc.extend_from_slice(&value.to_le_bytes());
            desc.extend_from_slice(&[0; 4]);
        }
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes()); // namesz, "GNU\0"
        note.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        note.extend_from_slice(&5u32.to_le_bytes()); // NT_GNU_PROPERTY_TYPE_0
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&desc);
        note
    }

    /// Wrap a raw property-note desc in a `GNU` note header, with an
    /// optional descsz override for truncation cases.
    fn gnu_note_with_desc(desc: &[u8], descsz: Option<u32>) -> Vec<u8> {
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes()); // namesz, "GNU\0"
        note.extend_from_slice(&descsz.unwrap_or(desc.len() as u32).to_le_bytes());
        note.extend_from_slice(&5u32.to_le_bytes()); // NT_GNU_PROPERTY_TYPE_0
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(desc);
        note
    }

    #[test]
    fn gnu_property_feature_1_and_is_parsed() {
        let both = gnu_property_note(&[(GNU_PROPERTY_X86_FEATURE_1_AND, 0b11)]);
        let info = parse_crafted_sections("cfboth", &[(".note.gnu.property", &both)]);
        assert_eq!(
            info.x86_feature_1_and,
            X86Feature1And::Present(X86_FEATURE_1_IBT_SHSTK)
        );
        let shstk_only = gnu_property_note(&[(GNU_PROPERTY_X86_FEATURE_1_AND, 0b10)]);
        let info = parse_crafted_sections("cfshstk", &[(".note.gnu.property", &shstk_only)]);
        assert_eq!(
            info.x86_feature_1_and,
            X86Feature1And::Present(X86_FEATURE_1_SHSTK)
        );
        // A present-but-zero value is a real value, not an absence.
        let zero = gnu_property_note(&[(GNU_PROPERTY_X86_FEATURE_1_AND, 0)]);
        let info = parse_crafted_sections("cfzero", &[(".note.gnu.property", &zero)]);
        assert_eq!(info.x86_feature_1_and, X86Feature1And::Present(0));
        // A property note without FEATURE_1_AND (here the x86
        // FEATURE_2_USED property) leaves the state Absent, as does a
        // binary with no property section at all.
        let other = gnu_property_note(&[(0xc000_0001, 0b11)]);
        let info = parse_crafted_sections("cfother", &[(".note.gnu.property", &other)]);
        assert_eq!(info.x86_feature_1_and, X86Feature1And::Absent);
        let info = parse_crafted_sections("cfnone", &[(".text", b"code")]);
        assert_eq!(info.x86_feature_1_and, X86Feature1And::Absent);
    }

    #[test]
    fn endbr64_is_detected_from_text_section_bytes() {
        // The gate sensor end to end: `has_endbr64` must come from
        // the parsed `.text` bytes, not from a hand-set field — a
        // wrong ENDBR64 constant or section-name drift would
        // silently disable the gate and fire on every hardened
        // binary.
        let with = parse_crafted_sections("cfendbr", &[(".text", b"\x90\xf3\x0f\x1e\xfa\xc3")]);
        assert!(with.has_endbr64, "ENDBR64 in .text must be detected");
        let without = parse_crafted_sections("cfnoendbr", &[(".text", b"\x90\x90\xc3")]);
        assert!(!without.has_endbr64);
        // The same bytes outside `.text` are not a code record.
        let rodata = parse_crafted_sections("cfendbrro", &[(".rodata", b"\xf3\x0f\x1e\xfa")]);
        assert!(!rodata.has_endbr64);
    }

    #[test]
    fn gnu_property_feature_1_and_elf32_layout() {
        // ELF32 property entries are 4-byte aligned, ELF64 ones 8-byte:
        // a 12-byte first entry places FEATURE_1_AND at offset 12,
        // where the ELF64 walk (16-byte stride) misses it.
        let mut desc = Vec::new();
        desc.extend_from_slice(&0xc000_0001u32.to_le_bytes()); // FEATURE_2_USED
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend_from_slice(&0xaaaa_aaaau32.to_le_bytes());
        desc.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend_from_slice(&X86_FEATURE_1_IBT_SHSTK.to_le_bytes());
        let note = gnu_note_with_desc(&desc, None);
        assert_eq!(
            parse_x86_feature_1_and(&note, false),
            X86Feature1And::Present(X86_FEATURE_1_IBT_SHSTK)
        );
        // Read with the ELF64 stride, the walk lands mid-entry and
        // the misread entry's declared size overruns the desc: the
        // state is unreadable (damage proves nothing), not absent.
        assert_eq!(
            parse_x86_feature_1_and(&note, true),
            X86Feature1And::Unreadable
        );
    }

    #[test]
    fn gnu_property_feature_1_and_truncated_is_unreadable() {
        // The entry declares 8 data bytes but the desc ends after 2:
        // the value is cut off, which is damage, not absence.
        let mut desc = Vec::new();
        desc.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        desc.extend_from_slice(&8u32.to_le_bytes());
        desc.extend_from_slice(&[0x03, 0x00]);
        let note = gnu_note_with_desc(&desc, None);
        assert_eq!(
            parse_x86_feature_1_and(&note, true),
            X86Feature1And::Unreadable
        );
        // An entry too small to hold the feature word at all.
        let mut desc = Vec::new();
        desc.extend_from_slice(&GNU_PROPERTY_X86_FEATURE_1_AND.to_le_bytes());
        desc.extend_from_slice(&2u32.to_le_bytes());
        desc.extend_from_slice(&[0x03, 0x00]);
        let note = gnu_note_with_desc(&desc, None);
        assert_eq!(
            parse_x86_feature_1_and(&note, true),
            X86Feature1And::Unreadable
        );
        // A note header claiming a desc longer than the section: the
        // property may have sat in the lost tail.
        let desc = vec![0u8; 8];
        let note = gnu_note_with_desc(&desc, Some(1024));
        assert_eq!(
            parse_x86_feature_1_and(&note, true),
            X86Feature1And::Unreadable
        );
        // A non-feature entry whose declared size overruns the desc
        // ends the walk the same way: the feature entry could have
        // sat in the lost tail.
        let mut desc = Vec::new();
        desc.extend_from_slice(&0xc000_0001u32.to_le_bytes());
        desc.extend_from_slice(&64u32.to_le_bytes());
        desc.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]);
        let note = gnu_note_with_desc(&desc, None);
        assert_eq!(
            parse_x86_feature_1_and(&note, true),
            X86Feature1And::Unreadable
        );
    }

    #[test]
    fn missing_cf_protection_fires_and_stays_quiet() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/probe", "ELF 64-bit LSB executable");
        let run = |info: &ReadelfInfo| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_hardening(&pkg, &pkgfile, info, &mut out);
            out.results().to_vec()
        };
        // syn_info is ET_EXEC / EM_X86_64 with no property recorded and
        // no ENDBR64: fires exactly once, at Warning.
        let results = run(&syn_info());
        let lines = lines_for(&results, "missing-cf-protection");
        assert_eq!(lines.len(), 1, "must fire once: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        // Both features recorded: quiet.
        let mut info = syn_info();
        info.x86_feature_1_and = X86Feature1And::Present(X86_FEATURE_1_IBT_SHSTK);
        assert!(lines_for(&run(&info), "missing-cf-protection").is_empty());
        // One feature only (SHSTK): the missing IBT still fires.
        let mut info = syn_info();
        info.x86_feature_1_and = X86Feature1And::Present(X86_FEATURE_1_SHSTK);
        assert_eq!(lines_for(&run(&info), "missing-cf-protection").len(), 1);
        // A present-but-zero value records neither feature: fires.
        let mut info = syn_info();
        info.x86_feature_1_and = X86Feature1And::Present(0);
        assert_eq!(lines_for(&run(&info), "missing-cf-protection").len(), 1);
        // A truncated property entry proves nothing either way: quiet.
        let mut info = syn_info();
        info.x86_feature_1_and = X86Feature1And::Unreadable;
        assert!(lines_for(&run(&info), "missing-cf-protection").is_empty());
        // ENDBR64 in .text: the code was compiled with the flag and
        // the property was cleared at link time by an input carrying
        // none — rebuilding cannot restore it, so the finding stays
        // quiet with no property and with a partial property alike.
        let mut info = syn_info();
        info.has_endbr64 = true;
        assert!(lines_for(&run(&info), "missing-cf-protection").is_empty());
        let mut info = syn_info();
        info.has_endbr64 = true;
        info.x86_feature_1_and = X86Feature1And::Present(X86_FEATURE_1_SHSTK);
        assert!(lines_for(&run(&info), "missing-cf-protection").is_empty());
        // Other architectures have no x86 property semantics.
        let mut info = syn_info();
        info.elf_machine = goblin::elf::header::EM_AARCH64;
        assert!(lines_for(&run(&info), "missing-cf-protection").is_empty());
        // Rust binaries do not emit the property for their own code.
        let mut info = syn_info();
        info.is_rust = true;
        assert!(lines_for(&run(&info), "missing-cf-protection").is_empty());
    }

    #[test]
    fn hardening_shim_predicate_unit() {
        assert!(!is_pure_loader_shim(&[]));
        assert!(is_pure_loader_shim(&[
            "dlopen@GLIBC_2.34".to_string(),
            "dlsym".to_string(),
            "__cxa_finalize".to_string(),
            "_ITM_deregisterTMCloneTable".to_string(),
        ]));
        assert!(!is_pure_loader_shim(&[
            "dlopen".to_string(),
            "malloc".to_string()
        ]));
        assert!(!is_pure_loader_shim(&["memcpy".to_string()]));
    }

    /// Deliberate divergence (divergences.toml, `case = "global"`, rpmcrab#17):
    /// the frozen reference emits no hardening findings, so a captured case
    /// gains a port-only `W: missing-fortify` line exactly where the binary
    /// clears the evidence threshold (rpmcrab#529):
    /// - `liblto21`: gains one (`/usr/lib64/libLTO.so.21.1`)
    /// - `llvm21-gold`: gains none -- `LLVMgold.so` imports only two
    ///   distinct fortifiable functions (`memcpy`, `snprintf`), below the
    ///   threshold, so crab and reference agree on silence there.
    #[test]
    fn hardening_captured_cases_pin_new_lines() {
        let cases: [(&str, &[&str]); 2] = [
            (
                "../../tests/parity/cases/liblto21/input/libLTO21-21.1.8-9.2.aarch64.rpm",
                &["libLTO21.aarch64: W: missing-fortify /usr/lib64/libLTO.so.21.1"],
            ),
            (
                "../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm",
                &[],
            ),
        ];
        for (rel, expected) in cases {
            let rpm = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
            let (results, _dir) = run_binaries_check(&rpm);
            let lines = lines_for(&results, "missing-fortify");
            assert_eq!(
                lines.as_slice(),
                expected,
                "port-only hardening delta for {rel}: {results:?}"
            );
        }
    }

    #[test]
    fn hardening_symbol_matching() {
        assert!(is_fortify_symbol("__memcpy_chk"));
        assert!(is_fortify_symbol("__sprintf_chk"));
        // .dynsym names carry a @VERSION suffix.
        assert!(is_fortify_symbol("__strcpy_chk@GLIBC_2.17"));
        assert!(!is_fortify_symbol("__stack_chk_fail"));
        assert!(!is_fortify_symbol("memcpy"));
        assert!(!is_fortify_symbol("__chk_version"));

        assert!(is_stack_protector_symbol("__stack_chk_fail"));
        assert!(is_stack_protector_symbol("__stack_chk_fail@GLIBC_2.17"));
        assert!(!is_stack_protector_symbol("__stack_chk_guard"));
        assert!(!is_stack_protector_symbol("__memcpy_chk"));

        assert!(is_fortifiable_import("memcpy"));
        assert!(is_fortifiable_import("strcpy@GLIBC_2.17"));
        assert!(is_fortifiable_import("snprintf"));
        assert!(is_fortifiable_import("read"));
        // The full glibc set: the stdio family, wide-char variants and
        // the less common wrappers are all fortifiable.
        for name in [
            "mempcpy",
            "fgets",
            "fgets_unlocked",
            "printf",
            "fprintf",
            "vprintf",
            "vfprintf",
            "dprintf",
            "asprintf",
            "poll",
            "ppoll",
            "readlinkat",
            "wcpcpy",
            "wcpncpy",
            "wmempcpy",
            "fgetws",
            "syslog",
            "longjmp",
            "inet_ntop",
            "strlcpy",
        ] {
            assert!(is_fortifiable_import(name), "{name} must be fortifiable");
        }
        assert!(!is_fortifiable_import("__memcpy_chk"));
        assert!(!is_fortifiable_import("malloc"));
        assert!(!is_fortifiable_import("strlen"));
        // No `__memccpy_chk` in glibc's dynamic symbol table, and
        // `__fdelt_chk` has no importable base name.
        assert!(!is_fortifiable_import("memccpy"));
        assert!(!is_fortifiable_import("fdelt"));
        assert!(!is_fortifiable_import("memcpy_s"));
    }
    /// Hand-built minimal ELF64 with crafted DWARF for the optflags tests.
    /// Each `(producer, inline)` pair becomes one compilation unit: `inline`
    /// uses `DW_FORM_string`, otherwise the producer is referenced with
    /// `DW_FORM_strp` from `.debug_str`.
    fn dwarf_test_elf(cus: &[(&str, bool)]) -> Vec<u8> {
        dwarf_test_elf_impl(cus, None)
    }

    /// Compression applied to the `.debug_info` section of the test ELF,
    /// mirroring what gcc/binutils emit.
    #[derive(Clone, Copy, Debug)]
    enum DwarfCompress {
        /// `SHF_COMPRESSED` + `ELFCOMPRESS_ZLIB` (modern `-gz=zlib`).
        ZlibShf,
        /// `SHF_COMPRESSED` + `ELFCOMPRESS_ZSTD` (modern `-gz=zstd`).
        ZstdShf,
        /// Legacy GNU `.zdebug_info`: "ZLIB\0" magic, 8-byte big-endian
        /// uncompressed size, zlib stream.
        GnuZdebug,
    }

    /// `Elf_Chdr` + compressed stream for the `SHF_COMPRESSED` fixture.
    fn shf_compressed(raw: &[u8], ch_type: u32) -> Vec<u8> {
        let stream = match ch_type {
            1 => {
                use std::io::Write;
                let mut enc =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                enc.write_all(raw).expect("zlib compress");
                enc.finish().expect("zlib finish")
            }
            _ => zstd::encode_all(raw, 0).expect("zstd compress"),
        };
        let mut out = Vec::new();
        // 64-bit Elf_Chdr: ch_type u32, padding u32, ch_size u64,
        // ch_addralign u64 (the fixture ELF is 64-bit).
        out.extend_from_slice(&ch_type.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&stream);
        out
    }

    /// Legacy GNU `.zdebug_*` payload: "ZLIB\0", BE size, zlib stream.
    fn gnu_zdebug(raw: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(raw).expect("zlib compress");
        let stream = enc.finish().expect("zlib finish");
        let mut out = Vec::new();
        out.extend_from_slice(b"ZLIB\0");
        out.extend_from_slice(&(raw.len() as u64).to_be_bytes());
        out.extend_from_slice(&stream);
        out
    }

    fn dwarf_test_elf_impl(cus: &[(&str, bool)], compress: Option<DwarfCompress>) -> Vec<u8> {
        let mut debug_str = Vec::new();
        let mut str_offsets: Vec<Option<u32>> = Vec::new();
        for (producer, inline) in cus {
            if *inline {
                str_offsets.push(None);
            } else {
                str_offsets.push(Some(debug_str.len() as u32));
                debug_str.extend_from_slice(producer.as_bytes());
                debug_str.push(0);
            }
        }
        // Abbrev codes: 1 = CU with strp producer, 2 = CU with inline producer.
        let debug_abbrev: &[u8] = &[
            0x01, 0x11, 0x00, 0x25, 0x0e, 0x00, 0x00, //
            0x02, 0x11, 0x00, 0x25, 0x08, 0x00, 0x00, //
            0x00,
        ];
        let mut debug_info = Vec::new();
        for (i, (producer, inline)) in cus.iter().enumerate() {
            let mut unit = Vec::new();
            unit.extend_from_slice(&2u16.to_le_bytes());
            unit.extend_from_slice(&0u32.to_le_bytes());
            unit.push(8);
            if *inline {
                unit.push(2);
                unit.extend_from_slice(producer.as_bytes());
                unit.push(0);
            } else {
                unit.push(1);
                unit.extend_from_slice(&str_offsets[i].expect("strp offset").to_le_bytes());
            }
            let len = unit.len() as u32;
            debug_info.extend_from_slice(&len.to_le_bytes());
            debug_info.extend_from_slice(&unit);
        }

        let shstrtab = b"\0.debug_abbrev\0.debug_info\0.debug_str\0.shstrtab\0.zdebug_info\0";
        let (info_bytes, info_name, info_flags) = match compress {
            None => (debug_info, 15u32, 0u64),
            Some(DwarfCompress::ZlibShf) => (shf_compressed(&debug_info, 1), 15, 0x800),
            Some(DwarfCompress::ZstdShf) => (shf_compressed(&debug_info, 2), 15, 0x800),
            Some(DwarfCompress::GnuZdebug) => (gnu_zdebug(&debug_info), 48, 0),
        };
        let sections: [&[u8]; 4] = [debug_abbrev, &info_bytes, &debug_str, &shstrtab[..]];
        let sh_names = [1u32, info_name, 27, 38];
        let sh_types = [1u32, 1, 1, 3];
        let sh_flags = [0u64, info_flags, 0, 0];

        let mut out = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&62u16.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0x400000u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        let shoff_pos = out.len();
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&64u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&64u16.to_le_bytes());
        out.extend_from_slice(&5u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        assert_eq!(out.len(), 64);

        let mut sh_offsets = Vec::new();
        for s in &sections {
            sh_offsets.push(out.len() as u64);
            out.extend_from_slice(s);
        }
        let shoff = out.len() as u64;
        out[shoff_pos..shoff_pos + 8].copy_from_slice(&shoff.to_le_bytes());

        out.extend_from_slice(&[0u8; 64]);
        for (i, s) in sections.iter().enumerate() {
            out.extend_from_slice(&sh_names[i].to_le_bytes());
            out.extend_from_slice(&sh_types[i].to_le_bytes());
            out.extend_from_slice(&sh_flags[i].to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&sh_offsets[i].to_le_bytes());
            out.extend_from_slice(&(s.len() as u64).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&1u64.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
        }
        out
    }

    fn write_dwarf_elf(dir: &tempfile::TempDir, name: &str, cus: &[(&str, bool)]) -> String {
        let path = dir.path().join(name);
        std::fs::write(&path, dwarf_test_elf(cus)).expect("write test ELF");
        path.to_string_lossy().into_owned()
    }

    fn optflags_config(forbidden: &[&str]) -> Config {
        let mut config = test_config();
        config.configuration["ForbiddenOptflags"] = toml::Value::Array(
            forbidden
                .iter()
                .map(|s| toml::Value::String((*s).to_string()))
                .collect(),
        );
        config
    }

    /// A `Pkg` shell for the optflags emission tests: the check only reads
    /// the package name and arch for rendering.
    fn optflags_test_pkg(dir: &tempfile::TempDir) -> Pkg {
        let rpm = format!(
            "{}/../../tests/fixtures/binaries-check/input/rpmcrab-binaries-fixture-1.0-1.aarch64.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        Pkg::open(std::path::Path::new(&rpm), dir.path(), true).expect("open fixture pkg")
    }

    fn run_optflags(pkg: &Pkg, elf_path: &str, config: &Config) -> Vec<(String, String)> {
        let pkgfile = PkgFile {
            name: "/usr/bin/dwarfprog".to_string(),
            path: elf_path.to_string(),
            ..Default::default()
        };
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let check = BinariesCheck::new(config);
        check.check_optflags(pkg, &pkgfile, config, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn dwarf_producer_extraction() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(
            &dir,
            "prog",
            &[
                ("GNU C17 12.3.1 -O2 -D_FORTIFY_SOURCE=2", false),
                ("GNU AS 2.33.1", true),
            ],
        );
        let info = ObjdumpInfo::parse(&path);
        assert!(
            info.failed.is_none(),
            "unexpected failure: {:?}",
            info.failed
        );
        assert_eq!(
            info.producers,
            vec!["GNU C17 12.3.1 -O2 -D_FORTIFY_SOURCE=2", "GNU AS 2.33.1"]
        );
    }

    #[test]
    fn dwarf_producer_keeps_colon_in_producer() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(
            &dir,
            "colon",
            &[("GNU C17 12.3.1: custom-tune=x86-64", false)],
        );
        let info = ObjdumpInfo::parse(&path);
        assert!(
            info.failed.is_none(),
            "unexpected failure: {:?}",
            info.failed
        );
        assert_eq!(info.producers, vec!["GNU C17 12.3.1: custom-tune=x86-64"]);
    }

    #[test]
    fn dwarf_producer_absent_without_debug_sections() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(&dir, "stripped", &[]);
        let info = ObjdumpInfo::parse(&path);
        assert!(
            info.failed.is_none(),
            "unexpected failure: {:?}",
            info.failed
        );
        assert!(info.producers.is_empty());
    }

    #[test]
    fn dwarf_producer_unparsable_file_fails() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let path = dir.path().join("bogus");
        std::fs::write(&path, b"not an ELF file").expect("write bogus");
        let info = ObjdumpInfo::parse(path.to_str().unwrap());
        assert!(info.failed.is_some(), "goblin failure should surface");
        assert!(info.producers.is_empty());
    }

    #[test]
    fn dwarf_producer_extraction_compressed_sections() {
        let cus = [("GNU C17 12.3.1 -O2 -D_FORTIFY_SOURCE=2", false)];
        for kind in [
            DwarfCompress::ZlibShf,
            DwarfCompress::ZstdShf,
            DwarfCompress::GnuZdebug,
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let path = dir.path().join("prog");
            std::fs::write(&path, dwarf_test_elf_impl(&cus, Some(kind))).expect("write test ELF");
            let info = ObjdumpInfo::parse(path.to_str().unwrap());
            assert!(
                info.failed.is_none(),
                "unexpected failure for {kind:?}: {:?}",
                info.failed
            );
            assert_eq!(
                info.producers,
                vec!["GNU C17 12.3.1 -O2 -D_FORTIFY_SOURCE=2"],
                "producer lost for {kind:?}"
            );
        }
    }

    #[test]
    fn optflags_mandatory_config_is_inert() {
        let pkg_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = optflags_test_pkg(&pkg_dir);
        let elf_dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(&elf_dir, "prog", &[("GNU C17 12.3.1 -O2", false)]);
        // A config that still sets MandatoryOptflags is a no-op: the
        // finding is not emitted, whatever the producer carries.
        let mut config = optflags_config(&[]);
        config.configuration.insert(
            "MandatoryOptflags".to_string(),
            toml::Value::Array(vec![
                toml::Value::String("-O2".to_string()),
                toml::Value::String("-D_FORTIFY_SOURCE=2".to_string()),
            ]),
        );
        let results = run_optflags(&pkg, &path, &config);
        assert_lacks(&results, "missing-mandatory-optflags");
        assert!(results.is_empty(), "results: {results:?}");
    }

    #[test]
    fn optflags_forbidden() {
        let pkg_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = optflags_test_pkg(&pkg_dir);
        let elf_dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(
            &elf_dir,
            "prog",
            &[("GNU C17 12.3.1 -O2 -fno-stack-protector", false)],
        );
        let config = optflags_config(&["-fno-stack-protector"]);
        let results = run_optflags(&pkg, &path, &config);
        let lines = lines_for(&results, "forbidden-optflags");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains(" E: "), "must be Error: {}", lines[0]);
        assert!(
            lines[0].contains("-fno-stack-protector"),
            "detail lists the forbidden flag: {}",
            lines[0]
        );
        assert_lacks(&results, "missing-mandatory-optflags");
    }

    #[test]
    fn optflags_clean_producer_no_findings() {
        let pkg_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = optflags_test_pkg(&pkg_dir);
        let elf_dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(
            &elf_dir,
            "prog",
            &[("GNU C17 12.3.1 -O2 -D_FORTIFY_SOURCE=2", false)],
        );
        let config = optflags_config(&["-fno-stack-protector"]);
        let results = run_optflags(&pkg, &path, &config);
        assert_lacks(&results, "missing-mandatory-optflags");
        assert_lacks(&results, "forbidden-optflags");
    }

    #[test]
    fn optflags_forbidden_evaluated_per_compilation_unit() {
        let pkg_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = optflags_test_pkg(&pkg_dir);
        let elf_dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(
            &elf_dir,
            "prog",
            &[
                ("GNU C17 12.3.1 -O2 -D_FORTIFY_SOURCE=2", false),
                ("GNU AS 2.33.1", true),
            ],
        );
        let config = optflags_config(&["-O2"]);
        let results = run_optflags(&pkg, &path, &config);
        // Only the C unit carries the forbidden flag: exactly one finding.
        let lines = lines_for(&results, "forbidden-optflags");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains("-O2"), "detail: {}", lines[0]);
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
    ) -> (Vec<(String, String)>, Vec<Level>, tempfile::TempDir, Pkg) {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(rpm), dir.path(), true).expect("open fixture");
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        let mut check = BinariesCheck::with_tool_dir(config, None);
        check.check_binary(&pkg, config, &mut out);
        (
            out.results().to_vec(),
            out.result_levels().to_vec(),
            dir,
            pkg,
        )
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

    /// Assert the fixture's `__asm__(".type ..., @function")` hack is live:
    /// the symbol must be FUNC in .dynsym. Modern GCC emits undefined
    /// imports as NOTYPE, which the scan does not match -- if a future
    /// toolchain ignores the directive, the forbidden-function tests would
    /// still go green, so this fails loudly instead (plusky's #241 review).
    fn assert_dynsym_is_func(pkg: &Pkg, so: &str, sym_name: &str) {
        let extracted = pkg.extracted_dir().expect("fixture extracted");
        let data = std::fs::read(extracted.join(so)).expect("fixture so readable");
        let elf = goblin::elf::Elf::parse(&data).expect("fixture so parses");
        let sym = elf
            .dynsyms
            .iter()
            .find(|s| elf.dynstrtab.get_at(s.st_name) == Some(sym_name))
            .unwrap_or_else(|| panic!("{sym_name} missing from {so}"));
        assert_eq!(
            sym.st_type(),
            goblin::elf::sym::STT_FUNC,
            "{sym_name} must stay FUNC in {so}"
        );
    }

    #[test]
    fn forbidden_function_fires_for_dynsym_import() {
        // libcryptobad.so is stripped: SSL_CTX_set_cipher_list exists only as
        // an undefined import in .dynsym. The pre-fix scan of .symtab alone
        // could never see it, so this test fails with the bug live.
        // NOTE: this depends on the fixture carrying the import as FUNC via
        // the __asm__(".type ..., @function") hack in build.sh. If the hack
        // ever stops working the symbol reverts to NOTYPE and this test goes
        // green without guarding anything, so do not remove it.
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let config = warn_on_function_config();
        let (results, levels, _dir, pkg) = run_binaries_check_with_config(&rpm_path, &config);
        assert_dynsym_is_func(&pkg, "usr/lib64/libcryptobad.so", "SSL_CTX_set_cipher_list");

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
        let (results, _levels, _dir, pkg) = run_binaries_check_with_config(&rpm_path, &config);
        assert_dynsym_is_func(&pkg, "usr/lib64/libgnutlswaived.so", "gnutls_priority_init");
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
                x86_feature_1_and: X86Feature1And::Absent,
                has_endbr64: false,
                sections,
                program_headers: Vec::new(),
                functions: Vec::new(),
                undefined_functions: Vec::new(),
                is_shlib: true,
                is_debug: false,
                soname: None,
                needed: Vec::new(),
                runpaths: Vec::new(),
                has_textrel: false,
                has_nonweak_undefined: false,
                defines_main: false,
                elf_type: goblin::elf::header::ET_DYN,
                elf_machine: goblin::elf::header::EM_X86_64,
                bind_now: false,
                has_dynamic: false,
                failed: None,
                is_rust: false,
                is_zig: false,
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
        // Name, detail, severity, ORDER byte-identical: missing-hash-section
        // sorts before missing-gnu-hash-section by check-name reverse-alpha
        // (not by severity: E before W here is coincidence).
        // The report order comes from Filter::render_results sorting, not
        // emission order, so pin the positions on the sorted (wire) vec.
        let mut sorted = results.clone();
        crate::filter::sort_results(&mut sorted);
        let hash_pos = sorted.iter().position(|(n, _)| n == "missing-hash-section");
        let gnu_pos = sorted
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
    // ---- Emission pins for previously unasserted findings ----
    //
    // The findings below were implemented with no test pinning them:
    // deleting any emission would have kept the suite green. Each test
    // drives the real emission function (or the full check_binary driver
    // where the finding only fires from the file loop) over hand-built
    // inputs and asserts name + level + detail.

    fn synthetic_pkg(name: &str, arch: &str, files: Vec<PkgFile>) -> Pkg {
        let rpm = format!(
            "{}/../../tests/fixtures/binaries-check/input/rpmcrab-binaries-fixture-1.0-1.aarch64.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut pkg =
            Pkg::open_no_extract(std::path::Path::new(&rpm)).expect("open fixture header");
        pkg.name = name.to_string();
        pkg.arch = arch.to_string();
        pkg.files = files;
        pkg
    }

    fn syn_file(name: &str, magic: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            magic: magic.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    fn syn_link(name: &str, linkto: &str) -> PkgFile {
        PkgFile {
            name: name.to_string(),
            path: name.to_string(),
            magic: String::new(),
            mode: 0o100777,
            linkto: linkto.to_string(),
            ..Default::default()
        }
    }

    fn syn_info() -> ReadelfInfo {
        ReadelfInfo {
            x86_feature_1_and: X86Feature1And::Absent,
            has_endbr64: false,
            sections: Vec::new(),
            program_headers: Vec::new(),
            functions: Vec::new(),
            undefined_functions: Vec::new(),
            is_shlib: false,
            is_debug: false,
            soname: None,
            needed: Vec::new(),
            runpaths: Vec::new(),
            has_textrel: false,
            has_nonweak_undefined: false,
            defines_main: false,
            elf_type: goblin::elf::header::ET_EXEC,
            elf_machine: goblin::elf::header::EM_X86_64,
            bind_now: false,
            has_dynamic: true,
            failed: None,
            is_rust: false,
            is_zig: false,
        }
    }

    fn sec(name: &str) -> ElfSection {
        ElfSection {
            name: name.to_string(),
            size: 100,
        }
    }

    fn syn_ldd() -> LddInfo {
        LddInfo {
            dependencies: Vec::new(),
            unused_dependencies: Vec::new(),
            undefined_symbols: Vec::new(),
            defined_symbols: Vec::new(),
            is_64: None,
            rpath: Vec::new(),
            runpath: Vec::new(),
            has_runpath: false,
            failed: None,
        }
    }

    fn config_with(snippet: &str) -> Config {
        let mut table: toml::Table = toml::from_str(include_str!("../../data/configdefaults.toml"))
            .expect("parse configdefaults");
        let overlay: toml::Table = toml::from_str(snippet).expect("parse overlay");
        for (k, v) in overlay {
            table.insert(k, v);
        }
        Config {
            configuration: table,
            ..Default::default()
        }
    }

    fn driver_results(pkg: &Pkg, config: &Config) -> Vec<(String, String)> {
        let mut check = BinariesCheck::with_tool_dir(config, None);
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_binary(pkg, config, &mut out);
        out.results().to_vec()
    }

    fn fake_tool_dir(name: &str, script_body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let tool_dir = dir.path().join("tools");
        std::fs::create_dir(&tool_dir).expect("mkdir tools");
        let path = tool_dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script_body}\n")).expect("write fake tool");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake tool");
        }
        (dir, tool_dir)
    }

    // A minimal ELF64 executable parseable by goblin, so run_elf_checks
    // reaches the ldd branch without a toolchain-produced fixture.
    fn parseable_elf() -> Vec<u8> {
        let mut elf: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        elf.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf.extend_from_slice(&1u32.to_le_bytes()); // version
        elf.extend_from_slice(&0u64.to_le_bytes()); // entry
        elf.extend_from_slice(&64u64.to_le_bytes()); // phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // ehsize
        elf.extend_from_slice(&56u16.to_le_bytes()); // phentsize
        elf.extend_from_slice(&1u16.to_le_bytes()); // phnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // shstrndx
        // One PT_LOAD segment.
        elf.extend_from_slice(&1u32.to_le_bytes()); // p_type
        elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags R+X
        elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
        elf.extend_from_slice(&0u64.to_le_bytes()); // p_vaddr
        elf.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
        elf.extend_from_slice(&120u64.to_le_bytes()); // p_filesz
        elf.extend_from_slice(&120u64.to_le_bytes()); // p_memsz
        elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        elf
    }

    #[test]
    fn noarch_package_with_binary_is_error() {
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/bin/main",
                "ELF 64-bit LSB executable, x86-64, version 1 (SYSV)",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/bin/main"),
            "detail names the binary: {}",
            lines[0]
        );
    }

    #[test]
    fn noarch_package_with_relocatable_object_is_error() {
        // Reference test_no_arch_error: a plain .o in a noarch package fires.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/opt/x86_64.o",
                "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/opt/x86_64.o"),
            "detail names the object: {}",
            lines[0]
        );
    }

    #[test]
    fn arch_package_with_binary_has_no_arch_finding() {
        let config = test_config();
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/bin/main",
                "ELF 64-bit LSB executable, x86-64, version 1 (SYSV)",
            )],
        );
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn ebpf_object_is_exempt_from_noarch_check() {
        // Reference test_no_arch_eBPF: eBPF objects never trigger the
        // arch-independent finding, even in a noarch package.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/opt/ebpf.o",
                "ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        assert!(
            results.is_empty(),
            "eBPF object must be fully quiet: {results:?}"
        );
    }

    #[test]
    fn noarch_with_lib64_is_error() {
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file("/usr/lib64/libfoo.so.1", "data")],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "noarch-with-lib64");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
    }

    #[test]
    fn package_without_binary_is_warning() {
        let config = test_config();
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/share/doc/testpkg/README", "ASCII text")],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
    }

    #[test]
    fn no_binary_quiet_when_files_in_usrlib_444() {
        // 32-bit blosc-devel shape: headers, .so symlink and pkgconfig under
        // /usr/lib, no binaries. The libdir exemption must not be lib64-only.
        let config = test_config();
        let pkg = synthetic_pkg(
            "blosc-devel",
            "i586",
            vec![
                syn_file("/usr/lib/libblosc.so.1.2.3", "ASCII text"),
                syn_link("/usr/lib/libblosc.so", "libblosc.so.1.2.3"),
                syn_file("/usr/lib/pkgconfig/blosc.pc", "ASCII text"),
                syn_file("/usr/include/blosc.h", "ASCII text"),
            ],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert!(
            lines.is_empty(),
            "no-binary must stay quiet for libdir content: {results:?}"
        );
    }

    #[test]
    fn no_binary_quiet_when_files_in_lib64() {
        // Same shape on 64-bit: the pre-existing lib64 exemption keeps working.
        let config = test_config();
        let pkg = synthetic_pkg(
            "blosc-devel",
            "x86_64",
            vec![
                syn_file("/usr/lib64/libblosc.so.1.2.3", "ASCII text"),
                syn_link("/usr/lib64/libblosc.so", "libblosc.so.1.2.3"),
                syn_file("/usr/lib64/pkgconfig/blosc.pc", "ASCII text"),
                syn_file("/usr/include/blosc.h", "ASCII text"),
            ],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert!(
            lines.is_empty(),
            "no-binary must stay quiet for lib64 content: {results:?}"
        );
    }

    #[test]
    fn no_binary_quiet_for_hwcaps_subarch_devel() {
        // tesseract-ocr-devel shape built for a hwcaps subarch (issue
        // #589): headers, .so symlink and pkgconfig under the base arch's
        // /usr/lib64, no binaries. The subarch takes the base arch's
        // native libdir, so the exemption applies exactly as it does for
        // the plain arch twin.
        let config = test_config();
        for arch in ["x86_64", "x86_64_v3", "x86_64_v4"] {
            let pkg = synthetic_pkg(
                "tesseract-ocr-devel",
                arch,
                vec![
                    syn_link("/usr/lib64/libtesseract.so", "libtesseract.so.5.0.4"),
                    syn_file("/usr/lib64/pkgconfig/tesseract.pc", "ASCII text"),
                    syn_file("/usr/include/tesseract/baseapi.h", "ASCII text"),
                ],
            );
            let results = driver_results(&pkg, &config);
            let lines = lines_for(&results, "no-binary");
            assert!(
                lines.is_empty(),
                "{arch} devel shape must stay quiet: {results:?}"
            );
        }
    }

    #[test]
    fn no_binary_libdir_exemption_matches_arch_word_size() {
        // The exemption covers only the package's own native libdir:
        // lib64 dirs on 64-bit arches, lib dirs on 32-bit ones. Content
        // under the other word size's libdir does not exempt -- e.g.
        // /usr/lib/systemd units must not silence no-binary on x86_64.
        // Bare directory entries never exempt on any arch: owning the
        // libdir itself is not shipping a library.
        let config = test_config();
        // (arch, sole payload file, no-binary stays quiet)
        let cases: [(&str, &str, bool); 23] = [
            ("x86_64", "/usr/lib64/libfoo.so.1", true),
            ("x86_64", "/lib64/libfoo.so.1", true),
            ("x86_64", "/usr/lib/libfoo.so.1", false),
            ("x86_64", "/lib/libfoo.so.1", false),
            ("x86_64", "/usr/lib/systemd/system/foo.service", false),
            ("x86_64", "/usr/lib64", false),
            ("x86_64", "/lib64", false),
            ("aarch64", "/usr/lib64/libfoo.so.1", true),
            ("aarch64", "/usr/lib/libfoo.so.1", false),
            ("aarch64", "/usr/lib64", false),
            ("aarch64", "/lib64", false),
            ("i586", "/usr/lib/libfoo.so.1", true),
            ("i586", "/lib/libfoo.so.1", true),
            ("i586", "/usr/lib", false),
            ("i586", "/lib", false),
            ("i586", "/usr/lib64/libfoo.so.1", false),
            ("i586", "/lib64/libfoo.so.1", false),
            ("i586", "/usr/lib64", false),
            ("i586", "/lib64", false),
            ("x86_64_v3", "/usr/lib64/libfoo.so.1", true),
            ("x86_64_v3", "/lib64/libfoo.so.1", true),
            ("x86_64_v3", "/usr/lib/libfoo.so.1", false),
            ("x86_64_v4", "/usr/lib64/libfoo.so.1", true),
        ];
        for (arch, path, quiet) in cases {
            let pkg = synthetic_pkg("testpkg", arch, vec![syn_file(path, "ASCII text")]);
            let results = driver_results(&pkg, &config);
            let lines = lines_for(&results, "no-binary");
            if quiet {
                assert!(
                    lines.is_empty(),
                    "{arch} + {path} must exempt from no-binary: {results:?}"
                );
            } else {
                assert_eq!(
                    lines.len(),
                    1,
                    "{arch} + {path} must still fire no-binary: {results:?}"
                );
            }
        }
    }

    #[test]
    fn no_binary_still_fires_without_libdir_content() {
        // Pure /usr/share content with no binaries: still fires.
        let config = test_config();
        let pkg = synthetic_pkg(
            "testpkg",
            "i586",
            vec![syn_file("/usr/share/doc/testpkg/README", "ASCII text")],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
    }

    #[test]
    fn arch_dependent_file_in_usr_share() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary_in_usr_share(&pkg, "/usr/share/main", &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(lines[0].contains("/usr/share/main"), "detail: {}", lines[0]);

        // An arch-qualified share path is exempt.
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary_in_usr_share(&pkg, "/usr/share/doc/x86_64/foo", &mut out);
        assert!(
            out.results().is_empty(),
            "exempt path must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn binary_in_etc() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        for name in ["/etc/foo", "/usr/etc/foo"] {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_binary_in_etc(&pkg, name, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "binary-in-etc");
            assert_eq!(lines.len(), 1, "one finding for {name}: {results:?}");
            assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
            assert!(lines[0].contains(name), "detail: {}", lines[0]);
        }
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary_in_etc(&pkg, "/usr/bin/foo", &mut out);
        assert!(
            out.results().is_empty(),
            "non-etc path must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn libtool_wrapper_in_package() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let path = dir.path().join("wrapper");
        std::fs::write(
            &path,
            "#!/bin/sh\n# This wrapper script should never be moved out of the build directory\n",
        )
        .expect("write wrapper");
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let mut pkgfile = syn_file("/usr/bin/wrapper", "Bourne-Again shell script");
        pkgfile.path = path.to_string_lossy().into_owned();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_libtool_wrapper(&pkg, "/usr/bin/wrapper", &pkgfile, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "libtool-wrapper-in-package");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/bin/wrapper"),
            "detail: {}",
            lines[0]
        );

        // A shell script without the marker is not a libtool wrapper.
        std::fs::write(&path, "#!/bin/sh\necho hello\n").expect("write plain script");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_libtool_wrapper(&pkg, "/usr/bin/wrapper", &pkgfile, &mut out);
        assert!(
            out.results().is_empty(),
            "plain script must be quiet: {:?}",
            out.results()
        );

        // A truncated marker (common prefix only) must not match: the check
        // pins the full marker text, so a prefix-only match would fail here.
        std::fs::write(
            &path,
            "#!/bin/sh\n# This wrapper script should never be moved out of the\n",
        )
        .expect("write truncated marker");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_libtool_wrapper(&pkg, "/usr/bin/wrapper", &pkgfile, &mut out);
        assert!(
            out.results().is_empty(),
            "truncated marker must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn unstripped_binary_is_warning() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file(
            "/usr/bin/foo",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), not stripped",
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_unstripped_binary("/usr/bin/foo", &pkg, &pkgfile, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "unstripped-binary-or-object");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(lines[0].contains("/usr/bin/foo"), "detail: {}", lines[0]);

        // Stripped binaries and debug files are quiet.
        let pkgfile = syn_file(
            "/usr/bin/foo",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), stripped",
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_unstripped_binary("/usr/bin/foo", &pkg, &pkgfile, &mut out);
        assert!(
            out.results().is_empty(),
            "stripped binary must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn non_pie_executable_error_with_patterns() {
        // Reference test_non_position_independent: a PieExecutables pattern
        // matching the path turns the suggestion into an error.
        let config = config_with("PieExecutables = [\".*\"]");
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_non_pie(&pkg, "/usr/bin/bcc-lua", &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "non-position-independent-executable");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/bin/bcc-lua"),
            "detail: {}",
            lines[0]
        );
        assert_lacks(&results, "position-independent-executable-suggested");
    }

    #[test]
    fn non_pie_executable_warns_without_patterns() {
        // Reference test_non_position_independent_sugg: with an empty
        // PieExecutables list the same file only gets the suggestion.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_non_pie(&pkg, "/usr/bin/bcc-lua", &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "position-independent-executable-suggested");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert_lacks(&results, "non-position-independent-executable");

        // Shared objects are exempt either way.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_non_pie(&pkg, "/usr/lib64/libfoo.so", &mut out);
        assert!(
            out.results().is_empty(),
            "shobj must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn missing_ldconfig_symlink() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_soname_symlink(&pkg, "/usr/lib64/libfoo.so.1.2.3", "libfoo.so.1", &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "no-ldconfig-symlink");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.so.1.2.3"),
            "detail: {}",
            lines[0]
        );

        // A missing symlink for a non-library file is not reported.
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_soname_symlink(&pkg, "/usr/lib64/foo", "foo", &mut out);
        assert!(
            out.results().is_empty(),
            "non-library name must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn shared_library_soname_findings() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkgfile = syn_file("/usr/lib64/libfoo.so.1", "ELF 64-bit LSB shared object");

        // Missing SONAME -> W no-soname.
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let mut info = syn_info();
        info.is_shlib = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_shared_library(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "no-soname");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.so.1"),
            "detail: {}",
            lines[0]
        );

        // Malformed SONAME -> E invalid-soname.
        let mut info = syn_info();
        info.is_shlib = true;
        info.soname = Some("b soname".to_string());
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_shared_library(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "invalid-soname");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("b soname"),
            "detail names the soname: {}",
            lines[0]
        );

        // A well-formed SONAME with a correct symlink is quiet.
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_link("/usr/lib64/libfoo.so.1", "libfoo.so.1.2.3")],
        );
        let pkgfile = syn_file("/usr/lib64/libfoo.so.1.2.3", "ELF 64-bit LSB shared object");
        let mut info = syn_info();
        info.is_shlib = true;
        info.soname = Some("libfoo.so.1".to_string());
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_shared_library(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "valid soname must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn shlib_policy_name_error() {
        // Reference test_shlib_policy.py: SONAME/package-suffix policy.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg(
            "libgame",
            "x86_64",
            vec![
                syn_file("/lib64/libgame.so", "ELF 64-bit LSB shared object"),
                syn_link("/lib64/libgame2-1.9.so.10.0.0", "libgame.so"),
            ],
        );
        let mut info = syn_info();
        info.is_shlib = true;
        info.soname = Some("libgame2-1.9.so.10.0.0".to_string());
        let pkgfile = syn_file("/lib64/libgame.so", "ELF 64-bit LSB shared object");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_shared_library(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "shlib-policy-name-error");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains(
                "SONAME: libgame2-1.9.so.10.0.0 (/lib64/libgame.so), \
                 expected package suffix: 1_9-10_0_0"
            ),
            "detail: {}",
            lines[0]
        );
        assert_lacks(&results, "no-ldconfig-symlink");
    }

    /// Run the shared-library policy-name test for one package/SONAME
    /// pair and return the rendered shlib-policy-name-error lines.
    fn shlib_policy_lines(pkgname: &str, soname: &str, file: &str) -> Vec<String> {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let parent = Path::new(file)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        let soname_path = if parent.is_empty() {
            soname.to_string()
        } else {
            format!("{parent}/{soname}")
        };
        let pkg = synthetic_pkg(pkgname, "x86_64", vec![syn_link(&soname_path, "libfoo.so")]);
        let pkgfile = syn_file(file, "ELF 64-bit LSB shared object");
        let mut info = syn_info();
        info.is_shlib = true;
        info.soname = Some(soname.to_string());
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_shared_library(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        lines_for(&results, "shlib-policy-name-error")
            .into_iter()
            .map(str::to_string)
            .collect()
    }

    /// The shlib-policy-name-error permutation matrix: every row pins
    /// one (package name, SONAME) pair to its verdict under the guard.
    /// Verdicts are pinned from, in order, the SLPP package-naming
    /// construction (openSUSE:Shared_library_packaging_policy#Package_naming),
    /// the reference's actual behaviour, and the review traces on
    /// PR #650; rows mined from the 2026-10-16 Factory sweep corpus
    /// (51,589 RPMs, SONAMEs from RPM provides) are marked as such.
    /// The guard accepts a name when it equals a SONAME-derived
    /// expected name (limb A: stem with '.' folded to '_', version
    /// glued or dash-separated per the SLPP construction) or when it
    /// ends with the expected suffix at a non-digit boundary (limb B:
    /// the trailing version run matches as a whole, the stem is not
    /// policed), after stripping a trailing baselibs (-32bit/-64bit)
    /// or flavour (-gcc15, -openmpi4) segment.
    #[test]
    fn shlib_policy_name_matrix() {
        // (package name, SONAME, fires?)
        let rows: &[(&str, &str, bool)] = &[
            // Straightforward conformant names.
            ("libfoo1", "libfoo.so.1", false),
            ("libfoo-1", "libfoo.so.1", false),
            ("libblkid1", "libblkid.so.1", false), // SLPP table
            ("libz1", "libz.so.1", false),         // corpus
            ("libcurl4", "libcurl.so.4", false),   // corpus
            ("libstdc++6", "libstdc++.so.6", false), // corpus, '+' stem
            ("libFLAC14", "libFLAC.so.14", false), // corpus, multi-digit
            ("libpoppler164", "libpoppler.so.164", false), // corpus, 3-digit
            ("libgcc_s1", "libgcc_s.so.1", false), // corpus, '_' in stem
            // Digit-ending stems: the glued form merges the version
            // into the stem's own digits (limb A); the SLPP dash form
            // is equally conformant.
            ("libx111", "libx11.so.1", false), // review trace, PR #650 round 1
            ("libx11-1", "libx11.so.1", false), // SLPP dash-between-numbers
            ("libbz2-1", "libbz2.so.1", false), // SLPP table
            ("libbz21", "libbz2.so.1", false), // glued twin of the SLPP row
            ("libxml2-2", "libxml2.so.2", false), // corpus (real name)
            ("libpng16-16", "libpng16.so.16", false), // corpus (real name)
            ("libpng1616", "libpng16.so.16", false), // glued twin
            ("libk5crypto3", "libk5crypto.so.3", false), // digits inside stem
            (
                "libnvidia-egl-wayland21",
                "libnvidia-egl-wayland2.so.1",
                false,
            ), // corpus
            ("libnvidia-egl-x111", "libnvidia-egl-x11.so.1", false), // round 1
            ("libx112", "libx11.so.1", true),  // wrong version, digit stem
            ("libfoo12", "libfoo.so.2", true), // trailing run 12 != 2
            // The bsc#1237372 defect class: a longer trailing version
            // run must not satisfy a shorter expected version.
            (
                "libkdecorations3private11",
                "libkdecorations3private.so.1",
                true,
            ),
            (
                "libkdecorations3private2",
                "libkdecorations3private.so.2",
                false,
            ), // corpus: the renamed package, correct pairing
            ("libfoo11", "libfoo.so.1", true),
            ("libfoo11-32bit", "libfoo.so.1", true),
            ("libfoo110_0_0", "libfoo.so.10.0.0", true),
            ("libfoo2", "libfoo.so.1", true),
            // Composite and -<pkgversion> forms (SLPP construction).
            ("libgame2-1_9-10_0_0", "libgame2-1.9.so.10.0.0", false), // SLPP table
            ("libgame2-11_9-10_0_0", "libgame2-1.9.so.10.0.0", true),
            ("libdb-4_8", "libdb-4.8.so", false), // SLPP table
            ("libfoo1", "libfoo-1.so", false),    // glued pkgversion-only form
            ("libfoo-1", "libfoo-1.so", false),   // dash pkgversion-only form
            // The glued twin of a digit-ending stem fires: the
            // pkgversion branch derives only the dash form
            // (libfoo2-1), and limb B's non-digit boundary rejects
            // the glued digit run. Pinned asymmetry (issue #673):
            // tolerated nowhere else, and no corpus pair needs it.
            ("libfoo21", "libfoo2-1.so", true),
            ("libfoo11", "libfoo-1.so", true), // longer run, pkgversion-only
            ("libfoo2", "libfoo-1.so", true),
            ("libzziplib-0-13", "libzziplib-0.so.13", false), // SLPP table
            ("libmwaw-0_3-3_0_11", "libmwaw-0.3.so.3.0.11", false), // SLPP page
            ("libSDL2_image-2_0-0", "libSDL2_image-2.0.so.0", false), // SLPP page
            ("libfoo10_0_0", "libfoo.so.10.0.0", false),
            ("libfoo1_0", "libfoo.so.1.0", false),
            // Cross-stem names: the name ends in the SONAME version
            // but derives from a different stem (a sibling library, a
            // renamed project). The reference stays quiet and the
            // check polices the version run, not the stem (limb B).
            ("libopenssl3", "libssl.so.3", false), // review trace, round 2
            ("libicu73", "libicuuc.so.73", false), // review trace, round 2
            ("libicu74", "libicuuc.so.73", true),  // wrong version, cross-stem
            ("libext2fs2", "libe2p.so.2", false),  // corpus
            ("libgc1", "libcord.so.1", false),     // corpus
            ("libgomp1", "libgomp-plugin-gcn.so.1", false), // corpus, sibling
            ("libQt5Gui5", "libQt5EglFSDeviceIntegration.so.5", false), // corpus
            ("libcasacore9", "libcasa_casa.so.9", false), // corpus
            ("libapr1-0", "libapr-1.so.0", false), // corpus: glued pkgversion, dashed SO
            // ...but a sibling whose version run does not match still
            // fires: the name belongs to libnvidia-egl-x11.so.1, whose
            // trailing run is 111, not the xcb library's 1.
            ("libnvidia-egl-x111", "libnvidia-egl-xcb.so.1", true),
            // Flavour and MPI tails: the version sits before a
            // trailing -<letters><digits> segment. The strip loosens
            // the reference where the tail's last digit does not
            // coincide with the version (libgomp1-gcc15 for .so.1);
            // the divergence is ledgered with its corpus measurement.
            ("libgfortran5-gcc15", "libgfortran.so.5", false), // round 1 trace
            ("libobjc4-gcc14", "libobjc.so.4", false),         // corpus
            ("libgomp1-gcc15", "libgomp.so.1", false),         // loosening row
            ("libgomp1-gcc15", "libgomp-plugin-gcn.so.1", false), // corpus
            ("libstdc++6-gcc15", "libstdc++.so.6", false),     // corpus
            ("libgfortran6-gcc15", "libgfortran.so.5", true),  // wrong version
            ("libHYPRE301-openmpi4", "libHYPRE.so.301", false), // corpus, MPI tail
            ("libnetcdf22-openmpi5", "libnetcdf.so.22", false), // corpus, MPI tail
            ("libdeal_II9_7_1-openmpi4", "libdeal_II.so.9.7.1", false), // corpus
            ("libpetsc3_25-openmpi4", "libpetsc.so.3.25", false), // corpus
            // Baselibs tails: the version sits before -32bit/-64bit.
            // The reference fires on the correct names; the loosening
            // is ledgered.
            ("libfoo1-32bit", "libfoo.so.1", false),
            ("libx111-32bit", "libx11.so.1", false),
            ("libfoo1-64bit", "libfoo.so.1", false),
            // Combined flavour+baselibs tails: the baselibs suffix
            // strips before the flavour strip runs, so the HPC shape
            // resolves (issue #673). The reverse tail order leaves
            // the version buried mid-name: the flavour strip sees
            // the whole name, the baselibs strip never applies, and
            // it fires.
            ("libnetcdf22-openmpi5-32bit", "libnetcdf.so.22", false),
            ("libnetcdf22-32bit-openmpi5", "libnetcdf.so.22", true),
            // Corpus pairs every predicate fires on: pre-existing
            // Factory naming violations, unchanged by this guard.
            ("libLLVM18", "libLLVM.so.18.1", true), // suffix is 18_1
            ("liblua5_3-5", "liblua.so.5.3", true), // suffix is 5_3
            // Gates: no version in the SONAME, and non-lib packages,
            // are outside the check entirely.
            ("libfoo", "libfoo.so", false),
            ("foo1", "libfoo.so.1", false),
            // A version-less SONAME whose stem carries the version
            // digits (the libtcl8.6.so shape): soversion_str is
            // empty, so the emission guard stays shut even when the
            // package name does not derive from the stem at all.
            // Unlike the libfoo.so row above, whose SONAME exits via
            // invalid-soname before the guard, these rows reach it
            // (issue #673).
            ("libfoo1", "libfoo1.so", false),
            ("libfoo2", "libfoo1.so", false),
        ];
        // Collect every mismatching row so one run reports the whole
        // failing set, not just the first cell.
        let mut failures = Vec::new();
        for (pkgname, soname, fires) in rows {
            let file = format!("/usr/lib64/{soname}");
            let lines = shlib_policy_lines(pkgname, soname, &file);
            if *fires {
                if lines.len() != 1 {
                    failures.push(format!(
                        "{pkgname} for {soname} must fire once, got: {lines:?}"
                    ));
                } else if !lines[0].contains(" E: ") {
                    failures.push(format!(
                        "{pkgname} for {soname} must fire at Error level: {}",
                        lines[0]
                    ));
                }
            } else if !lines.is_empty() {
                failures.push(format!(
                    "{pkgname} for {soname} must be quiet, got: {lines:?}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "matrix mismatches:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn non_executable_shlib_stays_quiet() {
        // shared-library-not-executable was deliberately dropped (upstream rpmlint#596):
        // a 0644 shared library must stay quiet through the full emission path.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let mut pkg =
            Pkg::open(std::path::Path::new(&rpm_path), dir.path(), true).expect("open fixture");
        let mut found = false;
        for f in pkg.files.iter_mut() {
            if f.name == "/usr/lib64/libgood.so.1" {
                f.mode = 0o100644;
                found = true;
            }
        }
        assert!(found, "libgood.so.1 missing from fixture");
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_lacks(&results, "shared-library-not-executable");
    }

    #[test]
    fn lto_bytecode_in_archive() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut info = syn_info();
        info.sections = vec![vec![sec(".text"), sec(".gnu.lto_.foo")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_lto_section(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "lto-bytecode");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.a"),
            "detail: {}",
            lines[0]
        );

        let mut info = syn_info();
        info.sections = vec![vec![sec(".text")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_lto_section(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "no LTO sections must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn lto_no_text_in_archive() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut info = syn_info();
        info.sections = vec![vec![sec(".comment")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "lto-no-text-in-archive");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.a"),
            "detail: {}",
            lines[0]
        );

        // A .text section means the archive carries real code.
        let mut info = syn_info();
        info.sections = vec![vec![sec(".comment"), sec(".text")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            ".text present must be quiet: {:?}",
            out.results()
        );

        // Known-empty glibc archives and their GHC (_p) variants are exempt.
        for name in ["/usr/lib64/libdl.a", "/usr/lib64/libdl_p.a"] {
            let pkgfile = syn_file(name, "current ar archive");
            let mut info = syn_info();
            info.sections = vec![vec![sec(".comment")]];
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
            assert!(
                out.results().is_empty(),
                "{name} must be exempt: {:?}",
                out.results()
            );
        }
    }

    /// Build a minimal SysV ar archive from (name, bytes) members.
    fn craft_ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, data) in members {
            // 60-byte member header: name(16) mtime(12) uid(6) gid(6)
            // mode(8) size(10) ending in "`\n". Short SysV names end with '/'.
            let mut header = [b' '; 60];
            let name_field = format!("{name}/");
            let name_len = name_field.len().min(16);
            header[..name_len].copy_from_slice(&name_field.as_bytes()[..name_len]);
            let size_field = data.len().to_string();
            header[48..48 + size_field.len()].copy_from_slice(size_field.as_bytes());
            header[58] = b'`';
            header[59] = b'\n';
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    #[test]
    fn archive_members_parse_like_readelf() {
        // Regression: archives used to fail as a whole with goblin's
        // "Invalid magic number" (readelf-failed); the reference runs
        // readelf over the archive and readelf iterates the members.
        let m1 = craft_shlib_elf(false, Some("liba.so.1"), None, &[]);
        let m2 = craft_shlib_elf(false, None, None, &[]);
        let archive = craft_ar_archive(&[("a.o", &m1), ("b.o", &m2)]);
        let path = std::env::temp_dir().join(format!("rpmcrab-ar-{}", std::process::id()));
        std::fs::write(&path, &archive).unwrap();

        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
        // This is the readelf-failed gate in run_elf_checks: any failure
        // here becomes the finding.
        assert!(
            info.failed.is_none(),
            "archive must parse member-wise: {:?}",
            info.failed
        );
        // Sections of both members merged, like readelf's per-member output.
        let names: Vec<&str> = info
            .sections
            .iter()
            .flatten()
            .map(|s| s.name.as_str())
            .collect();
        assert!(
            names.contains(&".dynamic"),
            "member sections merged: {names:?}"
        );
        assert_eq!(
            names.iter().filter(|n| **n == ".shstrtab").count(),
            2,
            "both members parsed: {names:?}"
        );

        // The archive checks now see real member data instead of being
        // skipped: the members carry no .text.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        assert_eq!(
            lines_for(&results, "lto-no-text-in-archive").len(),
            1,
            "archive checks run on parsed members: {results:?}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn archive_with_non_elf_member_fails_like_readelf() {
        // The reference's readelf exits nonzero when any member is not an
        // ELF object, failing the whole file.
        let m1 = craft_shlib_elf(false, None, None, &[]);
        let archive = craft_ar_archive(&[("a.o", &m1), ("note.txt", b"hello\n")]);
        let path = std::env::temp_dir().join(format!("rpmcrab-ar-mixed-{}", std::process::id()));
        std::fs::write(&path, &archive).unwrap();

        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
        assert!(
            info.failed.is_some(),
            "non-ELF member must fail the whole archive"
        );

        // Drive the emission path: run_elf_checks must surface the failure
        // as E: readelf-failed, not just record it on the struct.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: "/usr/lib64/libfoo.a".to_string(),
            path: path.to_str().unwrap().to_string(),
            magic: "current ar archive".to_string(),
            mode: 0o100644,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let analysis =
            ElfAnalysis::wants_analysis(&pkgfile, false).then(|| ElfAnalysis::parse(&pkgfile));
        check.run_elf_checks(&pkg, &pkgfile, &config, &mut out, analysis.as_ref());
        let results = out.results().to_vec();
        let lines = lines_for(&results, "readelf-failed");
        assert_eq!(lines.len(), 1, "exactly one readelf-failed: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.a"),
            "detail names the archive: {}",
            lines[0]
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn ghost_elf_file_is_not_analysed() {
        // #466: a %ghost file is in the header (with an ELF FILECLASS)
        // but not in the payload, so nothing was extracted to its path.
        // The header magic used to pass the ELF gates and the failed
        // payload read surfaced as E: readelf-failed.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let real_path = dir.path().join("libreal.so");
        std::fs::write(&real_path, craft_shlib_elf(false, None, None, &[])).expect("write so");

        let ghost_path = dir.path().join("vmlinux"); // never written: no payload
        let mut ghost = syn_file(
            "/usr/lib/modules/7.2.9-1-default/vmlinux",
            "ELF 64-bit LSB executable, x86-64, dynamically linked",
        );
        ghost.path = ghost_path.to_string_lossy().into_owned();
        ghost.flags = crate::pkg::pkgfile::RPMFILE_GHOST;
        ghost.mode = 0o100755;

        let mut real = syn_file("/usr/lib64/libreal.so", "ELF 64-bit LSB shared object");
        real.path = real_path.to_string_lossy().into_owned();

        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("kernel-default-base", "x86_64", vec![ghost.clone(), real]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_lacks(&results, "readelf-failed");
        assert!(
            !results.iter().any(|(_, line)| line.contains("vmlinux")),
            "ghost must produce no findings at all: {results:?}"
        );

        // The pre-pass must not even attempt to parse a ghost.
        assert!(!ElfAnalysis::wants_analysis(&ghost, false));
    }

    #[test]
    fn ghost_only_binary_package_does_not_fire_no_binary() {
        // #515: a package whose only binary-class file is a %ghost must
        // not fire no-binary — the header FILECLASS is authoritative for
        // package-level presence even though there is no payload on disk
        // to analyse. kernel-default-base ships exactly this shape: its
        // vmlinux is a %ghost that %post decompresses into place.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let ghost_path = dir.path().join("vmlinux"); // never written: no payload
        let mut ghost = syn_file(
            "/usr/lib/modules/7.2.9-1-default/vmlinux",
            "ELF 64-bit LSB executable, x86-64, statically linked, not stripped",
        );
        ghost.path = ghost_path.to_string_lossy().into_owned();
        ghost.flags = crate::pkg::pkgfile::RPMFILE_GHOST;
        ghost.mode = 0o100755;

        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("kernel-default-base", "x86_64", vec![ghost]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_lacks(&results, "no-binary");
        assert!(
            !results.iter().any(|(_, line)| line.contains("vmlinux")),
            "ghost must still produce no per-file findings: {results:?}"
        );
    }

    #[test]
    fn missing_payload_of_non_ghost_elf_still_fails() {
        // Control for the ghost skip: a regular file whose payload is
        // missing is a genuine extraction failure and keeps its
        // readelf-failed error.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let missing_path = dir.path().join("gone"); // never written
        let mut file = syn_file(
            "/usr/bin/gone",
            "ELF 64-bit LSB executable, x86-64, dynamically linked",
        );
        file.path = missing_path.to_string_lossy().into_owned();
        file.mode = 0o100755;

        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "readelf-failed");
        assert_eq!(lines.len(), 1, "exactly one readelf-failed: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
    }

    /// Build a GNU-style ar archive with a `/` symbol-index member,
    /// the shape `ar rcs` produces. `craft_ar_archive` above omits it;
    /// goblin's Archive::parse must skip it (and the `//` extended-name
    /// table). A refactor walking raw members would emit readelf-failed
    /// on every shipped .a and stay green without this.
    fn craft_gnu_ar_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        // Minimal `/` symbol table: zero symbols (4-byte big-endian count).
        let symtab: &[u8] = &0u32.to_be_bytes();
        let mut header = [b' '; 60];
        header[..1].copy_from_slice(b"/");
        let size_field = symtab.len().to_string();
        header[48..48 + size_field.len()].copy_from_slice(size_field.as_bytes());
        header[58] = b'`';
        header[59] = b'\n';
        out.extend_from_slice(&header);
        out.extend_from_slice(symtab);
        for (name, data) in members {
            let mut header = [b' '; 60];
            let name_field = format!("{name}/");
            let name_len = name_field.len().min(16);
            header[..name_len].copy_from_slice(&name_field.as_bytes()[..name_len]);
            let size_field = data.len().to_string();
            header[48..48 + size_field.len()].copy_from_slice(size_field.as_bytes());
            header[58] = b'`';
            header[59] = b'\n';
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            if data.len() % 2 == 1 {
                out.push(b'\n');
            }
        }
        out
    }

    #[test]
    fn gnu_ar_archive_with_symbol_index_parses() {
        // The `/` symbol-index member that `ar rcs` emits must not break
        // member-wise parsing: goblin skips it, sections still merge.
        let m1 = craft_shlib_elf(false, Some("liba.so.1"), None, &[]);
        let m2 = craft_shlib_elf(false, None, None, &[]);
        let archive = craft_gnu_ar_archive(&[("a.o", &m1), ("b.o", &m2)]);
        let path = std::env::temp_dir().join(format!("rpmcrab-ar-gnu-{}", std::process::id()));
        std::fs::write(&path, &archive).unwrap();

        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
        assert!(
            info.failed.is_none(),
            "GNU ar archive must parse member-wise: {:?}",
            info.failed
        );
        let names: Vec<&str> = info
            .sections
            .iter()
            .flatten()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(
            names.iter().filter(|n| **n == ".shstrtab").count(),
            2,
            "both members parsed, symbol index skipped: {names:?}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn static_library_without_symtab() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut info = syn_info();
        info.sections = vec![vec![sec(".text"), sec(".strtab")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_symtab_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "static-library-without-symtab");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.a"),
            "detail: {}",
            lines[0]
        );

        let mut info = syn_info();
        info.sections = vec![vec![sec(".text"), sec(".symtab")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_symtab_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            ".symtab present must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn static_library_without_debuginfo() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut info = syn_info();
        info.sections = vec![vec![sec(".text"), sec(".symtab")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_debug_info_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "static-library-without-debuginfo");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.a"),
            "detail: {}",
            lines[0]
        );

        let mut info = syn_info();
        info.sections = vec![vec![sec(".text"), sec(".debug_info")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_debug_info_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            ".debug_info present must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn patchable_function_entry_in_archive() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut info = syn_info();
        info.sections = vec![vec![sec(".text"), sec("__patchable_function_entries")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_patchable_function_entries_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "patchable-function-entry-in-archive");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/usr/lib64/libfoo.a"),
            "detail: {}",
            lines[0]
        );

        let mut info = syn_info();
        info.sections = vec![vec![sec(".text")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_patchable_function_entries_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "no patchable entries must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn bca_archive_is_not_standard() {
        // .bca (LLVM bitcode archives) are never standard ar archives:
        // the check bails out quietly instead of running ELF checks.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file(
            "/usr/lib64/klee/runtime/libkleeRuntimeFreeStanding.bca",
            "data",
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        assert!(
            !check.is_standard_archive(&pkg, &pkgfile, &mut out),
            ".bca is not a standard archive"
        );
        assert!(
            out.results().is_empty(),
            ".bca must stay quiet: {:?}",
            out.results()
        );
    }

    /// Craft a minimal ELF with a .symtab containing one undefined GLOBAL
    /// and one undefined WEAK symbol.
    fn elf_with_undef_symbols() -> Vec<u8> {
        let strtab = b"\0global_undef\0weak_undef\0";
        let mut symtab = vec![0u8; 24];
        symtab.extend_from_slice(&1u32.to_le_bytes());
        symtab.push(0x10);
        symtab.push(0);
        symtab.extend_from_slice(&0u16.to_le_bytes());
        symtab.extend_from_slice(&0u64.to_le_bytes());
        symtab.extend_from_slice(&0u64.to_le_bytes());
        symtab.extend_from_slice(&14u32.to_le_bytes());
        symtab.push(0x20);
        symtab.push(0);
        symtab.extend_from_slice(&0u16.to_le_bytes());
        symtab.extend_from_slice(&0u64.to_le_bytes());
        symtab.extend_from_slice(&0u64.to_le_bytes());

        let mut shstrtab = vec![0u8];
        let symtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".symtab\0");
        let strtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".strtab\0");
        let shstrtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut buf = vec![0u8; 64];
        let symtab_off = buf.len() as u64;
        buf.extend_from_slice(&symtab);
        let strtab_off = buf.len() as u64;
        buf.extend_from_slice(strtab);
        let shstrtab_off = buf.len() as u64;
        buf.extend_from_slice(&shstrtab);
        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        let shoff = buf.len() as u64;

        let mut shdrs = vec![0u8; 64];
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(&symtab_name.to_le_bytes());
        h[4..8].copy_from_slice(&2u32.to_le_bytes());
        h[24..32].copy_from_slice(&symtab_off.to_le_bytes());
        h[32..40].copy_from_slice(&(symtab.len() as u64).to_le_bytes());
        h[40..44].copy_from_slice(&2u32.to_le_bytes());
        h[44..48].copy_from_slice(&1u32.to_le_bytes());
        h[48..56].copy_from_slice(&8u64.to_le_bytes());
        h[56..64].copy_from_slice(&24u64.to_le_bytes());
        shdrs.extend(h);
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(&strtab_name.to_le_bytes());
        h[4..8].copy_from_slice(&3u32.to_le_bytes());
        h[24..32].copy_from_slice(&strtab_off.to_le_bytes());
        h[32..40].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
        h[48..56].copy_from_slice(&1u64.to_le_bytes());
        shdrs.extend(h);
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(&shstrtab_name.to_le_bytes());
        h[4..8].copy_from_slice(&3u32.to_le_bytes());
        h[24..32].copy_from_slice(&shstrtab_off.to_le_bytes());
        h[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
        h[48..56].copy_from_slice(&1u64.to_le_bytes());
        shdrs.extend(h);
        buf.extend(shdrs);

        let mut ehdr = vec![0u8; 64];
        ehdr[0..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 2;
        ehdr[5] = 1;
        ehdr[6] = 1;
        ehdr[16..18].copy_from_slice(&3u16.to_le_bytes());
        ehdr[18..20].copy_from_slice(&62u16.to_le_bytes());
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        ehdr[40..48].copy_from_slice(&shoff.to_le_bytes());
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes());
        ehdr[60..62].copy_from_slice(&4u16.to_le_bytes());
        ehdr[62..64].copy_from_slice(&3u16.to_le_bytes());
        buf[0..64].copy_from_slice(&ehdr);
        buf
    }

    #[test]
    fn ldd_weak_undefined_symbols_are_silent() {
        // The undefined set comes from .dynsym, the dynamic loader's
        // view: a global undefined symbol is reported exactly once (a
        // name can repeat across version references), while a weak
        // undefined symbol resolves to zero at load time and stays
        // silent, like the reference's `ldd -r`.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let elf_path = dir.path().join("libweak.so");
        let elf = craft_shlib_elf(
            false,
            None,
            Some("libweak.so"),
            &[
                ("global_undef", 1, 0, 0),
                ("global_undef", 1, 0, 0),
                ("weak_undef", 2, 0, 0),
                ("exported_sym", 1, 0, 1),
            ],
        );
        std::fs::write(&elf_path, elf).expect("write elf");
        let ldd = LddInfo::parse(&elf_path.to_string_lossy(), true);
        assert_eq!(
            ldd.undefined_symbols,
            ["global_undef"],
            "global undefined reported exactly once; weak undefined stays silent"
        );
        assert_eq!(
            ldd.defined_symbols,
            ["exported_sym"],
            "defined dynamic symbols are collected for provider resolution"
        );
    }

    #[test]
    fn ldd_undefined_symbols_ignore_symtab_only_entries() {
        // A .symtab-only undefined entry is not a dynamic reference:
        // the loader never resolves it and `ldd -r` stays silent. The
        // bogus undefined-non-weak-symbol hits in plusky/rpmcrab#467
        // came from scanning .symtab entries raw.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let elf_path = dir.path().join("libsymtab.so");
        std::fs::write(&elf_path, elf_with_undef_symbols()).expect("write elf");
        let ldd = LddInfo::parse(&elf_path.to_string_lossy(), true);
        assert!(
            ldd.undefined_symbols.is_empty(),
            "symtab-only undefined entries must not be reported: {:?}",
            ldd.undefined_symbols
        );
    }

    /// Write a crafted shlib into `dir` and return its `PkgFile`,
    /// named `/usr/lib64/<base>` inside the package.
    fn shlib_pkgfile(dir: &std::path::Path, base: &str, elf: &[u8]) -> PkgFile {
        let path = dir.join(base);
        std::fs::write(&path, elf).expect("write shlib");
        PkgFile {
            name: format!("/usr/lib64/{base}"),
            path: path.to_string_lossy().into_owned(),
            magic: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, not stripped"
                .to_string(),
            mode: 0o100755,
            ..Default::default()
        }
    }

    #[test]
    fn undefined_symbol_provided_by_needed_library_is_quiet() {
        // plusky/rpmcrab#467: the symbol is undefined in the consumer
        // but defined by a library in its DT_NEEDED closure shipped in
        // the same package (the glibc shape: libBrokenLocale NEEDs
        // libc, which defines the reported symbols), so `ldd -r`
        // stays silent. A weak undefined symbol in the consumer also
        // stays silent.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let provider = craft_shlib_elf(
            false,
            None,
            Some("libfoo.so.1"),
            &[("provided_sym", 1, 0, 1)],
        );
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("provided_sym", 1, 0, 0), ("weak_sym", 2, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![
                shlib_pkgfile(dir.path(), "libfoo.so.1", &provider),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
            ],
        );
        let results = driver_results(&pkg, &test_config());
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "provider-resolved and weak symbols must stay quiet: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_provided_transitively_is_quiet() {
        // The closure is transitive, like the loader's: the consumer
        // NEEDs libfoo, libfoo NEEDs libbaz, and libbaz defines the
        // symbol.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let baz = craft_shlib_elf(false, None, Some("libbaz.so.1"), &[("deep_sym", 1, 0, 1)]);
        let foo = craft_shlib_elf(false, Some("libbaz.so.1"), Some("libfoo.so.1"), &[]);
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("deep_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![
                shlib_pkgfile(dir.path(), "libbaz.so.1", &baz),
                shlib_pkgfile(dir.path(), "libfoo.so.1", &foo),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
            ],
        );
        let results = driver_results(&pkg, &test_config());
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "transitively provided symbols must stay quiet: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_defined_by_nobody_still_fires() {
        // The true-positive shape the check exists for: a symbol no
        // library in the package defines -- whether the DT_NEEDED
        // provider is present but does not define it, or the provider
        // is absent from the package entirely.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let provider = craft_shlib_elf(false, None, Some("libfoo.so.1"), &[("other_sym", 1, 0, 1)]);
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("missing_sym", 1, 0, 0)],
        );
        let orphan = craft_shlib_elf(
            false,
            Some("libabsent.so.9"),
            Some("libqux.so.1"),
            &[("orphan_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![
                shlib_pkgfile(dir.path(), "libfoo.so.1", &provider),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
                shlib_pkgfile(dir.path(), "libqux.so.1", &orphan),
            ],
        );
        let results = driver_results(&pkg, &test_config());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            2,
            "both unresolvable symbols fire: {results:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("libbar.so.1") && l.contains("missing_sym")),
            "consumer finding names file and symbol: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("libqux.so.1") && l.contains("orphan_sym")),
            "orphan finding names file and symbol: {lines:?}"
        );
        assert!(
            lines.iter().all(|l| l.contains(" W: ")),
            "Warning level (temporary levelling pending #701): {lines:?}"
        );
    }

    #[test]
    fn undefined_symbol_provided_via_absolute_needed_is_quiet() {
        // plusky/rpmcrab#469 review: a DT_NEEDED entry can be a
        // path, not a name (`/opt/libfoo.so.1` -- some upstreams
        // link that way). Providers are indexed by SONAME and file
        // basename, so the lookup must fall back to the NEED's
        // basename: the package ships libfoo.so.1, whose SONAME
        // defines the symbol, and `ldd -r` stays silent.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let provider = craft_shlib_elf(
            false,
            None,
            Some("libfoo.so.1"),
            &[("provided_sym", 1, 0, 1)],
        );
        let consumer = craft_shlib_elf(
            false,
            Some("/opt/libfoo.so.1"),
            Some("libbar.so.1"),
            &[("provided_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![
                shlib_pkgfile(dir.path(), "libfoo.so.1", &provider),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
            ],
        );
        let results = driver_results(&pkg, &test_config());
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "absolute-NEED provider in the same package must resolve: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_via_absolute_needed_unresolved_still_fires() {
        // The basename fallback must not turn path NEEDs into a
        // blanket allowance: a symbol the basename-matched provider
        // does not define still fires, and so does a path NEED whose
        // provider is in no package at all.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let provider = craft_shlib_elf(false, None, Some("libfoo.so.1"), &[("other_sym", 1, 0, 1)]);
        let consumer = craft_shlib_elf(
            false,
            Some("/opt/libfoo.so.1"),
            Some("libbar.so.1"),
            &[("missing_sym", 1, 0, 0)],
        );
        let orphan = craft_shlib_elf(
            false,
            Some("/opt/libabsent.so.9"),
            Some("libqux.so.1"),
            &[("orphan_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![
                shlib_pkgfile(dir.path(), "libfoo.so.1", &provider),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
                shlib_pkgfile(dir.path(), "libqux.so.1", &orphan),
            ],
        );
        let results = driver_results(&pkg, &test_config());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            2,
            "both unresolvable absolute-NEED symbols fire: {results:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("libbar.so.1") && l.contains("missing_sym")),
            "consumer finding names file and symbol: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("libqux.so.1") && l.contains("orphan_sym")),
            "orphan finding names file and symbol: {lines:?}"
        );
    }

    /// Run the full driver with the check's system-library fallback
    /// pointed at fixture roots instead of the (empty) test default.
    fn driver_results_with_system(
        pkg: &Pkg,
        config: &Config,
        system: SystemLibraries,
    ) -> Vec<(String, String)> {
        let mut check = BinariesCheck::with_tool_dir(config, None);
        check.system_libraries = system;
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        check.check_binary(pkg, config, &mut out);
        out.results().to_vec()
    }

    /// Write a crafted shlib as a "system" library: a plain file
    /// named by its SONAME inside the fixture root.
    fn write_system_lib(dir: &std::path::Path, soname: &str, elf: &[u8]) {
        std::fs::write(dir.join(soname), elf).expect("write system lib");
    }

    #[test]
    fn undefined_symbol_provided_by_system_library_is_quiet() {
        // plusky/rpmcrab#467, system fallback: the consumer's
        // DT_NEEDED provider is not in the package at all (the java /
        // rust shape: libc & friends live in another package), but
        // the system rpmcrab runs on has it, and it defines the
        // symbol -- the reference's `ldd -r` stays silent, so do we.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let syslib = craft_shlib_elf(
            false,
            None,
            Some("libsys.so.1"),
            &[("sys_sym", 1, 0, 1), ("sys_sym2", 1, 0, 1)],
        );
        write_system_lib(&sysroot, "libsys.so.1", &syslib);
        let consumer = craft_shlib_elf(
            false,
            Some("libsys.so.1"),
            Some("libbar.so.1"),
            &[("sys_sym", 1, 0, 0), ("sys_sym2", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let system = SystemLibraries::with_roots(vec![sysroot], None);
        let results = driver_results_with_system(&pkg, &test_config(), system);
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "system-provided symbols must stay quiet: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_provided_by_system_transitively_is_quiet() {
        // The system side of the closure is transitive too: the
        // consumer NEEDs libsys1, libsys1 NEEDs libsys2, libsys2
        // defines the symbol.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let sys2 = craft_shlib_elf(
            false,
            None,
            Some("libsys2.so.1"),
            &[("deep_sys_sym", 1, 0, 1)],
        );
        let sys1 = craft_shlib_elf(false, Some("libsys2.so.1"), Some("libsys1.so.1"), &[]);
        write_system_lib(&sysroot, "libsys2.so.1", &sys2);
        write_system_lib(&sysroot, "libsys1.so.1", &sys1);
        let consumer = craft_shlib_elf(
            false,
            Some("libsys1.so.1"),
            Some("libbar.so.1"),
            &[("deep_sys_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let system = SystemLibraries::with_roots(vec![sysroot], None);
        let results = driver_results_with_system(&pkg, &test_config(), system);
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "transitively system-provided symbols must stay quiet: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_missing_from_system_provider_still_fires() {
        // Resolution reads the system provider's real symbol table:
        // a provider that does not define the symbol satisfies
        // nothing, exactly like a package provider that does not.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let syslib = craft_shlib_elf(false, None, Some("libsys.so.1"), &[("other_sym", 1, 0, 1)]);
        write_system_lib(&sysroot, "libsys.so.1", &syslib);
        let consumer = craft_shlib_elf(
            false,
            Some("libsys.so.1"),
            Some("libbar.so.1"),
            &[("missing_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let system = SystemLibraries::with_roots(vec![sysroot], None);
        let results = driver_results_with_system(&pkg, &test_config(), system);
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 1, "the unprovided symbol fires: {results:?}");
        assert!(
            lines[0].contains("libbar.so.1") && lines[0].contains("missing_sym"),
            "finding names file and symbol: {lines:?}"
        );
    }

    #[test]
    fn undefined_symbol_without_system_roots_still_fires() {
        // With no system roots the fallback is inert and behaviour
        // is exactly the package-only resolution: a symbol whose
        // only provider would be a system library keeps firing.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let consumer = craft_shlib_elf(
            false,
            Some("libsys.so.1"),
            Some("libbar.so.1"),
            &[("sys_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 1, "no system, no resolution: {results:?}");
        assert!(
            lines[0].contains("sys_sym"),
            "finding names the symbol: {lines:?}"
        );
    }

    #[test]
    fn undefined_symbol_provided_by_system_at_absolute_path_is_quiet() {
        // plusky/rpmcrab#469 review: a DT_NEEDED entry containing a
        // slash is a path for the loader -- it loads that exact file
        // and never searches the library directories by name. The
        // system fallback must do the same: take the file at the
        // NEED's own path, even though it sits in none of the
        // configured search roots.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let optdir = dir.path().join("opt");
        std::fs::create_dir(&optdir).expect("mkdir opt");
        let syslib = craft_shlib_elf(
            false,
            None,
            Some("libfoo.so.1"),
            &[("provided_sym", 1, 0, 1)],
        );
        std::fs::write(optdir.join("libfoo.so.1"), &syslib).expect("write system lib");
        let need = optdir.join("libfoo.so.1").to_string_lossy().into_owned();
        let consumer = craft_shlib_elf(
            false,
            Some(need.as_str()),
            Some("libbar.so.1"),
            &[("provided_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let system = SystemLibraries::with_roots(vec![dir.path().join("elsewhere")], None);
        let results = driver_results_with_system(&pkg, &test_config(), system);
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "system library at the NEED's absolute path must resolve: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_provided_by_system_via_absolute_needed_basename_is_quiet() {
        // Companion to the absolute-path system case: the NEED is
        // spelled as a path (`/opt/libsys.so.1`) but no file exists
        // at that path on the system rpmcrab runs on; the system
        // does ship the library under its basename in a search
        // directory. `locate` must fall back to the basename there,
        // not give up because the exact NEED string names no file
        // in any root.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let syslib = craft_shlib_elf(false, None, Some("libsys.so.1"), &[("sys_sym", 1, 0, 1)]);
        write_system_lib(&sysroot, "libsys.so.1", &syslib);
        let consumer = craft_shlib_elf(
            false,
            Some("/opt/libsys.so.1"),
            Some("libbar.so.1"),
            &[("sys_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let system = SystemLibraries::with_roots(vec![sysroot], None);
        let results = driver_results_with_system(&pkg, &test_config(), system);
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "system provider found by the NEED's basename must resolve: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_provided_via_runpath_is_quiet() {
        // plusky/rpmcrab#504, the GHC shape: the provider lives in
        // a private directory named only by the consumer's
        // DT_RUNPATH. The reference's `ldd -r` honours RUNPATH, so
        // the symbol resolves even though the provider is neither
        // in the package nor in any system search root (the system
        // seam here is empty).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let privdir = dir.path().join("private");
        std::fs::create_dir(&privdir).expect("mkdir private");
        let provider = craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("priv_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libpriv.so.1"), &provider).expect("write provider");
        let runpath = privdir.to_string_lossy().into_owned();
        let consumer = craft_shlib_elf_paths(
            false,
            &["libpriv.so.1"],
            Some("libbar.so.1"),
            None,
            Some(runpath.as_str()),
            &[("priv_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "RUNPATH-located provider must resolve: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_provided_via_origin_runpath_is_quiet() {
        // `$ORIGIN` in a RUNPATH expands to the consumer's
        // installed directory: the provider sits in a private
        // subdirectory of it.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let libdir = dir.path().join("ghc").join("lib");
        let privdir = libdir.join("private");
        std::fs::create_dir_all(&privdir).expect("mkdir private");
        let provider = craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("priv_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libpriv.so.1"), &provider).expect("write provider");
        let consumer = craft_shlib_elf_paths(
            false,
            &["libpriv.so.1"],
            Some("libpoly.so"),
            None,
            Some("$ORIGIN/private"),
            &[("priv_sym", 1, 0, 0)],
        );
        let consumer_path = libdir.join("libpoly.so");
        std::fs::write(&consumer_path, &consumer).expect("write consumer");
        let pkgfile = PkgFile {
            name: consumer_path.to_string_lossy().into_owned(),
            path: consumer_path.to_string_lossy().into_owned(),
            magic: "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, not stripped"
                .to_string(),
            mode: 0o100755,
            ..Default::default()
        };
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![pkgfile]);
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "$ORIGIN-relative RUNPATH provider must resolve: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_missing_from_runpath_provider_still_fires() {
        // A RUNPATH-located provider that does not define the
        // symbol satisfies nothing: resolution reads its real
        // symbol table, like every other provider source.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let privdir = dir.path().join("private");
        std::fs::create_dir(&privdir).expect("mkdir private");
        let provider =
            craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("other_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libpriv.so.1"), &provider).expect("write provider");
        let runpath = privdir.to_string_lossy().into_owned();
        let consumer = craft_shlib_elf_paths(
            false,
            &["libpriv.so.1"],
            Some("libbar.so.1"),
            None,
            Some(runpath.as_str()),
            &[("missing_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 1, "the unprovided symbol fires: {results:?}");
        assert!(
            lines[0].contains("missing_sym"),
            "finding names the symbol: {lines:?}"
        );
    }

    #[test]
    fn undefined_symbol_in_wrong_runpath_dir_still_fires() {
        // The provider exists on the system but not in the
        // directory the RUNPATH names (nor anywhere else the
        // resolver searches): location is by directory, not by
        // name anywhere on disk.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let wrongdir = dir.path().join("wrong");
        let realdir = dir.path().join("real");
        std::fs::create_dir(&wrongdir).expect("mkdir wrong");
        std::fs::create_dir(&realdir).expect("mkdir real");
        let provider = craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("priv_sym", 1, 0, 1)]);
        std::fs::write(realdir.join("libpriv.so.1"), &provider).expect("write provider");
        let runpath = wrongdir.to_string_lossy().into_owned();
        let consumer = craft_shlib_elf_paths(
            false,
            &["libpriv.so.1"],
            Some("libbar.so.1"),
            None,
            Some(runpath.as_str()),
            &[("priv_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "provider outside the RUNPATH dir must not resolve: {results:?}"
        );
    }

    /// The RPATH/RUNPATH transitivity fixture: the consumer NEEDs
    /// libmid (in the system root), libmid NEEDs libleaf, and
    /// libleaf -- which lives only in `privdir` -- defines the
    /// consumer's undefined symbol. Whether the symbol resolves
    /// depends entirely on how the consumer's search path reaches
    /// libmid's own dependency.
    fn rpath_transitivity_results(rpath: bool) -> Vec<(String, String)> {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        let privdir = dir.path().join("private");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        std::fs::create_dir(&privdir).expect("mkdir private");
        let leaf = craft_shlib_elf(false, None, Some("libleaf.so.1"), &[("leaf_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libleaf.so.1"), &leaf).expect("write leaf");
        let mid = craft_shlib_elf(false, Some("libleaf.so.1"), Some("libmid.so.1"), &[]);
        write_system_lib(&sysroot, "libmid.so.1", &mid);
        let priv_s = privdir.to_string_lossy().into_owned();
        let (rpath, runpath) = if rpath {
            (Some(priv_s.as_str()), None)
        } else {
            (None, Some(priv_s.as_str()))
        };
        let consumer = craft_shlib_elf_paths(
            false,
            &["libmid.so.1"],
            Some("libbar.so.1"),
            rpath,
            runpath,
            &[("leaf_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let system = SystemLibraries::with_roots(vec![sysroot], None);
        driver_results_with_system(&pkg, &test_config(), system)
    }

    #[test]
    fn undefined_symbol_provided_via_rpath_transitively_is_quiet() {
        // DT_RPATH (with no DT_RUNPATH) is transitive: it also
        // locates the dependencies of the consumer's dependencies.
        let results = rpath_transitivity_results(true);
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "RPATH must reach the transitive provider: {results:?}"
        );
    }

    #[test]
    fn undefined_symbol_via_runpath_is_not_transitive() {
        // DT_RUNPATH locates only the needing object's own
        // entries: libmid's dependency on libleaf is not searched
        // in the consumer's RUNPATH, so the symbol keeps firing.
        let results = rpath_transitivity_results(false);
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "RUNPATH must not reach the transitive provider: {results:?}"
        );
        assert!(
            lines[0].contains("leaf_sym"),
            "finding names the symbol: {lines:?}"
        );
    }

    #[test]
    fn rpath_is_ignored_when_runpath_is_present() {
        // The loader ignores DT_RPATH entirely when the object
        // also carries DT_RUNPATH: the provider sits in the RPATH
        // directory, the RUNPATH directory is empty, so the
        // symbol keeps firing.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let privdir = dir.path().join("private");
        let emptydir = dir.path().join("empty");
        std::fs::create_dir(&privdir).expect("mkdir private");
        std::fs::create_dir(&emptydir).expect("mkdir empty");
        let provider = craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("priv_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libpriv.so.1"), &provider).expect("write provider");
        let priv_s = privdir.to_string_lossy().into_owned();
        let empty_s = emptydir.to_string_lossy().into_owned();
        let consumer = craft_shlib_elf_paths(
            false,
            &["libpriv.so.1"],
            Some("libbar.so.1"),
            Some(priv_s.as_str()),
            Some(empty_s.as_str()),
            &[("priv_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "DT_RPATH must be ignored next to DT_RUNPATH: {results:?}"
        );
    }

    #[test]
    fn rpath_is_ignored_when_runpath_is_empty() {
        // An empty DT_RUNPATH still counts as present: the linker
        // emits empty RUNPATH values, and ld.so suppresses DT_RPATH
        // on the tag's presence, not its content. Same shape as
        // `rpath_is_ignored_when_runpath_is_present`, except the
        // RUNPATH value is empty, so no segment survives parsing --
        // the RPATH directory must stay unsearched and the symbol
        // must keep firing.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let privdir = dir.path().join("private");
        std::fs::create_dir(&privdir).expect("mkdir private");
        let provider = craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("priv_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libpriv.so.1"), &provider).expect("write provider");
        let priv_s = privdir.to_string_lossy().into_owned();
        let consumer = craft_shlib_elf_paths(
            false,
            &["libpriv.so.1"],
            Some("libbar.so.1"),
            Some(priv_s.as_str()),
            Some(""),
            &[("priv_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "empty DT_RUNPATH must still suppress DT_RPATH: {results:?}"
        );
        assert!(
            lines[0].contains("priv_sym"),
            "finding names the symbol: {lines:?}"
        );
    }

    #[test]
    fn relative_search_path_entries_are_dropped() {
        // A relative RPATH/RUNPATH entry is relative to the
        // loader's working directory, which the resolver does not
        // model. It must be dropped before normalisation, never
        // turned into a host-absolute path that is then searched
        // on the host (`lib` must not become `/lib`).
        let origin = Path::new("/opt/pkg/lib");
        let dropped: Vec<PathBuf> = expand_search_dirs(
            &[
                "lib".to_string(),
                "./lib".to_string(),
                "../lib".to_string(),
                "lib/../lib".to_string(),
                String::new(),
            ],
            origin,
        );
        assert!(dropped.is_empty(), "relative entries dropped: {dropped:?}");
        let kept = expand_search_dirs(
            &[
                "/a/b/../c".to_string(),
                "$ORIGIN/private".to_string(),
                "${ORIGIN}/../shared".to_string(),
                "relative".to_string(),
            ],
            origin,
        );
        assert_eq!(
            kept,
            vec![
                PathBuf::from("/a/c"),
                PathBuf::from("/opt/pkg/lib/private"),
                PathBuf::from("/opt/pkg/shared"),
            ],
            "absolute and $ORIGIN entries kept, normalised: {kept:?}"
        );
        // The gate behind the empty-RUNPATH fix, pinned directly:
        // with a DT_RUNPATH tag present the object's own RPATH list
        // contributes nothing to the chain, however empty the
        // RUNPATH value was; without the tag it does.
        let rpath = vec!["/real/dir".to_string()];
        let gated = SearchContext::for_object(&rpath, &[], true, Path::new("/"), &[]);
        assert!(
            gated.rpath_chain.is_empty(),
            "has_runpath must gate the RPATH chain: {:?}",
            gated.rpath_chain
        );
        let ungated = SearchContext::for_object(&rpath, &[], false, Path::new("/"), &[]);
        assert_eq!(
            ungated.rpath_chain,
            vec![vec![PathBuf::from("/real/dir")]],
            "no RUNPATH tag: RPATH chain present"
        );
    }

    #[test]
    fn undefined_symbol_with_relative_rpath_still_fires() {
        // End-to-end companion to the unit pin above: a consumer
        // whose only search path is the relative entry `lib`,
        // NEEDing a library the host populates under `/lib`. The
        // loader searches the working directory's `lib`, finds
        // nothing there, and reports the symbol; searching the
        // host's `/lib` instead would wrongly silence it on hosts
        // where that library exists.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let consumer = craft_shlib_elf_paths(
            false,
            &["libc.so.6"],
            Some("libbar.so.1"),
            Some("lib"),
            None,
            &[("strlen", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "relative RPATH must not resolve against the host: {results:?}"
        );
        assert!(
            lines[0].contains("strlen"),
            "finding names the symbol: {lines:?}"
        );
    }

    #[test]
    fn runpath_is_used_when_rpath_is_also_present() {
        // Companion: with both tags present the RUNPATH directory
        // is searched (and the empty RPATH directory is not).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let privdir = dir.path().join("private");
        let emptydir = dir.path().join("empty");
        std::fs::create_dir(&privdir).expect("mkdir private");
        std::fs::create_dir(&emptydir).expect("mkdir empty");
        let provider = craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("priv_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libpriv.so.1"), &provider).expect("write provider");
        let priv_s = privdir.to_string_lossy().into_owned();
        let empty_s = emptydir.to_string_lossy().into_owned();
        let consumer = craft_shlib_elf_paths(
            false,
            &["libpriv.so.1"],
            Some("libbar.so.1"),
            Some(empty_s.as_str()),
            Some(priv_s.as_str()),
            &[("priv_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let results = driver_results_with_system(&pkg, &test_config(), SystemLibraries::empty());
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "DT_RUNPATH must be searched when both tags exist: {results:?}"
        );
    }

    #[test]
    fn runpath_located_provider_joins_closure_with_its_needs() {
        // A provider located via RUNPATH joins the closure like
        // any other: its own DT_NEEDED entries resolve in turn
        // (here through the system root).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        let privdir = dir.path().join("private");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        std::fs::create_dir(&privdir).expect("mkdir private");
        let deep = craft_shlib_elf(false, None, Some("libdeep.so.1"), &[("deep_sym", 1, 0, 1)]);
        write_system_lib(&sysroot, "libdeep.so.1", &deep);
        let mid = craft_shlib_elf(false, Some("libdeep.so.1"), Some("libmid.so.1"), &[]);
        std::fs::write(privdir.join("libmid.so.1"), &mid).expect("write mid");
        let runpath = privdir.to_string_lossy().into_owned();
        let consumer = craft_shlib_elf_paths(
            false,
            &["libmid.so.1"],
            Some("libbar.so.1"),
            None,
            Some(runpath.as_str()),
            &[("deep_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let system = SystemLibraries::with_roots(vec![sysroot], None);
        let results = driver_results_with_system(&pkg, &test_config(), system);
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "RUNPATH provider's own closure must resolve: {results:?}"
        );
    }

    #[test]
    fn dir_provider_searches_only_the_given_dirs() {
        // `provider_in_dirs` is scoped to its directory list and
        // class-matches like the system lookup; slash-carrying
        // names are direct paths and never directory-searched.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let privdir = dir.path().join("private");
        std::fs::create_dir(&privdir).expect("mkdir private");
        let provider = craft_shlib_elf(false, None, Some("libpriv.so.1"), &[("priv_sym", 1, 0, 1)]);
        std::fs::write(privdir.join("libpriv.so.1"), &provider).expect("write provider");
        let system = SystemLibraries::empty();
        assert!(
            system
                .provider_in_dirs("libpriv.so.1", Some(true), std::slice::from_ref(&privdir))
                .is_some(),
            "provider found in the given dir"
        );
        assert!(
            system
                .provider_in_dirs("libpriv.so.1", Some(false), std::slice::from_ref(&privdir))
                .is_none(),
            "32-bit consumer must not resolve against the 64-bit library"
        );
        assert!(
            system
                .provider_in_dirs("libpriv.so.1", Some(true), &[dir.path().join("elsewhere")])
                .is_none(),
            "no provider outside the given dirs"
        );
        assert!(
            system
                .provider_in_dirs("libabsent.so.9", Some(true), std::slice::from_ref(&privdir))
                .is_none(),
            "absent SONAME has no provider"
        );
        assert!(
            system
                .provider_in_dirs("/abs/libpriv.so.1", Some(true), &[privdir])
                .is_none(),
            "slash names are not directory-searched"
        );
    }

    #[test]
    fn system_provider_finds_direct_path_without_search_roots() {
        // A direct-path NEED is honoured by `locate` itself, with
        // no search directory to accidentally supply it through
        // `dir.join` discarding the directory for absolute paths:
        // with no roots at all, the file at the NEED's own path is
        // still the provider.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let syslib = craft_shlib_elf(false, None, Some("libsys.so.1"), &[("sys_sym", 1, 0, 1)]);
        write_system_lib(dir.path(), "libsys.so.1", &syslib);
        let need = dir
            .path()
            .join("libsys.so.1")
            .to_string_lossy()
            .into_owned();
        let system = SystemLibraries::with_roots(Vec::new(), None);
        assert!(
            system.provider(&need, Some(true)).is_some(),
            "direct path resolves with no search roots"
        );
        assert!(
            system
                .provider("/nonexistent/libsys.so.1", Some(true))
                .is_none(),
            "a direct path naming no file has no provider"
        );
    }

    #[test]
    fn system_provider_matches_elf_class() {
        // A provider of the wrong ELF class is not a provider: the
        // loader would not load it for this consumer either.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let syslib = craft_shlib_elf(false, None, Some("libsys.so.1"), &[("sys_sym", 1, 0, 1)]);
        write_system_lib(dir.path(), "libsys.so.1", &syslib);
        let system = SystemLibraries::with_roots(vec![dir.path().to_path_buf()], None);
        // The crafted libraries are 64-bit.
        assert!(
            system.provider("libsys.so.1", Some(true)).is_some(),
            "64-bit consumer finds the 64-bit provider"
        );
        assert!(
            system.provider("libsys.so.1", Some(false)).is_none(),
            "32-bit consumer must not resolve against the 64-bit library"
        );
        assert!(
            system.provider("libabsent.so.9", Some(true)).is_none(),
            "absent SONAME has no provider"
        );
    }

    #[test]
    fn ld_so_cache_parses_both_layouts() {
        // Build minimal cache images: header, entries, then the
        // strings the entries point at.
        let build = |new: bool| -> Vec<u8> {
            let (header, entry) = if new { (48usize, 24usize) } else { (32, 12) };
            let strings: Vec<&str> = vec![
                "libfoo.so.1",
                "/usr/lib64/libfoo.so.1",
                "libc.so.6",
                "/lib64/libc.so.6",
            ];
            let strtab = header + 2 * entry;
            let mut offsets = Vec::new();
            let mut blob: Vec<u8> = Vec::new();
            for s in &strings {
                offsets.push(blob.len());
                blob.extend_from_slice(s.as_bytes());
                blob.push(0);
            }
            let mut img = vec![0u8; strtab];
            img[0..17].copy_from_slice(b"glibc-ld.so.cache");
            img[17..20].copy_from_slice(b"1.1");
            img[20..24].copy_from_slice(&2u32.to_le_bytes());
            img[24..28].copy_from_slice(&(blob.len() as u32).to_le_bytes());
            for (i, (k, v)) in [(0, 1), (2, 3)].iter().enumerate() {
                let at = header + i * entry;
                let (ko, vo) = if new {
                    (strtab + offsets[*k], strtab + offsets[*v])
                } else {
                    (offsets[*k], offsets[*v])
                };
                img[at + 4..at + 8].copy_from_slice(&(ko as u32).to_le_bytes());
                img[at + 8..at + 12].copy_from_slice(&(vo as u32).to_le_bytes());
            }
            img.extend_from_slice(&blob);
            img
        };
        for new in [true, false] {
            let map = parse_ld_so_cache(&build(new)).expect("cache parses");
            assert_eq!(
                map.get("libfoo.so.1").map(Vec::as_slice),
                Some([PathBuf::from("/usr/lib64/libfoo.so.1")].as_slice()),
                "layout new={new}"
            );
            assert_eq!(
                map.get("libc.so.6").map(Vec::as_slice),
                Some([PathBuf::from("/lib64/libc.so.6")].as_slice()),
                "layout new={new}"
            );
        }
        // Garbage and truncations are "no cache", never a panic.
        assert!(parse_ld_so_cache(b"not a cache at all").is_none());
        assert!(parse_ld_so_cache(&build(true)[..40]).is_none());
    }

    #[test]
    fn undefined_non_weak_symbol() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_dynamically_linked = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.so.1", "ELF 64-bit LSB shared object");
        let mut ldd = syn_ldd();
        ldd.undefined_symbols = vec!["GSS_C_NT_HOSTBASED_SERVICE".to_string()];

        // Undefined symbols in a shared object -> Warning
        // (temporary levelling pending the #701 resolver fix).
        let mut info = syn_info();
        info.is_shlib = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_dependency(&pkg, &pkgfile, &info, &ldd, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("GSS_C_NT_HOSTBASED_SERVICE"),
            "detail names the symbol: {}",
            lines[0]
        );

        // The same undefined symbols in a plain executable stay quiet:
        // they resolve at load time, so the reference's `ldd -r` never
        // reports them (this fired hundreds of bogus hits, e.g. on
        // amberol's /usr/bin/amberol).
        let info = syn_info();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_dependency(&pkg, &pkgfile, &info, &ldd, &mut out);
        let results = out.results().to_vec();
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "executable must stay quiet: {results:?}"
        );

        // Not dynamically linked -> quiet.
        check.is_dynamically_linked = false;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_dependency(&pkg, &pkgfile, &info, &ldd, &mut out);
        assert!(
            out.results().is_empty(),
            "must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn linked_against_opt_library() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_dynamically_linked = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/bin/opt-dependency", "ELF 64-bit LSB executable");
        let mut ldd = syn_ldd();
        ldd.dependencies = vec!["/opt/libfoo.so".to_string()];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency_location(&pkg, &pkgfile, &ldd, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "linked-against-opt-library");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("/bin/opt-dependency") && lines[0].contains("/opt/libfoo.so"),
            "detail names file and dependency: {}",
            lines[0]
        );
    }

    #[test]
    fn linked_against_usr_library() {
        // Reference test_ldd_parser.py:109: a /bin binary linked against
        // /usr/libfoo.so warns.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_dynamically_linked = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/bin/usr-dependency", "ELF 64-bit LSB executable");
        let mut ldd = syn_ldd();
        ldd.dependencies = vec!["/usr/libfoo.so".to_string()];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency_location(&pkg, &pkgfile, &ldd, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "linked-against-usr-library");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("/bin/usr-dependency") && lines[0].contains("/usr/libfoo.so"),
            "detail names file and dependency: {}",
            lines[0]
        );

        // A binary outside /bin//lib//sbin is not subject to the check.
        let pkgfile = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency_location(&pkg, &pkgfile, &ldd, &mut out);
        assert!(
            out.results().is_empty(),
            "must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn security_function_findings() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);

        // mktemp -> Error.
        let mut info = syn_info();
        info.functions = vec!["mktemp".to_string()];
        let pkgfile = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "call-to-mktemp");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(lines[0].contains("/usr/bin/foo"), "detail: {}", lines[0]);

        // gethostbyname -> Warning.
        let mut info = syn_info();
        info.functions = vec!["gethostbyname".to_string()];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "binary-or-shlib-calls-gethostbyname");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // setuid+setgid without setgroups: Error with or without
        // the setuid bit (#593).
        let mut info = syn_info();
        info.functions = vec!["setuid".to_string(), "setgid".to_string()];
        let mut pkgfile = syn_file("/usr/bin/setuidbin", "ELF 64-bit LSB executable");
        pkgfile.mode = 0o104755;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "missing-call-to-setgroups-before-setuid");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);

        pkgfile.mode = 0o100755;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "missing-call-to-setgroups-before-setuid");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);

        // Calling setgroups silences the finding.
        let mut info = syn_info();
        info.functions = vec![
            "setuid".to_string(),
            "setgid".to_string(),
            "setgroups".to_string(),
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "setgroups present must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn forbidden_function_crypto_policy() {
        // Reference warn-on-functions.toml: the finding fires on a bare
        // SSL_CTX_set_cipher_list call, and is waived when the strings
        // output shows the PROFILE=SYSTEM good_param.
        let config = config_with(
            "[WarnOnFunction.crypto-policy-non-compliance-openssl]\n\
             f_name = \"SSL_CTX_set_cipher_list\"\n\
             good_param = \"PROFILE=SYSTEM\"\n",
        );
        let (_tmp, tool_dir) = fake_tool_dir("strings", "echo symbol-table-dump");
        let check = BinariesCheck::with_tool_dir(&config, Some(&tool_dir));
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/openssl-app", "ELF 64-bit LSB executable");
        let mut info = syn_info();
        info.functions = vec!["SSL_CTX_set_cipher_list".to_string()];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_forbidden_functions(&pkg, &pkgfile, &info, &config, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "crypto-policy-non-compliance-openssl");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        assert!(
            lines[0].contains("SSL_CTX_set_cipher_list"),
            "detail names the function: {}",
            lines[0]
        );

        // The good_param in the strings output waives the finding.
        let (_tmp, tool_dir) = fake_tool_dir("strings", "echo PROFILE=SYSTEM");
        let check = BinariesCheck::with_tool_dir(&config, Some(&tool_dir));
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_forbidden_functions(&pkg, &pkgfile, &info, &config, &mut out);
        assert!(
            out.results().is_empty(),
            "waived call must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn ldd_failed_is_unreachable_on_parseable_elf() {
        // ReadelfInfo::parse and LddInfo::parse fail on exactly the same
        // inputs (both read the file and run goblin over it), so
        // readelf-failed always fires first: ldd-failed has no reachable
        // emission in the port. Pin the negative on a parseable ELF.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let elf_path = dir.path().join("libok.so");
        std::fs::write(&elf_path, parseable_elf()).expect("write elf");
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_dynamically_linked = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: "/usr/lib64/libok.so".to_string(),
            path: elf_path.to_string_lossy().into_owned(),
            magic: "ELF 64-bit LSB shared object, x86-64, dynamically linked".to_string(),
            mode: 0o100755,
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let analysis =
            ElfAnalysis::wants_analysis(&pkgfile, false).then(|| ElfAnalysis::parse(&pkgfile));
        check.run_elf_checks(&pkg, &pkgfile, &config, &mut out, analysis.as_ref());
        let results = out.results().to_vec();
        assert_lacks(&results, "readelf-failed");
        assert_lacks(&results, "ldd-failed");
    }

    #[test]
    fn dangling_dt_gnu_hash_still_emits_hash_findings() {
        // #220 follow-up: objcopy --remove-section=.hash
        // --remove-section=.gnu.hash leaves the DT_GNU_HASH dynamic entry
        // dangling; goblin's strict parse rejects the file, and the port
        // used to emit readelf-failed and skip the hash-section analysis
        // while the reference emits both findings. The fixture .so was built
        // and stripped on openSUSE Tumbleweed, then packaged with rpmbuild;
        // the test drives it through the full BinariesCheck.
        let rpm_path = fixture_path("rpmcrab-binaries-dangling-gnuhash-1.0-1.aarch64.rpm");
        let (results, _dir) = run_binaries_check(&rpm_path);
        assert_lacks(&results, "readelf-failed");
        assert_lacks(&results, "ldd-failed");
        let hash_lines = lines_for(&results, "missing-hash-section");
        assert_eq!(hash_lines.len(), 1, "one missing-hash-section: {results:?}");
        assert!(
            hash_lines[0].contains(" E: "),
            "missing-hash-section is Error: {}",
            hash_lines[0]
        );
        assert!(
            hash_lines[0].contains("/usr/lib64/libdangling-stripped.so.1"),
            "missing-hash-section names the stripped library: {}",
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
    }

    #[test]
    fn parallel_prepass_keeps_output_deterministic() {
        // The rayon pre-pass parallelizes parsing only; finding emission
        // stays sequential in file order. Pin the frozen-output contract
        // (#113): 1-thread and N-thread runs must produce identical
        // findings on a real fixture package.
        let rpm = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let run = |threads: usize| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("rayon pool")
                .install(|| {
                    let dir = tempfile::TempDir::new().expect("tmpdir");
                    let pkg = Pkg::open(std::path::Path::new(&rpm), dir.path(), true)
                        .expect("open fixture");
                    let config = test_config();
                    let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
                    let mut check = BinariesCheck::with_tool_dir(&config, None);
                    check.check_binary(&pkg, &config, &mut out);
                    out.results().to_vec()
                })
        };
        let single = run(1);
        let parallel = run(4);
        assert_eq!(
            single, parallel,
            "findings must be identical under 1-thread and 4-thread pre-pass"
        );
    }
    /// Negative pins for the deleted autobuild-redundant findings
    /// (`executable-in-library-package`, `non-versioned-file-in-library-package`):
    /// the fixture carries a real shared library plus an executable and an
    /// unversioned data file -- the shape that fired pre-removal -- so
    /// re-adding either emission fails here under plain `cargo test`.
    #[test]
    fn killed_library_package_findings_stay_absent() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let so_path = dir.path().join("libfoo.so");
        std::fs::write(&so_path, craft_shlib_elf(false, None, None, &[])).expect("write so");
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let mut so_file = syn_file("/usr/lib64/libfoo.so", "ELF 64-bit LSB shared object");
        so_file.path = so_path.to_str().unwrap().to_string();
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![
                so_file,
                syn_file("/usr/bin/foo", "ELF 64-bit LSB executable"),
                syn_file("/usr/lib64/README", "ASCII text"),
            ],
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_lacks(&results, "executable-in-library-package");
        assert_lacks(&results, "non-versioned-file-in-library-package");
    }
}
