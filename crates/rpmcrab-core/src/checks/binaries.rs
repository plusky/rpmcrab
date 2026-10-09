//! `BinariesCheck`: ELF binary validation, ported from rpmlint's `BinariesCheck.py`.
//!
//! Covers the reference's `add_info` call sites: ELF section/header analysis
//! via `goblin`, dependency analysis via `goblin`, DWARF producer extraction
//! via `gimli`, forbidden functions via `strings`, and archive analysis via
//! `ar`.
//!
//! Deliberate gaps are ledgered in `tests/parity/divergences.toml`.

#![allow(clippy::collapsible_if)]

use std::path::Path;

use fancy_regex::Regex;
use rayon::prelude::*;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::PkgFile;
use crate::tools::{Tool, ToolSource, test_source};
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
    /// True when the binary was produced by the Rust toolchain.
    /// Computed during parse; see `detect_rust_binary`.
    is_rust: bool,
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
    /// DF_BIND_NOW (DT_FLAGS) or DF_1_NOW (DT_FLAGS_1). Together with a
    /// GNU_RELRO segment this is the full-versus-partial RELRO distinction.
    bind_now: bool,
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
            // The reference derives is_shlib and is_debug from the file name,
            // not the ELF content (readelfparser.py). A PIE executable or Go
            // binary is ET_DYN but is not a shared library for these checks.
            is_shlib: so_regex().is_match(name).unwrap_or(false),
            is_debug: name.ends_with(".debug"),
            is_rust: false,
            soname: None,
            needed: Vec::new(),
            runpaths: Vec::new(),
            has_textrel: false,
            elf_type: goblin::elf::header::ET_NONE,
            bind_now: false,
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
        for sym in elf.dynsyms.iter() {
            if sym.st_type() == goblin::elf::sym::STT_FUNC {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        self.functions.push(name.to_string());
                    }
                }
            }
        }

        // Dynamic section
        if let Some(dynamic) = &elf.dynamic {
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
    }
    fn has_function_matching(&self, regex: &fancy_regex::Regex) -> bool {
        self.functions
            .iter()
            .any(|s| regex.is_match(s).unwrap_or(false))
    }

    /// Go toolchain output carries a `.note.go.buildid` section. Go
    /// binaries are ET_DYN with no DT_NEEDED, but they are not shared
    /// objects missing dependency information.
    fn is_go_binary(&self) -> bool {
        self.sections
            .iter()
            .flatten()
            .any(|s| s.name == ".note.go.buildid")
    }

    /// Rust toolchain output carries none of the C-hardening artifacts:
    /// `_FORTIFY_SOURCE` is a glibc C-header feature rustc does not
    /// implement, and stack-protector instrumentation is not default
    /// rustc behavior.
    fn is_rust_binary(&self) -> bool {
        self.is_rust
    }
}

/// True when the ELF was produced by the Rust toolchain. No single
/// signal survives every strip level, so several are combined:
/// `.rustc` section (only rustc emits it; gone after any strip),
/// Rust runtime symbols, `.debug_gdb_scripts` containing "rust"
/// (rustc's GDB pretty-printer hook; gone after `strip -g`), and
/// `.rodata` containing `panicked at` (rustc's panic location format,
/// which survives even a full strip). Conservative on purpose: an
/// unrecognized binary is treated as C, so a missed detection only
/// keeps the current behavior.
/// A Rust toolchain symbol: runtime entry points, never emitted for
/// C/C++ code. `_ZN` alone is not enough (Itanium C++ mangling shares
/// the prefix), so only unambiguous Rust runtime names count here.
fn is_rust_symbol(name: &str) -> bool {
    name == "rust_begin_unwind" || name == "rust_eh_personality" || name.starts_with("__rust_")
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
            if bytes.windows(4).any(|w| w.eq_ignore_ascii_case(b"rust")) {
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

        let elf = match parse_elf(&data) {
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
    /// Go binaries are skipped: the Go toolchain emits none of these
    /// C-hardening artifacts, so every finding would be noise. Rust
    /// binaries skip only the two C-compiler findings below (see
    /// `is_rust_binary`); the linker-level RELRO checks still apply.
    fn check_hardening(&self, pkg: &Pkg, pkgfile: &PkgFile, info: &ReadelfInfo, out: &mut Filter) {
        use goblin::elf::header::{ET_DYN, ET_EXEC};
        if self.is_archive || info.is_go_binary() {
            return;
        }
        if info.elf_type != ET_EXEC && info.elf_type != ET_DYN {
            return;
        }
        // Rust emits neither `_FORTIFY_SOURCE` instrumentation nor
        // default stack-protector instrumentation: both findings would
        // be noise. When in doubt the binary is treated as C.
        let is_rust = info.is_rust_binary();
        if !is_rust && !info.functions.iter().any(|s| is_fortify_symbol(s)) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "missing-fortify",
                &[&pkgfile.name],
            );
        }
        if !is_rust && !info.functions.iter().any(|s| is_stack_protector_symbol(s)) {
            add_info(
                out,
                Level::Warning,
                pkg,
                "missing-stack-protector",
                &[&pkgfile.name],
            );
        }
        let has_relro = info.program_headers.iter().any(|h| h.name == "GNU_RELRO");
        if !has_relro {
            add_info(out, Level::Warning, pkg, "missing-relro", &[&pkgfile.name]);
        } else if !info.bind_now {
            add_info(out, Level::Warning, pkg, "partial-relro", &[&pkgfile.name]);
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
        // undefined-non-weak-symbol is meaningful for shared libraries only:
        // in an executable the undefined symbols resolve at load time, so the
        // reference's `ldd -r` stays silent there while a raw UND scan fires
        // hundreds of bogus hits.
        if info.is_shlib {
            for symbol in &ldd.undefined_symbols {
                add_info(
                    out,
                    Level::Error,
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
            } else if !info.is_go_binary() {
                // Go binaries are ET_DYN with no DT_NEEDED; only genuine
                // shared objects are missing dependency information here.
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

        // Parse the expensive per-file ELF metadata in parallel (rayon).
        // Finding emission stays in the sequential loop below, in file
        // order, so the output bytes are unchanged.
        let is_noarch = pkg.arch == "noarch";
        let analyses: Vec<Option<ElfAnalysis>> = pkg
            .files
            .par_iter()
            .map(|pkgfile| {
                ElfAnalysis::wants_analysis(pkgfile, is_noarch).then(|| ElfAnalysis::parse(pkgfile))
            })
            .collect();

        for (idx, pkgfile) in pkg.files.iter().enumerate() {
            let fname: &str = &pkgfile.name;
            self.check_libtool_wrapper(pkg, fname, pkgfile, out);
            self.check_invalid_la_file(pkg, fname, pkgfile, out);

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

        self.check_no_binary(pkg, pkg_has_binary, pkg_has_file_in_lib64, out);
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
    /// marker). `needed` adds a PT_LOAD + PT_DYNAMIC pair exposing one
    /// DT_NEEDED entry, so `ReadelfInfo.needed` fills the way goblin
    /// fills it for real linked libraries.
    fn craft_shlib_elf(go_note: bool, needed: Option<&str>) -> Vec<u8> {
        const SHSTRTAB: &[u8] = b"\0.shstrtab\0.dynamic\0.dynstr\0.note.go.buildid\0";
        // SHSTRTAB name offsets: .shstrtab=1, .dynamic=11, .dynstr=20,
        // .note.go.buildid=28.
        struct Sec {
            name_off: u32,
            stype: u32,
            flags: u64,
            data: Vec<u8>,
            align: u64,
            link: u32,
        }
        let mut secs: Vec<Sec> = vec![Sec {
            name_off: 1,
            stype: 3, // SHT_STRTAB
            flags: 0,
            data: SHSTRTAB.to_vec(),
            align: 1,
            link: 0,
        }];
        if let Some(lib) = needed {
            let mut dynstr = vec![0u8];
            dynstr.extend_from_slice(lib.as_bytes());
            dynstr.push(0);
            secs.push(Sec {
                name_off: 20,
                stype: 3,
                flags: 0,
                data: dynstr,
                align: 1,
                link: 0,
            });
            // Section-header index of .dynstr (NULL entry is index 0).
            let dynstr_idx = secs.len() as u32;
            secs.push(Sec {
                name_off: 11,
                stype: 6, // SHT_DYNAMIC
                flags: 2, // SHF_ALLOC
                data: vec![0u8; 64],
                align: 8,
                link: dynstr_idx,
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
            });
        }

        let mut buf: Vec<u8> = vec![0; 64]; // ELF header placeholder
        let phnum: u16 = if needed.is_some() { 2 } else { 0 };
        let phoff = buf.len() as u64;
        buf.extend(vec![0u8; 56 * phnum as usize]);

        // Section data blobs, in section order.
        let mut offs: Vec<u64> = Vec::new();
        for s in &secs {
            offs.push(buf.len() as u64);
            buf.extend(&s.data);
        }

        // Patch .dynamic now that the .dynstr file offset is known.
        if needed.is_some() {
            let dyn_i = secs.iter().position(|s| s.name_off == 11).unwrap();
            let str_i = secs.iter().position(|s| s.name_off == 20).unwrap();
            let mut dyns: Vec<u8> = Vec::new();
            let mut entry = |tag: i64, val: u64| {
                dyns.extend_from_slice(&tag.to_le_bytes());
                dyns.extend_from_slice(&val.to_le_bytes());
            };
            entry(1, 1); // DT_NEEDED -> dynstr[1]
            entry(5, offs[str_i]); // DT_STRTAB
            entry(10, secs[str_i].data.len() as u64); // DT_STRSZ
            entry(0, 0); // DT_NULL
            let at = offs[dyn_i] as usize;
            buf[at..at + 64].copy_from_slice(&dyns);
        }

        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        let shoff = buf.len() as u64;
        let shnum = secs.len() + 1;
        let total = shoff + 64 * shnum as u64;

        // Program headers. PT_LOAD covers the whole file so goblin's
        // vm_to_offset resolves DT_STRTAB to a file offset.
        if needed.is_some() {
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
            let dyn_i = secs.iter().position(|s| s.name_off == 11).unwrap();
            let load = ph(1, 5, 0, total);
            let dynamic = ph(2, 6, offs[dyn_i], 64);
            let at = phoff as usize;
            buf[at..at + 56].copy_from_slice(&load);
            buf[at + 56..at + 112].copy_from_slice(&dynamic);
        }

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
            h[48..56].copy_from_slice(&s.align.to_le_bytes());
            if s.stype == 6 {
                h[56..64].copy_from_slice(&16u64.to_le_bytes());
            }
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
        ehdr[56..58].copy_from_slice(&phnum.to_le_bytes());
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes());
        ehdr[60..62].copy_from_slice(&(shnum as u16).to_le_bytes());
        ehdr[62..64].copy_from_slice(&1u16.to_le_bytes()); // .shstrtab
        buf[0..64].copy_from_slice(&ehdr);
        buf
    }

    fn shlib_libdep_results(
        go_note: bool,
        needed: Option<&str>,
        is_shobj: bool,
    ) -> Vec<(String, String)> {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = is_shobj;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: "/usr/lib64/libnodep.so.1".to_string(),
            ..Default::default()
        };
        let bytes = craft_shlib_elf(go_note, needed);
        // Each caller gets its own fixture file: the flags and pid in
        // the name keep parallel `cargo test` runners from racing
        // write/parse/delete on a shared path (a fixed-/tmp- collision
        // flake). All four callers pass distinct flag tuples; the pid
        // keeps separate test processes from colliding too.
        let path = std::env::temp_dir().join(format!(
            "rpmcrab-shlib-nodep-{}-{}-{}-{}",
            go_note,
            needed.is_some(),
            is_shobj,
            std::process::id()
        ));
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
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        std::fs::remove_file(&path).ok();
        results
    }

    #[test]
    fn shlib_without_dependency_information_fires() {
        let results = shlib_libdep_results(false, None, true);
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
        // them quiet instead of flagging them as dependency-less.
        let results = shlib_libdep_results(true, None, true);
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert!(results.is_empty(), "Go shlib must be quiet: {results:?}");
    }

    #[test]
    fn shlib_with_needed_stays_quiet() {
        let results = shlib_libdep_results(false, Some("libc.so.6"), true);
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert_lacks(&results, "statically-linked-binary");
    }

    #[test]
    fn non_shlib_without_needed_still_statically_linked() {
        // Existing behavior for non-shared objects is unchanged.
        let results = shlib_libdep_results(false, None, false);
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

        // Absent under the default config: the optflags lists are empty there,
        // so the check returns before touching DWARF.
        assert_lacks(&results, "unused-direct-shlib-dependency");
        assert_lacks(&results, "missing-mandatory-optflags");
    }
    /// rpmcrab#17: checksec-style hardening verification. Each fixture
    /// binary misses exactly one protection; hardenedbin misses none.
    #[test]
    fn hardening_findings() {
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let (results, _dir) = run_binaries_check(&rpm_path);

        let has =
            |finding: &str, bin: &str| lines_for(&results, finding).iter().any(|l| l.contains(bin));

        // Fully hardened: silent on all four.
        for finding in [
            "missing-fortify",
            "missing-stack-protector",
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
    fn rust_detection_negative_plain_elf() {
        let info = parse_crafted_sections("plain", &[(".text", b"\0"), (".rodata", b"hello\0")]);
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
    }

    fn hardening_results_for(is_rust: bool) -> Vec<(String, String)> {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/probe", "ELF 64-bit LSB pie executable");
        let mut info = syn_info();
        info.is_rust = is_rust;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_hardening(&pkg, &pkgfile, &info, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn hardening_rust_binary_skips_fortify_and_ssp() {
        let results = hardening_results_for(true);
        assert!(
            lines_for(&results, "missing-fortify").is_empty(),
            "missing-fortify must not fire for Rust: {results:?}"
        );
        assert!(
            lines_for(&results, "missing-stack-protector").is_empty(),
            "missing-stack-protector must not fire for Rust: {results:?}"
        );
        // Linker-level RELRO checks still apply to Rust binaries.
        assert_eq!(
            lines_for(&results, "missing-relro").len(),
            1,
            "missing-relro must still fire for Rust: {results:?}"
        );
    }

    #[test]
    fn hardening_c_binary_still_fires_fortify_and_ssp() {
        let results = hardening_results_for(false);
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
    }

    /// Deliberate divergence (divergences.toml, `case = "global"`, rpmcrab#17):
    /// the frozen reference emits no hardening findings, so each captured case
    /// gains exactly one port-only `W: missing-fortify` line:
    /// - `liblto21`: 0 -> 1 warning (`/usr/lib64/libLTO.so.21.1`)
    /// - `llvm21-gold`: 1 -> 2 warnings (`/usr/lib64/LLVMgold.so`)
    #[test]
    fn hardening_captured_cases_pin_new_lines() {
        let cases = [
            (
                "../../tests/parity/cases/liblto21/input/libLTO21-21.1.8-9.2.aarch64.rpm",
                "libLTO21.aarch64: W: missing-fortify /usr/lib64/libLTO.so.21.1",
            ),
            (
                "../../tests/parity/cases/llvm21-gold/input/llvm21-gold-21.1.8-9.2.aarch64.rpm",
                "llvm21-gold.aarch64: W: missing-fortify /usr/lib64/LLVMgold.so",
            ),
        ];
        for (rel, expected) in cases {
            let rpm = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
            let (results, _dir) = run_binaries_check(&rpm);
            let lines = lines_for(&results, "missing-fortify");
            assert_eq!(
                lines,
                [expected],
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

    fn optflags_config(mandatory: &[&str], forbidden: &[&str]) -> Config {
        let mut config = test_config();
        let arr = |ss: &[&str]| {
            toml::Value::Array(
                ss.iter()
                    .map(|s| toml::Value::String((*s).to_string()))
                    .collect(),
            )
        };
        config.configuration["MandatoryOptflags"] = arr(mandatory);
        config.configuration["ForbiddenOptflags"] = arr(forbidden);
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
    fn optflags_missing_mandatory() {
        let pkg_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = optflags_test_pkg(&pkg_dir);
        let elf_dir = tempfile::TempDir::new().expect("tmpdir");
        let path = write_dwarf_elf(&elf_dir, "prog", &[("GNU C17 12.3.1 -O2", false)]);
        let config = optflags_config(&["-O2", "-D_FORTIFY_SOURCE=2"], &[]);
        let results = run_optflags(&pkg, &path, &config);
        let lines = lines_for(&results, "missing-mandatory-optflags");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(lines[0].contains(" W: "), "must be Warning: {}", lines[0]);
        assert!(
            lines[0].contains("-D_FORTIFY_SOURCE=2"),
            "detail lists the missing flag: {}",
            lines[0]
        );
        assert!(
            !lines[0].contains("-O2"),
            "present flags are not missing: {}",
            lines[0]
        );
        assert_lacks(&results, "forbidden-optflags");
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
        let config = optflags_config(&[], &["-fno-stack-protector"]);
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
        let config = optflags_config(&["-O2", "-D_FORTIFY_SOURCE=2"], &["-fno-stack-protector"]);
        let results = run_optflags(&pkg, &path, &config);
        assert_lacks(&results, "missing-mandatory-optflags");
        assert_lacks(&results, "forbidden-optflags");
    }

    #[test]
    fn optflags_evaluated_per_compilation_unit() {
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
        let config = optflags_config(&["-D_FORTIFY_SOURCE=2"], &[]);
        let results = run_optflags(&pkg, &path, &config);
        // Only the assembler unit is missing the flag: exactly one finding.
        let lines = lines_for(&results, "missing-mandatory-optflags");
        assert_eq!(lines.len(), 1, "results: {results:?}");
        assert!(
            lines[0].contains("-D_FORTIFY_SOURCE=2"),
            "detail: {}",
            lines[0]
        );
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
                sections,
                program_headers: Vec::new(),
                functions: Vec::new(),
                is_shlib: true,
                is_debug: false,
                soname: None,
                needed: Vec::new(),
                runpaths: Vec::new(),
                has_textrel: false,
                elf_type: goblin::elf::header::ET_DYN,
                bind_now: false,
                failed: None,
                is_rust: false,
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
            sections: Vec::new(),
            program_headers: Vec::new(),
            functions: Vec::new(),
            is_shlib: false,
            is_debug: false,
            soname: None,
            needed: Vec::new(),
            runpaths: Vec::new(),
            has_textrel: false,
            elf_type: goblin::elf::header::ET_EXEC,
            bind_now: false,
            failed: None,
            is_rust: false,
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
    fn package_without_binary_is_error() {
        let config = test_config();
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/share/doc/testpkg/README", "ASCII text")],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
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
        let m1 = craft_shlib_elf(false, Some("liba.so.1"));
        let m2 = craft_shlib_elf(false, None);
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
        let m1 = craft_shlib_elf(false, None);
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
        let m1 = craft_shlib_elf(false, Some("liba.so.1"));
        let m2 = craft_shlib_elf(false, None);
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

    #[test]
    fn undefined_non_weak_symbol() {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_dynamically_linked = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.so.1", "ELF 64-bit LSB shared object");
        let mut ldd = syn_ldd();
        ldd.undefined_symbols = vec!["GSS_C_NT_HOSTBASED_SERVICE".to_string()];

        // Undefined symbols in a shared object -> Error.
        let mut info = syn_info();
        info.is_shlib = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_dependency(&pkg, &pkgfile, &info, &ldd, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
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

        // setuid+setgid without setgroups: Error when installed setuid,
        // Warning otherwise.
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
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

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
        std::fs::write(&so_path, craft_shlib_elf(false, None)).expect("write so");
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
