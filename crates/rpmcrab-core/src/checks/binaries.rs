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

use crate::check::{Check, add_info, basename, make_finding};
use crate::checks::shared::{base_arch, is_64bit_arch};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::{PkgFile, is_reg, is_symlink};
use crate::tools::{Tool, ToolSource, spawn_with_retry, test_source};
use std::sync::OnceLock;

static VALIDSO_REGEX: OnceLock<Regex> = OnceLock::new();
fn validso_regex() -> &'static Regex {
    VALIDSO_REGEX.get_or_init(|| Regex::new(r"(\.so\.\d+(\.\d+)*|\d\.so)$").expect("static regex"))
}

/// The version tail of a SONAME: the part after its first `.so.`,
/// when that part is non-empty and starts with a letter or a digit
/// (`libstemmer.so.0d` -> `0d`, `libLimeSuite.so.23.11-1` ->
/// `23.11-1`, `libSDL_bgi.so.suse0` -> `suse0`). A SONAME with no
/// such tail (an empty one, `libterminal-nautilus.so.`, or one
/// starting with punctuation) stays outside the shared-library
/// arms the tail admits (issue #1029).
fn soname_tail(soname: &str) -> Option<&str> {
    let (_, tail) = soname.split_once(".so.")?;
    (!tail.is_empty() && tail.as_bytes()[0].is_ascii_alphanumeric()).then_some(tail)
}

/// Whether `path` sits directly in a directory named `lib` or
/// `lib64` -- its immediate parent directory (the SONAME-arm gate
/// of issue #1029 for files the shared-library file-name test
/// misses). A library in a subdirectory of a lib dir (a plugin or
/// compat tree such as `/usr/lib64/ncurses6nt/`) does not qualify.
fn in_lib_dir(path: &str) -> bool {
    let parent = path.rsplit_once('/').map_or("", |(p, _)| p);
    let dir = parent.rsplit_once('/').map_or(parent, |(_, last)| last);
    dir == "lib" || dir == "lib64"
}

/// Whether the basename of `path` is the SONAME itself, or the
/// SONAME followed by a `.` and a further suffix (the real library
/// file behind its SONAME symlink, e.g. `libstemmer.so.0d.0.0` for
/// SONAME `libstemmer.so.0d`).
fn basename_is_soname(path: &str, soname: &str) -> bool {
    let base = path.rsplit_once('/').map_or(path, |(_, b)| b);
    base == soname
        || base
            .strip_prefix(soname)
            .is_some_and(|rest| rest.starts_with('.'))
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
static GETS_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static TMPNAM_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static GETHOSTBYNAME_CALL_REGEX: OnceLock<Regex> = OnceLock::new();

static MD5_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static DES_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static RC4_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static WEAK_PRNG_CALL_REGEX: OnceLock<Regex> = OnceLock::new();
static UNBOUNDED_COPY_CALL_REGEX: OnceLock<Regex> = OnceLock::new();

static SHELL_CALL_REGEX: OnceLock<Regex> = OnceLock::new();

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

/// The `e_machine` values that are the given package architecture's
/// own. Debug info for these is extracted by the package arch's
/// debuginfo pipeline; objects for any other machine in the package
/// are cross content whose debuginfo belongs to the foreign target.
/// A hwcaps subarch resolves through `base_arch` (`x86_64_v3` is an
/// x86-64 package), like every other arch consumer. An arch with no
/// entry here maps to an empty slice, and callers treat that as
/// "charge any code": an unmapped arch must not silence findings it
/// cannot classify (plusky/rpmcrab#847).
fn host_elf_machines(arch: &str) -> &'static [u16] {
    use goblin::elf::header::{
        EM_68K, EM_386, EM_AARCH64, EM_ARM, EM_AVR, EM_IA_64, EM_MIPS, EM_PARISC, EM_PPC, EM_PPC64,
        EM_RISCV, EM_S390, EM_SH, EM_SPARC, EM_SPARCV9, EM_X86_64,
    };
    let arch = base_arch(arch);
    if arch.starts_with("arm") {
        return &[EM_ARM];
    }
    if arch.starts_with("mips") {
        return &[EM_MIPS];
    }
    match arch {
        "x86_64" => &[EM_X86_64],
        "i386" | "i486" | "i586" | "i686" => &[EM_386],
        "aarch64" => &[EM_AARCH64],
        "ppc" => &[EM_PPC],
        "ppc64" | "ppc64le" => &[EM_PPC64],
        "s390" | "s390x" => &[EM_S390],
        "riscv64" => &[EM_RISCV],
        "loongarch64" => &[258], // EM_LOONGARCH; goblin has no constant for it
        "sparc" => &[EM_SPARC],
        "sparc64" => &[EM_SPARCV9],
        "alpha" => &[36902], // EM_ALPHA; goblin has no constant for it
        "m68k" => &[EM_68K],
        "sh4" => &[EM_SH],
        "hppa" | "parisc" => &[EM_PARISC],
        "ia64" => &[EM_IA_64],
        "avr" => &[EM_AVR],
        _ => &[],
    }
}

/// ISA family of a package arch, for the foreign-payload question in
/// `check_library_dependency`. Unlike `host_elf_machines` (the exact
/// machines a package's own debuginfo pipeline handles), a family
/// groups the machines that execute on one another's hosts: a 32-bit
/// x86 binary runs on x86-64, AArch32 on AArch64. Only a machine from
/// a *different* family marks payload built for another architecture
/// entirely (firmware and cross data the host loader never loads).
/// An unmapped arch yields None, and callers treat that as "charge",
/// mirroring `host_elf_machines` (#847).
fn pkg_arch_family(arch: &str) -> Option<&'static str> {
    let arch = base_arch(arch);
    if arch.starts_with("arm") || arch == "aarch64" {
        return Some("arm");
    }
    if arch.starts_with("mips") {
        return Some("mips");
    }
    Some(match arch {
        "x86_64" | "i386" | "i486" | "i586" | "i686" => "x86",
        "ppc" | "ppc64" | "ppc64le" => "ppc",
        "s390" | "s390x" => "s390",
        "riscv64" => "riscv",
        "sparc" | "sparc64" => "sparc",
        "alpha" => "alpha",
        "m68k" => "m68k",
        "ia64" => "ia64",
        "sh4" => "sh",
        "hppa" | "parisc" => "parisc",
        "loongarch64" => "loongarch",
        "avr" => "avr",
        _ => return None,
    })
}

/// ISA family of an ELF `e_machine`; see `pkg_arch_family`.
fn elf_machine_family(machine: u16) -> Option<&'static str> {
    use goblin::elf::header::{
        EM_68K, EM_386, EM_AARCH64, EM_ARM, EM_AVR, EM_IA_64, EM_MIPS, EM_PARISC, EM_PPC, EM_PPC64,
        EM_RISCV, EM_S390, EM_SH, EM_SPARC, EM_SPARC32PLUS, EM_SPARCV9, EM_X86_64,
    };
    Some(match machine {
        EM_386 | EM_X86_64 => "x86",
        EM_ARM | EM_AARCH64 => "arm",
        EM_PPC | EM_PPC64 => "ppc",
        EM_S390 => "s390",
        EM_RISCV => "riscv",
        EM_SPARC | EM_SPARC32PLUS | EM_SPARCV9 => "sparc",
        36902 => "alpha", // EM_ALPHA; goblin has no constant for it
        EM_68K => "m68k",
        EM_MIPS => "mips",
        EM_IA_64 => "ia64",
        EM_SH => "sh",
        EM_PARISC => "parisc",
        258 => "loongarch", // EM_LOONGARCH; goblin has no constant for it
        EM_AVR => "avr",
        _ => return None,
    })
}

/// Whether an ELF's machine belongs to a different ISA family than
/// the package architecture: guest firmware and cross payloads the
/// package arch's dynamic linker never loads. An unmapped package
/// arch or an unclassified machine is not foreign -- the finding is
/// charged as before, since the gate cannot classify the file.
fn foreign_elf_machine(machine: u16, arch: &str) -> bool {
    match (elf_machine_family(machine), pkg_arch_family(arch)) {
        (Some(machine_family), Some(arch_family)) => machine_family != arch_family,
        _ => false,
    }
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
    /// Undefined FUNC-type symbol names from both `.symtab` and `.dynsym`:
    /// functions the object references but does not define. A definition
    /// site carries a real section index instead of `SHN_UNDEF`, so the
    /// library that implements a function never lands in this set; the
    /// mktemp call check reads it for archives, where the definition
    /// site is a separate member object and not a call site.
    undefined_function_refs: Vec<String>,
    is_shlib: bool,
    is_debug: bool,
    /// True when the binary was produced by the Rust toolchain.
    /// Computed during parse; see `detect_rust_binary`.
    is_rust: bool,
    /// True when the binary was produced by the Zig toolchain.
    /// Computed during parse; see `detect_zig_binary`.
    is_zig: bool,
    /// The Go toolchain releases that built this file, parsed from
    /// the `.go.buildinfo` section version strings of the file
    /// itself and, for an archive, of each member. Computed during
    /// parse; see `detect_go_toolchain`. Empty when no member
    /// records a version (a stripped binary, or not a Go binary) and
    /// when the recorded strings are not clean release versions
    /// (devel and release-candidate strings): the toolchain finder
    /// stays silent in both cases. Every distinct version is kept,
    /// because the floor judges each member against its own release
    /// line -- collapsing to one minimum across members would let a
    /// member on an older, fixed line hide a member below its own
    /// line's floor.
    go_toolchains: Vec<GoVersion>,
    /// True when the file bytes carry the Go buildinfo magic. The Go
    /// sections `is_go_binary` reads are the primary marker, but a
    /// build stripped of its section headers keeps the buildinfo
    /// block, whose magic is a fixed byte sequence (Go's
    /// `debug/buildinfo`). Computed during parse.
    go_buildinfo: bool,
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
    /// `e_machine` of every parsed ELF (for an archive: every member)
    /// that carries machine code: at least one `SHF_EXECINSTR`
    /// `SHT_PROGBITS` section whose file bytes are not all zero, or
    /// whose bytes the file data does not fully hold (an out-of-range
    /// offset, a truncated tail), so the section cannot be shown to be
    /// zero-filled. A zero-filled executable section is a
    /// relocation-filled slot, not code (the wine import-thunk shape:
    /// an 8-byte all-zero `.text` holding one relocation against a
    /// `__wine$func$` pointer), and a member with no executable section
    /// carries no code at all (the compiler-rt preinit shape). Consumed
    /// by `check_missing_debug_info_in_archive` (plusky/rpmcrab#847).
    code_machines: Vec<u16>,
    failed: Option<String>,
    /// An ar archive with members, none of which is an ELF object:
    /// every member is in another object format (COFF, wasm, LLVM
    /// bitcode, GIMPLE offload text, plain data), so the archive is
    /// outside the ELF checks' remit. Set by `parse_archive`.
    no_elf_members: bool,
    /// An ar archive with no members at all: the file is exactly the
    /// ar magic. glibc's post-2.34 merged-library linker stubs
    /// (libpthread.a, libdl.a and their kin) are shipped in this
    /// shape: empty placeholder archives whose symbols live in libc.
    /// Set by `parse_archive`.
    no_members: bool,
}

/// ar archive magic: `!<arch>` followed by a newline.
const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

/// ELF identification magic: `0x7f` followed by `ELF`.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

impl ReadelfInfo {
    fn empty(name: &str) -> Self {
        ReadelfInfo {
            sections: Vec::new(),
            program_headers: Vec::new(),
            functions: Vec::new(),
            undefined_functions: Vec::new(),
            undefined_function_refs: Vec::new(),
            // The reference derives is_shlib and is_debug from the file name,
            // not the ELF content (readelfparser.py). A PIE executable or Go
            // binary is ET_DYN but is not a shared library for these checks.
            is_shlib: so_regex().is_match(name).unwrap_or(false),
            is_debug: name.ends_with(".debug"),
            is_rust: false,
            is_zig: false,
            go_toolchains: Vec::new(),
            go_buildinfo: false,
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
            code_machines: Vec::new(),
            failed: None,
            no_elf_members: false,
            no_members: false,
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
    /// the archive. A member that presents as an ELF object (ELF magic)
    /// and then fails to parse fails the whole file, exactly like
    /// readelf's nonzero exit does for the reference. A member in
    /// another object format (COFF, wasm, LLVM bitcode, GIMPLE offload
    /// text, plain data) is outside the ELF checks' remit: it is
    /// skipped, and an archive whose members are all in other formats
    /// is marked `no_elf_members` so the ELF checks stay silent on it.
    fn parse_archive(data: &[u8], name: &str) -> Self {
        let mut info = Self::empty(name);
        let archive = match goblin::archive::Archive::parse(data) {
            Ok(a) => a,
            Err(e) => {
                info.failed = Some(e.to_string());
                return info;
            }
        };
        let mut members = 0usize;
        let mut elf_members = 0usize;
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
            members += 1;
            if !bytes.starts_with(ELF_MAGIC) {
                continue;
            }
            elf_members += 1;
            match parse_elf(bytes) {
                Ok(elf) => info.fill_from_elf(&elf, bytes),
                Err(e) => {
                    info.failed = Some(format!("{}: {e}", member.extended_name()));
                    return info;
                }
            }
        }
        info.no_elf_members = members > 0 && elf_members == 0;
        info.no_members = members == 0;
        info
    }

    /// Merge one parsed ELF's metadata, mirroring readelf's output.
    /// Archive members are merged by appending: each member's sections
    /// land in `sections` the same way readelf's per-member output does.
    fn fill_from_elf(&mut self, elf: &goblin::elf::Elf, data: &[u8]) {
        // Machine code carried by this ELF (see `code_machines`): an
        // executable PROGBITS section holding at least one non-zero
        // byte. The scan short-circuits on the first non-zero byte, so
        // real code costs a few byte reads; only an all-zero section
        // is scanned in full.
        let has_code = elf.section_headers.iter().any(|sh| {
            sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0
                && sh.sh_type == goblin::elf::section_header::SHT_PROGBITS
                && {
                    // The offsets convert with `try_from`, not `as`: a
                    // 64-bit range on a 32-bit build must not truncate
                    // into an in-range, all-zero one.
                    let range = usize::try_from(sh.sh_offset).ok().and_then(|start| {
                        usize::try_from(sh.sh_size)
                            .ok()
                            .map(|size| (start, start.saturating_add(size)))
                    });
                    // A range the data does not fully hold -- an
                    // out-of-range offset, a truncated tail, or a range
                    // `usize` cannot represent -- cannot be shown to be
                    // all zero, so it counts as code: fail open, the
                    // unmapped-arch principle applied to section bytes.
                    match range.and_then(|(start, end)| data.get(start..end)) {
                        Some(bytes) => bytes.iter().any(|b| *b != 0),
                        None => true,
                    }
                }
        });
        if has_code {
            self.code_machines.push(elf.header.e_machine);
        }

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
                        if sym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
                            self.undefined_function_refs.push(name.to_string());
                        }
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
                        if ty == goblin::elf::sym::STT_FUNC {
                            self.undefined_function_refs.push(name.to_string());
                        }
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
        // Accumulate across members: an archive's members are
        // normally one build's objects, but a member built by an
        // outdated toolchain carries its standard library with it,
        // and members built by different toolchains each stand for
        // themselves -- every distinct version is kept so the floor
        // can judge each against its own release line. A single
        // minimum across members would stand for the file instead,
        // and the oldest member is not necessarily the vulnerable
        // one: a fixed member on an older line sorts below a
        // below-floor member on a newer line.
        if let Some(found) = detect_go_toolchain(elf, data) {
            if !self.go_toolchains.contains(&found) {
                self.go_toolchains.push(found);
            }
        }
        // The magic scan walks the whole file; skip it when the
        // section test already established Go for this file.
        if !self.go_buildinfo && !self.is_go_binary() {
            self.go_buildinfo = has_go_buildinfo_magic(data);
        }
    }
    fn has_function_matching(&self, regex: &fancy_regex::Regex) -> bool {
        self.functions
            .iter()
            .any(|s| regex.is_match(s).unwrap_or(false))
    }

    /// The archive-member view of `has_function_matching`: only symbols
    /// the object references but does not define match, so a definition
    /// site (the archive member implementing the function) stays silent.
    fn has_undefined_function_matching(&self, regex: &fancy_regex::Regex) -> bool {
        self.undefined_function_refs
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
    /// object (no non-weak undefined symbols), an executable-entry
    /// shim (defines `main`), or a module whose build stamped its own
    /// file name as its DT_SONAME (see `soname_is_own_module_name`).
    fn is_plugin_like(&self, file_name: &str) -> bool {
        self.soname.is_none()
            || !self.has_nonweak_undefined
            || self.defines_main
            || self.soname_is_own_module_name(file_name)
    }

    /// The object's DT_SONAME is exactly its own file name and carries
    /// no version component: the shape of a module built to be loaded
    /// by path -- application plugins (slurm, apache, collectd),
    /// interpreter extension modules, VirtualBox ring-0 payloads --
    /// whose build stamps the module's own name as its SONAME. The
    /// credit is judged on the file's basename alone, at any location.
    /// Such an object is never DT_NEEDED-linked under that name
    /// (verified over the Factory corpus: no package records a
    /// DT_NEEDED on any of these names) and resolves its undefined
    /// symbols against the host process, so an empty DT_NEEDED states
    /// nothing. A versioned SONAME (`lib....so.<N>`) is a library ABI
    /// name instead: it stays checked even when it equals the file
    /// name, and so does a versioned SONAME carried by a longer file
    /// name (the genuine `libfrrfpm_pb.so.0` in
    /// `libfrrfpm_pb.so.0.0.0` shape, which other packages do
    /// DT_NEEDED-link).
    fn soname_is_own_module_name(&self, file_name: &str) -> bool {
        let Some(soname) = self.soname.as_deref() else {
            return false;
        };
        let base = Path::new(file_name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(file_name);
        soname == base && !soname_has_version_component(soname)
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

/// Whether a DT_SONAME carries a library ABI version component: a
/// `.so.` immediately followed by a digit (`libfoo.so.0`), or one of
/// the `validso_regex` tail forms -- a digit immediately before the
/// final `.so`, the dash and stem versions `libdb-4.8.so`,
/// `libtcl8.6.so` and `libfoo-1.so` the soname validity gate also
/// treats as versioned. An unversioned module name (`mod_foo.so`,
/// `plugin.so`, `VMMR0.r0`, `libfoo.so0`) has none.
fn soname_has_version_component(soname: &str) -> bool {
    if validso_regex().is_match(soname).unwrap_or(false) {
        return true;
    }
    let mut rest = soname;
    while let Some(idx) = rest.find(".so.") {
        let after = &rest[idx + 4..];
        if after.as_bytes().first().is_some_and(|c| c.is_ascii_digit()) {
            return true;
        }
        // Advance one byte past this occurrence's dot, so an
        // overlapping `.so.` (`x.so.so.1`) is still examined.
        rest = &rest[idx + 1..];
    }
    false
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

/// The Go buildinfo block opens with a fixed magic: 0xff followed by
/// ` Go buildinf:` (Go's `debug/buildinfo`). It survives stripping of
/// the section headers, which removes the `.gopclntab` /
/// `.note.go.buildid` sections `is_go_binary` reads, so sectionless
/// Go builds are still recognised as Go output. A magic occurrence
/// counts only as a structurally valid header -- the fixed 32-byte
/// header `parse_go_buildinfo` reads must fit, and the pointer-size
/// byte must be 4 or 8 -- mirroring the validation `debug/buildinfo`
/// itself applies while scanning, so the byte sequence appearing in
/// unrelated payload does not mark the file as Go output.
fn has_go_buildinfo_magic(data: &[u8]) -> bool {
    const HEADER_LEN: usize = 32;
    let magic = GO_BUILDINFO_MAGIC.as_slice();
    data.windows(magic.len())
        .enumerate()
        .any(|(i, w)| w == magic && data.len() - i >= HEADER_LEN && matches!(data[i + 14], 4 | 8))
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
/// unrecognized binary is treated as C. C output built with `zig cc`
/// carries the same markers -- the linker is Zig's LLD fork whatever the
/// source language -- and shares the static-exemption rationale: a fully
/// static binary is that toolchain's normal output shape.
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

/// A Go release version, parsed from the version string a Go
/// binary's `.go.buildinfo` section records
/// (`go<major>.<minor>[.<patch>]`). Only clean release strings
/// parse: devel, release-candidate and bootstrap strings return
/// `None`, so the toolchain finder built on this type stays silent
/// for toolchains it cannot order against the floor table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct GoVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl GoVersion {
    fn parse(raw: &str) -> Option<GoVersion> {
        fn component(text: &str) -> Option<u32> {
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            text.parse().ok()
        }
        let rest = raw.strip_prefix("go")?;
        let mut parts = rest.split('.');
        let version = GoVersion {
            major: component(parts.next()?)?,
            minor: component(parts.next()?)?,
            patch: match parts.next() {
                Some(text) => component(text)?,
                None => 0,
            },
        };
        if parts.next().is_some() {
            return None;
        }
        Some(version)
    }

    /// The release line this version belongs to: the version with
    /// the patch component zeroed, so line identity compares on
    /// (major, minor) alone.
    fn line(self) -> GoVersion {
        GoVersion { patch: 0, ..self }
    }
}

impl std::fmt::Display for GoVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.patch == 0 {
            write!(f, "go{}.{}", self.major, self.minor)
        } else {
            write!(f, "go{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

/// The build-info magic every Go binary's `.go.buildinfo` section
/// starts with.
const GO_BUILDINFO_MAGIC: &[u8; 14] = b"\xff Go buildinf:";

/// Extract the toolchain version string from a `.go.buildinfo`
/// section, mirroring `debug/buildinfo`: the blob opens with a
/// fixed 32-byte header — magic, a pointer-size byte, a flags byte,
/// then pointers to the version and module-info string headers.
/// With the flags version bit set (Go 1.18 and later) the strings
/// instead follow the header inline as uvarint-length-prefixed
/// contents. Without it, the header's first pointer addresses the
/// version string's (data pointer, length) header, resolved here
/// through the file's PT_LOAD segments; the flags low bit marks
/// big-endian pointer words. Anything malformed yields `None`,
/// never a guess.
fn parse_go_buildinfo(section: &[u8], data: &[u8], elf: &goblin::elf::Elf) -> Option<String> {
    const HEADER_LEN: usize = 32;
    if section.len() < HEADER_LEN || !section.starts_with(GO_BUILDINFO_MAGIC.as_slice()) {
        return None;
    }
    let ptr_size = usize::from(section[14]);
    if ptr_size != 4 && ptr_size != 8 {
        return None;
    }
    let flags = section[15];
    if flags & 2 != 0 {
        let (version, _) = read_go_buildinfo_string(section.get(HEADER_LEN..)?)?;
        if version.len() > 256 {
            return None;
        }
        return Some(version);
    }
    let big_endian = flags & 1 != 0;
    let read_word = |bytes: &[u8], offset: usize| -> Option<u64> {
        let raw = bytes.get(offset..offset.checked_add(ptr_size)?)?;
        let mut value = 0u64;
        if big_endian {
            for byte in raw {
                value = (value << 8) | u64::from(*byte);
            }
        } else {
            for (i, byte) in raw.iter().enumerate() {
                value |= u64::from(*byte) << (8 * i);
            }
        }
        Some(value)
    };
    let resolve = |address: u64| -> Option<usize> {
        for ph in &elf.program_headers {
            if ph.p_type != goblin::elf::program_header::PT_LOAD {
                continue;
            }
            if address >= ph.p_vaddr && address - ph.p_vaddr < ph.p_filesz {
                return usize::try_from(ph.p_offset.checked_add(address - ph.p_vaddr)?).ok();
            }
        }
        None
    };
    let header_offset = resolve(read_word(section, 16)?)?;
    let address = read_word(data, header_offset)?;
    let length = usize::try_from(read_word(data, header_offset.checked_add(ptr_size)?)?).ok()?;
    if length == 0 || length > 256 {
        return None;
    }
    let offset = resolve(address)?;
    let bytes = data.get(offset..offset.checked_add(length)?)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// One uvarint-length-prefixed string from Go build info; returns
/// the string and the number of bytes consumed.
fn read_go_buildinfo_string(bytes: &[u8]) -> Option<(String, usize)> {
    let mut length: u64 = 0;
    let mut shift = 0u32;
    let mut consumed = 0usize;
    loop {
        let byte = *bytes.get(consumed)?;
        consumed += 1;
        length |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    let length = usize::try_from(length).ok()?;
    let end = consumed.checked_add(length)?;
    let text = bytes.get(consumed..end)?;
    Some((String::from_utf8_lossy(text).into_owned(), end))
}

/// The Go toolchain that built this ELF, from its `.go.buildinfo`
/// section; `None` when the section is absent or its version string
/// is not a clean release version.
fn detect_go_toolchain(elf: &goblin::elf::Elf, data: &[u8]) -> Option<GoVersion> {
    for sh in &elf.section_headers {
        if elf.shdr_strtab.get_at(sh.sh_name) != Some(".go.buildinfo") {
            continue;
        }
        // A malformed section must not abort the scan: a later
        // `.go.buildinfo` section may still parse.
        let Ok(start) = usize::try_from(sh.sh_offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(sh.sh_size) else {
            continue;
        };
        let end = start.saturating_add(size).min(data.len());
        let Some(section) = data.get(start..end) else {
            continue;
        };
        if let Some(version) =
            parse_go_buildinfo(section, data, elf).and_then(|raw| GoVersion::parse(&raw))
        {
            return Some(version);
        }
    }
    None
}

/// The embedded Go toolchain floor: per release line, the minimum
/// release carrying the fixes for the recorded defect set. Baked in
/// like the defect-pattern registry so an installed binary needs no
/// data dir next to it; the table's as-of date and update route are
/// recorded in the file itself.
const GO_TOOLCHAIN_FLOOR_TOML: &str = include_str!("../../data/go-toolchain-floor.toml");

/// The parsed floor, parsed once (the `defect_pattern::registry`
/// pattern).
fn go_toolchain_floor() -> &'static [(GoVersion, GoVersion)] {
    static FLOOR: OnceLock<Vec<(GoVersion, GoVersion)>> = OnceLock::new();
    FLOOR.get_or_init(|| parse_go_toolchain_floor(GO_TOOLCHAIN_FLOOR_TOML))
}

/// Parse and validate the floor table. Validation takes the
/// staged-data posture (the registry's): a malformed table panics at
/// startup instead of silently disabling the finder.
fn parse_go_toolchain_floor(raw: &str) -> Vec<(GoVersion, GoVersion)> {
    let table: toml::Table = raw.parse().expect("go toolchain floor is valid TOML");
    assert!(
        table.get("as_of").and_then(toml::Value::as_str).is_some(),
        "go toolchain floor records an as_of date"
    );
    let records = table
        .get("line")
        .and_then(toml::Value::as_array)
        .expect("go toolchain floor has a [[line]] array");
    let mut floor: Vec<(GoVersion, GoVersion)> = records
        .iter()
        .map(|record| {
            let field = |name: &str| -> String {
                record
                    .get(name)
                    .and_then(toml::Value::as_str)
                    .unwrap_or_else(|| panic!("go toolchain floor line is missing {name:?}"))
                    .to_string()
            };
            let line = GoVersion::parse(&format!("go{}", field("release")))
                .expect("go toolchain floor release is a version");
            let minimum = GoVersion::parse(&format!("go{}", field("minimum")))
                .expect("go toolchain floor minimum is a version");
            assert!(
                minimum.line() == line && line.patch == 0,
                "go toolchain floor minimum belongs to its release line"
            );
            (line, minimum)
        })
        .collect();
    floor.sort();
    floor.dedup();
    assert!(
        !floor.is_empty(),
        "go toolchain floor lists at least one line"
    );
    assert!(
        floor.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "go toolchain floor lines are strictly ascending"
    );
    floor
}

/// Whether `version` is below the floor: below its own line's
/// minimum, or on a line older than every listed line (no release
/// on such a line carries the recorded fixes). A version on a line
/// newer than every listed line stays silent — the table does not
/// judge what it does not know, so a stale table under-fires and
/// never false-fires.
fn go_toolchain_below_floor(version: GoVersion, floor: &[(GoVersion, GoVersion)]) -> bool {
    let line = version.line();
    for (listed, minimum) in floor {
        if *listed == line {
            return version < *minimum;
        }
    }
    floor
        .iter()
        .map(|(listed, _)| *listed)
        .min()
        .is_some_and(|lowest| line < lowest)
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
/// dependency list, its ELF class, its search context, and the
/// package the file belongs to (system candidates are
/// class-matched, the provided set depends on the directories
/// the file's own entries are searched in, and the walk sees the
/// file's own package's providers first).
type ClosureKey = (Vec<String>, Option<bool>, SearchContext, PackageId);

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

/// The symbol providers one package ships, indexed by every name a
/// DT_NEEDED entry can carry: the library's SONAME and its file
/// basename. The two are equal for most libraries; when a package
/// file is a symlink, the real file behind it carries the SONAME.
/// Duplicate providers under one key (e.g. /lib64 and /usr/lib64
/// copies of one library) merge, keeping the first file's search
/// paths: the copies are the same library, and their defined
/// symbols and DT_NEEDED entries merge regardless.
fn package_providers(
    analyses: &[Option<ElfAnalysis>],
    files: &[PkgFile],
) -> HashMap<String, SymbolProvider> {
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
    providers
}

/// The symbol providers one package ships, kept as a unit: a
/// package is the resolution boundary across an invocation
/// (plusky/rpmcrab#735). Two packages can ship the same SONAME
/// with different symbol sets, DT_NEEDED entries and search
/// paths -- two versions or two architectures of one library --
/// so provider sets stay separate per package: unioning them
/// would invent a provider that exists in no package, masking
/// symbols the consumer's actual provider does not define and
/// mixing transitive closures through the wrong search paths.
struct PackageProviders {
    pkg_name: String,
    pkg_arch: String,
    pkg_filename: String,
    providers: HashMap<String, SymbolProvider>,
}

/// Identity of the package a resolution request originates from:
/// its name, architecture and package file. Two versions of one
/// package in one invocation are distinct identities (issue #799):
/// when both versions ship a SONAME, the consumer's provider is
/// its own package file's copy, not the sibling version's copy a
/// name+arch key would reach first in check order.
type PackageId = (String, String, String);

/// The resolution view over an invocation's per-package provider
/// sets, in package check order. A lookup for one needing object
/// considers its own package's set first, then the sets of other
/// packages with the object's own base architecture (a hwcaps
/// subarch such as `x86_64_v3` counts as its base arch), in check
/// order, and returns the first provider found for the SONAME
/// (exact spelling first, then the entry's basename). Sets of a
/// different architecture are never consulted: the loader does
/// not bind a consumer to a library built for another
/// architecture.
struct ProviderIndex {
    sets: Vec<(PackageId, HashMap<String, Arc<SymbolProvider>>)>,
}

impl ProviderIndex {
    fn new(sets: Vec<PackageProviders>) -> Self {
        ProviderIndex {
            sets: sets
                .into_iter()
                .map(|set| {
                    (
                        (set.pkg_name, set.pkg_arch, set.pkg_filename),
                        set.providers
                            .into_iter()
                            .map(|(k, v)| (k, Arc::new(v)))
                            .collect(),
                    )
                })
                .collect(),
        }
    }

    /// The provider for `soname` as seen by a needing object owned
    /// by `owner`, together with the identity of the package that
    /// ships it: the walk continues from that package's point of
    /// view for the provider's own DT_NEEDED entries.
    fn lookup(&self, soname: &str, owner: &PackageId) -> Option<(PackageId, Arc<SymbolProvider>)> {
        let base = basename(soname);
        for (id, map) in &self.sets {
            if id == owner {
                if let Some(provider) = map.get(soname).or_else(|| map.get(base)) {
                    return Some((id.clone(), provider.clone()));
                }
            }
        }
        for (id, map) in &self.sets {
            if id != owner && base_arch(&id.1) == base_arch(&owner.1) {
                if let Some(provider) = map.get(soname).or_else(|| map.get(base)) {
                    return Some((id.clone(), provider.clone()));
                }
            }
        }
        None
    }
}

/// One file's undefined-symbol resolution inputs, captured while
/// its package is checked and resolved in `after_checks`
/// (plusky/rpmcrab#701). Only files the emission gate in
/// `check_dependency` passes are captured, so a record exists
/// exactly where the finding could fire.
struct ConsumerFile {
    /// The package-internal path: the finding detail, and the base
    /// for the file's own search context (`installed_dir`).
    file_name: String,
    /// Undefined non-weak `.dynsym` names, in `.dynsym` order (the
    /// emission order).
    undefined_symbols: Vec<String>,
    /// The file's own defined symbols: subtracted after the closure
    /// walk, as in `resolve_undefined_symbols`. A set: the residue
    /// loop tests every undefined symbol against it.
    defined_symbols: HashSet<String>,
    /// The file's DT_NEEDED entries: the closure walk's roots.
    dependencies: Vec<String>,
    /// ELF class of the file (`Some(true)` = 64-bit); system
    /// candidates are matched against it.
    is_64: Option<bool>,
    /// DT_RPATH entries, colon-split, in order.
    rpath: Vec<String>,
    /// DT_RUNPATH entries, colon-split, in order.
    runpath: Vec<String>,
    /// A DT_RUNPATH tag is present at all (see `LddInfo`).
    has_runpath: bool,
}

/// One checked package's captured consumers, in file order.
struct PackageConsumers {
    pkg_name: String,
    pkg_arch: String,
    pkg_filename: String,
    files: Vec<ConsumerFile>,
}

/// Cross-package state for undefined-symbol resolution: exported
/// per package and merged before `after_checks`
/// (plusky/rpmcrab#701, `rpmlint#1595` plumbing).
#[derive(Default)]
struct BinariesState {
    /// The provider set of every contributing package, in package
    /// check order, kept per package (see `PackageProviders`).
    provider_sets: Vec<PackageProviders>,
    /// Captured consumers, in package check order.
    packages: Vec<PackageConsumers>,
    /// `(name, arch, filename)` of every package that carried
    /// ELF content (a provider or a consumer), in check order.
    /// The filename keeps two distinct packages that share a name
    /// and arch (two versions in one invocation) from collapsing
    /// into one contributor. The count is the invocation-mode
    /// switch in `after_checks`: one contributing package
    /// resolves with the system fallback, a wider batch resolves
    /// inside the invocation's set alone.
    contributors: Vec<(String, String, String)>,
}

impl BinariesState {
    fn is_empty(&self) -> bool {
        self.provider_sets
            .iter()
            .all(|set| set.providers.is_empty())
            && self.packages.is_empty()
            && self.contributors.is_empty()
    }

    fn merge(&mut self, other: BinariesState) {
        self.provider_sets.extend(other.provider_sets);
        self.packages.extend(other.packages);
        for contributor in other.contributors {
            if !self.contributors.contains(&contributor) {
                self.contributors.push(contributor);
            }
        }
    }
}

/// The set of symbols one file's DT_NEEDED closure provides: walk
/// the closure from the file's direct dependencies, looking each
/// entry up in the provider index first, then the way the loader
/// locates it -- in the needing object's DT_RPATH chain and
/// DT_RUNPATH (with `$ORIGIN` expansion, against the filesystem
/// rpmcrab runs on), then on the system (`SystemLibraries`), whose
/// libraries join the closure with their own DT_NEEDED entries in
/// turn. Most libraries share the same direct dependencies and
/// search paths, so the provided set is memoised on the
/// direct-dependency list, the file's ELF class (system candidates
/// are class-matched), the file's search context, and the
/// package the file belongs to.
fn provided_by_closure(
    providers: &ProviderIndex,
    system: &SystemLibraries,
    closures: &mut HashMap<ClosureKey, Rc<HashSet<String>>>,
    direct: &[String],
    is_64: Option<bool>,
    root_ctx: &SearchContext,
    root_owner: &PackageId,
) -> Rc<HashSet<String>> {
    closures
        .entry((direct.to_vec(), is_64, root_ctx.clone(), root_owner.clone()))
        .or_insert_with(|| {
            let mut provided: HashSet<String> = HashSet::new();
            let mut visited: HashSet<(String, SearchContext, PackageId)> = HashSet::new();
            let mut stack: Vec<(String, SearchContext, PackageId)> = direct
                .iter()
                .cloned()
                .map(|need| (need, root_ctx.clone(), root_owner.clone()))
                .collect();
            while let Some((soname, ctx, owner)) = stack.pop() {
                if !visited.insert((soname.clone(), ctx.clone(), owner.clone())) {
                    continue;
                }
                // The provider's owning package travels with the
                // walk: the provider's own DT_NEEDED entries are
                // looked up from its package's point of view, so a
                // closure is built from the providers of the
                // packages that actually ship each library in it.
                let (package_provider, provider_owner) = match providers.lookup(&soname, &owner) {
                    Some((id, provider)) => (Some(provider), id),
                    None => (None, owner.clone()),
                };
                let provider = package_provider
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
                            .or_else(|| system.provider_in_dirs(&soname, is_64, &ctx.runpath_dirs))
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
                            .map(|need| (need, child_ctx.clone(), provider_owner.clone())),
                    );
                }
            }
            Rc::new(provided)
        })
        .clone()
}

/// The detail of the aggregated `undefined-non-weak-symbol` finding:
/// the count and the names of the file's undefined non-weak symbols,
/// in the parenthesised shape the aggregated findings use (the
/// per-directory aggregation of `dir-or-file-outside-snapshot`).
fn undefined_symbol_detail(symbols: &[String]) -> String {
    let noun = if symbols.len() == 1 {
        "symbol"
    } else {
        "symbols"
    };
    format!(
        "({} undefined {}: {})",
        symbols.len(),
        noun,
        symbols.join(", ")
    )
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
    owner: &PackageId,
) {
    let providers = package_providers(analyses, files);
    if providers.is_empty() && system.is_empty() {
        return;
    }
    let providers = ProviderIndex::new(vec![PackageProviders {
        pkg_name: owner.0.clone(),
        pkg_arch: owner.1.clone(),
        pkg_filename: owner.2.clone(),
        providers,
    }]);

    let mut closures: HashMap<ClosureKey, Rc<HashSet<String>>> = HashMap::new();
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
        let provided = provided_by_closure(
            &providers,
            system,
            &mut closures,
            &direct,
            is_64,
            &root_ctx,
            owner,
        );
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

/// True when `data` is a structurally valid archive in the gplib
/// dialect -- the MPLIB-compatible format gputils' `gplib` writes for
/// SDCC's PIC (pic14/pic16) targets. GNU binutils does not implement
/// the dialect, so `ar t` fails on these files even though they are
/// working libraries for their toolchain.
///
/// The dialect keeps the `!<arch>` magic but frames members its own
/// way: a 256-byte name field (the member name, terminated by `/`,
/// padded with spaces), a fixed 22-byte field of digits, `l` and
/// spaces whose last digit run is the member size, and a `! ` header
/// terminator in place of the GNU `` ` `` + newline. Object members
/// carry PIC COFF objects (magic 0x1240). An optional symbol-index
/// member named `/` may come first. The test is deliberately strict
/// -- the member chain must land exactly on EOF -- so a corrupt GNU
/// archive cannot pass it.
fn is_gplib_archive(data: &[u8]) -> bool {
    if !data.starts_with(b"!<arch>\n") {
        return false;
    }
    let mut off = 8;
    let mut members = 0;
    while off < data.len() {
        let Some(header) = data.get(off..off + 280) else {
            return false;
        };
        let (name_field, fields) = header.split_at(256);
        let Some(pad) = name_field.iter().position(|&b| b == b' ') else {
            return false;
        };
        let name = &name_field[..pad];
        if name.is_empty()
            || !name.ends_with(b"/")
            || !name.iter().all(|&b| (0x21..=0x7e).contains(&b))
            || !name_field[pad..].iter().all(|&b| b == b' ')
        {
            return false;
        }
        if !fields[..22]
            .iter()
            .all(|&b| b.is_ascii_digit() || b == b'l' || b == b' ')
        {
            return false;
        }
        // The member size is the last run of digits in the field area.
        let mut size: Option<usize> = None;
        let mut run: Option<usize> = None;
        for &b in &fields[..22] {
            if b.is_ascii_digit() {
                let digit = usize::from(b - b'0');
                let cur = run.unwrap_or(0);
                let Some(next) = cur.checked_mul(10).and_then(|v| v.checked_add(digit)) else {
                    return false;
                };
                run = Some(next);
            } else if let Some(v) = run.take() {
                size = Some(v);
            }
        }
        if let Some(v) = run {
            size = Some(v);
        }
        let Some(size) = size else {
            return false;
        };
        if &fields[22..24] != b"! " {
            return false;
        }
        let data_start = off + 280;
        let Some(end) = data_start.checked_add(size) else {
            return false;
        };
        let Some(member) = data.get(data_start..end) else {
            return false;
        };
        if name.len() == 1 && name[0] == b'/' {
            // The symbol index is only ever the first member.
            if members != 0 {
                return false;
            }
        } else if !member.starts_with(b"\x40\x12") {
            // Object members are PIC COFF objects.
            return false;
        }
        off = end;
        members += 1;
    }
    members > 0 && off == data.len()
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
    gets_call_regex: Regex,
    tmpnam_call_regex: Regex,
    gethostbyname_call_regex: Regex,

    md5_call_regex: Regex,
    des_call_regex: Regex,
    rc4_call_regex: Regex,
    weak_prng_call_regex: Regex,
    unbounded_copy_call_regex: Regex,

    shell_call_regex: Regex,

    // Per-file state, set by detect_attributes before run_elf_checks.
    is_exec: bool,
    is_shobj: bool,
    is_archive: bool,
    is_dynamically_linked: bool,
    is_pie_exec: bool,
    is_nonstandard_archive: bool,
    // Undefined-symbol resolution state (plusky/rpmcrab#701):
    // `pending_state` is the package being checked (worker side,
    // exported after each package); `deferred_state` is the merged
    // state of the whole batch (main side, resolved in
    // `after_checks`); `defer_undefined` is set by `check_binary`
    // for extracted packages -- an installed package resolves in
    // place instead.
    pending_state: Option<BinariesState>,
    deferred_state: BinariesState,
    defer_undefined: bool,
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

/// The host ELF machines for the *noarch* classification below:
/// `EM_386` and `EM_X86_64`. A noarch package has no architecture of
/// its own to classify against, and that check's standing definition
/// of the host family is x86 (an x86-64 host executes both natively).
/// The /usr/share predicate does NOT use this: it classifies against
/// the package's own architecture via `foreign_elf_machine`, so on a
/// non-x86 build the host family is that build's family.
fn is_host_elf_machine(machine: u16) -> bool {
    machine == goblin::elf::header::EM_386 || machine == goblin::elf::header::EM_X86_64
}

/// Classification of a binary's ELF machine against the host family.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ElfMachineClass {
    Host,
    Foreign,
    Unknown,
}

/// The `e_machine` in an ELF header's first 20 bytes, read in the
/// header's own byte order. `None` when the bytes carry no readable
/// ELF header (no magic, truncated, or an unknown data encoding).
fn elf_e_machine(data: &[u8]) -> Option<u16> {
    if !data.starts_with(ELF_MAGIC) || data.len() < 20 {
        return None;
    }
    match data[5] {
        1 => Some(u16::from_le_bytes([data[18], data[19]])),
        2 => Some(u16::from_be_bytes([data[18], data[19]])),
        _ => None,
    }
}

/// Classify the `e_machine` in an ELF header's first 20 bytes. `None`
/// when the bytes carry no ELF header to read.
fn elf_machine_class_from_bytes(data: &[u8]) -> Option<ElfMachineClass> {
    if !data.starts_with(ELF_MAGIC) || data.len() < 20 {
        return None;
    }
    let Some(machine) = elf_e_machine(data) else {
        return Some(ElfMachineClass::Unknown);
    };
    Some(if is_host_elf_machine(machine) {
        ElfMachineClass::Host
    } else if machine == goblin::elf::header::EM_NONE {
        ElfMachineClass::Unknown
    } else {
        ElfMachineClass::Foreign
    })
}

/// Classify an ELF by the machine the magic string names, in the
/// spellings libmagic uses. The magic carries no machine for some
/// files; those stay `Unknown`.
fn elf_machine_class_from_magic(magic: &str) -> ElfMachineClass {
    if magic.contains("x86-64") || magic.contains("Intel 80386") {
        return ElfMachineClass::Host;
    }
    const FOREIGN_TOKENS: &[&str] = &[
        "Atmel AVR",
        "ARM",
        "UCB RISC-V",
        "LoongArch",
        "PA-RISC",
        "IBM S/390",
        "PowerPC",
        "MIPS",
        "SPARC",
        "IA-64",
        "MC68000",
        "Alpha",
        "Hitachi SH",
        "AMDGPU",
        "Nios II",
        "MicroBlaze",
        "Xtensa",
        "OpenRISC",
        "Blackfin",
        "TILE",
        "ARC",
        "CSKY",
        "VAX",
        "XCore",
    ];
    if FOREIGN_TOKENS.iter().any(|t| magic.contains(t)) {
        ElfMachineClass::Foreign
    } else {
        ElfMachineClass::Unknown
    }
}

/// Classify a file's ELF machine: the extracted payload's header
/// bytes first (the payload is on disk in real runs), the magic
/// string second (it is the only evidence for a file that cannot be
/// opened, and it names the machine for the ar archives libmagic
/// reports by their first ELF member).
fn elf_machine_class(pkgfile: &PkgFile) -> ElfMachineClass {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open(&pkgfile.path) {
        let mut head = [0u8; 20];
        if f.read_exact(&mut head).is_ok()
            && let Some(class) = elf_machine_class_from_bytes(&head)
        {
            return class;
        }
    }
    elf_machine_class_from_magic(&pkgfile.magic)
}

/// ISA family of the machine a magic string names, in the spellings
/// libmagic uses, for the families `elf_machine_family` knows. A
/// magic naming a machine outside that map (or no machine) yields
/// `None`: not positive evidence of foreign payload for any arch.
fn magic_machine_family(magic: &str) -> Option<&'static str> {
    if magic.contains("x86-64") || magic.contains("Intel 80386") {
        Some("x86")
    } else if magic.contains("ARM") {
        Some("arm")
    } else if magic.contains("UCB RISC-V") {
        Some("riscv")
    } else if magic.contains("LoongArch") {
        Some("loongarch")
    } else if magic.contains("PA-RISC") {
        Some("parisc")
    } else if magic.contains("IBM S/390") {
        Some("s390")
    } else if magic.contains("PowerPC") {
        Some("ppc")
    } else if magic.contains("MIPS") {
        Some("mips")
    } else if magic.contains("SPARC") {
        Some("sparc")
    } else if magic.contains("IA-64") {
        Some("ia64")
    } else if magic.contains("MC68000") {
        Some("m68k")
    } else if magic.contains("Alpha") {
        Some("alpha")
    } else if magic.contains("Hitachi SH") {
        Some("sh")
    } else {
        None
    }
}

/// Whether a bare ELF file is foreign-target payload for a package
/// of architecture `arch`: the payload header's `e_machine` first,
/// the magic string's machine family second (the only evidence for a
/// file that cannot be opened). A machine outside the family map, or
/// an unmapped package arch, is not foreign: the exemption takes
/// positive evidence.
fn elf_is_foreign_for_arch(pkgfile: &PkgFile, arch: &str) -> bool {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open(&pkgfile.path) {
        let mut head = [0u8; 20];
        if f.read_exact(&mut head).is_ok()
            && let Some(machine) = elf_e_machine(&head)
        {
            return foreign_elf_machine(machine, arch);
        }
    }
    match (magic_machine_family(&pkgfile.magic), pkg_arch_family(arch)) {
        (Some(machine_family), Some(arch_family)) => machine_family != arch_family,
        _ => false,
    }
}

/// How the ELF members of an ar archive classify as a whole.
enum ArchiveElfClass {
    /// No member presents as an ELF object: every member is in
    /// another object format (COFF, wasm, LLVM bitcode) or is plain
    /// data, and an empty archive (the glibc placeholder archives are
    /// the bare ar header) is the limiting case, so the archive
    /// carries no ELF code at all.
    NoElfMembers,
    /// Every ELF member is for a foreign machine.
    AllForeign,
    /// An ELF member is for the host family or names no machine.
    HasHostOrUnknown,
    /// The archive bytes cannot be read or parsed, or a member the
    /// index names cannot be extracted.
    Unreadable,
}

fn archive_elf_class(pkgfile: &PkgFile) -> ArchiveElfClass {
    let Ok(data) = std::fs::read(&pkgfile.path) else {
        return ArchiveElfClass::Unreadable;
    };
    if !data.starts_with(AR_MAGIC) {
        return ArchiveElfClass::Unreadable;
    }
    let Ok(archive) = goblin::archive::Archive::parse(&data) else {
        return ArchiveElfClass::Unreadable;
    };
    let mut elf_members = 0usize;
    for i in 0..archive.len() {
        // A member the index names but that cannot be extracted
        // leaves the classification incomplete -- the unreadable
        // member may be the host-code one -- so the archive is
        // unreadable, like a member range out of bounds.
        let Some(member) = archive.get_at(i) else {
            return ArchiveElfClass::Unreadable;
        };
        // Member offsets are u64; on a 32-bit target an offset past
        // 4 GiB does not fit a usize index. Fail closed (unreadable)
        // rather than truncate into another member's bytes.
        let Ok(start) = usize::try_from(member.offset) else {
            return ArchiveElfClass::Unreadable;
        };
        let Ok(end) = usize::try_from(member.offset.saturating_add(member.size() as u64)) else {
            return ArchiveElfClass::Unreadable;
        };
        let Some(bytes) = data.get(start..end) else {
            return ArchiveElfClass::Unreadable;
        };
        if !bytes.starts_with(ELF_MAGIC) {
            continue;
        }
        elf_members += 1;
        if elf_machine_class_from_bytes(bytes) != Some(ElfMachineClass::Foreign) {
            return ArchiveElfClass::HasHostOrUnknown;
        }
    }
    if elf_members == 0 {
        ArchiveElfClass::NoElfMembers
    } else {
        ArchiveElfClass::AllForeign
    }
}

/// The second-level directories of the host `/usr` layout: the set
/// the `filesystem` package owns (bin, etc, include, lib, lib64,
/// libexec, local, sbin, share, src) plus the remaining FHS names
/// (games, lib32, libx32, tmp, X11R6). A `sys-root` component below
/// one of these is a directory inside host layout that happens to be
/// named sys-root, not a cross sys-root.
const HOST_USR_DIRS: &[&str] = &[
    "X11R6", "bin", "etc", "games", "include", "lib", "lib32", "lib64", "libexec", "libx32",
    "local", "sbin", "share", "src", "tmp",
];

/// Whether the path segment above a `sys-root` component names a
/// target prefix: a triplet (riscv64-suse-linux,
/// x86_64-w64-mingw32) carries its dashes, and a bare target name
/// (avr, the AVR toolchain's /usr/avr/sys-root; the MinGW
/// /usr/<arch>/sys-root layouts) is a single component that is not
/// a host /usr layout directory.
fn sysroot_parent_is_target_prefix(seg: &str) -> bool {
    seg.contains('-') || !HOST_USR_DIRS.contains(&seg)
}

/// Classify an archive's members against the package architecture
/// `arch`, for the /usr/share predicate, over bytes already read by
/// the caller. Like `archive_elf_class`, but ELF members are judged
/// with `foreign_elf_machine` (the package arch's family is the host
/// family), and the no-ELF-members arm is narrowed to positive
/// evidence: every payload member must be text (the measured
/// population is ASxxxx `.rel` text objects and plain text data), or
/// there must be no payload members at all. A binary member in a
/// non-ELF format (COFF, wasm, bitcode, raw data) is not evidence --
/// its target cannot be classified -- so the archive keeps firing.
/// Archive bookkeeping members (the symbol index and the long-name
/// string table) are not payload and are skipped.
fn archive_elf_class_for_arch(data: &[u8], arch: &str) -> ArchiveElfClass {
    if !data.starts_with(AR_MAGIC) {
        return ArchiveElfClass::Unreadable;
    }
    let Ok(archive) = goblin::archive::Archive::parse(data) else {
        return ArchiveElfClass::Unreadable;
    };
    let mut elf_members = 0usize;
    let mut payload_members = 0usize;
    let mut all_payload_text = true;
    for i in 0..archive.len() {
        // See `archive_elf_class`: an unextractable member or an
        // out-of-range member range leaves the classification
        // incomplete, so the archive is unreadable (fail closed).
        let Some(member) = archive.get_at(i) else {
            return ArchiveElfClass::Unreadable;
        };
        let Ok(start) = usize::try_from(member.offset) else {
            return ArchiveElfClass::Unreadable;
        };
        let Ok(end) = usize::try_from(member.offset.saturating_add(member.size() as u64)) else {
            return ArchiveElfClass::Unreadable;
        };
        let Some(bytes) = data.get(start..end) else {
            return ArchiveElfClass::Unreadable;
        };
        if matches!(
            member.extended_name(),
            "/" | "/SYM64/" | "__.SYMDEF" | "__.SYMDEF SORTED" | "//"
        ) {
            continue;
        }
        payload_members += 1;
        if bytes.starts_with(ELF_MAGIC) {
            elf_members += 1;
            match elf_e_machine(bytes) {
                Some(machine) if foreign_elf_machine(machine, arch) => {}
                _ => return ArchiveElfClass::HasHostOrUnknown,
            }
        } else if !bytes
            .iter()
            .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
        {
            all_payload_text = false;
        }
    }
    if elf_members > 0 {
        ArchiveElfClass::AllForeign
    } else if payload_members == 0 || all_payload_text {
        ArchiveElfClass::NoElfMembers
    } else {
        ArchiveElfClass::HasHostOrUnknown
    }
}

/// Whether `fname` sits in a location that holds target payload by
/// layout: a cross sys-root (`/usr/<target>/sys-root/...`, the layout
/// the MinGW sys-root predicate in FilesCheck also recognises, with
/// any target triplet or bare target prefix), a firmware directory,
/// or `/boot` -- locations whose files the boot chain or the device
/// executes and the host only stores.
fn in_target_payload_location(fname: &str) -> bool {
    if fname.starts_with("/usr/lib/firmware/")
        || fname.starts_with("/lib/firmware/")
        || fname.starts_with("/boot/")
    {
        return true;
    }
    let mut segments = fname.split('/');
    matches!(segments.next(), Some(""))
        && matches!(segments.next(), Some("usr"))
        && segments.next().is_some_and(sysroot_parent_is_target_prefix)
        && matches!(segments.next(), Some("sys-root"))
        && segments.next().is_some_and(|rest| !rest.is_empty())
}

/// Whether a binary-class file in a noarch package is foreign-target
/// payload (issue #848): an archive carrying no ELF members at all
/// holds only foreign-format objects or data, and an ELF (or an
/// archive of ELFs) for a foreign machine in a target-payload
/// location is the target's code, stored as data for a cross
/// toolchain or a device. A host-machine ELF keeps firing in every
/// location, a foreign ELF outside the target locations keeps
/// firing, and a file whose machine cannot be determined keeps
/// firing: the exemption takes positive evidence.
fn noarch_binary_is_foreign_target(pkgfile: &PkgFile) -> bool {
    if pkgfile.magic.contains("current ar archive") {
        match archive_elf_class(pkgfile) {
            ArchiveElfClass::NoElfMembers => true,
            ArchiveElfClass::AllForeign => in_target_payload_location(&pkgfile.name),
            ArchiveElfClass::HasHostOrUnknown | ArchiveElfClass::Unreadable => false,
        }
    } else if elf_regex().is_match(&pkgfile.magic).unwrap_or(false) {
        in_target_payload_location(&pkgfile.name)
            && elf_machine_class(pkgfile) == ElfMachineClass::Foreign
    } else {
        // OCaml native code and Lua bytecode carry no ELF machine to
        // classify; the finding keeps firing for them.
        false
    }
}

/// Whether a binary-class file in /usr/share is foreign-target
/// payload for a package of architecture `arch`: an ar archive whose
/// payload members are all text and which carries no ELF members at
/// all holds only foreign-format text objects or data (the sdcc
/// cross libraries are archives of ASxxxx text objects for 8-bit MCU
/// targets), an archive of foreign-machine ELFs or a bare
/// foreign-machine ELF is code for another target stored as data
/// (emulator guest firmware), and a structurally valid gplib archive
/// carries only PIC COFF objects. "Foreign" and "host" are judged
/// against the package's own architecture (`foreign_elf_machine`):
/// on an aarch64 build an AArch64 ELF is host code and keeps firing,
/// exactly as an x86-64 ELF does on an x86_64 build. Such a file's
/// bytes are the same in every architecture build of the package, so
/// the arch-independence /usr/share exists to provide is not broken
/// by it. Unlike the noarch form
/// (`noarch_binary_is_foreign_target`) there is no location
/// condition: the package here is archful, so the only question is
/// whether the file is code for the package arch's family. A
/// host-family ELF or archive member keeps firing, a binary non-ELF
/// archive member keeps firing (its target cannot be classified), an
/// archive that parses neither as GNU ar nor as a structurally valid
/// gplib archive keeps firing, and a file whose machine cannot be
/// determined keeps firing: the exemption takes positive evidence.
/// The archive is read once; the same bytes feed both the GNU walk
/// and the gplib validator.
fn usr_share_binary_is_foreign_target(pkgfile: &PkgFile, arch: &str) -> bool {
    if pkgfile.magic.contains("current ar archive") {
        let Ok(data) = std::fs::read(&pkgfile.path) else {
            return false;
        };
        match archive_elf_class_for_arch(&data, arch) {
            ArchiveElfClass::NoElfMembers | ArchiveElfClass::AllForeign => true,
            ArchiveElfClass::HasHostOrUnknown => false,
            ArchiveElfClass::Unreadable => {
                // The MPLIB dialect (the gplib archives SDCC ships
                // for its pic14/pic16 targets) cannot be walked as
                // GNU ar, so it lands here even though it is a
                // working library -- the same dialect the ar-failed
                // gate credits through this validator. The gplib
                // structural validator is the positive evidence
                // instead: a valid gplib archive's object members
                // are all PIC COFF, so it carries no ELF members at
                // all. An archive that parses neither way keeps
                // firing.
                is_gplib_archive(&data)
            }
        }
    } else if elf_regex().is_match(&pkgfile.magic).unwrap_or(false) {
        elf_is_foreign_for_arch(pkgfile, arch)
    } else {
        // OCaml native code and Lua bytecode carry no ELF machine to
        // classify; the finding keeps firing for them.
        false
    }
}

/// Whether a binary-class file in a noarch package is a GRUB module:
/// an `ET_REL` object for a host machine carrying GRUB's
/// `.module_license` ABI section and not defining the `grub_main`
/// entry point. A GRUB module is loadable only inside GRUB itself --
/// it is the bootloader's payload, not host code -- so the
/// foreign-target gate's host-machine rule, which guards runnable
/// and linkable host binaries, does not reach it: a module is
/// neither. The signature is the measured one over the grub2
/// family's 2,682 module files in the Factory corpus: every module,
/// the final `.mod` files and the debug packages' `.module`
/// intermediates alike, is a host-machine relocatable carrying
/// `.module_license`, the ABI section GRUB's build stamps into each
/// module object. The sibling ABI sections cannot serve: `.modname`
/// and `.moddeps` are added only when a module is finalised (the
/// debug intermediates carry neither), and `.moddeps` is present
/// only on modules that have dependencies. GRUB's linked kernel
/// images are the one other relocatable output carrying the
/// section -- the EFI platform kernels are ET_REL -- and they
/// define `grub_main`, which no module defines, so a file defining
/// it keeps firing; so do the ET_EXEC core images, the section-less
/// intermediate objects (efiemu's) and an ordinary host `.o`, which
/// carries no GRUB section at all. The exemption takes the full
/// signature from the payload bytes; a file that cannot be read or
/// parsed keeps firing.
///
/// The signature's parts are exact, not nominal: the license
/// section must be a `PROGBITS` section with content (the stamp
/// GRUB's build emits carries the licence string), and the
/// not-defining test must be decidable -- it reads the symbol
/// table, so a file with no `SHT_SYMTAB` fails closed and keeps
/// firing, with one exception: an object carrying no executable
/// content at all cannot define an entry point, symtab or not.
/// The corpus's three symtab-less modules (the `all_video`
/// aggregators and `linuxefi`) are that shape -- link-only modules
/// whose `.text` is empty. A defined `grub_main` is recognised in
/// the symtab and the dynsym alike, under its plain name and under
/// a versioned spelling (`grub_main@...`); an undefined import of
/// the name is not a definition and does not block the credit.
fn noarch_binary_is_grub_module(pkgfile: &PkgFile) -> bool {
    let Ok(data) = std::fs::read(&pkgfile.path) else {
        return false;
    };
    let Ok(elf) = parse_elf(&data) else {
        return false;
    };
    if elf.header.e_type != goblin::elf::header::ET_REL
        || !is_host_elf_machine(elf.header.e_machine)
    {
        return false;
    }
    if !elf.section_headers.iter().any(|sh| {
        elf.shdr_strtab.get_at(sh.sh_name) == Some(".module_license")
            && sh.sh_type == goblin::elf::section_header::SHT_PROGBITS
            && sh.sh_size > 0
    }) {
        return false;
    }
    let has_symtab = elf
        .section_headers
        .iter()
        .any(|sh| sh.sh_type == goblin::elf::section_header::SHT_SYMTAB);
    if !has_symtab {
        // Fail closed: without a symbol table the not-defining test
        // is undecidable. The one credited shape is an object with
        // no executable content, which cannot define the entry
        // point; anything carrying code keeps firing.
        let has_exec_content = elf.section_headers.iter().any(|sh| {
            sh.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0
                && sh.sh_size > 0
        });
        return !has_exec_content;
    }
    !elf.syms.iter().any(|sym| {
        sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize
            && is_grub_main_name(elf.strtab.get_at(sym.st_name))
    }) && !dynsym_section_defines_grub_main(&elf, &data)
}

/// Whether the file's `SHT_DYNSYM` section defines `grub_main`.
/// The parser's own dynsym view is populated from the dynamic
/// segment, which relocatable images do not carry, so the section
/// is read directly; an unreadable section counts as not defining
/// (the symtab test above is the primary one, and its absence
/// already fails closed).
fn dynsym_section_defines_grub_main(elf: &goblin::elf::Elf, data: &[u8]) -> bool {
    use goblin::elf::section_header::{SHN_UNDEF, SHT_DYNSYM};

    let Some(sh) = elf
        .section_headers
        .iter()
        .find(|sh| sh.sh_type == SHT_DYNSYM)
    else {
        return false;
    };
    let Some(str_sh) = elf.section_headers.get(sh.sh_link as usize) else {
        return false;
    };
    let Ok(strtab) =
        goblin::strtab::Strtab::parse(data, str_sh.sh_offset as usize, str_sh.sh_size as usize, 0)
    else {
        return false;
    };
    let Ok(container) = elf.header.container() else {
        return false;
    };
    let Ok(endian) = elf.header.endianness() else {
        return false;
    };
    let ctx = goblin::container::Ctx::new(container, endian);
    let entsize = if sh.sh_entsize > 0 {
        sh.sh_entsize
    } else if elf.is_64 {
        24
    } else {
        16
    };
    let Ok(syms) = goblin::elf::sym::Symtab::parse(
        data,
        sh.sh_offset as usize,
        (sh.sh_size / entsize) as usize,
        ctx,
    ) else {
        return false;
    };
    syms.iter().any(|sym| {
        sym.st_shndx != SHN_UNDEF as usize && is_grub_main_name(strtab.get_at(sym.st_name))
    })
}

/// Whether a symbol name is the `grub_main` entry point, plain or
/// under a versioned spelling (`grub_main@VERSION`).
fn is_grub_main_name(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    name == "grub_main" || name.starts_with("grub_main@")
}

/// Collect the forbidden-function calls one file makes: for every
/// `WarnOnFunction` config entry whose function pattern matches the
/// file's symbols, the finding name, the function name and the
/// compiled `good_param` waiver pattern.
fn forbidden_function_calls(
    info: &ReadelfInfo,
    config: &Config,
) -> Vec<(String, String, Option<Regex>)> {
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
    let mut forbidden_calls = Vec::new();
    for (r_name, f_name, f_regex, good_param) in &forbidden {
        if info.has_function_matching(f_regex) {
            forbidden_calls.push((r_name.clone(), f_name.clone(), good_param.clone()));
        }
    }
    forbidden_calls
}

/// Emit the findings for one file's forbidden-function calls from its
/// collected `strings` output: a failed `strings` run reports
/// `strings-failed`; otherwise each call warns unless a string in the
/// output matches the entry's `good_param` waiver pattern.
fn report_forbidden_functions(
    pkg: &Pkg,
    pkgfile: &PkgFile,
    forbidden_calls: &[(String, String, Option<Regex>)],
    strings: &StringsInfo,
    out: &mut Filter,
) {
    if let Some(reason) = &strings.failed {
        add_info(
            out,
            Level::Error,
            pkg,
            "strings-failed",
            &[&pkgfile.name, reason],
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
            add_info(out, Level::Warning, pkg, r_name, &[&pkgfile.name, f_name]);
        }
    }
}

/// The embedded table of known native-layout data formats
/// (`data/arch-format-magics.toml`): on-disk structures whose byte
/// layout depends on the word size of the machine that wrote them.
/// Baked in like the defect-pattern registry so an installed binary
/// needs no data dir next to it; the table's as-of date and the
/// evidence for each entry are recorded in the file itself.
const ARCH_FORMAT_MAGICS_TOML: &str = include_str!("../../data/arch-format-magics.toml");

/// The parsed magic prefixes, parsed once (the
/// `defect_pattern::registry` pattern).
fn arch_format_magics() -> &'static [Vec<u8>] {
    static MAGICS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    MAGICS.get_or_init(|| parse_arch_format_magics(ARCH_FORMAT_MAGICS_TOML))
}

/// Parse and validate the magic table. Validation takes the
/// staged-data posture (the registry's): a malformed table panics at
/// startup instead of silently disabling the exemption.
fn parse_arch_format_magics(raw: &str) -> Vec<Vec<u8>> {
    let table: toml::Table = raw.parse().expect("arch-format magics are valid TOML");
    assert!(
        table.get("as_of").and_then(toml::Value::as_str).is_some(),
        "arch-format magics record an as_of date"
    );
    let records = table
        .get("format")
        .and_then(toml::Value::as_array)
        .expect("arch-format magics have a [[format]] array");
    assert!(!records.is_empty(), "arch-format magics are not empty");
    records
        .iter()
        .map(|record| {
            let hex = record
                .get("magic")
                .and_then(toml::Value::as_str)
                .expect("arch-format magic entry has a magic string");
            assert!(
                !hex.is_empty() && hex.len() % 2 == 0,
                "arch-format magic is whole bytes: {hex:?}"
            );
            (0..hex.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&hex[i..i + 2], 16)
                        .unwrap_or_else(|_| panic!("arch-format magic is hex: {hex:?}"))
                })
                .collect::<Vec<u8>>()
        })
        .collect()
}

/// Whether any payload file of `pkg` is data in a known native-layout
/// format (see `data/arch-format-magics.toml`). Such a file is bound
/// to the architecture class of the machine that wrote it, so its
/// presence is positive evidence that the package's arch marking is
/// deliberate rather than a forgotten `noarch` -- the case
/// `check_no_binary` exists to catch. Only regular files with an
/// on-disk payload count: a ghost entry has no bytes to read, and a
/// symlink's bytes name its target rather than carrying data.
fn pkg_has_arch_format_data(pkg: &Pkg) -> bool {
    use std::io::Read;
    let magics = arch_format_magics();
    let width = magics.iter().map(Vec::len).max().unwrap_or(0);
    pkg.files.iter().any(|pkgfile| {
        if pkgfile.is_ghost()
            || !crate::pkg::pkgfile::is_reg(pkgfile.mode)
            || crate::pkg::pkgfile::is_symlink(pkgfile.mode)
        {
            return false;
        }
        let Ok(mut fh) = std::fs::File::open(&pkgfile.path) else {
            return false;
        };
        let mut head = vec![0u8; width];
        let mut filled = 0;
        while filled < width {
            match fh.read(&mut head[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => return false,
            }
        }
        head.truncate(filled);
        magics
            .iter()
            .any(|magic| head.len() >= magic.len() && &head[..magic.len()] == magic.as_slice())
    })
}

/// Privilege gate (#959): the file itself runs with raised
/// privileges -- setuid or setgid bits, or file capabilities.
fn file_is_privileged(pkgfile: &PkgFile) -> bool {
    pkgfile.mode & (0o4000 | 0o2000) != 0
        || pkgfile
            .filecaps
            .as_deref()
            .is_some_and(|caps| !caps.is_empty())
}

/// Exposure gate (#959): the package ships a systemd service or
/// socket unit, so its binaries form daemon surface. Only units in
/// the package's own file list count, and only `.service`/`.socket`
/// under one of the systemd unit directories -- a D-Bus activation
/// file under share/dbus-1/services is not a daemon unit. Three
/// shapes do not count (#969 follow-up): a `%ghost` unit entry (the
/// package declares the path but ships no unit), a masked unit (a
/// symlink to /dev/null: the name is occupied precisely so that no
/// unit loads), and a path that merely contains a unit directory
/// as a substring (a documentation example under share/doc), so
/// the test is on the unit-directory prefixes systemd searches.
fn pkg_ships_daemon_units(pkg: &Pkg) -> bool {
    const UNIT_DIRS: [&str; 5] = [
        "/usr/lib/systemd/system/",
        "/lib/systemd/system/",
        "/etc/systemd/system/",
        "/run/systemd/system/",
        "/usr/local/lib/systemd/system/",
    ];
    pkg.files.iter().any(|f| {
        UNIT_DIRS.iter().any(|dir| f.name.starts_with(dir))
            && (f.name.ends_with(".service") || f.name.ends_with(".socket"))
            && !f.is_ghost()
            && !pkg.ghost_files.iter().any(|g| g == &f.name)
            && !(is_symlink(f.mode) && f.linkto == "/dev/null")
    })
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
        // The reference matches each PieExecutables pattern with
        // `regex.fullmatch(bin_name)`, so anchor the compiled patterns:
        // an unanchored search would also charge paths that merely
        // contain a listed name (e.g. /usr/bin/ssh-authorized-keys
        // containing /usr/bin/ssh, or /usr/bin/susedialog containing
        // /usr/bin/su) at error severity instead of the suggestion.
        // `\A`/`\z` rather than `^`/`$`: `$` also matches before a
        // trailing newline and `^` goes line-anchored under an embedded
        // `(?m)`, neither of which `fullmatch` permits.
        let pie_exec_regexes: Vec<Regex> = get_strings("PieExecutables")
            .iter()
            .filter_map(|r| Regex::new(&format!(r"\A(?:{r})\z")).ok())
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
            // Anchored at the start, unlike the reference's searched
            // regexp: the charged symbol must BE mktemp (optionally
            // version-decorated), not merely end with it — project
            // wrappers such as netsnmp_mktemp are their own functions,
            // not calls to the libc mktemp (fix-and-diverge; see the
            // divergences ledger).
            mktemp_call_regex: MKTEMP_CALL_REGEX
                .get_or_init(|| Regex::new(r"^(mktemp(?:@GLIBC\S+)?)(?:\s|$)")
                    .expect("static regex"))
                .clone(),
            gets_call_regex: GETS_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"^gets(?:@GLIBC\S+)?$").expect("static regex")
                })
                .clone(),
            tmpnam_call_regex: TMPNAM_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"^(tmpnam|tmpnam_r|tempnam)(?:@GLIBC\S+)?$")
                        .expect("static regex")
                })
                .clone(),
            gethostbyname_call_regex: GETHOSTBYNAME_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(
                        r"((gethostbyname|gethostbyname2|gethostbyaddr|gethostbyname_r|gethostbyname2_r|gethostbyaddr_r)(?:@GLIBC\S+)?)(?:\s|$)",
                    )
                    .expect("static regex")
                })
                .clone(),

            md5_call_regex: MD5_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(
                        r"^((MD5|MD5_Init|MD5_Update|MD5_Final|MD5_Transform)(?:@\S+)?)(?:\s|$)",
                    )
                    .expect("static regex")
                })
                .clone(),
            weak_prng_call_regex: WEAK_PRNG_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(
                        r"^((drand48_r|drand48|erand48_r|erand48|lrand48_r|lrand48|nrand48_r|nrand48|mrand48_r|mrand48|jrand48_r|jrand48|seed48_r|seed48|lcong48_r|lcong48|srand48_r|srand48|initstate_r|setstate_r|initstate|setstate|srandom_r|srandom|random_r|random|srand|rand_r|rand)(?:@GLIBC\S+)?)(?:\s|$)",
                    )
                    .expect("static regex")
                })
                .clone(),
            unbounded_copy_call_regex: UNBOUNDED_COPY_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(
                        r"^((strcpy|strcat|sprintf|vsprintf)(?:@GLIBC\S+)?)(?:\s|$)",
                    )
                    .expect("static regex")
                })
                .clone(),
            des_call_regex: DES_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"^((DES_[A-Za-z0-9_]+)(?:@\S+)?)(?:\s|$)").expect("static regex")
                })
                .clone(),
            rc4_call_regex: RC4_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"^((RC4|RC4_set_key|RC4_options)(?:@\S+)?)(?:\s|$)")
                        .expect("static regex")
                })
                .clone(),

            shell_call_regex: SHELL_CALL_REGEX
                .get_or_init(|| {
                    Regex::new(r"^((system|popen)(?:@GLIBC\S+)?)(?:\s|$)")

                        .expect("static regex")
                })
                .clone(),
            is_exec: false,
            is_shobj: false,
            is_archive: false,
            is_dynamically_linked: false,
            is_pie_exec: false,
            is_nonstandard_archive: false,
            pending_state: None,
            deferred_state: BinariesState::default(),
            defer_undefined: false,
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

    fn check_binary_in_noarch(&self, pkg: &Pkg, pkgfile: &PkgFile, out: &mut Filter) {
        if pkg.arch == "noarch"
            && !noarch_binary_is_foreign_target(pkgfile)
            && !noarch_binary_is_grub_module(pkgfile)
        {
            add_info(
                out,
                Level::Error,
                pkg,
                "arch-independent-package-contains-binary-or-object",
                &[&pkgfile.name],
            );
        }
    }

    fn check_binary_in_usr_share(&self, pkg: &Pkg, pkgfile: &PkgFile, out: &mut Filter) {
        let bin_name: &str = &pkgfile.name;
        if bin_name.starts_with("/usr/share/")
            && !usr_arch_share_regex().is_match(bin_name).unwrap_or(false)
            && !usr_share_binary_is_foreign_target(pkgfile, &pkg.arch)
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
        // Separate debuginfo carries the debug symbols by design, so
        // "not stripped" states nothing about it: the finding stays
        // quiet there -- the treatment `check_hardening` applies to
        // its findings. The `.debug` suffix covers the name-based
        // half; the path covers the rest of the canonical debuginfo
        // location (e.g. ovmf's GdbSyms.dll).
        if bin_name.ends_with(".debug") || bin_name.starts_with("/usr/lib/debug/") {
            return;
        }
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
                // the compiled patterns are anchored at construction,
                // giving the reference's fullmatch semantics
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
        // A -debugsource package ships only source files under
        // /usr/src/debug by construction, so an arch package of that
        // shape with no binaries is the expected shape, not a defect.
        // The suffix test matches the debug-companion recognition
        // FilesCheck and FilelistCheck use (plusky/rpmcrab#948).
        // Payload in a known native-layout data format (an X11
        // compose cache, a GDBM database) is bound to the build
        // architecture, so a package shipping it is arch-specific by
        // design even without binaries (boo#1110020).
        if !has_binary
            && !has_file_in_libdir
            && pkg.arch != "noarch"
            && !pkg.name.ends_with("-debugsource")
            && !pkg_has_arch_format_data(pkg)
        {
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
            // A structurally valid gplib archive (the MPLIB-compatible
            // dialect gputils writes for SDCC's PIC targets) is a
            // working library for its toolchain; GNU `ar` cannot read
            // the dialect, but that is a format difference, not
            // corruption. Treat it as a non-standard archive, like the
            // `.bca` case above, instead of charging ar-failed.
            if std::fs::read(&pkgfile.path).is_ok_and(|data| is_gplib_archive(&data)) {
                return false;
            }
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
        // The finding charges an archive built with LTO but without
        // -ffat-lto-objects, so candidacy requires LTO content among
        // the members: a `.gnu.lto_` section (GCC) or an `.llvmbc`
        // embedded-bitcode section (LLVM) in an ELF member. An archive
        // whose ELF members carry no LTO content -- a plain library of
        // data-only objects, such as the GUID libraries wine ships for
        // its Unix side -- has no text to miss. Members in other object
        // formats neither confer nor block candidacy (see
        // `parse_archive`): the ELF members decide.
        let has_lto_content = info
            .sections
            .iter()
            .flatten()
            .any(|s| s.name.contains(".gnu.lto_.") || s.name == ".llvmbc");
        if !has_lto_content {
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
        // An archive with no members has nothing an index could
        // index and nothing a symtab could describe: glibc's
        // post-2.34 merged-library stubs (libpthread.a, libdl.a,
        // ...) are empty placeholder archives shipped so the old
        // `-l` names keep resolving to libc, and they link
        // vacuously. The finding's premise -- a linkable library
        // gutted of its symtab -- cannot hold there. The sibling
        // debuginfo check stays quiet on the same shape through
        // its no-code-carrying-member gate (plusky/rpmcrab#847).
        if info.no_members {
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
        // The finding is charged only when the archive carries host
        // machine code that debuginfo could describe (plusky/rpmcrab#847).
        // An archive with no code-carrying member at all -- an empty
        // placeholder archive (glibc's post-2.34 linker stubs), an
        // import library whose members are zero-filled relocation
        // slots (the wine family), a stub archive whose members carry
        // no executable section (compiler-rt preinit archives) -- has
        // nothing that could hold DWARF. An archive whose code is all
        // for a foreign machine (a cross archive, e.g. AVR objects in
        // a package built for the host arch) belongs to the foreign
        // target's debuginfo handling, not the host package's. An
        // unmapped package arch charges any code, as before.
        let host = host_elf_machines(&pkg.arch);
        if !info
            .code_machines
            .iter()
            .any(|m| host.is_empty() || host.contains(m))
        {
            return;
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
        use goblin::elf::header::{ET_DYN, ET_EXEC};
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
            // PT_GNU_STACK is a programme header, and its absence is a
            // statement about how a binary was linked only where the
            // file is a linked image carrying a programme header table
            // for the header to be absent from (plusky/rpmcrab#850): a
            // relocatable object carries no programme headers by
            // construction, and a linked-type file without a table is
            // not a loadable image. Separate debuginfo is never loaded
            // by the dynamic linker, so the absence states nothing
            // there either: `is_debug` covers the `.debug` name suffix
            // and the path covers the canonical debuginfo location --
            // the treatment `check_hardening` already applies to its
            // findings. A linked image built for a different
            // instruction set than the package architecture is payload
            // for another machine (guest firmware, a cross helper):
            // the package arch's dynamic linker never loads it, so
            // the absence states nothing there either.
            if (info.elf_type == ET_EXEC || info.elf_type == ET_DYN)
                && !info.program_headers.is_empty()
                && !info.is_debug
                && !pkgfile.name.starts_with("/usr/lib/debug/")
                && !foreign_elf_machine(info.elf_machine, &pkg.arch)
            {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "missing-PT_GNU_STACK-section",
                    &[&pkgfile.name],
                );
            }
        } else if stack_headers[0].flags.contains('E')
            && !foreign_elf_machine(info.elf_machine, &pkg.arch)
        {
            // The marking is charged only where it takes effect: on
            // an image the package arch's dynamic linker loads, an
            // explicitly executable stack is a link decision with
            // live effect on the host. A linked image built for a
            // different instruction set is payload for another
            // machine (guest firmware, a cross helper): the emulator
            // maps it as data into guest memory, and its GNU_STACK
            // flags state the target ABI's conventions, not this
            // package's hardening.
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

    /// The package-name arm of the shared-library policy: the
    /// package name is judged against the names derived from the
    /// SONAME (`shlib-policy-name-error`). `pkgversion` is the
    /// SONAME's `-<version>` component before `.so` (empty when it
    /// has none) and `soversion` its version after `.so.` -- the
    /// numeric capture for a SONAME that passes the validity gate,
    /// or the whole non-numeric tail for one admitted by the tail
    /// rule of issue #1029.
    fn check_shlib_name(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        soname: &str,
        pkgversion: &str,
        soversion: &str,
        out: &mut Filter,
    ) {
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
        //
        // Two further derived forms are credited on
        // limb A only (the stripped or reduced name
        // must equal a SONAME-derived name exactly;
        // limb B's stem-blind suffix is not enough):
        //
        // (C) A trailing flavour segment of letters
        // only (-opencl, -mini, -dummy): the same
        // flavour shape as above with no digit in
        // the tail (libarmnn36-opencl ships
        // libarmnn.so.36, libuna1-mini ships
        // libuna.so.1). Limb A only, so a name whose
        // own stem merely ends in the version
        // (libqt5-qtwebengine for libQt5WebEngine.so.5)
        // still fires.
        //
        // (D) A SONAME version whose trailing
        // components are all zero, with the zeros
        // elided: libprotobuf.so.3.21.12.0 is
        // packaged as libprotobuf3_21_12 and
        // libCppMicroServices.so.4.0.0 as
        // libCppMicroServices4. A dropped zero
        // carries no ABI discrimination — any
        // non-zero change to the elided components
        // re-fires — while a partially elided form
        // (libfoo4_0 for libfoo.so.4.0.0) still
        // fires.
        let stem = match soname.split_once(".so") {
            Some((head, _)) => head,
            None => soname,
        }
        .replace('.', "_");
        let soversion_pkgform = soversion.replace('.', "_");
        let mut expected: Vec<String> = if pkgversion.is_empty() {
            vec![
                format!("{stem}{soversion_pkgform}"),
                format!("{stem}-{soversion_pkgform}"),
            ]
        } else if soversion.is_empty() {
            vec![stem.clone()]
        } else {
            vec![format!("{stem}-{soversion_pkgform}")]
        };
        // (D) The trailing-zero-elided derived
        // names: drop trailing ".0" components of
        // the SONAME version (keeping at least one)
        // and derive again by the same construction.
        let mut reduced: Vec<&str> = soversion.split('.').collect();
        while reduced.len() > 1 && reduced.last() == Some(&"0") {
            reduced.pop();
        }
        let reduced_form = reduced.join("_");
        if reduced_form != soversion_pkgform {
            if pkgversion.is_empty() {
                expected.push(format!("{stem}{reduced_form}"));
                expected.push(format!("{stem}-{reduced_form}"));
            } else if !soversion.is_empty() {
                expected.push(format!("{stem}-{reduced_form}"));
            }
        }
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
        fn strip_alpha_flavour(name: &str) -> Option<&str> {
            let (head, tail) = name.rsplit_once('-')?;
            if !head.is_empty() && !tail.is_empty() && tail.chars().all(|c| c.is_ascii_alphabetic())
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
        let accepts =
            |name: &str| expected.iter().any(|e| e == name) || whole_suffix(name, &soversion_str);
        let derived_only = |name: &str| expected.iter().any(|e| e == name);
        let name_matches = accepts(pkgname)
            || strip_flavour(pkgname).is_some_and(accepts)
            || strip_alpha_flavour(pkgname).is_some_and(derived_only);
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

    /// The two SONAME arms of the shared-library policy: the
    /// ldconfig-symlink arm and the package-name arm. They run for
    /// a SONAME that passes the validity gate, and -- since issue
    /// #1029 -- also for one whose version tail is non-numeric (see
    /// `soname_tail`), where the whole tail is taken as the
    /// soversion: the existing `.` -> `_` folding derives
    /// `libLimeSuite23_11-1` from the tail `23.11-1` and
    /// `libstemmer0d` from `0d`, where the numeric capture would
    /// stop at the first non-digit.
    fn check_soname_arms(&self, pkg: &Pkg, pkgfile: &PkgFile, soname: &str, out: &mut Filter) {
        self.check_soname_symlink(pkg, &pkgfile.name, soname, out);
        if pkg.name.starts_with("lib")
            && !self
                .hpc_locations()
                .iter()
                .any(|p| pkgfile.name.starts_with(p))
        {
            if validso_regex().is_match(soname).unwrap_or(false) {
                if let Ok(Some(caps)) = soversion_regex().captures(soname) {
                    let pkgversion = caps.name("pkgversion").map(|m| m.as_str()).unwrap_or("");
                    let soversion = caps.name("soversion").map(|m| m.as_str()).unwrap_or("");
                    self.check_shlib_name(pkg, pkgfile, soname, pkgversion, soversion, out);
                }
            } else if let Some(tail) = soname_tail(soname) {
                self.check_shlib_name(pkg, pkgfile, soname, "", tail, out);
            }
        }
    }

    /// Issue #1029, SONAME arm (b): a regular ELF file that the
    /// shared-library file-name test misses can still be a shipped
    /// library under a decorated SONAME spelling -- the real file
    /// behind its SONAME symlink (`libstemmer.so.0d.0.0` for SONAME
    /// `libstemmer.so.0d`), or the SONAME-named file itself when no
    /// dotted-digit spelling exists (`libLimeSuite.so.23.11-1`,
    /// `libSDL_bgi.so.suse0`). Such a file gets the two SONAME arms
    /// and nothing else: `is_shlib` is unchanged, so the symbol,
    /// hash-section and non-PIC findings do not widen to it. The
    /// basename must be the SONAME, or the SONAME followed by a `.`
    /// suffix, which keeps a file like `libclang.so.22.0.0.rocm`
    /// (whose SONAME `libclang.so.22.0.rocm` is not a prefix of its
    /// name) outside.
    fn check_soname_tail_library(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        let Some(soname) = &info.soname else {
            return;
        };
        if soname_tail(soname).is_none()
            || !is_reg(pkgfile.mode)
            || info.is_debug
            || pkgfile.name.starts_with("/usr/lib/debug/")
            || !in_lib_dir(&pkgfile.name)
            || !basename_is_soname(&pkgfile.name, soname)
        {
            return;
        }
        self.check_soname_arms(pkg, pkgfile, soname, out);
    }

    fn check_shared_library(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        if !info.is_shlib {
            self.check_soname_tail_library(pkg, pkgfile, info, out);
            return;
        }
        match &info.soname {
            None => {
                add_info(out, Level::Warning, pkg, "no-soname", &[&pkgfile.name]);
            }
            Some(soname) => {
                if validso_regex().is_match(soname).unwrap_or(false)
                    || soname_tail(soname).is_some()
                {
                    self.check_soname_arms(pkg, pkgfile, soname, out);
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
        &mut self,
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
            if self.defer_undefined {
                // Captured for the invocation-wide resolution in
                // `after_checks` (plusky/rpmcrab#701); this gate is
                // the only capture point, so a record exists
                // exactly where the finding could fire. A file
                // with no undefined symbols has nothing to resolve,
                // so it is not captured: its symbol lists would be
                // cloned into the state only to be skipped in
                // `after_checks`.
                if !ldd.undefined_symbols.is_empty() {
                    let state = self
                        .pending_state
                        .get_or_insert_with(BinariesState::default);
                    if !matches!(
                        state.packages.last(),
                        Some(record) if record.pkg_name == pkg.name
                            && record.pkg_arch == pkg.arch
                            && record.pkg_filename == pkg.filename
                    ) {
                        state.packages.push(PackageConsumers {
                            pkg_name: pkg.name.clone(),
                            pkg_arch: pkg.arch.clone(),
                            pkg_filename: pkg.filename.clone(),
                            files: Vec::new(),
                        });
                    }
                    if let Some(record) = state.packages.last_mut() {
                        record.files.push(ConsumerFile {
                            file_name: pkgfile.name.clone(),
                            undefined_symbols: ldd.undefined_symbols.clone(),
                            // Only the intersection is kept
                            // (issue #799): `after_checks` tests
                            // membership for the consumer's own
                            // undefined symbols, so a defined symbol
                            // outside that set is never consulted.
                            defined_symbols: {
                                let undefined: HashSet<&str> =
                                    ldd.undefined_symbols.iter().map(String::as_str).collect();
                                ldd.defined_symbols
                                    .iter()
                                    .filter(|sym| undefined.contains(sym.as_str()))
                                    .cloned()
                                    .collect()
                            },
                            dependencies: ldd.dependencies.clone(),
                            is_64: ldd.is_64,
                            rpath: ldd.rpath.clone(),
                            runpath: ldd.runpath.clone(),
                            has_runpath: ldd.has_runpath,
                        });
                    }
                }
            } else if !ldd.undefined_symbols.is_empty() {
                let detail = undefined_symbol_detail(&ldd.undefined_symbols);
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "undefined-non-weak-symbol",
                    &[&pkgfile.name, &detail],
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
        // An archive charges only a reference: its members are separate
        // objects, so the member that defines mktemp (newlib's libc.a
        // carries the definition in libc_a-mktemp.o) makes no call and
        // stays silent. A linked object — an executable or a shared
        // library — charges any match, defined or not: a statically
        // linked executable bundling mktemp and a wrapper library that
        // defines and calls its own variant both carry the definition
        // with no undefined reference, and the reference counts every
        // FUNC symbol there (fix-and-diverge scoped to archives, #852).
        let mktemp = if self.is_archive {
            info.has_undefined_function_matching(&self.mktemp_call_regex)
        } else {
            info.has_function_matching(&self.mktemp_call_regex)
        };
        // gets (#972): the charge is the undefined reference itself,
        // in archives and linked objects alike. gets reads a line
        // into a caller buffer with no bound -- CWE-242's defining
        // call, removed from C11 and POSIX.1-2024, kept by glibc only
        // as a binary-compatibility symbol. There is no safe use and
        // no gated form: the pattern is a tripwire, and the corpus
        // measurement behind this finder found the population at
        // zero. A definition is never charged (glibc's libc defines
        // gets; the provider is not a caller), and the fortified
        // __gets_chk -- a different symbol with a checked bound --
        // does not match the anchored pattern. STT_NOTYPE dynsym
        // imports land only in `undefined_functions` (fill_from_elf),
        // so that set is scanned too (#1045).
        let gets = info.has_undefined_function_matching(&self.gets_call_regex)
            || info
                .undefined_functions
                .iter()
                .any(|s| self.gets_call_regex.is_match(s).unwrap_or(false));
        // tmpnam family (#972): the charge is the undefined reference
        // itself, in archives and linked objects alike. All three names
        // (tmpnam, tmpnam_r, tempnam) return a caller-chosen file NAME
        // rather than an open descriptor, so the name-to-open interval
        // is the CWE-377 race call-to-mktemp charges, and glibc's own
        // linker warning records the family's no-safe-use verdict. A
        // definition is never charged: the library that implements
        // the family (glibc's libc carries the definitions) is the
        // provider, not a caller -- the definition-is-not-a-call line
        // the mktemp scoping draws for archives (#852), applied here
        // to every object kind, so this finder does not import the
        // defined-match overreach the family tightening removes.
        let tmpnam = info.has_undefined_function_matching(&self.tmpnam_call_regex);
        let gethostbyname = info.has_function_matching(&self.gethostbyname_call_regex);
        // Legacy crypto primitives (#972 candidate 6): undefined
        // references to the low-level OpenSSL-style entry points.
        // The reference is the predicate -- the implementing
        // libraries define these symbols and stay silent. Warning
        // only: the artefact cannot tell a security use (credential
        // storage, confidentiality) from a benign one (a checksum
        // over public data), and the corpus classification in #972
        // shows both. The regexes are anchored: EVP_MD5 and friends
        // are the policy-controlled high-level interface, not this
        // pattern.
        let md5 = info.has_undefined_function_matching(&self.md5_call_regex);
        let des = info.has_undefined_function_matching(&self.des_call_regex);
        let rc4 = info.has_undefined_function_matching(&self.rc4_call_regex);
        // Weak PRNG family (#972 candidate 7): undefined references
        // to rand/random and the *48 generators. Charged only inside
        // the privilege-or-exposure gate -- the bare population stays
        // silent, because outside a privileged or daemon context the
        // the family's dominant uses are jitter, retry backoff and
        // identifier uniqueness.
        // Warning inside the gate too: the artefact cannot tell a
        // security value (session id, password salt, token) from
        // jitter, and the gated corpus population is dominated by
        // the benign uses. The regex is anchored: arc4random and
        // getrandom are strong sources, not this pattern.
        let weak_prng = info.has_undefined_function_matching(&self.weak_prng_call_regex)
            && (file_is_privileged(pkgfile) || pkg_ships_daemon_units(pkg));
        // An undefined reference charges the call (#972 candidate 4):
        // the definition site -- glibc itself, or a library shipping
        // its own variant -- makes no call and stays silent, unlike
        // call-to-mktemp's linked-object rule (#852), whose subject
        // has no implementation library in the distribution. The
        // fortified __*_chk spellings do not match the regex: they
        // are the checked form of the same calls. Warning only --
        // whether a call overflows depends on the destination size
        // at the call site, which the binary cannot decide, so the
        // gated population measured in #972 earns no Error form.
        // The second disjunct covers dynsym imports typed STT_NOTYPE:
        // fill_from_elf files those only under `undefined_functions`,
        // never under the FUNC-only `undefined_function_refs`.
        let unbounded_copy = info.has_undefined_function_matching(&self.unbounded_copy_call_regex)
            || info
                .undefined_functions
                .iter()
                .any(|s| self.unbounded_copy_call_regex.is_match(s).unwrap_or(false));

        if setgid && setuid && !setgroups {
            // Warning unconditionally (fix-and-diverge, #743). The
            // reference splits the level on the setuid bit (E when
            // installed setuid, W otherwise). The symbol pattern
            // cannot distinguish an identity switch that neglects
            // setgroups from the safe idiom that drops the effective
            // ids to the real ids (util-linux drop_permissions()),
            // so an Error breaks builds on bogus findings; the
            // finding stays as a human-review signal.
            add_info(
                out,
                Level::Warning,
                pkg,
                "missing-call-to-setgroups-before-setuid",
                &[&pkgfile.name],
            );
        }
        if mktemp {
            add_info(out, Level::Error, pkg, "call-to-mktemp", &[&pkgfile.name]);
        }
        if gets {
            add_info(out, Level::Error, pkg, "call-to-gets", &[&pkgfile.name]);
        }
        if tmpnam {
            add_info(out, Level::Error, pkg, "call-to-tmpnam", &[&pkgfile.name]);
        }
        if gethostbyname {
            // Defect-pattern gate (registry gate shape
            // "privilege-or-exposure", #959): the bare pattern stays a
            // Warning. The gated forms report at Error: the file
            // itself carries privilege (setuid/setgid bits or file
            // capabilities), or the package ships systemd service or
            // socket units, i.e. the caller runs as a daemon. The
            // Error form also requires a call — an undefined reference
            // to the family. A file that only defines the symbols
            // (an NSS module implementing the legacy entry points, a
            // bundled replacement) carries the pattern without making
            // the call and stays in the Warning population: the same
            // definition/call split the archive scoping of
            // call-to-mktemp uses (#852). The level rests on the
            // Factory corpus measurement recorded in the divergence
            // ledger (#967).
            if info.has_undefined_function_matching(&self.gethostbyname_call_regex)
                && (file_is_privileged(pkgfile) || pkg_ships_daemon_units(pkg))
            {
                add_info(
                    out,
                    Level::Error,
                    pkg,
                    "binary-or-shlib-calls-gethostbyname",
                    &[&pkgfile.name],
                );
            } else {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "binary-or-shlib-calls-gethostbyname",
                    &[&pkgfile.name],
                );
            }
        }

        if md5 {
            add_info(
                out,
                Level::Warning,
                pkg,
                "binary-or-shlib-calls-md5",
                &[&pkgfile.name],
            );
        }
        if des {
            add_info(
                out,
                Level::Warning,
                pkg,
                "binary-or-shlib-calls-des",
                &[&pkgfile.name],
            );
        }
        if rc4 {
            add_info(
                out,
                Level::Warning,
                pkg,
                "binary-or-shlib-calls-rc4",
                &[&pkgfile.name],
            );
        }
        if weak_prng {
            add_info(
                out,
                Level::Warning,
                pkg,
                "binary-or-shlib-calls-weak-prng",
                &[&pkgfile.name],
            );
        }
        if unbounded_copy {
            add_info(
                out,
                Level::Warning,
                pkg,
                "binary-or-shlib-calls-unbounded-copy",
                &[&pkgfile.name],
            );
        }

        // #972 (defect-patterns): system()/popen() hand a command
        // string to a shell. The call form fires only behind the
        // privilege/exposure gates (the same gates as the
        // gethostbyname finder above): ungated, the surface is
        // unremarkable, and binary facts cannot tell a fixed-string
        // call from one whose command is built from untrusted data,
        // so the gated form is a Warning — the maintainer audits
        // what reaches the command (the corpus classification is
        // recorded in the divergences ledger). The second disjunct
        // covers dynsym imports typed STT_NOTYPE: fill_from_elf
        // files those only under `undefined_functions`, never under
        // the FUNC-only `undefined_function_refs`.
        let shell_call = info.has_undefined_function_matching(&self.shell_call_regex)
            || info
                .undefined_functions
                .iter()
                .any(|s| self.shell_call_regex.is_match(s).unwrap_or(false));
        if (file_is_privileged(pkgfile) || pkg_ships_daemon_units(pkg)) && shell_call {
            add_info(
                out,
                Level::Warning,
                pkg,
                "binary-or-shlib-calls-shell",
                &[&pkgfile.name],
            );
        }
    }

    /// `go-toolchain-outdated`: the `.go.buildinfo` of the file (or
    /// of an archive member) records a Go toolchain below the
    /// embedded floor for its release line (see
    /// `go_toolchain_below_floor`). A Go binary keeps the standard
    /// library it was built with, so defects fixed upstream stay in
    /// the shipped binary until the package is rebuilt; the remedy
    /// is a rebuild with a fixed toolchain, a distribution
    /// scheduling action rather than a defect that should fail a
    /// build, which is why this is a warning and not an error.
    fn check_go_toolchain(
        &self,
        pkg: &Pkg,
        pkgfile: &PkgFile,
        info: &ReadelfInfo,
        out: &mut Filter,
    ) {
        let floor = go_toolchain_floor();
        let Some(version) = info
            .go_toolchains
            .iter()
            .copied()
            .filter(|version| go_toolchain_below_floor(*version, floor))
            .min()
        else {
            return;
        };
        let version_text = version.to_string();
        add_info(
            out,
            Level::Warning,
            pkg,
            "go-toolchain-outdated",
            &[&pkgfile.name, &version_text],
        );
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
        // Separate debuginfo files are ELF containers of debug
        // sections with no DT_NEEDED by construction -- the dwz
        // multi-file artefact under /usr/lib/debug/.dwz included --
        // so the absence of a library dependency states nothing
        // there (issue #955, divergences.toml). `is_debug` covers
        // the `.debug` name suffix; the path covers the rest of the
        // canonical debuginfo location: the treatment
        // `check_hardening` already applies to its findings.
        if info.is_debug || pkgfile.name.starts_with("/usr/lib/debug/") {
            return;
        }
        let ldso = info
            .soname
            .as_ref()
            .map(|s| ldso_soname_regex().is_match(s).unwrap_or(false))
            .unwrap_or(false);
        if info.needed.is_empty() && !(info.soname.is_some() && ldso) {
            if !self.is_shobj {
                // Three shapes are not charged. A relocatable object
                // is not linked at all (Go race `.syso` objects, FPC
                // `.or` units, kernel modules outside the module tree
                // the path guard above covers): it has no DT_NEEDED
                // by construction. Payload whose ELF machine belongs
                // to a different ISA family than the package
                // architecture (firmware images, cross data) is never
                // loaded by the host's dynamic linker; a same-family
                // machine (32-bit x86 in an x86-64 package) still
                // charges, as that code runs on the host. And the Go
                // and Zig toolchains emit fully static binaries as
                // their normal output shape -- pure-Go builds have no
                // dynamic mode at all -- a verdict the shared-object
                // branch below already credits for Go.
                // `go_buildinfo` covers builds stripped of the
                // section headers the section test reads.
                let foreign_payload = matches!(
                    (
                        pkg_arch_family(&pkg.arch),
                        elf_machine_family(info.elf_machine)
                    ),
                    (Some(pf), Some(mf)) if pf != mf
                );
                if info.elf_type != goblin::elf::header::ET_REL
                    && !foreign_payload
                    && !info.is_go_binary()
                    && !info.go_buildinfo
                    && !info.is_zig_binary()
                {
                    add_info(
                        out,
                        Level::Error,
                        pkg,
                        "statically-linked-binary",
                        &[&pkgfile.name],
                    );
                }
            } else if !info.is_go_binary() && !info.is_plugin_like(&pkgfile.name) {
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
        let forbidden_calls = forbidden_function_calls(info, config);
        if forbidden_calls.is_empty() {
            return;
        }
        if !self.strings.is_present() {
            log::debug!("BinariesCheck: strings not found, skipping forbidden-function check");
            return;
        }
        let strings = StringsInfo::parse(&self.strings, &pkgfile.path);
        report_forbidden_functions(pkg, pkgfile, &forbidden_calls, &strings, out);
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
        // An archive whose members are all in other object formats has
        // no ELF content for any of these checks to read.
        if info.no_elf_members {
            return;
        }
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
        self.check_go_toolchain(pkg, pkgfile, info, out);
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
        //
        // An installed package resolves in place: its own files and
        // the system are the reference's whole universe there. An
        // extracted package is captured instead (plusky/rpmcrab#701):
        // the providers it ships join the invocation-wide index and
        // its consumers are recorded by `check_dependency`, then
        // resolved in `after_checks` once every package of the
        // batch has contributed -- resolution inside one package
        // alone cannot see the sibling packages a multi-package
        // invocation installs side by side.
        self.defer_undefined = !pkg.is_installed();
        if self.defer_undefined {
            let state = BinariesState {
                provider_sets: vec![PackageProviders {
                    pkg_name: pkg.name.clone(),
                    pkg_arch: pkg.arch.clone(),
                    pkg_filename: pkg.filename.clone(),
                    providers: package_providers(&analyses, &pkg.files),
                }],
                ..BinariesState::default()
            };
            match &mut self.pending_state {
                Some(existing) => existing.merge(state),
                None => self.pending_state = Some(state),
            }
        } else {
            let owner: PackageId = (pkg.name.clone(), pkg.arch.clone(), pkg.filename.clone());
            resolve_undefined_symbols(&mut analyses, &pkg.files, &self.system_libraries, &owner);
        }

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

            self.check_binary_in_noarch(pkg, pkgfile, out);
            if pkg.arch == "noarch" {
                continue;
            }

            self.check_binary_in_usr_share(pkg, pkgfile, out);
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

        // Register this package as an invocation contributor only
        // now, when what it actually contributed is known
        // (plusky/rpmcrab#735 review): a captured consumer (the
        // records `check_dependency` left in the pending state) or a
        // provider library (an `ldd`-clean file that is a shared
        // library, carries a SONAME, or is named like one). A package
        // shipping only executables contributes neither --
        // executables are never captured as consumers and their
        // basenames are not library providers -- so it must not flip
        // a batch into invocation-wide resolution in `after_checks`.
        if self.defer_undefined {
            let captured = self.pending_state.as_ref().is_some_and(|state| {
                state.packages.iter().any(|p| {
                    p.pkg_name == pkg.name
                        && p.pkg_arch == pkg.arch
                        && p.pkg_filename == pkg.filename
                })
            });
            let provides = analyses
                .iter()
                .zip(pkg.files.iter())
                .any(|(analysis, pkgfile)| {
                    let Some(analysis) = analysis else {
                        return false;
                    };
                    analysis.ldd.as_ref().is_some_and(|l| l.failed.is_none())
                        && (analysis.info.is_shlib
                            || analysis.info.soname.is_some()
                            || basename(&pkgfile.name).contains(".so"))
                });
            if captured || provides {
                let state = self
                    .pending_state
                    .get_or_insert_with(BinariesState::default);
                let contributor = (pkg.name.clone(), pkg.arch.clone(), pkg.filename.clone());
                if !state.contributors.contains(&contributor) {
                    state.contributors.push(contributor);
                }
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

    fn reset(&mut self) {
        self.pending_state = None;
        self.deferred_state = BinariesState::default();
        self.defer_undefined = false;
    }

    fn export_state(&mut self) -> Option<Box<dyn std::any::Any + Send>> {
        match self.pending_state.take() {
            Some(state) if !state.is_empty() => Some(Box::new(state)),
            _ => None,
        }
    }

    fn import_state(&mut self, state: Box<dyn std::any::Any + Send>) {
        if let Ok(state) = state.downcast::<BinariesState>() {
            self.deferred_state.merge(*state);
        }
    }

    /// Resolve the batch's captured consumers against the
    /// per-package provider sets and emit the residue
    /// (plusky/rpmcrab#701).
    /// A batch with one contributing package resolves against that
    /// package's providers plus the system -- the single-package
    /// model extracted packages have always used. A wider batch
    /// resolves inside the invocation's set alone: the system the
    /// scan happens to run on is not part of the install the
    /// invocation describes, and its libraries must not mask a
    /// provider the invocation itself lacks.
    fn after_checks(&mut self, _config: &Config, out: &mut Filter) {
        if self.deferred_state.is_empty() {
            return;
        }
        let state = std::mem::take(&mut self.deferred_state);
        let invocation_wide = state.contributors.len() > 1;
        // Single-contributor mode resolves against the contributing
        // package's providers plus the system (issue #799): the
        // index holds that package's set alone. Every other set is
        // outside the model -- a sibling's basename entries (an
        // exe-only package's files land in its set under their
        // basenames) must not satisfy the contributor's DT_NEEDED
        // spellings.
        let provider_sets = if invocation_wide {
            state.provider_sets
        } else {
            // A batch can reach here with no contributor at all
            // (only exe-only or provider-only packages): the filter
            // then keeps nothing, and the resolution loop below has
            // no consumers to resolve.
            let contributor = state.contributors.first();
            state
                .provider_sets
                .into_iter()
                .filter(|set| {
                    contributor.is_some_and(|c| {
                        set.pkg_name == c.0 && set.pkg_arch == c.1 && set.pkg_filename == c.2
                    })
                })
                .collect()
        };
        let providers = ProviderIndex::new(provider_sets);
        let empty_system;
        let system = if invocation_wide {
            empty_system = SystemLibraries::empty();
            &empty_system
        } else {
            &self.system_libraries
        };
        let mut closures: HashMap<ClosureKey, Rc<HashSet<String>>> = HashMap::new();
        for package in &state.packages {
            let owner: PackageId = (
                package.pkg_name.clone(),
                package.pkg_arch.clone(),
                package.pkg_filename.clone(),
            );
            for consumer in &package.files {
                if consumer.undefined_symbols.is_empty() {
                    continue;
                }
                let root_ctx = SearchContext::for_object(
                    &consumer.rpath,
                    &consumer.runpath,
                    consumer.has_runpath,
                    &installed_dir(&consumer.file_name),
                    &[],
                );
                let provided = provided_by_closure(
                    &providers,
                    system,
                    &mut closures,
                    &consumer.dependencies,
                    consumer.is_64,
                    &root_ctx,
                    &owner,
                );
                let unresolved: Vec<String> = consumer
                    .undefined_symbols
                    .iter()
                    .filter(|symbol| {
                        !provided.contains(*symbol) && !consumer.defined_symbols.contains(*symbol)
                    })
                    .cloned()
                    .collect();
                if !unresolved.is_empty() {
                    out.add_info(make_finding(
                        &package.pkg_name,
                        &package.pkg_arch,
                        Level::Warning,
                        "undefined-non-weak-symbol",
                        vec![
                            consumer.file_name.clone(),
                            undefined_symbol_detail(&unresolved),
                        ],
                        None,
                    ));
                }
            }
        }
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
        shlib_libdep_results_named(
            id,
            go_note,
            needed,
            is_shobj,
            soname,
            dynsyms,
            "/usr/lib64/libnodep.so.1",
        )
    }

    fn shlib_libdep_results_named(
        id: &str,
        go_note: bool,
        needed: Option<&str>,
        is_shobj: bool,
        soname: Option<&str>,
        dynsyms: &[(&str, u8, u8, u16)],
        file_name: &str,
    ) -> Vec<(String, String)> {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = is_shobj;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: file_name.to_string(),
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
    fn shlib_without_dependency_information_skips_own_name_module() {
        // Module shape: the build stamped the module's own file name
        // as its DT_SONAME (the slurm/apache plugin shape). The real
        // non-weak undefined import rules out the self-contained
        // disjunct and the present SONAME rules out the dlopen-only
        // one -- only the own-name disjunct can silence this fixture,
        // so dropping it must fail this test.
        let results = shlib_libdep_results_named(
            "ownname",
            false,
            None,
            true,
            Some("certmgr_script.so"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
            "/usr/lib64/slurm/certmgr_script.so",
        );
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert!(
            results.is_empty(),
            "own-name module must be quiet: {results:?}"
        );
    }

    #[test]
    fn shlib_without_dependency_information_skips_own_name_non_so_module() {
        // The own-name shape is not tied to a `.so` name: a VirtualBox
        // ring-0 payload carries its own `.r0` file name as SONAME.
        let results = shlib_libdep_results_named(
            "ownnamer0",
            false,
            None,
            true,
            Some("VMMR0.r0"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
            "/usr/lib/virtualbox/VMMR0.r0",
        );
        assert_lacks(&results, "shared-library-without-dependency-information");
        assert!(
            results.is_empty(),
            "own-name .r0 module must be quiet: {results:?}"
        );
    }

    #[test]
    fn shlib_without_dependency_information_fires_versioned_own_name() {
        // Near miss: the SONAME equals the file name but carries an
        // ABI version component -- a genuine linkable library whose
        // name other packages record DT_NEEDED against, still
        // checked. Dropping the version condition in the own-name
        // disjunct must fail this test.
        let results = shlib_libdep_results_named(
            "versionedname",
            false,
            None,
            true,
            Some("libfoo.so.1"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
            "/usr/lib64/libfoo.so.1",
        );
        let lines = lines_for(&results, "shared-library-without-dependency-information");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
    }

    #[test]
    fn shlib_without_dependency_information_fires_versioned_shorter_soname() {
        // Near miss, the genuine-library shape measured in the corpus
        // (libfrrfpm_pb): a versioned SONAME carried by a file with a
        // longer full-version name. The own-name credit must not
        // reach it.
        let results = shlib_libdep_results_named(
            "versionedshort",
            false,
            None,
            true,
            Some("libfrrfpm_pb.so.0"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
            "/usr/lib64/libfrrfpm_pb.so.0.0.0",
        );
        let lines = lines_for(&results, "shared-library-without-dependency-information");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
    }

    #[test]
    fn soname_version_component_shapes() {
        // The `.so.<digit>` substring form, overlaps included.
        assert!(soname_has_version_component("libfoo.so.0"));
        assert!(soname_has_version_component("libfoo.so.1.2"));
        assert!(soname_has_version_component("x.so.so.1"));
        // The validso tail forms: dash and stem versions.
        assert!(soname_has_version_component("libdb-4.8.so"));
        assert!(soname_has_version_component("libtcl8.6.so"));
        assert!(soname_has_version_component("libfoo-1.so"));
        // Unversioned module names.
        assert!(!soname_has_version_component("mod_foo.so"));
        assert!(!soname_has_version_component("plugin.so"));
        assert!(!soname_has_version_component("VMMR0.r0"));
        assert!(!soname_has_version_component("libfoo.so0"));
        assert!(!soname_has_version_component("certmgr_script.so"));
    }

    #[test]
    fn shlib_without_dependency_information_fires_dash_versioned_own_name() {
        // Near miss under the widened predicate: the SONAME equals
        // the file name, but its dash version is a version component
        // (the shape the soname validity gate treats as versioned),
        // so the own-name credit does not reach it.
        let results = shlib_libdep_results_named(
            "dashverown",
            false,
            None,
            true,
            Some("libdb-4.8.so"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
            "/usr/lib64/libdb-4.8.so",
        );
        let lines = lines_for(&results, "shared-library-without-dependency-information");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
    }

    #[test]
    fn shlib_without_dependency_information_fires_foreign_unversioned_soname() {
        // Near miss: an unversioned SONAME that is NOT the object's
        // own file name. The credit is the own-name shape, not the
        // mere absence of a version component.
        let results = shlib_libdep_results_named(
            "foreignname",
            false,
            None,
            true,
            Some("other.so"),
            &[(
                "external_func",
                goblin::elf::sym::STB_GLOBAL,
                goblin::elf::sym::STT_FUNC,
                0,
            )],
            "/usr/lib64/plugins/thing.so",
        );
        let lines = lines_for(&results, "shared-library-without-dependency-information");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
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

    fn libdep_results_for_bytes(id: &str, bytes: &[u8], arch: &str) -> Vec<(String, String)> {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = false;
        let pkg = synthetic_pkg("testpkg", arch, vec![]);
        let pkgfile = PkgFile {
            name: "/usr/bin/foo".to_string(),
            ..Default::default()
        };
        let path =
            std::env::temp_dir().join(format!("rpmcrab-libdep-bytes-{id}-{}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), &pkgfile.name);
        assert!(info.failed.is_none(), "crafted ELF must parse");
        assert!(info.needed.is_empty(), "no DT_NEEDED");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        std::fs::remove_file(&path).ok();
        results
    }

    #[test]
    fn go_binary_without_needed_stays_quiet() {
        // Go output in the executable (non-shared-object) shape: the
        // section marker credits it the way the shared-object branch
        // already credits Go.
        let results = shlib_libdep_results("goexec", true, None, false, None, &[]);
        assert!(results.is_empty(), "Go binary must be quiet: {results:?}");
    }

    #[test]
    fn go_buildinfo_magic_without_sections_stays_quiet() {
        // A Go build stripped of its section headers keeps only the
        // buildinfo block: no `.note.go.buildid` for the section
        // test, but the magic still marks it as Go output (the
        // sectionless shape found in the Factory corpus).
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = false;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: "/usr/bin/foo".to_string(),
            ..Default::default()
        };
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes.extend_from_slice(b"\xff Go buildinf:");
        bytes.extend_from_slice(&[8, 0]);
        bytes.extend_from_slice(&[0u8; 30]);
        let path =
            std::env::temp_dir().join(format!("rpmcrab-libdep-gomagic-{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), &pkgfile.name);
        assert!(info.failed.is_none(), "crafted ELF must parse");
        assert!(!info.is_go_binary(), "fixture carries no Go sections");
        assert!(info.go_buildinfo, "buildinfo magic must be detected");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        std::fs::remove_file(&path).ok();
        assert!(
            results.is_empty(),
            "buildinfo-only Go binary must be quiet: {results:?}"
        );
    }

    #[test]
    fn go_buildinfo_magic_with_invalid_header_still_charges() {
        // The magic byte sequence alone is not enough: a pointer-size
        // byte outside {4, 8}, or a header truncated before the fixed
        // 32 bytes, is not a buildinfo block and earns no credit.
        for (id, tail) in [("badptr", [7u8, 0].as_slice()), ("trunc", [8u8].as_slice())] {
            let mut bytes = craft_shlib_elf(false, None, None, &[]);
            bytes.extend_from_slice(b"\xff Go buildinf:");
            bytes.extend_from_slice(tail);
            if id == "badptr" {
                bytes.extend_from_slice(&[0u8; 30]);
            }
            let results = libdep_results_for_bytes(id, &bytes, "x86_64");
            let lines = lines_for(&results, "statically-linked-binary");
            assert_eq!(lines.len(), 1, "{id} must fire: {results:?}");
        }
    }

    #[test]
    fn static_charge_fail_closed_on_unmapped_arch_and_machine() {
        // Unmapped package arch: `pkg_arch_family` yields None, so
        // even a foreign-machine payload still charges -- the gate
        // cannot classify the file (the #847 principle).
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes[18..20].copy_from_slice(&goblin::elf::header::EM_SPARC.to_le_bytes());
        let results = libdep_results_for_bytes("unmappedarch", &bytes, "e2k");
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "unmapped arch must fire: {results:?}");

        // Unmapped e_machine: `elf_machine_family` yields None, same
        // fail-closed outcome in a mapped-arch package.
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes[18..20].copy_from_slice(&0xBEEFu16.to_le_bytes());
        let results = libdep_results_for_bytes("unmappedmachine", &bytes, "x86_64");
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "unmapped machine must fire: {results:?}");

        // ARM same-family: a 32-bit ARM payload in an AArch64 package
        // is the package's own family and runs on the host -- charges.
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes[18..20].copy_from_slice(&goblin::elf::header::EM_ARM.to_le_bytes());
        let results = libdep_results_for_bytes("armfamily", &bytes, "aarch64");
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "ARM same-family must fire: {results:?}");
    }

    #[test]
    fn zig_binary_without_needed_stays_quiet() {
        // Zig output in the executable shape; the branch consumes the
        // detector's verdict, pinned here with literal infos.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = false;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: "/usr/bin/foo".to_string(),
            ..Default::default()
        };
        let run = |info: &ReadelfInfo| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_library_dependency(&pkg, &pkgfile, info, &mut out);
            out.results().to_vec()
        };
        let info = ReadelfInfo {
            is_zig: true,
            ..syn_info()
        };
        let results = run(&info);
        assert!(results.is_empty(), "Zig binary must be quiet: {results:?}");
        // Control: the same shape without the Zig marker charges.
        let results = run(&syn_info());
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "unmarked shape must fire: {results:?}");
    }

    #[test]
    fn relocatable_object_stays_quiet() {
        // ET_REL payload is not linked at all (Go race `.syso`
        // objects, FPC `.or` units): the absence of DT_NEEDED states
        // nothing.
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes[16..18].copy_from_slice(&goblin::elf::header::ET_REL.to_le_bytes());
        let results = libdep_results_for_bytes("relobj", &bytes, "x86_64");
        assert!(
            results.is_empty(),
            "relocatable object must be quiet: {results:?}"
        );
    }

    #[test]
    fn foreign_machine_payload_stays_quiet() {
        // A SPARC payload in an x86-64 package is firmware/data for
        // another machine (the qemu firmware shape); the host loader
        // never loads it.
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes[18..20].copy_from_slice(&goblin::elf::header::EM_SPARC.to_le_bytes());
        let results = libdep_results_for_bytes("foreign", &bytes, "x86_64");
        assert!(
            results.is_empty(),
            "foreign-machine payload must be quiet: {results:?}"
        );

        // Near miss: 32-bit x86 is the same family as x86-64 and runs
        // on the host -- it still charges.
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes[18..20].copy_from_slice(&goblin::elf::header::EM_386.to_le_bytes());
        let results = libdep_results_for_bytes("familymatch", &bytes, "x86_64");
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "same-family payload must fire: {results:?}");

        // The predicate is family-relative, not a per-machine
        // exemption: the same SPARC payload in a SPARC package
        // charges.
        let mut bytes = craft_shlib_elf(false, None, None, &[]);
        bytes[18..20].copy_from_slice(&goblin::elf::header::EM_SPARCV9.to_le_bytes());
        let results = libdep_results_for_bytes("foreignhome", &bytes, "sparc64");
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "host-family payload must fire: {results:?}");
    }

    fn libdep_results_for_name(id: &str, name: &str) -> Vec<(String, String)> {
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_shobj = false;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: name.to_string(),
            ..Default::default()
        };
        let bytes = craft_shlib_elf(false, None, None, &[]);
        let path = std::env::temp_dir().join(format!("rpmcrab-libdep-{id}-{}", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), &pkgfile.name);
        assert!(info.failed.is_none(), "crafted ELF must parse");
        assert!(info.needed.is_empty(), "no DT_NEEDED");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_library_dependency(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        std::fs::remove_file(&path).ok();
        results
    }

    #[test]
    fn statically_linked_quiet_for_separate_debuginfo() {
        // Issue #955: the dwz multi-file artefact is an ELF container
        // of debug sections with no DT_NEEDED by construction; its
        // name carries no `.debug` suffix, so only the path arm of
        // the separate-debuginfo predicate can silence it.
        let results = libdep_results_for_name(
            "dwz",
            "/usr/lib/debug/.dwz/plymouth-22.02.122+94.4bd41a3-0.x86_64",
        );
        assert!(
            results.is_empty(),
            "dwz artefact must be quiet: {results:?}"
        );
        // The `.debug` name-suffix arm, outside the debug tree.
        let results = libdep_results_for_name("debugsuffix", "/usr/lib64/libfoo.so.1.debug");
        assert!(
            results.is_empty(),
            ".debug payload must be quiet: {results:?}"
        );
        // Near misses stay charged: a statically linked executable
        // in /usr/bin, and one under a lookalike prefix.
        let results = libdep_results_for_name("bin", "/usr/bin/foo");
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        let results = libdep_results_for_name("debugfoo", "/usr/lib/debugfoo/foo");
        let lines = lines_for(&results, "statically-linked-binary");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
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
        run_batch(&mut check, &pkg, &config, &mut out);
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

        // setuidbin: setuid without setgroups, installed setuid -> Warning
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
            setgroups_lines[0].contains(" W: "),
            "setgroups finding should be Warning for setuid binary: {}",
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
                undefined_function_refs: Vec::new(),
                is_shlib: false,
                is_debug: false,
                is_rust: false,
                is_zig: false,
                go_toolchains: Vec::new(),
                go_buildinfo: false,
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
                code_machines: Vec::new(),
                failed: None,
                no_elf_members: false,
                no_members: false,
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

    fn parse_elf_bytes(tag: &str, bytes: &[u8]) -> ReadelfInfo {
        // Unique per test: parallel cargo test threads share the process.
        let path =
            std::env::temp_dir().join(format!("rpmcrab-go-detect-{}-{}", tag, std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/bin/probe");
        assert!(info.failed.is_none(), "crafted ELF must parse");
        std::fs::remove_file(&path).ok();
        info
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
        // Each case below isolates one disjunct of the skip gate, so a
        // regression in either one alone fails this test.
        for (name, is_debug) in [
            ("/usr/bin/probe.debug", true),
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
        run_batch(&mut check, &pkg, config, &mut out);
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
    /// still go green, so this fails loudly instead (#241 review).
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

    /// One gplib member: the 256-byte name field, the fixed numeric
    /// field area (a timestamp-shaped run, then the size), the `! `
    /// terminator and the payload.
    fn gplib_member(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut name_field = name.as_bytes().to_vec();
        name_field.resize(256, b' ');
        out.extend_from_slice(&name_field);
        out.extend_from_slice(format!("{}l {:<10}", 1_785_131_819u64, payload.len()).as_bytes());
        out.extend_from_slice(b"! ");
        out.extend_from_slice(payload);
        out
    }

    fn gplib_archive(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = b"!<arch>\n".to_vec();
        for (name, payload) in members {
            out.extend_from_slice(&gplib_member(name, payload));
        }
        out
    }

    #[test]
    fn gplib_archive_shapes_validate() {
        let coff = b"\x40\x12\x02\x00\x2a\xf3\x66\x6a";
        // Symbol index first, then an object member.
        let with_index = gplib_archive(&[("/", b"\x01\x00\x00\x00"), ("foo.o/", coff)]);
        assert!(is_gplib_archive(&with_index));
        // Index-less single-member archive (the shape SDCC's libio
        // libraries take).
        let single = gplib_archive(&[("libfoo_a-dummy.o/", coff)]);
        assert!(is_gplib_archive(&single));
        // The index alone (an empty library).
        let index_only = gplib_archive(&[("/", b"\x00\x00\x00\x00")]);
        assert!(is_gplib_archive(&index_only));
    }

    #[test]
    fn gplib_archive_near_misses_do_not_validate() {
        let coff = b"\x40\x12\x02\x00\x2a\xf3\x66\x6a";
        let good = gplib_archive(&[("/", b"\x01\x00\x00\x00"), ("foo.o/", coff)]);
        // Truncated payload: the chain no longer lands on EOF.
        assert!(!is_gplib_archive(&good[..good.len() - 1]));
        // Trailing garbage after the last member.
        let mut trailed = good.clone();
        trailed.push(b'\n');
        assert!(!is_gplib_archive(&trailed));
        // Wrong global magic.
        let mut wrong_magic = good.clone();
        wrong_magic[0] = b'?';
        assert!(!is_gplib_archive(&wrong_magic));
        // GNU ar framing (16-byte name field) is not the dialect.
        let gnu: &[u8] =
            b"!<arch>\nfoo.o/          1785131819  1000  1000  100644  8         `\n........";
        assert!(!is_gplib_archive(gnu));
        // An object member without the PIC COFF magic.
        let not_coff = gplib_archive(&[("foo.o/", b"NOPE........")]);
        assert!(!is_gplib_archive(&not_coff));
        // A member name without the terminating slash.
        let no_slash = gplib_archive(&[("foo.o", coff)]);
        assert!(!is_gplib_archive(&no_slash));
        // A lying size field breaks the member chain.
        let mut lying = gplib_archive(&[("foo.o/", coff)]);
        let pos = 8 + 256 + 12;
        lying[pos] = if lying[pos] == b'9' { b'1' } else { b'9' };
        assert!(!is_gplib_archive(&lying));
    }

    #[test]
    fn gplib_archive_is_not_charged_ar_failed() {
        // GNU `ar` cannot read the gplib dialect, but a structurally
        // valid gplib archive is a working library for its toolchain:
        // a non-standard archive, not an ar-failed one.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        assert!(check.ar.is_present());
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let archive = dir.path().join("libsdcc.lib");
        let coff = b"\x40\x12\x02\x00\x2a\xf3\x66\x6a";
        std::fs::write(
            &archive,
            gplib_archive(&[("/", b"\x01\x00\x00\x00"), ("foo.o/", coff)]),
        )
        .expect("write archive");
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let extract_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(&rpm_path), extract_dir.path(), true)
            .expect("open fixture");
        let pkgfile = PkgFile {
            name: "/usr/share/sdcc/lib/pic16/libsdcc.lib".to_string(),
            path: archive.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        assert!(
            !check.is_standard_archive(&pkg, &pkgfile, &mut out),
            "gplib archives are non-standard archives"
        );
        assert!(
            out.results().is_empty(),
            "no findings invented: {:?}",
            out.results()
        );
    }

    #[test]
    fn broken_archive_is_charged_ar_failed() {
        // Garbage behind an ar magic is neither GNU ar nor gplib: the
        // ar-failed charge stands.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        assert!(check.ar.is_present());
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let archive = dir.path().join("libbroken.a");
        let mut bytes = b"!<arch>\n".to_vec();
        bytes.resize(8 + 400, b'x');
        std::fs::write(&archive, bytes).expect("write archive");
        let rpm_path = fixture_path("rpmcrab-binaries-fixture-1.0-1.aarch64.rpm");
        let extract_dir = tempfile::TempDir::new().expect("tmpdir");
        let pkg = Pkg::open(std::path::Path::new(&rpm_path), extract_dir.path(), true)
            .expect("open fixture");
        let pkgfile = PkgFile {
            name: "/usr/lib64/libbroken.a".to_string(),
            path: archive.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        assert!(!check.is_standard_archive(&pkg, &pkgfile, &mut out));
        assert_eq!(out.results().len(), 1, "one finding: {:?}", out.results());
        assert!(
            out.results()[0].1.contains("ar-failed"),
            "the finding is ar-failed: {:?}",
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
                undefined_function_refs: Vec::new(),
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
                code_machines: Vec::new(),
                failed: None,
                no_elf_members: false,
                no_members: false,
                is_rust: false,
                is_zig: false,
                go_toolchains: Vec::new(),
                go_buildinfo: false,
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
            undefined_function_refs: Vec::new(),
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
            code_machines: Vec::new(),
            failed: None,
            no_elf_members: false,
            no_members: false,
            is_rust: false,
            is_zig: false,
            go_toolchains: Vec::new(),
            go_buildinfo: false,
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

    /// Run one package through the production batch flow on one
    /// check instance: check it, export its per-package state,
    /// merge the state back, and run `after_checks`. Undefined
    /// symbols of extracted packages resolve in `after_checks`
    /// (plusky/rpmcrab#701), so a bare `check_binary` no longer
    /// shows their findings.
    fn run_batch(check: &mut BinariesCheck, pkg: &Pkg, config: &Config, out: &mut Filter) {
        check.check_binary(pkg, config, out);
        if let Some(state) = check.export_state() {
            check.import_state(state);
        }
        check.after_checks(config, out);
    }

    /// Run several packages as one invocation on one check
    /// instance: each package is checked and its exported state
    /// merged, then a single `after_checks` resolves the whole
    /// batch (plusky/rpmcrab#701) -- the worker/main split of
    /// `run_batch`, with the merge accumulating across packages
    /// instead of resolving after each one.
    fn run_invocation(check: &mut BinariesCheck, pkgs: &[&Pkg], config: &Config, out: &mut Filter) {
        for pkg in pkgs {
            check.check_binary(pkg, config, out);
            if let Some(state) = check.export_state() {
                check.import_state(state);
            }
        }
        check.after_checks(config, out);
    }

    fn driver_results(pkg: &Pkg, config: &Config) -> Vec<(String, String)> {
        let mut check = BinariesCheck::with_tool_dir(config, None);
        let mut out = Filter::new(config, Color::for_tty(false)).unwrap();
        run_batch(&mut check, pkg, config, &mut out);
        out.results().to_vec()
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

    /// A minimal ELF64 with the given `e_type` and programme header
    /// types, parseable by goblin: the byte-level counterpart of the
    /// synthetic `ReadelfInfo` shapes, so the executable-stack gate is
    /// pinned against what the parser produces for each file shape.
    fn elf_with_phdrs(e_type: u16, phdr_types: &[u32]) -> Vec<u8> {
        let mut elf: Vec<u8> = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        elf.extend_from_slice(&e_type.to_le_bytes());
        elf.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf.extend_from_slice(&1u32.to_le_bytes()); // version
        elf.extend_from_slice(&0u64.to_le_bytes()); // entry
        elf.extend_from_slice(&64u64.to_le_bytes()); // phoff
        elf.extend_from_slice(&0u64.to_le_bytes()); // shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // flags
        elf.extend_from_slice(&64u16.to_le_bytes()); // ehsize
        elf.extend_from_slice(&56u16.to_le_bytes()); // phentsize
        elf.extend_from_slice(&(phdr_types.len() as u16).to_le_bytes()); // phnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // shentsize
        elf.extend_from_slice(&0u16.to_le_bytes()); // shnum
        elf.extend_from_slice(&0u16.to_le_bytes()); // shstrndx
        for &p_type in phdr_types {
            elf.extend_from_slice(&p_type.to_le_bytes());
            elf.extend_from_slice(&5u32.to_le_bytes()); // p_flags R+X
            elf.extend_from_slice(&0u64.to_le_bytes()); // p_offset
            elf.extend_from_slice(&0u64.to_le_bytes()); // p_vaddr
            elf.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
            elf.extend_from_slice(&0u64.to_le_bytes()); // p_filesz
            elf.extend_from_slice(&0u64.to_le_bytes()); // p_memsz
            elf.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        }
        elf
    }

    /// Run `check_executable_stack` over a byte fixture parsed by the
    /// real parser, under the given package file name.
    fn executable_stack_results(name: &str, bytes: &[u8]) -> Vec<(String, String)> {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let path = dir.path().join("payload");
        std::fs::write(&path, bytes).expect("write elf");
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = PkgFile {
            name: name.to_string(),
            path: path.to_string_lossy().into_owned(),
            magic: "ELF 64-bit LSB executable, x86-64".to_string(),
            mode: 0o100755,
            ..Default::default()
        };
        let info = ReadelfInfo::parse(&pkgfile.path, &pkgfile.name);
        assert!(
            info.failed.is_none(),
            "fixture must parse: {:?}",
            info.failed
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_executable_stack(&pkg, &pkgfile, &info, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn missing_gnu_stack_fires_for_linked_images_with_phdr_tables() {
        use goblin::elf::header::{ET_DYN, ET_EXEC};
        use goblin::elf::program_header::{PT_DYNAMIC, PT_LOAD};
        // The population the finding addresses: executables and shared
        // objects whose programme header table has no PT_GNU_STACK.
        for (e_type, phdrs) in [
            (ET_EXEC, &[PT_LOAD][..]),
            (ET_DYN, &[PT_LOAD, PT_DYNAMIC][..]),
        ] {
            let results = executable_stack_results("/usr/bin/tool", &elf_with_phdrs(e_type, phdrs));
            let lines = lines_for(&results, "missing-PT_GNU_STACK-section");
            assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
            assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
            assert!(
                lines[0].contains("/usr/bin/tool"),
                "detail names the file: {}",
                lines[0]
            );
        }
    }

    #[test]
    fn missing_gnu_stack_silent_without_phdr_table() {
        use goblin::elf::header::{ET_DYN, ET_EXEC};
        // A linked-type file with no programme header table is not a
        // loadable image (the firmware-blob shape): there is no header
        // to be missing.
        for e_type in [ET_EXEC, ET_DYN] {
            let results =
                executable_stack_results("/usr/share/fw/blob", &elf_with_phdrs(e_type, &[]));
            assert_lacks(&results, "missing-PT_GNU_STACK-section");
            assert_lacks(&results, "executable-stack");
        }
    }

    #[test]
    fn missing_gnu_stack_silent_for_relocatable_objects() {
        use goblin::elf::header::ET_REL;
        // Kernel modules outside the module paths, Go .syso objects
        // and compiler .or files are ET_REL: no programme headers by
        // construction.
        let results =
            executable_stack_results("/usr/share/blob/nsm.ko", &elf_with_phdrs(ET_REL, &[]));
        assert_lacks(&results, "missing-PT_GNU_STACK-section");
        assert_lacks(&results, "executable-stack");
    }

    #[test]
    fn missing_gnu_stack_silent_for_debuginfo() {
        use goblin::elf::header::ET_EXEC;
        use goblin::elf::program_header::{PT_DYNAMIC, PT_LOAD};
        // The ovmf shape (plusky/rpmcrab#850): EDK2 GdbSyms companions
        // are ET_EXEC with a real programme header table, stored as
        // debuginfo the dynamic linker never loads. The `.debug` name
        // and the canonical debuginfo location each suffice.
        let bytes = elf_with_phdrs(ET_EXEC, &[PT_LOAD, PT_LOAD, PT_DYNAMIC]);
        for name in [
            "/usr/lib/debug/ovmf-x86_64-4m/DebugPkg/GdbSyms/GdbSyms/DEBUG/GdbSyms.debug",
            "/usr/lib/debug/ovmf-x86_64-4m/DebugPkg/GdbSyms/GdbSyms/DEBUG/GdbSyms.dll",
        ] {
            let results = executable_stack_results(name, &bytes);
            assert_lacks(&results, "missing-PT_GNU_STACK-section");
        }
    }

    fn executable_stack_syn_machine(
        elf_type: u16,
        machine: u16,
        headers: Vec<ElfProgramHeader>,
    ) -> Vec<(String, String)> {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/tool", "ELF 64-bit LSB executable, x86-64");
        let mut info = syn_info();
        info.elf_type = elf_type;
        info.elf_machine = machine;
        info.program_headers = headers;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_executable_stack(&pkg, &pkgfile, &info, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn missing_gnu_stack_silent_for_foreign_machine() {
        use goblin::elf::header::{EM_ARM, EM_PPC, EM_SPARC, EM_SPARCV9, ET_DYN, ET_EXEC};
        // Guest firmware and cross payloads in an x86_64 package: the
        // images are linked images with a programme header table, but
        // built for another instruction set -- OpenBIOS for SPARC
        // guests, a U-Boot ROM for a PPC guest, an ARM helper image.
        // The package arch's dynamic linker never loads them, so the
        // missing header states nothing about how they were linked.
        for machine in [EM_SPARC, EM_SPARCV9, EM_PPC, EM_ARM] {
            let results = executable_stack_syn_machine(ET_EXEC, machine, vec![phdr("LOAD", "R E")]);
            assert_lacks(&results, "missing-PT_GNU_STACK-section");
        }
        let results = executable_stack_syn_machine(ET_DYN, EM_PPC, vec![phdr("LOAD", "R E")]);
        assert_lacks(&results, "missing-PT_GNU_STACK-section");
    }

    #[test]
    fn missing_gnu_stack_silent_for_foreign_machine_bytes() {
        use goblin::elf::header::{EM_SPARCV9, ET_EXEC};
        use goblin::elf::program_header::PT_LOAD;
        // The byte-level counterpart of the synthetic test: the
        // parser must surface the foreign e_machine for the gate to
        // see it (the fixture builder writes EM_X86_64; patch the
        // e_machine field at offset 18).
        let mut bytes = elf_with_phdrs(ET_EXEC, &[PT_LOAD]);
        bytes[18..20].copy_from_slice(&EM_SPARCV9.to_le_bytes());
        let results = executable_stack_results("/usr/share/qemu/openbios-sparc64", &bytes);
        assert_lacks(&results, "missing-PT_GNU_STACK-section");
        assert_lacks(&results, "executable-stack");
    }

    #[test]
    fn missing_gnu_stack_fires_for_same_family_machines() {
        use goblin::elf::header::{EM_386, EM_X86_64, ET_DYN, ET_EXEC};
        // Near misses: the other word size of the package's own ISA
        // is served by the same dynamic linker family -- a 32-bit
        // executable or shared library in an x86_64 package is
        // exactly the population the finding addresses.
        for (elf_type, machine) in [(ET_EXEC, EM_386), (ET_DYN, EM_386), (ET_EXEC, EM_X86_64)] {
            let results =
                executable_stack_syn_machine(elf_type, machine, vec![phdr("LOAD", "R E")]);
            assert_eq!(
                lines_for(&results, "missing-PT_GNU_STACK-section").len(),
                1,
                "machine {machine} keeps firing: {results:?}"
            );
        }
    }

    #[test]
    fn missing_gnu_stack_family_table_fails_closed() {
        use goblin::elf::header::{EM_386, EM_AARCH64, EM_NONE, EM_PPC64, EM_SPARCV9, EM_X86_64};
        // The word-size pairs share a family on both sides of the
        // comparison (and a hwcaps subarch resolves to its base), and
        // an unclassified machine or an unmapped package arch never
        // counts as foreign: the gate cannot classify those, so the
        // charge stands.
        assert!(!foreign_elf_machine(EM_SPARCV9, "sparc64"));
        assert!(!foreign_elf_machine(EM_PPC64, "ppc"));
        assert!(!foreign_elf_machine(EM_386, "x86_64_v3"));
        assert!(foreign_elf_machine(EM_AARCH64, "x86_64"));
        assert!(!foreign_elf_machine(EM_NONE, "x86_64"));
        assert!(!foreign_elf_machine(EM_X86_64, "noarch"));
    }

    fn executable_stack_syn(
        elf_type: u16,
        headers: Vec<ElfProgramHeader>,
    ) -> Vec<(String, String)> {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/tool", "ELF 64-bit LSB executable, x86-64");
        let mut info = syn_info();
        info.elf_type = elf_type;
        info.program_headers = headers;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_executable_stack(&pkg, &pkgfile, &info, &mut out);
        out.results().to_vec()
    }

    fn phdr(name: &str, flags: &str) -> ElfProgramHeader {
        ElfProgramHeader {
            name: name.to_string(),
            flags: flags.to_string(),
        }
    }

    #[test]
    fn missing_gnu_stack_gate_keys_on_elf_type() {
        use goblin::elf::header::{ET_CORE, ET_DYN, ET_NONE, ET_REL};
        // The type arm of the gate does its own work: even with a
        // programme header present, a non-linked type stays silent,
        // while ET_DYN with a table fires.
        for elf_type in [ET_REL, ET_CORE, ET_NONE] {
            let results = executable_stack_syn(elf_type, vec![phdr("LOAD", "R E")]);
            assert_lacks(&results, "missing-PT_GNU_STACK-section");
        }
        let results = executable_stack_syn(ET_DYN, vec![phdr("LOAD", "R E")]);
        assert_eq!(
            lines_for(&results, "missing-PT_GNU_STACK-section").len(),
            1,
            "ET_DYN with a table fires: {results:?}"
        );
    }

    #[test]
    fn gnu_stack_present_arms_unchanged() {
        use goblin::elf::header::ET_EXEC;
        // A non-executable GNU_STACK silences both findings; an
        // executable one keeps firing executable-stack.
        let results = executable_stack_syn(ET_EXEC, vec![phdr("GNU_STACK", "RW ")]);
        assert_lacks(&results, "missing-PT_GNU_STACK-section");
        assert_lacks(&results, "executable-stack");
        let results = executable_stack_syn(ET_EXEC, vec![phdr("GNU_STACK", "RWE")]);
        assert_lacks(&results, "missing-PT_GNU_STACK-section");
        assert_eq!(
            lines_for(&results, "executable-stack").len(),
            1,
            "executable-stack fires: {results:?}"
        );
    }

    fn rwe_stack_syn_machine(
        elf_type: u16,
        machine: u16,
        headers: Vec<ElfProgramHeader>,
    ) -> Vec<(String, String)> {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/tool", "ELF 64-bit LSB executable, x86-64");
        let mut info = syn_info();
        info.elf_type = elf_type;
        info.elf_machine = machine;
        info.program_headers = headers;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_executable_stack(&pkg, &pkgfile, &info, &mut out);
        out.results().to_vec()
    }

    #[test]
    fn executable_stack_silent_for_foreign_machine() {
        use goblin::elf::header::{EM_ARM, EM_PARISC, EM_SPARC, ET_DYN, ET_EXEC};
        // Guest firmware in an x86_64 package whose GNU_STACK is
        // explicitly executable: the HPPA ROM images QEMU ships carry
        // an RWE stack because that is the target ABI's convention.
        // The package arch's dynamic linker never loads them (the
        // emulator maps them as data into guest memory), so the
        // marking states nothing about this package's hardening.
        for (elf_type, machine) in [(ET_EXEC, EM_PARISC), (ET_EXEC, EM_SPARC), (ET_DYN, EM_ARM)] {
            let results = rwe_stack_syn_machine(elf_type, machine, vec![phdr("GNU_STACK", "RWE")]);
            assert_lacks(&results, "executable-stack");
        }
    }

    #[test]
    fn executable_stack_silent_for_foreign_machine_bytes() {
        use goblin::elf::header::{EM_PARISC, ET_EXEC};
        use goblin::elf::program_header::PT_GNU_STACK;
        // The byte-level counterpart: the parser must surface the
        // foreign e_machine for the gate to see it (the fixture
        // builder writes EM_X86_64 and an R+X phdr; patch the
        // e_machine field at offset 18). The unpatched fixture keeps
        // firing, so the silence comes from the machine, not the
        // fixture.
        let bytes = elf_with_phdrs(ET_EXEC, &[PT_GNU_STACK]);
        let results = executable_stack_results("/usr/share/qemu/hppa-firmware.img", &bytes);
        assert_eq!(
            lines_for(&results, "executable-stack").len(),
            1,
            "same-family byte fixture fires: {results:?}"
        );
        let mut bytes = bytes;
        bytes[18..20].copy_from_slice(&EM_PARISC.to_le_bytes());
        let results = executable_stack_results("/usr/share/qemu/hppa-firmware.img", &bytes);
        assert_lacks(&results, "executable-stack");
        assert_lacks(&results, "missing-PT_GNU_STACK-section");
    }

    #[test]
    fn executable_stack_fires_for_same_family_machines() {
        use goblin::elf::header::{EM_386, EM_X86_64, ET_DYN, ET_EXEC};
        // Near misses: the other word size of the package's own ISA
        // is served by the same dynamic linker family, and an
        // executable stack there is a link decision with live effect
        // on the host -- exactly the population the finding addresses.
        for (elf_type, machine) in [(ET_EXEC, EM_X86_64), (ET_DYN, EM_X86_64), (ET_EXEC, EM_386)] {
            let results = rwe_stack_syn_machine(elf_type, machine, vec![phdr("GNU_STACK", "RWE")]);
            assert_eq!(
                lines_for(&results, "executable-stack").len(),
                1,
                "machine {machine} keeps firing: {results:?}"
            );
        }
    }

    #[test]
    fn foreign_machine_gate_fails_closed() {
        use goblin::elf::header::{EM_386, EM_NONE, EM_PARISC, EM_PPC64, EM_SPARCV9, EM_X86_64};
        // The word-size pairs share a family on both sides of the
        // comparison (and a hwcaps subarch resolves to its base), and
        // an unclassified machine or an unmapped package arch never
        // counts as foreign: the gate cannot classify those, so the
        // charge stands.
        assert!(!foreign_elf_machine(EM_SPARCV9, "sparc64"));
        assert!(!foreign_elf_machine(EM_PPC64, "ppc"));
        assert!(!foreign_elf_machine(EM_386, "x86_64_v3"));
        assert!(!foreign_elf_machine(EM_PARISC, "hppa"));
        assert!(foreign_elf_machine(EM_PARISC, "x86_64"));
        assert!(foreign_elf_machine(EM_X86_64, "hppa"));
        assert!(!foreign_elf_machine(EM_NONE, "x86_64"));
        assert!(!foreign_elf_machine(EM_X86_64, "noarch"));
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

    /// A crafted ELF with its `e_machine` rewritten: the header is
    /// the part the noarch foreign-target classification reads.
    fn elf_with_machine(machine: u16) -> Vec<u8> {
        let mut elf = craft_shlib_elf(false, None, None, &[]);
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf
    }

    /// Craft a minimal ELF object (32- or 64-bit) with the given
    /// `e_type` and `e_machine`, the named SHT_PROGBITS sections and
    /// a `.symtab` defining `defined_syms` in section 1. Enough
    /// structure for goblin to expose the header, the section names
    /// and the defined symbols -- the three things the GRUB-module
    /// classification reads.
    fn elf_object(
        is_64: bool,
        machine: u16,
        elf_type: u16,
        sections: &[&str],
        defined_syms: &[&str],
    ) -> Vec<u8> {
        // String tables first: their offsets drive the headers.
        let mut strtab: Vec<u8> = vec![0];
        let mut sym_name_offs: Vec<u32> = Vec::new();
        for s in defined_syms {
            sym_name_offs.push(u32::try_from(strtab.len()).unwrap());
            strtab.extend_from_slice(s.as_bytes());
            strtab.push(0);
        }
        let all_names: Vec<&str> = sections
            .iter()
            .copied()
            .chain([".symtab", ".strtab", ".shstrtab"])
            .collect();
        let mut shstrtab: Vec<u8> = vec![0];
        let mut sec_name_offs: Vec<u32> = Vec::new();
        for s in &all_names {
            sec_name_offs.push(u32::try_from(shstrtab.len()).unwrap());
            shstrtab.extend_from_slice(s.as_bytes());
            shstrtab.push(0);
        }

        let ehsize: usize = if is_64 { 64 } else { 52 };
        let shentsize: usize = if is_64 { 64 } else { 40 };
        let syment: usize = if is_64 { 24 } else { 16 };
        let nsec = sections.len();
        let strtab_idx = nsec + 2;
        let shstrtab_idx = nsec + 3;
        let shnum = nsec + 4;

        // The symbol table: a null entry, then one defined
        // GLOBAL FUNC symbol per name, all in section 1.
        let mut symtab: Vec<u8> = vec![0; syment];
        for off in &sym_name_offs {
            if is_64 {
                symtab.extend_from_slice(&off.to_le_bytes());
                symtab.push(0x12); // STB_GLOBAL | STT_FUNC
                symtab.push(0);
                symtab.extend_from_slice(&1u16.to_le_bytes());
                symtab.extend_from_slice(&0u64.to_le_bytes());
                symtab.extend_from_slice(&0u64.to_le_bytes());
            } else {
                symtab.extend_from_slice(&off.to_le_bytes());
                symtab.extend_from_slice(&0u32.to_le_bytes());
                symtab.extend_from_slice(&0u32.to_le_bytes());
                symtab.push(0x12);
                symtab.push(0);
                symtab.extend_from_slice(&1u16.to_le_bytes());
            }
        }

        // Section contents sit right after the ELF header: one byte
        // per named section, then symtab, strtab, shstrtab.
        let mut offsets: Vec<usize> = Vec::new();
        let mut cursor = ehsize;
        for _ in sections {
            offsets.push(cursor);
            cursor += 1;
        }
        let symtab_off = cursor;
        cursor += symtab.len();
        let strtab_off = cursor;
        cursor += strtab.len();
        let shstrtab_off = cursor;
        cursor += shstrtab.len();
        let shoff = cursor;

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(ELF_MAGIC);
        out.push(if is_64 { 2 } else { 1 }); // EI_CLASS
        out.push(1); // EI_DATA: little-endian
        out.push(1); // EI_VERSION
        out.extend_from_slice(&[0; 9]); // EI_OSABI + padding
        out.extend_from_slice(&elf_type.to_le_bytes());
        out.extend_from_slice(&machine.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // e_version
        if is_64 {
            out.extend_from_slice(&0u64.to_le_bytes()); // e_entry
            out.extend_from_slice(&0u64.to_le_bytes()); // e_phoff
            out.extend_from_slice(&(shoff as u64).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
            out.extend_from_slice(&(ehsize as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // e_phentsize
            out.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
            out.extend_from_slice(&(shentsize as u16).to_le_bytes());
            out.extend_from_slice(&(shnum as u16).to_le_bytes());
            out.extend_from_slice(&(shstrtab_idx as u16).to_le_bytes());
        } else {
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(shoff as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(ehsize as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&(shentsize as u16).to_le_bytes());
            out.extend_from_slice(&(shnum as u16).to_le_bytes());
            out.extend_from_slice(&(shstrtab_idx as u16).to_le_bytes());
        }
        debug_assert_eq!(out.len(), ehsize);
        out.resize(out.len() + sections.len(), b'X');
        out.extend_from_slice(&symtab);
        out.extend_from_slice(&strtab);
        out.extend_from_slice(&shstrtab);
        debug_assert_eq!(out.len(), shoff);

        struct Shdr {
            name: u32,
            stype: u32,
            flags: u64,
            off: usize,
            size: usize,
            link: u32,
            info: u32,
            align: u64,
            entsize: u64,
        }
        fn push_sh(out: &mut Vec<u8>, is_64: bool, sh: &Shdr) {
            out.extend_from_slice(&sh.name.to_le_bytes());
            out.extend_from_slice(&sh.stype.to_le_bytes());
            if is_64 {
                out.extend_from_slice(&sh.flags.to_le_bytes());
                out.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
                out.extend_from_slice(&(sh.off as u64).to_le_bytes());
                out.extend_from_slice(&(sh.size as u64).to_le_bytes());
                out.extend_from_slice(&sh.link.to_le_bytes());
                out.extend_from_slice(&sh.info.to_le_bytes());
                out.extend_from_slice(&sh.align.to_le_bytes());
                out.extend_from_slice(&sh.entsize.to_le_bytes());
            } else {
                out.extend_from_slice(&(sh.flags as u32).to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&(sh.off as u32).to_le_bytes());
                out.extend_from_slice(&(sh.size as u32).to_le_bytes());
                out.extend_from_slice(&sh.link.to_le_bytes());
                out.extend_from_slice(&sh.info.to_le_bytes());
                out.extend_from_slice(&(sh.align as u32).to_le_bytes());
                out.extend_from_slice(&(sh.entsize as u32).to_le_bytes());
            }
        }
        // The NULL section header.
        push_sh(
            &mut out,
            is_64,
            &Shdr {
                name: 0,
                stype: 0,
                flags: 0,
                off: 0,
                size: 0,
                link: 0,
                info: 0,
                align: 0,
                entsize: 0,
            },
        );
        for (i, _) in sections.iter().enumerate() {
            push_sh(
                &mut out,
                is_64,
                &Shdr {
                    name: sec_name_offs[i],
                    stype: 1,   // SHT_PROGBITS
                    flags: 0x2, // SHF_ALLOC
                    off: offsets[i],
                    size: 1,
                    link: 0,
                    info: 0,
                    align: 1,
                    entsize: 0,
                },
            );
        }
        push_sh(
            &mut out,
            is_64,
            &Shdr {
                name: sec_name_offs[nsec],
                stype: 2, // SHT_SYMTAB
                flags: 0,
                off: symtab_off,
                size: symtab.len(),
                link: u32::try_from(strtab_idx).unwrap(),
                info: 1, // one local symbol: the null entry
                align: 8,
                entsize: syment as u64,
            },
        );
        push_sh(
            &mut out,
            is_64,
            &Shdr {
                name: sec_name_offs[nsec + 1],
                stype: 3, // SHT_STRTAB
                flags: 0,
                off: strtab_off,
                size: strtab.len(),
                link: 0,
                info: 0,
                align: 1,
                entsize: 0,
            },
        );
        push_sh(
            &mut out,
            is_64,
            &Shdr {
                name: sec_name_offs[nsec + 2],
                stype: 3,
                flags: 0,
                off: shstrtab_off,
                size: shstrtab.len(),
                link: 0,
                info: 0,
                align: 1,
                entsize: 0,
            },
        );
        out
    }

    /// Craft a minimal ELF object with explicit section types,
    /// flags and sizes, and optional symbol tables whose entries
    /// carry explicit section indices -- the knobs the GRUB-module
    /// hardening pins need (a missing symtab, an empty or non-PROGBITS
    /// license section, an undefined import, a dynsym definition).
    /// `sections` are `(name, sh_type, sh_flags, size)`; contents are
    /// zero bytes of the stated size. `symtab` / `dynsym` are
    /// `(name, st_shndx)` lists; `None` omits the table entirely.
    fn elf_object2(
        is_64: bool,
        machine: u16,
        elf_type: u16,
        sections: &[(&str, u32, u64, u64)],
        symtab: Option<&[(&str, u16)]>,
        dynsym: Option<&[(&str, u16)]>,
    ) -> Vec<u8> {
        let ehsize: usize = if is_64 { 64 } else { 52 };
        let shentsize: usize = if is_64 { 64 } else { 40 };
        let syment: usize = if is_64 { 24 } else { 16 };

        let build_strtab = |syms: &[(&str, u16)]| -> Vec<u8> {
            let mut tab: Vec<u8> = vec![0];
            for (name, _) in syms {
                tab.extend_from_slice(name.as_bytes());
                tab.push(0);
            }
            tab
        };
        let build_symtab = |syms: &[(&str, u16)], strtab: &[u8]| -> Vec<u8> {
            let mut offs: Vec<u32> = Vec::new();
            let mut cursor = 1usize;
            for (name, _) in syms {
                offs.push(u32::try_from(cursor).unwrap());
                cursor += name.len() + 1;
            }
            let _ = strtab;
            let mut tab: Vec<u8> = vec![0; syment];
            for (i, (_, shndx)) in syms.iter().enumerate() {
                if is_64 {
                    tab.extend_from_slice(&offs[i].to_le_bytes());
                    tab.push(0x12); // STB_GLOBAL | STT_FUNC
                    tab.push(0);
                    tab.extend_from_slice(&shndx.to_le_bytes());
                    tab.extend_from_slice(&0u64.to_le_bytes());
                    tab.extend_from_slice(&0u64.to_le_bytes());
                } else {
                    tab.extend_from_slice(&offs[i].to_le_bytes());
                    tab.extend_from_slice(&0u32.to_le_bytes());
                    tab.extend_from_slice(&0u32.to_le_bytes());
                    tab.push(0x12);
                    tab.push(0);
                    tab.extend_from_slice(&shndx.to_le_bytes());
                }
            }
            tab
        };

        let strtab: Vec<u8> = symtab.map(build_strtab).unwrap_or_default();
        let symtab_bytes: Vec<u8> = symtab.map(|s| build_symtab(s, &strtab)).unwrap_or_default();
        let dynstr: Vec<u8> = dynsym.map(build_strtab).unwrap_or_default();
        let dynsym_bytes: Vec<u8> = dynsym.map(|s| build_symtab(s, &dynstr)).unwrap_or_default();

        // Section order: NULL, the named sections, then .symtab,
        // .strtab, .dynsym, .dynstr (each pair only when present),
        // then .shstrtab.
        let nsec = sections.len();
        let strtab_idx = nsec + 2;
        let dynsym_idx = if symtab.is_some() { nsec + 3 } else { nsec + 1 };
        let dynstr_idx = dynsym_idx + 1;
        let shstrtab_idx = if dynsym.is_some() {
            dynstr_idx + 1
        } else if symtab.is_some() {
            nsec + 3
        } else {
            nsec + 1
        };
        let shnum = shstrtab_idx + 1;

        let mut all_names: Vec<&str> = sections.iter().map(|(n, _, _, _)| *n).collect();
        if symtab.is_some() {
            all_names.extend([".symtab", ".strtab"]);
        }
        if dynsym.is_some() {
            all_names.extend([".dynsym", ".dynstr"]);
        }
        all_names.push(".shstrtab");
        let mut shstrtab: Vec<u8> = vec![0];
        let mut sec_name_offs: Vec<u32> = Vec::new();
        for s in &all_names {
            sec_name_offs.push(u32::try_from(shstrtab.len()).unwrap());
            shstrtab.extend_from_slice(s.as_bytes());
            shstrtab.push(0);
        }

        let mut offsets: Vec<usize> = Vec::new();
        let mut cursor = ehsize;
        for (_, _, _, size) in sections {
            offsets.push(cursor);
            cursor += *size as usize;
        }
        let symtab_off = cursor;
        cursor += symtab_bytes.len();
        let strtab_off = cursor;
        cursor += strtab.len();
        let dynsym_off = cursor;
        cursor += dynsym_bytes.len();
        let dynstr_off = cursor;
        cursor += dynstr.len();
        let shstrtab_off = cursor;
        cursor += shstrtab.len();
        let shoff = cursor;

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(ELF_MAGIC);
        out.push(if is_64 { 2 } else { 1 });
        out.push(1);
        out.push(1);
        out.extend_from_slice(&[0; 9]);
        out.extend_from_slice(&elf_type.to_le_bytes());
        out.extend_from_slice(&machine.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        if is_64 {
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&(shoff as u64).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(ehsize as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&(shentsize as u16).to_le_bytes());
            out.extend_from_slice(&(shnum as u16).to_le_bytes());
            out.extend_from_slice(&(shstrtab_idx as u16).to_le_bytes());
        } else {
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(shoff as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(ehsize as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&(shentsize as u16).to_le_bytes());
            out.extend_from_slice(&(shnum as u16).to_le_bytes());
            out.extend_from_slice(&(shstrtab_idx as u16).to_le_bytes());
        }
        debug_assert_eq!(out.len(), ehsize);
        for (_, _, _, size) in sections {
            out.resize(out.len() + *size as usize, 0);
        }
        out.extend_from_slice(&symtab_bytes);
        out.extend_from_slice(&strtab);
        out.extend_from_slice(&dynsym_bytes);
        out.extend_from_slice(&dynstr);
        out.extend_from_slice(&shstrtab);
        debug_assert_eq!(out.len(), shoff);

        struct Shdr {
            name: u32,
            stype: u32,
            flags: u64,
            off: usize,
            size: usize,
            link: u32,
            entsize: u64,
        }
        fn push_sh(out: &mut Vec<u8>, is_64: bool, sh: &Shdr) {
            out.extend_from_slice(&sh.name.to_le_bytes());
            out.extend_from_slice(&sh.stype.to_le_bytes());
            if is_64 {
                out.extend_from_slice(&sh.flags.to_le_bytes());
                out.extend_from_slice(&0u64.to_le_bytes());
                out.extend_from_slice(&(sh.off as u64).to_le_bytes());
                out.extend_from_slice(&(sh.size as u64).to_le_bytes());
                out.extend_from_slice(&sh.link.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&1u64.to_le_bytes());
                out.extend_from_slice(&sh.entsize.to_le_bytes());
            } else {
                out.extend_from_slice(&(sh.flags as u32).to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&(sh.off as u32).to_le_bytes());
                out.extend_from_slice(&(sh.size as u32).to_le_bytes());
                out.extend_from_slice(&sh.link.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes());
                out.extend_from_slice(&1u32.to_le_bytes());
                out.extend_from_slice(&(sh.entsize as u32).to_le_bytes());
            }
        }
        let null = Shdr {
            name: 0,
            stype: 0,
            flags: 0,
            off: 0,
            size: 0,
            link: 0,
            entsize: 0,
        };
        push_sh(&mut out, is_64, &null);
        for (i, (_, stype, flags, size)) in sections.iter().enumerate() {
            push_sh(
                &mut out,
                is_64,
                &Shdr {
                    name: sec_name_offs[i],
                    stype: *stype,
                    flags: *flags,
                    off: offsets[i],
                    size: *size as usize,
                    link: 0,
                    entsize: 0,
                },
            );
        }
        let mut name_cursor = nsec;
        if symtab.is_some() {
            push_sh(
                &mut out,
                is_64,
                &Shdr {
                    name: sec_name_offs[name_cursor],
                    stype: 2, // SHT_SYMTAB
                    flags: 0,
                    off: symtab_off,
                    size: symtab_bytes.len(),
                    link: u32::try_from(strtab_idx).unwrap(),
                    entsize: syment as u64,
                },
            );
            push_sh(
                &mut out,
                is_64,
                &Shdr {
                    name: sec_name_offs[name_cursor + 1],
                    stype: 3, // SHT_STRTAB
                    flags: 0,
                    off: strtab_off,
                    size: strtab.len(),
                    link: 0,
                    entsize: 0,
                },
            );
            name_cursor += 2;
        }
        if dynsym.is_some() {
            push_sh(
                &mut out,
                is_64,
                &Shdr {
                    name: sec_name_offs[name_cursor],
                    stype: 11, // SHT_DYNSYM
                    flags: 0,
                    off: dynsym_off,
                    size: dynsym_bytes.len(),
                    link: u32::try_from(dynstr_idx).unwrap(),
                    entsize: syment as u64,
                },
            );
            push_sh(
                &mut out,
                is_64,
                &Shdr {
                    name: sec_name_offs[name_cursor + 1],
                    stype: 3,
                    flags: 0,
                    off: dynstr_off,
                    size: dynstr.len(),
                    link: 0,
                    entsize: 0,
                },
            );
            name_cursor += 2;
        }
        push_sh(
            &mut out,
            is_64,
            &Shdr {
                name: sec_name_offs[name_cursor],
                stype: 3,
                flags: 0,
                off: shstrtab_off,
                size: shstrtab.len(),
                link: 0,
                entsize: 0,
            },
        );
        out
    }

    /// A `PkgFile` backed by a real temp file holding `bytes`, so the
    /// classification reads the payload header and archive members
    /// instead of the magic string.
    fn real_file_pkgfile(
        dir: &tempfile::TempDir,
        file_name: &str,
        name: &str,
        magic: &str,
        bytes: &[u8],
    ) -> PkgFile {
        let path = dir.path().join(file_name);
        std::fs::write(&path, bytes).expect("write fixture");
        PkgFile {
            name: name.to_string(),
            path: path.to_str().unwrap().to_string(),
            magic: magic.to_string(),
            mode: 0o100644,
            ..Default::default()
        }
    }

    #[test]
    fn elf_machine_class_from_bytes_reads_both_endians() {
        // The header's data-encoding byte decides the e_machine byte
        // order: the corpus carries MSB files (S/390, PowerPC,
        // PA-RISC) alongside the LSB ones.
        let mut le = [0u8; 20];
        le[0..4].copy_from_slice(ELF_MAGIC);
        le[5] = 1;
        le[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert_eq!(
            elf_machine_class_from_bytes(&le),
            Some(ElfMachineClass::Host)
        );
        let mut be = [0u8; 20];
        be[0..4].copy_from_slice(ELF_MAGIC);
        be[5] = 2;
        be[18..20].copy_from_slice(&62u16.to_be_bytes());
        assert_eq!(
            elf_machine_class_from_bytes(&be),
            Some(ElfMachineClass::Host)
        );
        be[18..20].copy_from_slice(&22u16.to_be_bytes()); // EM_S390
        assert_eq!(
            elf_machine_class_from_bytes(&be),
            Some(ElfMachineClass::Foreign)
        );
        be[18..20].copy_from_slice(&0u16.to_be_bytes()); // EM_NONE
        assert_eq!(
            elf_machine_class_from_bytes(&be),
            Some(ElfMachineClass::Unknown)
        );
        // No ELF header to read.
        assert_eq!(elf_machine_class_from_bytes(b"!<arch>\n......."), None);
        assert_eq!(elf_machine_class_from_bytes(&le[..12]), None);
    }

    #[test]
    fn target_payload_location_shapes() {
        // Issue #848: a cross sys-root with any target triplet, and the
        // firmware directories, are target-payload locations.
        assert!(in_target_payload_location(
            "/usr/riscv64-suse-linux/sys-root/lib64/libc.so.6"
        ));
        assert!(in_target_payload_location(
            "/usr/x86_64-w64-mingw32/sys-root/mingw/lib/libfoo.a"
        ));
        // A bare target prefix is a sys-root parent too: the AVR
        // toolchain's single-component target directory, and the
        // MinGW /usr/<arch>/sys-root layouts.
        assert!(in_target_payload_location(
            "/usr/avr/sys-root/lib/avr/libc.a"
        ));
        assert!(in_target_payload_location(
            "/usr/x86_64/sys-root/win32/lib/libfoo.a"
        ));
        assert!(in_target_payload_location("/usr/lib/firmware/miXart8.elf"));
        assert!(in_target_payload_location("/lib/firmware/miXart8.elf"));
        // The boot partition holds boot payload by layout: the
        // Raspberry Pi GPU firmware lives under /boot/vc.
        assert!(in_target_payload_location("/boot/vc/start.elf"));
        assert!(!in_target_payload_location("/boot"));
        assert!(!in_target_payload_location("/bootx/start.elf"));
        // The segment after /usr must name a target: a bare `sys-root`
        // component below a host /usr layout directory does not make
        // a location a sys-root.
        assert!(!in_target_payload_location("/usr/lib/sys-root/libfoo.so"));
        assert!(!in_target_payload_location("/usr/share/sys-root/libfoo.so"));
        assert!(!in_target_payload_location("/usr/local/sys-root/libfoo.so"));
        assert!(!in_target_payload_location(
            "/usr/libexec/sys-root/libfoo.so"
        ));
        // A triplet directory without the sys-root level is host layout.
        assert!(!in_target_payload_location(
            "/usr/riscv64-suse-linux/lib/libc.so.6"
        ));
        assert!(!in_target_payload_location("/usr/bin/foo"));
        assert!(!in_target_payload_location("/usr/lib/firmware2/foo.elf"));
    }

    #[test]
    fn noarch_sysroot_foreign_elf_is_quiet() {
        // Issue #848: a cross sys-root's payload is the target's C
        // library. No file backs this fixture, so the magic string's
        // machine carries the classification.
        let config = test_config();
        let pkg = synthetic_pkg(
            "cross-riscv64-glibc-devel",
            "noarch",
            vec![syn_file(
                "/usr/riscv64-suse-linux/sys-root/lib64/libc.so.6",
                "ELF 64-bit LSB shared object, UCB RISC-V, RVC, double-float ABI, \
                 version 1 (SYSV), dynamically linked, not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_sysroot_foreign_elf_bytes_are_quiet() {
        // The same shape with a real payload: the header bytes
        // (EM_RISCV) classify, in a sys-root location.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "libc.so.6",
            "/usr/riscv64-suse-linux/sys-root/lib64/libc.so.6",
            "ELF 64-bit LSB shared object, UCB RISC-V, version 1 (SYSV)",
            &elf_with_machine(goblin::elf::header::EM_RISCV),
        );
        let pkg = synthetic_pkg("cross-riscv64-glibc-devel", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_firmware_foreign_elf_is_quiet() {
        // Issue #848: DSP firmware in ELF form (a PowerPC image the
        // sound card executes) under the firmware directory.
        let config = test_config();
        let pkg = synthetic_pkg(
            "alsa-firmware",
            "noarch",
            vec![syn_file(
                "/usr/lib/firmware/mixart/miXart8.elf",
                "ELF 32-bit MSB shared object, PowerPC or cisco 4500, version 1 (SYSV), \
                 statically linked, not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_boot_foreign_elf_bytes_are_quiet() {
        // The Raspberry Pi boot firmware: a VideoCore III image
        // (e_machine 137) the GPU executes before the ARM cores
        // start, shipped under /boot/vc. Foreign by header, in a
        // boot-payload location.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "start.elf",
            "/boot/vc/start.elf",
            "ELF 32-bit LSB executable, Broadcom VideoCore III, version 1 (SYSV), \
             statically linked, stripped",
            &elf_with_machine(137),
        );
        let pkg = synthetic_pkg("raspberrypi-firmware", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_boot_host_elf_still_fires() {
        // Near-miss: the boot location saves foreign payload, not a
        // host binary stored there.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "tool",
            "/boot/efi/tool",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked",
            &elf_with_machine(goblin::elf::header::EM_X86_64),
        );
        let pkg = synthetic_pkg("noarchpkg", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "host ELF under /boot fires: {results:?}");
    }

    #[test]
    fn noarch_sysroot_foreign_archive_is_quiet() {
        // Issue #848: a sys-root static library whose ELF members are
        // all for the target machine (a data member does not change
        // the classification).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let riscv = elf_with_machine(goblin::elf::header::EM_RISCV);
        let archive = craft_ar_archive(&[("a.o", &riscv), ("note.o", b"data\n")]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/riscv64-suse-linux/sys-root/usr/lib64/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("cross-riscv64-glibc-devel", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_avr_sysroot_foreign_elf_bytes_are_quiet() {
        // The AVR toolchain's sys-root sits under a bare target
        // directory (/usr/avr, no triplet dashes): its payload is
        // EM_AVR objects, foreign by header.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "crtmega328p.o",
            "/usr/avr/sys-root/lib/avr5/crtmega328p.o",
            "ELF 32-bit LSB relocatable, Atmel AVR 8-bit, version 1 (SYSV), not stripped",
            &elf_with_machine(goblin::elf::header::EM_AVR),
        );
        let pkg = synthetic_pkg("avr-libc", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_avr_sysroot_foreign_elf_magic_is_quiet() {
        // The magic fallback names the machine when no payload can
        // be opened: libmagic spells the AVR machine "Atmel AVR".
        let config = test_config();
        let pkg = synthetic_pkg(
            "avr-libc",
            "noarch",
            vec![syn_file(
                "/usr/avr/sys-root/lib/avr5/crtmega328p.o",
                "ELF 32-bit LSB relocatable, Atmel AVR 8-bit, version 1 (SYSV), not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_avr_sysroot_foreign_archive_is_quiet() {
        // An AVR static library: every ELF member is EM_AVR.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let avr = elf_with_machine(goblin::elf::header::EM_AVR);
        let archive = craft_ar_archive(&[("a.o", &avr), ("note.o", b"data\n")]);
        let file = real_file_pkgfile(
            &dir,
            "libc.a",
            "/usr/avr/sys-root/lib/libc.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("avr-libc", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_avr_sysroot_host_elf_still_fires() {
        // Near-miss: the bare-target sys-root location saves foreign
        // payload, not a host object that strayed into it.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "libfoo.o",
            "/usr/avr/sys-root/lib/libfoo.o",
            "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped",
            &elf_with_machine(goblin::elf::header::EM_X86_64),
        );
        let pkg = synthetic_pkg("noarchpkg", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(
            lines.len(),
            1,
            "host ELF in the AVR sys-root fires: {results:?}"
        );
    }

    #[test]
    fn noarch_foreign_elf_in_host_dir_sysroot_still_fires() {
        // Near-miss: a directory named sys-root below a host /usr
        // layout directory is host layout, so foreign payload there
        // is not in a target-payload location.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "libfoo.so",
            "/usr/share/sys-root/lib/libfoo.so",
            "ELF 64-bit LSB shared object, UCB RISC-V, version 1 (SYSV)",
            &elf_with_machine(goblin::elf::header::EM_RISCV),
        );
        let pkg = synthetic_pkg("noarchpkg", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(
            lines.len(),
            1,
            "foreign ELF below a host-dir sys-root fires: {results:?}"
        );
    }

    #[test]
    fn noarch_archive_without_elf_members_is_quiet() {
        // Issue #848: archives whose members are all in foreign
        // object formats (a COFF object, a wasm object) carry no ELF
        // code; the exemption is by member content, at any location.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let coff: &[u8] = b"\x64\x86\x06\x00\x00\x00\x00\x00\x36\x01\x00\x00\x0e\x00\x00\x00";
        let wasm: &[u8] = b"\x00asm\x01\x00\x00\x00";
        let coff_archive = craft_ar_archive(&[("coff.o", coff)]);
        let wasm_archive = craft_ar_archive(&[("wasm.o", wasm)]);
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![
                real_file_pkgfile(
                    &dir,
                    "libcoff.a",
                    "/usr/lib/libcoff.a",
                    "current ar archive",
                    &coff_archive,
                ),
                real_file_pkgfile(
                    &dir,
                    "libwasm.a",
                    "/usr/lib/rustlib/src/libwasm.a",
                    "current ar archive",
                    &wasm_archive,
                ),
                real_file_pkgfile(
                    &dir,
                    "libempty.a",
                    "/usr/lib/libempty.a",
                    "current ar archive",
                    b"!<arch>\n",
                ),
            ],
        );
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_grub_module_is_quiet() {
        // A GRUB module in a noarch
        // package is the bootloader's own payload, not host code --
        // a host-machine ET_REL carrying GRUB's ABI sections.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            true,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::ET_REL,
            &[".text", ".module_license", ".moddeps", ".modname"],
            &["grub_mod_init", "grub_mod_fini"],
        );
        let file = real_file_pkgfile(
            &dir,
            "normal.mod",
            "/usr/share/grub2/x86_64-efi/normal.mod",
            "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped",
            &bytes,
        );
        let pkg = synthetic_pkg("grub2-x86_64-efi", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_grub_debug_module_is_quiet() {
        // The debug packages' `.module` intermediates are the same
        // modules before finalisation: they carry `.module_license`
        // but neither `.modname` nor `.moddeps`, so the signature
        // must not require the finalisation sections.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            false,
            goblin::elf::header::EM_386,
            goblin::elf::header::ET_REL,
            &[".text", ".module_license"],
            &["grub_mod_init", "grub_mod_fini"],
        );
        let file = real_file_pkgfile(
            &dir,
            "acpi.module",
            "/usr/share/grub2/i386-pc/acpi.module",
            "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped",
            &bytes,
        );
        let pkg = synthetic_pkg("grub2-i386-pc-debug", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_plain_relocatable_object_still_fires() {
        // Near-miss, #848's core case: an ordinary host `.o` in a
        // noarch package -- ET_REL and host-machine like a module,
        // but no GRUB ABI section. It keeps firing.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            true,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::ET_REL,
            &[".text"],
            &[],
        );
        let file = real_file_pkgfile(
            &dir,
            "efiemu64.o",
            "/usr/share/grub2/i386-pc/efiemu64.o",
            "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped",
            &bytes,
        );
        let pkg = synthetic_pkg("grub2-i386-pc", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "a plain object fires: {results:?}");
    }

    #[test]
    fn noarch_grub_kernel_image_still_fires() {
        // Near-miss: GRUB's linked kernel image for the EFI
        // platforms is itself an ET_REL carrying `.module_license`
        // (the license objects of the statically linked modules),
        // but it defines the `grub_main` entry point, which no
        // module defines. It keeps firing.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            false,
            goblin::elf::header::EM_386,
            goblin::elf::header::ET_REL,
            &[".text", ".module_license"],
            &["grub_main"],
        );
        let file = real_file_pkgfile(
            &dir,
            "kernel.img",
            "/usr/share/grub2/i386-efi/kernel.img",
            "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped",
            &bytes,
        );
        let pkg = synthetic_pkg("grub2-i386-efi", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "the kernel image fires: {results:?}");
    }

    #[test]
    fn noarch_grub_sectioned_exec_still_fires() {
        // Near-miss: the PC platforms' kernel images are ET_EXEC
        // and carry `.module_license` too; the signature requires
        // ET_REL, so they keep firing.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            true,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::ET_EXEC,
            &[".text", ".module_license"],
            &["grub_main"],
        );
        let file = real_file_pkgfile(
            &dir,
            "kernel.img",
            "/usr/share/grub2/i386-pc/kernel.img",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), not stripped",
            &bytes,
        );
        let pkg = synthetic_pkg("grub2-i386-pc", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "an ET_EXEC image fires: {results:?}");
    }

    #[test]
    fn noarch_grub_sectioned_exec_without_entry_still_fires() {
        // The type arm isolated: an ET_EXEC carrying the ABI
        // sections and a module entry symbol, but not `grub_main`.
        // Only the ET_REL requirement keeps this firing -- a linked
        // image is a runnable host binary whatever sections it
        // carries.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            true,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::ET_EXEC,
            &[".text", ".module_license", ".modname"],
            &["grub_mod_init"],
        );
        let file = real_file_pkgfile(
            &dir,
            "linked.img",
            "/usr/share/grub2/x86_64-efi/linked.img",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), not stripped",
            &bytes,
        );
        let pkg = synthetic_pkg("grub2-x86_64-efi", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "a linked image fires: {results:?}");
    }

    #[test]
    fn noarch_grub_module_in_archive_still_fires() {
        // The GRUB arm reads plain files only: an archive member
        // with the module signature is classified by the archive
        // rules as before (a host ELF member keeps the archive
        // firing outside the foreign-target exemption).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let module = elf_object(
            true,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::ET_REL,
            &[".text", ".module_license", ".modname"],
            &["grub_mod_init"],
        );
        let archive = craft_ar_archive(&[("normal.o", &module)]);
        let file = real_file_pkgfile(
            &dir,
            "libmodules.a",
            "/usr/lib/libmodules.a",
            "current ar archive",
            &archive,
        );
        assert!(!noarch_binary_is_grub_module(&file));
        let pkg = synthetic_pkg("noarchpkg", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "an archived module fires: {results:?}");
    }

    #[test]
    fn noarch_grub_stripped_image_still_fires() {
        // A module-shaped object with executable content but no
        // symbol table: the not-defining-grub_main test is
        // undecidable, so the gate fails closed and the file keeps
        // firing (the stripped kernel-image shape).
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object2(
            true,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::ET_REL,
            &[(".text", 1, 0x6, 64), (".module_license", 1, 0x2, 15)],
            None,
            None,
        );
        let file = real_file_pkgfile(
            &dir,
            "stripped.mod",
            "/usr/share/grub2/x86_64-efi/stripped.mod",
            "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), stripped",
            &bytes,
        );
        assert!(!noarch_binary_is_grub_module(&file));
        let pkg = synthetic_pkg("grub2-x86_64-efi", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "a stripped image fires: {results:?}");
    }

    #[test]
    fn noarch_grub_aggregator_without_symtab_is_quiet() {
        // The corpus's symtab-less modules are link-only aggregators:
        // no executable content, so there is no entry point they
        // could define and the credit holds without a symbol table.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object2(
            false,
            goblin::elf::header::EM_386,
            goblin::elf::header::ET_REL,
            &[
                (".text", 1, 0x6, 0),
                (".module_license", 1, 0x2, 15),
                (".moddeps", 1, 0, 29),
                (".modname", 1, 0, 10),
            ],
            None,
            None,
        );
        let file = real_file_pkgfile(
            &dir,
            "all_video.mod",
            "/usr/share/grub2/i386-pc/all_video.mod",
            "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), stripped",
            &bytes,
        );
        assert!(noarch_binary_is_grub_module(&file));
        let pkg = synthetic_pkg("grub2-i386-pc", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_grub_license_section_must_be_progbits_with_content() {
        // The license stamp is a PROGBITS section carrying the
        // licence string; a name-only section -- empty, or of
        // another type -- is not the stamp and does not credit.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        for (tag, license) in [
            ("empty", (".module_license", 1u32, 0x2u64, 0u64)),
            ("note", (".module_license", 7, 0x2, 15)),
        ] {
            let bytes = elf_object2(
                true,
                goblin::elf::header::EM_X86_64,
                goblin::elf::header::ET_REL,
                &[(".text", 1, 0x6, 32), license],
                Some(&[("grub_mod_init", 1)]),
                None,
            );
            let file = real_file_pkgfile(
                &dir,
                "fake.mod",
                "/usr/share/grub2/x86_64-efi/fake.mod",
                "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped",
                &bytes,
            );
            assert!(
                !noarch_binary_is_grub_module(&file),
                "{tag} license section must not credit"
            );
            let pkg = synthetic_pkg("grub2-x86_64-efi", "noarch", vec![file]);
            let results = driver_results(&pkg, &config);
            let lines = lines_for(
                &results,
                "arch-independent-package-contains-binary-or-object",
            );
            assert_eq!(lines.len(), 1, "{tag} shape fires: {results:?}");
        }
    }

    #[test]
    fn noarch_grub_dynsym_or_versioned_main_still_fires() {
        // A defined grub_main blocks the credit wherever it is
        // recorded: in the dynsym, or under a versioned spelling in
        // either table.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sections: &[(&str, u32, u64, u64)] =
            &[(".text", 1, 0x6, 32), (".module_license", 1, 0x2, 15)];
        for (tag, symtab, dynsym) in [
            (
                "dynsym",
                Some(&[("grub_mod_init", 1u16)][..]),
                Some(&[("grub_main", 1u16)][..]),
            ),
            (
                "versioned-symtab",
                Some(&[("grub_main@@GRUB_1.0", 1u16)][..]),
                None,
            ),
            (
                "versioned-dynsym",
                Some(&[("grub_mod_init", 1u16)][..]),
                Some(&[("grub_main@GRUB_1.0", 1u16)][..]),
            ),
        ] {
            let bytes = elf_object2(
                true,
                goblin::elf::header::EM_X86_64,
                goblin::elf::header::ET_REL,
                sections,
                symtab,
                dynsym,
            );
            let file = real_file_pkgfile(
                &dir,
                "linked.mod",
                "/usr/share/grub2/x86_64-efi/linked.mod",
                "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped",
                &bytes,
            );
            assert!(
                !noarch_binary_is_grub_module(&file),
                "{tag} grub_main must block the credit"
            );
            let pkg = synthetic_pkg("grub2-x86_64-efi", "noarch", vec![file]);
            let results = driver_results(&pkg, &config);
            let lines = lines_for(
                &results,
                "arch-independent-package-contains-binary-or-object",
            );
            assert_eq!(lines.len(), 1, "{tag} shape fires: {results:?}");
        }
    }

    #[test]
    fn noarch_grub_undefined_main_import_is_quiet() {
        // Modules reference the kernel's entry points; an undefined
        // import of grub_main is not a definition and does not block
        // the credit.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object2(
            true,
            goblin::elf::header::EM_X86_64,
            goblin::elf::header::ET_REL,
            &[(".text", 1, 0x6, 32), (".module_license", 1, 0x2, 15)],
            Some(&[("grub_main", 0), ("grub_mod_init", 1)]),
            None,
        );
        let file = real_file_pkgfile(
            &dir,
            "importer.mod",
            "/usr/share/grub2/x86_64-efi/importer.mod",
            "ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped",
            &bytes,
        );
        assert!(noarch_binary_is_grub_module(&file));
        let pkg = synthetic_pkg("grub2-x86_64-efi", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_grub_module_library_without_init_fini_is_quiet() {
        // A full platform module library (the grub2-i386-pc shape,
        // ~350 modules) is quiet as a set; the credit reads the
        // license section and the entry-point test only, so modules
        // defining neither grub_mod_init nor grub_mod_fini are
        // credited on the same signature.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            false,
            goblin::elf::header::EM_386,
            goblin::elf::header::ET_REL,
            &[".text", ".module_license", ".moddeps", ".modname"],
            &["grub_mod_register"],
        );
        let mut files = Vec::new();
        for i in 0..350 {
            files.push(real_file_pkgfile(
                &dir,
                &format!("mod{i}.mod"),
                &format!("/usr/share/grub2/i386-pc/mod{i}.mod"),
                "ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped",
                &bytes,
            ));
        }
        let pkg = synthetic_pkg("grub2-i386-pc", "noarch", files);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
    }

    #[test]
    fn noarch_foreign_grub_shaped_payload_boundaries() {
        // The GRUB arm is scoped to host machines (the class
        // defined above). A foreign-machine module-shaped object is the
        // foreign-target gate's business, unchanged: quiet in a
        // target-payload location, firing outside one.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let bytes = elf_object(
            true,
            goblin::elf::header::EM_AARCH64,
            goblin::elf::header::ET_REL,
            &[".text", ".module_license", ".modname"],
            &["grub_mod_init"],
        );
        let in_sysroot = real_file_pkgfile(
            &dir,
            "in.mod",
            "/usr/aarch64-suse-linux/sys-root/usr/lib/in.mod",
            "ELF 64-bit LSB relocatable, ARM aarch64, version 1 (SYSV), not stripped",
            &bytes,
        );
        assert!(!noarch_binary_is_grub_module(&in_sysroot));
        let pkg = synthetic_pkg("cross-pkg", "noarch", vec![in_sysroot]);
        let results = driver_results(&pkg, &config);
        assert_lacks(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );

        let outside = real_file_pkgfile(
            &dir,
            "out.mod",
            "/usr/share/grub2/arm64-efi/out.mod",
            "ELF 64-bit LSB relocatable, ARM aarch64, version 1 (SYSV), not stripped",
            &bytes,
        );
        let pkg = synthetic_pkg("grub2-arm64-efi", "noarch", vec![outside]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(
            lines.len(),
            1,
            "a foreign object outside the target locations fires: {results:?}"
        );
    }

    #[test]
    fn noarch_host_elf_in_sysroot_still_fires() {
        // Near-miss: the sys-root location saves foreign payload, not
        // a host binary that strayed into it.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/riscv64-suse-linux/sys-root/lib64/libfoo.so.1",
                "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), \
                 dynamically linked, not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "host ELF in a sys-root fires: {results:?}");
    }

    #[test]
    fn noarch_host_elf_in_firmware_still_fires() {
        // Near-miss: a host ELF fires regardless of directory,
        // including the firmware directory.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/lib/firmware/helper.elf",
                "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), \
                 statically linked, not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "host ELF in firmware fires: {results:?}");
    }

    #[test]
    fn noarch_foreign_elf_outside_target_locations_still_fires() {
        // Near-miss: a foreign ELF in ordinary host layout (a program
        // directory) is a binary in a noarch package; only the
        // target-payload locations exempt it.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/bin/foo",
                "ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), \
                 dynamically linked, not stripped",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(
            lines.len(),
            1,
            "foreign ELF outside target locations fires: {results:?}"
        );
    }

    #[test]
    fn noarch_archive_with_host_member_in_sysroot_still_fires() {
        // Near-miss: one host-machine ELF member is enough; the
        // archive is not all-foreign.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let riscv = elf_with_machine(goblin::elf::header::EM_RISCV);
        let host = elf_with_machine(goblin::elf::header::EM_X86_64);
        let archive = craft_ar_archive(&[("a.o", &riscv), ("b.o", &host)]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/riscv64-suse-linux/sys-root/usr/lib64/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("noarchpkg", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(
            lines.len(),
            1,
            "archive with a host member fires: {results:?}"
        );
    }

    #[test]
    fn noarch_foreign_archive_outside_target_locations_still_fires() {
        // Near-miss: all-foreign ELF members still fire outside the
        // target-payload locations.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let riscv = elf_with_machine(goblin::elf::header::EM_RISCV);
        let archive = craft_ar_archive(&[("a.o", &riscv)]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/lib/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("noarchpkg", "noarch", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(
            lines.len(),
            1,
            "foreign archive in the host libdir fires: {results:?}"
        );
    }

    #[test]
    fn noarch_unknown_machine_elf_in_sysroot_still_fires() {
        // The exemption takes positive evidence: a magic naming no
        // machine at all (and no file to read) stays a finding.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/riscv64-suse-linux/sys-root/lib64/libfoo.so.1",
                "ELF 64-bit LSB shared object, version 1 (SYSV), dynamically linked",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "unclassified ELF fires: {results:?}");
    }

    #[test]
    fn noarch_unreadable_archive_in_sysroot_still_fires() {
        // An archive whose members cannot be read (no payload file)
        // gives no evidence of foreign content and stays a finding.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/riscv64-suse-linux/sys-root/usr/lib64/libfoo.a",
                "current ar archive",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "unreadable archive fires: {results:?}");
    }

    #[test]
    fn noarch_lua_bytecode_still_fires() {
        // Lua bytecode carries no ELF machine to classify, so the
        // foreign-target exemption does not reach it.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/share/wesnoth/data/test/bytecode.bin",
                "Lua bytecode, version 5.3",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "Lua bytecode fires: {results:?}");
    }

    #[test]
    fn noarch_ocaml_native_still_fires() {
        // OCaml native code carries no ELF machine to classify, so
        // the foreign-target exemption does not reach it -- in a
        // target-payload location either.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/riscv64-suse-linux/sys-root/lib64/camlprog",
                "Objective caml native code executable, version 5.2",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(lines.len(), 1, "OCaml native code fires: {results:?}");
    }

    #[test]
    fn noarch_file_named_sysroot_still_fires() {
        // The sys-root location is the path *below* sys-root: a file
        // whose path ends at sys-root itself sits in no sys-root, so
        // foreign evidence does not exempt it.
        let config = test_config();
        let pkg = synthetic_pkg(
            "noarchpkg",
            "noarch",
            vec![syn_file(
                "/usr/riscv64-suse-linux/sys-root",
                "ELF 64-bit LSB shared object, UCB RISC-V, version 1 (SYSV)",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(
            &results,
            "arch-independent-package-contains-binary-or-object",
        );
        assert_eq!(
            lines.len(),
            1,
            "the sys-root path itself fires: {results:?}"
        );
    }

    #[test]
    fn noarch_magic_machine_names_classify_foreign() {
        // The spellings libmagic actually emits: aarch64 payloads are
        // "ARM aarch64" (the ARM token carries them), and the ARC
        // machine name arrives in comma form.
        assert_eq!(
            elf_machine_class_from_magic(
                "ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV)"
            ),
            ElfMachineClass::Foreign
        );
        assert_eq!(
            elf_machine_class_from_magic("ELF 32-bit LSB relocatable, ARC, version 1 (SYSV)"),
            ElfMachineClass::Foreign
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
    fn no_binary_quiet_for_debugsource_package() {
        // pam-config-debugsource shape (issue #948): an arch package
        // whose whole payload is source files under /usr/src/debug.
        let config = test_config();
        let pkg = synthetic_pkg(
            "pam-config-debugsource",
            "x86_64",
            vec![
                syn_file(
                    "/usr/src/debug/pam-config-2.14/src/pam-config.c",
                    "ASCII text",
                ),
                syn_file(
                    "/usr/src/debug/pam-config-2.14/src/pam-config.h",
                    "ASCII text",
                ),
            ],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert!(
            lines.is_empty(),
            "no-binary must stay quiet for a -debugsource package: {results:?}"
        );
    }

    #[test]
    fn no_binary_still_fires_when_debugsource_is_not_the_suffix() {
        // The exemption is the -debugsource suffix only: a name that
        // merely contains the word, or carries it mid-name, is an
        // ordinary package and still fires.
        let config = test_config();
        for name in ["mydebugsource", "foo-debugsource-data"] {
            let pkg = synthetic_pkg(
                name,
                "x86_64",
                vec![syn_file("/usr/share/doc/x/README", "ASCII text")],
            );
            let results = driver_results(&pkg, &config);
            let lines = lines_for(&results, "no-binary");
            assert_eq!(
                lines.len(),
                1,
                "{name} must still fire no-binary: {results:?}"
            );
        }
    }

    #[test]
    fn no_binary_still_fires_for_debuginfo_package_without_binaries() {
        // The exemption covers -debugsource only. A -debuginfo package
        // ships ELF .debug payloads, which the binary accounting counts,
        // so it stays quiet through has_binary in practice; a payload
        // with no binaries at all still fires, as in the reference.
        let config = test_config();
        let pkg = synthetic_pkg(
            "foo-debuginfo",
            "x86_64",
            vec![syn_file("/usr/share/doc/foo/README", "ASCII text")],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
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
    fn arch_format_magics_table_is_well_formed() {
        // The embedded table parses (staged-data validation) and
        // carries the two evidenced formats.
        let magics = arch_format_magics();
        assert!(magics.contains(&b"XimC".to_vec()), "{magics:?}");
        assert!(magics.contains(&vec![0xcf, 0x9a, 0x57, 0x13]), "{magics:?}");
        assert!(magics.contains(&vec![0x13, 0x57, 0x9a, 0xcf]), "{magics:?}");
        assert!(magics.contains(&vec![0xce, 0x9a, 0x57, 0x13]), "{magics:?}");
        assert!(magics.contains(&vec![0x13, 0x57, 0x9a, 0xce]), "{magics:?}");
    }

    #[test]
    fn no_binary_quiet_for_ximc_payload() {
        // xorg-x11-libX11-ccache shape (boo#1110020): the payload is
        // X11 compose caches -- data in libX11's native-word layout,
        // bound to the architecture that generated it.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let cache = dir.path().join("l4_030_deadbeef");
        let mut bytes = b"XimC".to_vec();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        std::fs::write(&cache, &bytes).expect("write cache");
        let config = test_config();
        let mut cache_file = syn_file("/var/cache/libx11/compose/l4_030_deadbeef", "data");
        cache_file.path = cache.to_string_lossy().into_owned();
        let pkg = synthetic_pkg(
            "xorg-x11-libX11-ccache",
            "x86_64",
            vec![
                cache_file,
                syn_file(
                    "/usr/share/licenses/xorg-x11-libX11-ccache/LICENSE",
                    "ASCII text",
                ),
            ],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "no-binary");
        assert!(
            lines.is_empty(),
            "no-binary must stay quiet for XimC payload: {results:?}"
        );
    }

    #[test]
    fn no_binary_quiet_for_gdbm_payload() {
        // A GDBM database header is a native C struct (magic in host
        // byte order, then native int/off_t members): both byte
        // orders of both magics exempt.
        let config = test_config();
        for magic in [
            vec![0xcf, 0x9a, 0x57, 0x13], // 0x13579acf, little-endian
            vec![0x13, 0x57, 0x9a, 0xcf], // 0x13579acf, big-endian
            vec![0xce, 0x9a, 0x57, 0x13], // 0x13579ace, little-endian
            vec![0x13, 0x57, 0x9a, 0xce], // 0x13579ace, big-endian
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let db = dir.path().join("data.db");
            let mut bytes = magic.clone();
            bytes.extend_from_slice(&[0u8; 60]);
            std::fs::write(&db, &bytes).expect("write db");
            let mut db_file = syn_file("/var/lib/foo/data.db", "data");
            db_file.path = db.to_string_lossy().into_owned();
            let pkg = synthetic_pkg("foodb", "x86_64", vec![db_file]);
            let results = driver_results(&pkg, &config);
            let lines = lines_for(&results, "no-binary");
            assert!(
                lines.is_empty(),
                "no-binary must stay quiet for GDBM magic {magic:?}: {results:?}"
            );
        }
    }

    #[test]
    fn no_binary_still_fires_for_portable_or_near_miss_payload() {
        // Portable payload is not arch evidence: a gettext .mo has
        // fixed-width fields and a magic that self-describes the byte
        // order. Near misses are not evidence either: the match is
        // the full magic prefix, not a resemblance.
        let config = test_config();
        for (name, bytes) in [
            ("mo", vec![0xde, 0x12, 0x04, 0x95, 0, 0, 0, 0]),
            ("ximc-truncated", b"Xim".to_vec()),
            ("ximc-wrong-fourth-byte", b"XimD\0\0\0\0".to_vec()),
            ("gdbm-off-by-one", vec![0xcf, 0x9a, 0x57, 0x14]),
            ("text", b"just some text\n".to_vec()),
        ] {
            let dir = tempfile::TempDir::new().expect("tmpdir");
            let f = dir.path().join("payload");
            std::fs::write(&f, &bytes).expect("write payload");
            let mut pf = syn_file("/usr/share/foo/payload", "data");
            pf.path = f.to_string_lossy().into_owned();
            let pkg = synthetic_pkg("foopkg", "x86_64", vec![pf]);
            let results = driver_results(&pkg, &config);
            let lines = lines_for(&results, "no-binary");
            assert_eq!(
                lines.len(),
                1,
                "{name} must still fire no-binary: {results:?}"
            );
        }
    }

    #[test]
    fn no_binary_still_fires_when_arch_format_file_is_ghost_or_symlink() {
        // A ghost entry has no on-disk bytes, so it is no evidence;
        // a symlink's bytes name its target rather than carrying
        // data. Neither exempts.
        let config = test_config();
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let cache = dir.path().join("cache");
        let mut bytes = b"XimC".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        std::fs::write(&cache, &bytes).expect("write cache");

        let mut ghost = syn_file("/var/cache/foo/cache", "data");
        ghost.flags = crate::pkg::pkgfile::RPMFILE_GHOST;
        ghost.path = cache.to_string_lossy().into_owned();
        let pkg = synthetic_pkg("foopkg", "x86_64", vec![ghost]);
        let results = driver_results(&pkg, &config);
        assert_eq!(
            lines_for(&results, "no-binary").len(),
            1,
            "ghost XimC must still fire: {results:?}"
        );

        let mut link = syn_file("/var/cache/foo/cache", "symbolic link");
        link.mode = 0o120777;
        link.linkto = "real-cache".to_string();
        link.path = cache.to_string_lossy().into_owned();
        let pkg = synthetic_pkg("foopkg", "x86_64", vec![link]);
        let results = driver_results(&pkg, &config);
        assert_eq!(
            lines_for(&results, "no-binary").len(),
            1,
            "symlink to XimC must still fire: {results:?}"
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
        let host = syn_file(
            "/usr/share/main",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked",
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary_in_usr_share(&pkg, &host, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(lines[0].contains("/usr/share/main"), "detail: {}", lines[0]);

        // An arch-qualified share path is exempt.
        let qualified = syn_file(
            "/usr/share/doc/x86_64/foo",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked",
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_binary_in_usr_share(&pkg, &qualified, &mut out);
        assert!(
            out.results().is_empty(),
            "exempt path must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn usr_share_foreign_elf_is_silent() {
        // A foreign-machine ELF in /usr/share is target payload (guest
        // firmware): its bytes do not depend on the package's arch.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "openbios-ppc",
            "/usr/share/qemu/openbios-ppc",
            "ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV)",
            &elf_with_machine(goblin::elf::header::EM_PPC),
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert!(lines.is_empty(), "foreign ELF must be quiet: {results:?}");
    }

    #[test]
    fn usr_share_archive_without_elf_members_is_silent() {
        // An archive whose members are all in another object format
        // (the sdcc shape: ASxxxx text objects) carries no ELF code.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let archive =
            craft_ar_archive(&[("divunsigned.rel", b"XL4\nH 1 areas 5 global symbols\n")]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.lib",
            "/usr/share/sdcc/lib/z80/libfoo.lib",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert!(
            lines.is_empty(),
            "memberless-ELF archive must be quiet: {results:?}"
        );
    }

    #[test]
    fn usr_share_archive_of_foreign_elves_is_silent() {
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let riscv = elf_with_machine(goblin::elf::header::EM_RISCV);
        let archive = craft_ar_archive(&[("a.o", &riscv)]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/share/testpkg/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert!(
            lines.is_empty(),
            "all-foreign archive must be quiet: {results:?}"
        );
    }

    #[test]
    fn usr_share_host_elf_still_fires() {
        // The exemption takes positive evidence of foreign content: a
        // host-machine ELF in /usr/share is the finding's core case.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "helper",
            "/usr/share/testpkg/helper",
            "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)",
            &elf_with_machine(goblin::elf::header::EM_X86_64),
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "host ELF fires: {results:?}");
    }

    #[test]
    fn usr_share_aarch64_host_elf_still_fires() {
        // Non-x86 host pin: the host family is the package arch's
        // family, not x86 -- an AArch64 ELF in an aarch64 package is
        // host code in /usr/share and keeps firing.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "helper",
            "/usr/share/testpkg/helper",
            "ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV)",
            &elf_with_machine(goblin::elf::header::EM_AARCH64),
        );
        let pkg = synthetic_pkg("testpkg", "aarch64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "aarch64 host ELF fires: {results:?}");
    }

    #[test]
    fn usr_share_x86_elf_in_aarch64_package_is_silent() {
        // The mirror pin: an x86-64 ELF is foreign payload in an
        // aarch64 package, so it is exempt there even though the same
        // bytes fire in an x86_64 package.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let file = real_file_pkgfile(
            &dir,
            "payload",
            "/usr/share/testpkg/payload",
            "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)",
            &elf_with_machine(goblin::elf::header::EM_X86_64),
        );
        let pkg = synthetic_pkg("testpkg", "aarch64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert!(
            lines.is_empty(),
            "x86 ELF in aarch64 pkg quiet: {results:?}"
        );
    }

    #[test]
    fn usr_share_archive_with_aarch64_member_in_aarch64_package_still_fires() {
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let host = elf_with_machine(goblin::elf::header::EM_AARCH64);
        let archive = craft_ar_archive(&[("a.o", &host)]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/share/testpkg/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "aarch64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "aarch64-member archive fires: {results:?}");
    }

    #[test]
    fn usr_share_archive_of_x86_elves_in_aarch64_package_is_silent() {
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let foreign = elf_with_machine(goblin::elf::header::EM_X86_64);
        let archive = craft_ar_archive(&[("a.o", &foreign)]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/share/testpkg/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "aarch64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert!(
            lines.is_empty(),
            "all-x86 archive in aarch64 pkg quiet: {results:?}"
        );
    }

    #[test]
    fn usr_share_archive_with_binary_nonelf_member_still_fires() {
        // The no-ELF-members arm is narrowed to text payload: a
        // binary member in another object format (a COFF object
        // here) is not positive evidence of foreign-target payload,
        // since its target cannot be classified.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let coff = b"\x4c\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let archive = craft_ar_archive(&[("a.obj", coff.as_slice())]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/share/testpkg/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "binary non-ELF member fires: {results:?}");
    }

    #[test]
    fn usr_share_empty_archive_is_silent() {
        // An archive with no members at all carries no code: the
        // limiting case of the no-ELF-members arm stays exempt.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let archive = craft_ar_archive(&[]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/share/testpkg/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert!(lines.is_empty(), "empty archive quiet: {results:?}");
    }

    #[test]
    fn magic_machine_family_names_families() {
        assert_eq!(
            magic_machine_family("ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV)"),
            Some("arm")
        );
        assert_eq!(
            magic_machine_family("ELF 64-bit LSB executable, x86-64, version 1 (SYSV)"),
            Some("x86")
        );
        assert_eq!(
            magic_machine_family(
                "ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV)"
            ),
            Some("ppc")
        );
        assert_eq!(
            magic_machine_family("ELF 64-bit LSB shared object, version 1 (SYSV)"),
            None
        );
    }

    #[test]
    fn usr_share_archive_with_host_member_still_fires() {
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let host = elf_with_machine(goblin::elf::header::EM_X86_64);
        let archive = craft_ar_archive(&[("a.o", &host)]);
        let file = real_file_pkgfile(
            &dir,
            "libfoo.a",
            "/usr/share/testpkg/libfoo.a",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "host-member archive fires: {results:?}");
    }

    #[test]
    fn usr_share_unreadable_archive_still_fires() {
        // No payload on disk: no evidence of foreign content.
        let config = test_config();
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/share/testpkg/libfoo.a",
                "current ar archive",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "unreadable archive fires: {results:?}");
    }

    #[test]
    fn usr_share_unknown_machine_elf_still_fires() {
        // A magic naming no machine (and no file to read) classifies
        // as Unknown, not Foreign.
        let config = test_config();
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/share/testpkg/blob",
                "ELF 64-bit LSB shared object, version 1 (SYSV), dynamically linked",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "unclassified ELF fires: {results:?}");
    }

    #[test]
    fn usr_share_lua_bytecode_still_fires() {
        // Lua bytecode carries no ELF machine to classify, so the
        // foreign-target exemption does not reach it.
        let config = test_config();
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/share/testpkg/bytecode.bin",
                "Lua bytecode, version 5.3",
            )],
        );
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "Lua bytecode fires: {results:?}");
    }

    #[test]
    fn usr_share_gplib_archive_is_silent() {
        // SDCC's pic14/pic16 libraries are gplib-dialect archives:
        // the GNU member walk enumerates nothing for the dialect,
        // but the structural validator proves every object member
        // is a PIC COFF object, so the archive carries no ELF code.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let coff = b"\x40\x12\x02\x00\x2a\xf3\x66\x6a";
        let archive = gplib_archive(&[("/", b"\x01\x00\x00\x00"), ("foo.o/", coff)]);
        let file = real_file_pkgfile(
            &dir,
            "libsdcc.lib",
            "/usr/share/sdcc/lib/pic16/libsdcc.lib",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert!(lines.is_empty(), "gplib archive must be quiet: {results:?}");
    }

    #[test]
    fn usr_share_broken_gplib_archive_still_fires() {
        // A gplib-shaped archive whose member chain does not land
        // exactly on EOF fails the structural validator: without
        // positive evidence the finding stands.
        let config = test_config();
        let dir = tempfile::tempdir().expect("tmpdir");
        let coff = b"\x40\x12\x02\x00\x2a\xf3\x66\x6a";
        let mut archive = gplib_archive(&[("foo.o/", coff)]);
        archive.push(b'\n');
        let file = real_file_pkgfile(
            &dir,
            "libsdcc.lib",
            "/usr/share/sdcc/lib/pic16/libsdcc.lib",
            "current ar archive",
            &archive,
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![file]);
        let results = driver_results(&pkg, &config);
        let lines = lines_for(&results, "arch-dependent-file-in-usr-share");
        assert_eq!(lines.len(), 1, "broken gplib archive fires: {results:?}");
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
    fn unstripped_binary_quiet_for_separate_debuginfo() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg-debuginfo", "x86_64", vec![]);
        let not_stripped = "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), not stripped";

        // The canonical debuginfo location: the pam-config-debuginfo
        // payload of issue #949.
        let pkgfile = syn_file("/usr/lib/debug/usr/sbin/pam-config.debug", not_stripped);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_unstripped_binary(
            "/usr/lib/debug/usr/sbin/pam-config.debug",
            &pkg,
            &pkgfile,
            &mut out,
        );
        assert!(
            out.results().is_empty(),
            "debuginfo payload must be quiet: {:?}",
            out.results()
        );

        // The `.debug` suffix alone names separate debuginfo, wherever
        // it sits.
        let pkgfile = syn_file("/usr/lib64/libfoo.so.1.debug", not_stripped);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_unstripped_binary("/usr/lib64/libfoo.so.1.debug", &pkg, &pkgfile, &mut out);
        assert!(
            out.results().is_empty(),
            ".debug payload must be quiet: {:?}",
            out.results()
        );

        // The path alone covers debuginfo without the suffix (ovmf's
        // GdbSyms.dll).
        let pkgfile = syn_file("/usr/lib/debug/ovmf-x86_64/DEBUG/GdbSyms.dll", not_stripped);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_unstripped_binary(
            "/usr/lib/debug/ovmf-x86_64/DEBUG/GdbSyms.dll",
            &pkg,
            &pkgfile,
            &mut out,
        );
        assert!(
            out.results().is_empty(),
            "debug-tree payload must be quiet: {:?}",
            out.results()
        );

        // A stripped debuginfo payload is quiet under the magic rule
        // alone, as any stripped file is.
        let pkgfile = syn_file(
            "/usr/lib/debug/usr/bin/foo.debug",
            "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), stripped",
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_unstripped_binary("/usr/lib/debug/usr/bin/foo.debug", &pkg, &pkgfile, &mut out);
        assert!(
            out.results().is_empty(),
            "stripped payload must be quiet: {:?}",
            out.results()
        );

        // Near misses: a prefix lookalike is not the debug tree, and a
        // real unstripped binary outside it still fires.
        for name in ["/usr/lib/debugfoo/tool", "/usr/lib64/libfoo.so.1"] {
            let pkgfile = syn_file(name, not_stripped);
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_unstripped_binary(name, &pkg, &pkgfile, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "unstripped-binary-or-object");
            assert_eq!(lines.len(), 1, "{} must still fire: {:?}", name, results);
            assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        }
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
    fn non_pie_executable_error_requires_full_path_match() {
        // The reference matches PieExecutables with fullmatch: a path
        // that merely contains a listed name is not the listed
        // executable and only gets the suggestion. Corpus cases:
        // ssh-tools' /usr/bin/ssh-authorized-keys and /usr/bin/ssh-sig
        // (contain /usr/bin/ssh) and susedialog's /usr/bin/susedialog
        // (contains /usr/bin/su) were charged at E by an unanchored
        // search; the reference charges all three at W.
        let config = config_with("PieExecutables = [\"/usr/bin/ssh\", \"/usr/bin/su\"]");
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);

        // Exact listed paths keep firing at E.
        for name in ["/usr/bin/ssh", "/usr/bin/su"] {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_non_pie(&pkg, name, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "non-position-independent-executable");
            assert_eq!(lines.len(), 1, "{name} must fire at E: {results:?}");
            assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
            assert_lacks(&results, "position-independent-executable-suggested");
        }

        // Prefix extensions, suffix extensions and paths containing a
        // listed name in the middle only get the suggestion.
        for name in [
            "/usr/bin/ssh-authorized-keys",
            "/usr/bin/ssh-sig",
            "/usr/bin/susedialog",
            "/usr/bin/supercat",
            "/usr/share/rootfs/usr/bin/ssh",
        ] {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_non_pie(&pkg, name, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "position-independent-executable-suggested");
            assert_eq!(lines.len(), 1, "{name} must only be suggested: {results:?}");
            assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
            assert_lacks(&results, "non-position-independent-executable");
        }
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

        // A malformed SONAME stays quiet: it fails the validity gate
        // that guards the symlink and shlib-policy checks, and no
        // finding is emitted for the name itself.
        let mut info = syn_info();
        info.is_shlib = true;
        info.soname = Some("b soname".to_string());
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_shared_library(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "malformed soname must be quiet: {:?}",
            out.results()
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
    fn soname_tail_shapes() {
        assert_eq!(soname_tail("libfoo.so.1"), Some("1"));
        assert_eq!(soname_tail("libstemmer.so.0d"), Some("0d"));
        assert_eq!(soname_tail("libLimeSuite.so.23.11-1"), Some("23.11-1"));
        assert_eq!(soname_tail("libSDL_bgi.so.suse0"), Some("suse0"));
        // An empty tail stays outside the rule, as does a SONAME
        // with no `.so.` at all or a tail starting with punctuation.
        assert_eq!(soname_tail("libterminal-nautilus.so."), None);
        assert_eq!(soname_tail("libfoo.so"), None);
        assert_eq!(soname_tail("libfoo.so.-1"), None);
        assert_eq!(soname_tail("b soname"), None);
    }

    /// Issue #1029, SONAME arm (a): a shared library whose SONAME
    /// tail is non-numeric gets the package-name arm with the whole
    /// tail as the soversion. Rows are the corpus shapes of the
    /// issue's section 4 (SONAMEs read from the Factory RPMs).
    #[test]
    fn shlib_policy_name_tail_matrix() {
        // (package name, SONAME, file, fires?)
        let rows: &[(&str, &str, &str, bool)] = &[
            (
                "libstemmer0d",
                "libstemmer.so.0d",
                "/usr/lib64/libstemmer.so.0d",
                false,
            ),
            (
                "libstemmer1d",
                "libstemmer.so.0d",
                "/usr/lib64/libstemmer.so.0d",
                true,
            ),
            (
                "libLimeSuite23_11-1",
                "libLimeSuite.so.23.11-1",
                "/usr/lib64/libLimeSuite.so.23.11-1",
                false,
            ),
            (
                "libSDL3_bgi-suse0",
                "libSDL3_bgi.so.suse0",
                "/usr/lib64/libSDL3_bgi.so.suse0",
                false,
            ),
            (
                "libSDL3_bgi-suse9",
                "libSDL3_bgi.so.suse0",
                "/usr/lib64/libSDL3_bgi.so.suse0",
                true,
            ),
            (
                "libaws-c-io0unstable",
                "libaws-c-io.so.0unstable",
                "/usr/lib64/libaws-c-io.so.1.0.0",
                false,
            ),
            (
                "libSoapySDR0_8-3",
                "libSoapySDR.so.0.8-3",
                "/usr/lib64/libSoapySDR.so.0.8.1",
                false,
            ),
            (
                "libcmark-gfm0_29_0_gfm_13",
                "libcmark-gfm.so.0.29.0.gfm.13",
                "/usr/lib64/libcmark-gfm.so.0.29.0.gfm.13",
                false,
            ),
        ];
        for (pkgname, soname, file, fires) in rows {
            let lines = shlib_policy_lines(pkgname, soname, file);
            assert_eq!(!lines.is_empty(), *fires, "{pkgname} / {soname}: {lines:?}");
        }
        // The one gained corpus finding names the whole tail.
        let lines = shlib_policy_lines(
            "libstemmer1d",
            "libstemmer.so.0d",
            "/usr/lib64/libstemmer.so.0d",
        );
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("expected package suffix: 0d"),
            "detail: {}",
            lines[0]
        );
    }

    /// Issue #1029, SONAME arm (b): a regular ELF file the
    /// file-name test misses still gets the two SONAME arms when it
    /// sits in a lib directory under its SONAME's name; the
    /// near-miss shapes stay outside.
    #[test]
    fn soname_tail_library_arms() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let elf = "ELF 64-bit LSB shared object";
        let run = |pkg: &Pkg, pkgfile: &PkgFile, info: &ReadelfInfo| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_shared_library(pkg, pkgfile, info, &mut out);
            out.results().to_vec()
        };
        let info_for = |soname: &str| {
            let mut info = syn_info();
            info.soname = Some(soname.to_string());
            info
        };

        // The stemmer shape: the real file libstemmer.so.0d.0.0 is
        // not a shlib by name; its SONAME is libstemmer.so.0d, and
        // the package kept the pre-rename name libstemmer1d.
        let stemmer_files = vec![
            syn_file("/usr/lib64/libstemmer.so.0d.0.0", elf),
            syn_link("/usr/lib64/libstemmer.so.0d", "libstemmer.so.0d.0.0"),
        ];
        let pkgfile = syn_file("/usr/lib64/libstemmer.so.0d.0.0", elf);
        let info = info_for("libstemmer.so.0d");
        let pkg = synthetic_pkg("libstemmer1d", "x86_64", stemmer_files.clone());
        let results = run(&pkg, &pkgfile, &info);
        let lines = lines_for(&results, "shlib-policy-name-error");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert_lacks(&results, "no-ldconfig-symlink");
        // The correctly named package is quiet.
        let pkg = synthetic_pkg("libstemmer0d", "x86_64", stemmer_files);
        let results = run(&pkg, &pkgfile, &info);
        assert!(
            results.is_empty(),
            "correct name must be quiet: {results:?}"
        );

        // The limesuite shape: the shipped file is the SONAME
        // itself, under a decorated spelling.
        let pkgfile = syn_file("/usr/lib64/libLimeSuite.so.23.11-1", elf);
        let info = info_for("libLimeSuite.so.23.11-1");
        let pkg = synthetic_pkg(
            "libLimeSuite23_11-1",
            "x86_64",
            vec![syn_file("/usr/lib64/libLimeSuite.so.23.11-1", elf)],
        );
        let results = run(&pkg, &pkgfile, &info);
        assert!(
            results.is_empty(),
            "limesuite shape must be quiet: {results:?}"
        );

        // Near-misses stay outside the arm:
        let quiet: &[(&str, &str, &str)] = &[
            // SONAME is not a prefix of the basename (libclang).
            (
                "libclang22",
                "libclang.so.22.0.rocm",
                "/usr/lib64/libclang.so.22.0.0.rocm",
            ),
            // Empty SONAME tail.
            (
                "libterminal-nautilus",
                "libterminal-nautilus.so.",
                "/usr/lib64/libterminal-nautilus.so.",
            ),
            // Outside a lib directory.
            (
                "libstemmer0d",
                "libstemmer.so.0d",
                "/usr/share/libstemmer.so.0d.0.0",
            ),
            // In a subdirectory of a lib dir: a compat tree is not
            // a lib directory (the libncurses6-compat shape).
            (
                "libncurses6-compat",
                "libtinfo.so.6",
                "/usr/lib64/ncurses6nt/libtinfo.so.6.6",
            ),
            // In a glibc-hwcaps subdirectory (the x86-64-v3 shape).
            (
                "libz1-x86-64-v3",
                "libz.so.1",
                "/usr/lib64/glibc-hwcaps/x86-64-v3/libz.so.1.3.1",
            ),
            // Under the debuginfo tree.
            (
                "libstemmer0d",
                "libstemmer.so.0d",
                "/usr/lib/debug/usr/lib64/libstemmer.so.0d.0.0",
            ),
        ];
        for (pkgname, soname, file) in quiet {
            let pkgfile = syn_file(file, elf);
            let info = info_for(soname);
            let pkg = synthetic_pkg(pkgname, "x86_64", vec![syn_file(file, elf)]);
            let results = run(&pkg, &pkgfile, &info);
            assert!(
                results.is_empty(),
                "{pkgname} / {soname} / {file} must be quiet: {results:?}"
            );
        }

        // A debuginfo file (`.debug` name) stays outside even in a
        // lib directory under a SONAME-shaped name.
        let pkgfile = syn_file("/usr/lib64/libstemmer.so.0d.0.0", elf);
        let mut info = info_for("libstemmer.so.0d");
        info.is_debug = true;
        let pkg = synthetic_pkg(
            "libstemmer1d",
            "x86_64",
            vec![syn_file("/usr/lib64/libstemmer.so.0d.0.0", elf)],
        );
        let results = run(&pkg, &pkgfile, &info);
        assert!(results.is_empty(), "debug file must be quiet: {results:?}");

        // A symlink is not a regular file: no arms.
        let pkgfile = PkgFile {
            mode: 0o120777,
            ..syn_file("/usr/lib64/libstemmer.so.0d.0.0", elf)
        };
        let info = info_for("libstemmer.so.0d");
        let results = run(&pkg, &pkgfile, &info);
        assert!(results.is_empty(), "symlink must be quiet: {results:?}");
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
    /// or flavour (-gcc15, -openmpi4) segment. Two derived-only
    /// extensions: an alphabetic flavour tail (-opencl, -mini) is
    /// stripped when the remainder equals a derived name exactly
    /// (limb C), and derived names are also built from the SONAME
    /// version with trailing zero components elided (limb D).
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
            // Alphabetic flavour tails (limb C): the version sits
            // before a trailing -<letters> segment and the stripped
            // name must equal a SONAME-derived name exactly.
            ("libarmnn36-opencl", "libarmnn.so.36", false), // corpus
            ("libfoo1-mini", "libfoo.so.1", false),
            ("libfoo1-dummy", "libfoo.so.1", false),
            ("libfoo2-mini", "libfoo.so.1", true), // wrong version before tail
            ("libbar5-baz", "libBaz.so.5", true),  // stem-blind suffix must not credit
            ("libfoo1-compat", "libbar.so.1", true), // stripped name is another stem
            // Trailing-zero elision (limb D): the name derives from
            // the SONAME version with trailing zero components
            // dropped; any non-zero change re-fires, and a partially
            // elided form still fires.
            ("libfoo4", "libfoo.so.4.0.0", false), // corpus shape (CppMicroServices)
            ("libfoo3_21_12", "libfoo.so.3.21.12.0", false), // corpus shape (protobuf)
            ("libfoo10", "libfoo.so.10.0.0", false), // elision to one component
            ("libfoo4", "libfoo.so.4.0.1", true),  // non-zero tail component
            ("libfoo4_0", "libfoo.so.4.0.0", true), // partial elision
            ("libfoo4_0_0", "libfoo.so.4.0.0", false), // full form, as before
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
            // Unlike the libfoo.so row above, whose SONAME fails the
            // validity gate before the guard, these rows reach it
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
        run_batch(&mut check, &pkg, &config, &mut out);
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
        info.sections = vec![vec![sec(".gnu.lto_.opts"), sec(".comment")]];
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
        info.sections = vec![vec![sec(".gnu.lto_.opts"), sec(".comment"), sec(".text")]];
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
            info.sections = vec![vec![sec(".gnu.lto_.opts"), sec(".comment")]];
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
            assert!(
                out.results().is_empty(),
                "{name} must be exempt: {:?}",
                out.results()
            );
        }
    }

    #[test]
    fn lto_no_text_in_archive_needs_lto_content() {
        // #869: candidacy turns on LTO content among the members. A
        // data-only member set -- the wine shape: ELF objects whose
        // .text and .data are empty and whose content sits in .rodata --
        // is not an LTO archive and stays silent, as does an archive
        // with no ELF member sections at all.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libuuid.a", "current ar archive");
        let zsec = |name: &str| ElfSection {
            name: name.to_string(),
            size: 0,
        };

        let mut info = syn_info();
        info.sections = vec![vec![
            zsec(".text"),
            zsec(".data"),
            sec(".rodata"),
            sec(".debug_info"),
        ]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "data-only members must be quiet: {:?}",
            out.results()
        );

        let info = syn_info();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "no member sections must be quiet: {:?}",
            out.results()
        );

        // A slim LTO member (LTO sections, no non-empty text) is the
        // canonical positive: the finding fires.
        let mut info = syn_info();
        info.sections = vec![vec![sec(".gnu.lto_.symtab.0123abcd"), zsec(".text")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        assert_eq!(
            lines_for(&results, "lto-no-text-in-archive").len(),
            1,
            "slim LTO member must fire: {results:?}"
        );

        // An embedded-bitcode member is LTO content too.
        let mut info = syn_info();
        info.sections = vec![vec![sec(".llvmbc")]];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        assert_eq!(
            lines_for(&results, "lto-no-text-in-archive").len(),
            1,
            "embedded bitcode member must fire: {results:?}"
        );
    }

    #[test]
    fn lto_no_text_in_archive_member_formats() {
        // #869 at the parse level: candidacy is decided by the ELF
        // members. A COFF import member alone contributes no sections
        // and stays silent; mixed with a data-only ELF member it still
        // stays silent (the foreign member neither confers nor blocks
        // candidacy); mixed with an LTO ELF member the finding fires.
        let config = test_config();
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let coff: &[u8] = b"\x64\x86\x06\x00\x00\x00\x00\x00\x36\x01\x00\x00\x0e\x00\x00\x00";
        let data_only = craft_elf_sections(&[(".rodata", b"guid-guid-guid!!")]);
        let lto = craft_elf_sections(&[(".gnu.lto_.opts", b"\x01\x02")]);
        let run = |tag: &str, members: &[(&str, &[u8])]| {
            let archive = craft_ar_archive(members);
            let path = std::env::temp_dir()
                .join(format!("rpmcrab-ar-lto869-{tag}-{}", std::process::id()));
            std::fs::write(&path, &archive).unwrap();
            let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
            assert!(
                info.failed.is_none(),
                "{tag}: parse must not fail: {:?}",
                info.failed
            );
            let mut check = BinariesCheck::with_tool_dir(&config, None);
            check.is_archive = true;
            let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            std::fs::remove_file(&path).ok();
            lines_for(&results, "lto-no-text-in-archive").len()
        };
        assert_eq!(run("coff", &[("import.o", coff)]), 0, "COFF-only archive");
        assert_eq!(
            run("mixed-data", &[("import.o", coff), ("uuid.o", &data_only)]),
            0,
            "COFF + data-only ELF members"
        );
        assert_eq!(
            run("mixed-lto", &[("import.o", coff), ("lto.o", &lto)]),
            1,
            "COFF + LTO ELF member"
        );
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
        // skipped: the members carry no .symtab, so the symtab finding
        // fires on the merged sections.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_symtab_in_archive(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        assert_eq!(
            lines_for(&results, "static-library-without-symtab").len(),
            1,
            "archive checks run on parsed members: {results:?}"
        );
        // The members carry no LTO content, so the LTO finding stays
        // silent on the same merged sections (plusky/rpmcrab#869).
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_no_text_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "no LTO content must be quiet: {:?}",
            out.results()
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn archive_with_non_elf_member_skips_that_member() {
        // #846: a member in another object format is outside the ELF
        // checks' remit. The member is named like an object file: the
        // skip is by content (no ELF magic), never by name.
        let m1 = craft_shlib_elf(false, None, None, &[]);
        let archive = craft_ar_archive(&[("a.o", &m1), ("data.o", b"hello\n")]);
        let path = std::env::temp_dir().join(format!("rpmcrab-ar-nonelf-{}", std::process::id()));
        std::fs::write(&path, &archive).unwrap();

        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
        assert!(
            info.failed.is_none(),
            "non-ELF member must not fail the archive: {:?}",
            info.failed
        );
        assert!(
            !info.no_elf_members,
            "the ELF member keeps the archive in the ELF checks' remit"
        );
        // The ELF member's metadata is still merged.
        let names: Vec<&str> = info
            .sections
            .iter()
            .flatten()
            .map(|s| s.name.as_str())
            .collect();
        assert!(
            names.contains(&".shstrtab"),
            "ELF member sections merged: {names:?}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn archive_with_only_non_elf_members_stays_silent() {
        // #846: the swept foreign formats in one archive -- a COFF
        // object, a wasm object, an LLVM bitcode object, a GIMPLE
        // offload text member and a plain-text member, each named like
        // an object file. No member presents as an ELF object, so the
        // archive is outside the ELF checks' remit and run_elf_checks
        // emits nothing for it: the archive findings that read the
        // merged sections (lto-no-text-in-archive,
        // static-library-without-symtab, static-library-without-debuginfo)
        // stay silent on it too.
        let coff: &[u8] = b"\x64\x86\x06\x00\x00\x00\x00\x00\x36\x01\x00\x00\x0e\x00\x00\x00";
        let wasm: &[u8] = b"\x00asm\x01\x00\x00\x00";
        let bitcode: &[u8] = b"BC\xc0\xde\x35\x14\x00\x00";
        let gimple: &[u8] = b"// BEGIN PREAMBLE\n.version\n";
        let archive = craft_ar_archive(&[
            ("coff.o", coff),
            ("wasm.o", wasm),
            ("bitcode.o", bitcode),
            ("gimple.o", gimple),
            ("note.o", b"hello\n"),
        ]);
        let path = std::env::temp_dir().join(format!("rpmcrab-ar-foreign-{}", std::process::id()));
        std::fs::write(&path, &archive).unwrap();

        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
        assert!(
            info.failed.is_none(),
            "foreign members must not fail the archive: {:?}",
            info.failed
        );
        assert!(
            info.no_elf_members,
            "an archive with members but no ELF member is marked"
        );

        // Drive the emission path: no finding of any kind.
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
        assert!(
            results.is_empty(),
            "foreign archive must produce no findings: {results:?}"
        );

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn archive_with_corrupt_elf_member_fails() {
        // #846 firing control: a member that presents as an ELF object
        // (ELF magic) and then fails to parse still fails the whole
        // archive, even when an earlier member is in another format
        // and is skipped.
        let good = craft_shlib_elf(false, None, None, &[]);
        let mut corrupt = good.clone();
        corrupt.truncate(32);
        let archive =
            craft_ar_archive(&[("note.o", b"hello\n"), ("a.o", &good), ("bad.o", &corrupt)]);
        let path = std::env::temp_dir().join(format!("rpmcrab-ar-corrupt-{}", std::process::id()));
        std::fs::write(&path, &archive).unwrap();

        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
        let failed = info
            .failed
            .clone()
            .expect("corrupt ELF member must fail the archive");
        assert!(
            failed.contains("bad.o"),
            "failure names the corrupt member: {failed}"
        );
        assert!(
            !info.no_elf_members,
            "an archive with ELF members is in the ELF checks' remit"
        );

        // Drive the emission path: run_elf_checks must surface the
        // failure as E: readelf-failed, exactly once.
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
        run_batch(&mut check, &pkg, &config, &mut out);
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
        run_batch(&mut check, &pkg, &config, &mut out);
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
        run_batch(&mut check, &pkg, &config, &mut out);
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
    fn zero_member_archive_parses_as_no_members() {
        // The file is exactly the ar magic: glibc's post-2.34
        // merged-library stubs (libpthread.a and kin) ship in this
        // shape, as empty placeholders whose symbols live in libc.
        let path = std::env::temp_dir().join(format!("rpmcrab-ar-empty-{}", std::process::id()));
        std::fs::write(&path, b"!<arch>\n").unwrap();

        let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libpthread.a");
        assert!(
            info.failed.is_none(),
            "zero-member archive must parse: {:?}",
            info.failed
        );
        assert!(info.no_members, "the member count is recorded at parse");
        assert!(!info.no_elf_members, "no members is not no-ELF-members");
        assert!(info.sections.is_empty(), "no member contributes sections");

        // Both archive checks stay quiet on the parsed shape: the
        // symtab check through the no-members gate above, the
        // debuginfo check through its no-code-member gate (#847) --
        // the two agree on what a zero-member archive is.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("glibc-devel", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libpthread.a", "current ar archive");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_symtab_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "symtab check quiet on zero members: {:?}",
            out.results()
        );
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_debug_info_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "debuginfo check quiet on zero members: {:?}",
            out.results()
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

        // A zero-member archive (glibc's post-2.34 merged-library
        // stubs: the file is exactly the ar magic, which parses to
        // no sections and no members) has nothing a symtab could
        // describe and stays quiet.
        let mut info = syn_info();
        info.no_members = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_symtab_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "zero-member archive must be quiet: {:?}",
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
        info.code_machines = vec![goblin::elf::header::EM_X86_64];
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
        info.code_machines = vec![goblin::elf::header::EM_X86_64];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_missing_debug_info_in_archive(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            ".debug_info present must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn static_library_without_debuginfo_needs_host_code() {
        // #847: the finding charges only archives carrying host machine
        // code. Each silent shape below is a swept Factory shape.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let run = |check: &mut BinariesCheck, arch: &str, code_machines: Vec<u16>| {
            let pkg = synthetic_pkg("testpkg", arch, vec![]);
            let mut info = syn_info();
            info.sections = vec![vec![sec(".text"), sec(".symtab")]];
            info.code_machines = code_machines;
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_missing_debug_info_in_archive(&pkg, &pkgfile, &info, &mut out);
            out.results().to_vec()
        };

        // No code-carrying member at all: an empty placeholder archive
        // (glibc), an import library of zero-filled relocation slots
        // (wine) and a stub archive with no executable section
        // (compiler-rt preinit) all parse to this shape.
        let results = run(&mut check, "x86_64", vec![]);
        assert!(
            results.is_empty(),
            "no host code must be quiet: {results:?}"
        );

        // Code only for a foreign machine: a cross archive (AVR
        // objects in an x86_64 package).
        let results = run(&mut check, "x86_64", vec![goblin::elf::header::EM_AVR]);
        assert!(
            results.is_empty(),
            "foreign-only code must be quiet: {results:?}"
        );

        // A foreign member does not shield a host-code member: the
        // archive still carries host code without debuginfo.
        let results = run(
            &mut check,
            "x86_64",
            vec![goblin::elf::header::EM_AVR, goblin::elf::header::EM_X86_64],
        );
        let lines = lines_for(&results, "static-library-without-debuginfo");
        assert_eq!(lines.len(), 1, "host code member must fire: {results:?}");

        // The host mapping follows the package arch, not a fixed
        // machine: x86_64 code is foreign to an aarch64 package and
        // aarch64 code is its own.
        let results = run(&mut check, "aarch64", vec![goblin::elf::header::EM_X86_64]);
        assert!(
            results.is_empty(),
            "x86_64 code in an aarch64 package must be quiet: {results:?}"
        );
        let results = run(&mut check, "aarch64", vec![goblin::elf::header::EM_AARCH64]);
        let lines = lines_for(&results, "static-library-without-debuginfo");
        assert_eq!(lines.len(), 1, "aarch64 host code must fire: {results:?}");

        // A hwcaps subarch takes its base arch's machines: x86-64 code
        // in an x86_64_v3 package is host code (fires), AVR code stays
        // foreign (quiet).
        let results = run(
            &mut check,
            "x86_64_v3",
            vec![goblin::elf::header::EM_X86_64],
        );
        let lines = lines_for(&results, "static-library-without-debuginfo");
        assert_eq!(
            lines.len(),
            1,
            "x86-64 code in an x86_64_v3 package is host code: {results:?}"
        );
        let results = run(&mut check, "x86_64_v3", vec![goblin::elf::header::EM_AVR]);
        assert!(
            results.is_empty(),
            "foreign code in an x86_64_v3 package must be quiet: {results:?}"
        );

        // An unmapped arch charges any code, as before this gate.
        let results = run(&mut check, "e2k", vec![goblin::elf::header::EM_AVR]);
        let lines = lines_for(&results, "static-library-without-debuginfo");
        assert_eq!(
            lines.len(),
            1,
            "unmapped arch must keep charging any code: {results:?}"
        );
    }

    /// Minimal ET_REL ELF64 object whose `.text` (SHF_ALLOC |
    /// SHF_EXECINSTR, SHT_PROGBITS) holds `text`, for the #847
    /// code-carrying-member tests. `machine` is the ELF `e_machine`.
    fn craft_code_object(machine: u16, text: &[u8]) -> Vec<u8> {
        let mut shstrtab = vec![0u8];
        let text_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".text\0");
        let shstrtab_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut buf = vec![0u8; 64]; // ELF header placeholder
        let text_off = buf.len() as u64;
        buf.extend_from_slice(text);
        let shstrtab_off = buf.len() as u64;
        buf.extend_from_slice(&shstrtab);
        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        let shoff = buf.len() as u64;

        // Section headers: NULL + .text + shstrtab.
        let mut shdrs = vec![0u8; 64];
        {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&text_name_off.to_le_bytes());
            h[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
            h[8..16].copy_from_slice(&0x6u64.to_le_bytes()); // SHF_ALLOC | SHF_EXECINSTR
            h[24..32].copy_from_slice(&text_off.to_le_bytes());
            h[32..40].copy_from_slice(&(text.len() as u64).to_le_bytes());
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

        let mut ehdr = vec![0u8; 64];
        ehdr[0..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 2; // ELFCLASS64
        ehdr[5] = 1; // ELFDATA2LSB
        ehdr[6] = 1; // EV_CURRENT
        ehdr[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        ehdr[18..20].copy_from_slice(&machine.to_le_bytes());
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        ehdr[40..48].copy_from_slice(&shoff.to_le_bytes());
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        ehdr[60..62].copy_from_slice(&3u16.to_le_bytes()); // shnum
        ehdr[62..64].copy_from_slice(&2u16.to_le_bytes()); // shstrndx
        buf[0..64].copy_from_slice(&ehdr);
        buf
    }

    #[test]
    fn archive_code_machines_recorded_per_member() {
        // #847 parse level: `code_machines` records exactly the
        // members carrying machine code, with their machines.
        let parse = |tag: &str, archive: &[u8]| {
            let path = std::env::temp_dir().join(format!(
                "rpmcrab-ar-code-{}-{}",
                tag,
                std::process::id()
            ));
            std::fs::write(&path, archive).unwrap();
            let info = ReadelfInfo::parse(path.to_str().unwrap(), "/usr/lib64/libfoo.a");
            std::fs::remove_file(&path).ok();
            info
        };

        // A member with non-zero executable bytes records its machine.
        let archive = craft_ar_archive(&[("a.o", &craft_code_object(62, &[0x90, 0xc3]))]);
        let info = parse("host", &archive);
        assert!(info.failed.is_none(), "must parse: {:?}", info.failed);
        assert_eq!(info.code_machines, vec![62], "host code member recorded");

        // The wine import-thunk shape: the only executable section is
        // all zero bytes (a relocation-filled slot), so no code is
        // recorded even though the section is non-empty.
        let archive = craft_ar_archive(&[("a.o", &craft_code_object(62, &[0u8; 8]))]);
        let info = parse("stub", &archive);
        assert!(info.failed.is_none(), "must parse: {:?}", info.failed);
        assert!(
            info.code_machines.is_empty(),
            "all-zero executable section is not code: {:?}",
            info.code_machines
        );

        // A foreign member with real code records the foreign machine.
        let archive = craft_ar_archive(&[("a.o", &craft_code_object(83, &[0x90, 0xc3]))]);
        let info = parse("foreign", &archive);
        assert_eq!(
            info.code_machines,
            vec![83],
            "foreign code recorded as foreign"
        );

        // An executable section whose offset points past the end of
        // the member cannot be shown to be zero-filled: it records
        // code (fail open).
        let mut obj = craft_code_object(62, &[0u8; 8]);
        let shoff = u64::from_le_bytes(obj[40..48].try_into().unwrap()) as usize;
        let text_shdr = shoff + 64; // section header 1 is .text
        let past_end = obj.len() as u64 + 0x1000;
        obj[text_shdr + 24..text_shdr + 32].copy_from_slice(&past_end.to_le_bytes());
        let archive = craft_ar_archive(&[("a.o", &obj)]);
        let info = parse("outofrange", &archive);
        assert!(info.failed.is_none(), "must parse: {:?}", info.failed);
        assert_eq!(
            info.code_machines,
            vec![62],
            "out-of-range executable section counts as code"
        );

        // An executable section whose declared size runs past the end
        // of the member, with an all-zero readable prefix, records code
        // the same way: the unreadable tail may hold anything.
        let mut obj = craft_code_object(62, &[0u8; 8]);
        let shoff = u64::from_le_bytes(obj[40..48].try_into().unwrap()) as usize;
        let text_shdr = shoff + 64;
        // .text offset: the member's last 8 bytes (the trailing zeros
        // of the final section header); declared size 64, so 56 bytes
        // of the section sit past the end of the data.
        let tail_start = obj.len() as u64 - 8;
        obj[text_shdr + 24..text_shdr + 32].copy_from_slice(&tail_start.to_le_bytes());
        obj[text_shdr + 32..text_shdr + 40].copy_from_slice(&64u64.to_le_bytes());
        let archive = craft_ar_archive(&[("a.o", &obj)]);
        let info = parse("truncated", &archive);
        assert!(info.failed.is_none(), "must parse: {:?}", info.failed);
        assert_eq!(
            info.code_machines,
            vec![62],
            "truncated executable section counts as code"
        );

        // An empty archive (the glibc placeholder shape) parses with
        // no members and records no code.
        let info = parse("empty", b"!<arch>\n");
        assert!(
            info.failed.is_none(),
            "empty archive must parse: {:?}",
            info.failed
        );
        assert!(info.code_machines.is_empty());
        assert!(info.sections.is_empty());
    }

    #[test]
    fn archive_without_host_code_emits_no_debuginfo_finding() {
        // #847 emission level, through run_elf_checks: the debuginfo
        // finding fires only for an archive carrying host code.
        let config = test_config();
        let run = |tag: &str, archive: &[u8]| {
            let path = std::env::temp_dir().join(format!(
                "rpmcrab-ar-emit-{}-{}",
                tag,
                std::process::id()
            ));
            std::fs::write(&path, archive).unwrap();
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
            std::fs::remove_file(&path).ok();
            out.results().to_vec()
        };

        // All members are zero-filled import slots: no debuginfo finding.
        let stub = craft_code_object(62, &[0u8; 8]);
        let archive = craft_ar_archive(&[("a.o", &stub), ("b.o", &stub)]);
        let results = run("stub", &archive);
        assert_lacks(&results, "static-library-without-debuginfo");

        // All members carry foreign code: no debuginfo finding.
        let foreign = craft_code_object(83, &[0x90, 0xc3]);
        let archive = craft_ar_archive(&[("a.o", &foreign)]);
        let results = run("foreign", &archive);
        assert_lacks(&results, "static-library-without-debuginfo");

        // A host-code member alongside a stub member: the finding
        // fires exactly once (the stub does not shield it).
        let real = craft_code_object(62, &[0x90, 0xc3]);
        let archive = craft_ar_archive(&[("a.o", &stub), ("b.o", &real)]);
        let results = run("mixed", &archive);
        let lines = lines_for(&results, "static-library-without-debuginfo");
        assert_eq!(lines.len(), 1, "host code must fire once: {results:?}");
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

    /// Write a crafted executable into `dir` and return its
    /// `PkgFile`, named `/usr/bin/<base>` inside the package. The
    /// bytes are the crafted ET_DYN shape; executability follows
    /// from the file's name and magic, as in the reference.
    fn exe_pkgfile(dir: &std::path::Path, base: &str, elf: &[u8]) -> PkgFile {
        let path = dir.join(base);
        std::fs::write(&path, elf).expect("write exe");
        PkgFile {
            name: format!("/usr/bin/{base}"),
            path: path.to_string_lossy().into_owned(),
            magic: "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, not stripped"
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
            "Warning level: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("(1 undefined symbol: missing_sym)")),
            "aggregated detail names count and symbol: {lines:?}"
        );
    }

    #[test]
    fn undefined_symbols_aggregate_per_file() {
        // The finding fires once per file, however many undefined
        // symbols the file carries: the detail names the count and
        // every symbol, so the population stays visible without a
        // line per symbol.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let many = craft_shlib_elf(
            false,
            Some("libabsent.so.9"),
            Some("libmany.so.1"),
            &[
                ("sym_one", 1, 0, 0),
                ("sym_two", 1, 0, 0),
                ("sym_three", 1, 0, 0),
                ("sym_four", 1, 0, 0),
                ("sym_five", 1, 0, 0),
            ],
        );
        let one = craft_shlib_elf(
            false,
            Some("libabsent.so.9"),
            Some("libone.so.1"),
            &[("only_sym", 1, 0, 0)],
        );
        let pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![
                shlib_pkgfile(dir.path(), "libmany.so.1", &many),
                shlib_pkgfile(dir.path(), "libone.so.1", &one),
            ],
        );
        let results = driver_results(&pkg, &test_config());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 2, "one finding per file: {results:?}");
        let many_line = lines
            .iter()
            .find(|l| l.contains("libmany.so.1"))
            .expect("the many-symbol file fires");
        assert!(many_line.contains(" W: "), "Warning level: {many_line}");
        assert!(
            many_line
                .contains("(5 undefined symbols: sym_one, sym_two, sym_three, sym_four, sym_five)"),
            "count and every symbol named: {many_line}"
        );
        let one_line = lines
            .iter()
            .find(|l| l.contains("libone.so.1"))
            .expect("the one-symbol file fires");
        assert!(
            one_line.contains("(1 undefined symbol: only_sym)"),
            "singular shape: {one_line}"
        );
    }

    #[test]
    fn undefined_symbol_provided_by_another_package_is_quiet() {
        // plusky/rpmcrab#701: in a multi-package invocation the
        // provider universe is the whole batch -- a consumer in one
        // package resolves against a library shipped by another
        // package, whichever order the two are checked in. The
        // symbol nobody in the batch provides keeps firing.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let provider =
            craft_shlib_elf(false, None, Some("libfoo.so.1"), &[("shared_sym", 1, 0, 1)]);
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("shared_sym", 1, 0, 0), ("nowhere_sym", 1, 0, 0)],
        );
        let provider_pkg = synthetic_pkg(
            "providerpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libfoo.so.1", &provider)],
        );
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let config = test_config();

        // The consumer alone: both symbols are unresolvable, and
        // they aggregate into the file's single finding.
        let alone = driver_results(&consumer_pkg, &config);
        let lines = lines_for(&alone, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 1, "one aggregated finding alone: {alone:?}");
        assert!(
            lines[0].contains("(2 undefined symbols: shared_sym, nowhere_sym)"),
            "the aggregate names both symbols: {lines:?}"
        );

        // Consumer first, provider second: the batch still
        // resolves shared_sym; only nowhere_sym remains.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(
            &mut check,
            &[&consumer_pkg, &provider_pkg],
            &config,
            &mut out,
        );
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(lines.len(), 1, "only the residue fires: {results:?}");
        assert!(
            lines[0].contains("nowhere_sym"),
            "the residue names the unprovided symbol: {lines:?}"
        );
        assert!(
            lines[0].contains(" W: "),
            "the residue is a warning: {lines:?}"
        );
    }

    #[test]
    fn system_provider_does_not_rescue_inside_an_invocation() {
        // plusky/rpmcrab#701: the system fallback belongs to the
        // single-package and installed cases. Inside a
        // multi-package invocation the batch is the universe: a
        // symbol only the host system provides keeps firing, so a
        // scan's results do not depend on the host it runs on.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let syslib = craft_shlib_elf(false, None, Some("libsys.so.1"), &[("sys_sym", 1, 0, 1)]);
        write_system_lib(&sysroot, "libsys.so.1", &syslib);
        let consumer = craft_shlib_elf(
            false,
            Some("libsys.so.1"),
            Some("libbar.so.1"),
            &[("sys_sym", 1, 0, 0)],
        );
        let other = craft_shlib_elf(
            false,
            None,
            Some("libother.so.1"),
            &[("other_sym", 1, 0, 1)],
        );
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let other_pkg = synthetic_pkg(
            "otherpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libother.so.1", &other)],
        );
        let config = test_config();

        // Alone, the system provider rescues the consumer.
        let alone = driver_results_with_system(
            &consumer_pkg,
            &config,
            SystemLibraries::with_roots(vec![sysroot.clone()], None),
        );
        assert!(
            lines_for(&alone, "undefined-non-weak-symbol").is_empty(),
            "system provider rescues a lone package: {alone:?}"
        );

        // In a batch, it does not.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.system_libraries = SystemLibraries::with_roots(vec![sysroot], None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(&mut check, &[&consumer_pkg, &other_pkg], &config, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "host-only provider must not rescue: {results:?}"
        );
        assert!(lines[0].contains("sys_sym"), "names the symbol: {lines:?}");
    }

    #[test]
    fn exe_only_package_does_not_flip_invocation_wide() {
        // plusky/rpmcrab#735 review: a package shipping only
        // executables contributes no provider library and no captured
        // consumer (executables are never captured -- the shlib gate
        // in `check_dependency`), so it must not count as an
        // invocation contributor. Otherwise adding it to a batch
        // disables the system fallback for a sibling package whose
        // symbols the system provides, and the sibling's verdict
        // depends on an unrelated package.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let syslib = craft_shlib_elf(false, None, Some("libsys.so.1"), &[("sys_sym", 1, 0, 1)]);
        write_system_lib(&sysroot, "libsys.so.1", &syslib);
        let consumer = craft_shlib_elf(
            false,
            Some("libsys.so.1"),
            Some("libbar.so.1"),
            &[("sys_sym", 1, 0, 0)],
        );
        let exe = craft_shlib_elf(false, Some("libsys.so.1"), None, &[("main", 1, 2, 1)]);
        let other = craft_shlib_elf(
            false,
            None,
            Some("libother.so.1"),
            &[("other_sym", 1, 0, 1)],
        );
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let exe_pkg = synthetic_pkg(
            "exepkg",
            "x86_64",
            vec![exe_pkgfile(dir.path(), "tool", &exe)],
        );
        let other_pkg = synthetic_pkg(
            "otherpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libother.so.1", &other)],
        );
        let config = test_config();

        // Alone, the system provider rescues the consumer.
        let alone = driver_results_with_system(
            &consumer_pkg,
            &config,
            SystemLibraries::with_roots(vec![sysroot.clone()], None),
        );
        assert!(
            lines_for(&alone, "undefined-non-weak-symbol").is_empty(),
            "system provider rescues a lone package: {alone:?}"
        );

        // Batched with the exe-only package, the consumer is still
        // the only contributor: the system fallback stays in place
        // and the verdict is the same as alone.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.system_libraries = SystemLibraries::with_roots(vec![sysroot.clone()], None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(&mut check, &[&consumer_pkg, &exe_pkg], &config, &mut out);
        let results = out.results().to_vec();
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "exe-only package must not disable the system fallback: {results:?}"
        );

        // A genuine contributor alongside still flips the batch:
        // with a second library package in the invocation the system
        // fallback is off and the host-only symbol fires.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.system_libraries = SystemLibraries::with_roots(vec![sysroot], None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(
            &mut check,
            &[&consumer_pkg, &exe_pkg, &other_pkg],
            &config,
            &mut out,
        );
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "genuine contributor still flips the batch: {results:?}"
        );
        assert!(lines[0].contains("sys_sym"), "names the symbol: {lines:?}");
    }

    #[test]
    fn cross_package_same_soname_provider_does_not_mask_consumers_own() {
        // plusky/rpmcrab#735 blocker 3: two packages in one
        // invocation ship the same SONAME with different symbol
        // sets (two versions of one library). The consumer's own
        // package ships the older copy, which does not define
        // `versioned_sym`; the sibling's copy does. Unioning the
        // two providers under the bare SONAME would mask the
        // missing symbol -- the consumer resolves against its own
        // package's provider, so the symbol must fire, in either
        // package order (order-independence pin).
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let own_dir = dir.path().join("own");
        let sibling_dir = dir.path().join("sibling");
        std::fs::create_dir(&own_dir).expect("mkdir own");
        std::fs::create_dir(&sibling_dir).expect("mkdir sibling");
        let own_provider =
            craft_shlib_elf(false, None, Some("libfoo.so.1"), &[("shared_sym", 1, 0, 1)]);
        let sibling_provider = craft_shlib_elf(
            false,
            None,
            Some("libfoo.so.1"),
            &[("shared_sym", 1, 0, 1), ("versioned_sym", 1, 0, 1)],
        );
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("shared_sym", 1, 0, 0), ("versioned_sym", 1, 0, 0)],
        );
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![
                shlib_pkgfile(&own_dir, "libfoo.so.1", &own_provider),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
            ],
        );
        let sibling_pkg = synthetic_pkg(
            "siblingpkg",
            "x86_64",
            vec![shlib_pkgfile(
                &sibling_dir,
                "libfoo.so.1",
                &sibling_provider,
            )],
        );
        let config = test_config();
        for pkgs in [
            &[&consumer_pkg, &sibling_pkg][..],
            &[&sibling_pkg, &consumer_pkg][..],
        ] {
            let mut check = BinariesCheck::with_tool_dir(&config, None);
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            run_invocation(&mut check, pkgs, &config, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "undefined-non-weak-symbol");
            assert_eq!(
                lines.len(),
                1,
                "only the symbol the consumer's own provider lacks fires, \
                 in either package order: {results:?}"
            );
            assert!(
                lines[0].contains("versioned_sym"),
                "the residue names the masked symbol: {lines:?}"
            );
        }
    }

    #[test]
    fn cross_package_same_soname_needs_do_not_join_consumers_closure() {
        // plusky/rpmcrab#735 blocker 3, transitive half: the
        // sibling's copy of libfoo NEEDs libdeep, the consumer's
        // own copy does not. Unioning the providers would also
        // union their DT_NEEDED entries and pull libdeep into the
        // consumer's closure through a provider it never loads,
        // masking `deep_sym`.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let own_dir = dir.path().join("own");
        let sibling_dir = dir.path().join("sibling");
        std::fs::create_dir(&own_dir).expect("mkdir own");
        std::fs::create_dir(&sibling_dir).expect("mkdir sibling");
        let own_provider = craft_shlib_elf_paths(
            false,
            &[],
            Some("libfoo.so.1"),
            None,
            None,
            &[("foo_sym", 1, 0, 1)],
        );
        let sibling_provider = craft_shlib_elf_paths(
            false,
            &["libdeep.so.1"],
            Some("libfoo.so.1"),
            None,
            None,
            &[("foo_sym", 1, 0, 1)],
        );
        let deep_provider =
            craft_shlib_elf(false, None, Some("libdeep.so.1"), &[("deep_sym", 1, 0, 1)]);
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("foo_sym", 1, 0, 0), ("deep_sym", 1, 0, 0)],
        );
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![
                shlib_pkgfile(&own_dir, "libfoo.so.1", &own_provider),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
            ],
        );
        let sibling_pkg = synthetic_pkg(
            "siblingpkg",
            "x86_64",
            vec![
                shlib_pkgfile(&sibling_dir, "libfoo.so.1", &sibling_provider),
                shlib_pkgfile(&sibling_dir, "libdeep.so.1", &deep_provider),
            ],
        );
        let config = test_config();
        for pkgs in [
            &[&consumer_pkg, &sibling_pkg][..],
            &[&sibling_pkg, &consumer_pkg][..],
        ] {
            let mut check = BinariesCheck::with_tool_dir(&config, None);
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            run_invocation(&mut check, pkgs, &config, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "undefined-non-weak-symbol");
            assert_eq!(
                lines.len(),
                1,
                "only the symbol reachable solely through the sibling \
                 provider's needs fires, in either package order: {results:?}"
            );
            assert!(
                lines[0].contains("deep_sym"),
                "the residue names the transitively masked symbol: {lines:?}"
            );
        }
    }

    #[test]
    fn provider_from_a_different_arch_package_does_not_resolve() {
        // plusky/rpmcrab#735 blocker 3, arch half: a provider
        // shipped by a package of a different architecture is not
        // a provider for this consumer at all -- the loader would
        // never bind an x86_64 consumer to an aarch64 library,
        // however the two are keyed.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let provider = craft_shlib_elf(false, None, Some("libfoo.so.1"), &[("arch_sym", 1, 0, 1)]);
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("arch_sym", 1, 0, 0)],
        );
        let provider_pkg = synthetic_pkg(
            "providerpkg",
            "aarch64",
            vec![shlib_pkgfile(dir.path(), "libfoo.so.1", &provider)],
        );
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(
            &mut check,
            &[&consumer_pkg, &provider_pkg],
            &config,
            &mut out,
        );
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "a different-arch provider must not resolve: {results:?}"
        );
        assert!(
            lines[0].contains("arch_sym"),
            "the residue names the symbol: {lines:?}"
        );
    }

    #[test]
    fn same_name_arch_packages_with_distinct_files_both_count_as_contributors() {
        // plusky/rpmcrab#735 OCR nit: contributor dedup keyed on
        // (name, arch) collapses two distinct packages that share
        // a name and arch (two versions in one invocation) into
        // one contributor, so the batch wrongly stays in
        // single-package mode and the system fallback rescues a
        // symbol the invocation itself does not provide.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let syslib = craft_shlib_elf(false, None, Some("libsys.so.1"), &[("sys_sym", 1, 0, 1)]);
        write_system_lib(&sysroot, "libsys.so.1", &syslib);
        let consumer = craft_shlib_elf(
            false,
            Some("libsys.so.1"),
            Some("libbar.so.1"),
            &[("sys_sym", 1, 0, 0)],
        );
        let other = craft_shlib_elf(
            false,
            None,
            Some("libother.so.1"),
            &[("other_sym", 1, 0, 1)],
        );
        let mut consumer_pkg = synthetic_pkg(
            "samepkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        consumer_pkg.filename = "samepkg-1.0-1.x86_64.rpm".to_string();
        let mut other_pkg = synthetic_pkg(
            "samepkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libother.so.1", &other)],
        );
        other_pkg.filename = "samepkg-2.0-1.x86_64.rpm".to_string();
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.system_libraries = SystemLibraries::with_roots(vec![sysroot], None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(&mut check, &[&consumer_pkg, &other_pkg], &config, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "two distinct same-name packages flip the batch to \
             invocation-wide resolution: {results:?}"
        );
        assert!(lines[0].contains("sys_sym"), "names the symbol: {lines:?}");
    }

    #[test]
    fn same_name_versions_resolve_against_own_package_file() {
        // Issue #799: the provider index keyed a package by
        // (name, arch) alone, so two versions of one package in one
        // invocation shared a lookup identity: a consumer in the
        // newer version resolved against whichever version's copy
        // of a SONAME check order reached first. The identity now
        // includes the package file, so the consumer resolves
        // against its own version's copy -- which does not define
        // `versioned_sym`, so the symbol fires.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let v1_dir = dir.path().join("v1");
        let v2_dir = dir.path().join("v2");
        std::fs::create_dir(&v1_dir).expect("mkdir v1");
        std::fs::create_dir(&v2_dir).expect("mkdir v2");
        let defining = craft_shlib_elf(
            false,
            None,
            Some("libfoo.so.1"),
            &[("versioned_sym", 1, 0, 1)],
        );
        let lacking = craft_shlib_elf(false, None, Some("libfoo.so.1"), &[("other_sym", 1, 0, 1)]);
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("versioned_sym", 1, 0, 0)],
        );
        let mut v1_pkg = synthetic_pkg(
            "libpkg",
            "x86_64",
            vec![shlib_pkgfile(&v1_dir, "libfoo.so.1", &defining)],
        );
        v1_pkg.filename = "libpkg-1.0-1.x86_64.rpm".to_string();
        let mut v2_pkg = synthetic_pkg(
            "libpkg",
            "x86_64",
            vec![
                shlib_pkgfile(&v2_dir, "libfoo.so.1", &lacking),
                shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
            ],
        );
        v2_pkg.filename = "libpkg-2.0-1.x86_64.rpm".to_string();
        let config = test_config();
        // The defining version is checked first: under a name+arch
        // identity its copy is the one the lookup reaches.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(&mut check, &[&v1_pkg, &v2_pkg], &config, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "the consumer resolves against its own version's copy: {results:?}"
        );
        assert!(
            lines[0].contains("versioned_sym"),
            "names the symbol: {lines:?}"
        );
    }

    #[test]
    fn single_contributor_index_excludes_non_contributor_sets() {
        // Issue #799: in single-contributor mode the provider index
        // was built from every package's set, so a non-contributing
        // sibling's entries could satisfy the contributor's
        // DT_NEEDED spellings. An exe-only package's files land in
        // its provider set under their basenames; here the sibling
        // ships an executable whose basename matches the consumer's
        // DT_NEEDED spelling and whose defined symbols cover the
        // undefined one. Single-contributor resolution sees the
        // contributor's own set plus the system only, so the symbol
        // must fire.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let sysroot = dir.path().join("sysroot");
        std::fs::create_dir(&sysroot).expect("mkdir sysroot");
        let consumer = craft_shlib_elf(
            false,
            Some("tool"),
            Some("libbar.so.1"),
            &[("tool_sym", 1, 0, 0)],
        );
        let exe = craft_shlib_elf(false, None, None, &[("tool_sym", 1, 0, 1)]);
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let exe_pkg = synthetic_pkg(
            "exepkg",
            "x86_64",
            vec![exe_pkgfile(dir.path(), "tool", &exe)],
        );
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.system_libraries = SystemLibraries::with_roots(vec![sysroot], None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(&mut check, &[&consumer_pkg, &exe_pkg], &config, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "a non-contributor's basename entry must not satisfy the spelling: {results:?}"
        );
        assert!(lines[0].contains("tool_sym"), "names the symbol: {lines:?}");
    }

    #[test]
    fn contributorless_batch_resolves_nothing() {
        // A deferred batch in which no package contributes -- an
        // exe-only package's files land in its provider set under
        // their basenames, yet it captures no consumer and provides
        // no library -- reaches `after_checks` with an empty
        // contributor list. The single-contributor filter must keep
        // no set (and must not index into the missing contributor);
        // with no consumers there is nothing to resolve.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let exe = craft_shlib_elf(false, None, None, &[("tool_sym", 1, 0, 1)]);
        let exe_pkg = synthetic_pkg(
            "exepkg",
            "x86_64",
            vec![exe_pkgfile(dir.path(), "tool", &exe)],
        );
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(&mut check, &[&exe_pkg], &config, &mut out);
        let results = out.results().to_vec();
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "no consumers, no findings: {results:?}"
        );
    }

    #[test]
    fn hwcaps_subarch_provider_resolves_for_base_arch_consumer() {
        // Issue #799: the cross-package lookup compared raw arch
        // strings, so a provider package built for a hwcaps subarch
        // (x86_64_v3) never resolved a base-arch (x86_64) consumer,
        // even though subarch packages ship files under the base
        // arch's libdirs. The comparison now runs on base arches.
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let provider = craft_shlib_elf(false, None, Some("libfoo.so.1"), &[("foo_sym", 1, 0, 1)]);
        let consumer = craft_shlib_elf(
            false,
            Some("libfoo.so.1"),
            Some("libbar.so.1"),
            &[("foo_sym", 1, 0, 0)],
        );
        let provider_pkg = synthetic_pkg(
            "providerpkg",
            "x86_64_v3",
            vec![shlib_pkgfile(dir.path(), "libfoo.so.1", &provider)],
        );
        let consumer_pkg = synthetic_pkg(
            "consumerpkg",
            "x86_64",
            vec![shlib_pkgfile(dir.path(), "libbar.so.1", &consumer)],
        );
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        run_invocation(
            &mut check,
            &[&consumer_pkg, &provider_pkg],
            &config,
            &mut out,
        );
        let results = out.results().to_vec();
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "a base-arch-equal provider resolves the consumer: {results:?}"
        );
    }

    #[test]
    fn installed_package_resolves_undefined_symbols_in_place() {
        // The installed path (`resolve_undefined_symbols` during
        // `check_binary`, no deferral): a symbol the package's own
        // provider defines stays quiet and a symbol nobody defines
        // fires, as a warning, during the package's own check.
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
            &[("provided_sym", 1, 0, 0), ("missing_sym", 1, 0, 0)],
        );
        let rpm = format!(
            "{}/../../tests/fixtures/binaries-check/input/rpmcrab-binaries-fixture-1.0-1.aarch64.rpm",
            env!("CARGO_MANIFEST_DIR")
        );
        let header = librpm::PackageHeader::from_file(
            std::path::Path::new(&rpm),
            Some(&librpm::verify::VerifyOptions::skip_verification()),
        )
        .expect("open fixture header");
        let mut pkg = Pkg::installed(header).expect("build installed package");
        pkg.name = "testpkg".to_string();
        pkg.arch = "x86_64".to_string();
        pkg.files = vec![
            shlib_pkgfile(dir.path(), "libfoo.so.1", &provider),
            shlib_pkgfile(dir.path(), "libbar.so.1", &consumer),
        ];
        assert!(
            pkg.is_installed(),
            "the fixture must take the installed path"
        );
        let results = driver_results(&pkg, &test_config());
        let lines = lines_for(&results, "undefined-non-weak-symbol");
        assert_eq!(
            lines.len(),
            1,
            "only the unprovided symbol fires for an installed package: {results:?}"
        );
        assert!(
            lines[0].contains("missing_sym"),
            "the residue names the symbol: {lines:?}"
        );
        assert!(
            lines[0].contains(" W: "),
            "the residue is a warning: {lines:?}"
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
        run_batch(&mut check, pkg, config, &mut out);
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

        // Undefined symbols in a shared object -> Warning.
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
    fn deferred_capture_keeps_only_the_defined_undefined_intersection() {
        // Issue #799: the deferred capture keeps only the defined
        // symbols that are also undefined -- `after_checks` tests
        // membership for the consumer's own undefined symbols, so a
        // defined symbol outside that set is never consulted. The
        // intersection is computed at the capture site (set-based
        // since issue #804); this pins its contents, so a widened,
        // narrowed or inverted filter fails here.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_dynamically_linked = true;
        check.defer_undefined = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libfoo.so.1", "ELF 64-bit LSB shared object");
        let mut ldd = syn_ldd();
        ldd.undefined_symbols = vec!["self_sym".to_string(), "missing_sym".to_string()];
        ldd.defined_symbols = vec!["self_sym".to_string(), "other_sym".to_string()];
        let mut info = syn_info();
        info.is_shlib = true;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_dependency(&pkg, &pkgfile, &info, &ldd, &mut out);
        let results = out.results().to_vec();
        assert!(
            lines_for(&results, "undefined-non-weak-symbol").is_empty(),
            "deferred capture emits nothing yet: {results:?}"
        );
        let state = check.pending_state.as_ref().expect("capture recorded");
        assert_eq!(state.packages.len(), 1);
        let captured = &state.packages[0].files[0];
        assert_eq!(
            captured.undefined_symbols,
            vec!["self_sym".to_string(), "missing_sym".to_string()]
        );
        let expected: HashSet<String> = ["self_sym".to_string()].into_iter().collect();
        assert_eq!(captured.defined_symbols, expected);
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
    fn mktemp_definition_site_is_not_a_call_in_an_archive() {
        // #852: in an archive, call-to-mktemp charges a call, and a call
        // is an undefined reference. The member that defines mktemp
        // (newlib's libc.a carries the definition) makes no call and
        // stays silent.
        let config = test_config();
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/lib64/libc.a", "current ar archive");
        let count = |info: &ReadelfInfo| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "call-to-mktemp").len()
        };
        let with = |functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            info
        };

        // An import (the stripped-executable shape) is a call: fires.
        assert_eq!(count(&with(&["mktemp"], &["mktemp"])), 1);
        // A versioned import is a call: fires.
        assert_eq!(count(&with(&["mktemp"], &["mktemp@GLIBC_2.2.5"])), 1);
        // The definition alone (the newlib shape) is not a call: silent.
        assert_eq!(count(&with(&["mktemp"], &[])), 0);
        // Near-miss names in the reference set stay silent.
        assert_eq!(count(&with(&["mkstemp"], &["mkstemp"])), 0);
        assert_eq!(count(&with(&["mktemp64"], &["mktemp64"])), 0);
    }

    #[test]
    fn mktemp_defined_only_fires_in_a_linked_object() {
        // #852: a linked object — an executable or a shared library —
        // charges a defined match too. A statically linked executable
        // bundling mktemp and a wrapper library that defines and calls
        // its own variant both carry the definition with no undefined
        // reference, and they fire, as they do in the reference.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        assert!(!check.is_archive);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let count = |info: &ReadelfInfo| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "call-to-mktemp").len()
        };
        let with = |functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            info
        };

        // The definition alone (the statically linked shape) fires.
        assert_eq!(count(&with(&["mktemp"], &[])), 1);
        // A versioned definition fires.
        assert_eq!(count(&with(&["mktemp@GLIBC_2.2.5"], &[])), 1);
        // An import fires too, as before.
        assert_eq!(count(&with(&["mktemp"], &["mktemp"])), 1);
        // Near-miss defined names stay silent.
        assert_eq!(count(&with(&["mkstemp"], &[])), 0);
        assert_eq!(count(&with(&["mktemp64"], &[])), 0);
    }

    #[test]
    fn gets_charges_undefined_references_only() {
        // #972: call-to-gets charges an undefined reference to gets,
        // in an archive and in a linked object alike. A definition is
        // never a call (glibc's libc defines gets as a compatibility
        // symbol), and the anchored pattern keeps the safe and the
        // fortified neighbours silent.
        let config = test_config();
        let count = |is_archive: bool, info: &ReadelfInfo| {
            let mut check = BinariesCheck::with_tool_dir(&config, None);
            check.is_archive = is_archive;
            let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
            let pkgfile = if is_archive {
                syn_file("/usr/lib64/libfoo.a", "current ar archive")
            } else {
                syn_file("/usr/lib64/libfoo.so", "ELF 64-bit LSB shared object")
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "call-to-gets").len()
        };
        let with = |functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            info
        };

        for is_archive in [true, false] {
            // A reference is a call: fires, plain and versioned.
            assert_eq!(count(is_archive, &with(&["gets"], &["gets"])), 1);
            assert_eq!(
                count(is_archive, &with(&["gets"], &["gets@GLIBC_2.2.5"])),
                1
            );
            // The definition alone (the glibc shape) is not a call: silent.
            assert_eq!(count(is_archive, &with(&["gets"], &[])), 0);
            // Near-miss names stay silent: the safe replacement, the
            // bounded Annex K form, and the fortified variant whose
            // bound is checked.
            assert_eq!(count(is_archive, &with(&["fgets"], &["fgets"])), 0);
            assert_eq!(count(is_archive, &with(&["gets_s"], &["gets_s"])), 0);
            assert_eq!(
                count(is_archive, &with(&["__gets_chk"], &["__gets_chk"])),
                0
            );
            assert_eq!(count(is_archive, &with(&["getline"], &["getline"])), 0);
            // A NOTYPE dynsym import lands only in
            // `undefined_functions`, with no FUNC reference: fires.
            let mut info = syn_info();
            info.undefined_functions = vec!["gets".to_string()];
            assert_eq!(count(is_archive, &info), 1);
        }
    }

    #[test]
    fn tmpnam_charges_undefined_references_only() {
        // #972: call-to-tmpnam charges an undefined reference to the
        // tmpnam family (tmpnam, tmpnam_r, tempnam), in an archive and
        // in a linked object alike. A definition is never a call: the
        // library implementing the family (glibc's libc carries the
        // definitions) is the provider, not a caller.
        let config = test_config();
        let count = |is_archive: bool, info: &ReadelfInfo| {
            let mut check = BinariesCheck::with_tool_dir(&config, None);
            check.is_archive = is_archive;
            let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
            let pkgfile = if is_archive {
                syn_file("/usr/lib64/libfoo.a", "current ar archive")
            } else {
                syn_file("/usr/lib64/libfoo.so", "ELF 64-bit LSB shared object")
            };
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "call-to-tmpnam").len()
        };
        let with = |functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            info
        };

        for is_archive in [true, false] {
            // Each family member, referenced: a call, fires.
            assert_eq!(count(is_archive, &with(&["tmpnam"], &["tmpnam"])), 1);
            assert_eq!(count(is_archive, &with(&["tmpnam_r"], &["tmpnam_r"])), 1);
            assert_eq!(count(is_archive, &with(&["tempnam"], &["tempnam"])), 1);
            // A versioned reference fires.
            assert_eq!(
                count(is_archive, &with(&["tmpnam"], &["tmpnam@GLIBC_2.2.5"])),
                1
            );
            // The definition alone (the glibc shape) is not a call: silent.
            assert_eq!(count(is_archive, &with(&["tmpnam"], &[])), 0);
            assert_eq!(count(is_archive, &with(&["tempnam"], &[])), 0);
            // Near-miss names stay silent: the safe sibling, the
            // descriptor-returning relative, and suffixed strangers the
            // anchored pattern must not reach.
            assert_eq!(count(is_archive, &with(&["mkstemp"], &["mkstemp"])), 0);
            assert_eq!(count(is_archive, &with(&["tmpfile"], &["tmpfile"])), 0);
            assert_eq!(count(is_archive, &with(&["tmpnam64"], &["tmpnam64"])), 0);
            assert_eq!(count(is_archive, &with(&["my_tmpnam"], &["my_tmpnam"])), 0);
            // Another family's reference does not cross-fire.
            assert_eq!(count(is_archive, &with(&["mktemp"], &["mktemp"])), 0);
        }
    }

    #[test]
    fn mktemp_lookalike_names_stay_silent() {
        // The charged symbol must BE mktemp: the pattern is anchored
        // at the start, so a project-private wrapper whose name merely
        // ends in mktemp (net-snmp's netsnmp_mktemp and its kin) is a
        // call to that project's own function, not to the libc mktemp.
        // The reference's searched regexp fires on these names too;
        // this is a deliberate divergence (see the divergences ledger).
        let config = test_config();
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let run = |check: &BinariesCheck, pkgfile: &PkgFile, info: &ReadelfInfo| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, pkgfile, info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "call-to-mktemp").len()
        };
        let with = |functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            info
        };

        // Linked object: any FUNC match charges, defined or not.
        let check = BinariesCheck::with_tool_dir(&config, None);
        let exe = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        for name in [
            "netsnmp_mktemp",
            "apr_file_mktemp",
            "e_mktemp",
            "netsnmp_mktemp@GLIBC_2.2.5",
            "mktemp_wrapper",
        ] {
            assert_eq!(run(&check, &exe, &with(&[name], &[name])), 0, "{name}");
        }
        // The real symbol still fires, plain and versioned.
        assert_eq!(run(&check, &exe, &with(&["mktemp"], &[])), 1);
        assert_eq!(run(&check, &exe, &with(&["mktemp@GLIBC_2.2.5"], &[])), 1);

        // Archive: only an undefined reference charges.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let lib = syn_file("/usr/lib64/libnetsnmp.a", "current ar archive");
        assert_eq!(
            run(
                &check,
                &lib,
                &with(&["netsnmp_mktemp"], &["netsnmp_mktemp"])
            ),
            0
        );
        assert_eq!(run(&check, &lib, &with(&["mktemp"], &["mktemp"])), 1);
    }

    /// Minimal ET_REL ELF64 object carrying a `.symtab`, for the #852
    /// parse tests. Each sym is (name, bind, type, shndx); shndx 0 is
    /// SHN_UNDEF (a reference), 1 is the `.text` section (a definition).
    fn craft_symtab_object(syms: &[(&str, u8, u8, u16)]) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut name_offs = Vec::new();
        for (name, _, _, _) in syms {
            name_offs.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }
        let mut symtab = vec![0u8; 24];
        for (i, (_, bind, typ, shndx)) in syms.iter().enumerate() {
            let mut e = vec![0u8; 24];
            e[0..4].copy_from_slice(&name_offs[i].to_le_bytes());
            e[4] = (bind << 4) | typ;
            e[6..8].copy_from_slice(&shndx.to_le_bytes());
            symtab.extend(e);
        }
        let mut shstrtab = vec![0u8];
        let text_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".text\0");
        let symtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".symtab\0");
        let strtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".strtab\0");
        let shstrtab_name = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");

        let mut buf = vec![0u8; 64];
        let text_off = buf.len() as u64;
        buf.push(0xc3);
        let symtab_off = buf.len() as u64;
        buf.extend_from_slice(&symtab);
        let strtab_off = buf.len() as u64;
        buf.extend_from_slice(&strtab);
        let shstrtab_off = buf.len() as u64;
        buf.extend_from_slice(&shstrtab);
        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        let shoff = buf.len() as u64;

        // Section headers: NULL, .text, .symtab, .strtab, .shstrtab.
        let mut shdrs = vec![0u8; 64];
        let mut push_sh = |name: u32,
                           stype: u32,
                           flags: u64,
                           off: u64,
                           size: u64,
                           link: u32,
                           info: u32,
                           entsize: u64| {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&stype.to_le_bytes());
            h[8..16].copy_from_slice(&flags.to_le_bytes());
            h[24..32].copy_from_slice(&off.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            h[40..44].copy_from_slice(&link.to_le_bytes());
            h[44..48].copy_from_slice(&info.to_le_bytes());
            h[48..56].copy_from_slice(&1u64.to_le_bytes());
            h[56..64].copy_from_slice(&entsize.to_le_bytes());
            shdrs.extend(h);
        };
        push_sh(text_name, 1, 0x6, text_off, 1, 0, 0, 0);
        push_sh(symtab_name, 2, 0, symtab_off, symtab.len() as u64, 3, 1, 24);
        push_sh(strtab_name, 3, 0, strtab_off, strtab.len() as u64, 0, 0, 0);
        push_sh(
            shstrtab_name,
            3,
            0,
            shstrtab_off,
            shstrtab.len() as u64,
            0,
            0,
            0,
        );
        buf.extend(shdrs);

        let mut ehdr = vec![0u8; 64];
        ehdr[0..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 2;
        ehdr[5] = 1;
        ehdr[6] = 1;
        ehdr[16..18].copy_from_slice(&1u16.to_le_bytes());
        ehdr[18..20].copy_from_slice(&62u16.to_le_bytes());
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        ehdr[40..48].copy_from_slice(&shoff.to_le_bytes());
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes());
        ehdr[60..62].copy_from_slice(&5u16.to_le_bytes());
        ehdr[62..64].copy_from_slice(&4u16.to_le_bytes());
        buf[0..64].copy_from_slice(&ehdr);
        buf
    }

    #[test]
    fn mktemp_refs_come_from_undefined_func_symbols_only() {
        // #852 parse level: `undefined_function_refs` collects exactly
        // the undefined STT_FUNC symbols of both symbol tables.
        // (name, bind, type, shndx); STB_GLOBAL = 1, STT_NOTYPE = 0,
        // STT_FUNC = 2, SHN_UNDEF = 0.
        let parse = |tag: &str, bytes: &[u8], name: &str| {
            let path = std::env::temp_dir()
                .join(format!("rpmcrab-mktemp-parse-{tag}-{}", std::process::id()));
            std::fs::write(&path, bytes).unwrap();
            let info = ReadelfInfo::parse(path.to_str().unwrap(), name);
            std::fs::remove_file(&path).ok();
            assert!(
                info.failed.is_none(),
                "crafted ELF must parse: {:?}",
                info.failed
            );
            info
        };
        let has = |v: &[String], n: &str| v.iter().any(|s| s == n);

        // .dynsym import: a reference, and a function.
        let info = parse(
            "dyn-import",
            &craft_shlib_elf(false, None, None, &[("mktemp", 1, 2, 0)]),
            "/usr/lib64/libprobe.so",
        );
        assert!(
            has(&info.undefined_function_refs, "mktemp"),
            "refs: {:?}",
            info.undefined_function_refs
        );
        assert!(has(&info.functions, "mktemp"));

        // .dynsym definition: a function, but no reference.
        let info = parse(
            "dyn-def",
            &craft_shlib_elf(false, None, None, &[("mktemp", 1, 2, 1)]),
            "/usr/lib64/libprobe.so",
        );
        assert!(has(&info.functions, "mktemp"));
        assert!(
            !has(&info.undefined_function_refs, "mktemp"),
            "refs: {:?}",
            info.undefined_function_refs
        );

        // .dynsym NOTYPE import: an import for the import set, but not
        // a function reference, mirroring `functions`.
        let info = parse(
            "dyn-notype",
            &craft_shlib_elf(false, None, None, &[("mktemp", 1, 0, 0)]),
            "/usr/lib64/libprobe.so",
        );
        assert!(has(&info.undefined_functions, "mktemp"));
        assert!(!has(&info.functions, "mktemp"));
        assert!(
            !has(&info.undefined_function_refs, "mktemp"),
            "refs: {:?}",
            info.undefined_function_refs
        );

        // .symtab reference (an archive member): a reference. The bare
        // ET_REL object is wrapped in an ar archive so the case covers
        // the member merging a real archive parse performs.
        let member = craft_symtab_object(&[("mktemp", 1, 2, 0)]);
        let archive = craft_ar_archive(&[("mktemp_ref.o", &member)]);
        let info = parse("sym-ref", &archive, "/usr/lib64/libprobe.a");
        assert!(
            has(&info.undefined_function_refs, "mktemp"),
            "refs: {:?}",
            info.undefined_function_refs
        );
        assert!(has(&info.functions, "mktemp"));

        // .symtab definition (the newlib shape): no reference.
        let member = craft_symtab_object(&[("mktemp", 1, 2, 1)]);
        let archive = craft_ar_archive(&[("libc_a-mktemp.o", &member)]);
        let info = parse("sym-def", &archive, "/usr/lib64/libprobe.a");
        assert!(has(&info.functions, "mktemp"));
        assert!(
            !has(&info.undefined_function_refs, "mktemp"),
            "refs: {:?}",
            info.undefined_function_refs
        );

        // Merged members: one member defines mktemp, another references
        // it — the merged archive carries the reference, so the archive
        // gate fires on the referencing member's call.
        let defining = craft_symtab_object(&[("mktemp", 1, 2, 1)]);
        let referencing = craft_symtab_object(&[("mktemp", 1, 2, 0)]);
        let archive =
            craft_ar_archive(&[("libc_a-mktemp.o", &defining), ("caller.o", &referencing)]);
        let info = parse("sym-merged", &archive, "/usr/lib64/libprobe.a");
        assert!(has(&info.functions, "mktemp"));
        assert!(
            has(&info.undefined_function_refs, "mktemp"),
            "refs: {:?}",
            info.undefined_function_refs
        );
    }

    #[test]
    fn security_function_findings() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);

        // mktemp referenced (an undefined import) -> Error.
        let mut info = syn_info();
        info.functions = vec!["mktemp".to_string()];
        info.undefined_function_refs = vec!["mktemp".to_string()];
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

        // setuid+setgid without setgroups: Warning with or without
        // the setuid bit (#743).
        let mut info = syn_info();
        info.functions = vec!["setuid".to_string(), "setgid".to_string()];
        let mut pkgfile = syn_file("/usr/bin/setuidbin", "ELF 64-bit LSB executable");
        pkgfile.mode = 0o104755;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "missing-call-to-setgroups-before-setuid");
        assert_eq!(lines.len(), 1, "exactly one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

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

        // Calling initgroups silences the finding too.
        let mut info = syn_info();
        info.functions = vec![
            "setuid".to_string(),
            "setgid".to_string(),
            "initgroups".to_string(),
        ];
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        assert!(
            out.results().is_empty(),
            "initgroups present must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn legacy_crypto_findings() {
        // #972 candidate 6: an undefined reference to a low-level
        // legacy-primitive entry point reports at Warning, one tag
        // per primitive set. Definitions (the implementing library's
        // shape) and the high-level EVP interface stay silent.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let count = |info: &ReadelfInfo, tag: &str| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, tag).len()
        };
        let with = |functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            info
        };

        // MD5 set: each entry point referenced fires, at Warning.
        for sym in ["MD5", "MD5_Init", "MD5_Update", "MD5_Final"] {
            let info = with(&[sym], &[sym]);
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "binary-or-shlib-calls-md5");
            assert_eq!(lines.len(), 1, "{sym} referenced must fire: {results:?}");
            assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
            assert_eq!(count(&info, "binary-or-shlib-calls-des"), 0);
            assert_eq!(count(&info, "binary-or-shlib-calls-rc4"), 0);
        }
        // A versioned reference is a call: fires.
        assert_eq!(
            count(
                &with(&["MD5_Init"], &["MD5_Init@OPENSSL_3.0.0"]),
                "binary-or-shlib-calls-md5"
            ),
            1
        );
        // The definition alone (libcrypto's shape) is not a call: silent.
        assert_eq!(
            count(&with(&["MD5_Init"], &[]), "binary-or-shlib-calls-md5"),
            0
        );
        // EVP_MD5 is the high-level interface, not this pattern: silent.
        assert_eq!(
            count(
                &with(&["EVP_MD5"], &["EVP_MD5"]),
                "binary-or-shlib-calls-md5"
            ),
            0
        );
        // SHA1 is not in the candidate's sets: silent.
        assert_eq!(
            count(
                &with(&["SHA1_Init"], &["SHA1_Init"]),
                "binary-or-shlib-calls-md5"
            ),
            0
        );

        // DES set: the DES_* entry points referenced fire.
        for sym in ["DES_ecb_encrypt", "DES_set_key", "DES_cbc_encrypt"] {
            assert_eq!(
                count(&with(&[sym], &[sym]), "binary-or-shlib-calls-des"),
                1,
                "{sym} referenced must fire"
            );
        }
        assert_eq!(
            count(
                &with(&["DES_ecb_encrypt"], &[]),
                "binary-or-shlib-calls-des"
            ),
            0
        );
        // A name merely containing the prefix off-anchor stays silent.
        assert_eq!(
            count(
                &with(&["XDES_ecb_encrypt"], &["XDES_ecb_encrypt"]),
                "binary-or-shlib-calls-des"
            ),
            0
        );

        // RC4 set.
        for sym in ["RC4", "RC4_set_key"] {
            assert_eq!(
                count(&with(&[sym], &[sym]), "binary-or-shlib-calls-rc4"),
                1,
                "{sym} referenced must fire"
            );
        }
        assert_eq!(count(&with(&["RC4"], &[]), "binary-or-shlib-calls-rc4"), 0);
    }

    #[test]
    fn weak_prng_gated_findings() {
        // #972 candidate 7: an undefined reference to the rand family
        // reports at Warning only inside the privilege-or-exposure
        // gate; the bare shape, the definition-only shape and the
        // strong generators stay silent everywhere.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let plain = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let bare_pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let count = |pkg: &Pkg, pkgfile: &PkgFile, functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(pkg, pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "binary-or-shlib-calls-weak-prng").len()
        };
        let called = |sym: &str| count(&bare_pkg, &plain, &[sym], &[sym]);

        // Bare shape: silent for the whole family.
        for sym in ["rand", "random", "srand", "drand48", "srand48", "initstate"] {
            assert_eq!(called(sym), 0, "bare {sym} must stay silent");
        }

        // Setuid firing file -> Warning.
        let mut suid = plain.clone();
        suid.mode = 0o104755;
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut info = syn_info();
        info.functions = vec!["rand".to_string()];
        info.undefined_function_refs = vec!["rand".to_string()];
        check.check_security_functions(&bare_pkg, &suid, &info, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "binary-or-shlib-calls-weak-prng");
        assert_eq!(lines.len(), 1, "one finding: {results:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Setgid and capability-carrying firing files -> fire.
        let mut sgid = plain.clone();
        sgid.mode = 0o102755;
        assert_eq!(count(&bare_pkg, &sgid, &["srand48"], &["srand48"]), 1);
        let mut caps = plain.clone();
        caps.filecaps = Some("cap_net_raw+ep".to_string());
        assert_eq!(count(&bare_pkg, &caps, &["random"], &["random"]), 1);

        // Daemon packages (service or socket unit) -> fire.
        let svc_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/lib/systemd/system/foo.service",
                "ASCII text",
            )],
        );
        assert_eq!(count(&svc_pkg, &plain, &["drand48"], &["drand48"]), 1);
        let sock_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/lib/systemd/system/foo.socket", "ASCII text")],
        );
        assert_eq!(count(&sock_pkg, &plain, &["lrand48"], &["lrand48"]), 1);

        // Near miss: a %ghost unit entry ships no unit -> silent.
        let mut ghost_unit = syn_file("/usr/lib/systemd/system/foo.service", "ASCII text");
        ghost_unit.flags = crate::pkg::pkgfile::RPMFILE_GHOST;
        let ghost_pkg = synthetic_pkg("testpkg", "x86_64", vec![ghost_unit]);
        assert_eq!(count(&ghost_pkg, &plain, &["rand"], &["rand"]), 0);
        // Near miss: a masked unit (a symlink to /dev/null) loads
        // nothing -> silent.
        let mut masked_unit = syn_file("/usr/lib/systemd/system/foo.service", "ASCII text");
        masked_unit.mode = 0o120777;
        masked_unit.linkto = "/dev/null".to_string();
        let masked_pkg = synthetic_pkg("testpkg", "x86_64", vec![masked_unit]);
        assert_eq!(count(&masked_pkg, &plain, &["rand"], &["rand"]), 0);
        // Near miss: a unit path outside the unit directories (a
        // documentation example) is not daemon surface -> silent.
        let doc_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/share/doc/foo/systemd/system/bar.service",
                "ASCII text",
            )],
        );
        assert_eq!(count(&doc_pkg, &plain, &["rand"], &["rand"]), 0);
        // Near miss: a timer unit is not daemon surface -> silent.
        let timer_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/lib/systemd/system/foo.timer", "ASCII text")],
        );
        assert_eq!(count(&timer_pkg, &plain, &["rand"], &["rand"]), 0);
        // Near miss: a D-Bus activation file is not a systemd unit.
        let dbus_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/share/dbus-1/services/org.example.Foo.service",
                "ASCII text",
            )],
        );
        assert_eq!(count(&dbus_pkg, &plain, &["rand"], &["rand"]), 0);
        // Near miss: privilege on a different file does not gate this one.
        let mut other = syn_file("/usr/bin/helper", "ELF 64-bit LSB executable");
        other.mode = 0o104755;
        let mixed_pkg = synthetic_pkg("testpkg", "x86_64", vec![other]);
        assert_eq!(count(&mixed_pkg, &plain, &["rand"], &["rand"]), 0);
        // Definition-only (an implementing library's shape) stays silent
        // even in a gated package.
        assert_eq!(count(&svc_pkg, &plain, &["rand"], &[]), 0);
        // Reentrant forms fire inside the gate.
        assert_eq!(count(&bare_pkg, &suid, &["srandom_r"], &["srandom_r"]), 1);
        assert_eq!(count(&svc_pkg, &plain, &["drand48_r"], &["drand48_r"]), 1);
        // The strong generators are not this pattern, even setuid.
        assert_eq!(count(&bare_pkg, &suid, &["arc4random"], &["arc4random"]), 0);
        assert_eq!(count(&bare_pkg, &suid, &["getrandom"], &["getrandom"]), 0);
        assert_eq!(count(&bare_pkg, &suid, &["getentropy"], &["getentropy"]), 0);
    }

    #[test]
    fn gethostbyname_gate_levels() {
        // The defect-pattern privilege/exposure gates (#959, #967):
        // the bare pattern is a Warning; a firing file that itself
        // carries privilege, or any firing file in a package shipping
        // systemd service/socket units, is an Error.
        fn run(pkg: &Pkg, pkgfile: &PkgFile, functions: &[&str]) -> Vec<String> {
            let config = test_config();
            let check = BinariesCheck::with_tool_dir(&config, None);
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = info.functions.clone();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(pkg, pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "binary-or-shlib-calls-gethostbyname")
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        // A file that only defines the pattern (no undefined
        // reference): the pattern fires, the gate cannot promote it.
        fn run_definition_only(pkg: &Pkg, pkgfile: &PkgFile) -> Vec<String> {
            let config = test_config();
            let check = BinariesCheck::with_tool_dir(&config, None);
            let mut info = syn_info();
            info.functions = vec!["gethostbyname".to_string()];
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(pkg, pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "binary-or-shlib-calls-gethostbyname")
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        let plain = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let bare_pkg = synthetic_pkg("testpkg", "x86_64", vec![]);

        // Setuid firing file -> Error.
        let mut suid = plain.clone();
        suid.mode = 0o104755;
        let lines = run(&bare_pkg, &suid, &["gethostbyname"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);

        // Setgid firing file -> Error.
        let mut sgid = plain.clone();
        sgid.mode = 0o102755;
        let lines = run(&bare_pkg, &sgid, &["gethostbyname"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);

        // Capability-carrying firing file -> Error.
        let mut caps = plain.clone();
        caps.filecaps = Some("cap_net_raw+ep".to_string());
        let lines = run(&bare_pkg, &caps, &["gethostbyname"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);

        // Package shipping a systemd service unit -> Error, and the
        // _r lookalike fires through the same gate.
        let svc_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/lib/systemd/system/foo.service",
                "ASCII text",
            )],
        );
        let lines = run(&svc_pkg, &plain, &["gethostbyname_r"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);

        // Package shipping a systemd socket unit -> Error.
        let sock_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/lib/systemd/system/foo.socket", "ASCII text")],
        );
        let lines = run(&sock_pkg, &plain, &["gethostbyname"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);

        // Near miss: a timer unit is not daemon surface -> Warning.
        let timer_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/lib/systemd/system/foo.timer", "ASCII text")],
        );
        let lines = run(&timer_pkg, &plain, &["gethostbyname"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Near miss: a D-Bus activation file is not a systemd unit ->
        // Warning.
        let dbus_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/share/dbus-1/services/org.example.Foo.service",
                "ASCII text",
            )],
        );
        let lines = run(&dbus_pkg, &plain, &["gethostbyname"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Near miss: privilege on a *different* file of the package
        // does not gate this file's finding -> Warning.
        let mut other = syn_file("/usr/bin/helper", "ELF 64-bit LSB executable");
        other.mode = 0o104755;
        let mixed_pkg = synthetic_pkg("testpkg", "x86_64", vec![other]);
        let lines = run(&mixed_pkg, &plain, &["gethostbyname"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Near miss: a definition-only file in a daemon package
        // (an NSS module implementing the legacy entry points)
        // stays a Warning although the exposure gate matches.
        let lines = run_definition_only(&svc_pkg, &plain);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Near miss: a definition-only setuid file stays a Warning
        // although the privilege gate matches.
        let lines = run_definition_only(&bare_pkg, &suid);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Quiet shape: a privileged file in a daemon package that
        // resolves through getaddrinfo emits nothing.
        let mut suid_svc = plain.clone();
        suid_svc.mode = 0o104755;
        let lines = run(&svc_pkg, &suid_svc, &["getaddrinfo"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");
    }

    #[test]

    fn unbounded_copy_findings() {
        // #972 candidate 4: an undefined reference to strcpy, strcat,
        // sprintf or vsprintf reports at Warning. The predicate is the
        // reference, not the definition, and the fortified __*_chk
        // spellings are the checked form and stay silent.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let count = |info: &ReadelfInfo| {
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "binary-or-shlib-calls-unbounded-copy").len()
        };
        let with = |functions: &[&str], refs: &[&str]| {
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = refs.iter().map(|s| s.to_string()).collect();
            info
        };

        // Every set member referenced is a call: fires, at Warning.
        for sym in ["strcpy", "strcat", "sprintf", "vsprintf"] {
            let info = with(&[sym], &[sym]);
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            let lines = lines_for(&results, "binary-or-shlib-calls-unbounded-copy");
            assert_eq!(lines.len(), 1, "{sym} referenced must fire: {results:?}");
            assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        }
        // A versioned reference is a call: fires.
        assert_eq!(count(&with(&["strcpy"], &["strcpy@GLIBC_2.2.5"])), 1);
        // The definition alone (glibc's own shape) is not a call: silent.
        assert_eq!(count(&with(&["strcpy"], &[])), 0);
        // The fortified spellings are the checked form: silent.
        assert_eq!(count(&with(&["__strcpy_chk"], &["__strcpy_chk"])), 0);
        assert_eq!(count(&with(&["__sprintf_chk"], &["__sprintf_chk"])), 0);
        // Bounded siblings and the out-of-set stpcpy stay silent.
        assert_eq!(count(&with(&["strncpy"], &["strncpy"])), 0);
        // xstrcpy is a different function (an allocating wrapper that
        // sizes the destination to the input): the anchored regex
        // must not charge it for strcpy.
        assert_eq!(count(&with(&["xstrcpy"], &["xstrcpy"])), 0);
        assert_eq!(count(&with(&["snprintf"], &["snprintf"])), 0);
        assert_eq!(count(&with(&["stpcpy"], &["stpcpy"])), 0);

        // A NOTYPE dynsym import (the stripped-binary shape) lands
        // only in `undefined_functions`, with no FUNC reference at
        // all: fires, plain and versioned.
        let mut info = syn_info();
        info.undefined_functions = vec!["strcpy".to_string()];
        assert_eq!(count(&info), 1);
        let mut info = syn_info();
        info.undefined_functions = vec!["strcpy@GLIBC_2.2.5".to_string()];
        assert_eq!(count(&info), 1);

        // An archive member's reference is a call too: fires.
        let mut check = BinariesCheck::with_tool_dir(&config, None);
        check.is_archive = true;
        let pkgfile = syn_file("/usr/lib64/libfoo.a", "current ar archive");
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let info = with(&["strcat"], &["strcat"]);
        check.check_security_functions(&pkg, &pkgfile, &info, &mut out);
        let results = out.results().to_vec();
        assert_eq!(
            lines_for(&results, "binary-or-shlib-calls-unbounded-copy").len(),
            1,
            "archive reference must fire: {results:?}"
        );
    }

    #[test]

    fn shell_call_gate_levels() {
        // #972 (defect-patterns): undefined references to system()/
        // popen() fire only behind the privilege/exposure gates -
        // the same gates as the gethostbyname finder - and only at
        // Warning: binary facts cannot tell a fixed-string call
        // from one whose command is built from untrusted data, so
        // the gated population is a shell-reachable surface to
        // audit, not a proven defect (the corpus classification is
        // recorded in the divergences ledger).
        fn run(pkg: &Pkg, pkgfile: &PkgFile, functions: &[&str]) -> Vec<String> {
            let config = test_config();
            let check = BinariesCheck::with_tool_dir(&config, None);
            let mut info = syn_info();
            info.functions = functions.iter().map(|s| s.to_string()).collect();
            info.undefined_function_refs = info.functions.clone();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(pkg, pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "binary-or-shlib-calls-shell")
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        // A file that only defines the entry points (no undefined
        // reference) never fires the call form.
        fn run_definition_only(pkg: &Pkg, pkgfile: &PkgFile) -> Vec<String> {
            let config = test_config();
            let check = BinariesCheck::with_tool_dir(&config, None);
            let mut info = syn_info();
            info.functions = vec!["system".to_string(), "popen".to_string()];
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(pkg, pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "binary-or-shlib-calls-shell")
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        let plain = syn_file("/usr/bin/foo", "ELF 64-bit LSB executable");
        let bare_pkg = synthetic_pkg("testpkg", "x86_64", vec![]);

        // Setuid firing file -> Warning.
        let mut suid = plain.clone();
        suid.mode = 0o104755;
        let lines = run(&bare_pkg, &suid, &["system"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Setgid firing file -> Warning.
        let mut sgid = plain.clone();
        sgid.mode = 0o102755;
        let lines = run(&bare_pkg, &sgid, &["popen"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Capability-carrying firing file -> Warning.
        let mut caps = plain.clone();
        caps.filecaps = Some("cap_net_raw+ep".to_string());
        let lines = run(&bare_pkg, &caps, &["system"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Package shipping a systemd service unit -> Warning; the
        // versioned reference form fires through the same gate.
        let svc_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/lib/systemd/system/foo.service",
                "ASCII text",
            )],
        );
        let lines = run(&svc_pkg, &plain, &["popen"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        let lines = run(&svc_pkg, &plain, &["system@GLIBC_2.2.5"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Package shipping a systemd socket unit -> Warning.
        let sock_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/lib/systemd/system/foo.socket", "ASCII text")],
        );
        let lines = run(&sock_pkg, &plain, &["system"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);

        // Near miss: the bare pattern in an ungated package (a
        // desktop application shelling out) does not fire at all.
        let lines = run(&bare_pkg, &plain, &["system"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");
        let lines = run(&bare_pkg, &plain, &["popen"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");

        // Near miss: a timer unit is not daemon surface.
        let timer_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file("/usr/lib/systemd/system/foo.timer", "ASCII text")],
        );
        let lines = run(&timer_pkg, &plain, &["system"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");

        // Near miss: a D-Bus activation file is not a systemd unit.
        let dbus_pkg = synthetic_pkg(
            "testpkg",
            "x86_64",
            vec![syn_file(
                "/usr/share/dbus-1/services/org.example.Foo.service",
                "ASCII text",
            )],
        );
        let lines = run(&dbus_pkg, &plain, &["popen"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");

        // Near miss: privilege on a *different* file of the package
        // does not gate this file's reference.
        let mut other = syn_file("/usr/bin/helper", "ELF 64-bit LSB executable");
        other.mode = 0o104755;
        let mixed_pkg = synthetic_pkg("testpkg", "x86_64", vec![other]);
        let lines = run(&mixed_pkg, &plain, &["system"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");

        // Near miss: a definition-only file does not fire the call
        // form, in a daemon package or with privilege of its own.
        let lines = run_definition_only(&svc_pkg, &plain);
        assert!(lines.is_empty(), "no finding: {lines:?}");
        let lines = run_definition_only(&bare_pkg, &suid);
        assert!(lines.is_empty(), "no finding: {lines:?}");

        // Near miss: symbols that merely contain the entry-point
        // names do not match - the reference must be to system()/
        // popen() themselves.
        let lines = run(&svc_pkg, &plain, &["asystem", "systemd_foo", "popen2"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");

        // A NOTYPE dynsym import (the stripped-binary shape) lands
        // only in `undefined_functions`, with no FUNC reference at
        // all: fires behind the gate, plain and versioned, and
        // stays silent ungated.
        fn run_notype(pkg: &Pkg, pkgfile: &PkgFile, symbols: &[&str]) -> Vec<String> {
            let config = test_config();
            let check = BinariesCheck::with_tool_dir(&config, None);
            let mut info = syn_info();
            info.undefined_functions = symbols.iter().map(|s| s.to_string()).collect();
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_security_functions(pkg, pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "binary-or-shlib-calls-shell")
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        let lines = run_notype(&svc_pkg, &plain, &["system"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        assert!(lines[0].contains(" W: "), "Warning level: {}", lines[0]);
        let lines = run_notype(&svc_pkg, &plain, &["popen@GLIBC_2.2.5"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        let lines = run_notype(&bare_pkg, &suid, &["system"]);
        assert_eq!(lines.len(), 1, "one finding: {lines:?}");
        let lines = run_notype(&bare_pkg, &plain, &["system"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");

        // Quiet shape: a privileged file in a daemon package that
        // references none of the entry points emits nothing.
        let mut suid_svc = plain.clone();
        suid_svc.mode = 0o104755;
        let lines = run(&svc_pkg, &suid_svc, &["getaddrinfo"]);
        assert!(lines.is_empty(), "no finding: {lines:?}");
    }

    #[test]
    fn forbidden_function_crypto_policy() {
        // Reference warn-on-functions.toml: the finding fires on a bare
        // SSL_CTX_set_cipher_list call, and is waived when the strings
        // output shows the PROFILE=SYSTEM good_param. The evaluation is
        // pinned on collected strings rather than a live `strings` run:
        // this test flaked repeatedly in CI (#548, #736) when a
        // transient fork/exec failure under parallel load flipped the
        // tool probe or the parse spawn behind it. The end-to-end path
        // over the real tool stays pinned by the fixture tests
        // (forbidden_function_fires_for_dynsym_import,
        // forbidden_function_waived_by_good_param).
        let config = config_with(
            "[WarnOnFunction.crypto-policy-non-compliance-openssl]\n\
             f_name = \"SSL_CTX_set_cipher_list\"\n\
             good_param = \"PROFILE=SYSTEM\"\n",
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/openssl-app", "ELF 64-bit LSB executable");
        let mut info = syn_info();
        info.functions = vec!["SSL_CTX_set_cipher_list".to_string()];
        let calls = forbidden_function_calls(&info, &config);
        assert_eq!(calls.len(), 1, "one forbidden call collected");
        assert_eq!(calls[0].0, "crypto-policy-non-compliance-openssl");
        assert_eq!(calls[0].1, "SSL_CTX_set_cipher_list");
        assert!(calls[0].2.is_some(), "good_param pattern compiled");

        let strings = |lines: &[&str]| StringsInfo {
            strings: lines.iter().map(ToString::to_string).collect(),
            failed: None,
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        report_forbidden_functions(
            &pkg,
            &pkgfile,
            &calls,
            &strings(&["symbol-table-dump"]),
            &mut out,
        );
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
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        report_forbidden_functions(
            &pkg,
            &pkgfile,
            &calls,
            &strings(&["PROFILE=SYSTEM"]),
            &mut out,
        );
        assert!(
            out.results().is_empty(),
            "waived call must be quiet: {:?}",
            out.results()
        );
    }

    #[test]
    fn forbidden_function_strings_failure_is_reported() {
        // A failed `strings` run over a file with a forbidden call
        // reports strings-failed instead of the per-function findings:
        // the waiver scan has no output to consult.
        let config = config_with(
            "[WarnOnFunction.crypto-policy-non-compliance-openssl]\n\
             f_name = \"SSL_CTX_set_cipher_list\"\n\
             good_param = \"PROFILE=SYSTEM\"\n",
        );
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/openssl-app", "ELF 64-bit LSB executable");
        let mut info = syn_info();
        info.functions = vec!["SSL_CTX_set_cipher_list".to_string()];
        let calls = forbidden_function_calls(&info, &config);
        let failed = StringsInfo {
            strings: Vec::new(),
            failed: Some("exit status: 1".to_string()),
        };
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        report_forbidden_functions(&pkg, &pkgfile, &calls, &failed, &mut out);
        let results = out.results().to_vec();
        let lines = lines_for(&results, "strings-failed");
        assert_eq!(lines.len(), 1, "exactly one failure line: {results:?}");
        assert!(lines[0].contains(" E: "), "Error level: {}", lines[0]);
        assert!(
            lines[0].contains("exit status: 1"),
            "detail carries the reason: {}",
            lines[0]
        );
        assert_lacks(&results, "crypto-policy-non-compliance-openssl");
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
                    run_batch(&mut check, &pkg, &config, &mut out);
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
        run_batch(&mut check, &pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_lacks(&results, "executable-in-library-package");
        assert_lacks(&results, "non-versioned-file-in-library-package");
    }

    /// Fabricate `.go.buildinfo` section bytes in the inline-strings
    /// format (Go 1.18 and later) recording `version` as the
    /// toolchain, with a minimal module-info string behind it.
    fn go_buildinfo_inline(version: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xff Go buildinf:");
        bytes.push(8); // pointer size
        bytes.push(2); // flags: inline strings
        bytes.extend_from_slice(&[0u8; 16]); // rest of the 32-byte header
        let push_string = |bytes: &mut Vec<u8>, text: &str| {
            assert!(text.len() < 128, "fixture strings use a one-byte uvarint");
            bytes.push(text.len() as u8);
            bytes.extend_from_slice(text.as_bytes());
        };
        push_string(&mut bytes, version);
        push_string(
            &mut bytes,
            "path\texample.invalid/tool\nbuild\t-buildmode=exe\n",
        );
        bytes
    }

    /// A minimal ELF64 (little-endian) with one identity PT_LOAD
    /// (vaddr == file offset) and a legacy-format `.go.buildinfo`
    /// section: the 32-byte header's first pointer addresses the
    /// version string's (data pointer, length) header, which sits
    /// behind the version bytes outside the section.
    fn go_buildinfo_legacy_elf(version: &str) -> Vec<u8> {
        let shstrtab: &[u8] = b"\0.go.buildinfo\0.shstrtab\0";
        let buildinfo_off = 120u64; // ELF header (64) + program header (56)
        let version_off = buildinfo_off + 32;
        let strhdr_off = version_off + version.len() as u64;
        let shstrtab_off = strhdr_off + 16;
        let mut shoff = shstrtab_off + shstrtab.len() as u64;
        while !shoff.is_multiple_of(8) {
            shoff += 1;
        }
        let total = shoff + 3 * 64;

        let mut buf = vec![0u8; 64]; // ELF header placeholder, patched in below
        let mut ph = vec![0u8; 56];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        ph[4..8].copy_from_slice(&5u32.to_le_bytes()); // R+X
        ph[32..40].copy_from_slice(&total.to_le_bytes()); // filesz
        ph[40..48].copy_from_slice(&total.to_le_bytes()); // memsz
        ph[48..56].copy_from_slice(&0x1000u64.to_le_bytes()); // align
        buf.extend(ph);

        let mut section = Vec::new();
        section.extend_from_slice(b"\xff Go buildinf:");
        section.push(8); // pointer size
        section.push(0); // flags: pointer strings
        section.extend_from_slice(&strhdr_off.to_le_bytes());
        section.extend_from_slice(&0u64.to_le_bytes()); // module info: null
        assert_eq!(section.len(), 32);
        buf.extend(section);
        buf.extend_from_slice(version.as_bytes());
        buf.extend_from_slice(&version_off.to_le_bytes());
        buf.extend_from_slice(&(version.len() as u64).to_le_bytes());
        buf.extend_from_slice(shstrtab);
        while !buf.len().is_multiple_of(8) {
            buf.push(0);
        }
        assert_eq!(buf.len() as u64, shoff);

        let shdr = |name: u32, ty: u32, off: u64, size: u64| -> Vec<u8> {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&ty.to_le_bytes());
            h[24..32].copy_from_slice(&off.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            h[48..56].copy_from_slice(&1u64.to_le_bytes());
            h
        };
        buf.extend(vec![0u8; 64]); // NULL section
        buf.extend(shdr(1, 1, buildinfo_off, 32)); // .go.buildinfo, SHT_PROGBITS
        buf.extend(shdr(15, 3, shstrtab_off, shstrtab.len() as u64)); // .shstrtab

        let mut ehdr = vec![0u8; 64];
        ehdr[0..4].copy_from_slice(b"\x7fELF");
        ehdr[4] = 2; // ELFCLASS64
        ehdr[5] = 1; // ELFDATA2LSB
        ehdr[6] = 1; // EV_CURRENT
        ehdr[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        ehdr[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        ehdr[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        ehdr[40..48].copy_from_slice(&shoff.to_le_bytes());
        ehdr[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
        ehdr[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        ehdr[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes()); // shentsize
        ehdr[60..62].copy_from_slice(&3u16.to_le_bytes()); // shnum
        ehdr[62..64].copy_from_slice(&2u16.to_le_bytes()); // shstrndx
        buf[0..64].copy_from_slice(&ehdr);
        buf
    }

    #[test]
    fn go_version_parse_accepts_releases_only() {
        let v = |major, minor, patch| {
            Some(GoVersion {
                major,
                minor,
                patch,
            })
        };
        assert_eq!(GoVersion::parse("go1.23.8"), v(1, 23, 8));
        assert_eq!(GoVersion::parse("go1.24"), v(1, 24, 0));
        assert_eq!(GoVersion::parse("go1.9.2"), v(1, 9, 2));
        // Devel, release-candidate and bootstrap strings never parse:
        // the finder stays silent for versions it cannot order
        // against the floor.
        for raw in [
            "devel go1.25-0123456789ab",
            "go1.24rc1",
            "go1.4-bootstrap-20171003",
            "(devel)",
            "go",
            "go1",
            "go1.x",
            "go1.2.3.4",
            "",
        ] {
            assert_eq!(GoVersion::parse(raw), None, "{raw:?} must not parse");
        }
    }

    #[test]
    fn go_floor_comparison() {
        let floor = [
            (
                GoVersion {
                    major: 1,
                    minor: 23,
                    patch: 0,
                },
                GoVersion {
                    major: 1,
                    minor: 23,
                    patch: 8,
                },
            ),
            (
                GoVersion {
                    major: 1,
                    minor: 24,
                    patch: 0,
                },
                GoVersion {
                    major: 1,
                    minor: 24,
                    patch: 2,
                },
            ),
        ];
        let v = |major, minor, patch| GoVersion {
            major,
            minor,
            patch,
        };
        assert!(go_toolchain_below_floor(v(1, 23, 5), &floor));
        assert!(!go_toolchain_below_floor(v(1, 23, 8), &floor));
        assert!(!go_toolchain_below_floor(v(1, 23, 12), &floor));
        assert!(go_toolchain_below_floor(v(1, 24, 1), &floor));
        assert!(!go_toolchain_below_floor(v(1, 24, 2), &floor));
        // Older than every listed line: no release there carries the
        // recorded fixes, so it fires.
        assert!(go_toolchain_below_floor(v(1, 22, 4), &floor));
        assert!(go_toolchain_below_floor(v(1, 14, 1), &floor));
        // Newer than every listed line: the table does not judge what
        // it does not know, so it stays silent.
        assert!(!go_toolchain_below_floor(v(1, 25, 0), &floor));
        assert!(!go_toolchain_below_floor(v(1, 27, 0), &floor));
        assert!(!go_toolchain_below_floor(v(2, 0, 0), &floor));
        // The comparison does not depend on the table's order.
        let reversed = [floor[1], floor[0]];
        assert!(go_toolchain_below_floor(v(1, 23, 5), &reversed));
        assert!(!go_toolchain_below_floor(v(1, 23, 8), &reversed));
        assert!(go_toolchain_below_floor(v(1, 22, 4), &reversed));
        assert!(!go_toolchain_below_floor(v(1, 25, 0), &reversed));
    }

    #[test]
    fn go_floor_table_records_the_anchor_fixes() {
        // The shipped floor is anchored on CVE-2025-22871, fixed in
        // go1.23.8 and go1.24.2: versions just below those releases
        // must read as below the floor whatever later raises the
        // recorded defect set adds.
        let floor = go_toolchain_floor();
        assert!(!floor.is_empty(), "the shipped floor has lines");
        for (line, minimum) in floor {
            assert_eq!(minimum.line(), *line, "minimum belongs to its line");
        }
        let v = |major, minor, patch| GoVersion {
            major,
            minor,
            patch,
        };
        assert!(go_toolchain_below_floor(v(1, 23, 7), floor));
        assert!(go_toolchain_below_floor(v(1, 24, 1), floor));
        assert!(go_toolchain_below_floor(v(1, 22, 0), floor));
    }

    #[test]
    fn go_floor_table_validation_rejects_a_misfiled_minimum() {
        let raw = "as_of = \"2026-10-26\"\n\n[[line]]\nrelease = \"1.24\"\nminimum = \"1.23.8\"\n";
        let result = std::panic::catch_unwind(|| parse_go_toolchain_floor(raw));
        assert!(result.is_err(), "a minimum on the wrong line is rejected");
    }

    #[test]
    fn go_toolchain_detected_from_inline_buildinfo() {
        let info = parse_crafted_sections(
            "go-inline",
            &[(".go.buildinfo", &go_buildinfo_inline("go1.23.5"))],
        );
        assert_eq!(
            info.go_toolchains,
            vec![GoVersion {
                major: 1,
                minor: 23,
                patch: 5
            }]
        );
    }

    #[test]
    fn go_toolchain_detected_from_legacy_buildinfo() {
        let info = parse_elf_bytes("go-legacy", &go_buildinfo_legacy_elf("go1.16.3"));
        assert_eq!(
            info.go_toolchains,
            vec![GoVersion {
                major: 1,
                minor: 16,
                patch: 3
            }]
        );
    }

    #[test]
    fn go_toolchain_absent_without_buildinfo() {
        let info = parse_crafted_sections("go-none", &[(".text", b"\0"), (".rodata", b"hello\0")]);
        assert!(info.go_toolchains.is_empty());
    }

    #[test]
    fn go_toolchain_devel_string_stays_silent() {
        let info = parse_crafted_sections(
            "go-devel",
            &[(
                ".go.buildinfo",
                &go_buildinfo_inline("devel go1.25-0123456789ab"),
            )],
        );
        assert!(info.go_toolchains.is_empty());
    }

    #[test]
    fn go_toolchain_garbage_buildinfo_stays_silent() {
        let info = parse_crafted_sections(
            "go-garbage",
            &[(".go.buildinfo", b"\xff Go buildinf:\x08\x02\xff\xff\xff")],
        );
        assert!(info.go_toolchains.is_empty());
    }

    #[test]
    fn go_toolchain_below_floor_fires_a_warning() {
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/tool", "ELF 64-bit LSB executable");
        let lines = |versions: Vec<GoVersion>| -> Vec<String> {
            let mut info = syn_info();
            info.go_toolchains = versions;
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_go_toolchain(&pkg, &pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "go-toolchain-outdated")
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        let v = |major, minor, patch| GoVersion {
            major,
            minor,
            patch,
        };
        let firing = lines(vec![v(1, 22, 4)]);
        assert_eq!(firing.len(), 1, "exactly one finding: {firing:?}");
        assert!(firing[0].contains(" W: "), "Warning level: {}", firing[0]);
        assert!(
            firing[0].contains("go1.22.4"),
            "the detail names the recorded version: {}",
            firing[0]
        );
        assert_eq!(lines(vec![v(1, 23, 7)]).len(), 1);
        assert_eq!(lines(vec![v(1, 24, 1)]).len(), 1);
        // The fixed releases, and toolchains newer than the table
        // knows, stay silent.
        assert_eq!(lines(vec![v(1, 23, 8)]).len(), 0);
        assert_eq!(lines(vec![v(1, 24, 2)]).len(), 0);
        assert_eq!(lines(vec![v(1, 26, 0)]).len(), 0);
        assert_eq!(lines(vec![]).len(), 0);
    }

    #[test]
    fn go_toolchain_mixed_lines_judge_each_member_on_its_own_line() {
        // Issue #1109: members {go1.23.8 (at its line's floor),
        // go1.24.1 (below the 1.24 line's floor go1.24.2)} must
        // fire. Judged by a single minimum across members the file
        // read as go1.23.8 and stayed silent, though the go1.24.1
        // member carries a vulnerable standard library.
        let config = test_config();
        let check = BinariesCheck::with_tool_dir(&config, None);
        let pkg = synthetic_pkg("testpkg", "x86_64", vec![]);
        let pkgfile = syn_file("/usr/bin/tool", "ELF 64-bit LSB executable");
        let lines = |versions: Vec<GoVersion>| -> Vec<String> {
            let mut info = syn_info();
            info.go_toolchains = versions;
            let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
            check.check_go_toolchain(&pkg, &pkgfile, &info, &mut out);
            let results = out.results().to_vec();
            lines_for(&results, "go-toolchain-outdated")
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        let v = |major, minor, patch| GoVersion {
            major,
            minor,
            patch,
        };
        let firing = lines(vec![v(1, 23, 8), v(1, 24, 1)]);
        assert_eq!(firing.len(), 1, "exactly one finding: {firing:?}");
        assert!(
            firing[0].contains("go1.24.1"),
            "the detail names the below-floor member: {}",
            firing[0]
        );
        // Member order does not change the verdict.
        assert_eq!(lines(vec![v(1, 24, 1), v(1, 23, 8)]).len(), 1);
        // Every member at its own line's floor stays silent.
        assert_eq!(lines(vec![v(1, 23, 8), v(1, 24, 2)]).len(), 0);
    }

    #[test]
    fn go_toolchains_accumulate_across_members() {
        let mut info = parse_crafted_sections(
            "go-members-fixed",
            &[(".go.buildinfo", &go_buildinfo_inline("go1.23.8"))],
        );
        assert_eq!(info.go_toolchains.len(), 1);
        let bytes = craft_elf_sections(&[(".go.buildinfo", &go_buildinfo_inline("go1.24.1"))]);
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        info.fill_from_elf(&elf, &bytes);
        let v = |major, minor, patch| GoVersion {
            major,
            minor,
            patch,
        };
        assert_eq!(info.go_toolchains, vec![v(1, 23, 8), v(1, 24, 1)]);
        // A further member built by an already-recorded toolchain
        // adds nothing.
        info.fill_from_elf(&elf, &bytes);
        assert_eq!(info.go_toolchains.len(), 2);
    }
}
