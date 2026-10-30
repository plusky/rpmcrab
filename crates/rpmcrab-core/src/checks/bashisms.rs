//! `BashismsCheck` — bash-specific constructs in `/bin/sh` scripts.
//!
//! Ported from `rpmlint/checks/BashismsCheck.py`. Two findings:
//! `bin-sh-syntax-error` and `potential-bashisms`.
//!
//! The reference shells out to `dash -n` and `checkbashisms`; this port runs
//! `dash -n` when dash exists and skips the file (debug-logged) when it does
//! not, rather than crashing at init like the reference. `checkbashisms` is
//! optional: without it only `potential-bashisms` is suppressed.
//! Files the tools never run on: polyglot wrappers, whose shell prologue
//! hands execution to another interpreter (so the `dash -n` failure is the
//! other language's code), and generator-template files (`.skel`, `.ww`,
//! `.in`), which are rendered before anything executes them.

use std::path::Path;
use std::sync::OnceLock;

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;
use crate::tools::{Tool, ToolSource, test_source};

pub struct BashismsCheck {
    dash: Tool,
    checkbashisms: Tool,
    use_early_fail: bool,
    checked_files: usize,
}

impl BashismsCheck {
    pub fn new(_config: &Config) -> Self {
        Self::with_tool_source(ToolSource::Path)
    }

    /// Probe for `dash` and `checkbashisms` under `source`. The reference
    /// crashes when `checkbashisms` is absent; we degrade gracefully instead:
    /// without dash the check is a no-op, without checkbashisms only
    /// `potential-bashisms` is suppressed.
    pub fn with_tool_source(source: ToolSource) -> Self {
        let (dash, _) = Tool::probe(&source, "dash", &["--version"]);
        let (checkbashisms, help) = Tool::probe(&source, "checkbashisms", &["--help"]);
        // The `--early-fail` option speeds the check up; detect it from the
        // probe output instead of spawning twice.
        let use_early_fail = help
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).into_owned()
                    + &String::from_utf8_lossy(&o.stderr)
            })
            .map(|text| text.contains("[-e]"))
            .unwrap_or(false);
        Self {
            dash,
            checkbashisms,
            use_early_fail,
            checked_files: 0,
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves both tools under `dir`, so tests can drive the whole check
    /// against fake tools without mutating the process environment.
    pub fn with_tool_dir(bin_dir: Option<&Path>) -> Self {
        Self::with_tool_source(test_source(bin_dir))
    }

    /// `(have_dash, use_early_fail)`, kept for the probe tests.
    pub fn detect_tools(bin_dir: Option<&Path>) -> (bool, bool) {
        let check = Self::with_tool_dir(bin_dir);
        (check.have_dash(), check.use_early_fail)
    }

    /// `bin-sh-syntax-error` needs only `dash -n`; `checkbashisms` is optional.
    fn have_dash(&self) -> bool {
        self.dash.is_present()
    }

    /// The findings for one script file, with their levels:
    /// `bin-sh-syntax-error` and/or `potential-bashisms`.
    ///
    /// Pure classification of the two tools' exit codes, split out so tests
    /// can drive it without subprocesses.
    fn classify_bashisms(
        dash_code: Option<i32>,
        bashisms_code: Option<i32>,
    ) -> Vec<(Level, &'static str)> {
        let mut out = Vec::new();
        match dash_code {
            Some(2) => out.push((Level::Warning, "bin-sh-syntax-error")),
            // 127 or spawn failure: dash itself is missing, nothing to report.
            Some(127) | None => return out,
            _ => {}
        }
        if bashisms_code == Some(1) {
            // Deliberate divergence (#593): info, not a warning.
            out.push((Level::Info, "potential-bashisms"));
        }
        out
    }

    /// Run the tools and classify their exit codes.
    fn check_bashisms(&self, path: &str) -> Vec<(Level, &'static str)> {
        let dash_code = self.run_dash(path);
        let bashisms_code = self.run_checkbashisms(path);
        Self::classify_bashisms(dash_code, bashisms_code)
    }

    fn run_dash(&self, path: &str) -> Option<i32> {
        let mut cmd = self.dash.command()?;
        cmd.args(["-n", path]).env("LC_ALL", "C");
        cmd.output().ok()?.status.code()
    }

    fn run_checkbashisms(&self, path: &str) -> Option<i32> {
        let mut cmd = self.checkbashisms.command()?;
        cmd.arg(path).env("LC_ALL", "C");
        if self.use_early_fail {
            cmd.arg("-e");
        }
        cmd.output().ok()?.status.code()
    }
}

/// File names that are never executed as shipped: generator inputs and
/// overlay/skeleton templates. The shipped file is rendered first, so a
/// `dash -n` failure in it is unrendered template text, not a failure in
/// any executed script.
fn is_template_script(name: &str) -> bool {
    name.ends_with(".skel") || name.ends_with(".ww") || name.ends_with(".in")
}

/// Whether the content is a polyglot program whose shell prologue hands
/// execution to another interpreter, rather than a shell script. The scan
/// covers the first fifteen code lines (blank lines and comments skipped): a
/// switch idiom there means the rest of the file is the other language's
/// code, and a `dash -n` failure in it is not a shell syntax error.
/// Limitation: the skip covers the whole file, so a genuine bashism
/// on a pre-switch prologue line is silenced too, and both findings
/// are suppressed (`bin-sh-syntax-error` and `potential-bashisms`).
fn is_polyglot_wrapper(content: &str) -> bool {
    let mut self_vars: Vec<String> = Vec::new();
    let mut code_lines = 0;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        code_lines += 1;
        if code_lines > 15 {
            break;
        }
        if let Some(var) = self_var_assignment(trimmed) {
            self_vars.push(var);
        }
        if is_switch_line(trimmed, &self_vars) {
            return true;
        }
    }
    false
}

/// A `var=$0` assignment in the prologue, for the indirection form
/// (`argv0=$0`, then `exec wish "$argv0"`).
fn self_var_assignment(line: &str) -> Option<String> {
    let (var, mut value) = line.split_once('=')?;
    if var.is_empty()
        || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || var.chars().next().is_some_and(|c| c.is_ascii_digit())
    {
        return None;
    }
    value = value.trim();
    value = value.strip_suffix('\\').unwrap_or(value).trim();
    value = value.strip_suffix(';').unwrap_or(value).trim();
    value = value.strip_prefix(['"', '\'']).unwrap_or(value);
    value = value.strip_suffix(['"', '\'']).unwrap_or(value);
    if value == "$0" {
        Some(var.to_string())
    } else {
        None
    }
}

fn exec_switch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:^'''|^|[;&|]\s*|then\s+|else\s+|eval\s+'?)exec['"]?\s+(['"]?)([^\s'"]+)"#)
            .expect("static regex")
    })
}

/// An `exec` command whose target is another interpreter and whose
/// arguments re-run the script itself: `exec wish "$0"`, `eval 'exec perl
/// -x $0'`, `//bin/true && exec stap -g $0`, `exec 'wish' "$argv0"` after
/// `argv0=$0`. A re-exec under `sh` or of the script itself is not a
/// switch.
fn exec_switch(line: &str, self_vars: &[String]) -> bool {
    let Some(caps) = exec_switch_re().captures(line).ok().flatten() else {
        return false;
    };
    let Some(target) = caps.get(2).map(|m| m.as_str()) else {
        return false;
    };
    if target == "$0" || target == "${0}" {
        return false;
    }
    if target.rsplit('/').next().is_some_and(|base| base == "sh") {
        return false;
    }
    let Some(m) = caps.get(0) else {
        return false;
    };
    let rest = &line[m.end()..];
    rest.contains("$0")
        || rest.contains("${0}")
        || self_vars
            .iter()
            .any(|v| rest.contains(&format!("${v}")) || rest.contains(&format!("${{{v}}}")))
}

fn bare_interp_switch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(wish\w*|tclsh|perl|python[\d.]*|ruby|guile[\d.-]*|stap)\b.*\$0")
            .expect("static regex")
    })
}

/// A bare invocation of a known interpreter on the script itself, with no
/// `exec` in sight: `wishwn "$0" "$@" &`.
fn bare_interp_switch(line: &str) -> bool {
    bare_interp_switch_re().is_match(line).unwrap_or(false)
}

/// A variable-held interpreter extracting the script itself: `$ruby -x
/// $0` (the `-x` flag tells the interpreter to skip ahead to its own code
/// in this file).
fn variable_x_switch(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let Some(first) = tokens.first() else {
        return false;
    };
    if !first.starts_with('$') {
        return false;
    }
    let Some(x) = tokens.iter().position(|t| *t == "-x") else {
        return false;
    };
    tokens[x + 1..].iter().any(|t| t.contains("$0"))
}

/// Whether one prologue code line hands execution to another interpreter
/// with the script itself as input.
fn is_switch_line(line: &str, self_vars: &[String]) -> bool {
    exec_switch(line, self_vars) || bare_interp_switch(line) || variable_x_switch(line)
}

impl Check for BashismsCheck {
    fn name(&self) -> &'static str {
        "BashismsCheck"
    }

    /// This check never emits errors (its findings are warnings and
    /// info), so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if !self.have_dash() {
            log::debug!("BashismsCheck: dash not found, skipping");
            return;
        }
        // Cache by md5 like the reference (kernel-source ships the same
        // script in several packages).
        let mut cache: std::collections::HashMap<String, Vec<(Level, &'static str)>> =
            std::collections::HashMap::new();
        for pkgfile in &pkg.files {
            // The reference counts every non-ghost file (files_re is `.*`) and
            // drops ghosts from the dispatch list (AbstractCheck.py:45), so a
            // ghost script is never handed to the tools.
            if pkg.ghost_files.contains(&pkgfile.name) {
                continue;
            }
            self.checked_files += 1;
            if !is_reg(pkgfile.mode) {
                continue;
            }
            if !pkgfile.magic.starts_with("POSIX shell script") {
                continue;
            }
            if is_template_script(&pkgfile.name) {
                continue;
            }
            let key = pkgfile.md5.clone().unwrap_or_else(|| pkgfile.name.clone());
            let warnings = cache.entry(key).or_insert_with(|| {
                // Lossy read: a non-UTF-8 byte anywhere must not disable
                // the wrapper scan (the switch idioms are ASCII, and ASCII
                // bytes survive lossy conversion verbatim).
                match std::fs::read(&pkgfile.path) {
                    Ok(bytes) if is_polyglot_wrapper(&String::from_utf8_lossy(&bytes)) => {
                        Vec::new()
                    }
                    _ => self.check_bashisms(&pkgfile.path),
                }
            });
            for (level, warning) in warnings.clone() {
                add_info(out, level, pkg, warning, &[&pkgfile.name]);
            }
        }
    }

    fn reset(&mut self) {
        self.checked_files = 0;
    }

    fn checked_files(&self) -> Option<usize> {
        Some(self.checked_files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::color::Color;
    use crate::pkg::pkgfile::PkgFile;

    #[cfg(unix)]
    fn fake_tool(dir: &std::path::Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake tool");
        let mut perms = std::fs::metadata(&path)
            .expect("stat fake tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod fake tool");
        // A just-written script can still be "text file busy" (ETXTBSY) on
        // first spawn under parallel load; settle it so probes below see an
        // exec-ready tool.
        for _ in 0..100 {
            match std::process::Command::new(&path).arg("--version").output() {
                Ok(_) => return,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("fake tool {} failed: {e}", path.display()),
            }
        }
        panic!("fake tool {} stayed busy", path.display());
    }

    #[test]
    #[cfg(unix)]
    fn detect_tools_finds_probed_tools() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(dir.path(), "dash", "echo 'dash 0.5.12'");
        fake_tool(
            dir.path(),
            "checkbashisms",
            "echo 'usage: checkbashisms [-e] file'",
        );
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (true, true));
    }

    #[test]
    #[cfg(unix)]
    fn detect_tools_reports_missing_checkbashisms() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(dir.path(), "dash", "echo 'dash 0.5.12'");
        // dash alone suffices for bin-sh-syntax-error; only the
        // checkbashisms-dependent early-fail probe is negative.
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (true, false));
    }

    #[test]
    #[cfg(unix)]
    fn detect_tools_reports_missing_dash() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(
            dir.path(),
            "checkbashisms",
            "echo 'usage: checkbashisms [-e] file'",
        );
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (false, true));
    }

    #[test]
    #[cfg(unix)]
    fn detect_tools_detects_early_fail_support() {
        let dir = tempfile::tempdir().expect("tmpdir");
        fake_tool(dir.path(), "dash", "echo 'dash 0.5.12'");
        fake_tool(
            dir.path(),
            "checkbashisms",
            "echo 'usage: checkbashisms file'",
        );
        assert_eq!(BashismsCheck::detect_tools(Some(dir.path())), (true, false));
    }

    #[test]
    fn syntax_error_is_reported() {
        assert_eq!(
            BashismsCheck::classify_bashisms(Some(2), Some(0)),
            vec![(Level::Warning, "bin-sh-syntax-error")]
        );
    }

    #[test]
    fn syntax_error_and_bashisms_combine() {
        assert_eq!(
            BashismsCheck::classify_bashisms(Some(2), Some(1)),
            vec![
                (Level::Warning, "bin-sh-syntax-error"),
                (Level::Info, "potential-bashisms")
            ]
        );
    }

    #[test]
    fn clean_dash_with_bashisms() {
        assert_eq!(
            BashismsCheck::classify_bashisms(Some(0), Some(1)),
            vec![(Level::Info, "potential-bashisms")]
        );
    }

    #[test]
    fn clean_run_is_quiet() {
        assert!(BashismsCheck::classify_bashisms(Some(0), Some(0)).is_empty());
    }

    #[test]
    fn missing_dash_reports_nothing() {
        // dash exit 127 (or a spawn failure): the tool is absent, and the
        // reference's FileNotFoundError path yields no findings either.
        assert!(BashismsCheck::classify_bashisms(Some(127), Some(1)).is_empty());
        assert!(BashismsCheck::classify_bashisms(None, Some(1)).is_empty());
    }

    #[test]
    fn dash_syntax_error_without_checkbashisms() {
        // checkbashisms absent (None exit code): bin-sh-syntax-error still
        // fires from `dash -n` alone.
        assert_eq!(
            BashismsCheck::classify_bashisms(Some(2), None),
            vec![(Level::Warning, "bin-sh-syntax-error")]
        );
    }

    #[test]
    fn clean_dash_without_checkbashisms() {
        assert!(BashismsCheck::classify_bashisms(Some(0), None).is_empty());
    }

    /// Dash-only emission: a fake `dash` exiting 2 with no `checkbashisms`
    /// in the tool dir emits exactly one `bin-sh-syntax-error` finding
    /// (W, naming the script) and no `potential-bashisms`.
    #[test]
    #[cfg(unix)]
    fn dash_only_emits_syntax_error() {
        let tools = tempfile::tempdir().expect("tmpdir");
        fake_tool(tools.path(), "dash", "exit 2");
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("bad.sh");
        std::fs::write(&script, "#!/bin/sh\nif then\n").expect("write script");
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "bashisms-test".to_string();
        pkg.files.clear();
        pkg.files.push(PkgFile {
            name: "/usr/bin/bad.sh".to_string(),
            path: script.to_string_lossy().into_owned(),
            mode: 0o100755,
            magic: "POSIX shell script".to_string(),
            ..Default::default()
        });
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = BashismsCheck::with_tool_dir(Some(tools.path()));
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_eq!(results.len(), 1, "one finding expected: {results:?}");
        let (name, line) = &results[0];
        assert_eq!(name, "bin-sh-syntax-error");
        assert!(line.contains("/usr/bin/bad.sh"), "detail lost: {line}");
        assert_eq!(out.result_levels(), &[Level::Warning]);
        assert!(
            results.iter().all(|(n, _)| n != "potential-bashisms"),
            "checkbashisms absent, yet potential-bashisms fired: {results:?}"
        );
    }

    #[test]
    fn wrapper_line_start_exec() {
        assert!(is_polyglot_wrapper(
            "#!/bin/sh\nexec wish \"$0\" -- \"$@\"\nset appvers {1.0}\n"
        ));
    }

    #[test]
    fn wrapper_eval_exec() {
        assert!(is_polyglot_wrapper(
            "#!/bin/sh\n#! -*-perl-*-\n# comment\neval 'exec perl -wSx \"$0\" \"$@\"'\nif 0;\n"
        ));
    }

    #[test]
    fn wrapper_midline_exec() {
        assert!(is_polyglot_wrapper(
            "#! /bin/sh\n\n//bin/true && exec stap -g $0 ${1+\"$@\"}\nprobe begin {}\n"
        ));
    }

    #[test]
    fn wrapper_argv0_indirection() {
        assert!(is_polyglot_wrapper(
            "#!/bin/sh\n# Tcl ignores the next line\nif test x; then\n  echo v;\n  exit;\nfi;\nargv0=$0;\nexec 'wish' \"$argv0\" -- \"$@\"\n"
        ));
    }

    #[test]
    fn wrapper_bare_interp() {
        assert!(is_polyglot_wrapper(
            "#!/bin/sh \n# the following line is evaluated by sh but ignored by tcl \nwishwn \"$0\" \"$@\" &\nexec true\n"
        ));
    }

    #[test]
    fn wrapper_variable_x() {
        assert!(is_polyglot_wrapper(
            "#!/bin/sh\nfor ruby in foo; do\n  $ruby -x $0 \"$@\"\ndone\n"
        ));
    }

    #[test]
    fn wrapper_past_comments_not_past_code_limit() {
        let mut content = String::from("#!/bin/sh\n");
        for _ in 0..12 {
            content.push_str("# filler comment\n");
        }
        content.push_str("SPACK_PYTHON=python3\n");
        content.push_str("exec \"${SPACK_PYTHON}\" \"$0\" \"$@\"\n");
        assert!(is_polyglot_wrapper(&content));
    }

    #[test]
    fn plain_shell_is_not_wrapper() {
        assert!(!is_polyglot_wrapper(
            "#!/bin/sh\n# comment\nTESTBINDIR=/x\nfunction run_test()\n{\necho hi\n}\n"
        ));
    }

    #[test]
    fn self_exec_is_not_wrapper() {
        assert!(!is_polyglot_wrapper("#!/bin/sh\nexec sh \"$0\" \"$@\"\n"));
        assert!(!is_polyglot_wrapper("#!/bin/sh\nexec \"$0\" \"$@\"\n"));
    }

    #[test]
    fn exec_redirect_only_is_not_wrapper() {
        assert!(!is_polyglot_wrapper(
            "#!/bin/sh\nexec < /dev/console >/dev/console 2>&1\n"
        ));
    }

    #[test]
    fn wrapper_argv0_indirection_with_continuation() {
        assert!(is_polyglot_wrapper(
            "#!/bin/sh\n# Tcl ignores the next line -*- tcl -*- \\\nif test x; then\n  echo v;\n  exit;\nfi;\nargv0=$0; \\\nexec 'wish' \"$argv0\" -- \"$@\"\n"
        ));
    }

    #[test]
    fn wrapper_past_eleven_code_lines() {
        assert!(is_polyglot_wrapper(
            "#!/bin/sh\n=begin &>/dev/null\nexport LC_ALL=\"en_US.UTF-8\"\nexport LANG=\"en_US.UTF-8\"\nruby=\"\"\nfor bundler in foo; do\n  if [ -x \"$bundler\" ]; then\n    ruby=\"$bundler\"\n    break\n  fi\ndone\nexec $ruby -x $0 \"$@\"\n"
        ));
    }

    #[test]
    fn template_suffixes() {
        assert!(is_template_script("/usr/share/doc/x/meas.sh.skel"));
        assert!(is_template_script(
            "/var/lib/warewulf/overlays/mkfs/20-mkfs.sh.ww"
        ));
        assert!(is_template_script(
            "/usr/share/hdf5_examples/testh5fc.sh.in"
        ));
        assert!(!is_template_script("/usr/bin/bad.sh"));
        assert!(!is_template_script("/usr/bin/login"));
        assert!(!is_template_script("/usr/share/pgaccess/pgaccess.tcl"));
    }

    /// A wrapper file emits nothing even when the fake `dash` exits 2.
    #[test]
    #[cfg(unix)]
    fn dash_only_skips_wrapper() {
        let tools = tempfile::tempdir().expect("tmpdir");
        fake_tool(tools.path(), "dash", "exit 2");
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("gui");
        std::fs::write(
            &script,
            "#!/bin/sh\nexec wish \"$0\" -- \"$@\"\nset appvers {1.0}\n",
        )
        .expect("write script");
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "bashisms-test".to_string();
        pkg.files.clear();
        pkg.files.push(PkgFile {
            name: "/usr/bin/gui".to_string(),
            path: script.to_string_lossy().into_owned(),
            mode: 0o100755,
            magic: "POSIX shell script".to_string(),
            ..Default::default()
        });
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = BashismsCheck::with_tool_dir(Some(tools.path()));
        check.check_binary(&pkg, &config, &mut out);
        assert!(out.results().is_empty(), "wrapper must stay silent");
    }

    /// A wrapper file with a non-UTF-8 byte elsewhere in it still emits
    /// nothing: the content read is lossy, so one bad byte cannot disable
    /// the wrapper scan the way a strict UTF-8 read would.
    #[test]
    #[cfg(unix)]
    fn dash_only_skips_non_utf8_wrapper() {
        let tools = tempfile::tempdir().expect("tmpdir");
        fake_tool(tools.path(), "dash", "exit 2");
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("gui");
        std::fs::write(
            &script,
            b"#!/bin/sh\nexec wish \"$0\" -- \"$@\"\n# \xff\nset x {1}\n",
        )
        .expect("write script");
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "bashisms-test".to_string();
        pkg.files.clear();
        pkg.files.push(PkgFile {
            name: "/usr/bin/gui".to_string(),
            path: script.to_string_lossy().into_owned(),
            mode: 0o100755,
            magic: "POSIX shell script".to_string(),
            ..Default::default()
        });
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = BashismsCheck::with_tool_dir(Some(tools.path()));
        check.check_binary(&pkg, &config, &mut out);
        assert!(out.results().is_empty(), "wrapper must stay silent");
    }

    /// A template file emits nothing even when the fake `dash` exits 2.
    #[test]
    #[cfg(unix)]
    fn dash_only_skips_template() {
        let tools = tempfile::tempdir().expect("tmpdir");
        fake_tool(tools.path(), "dash", "exit 2");
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("meas.sh.skel");
        std::fs::write(&script, "#!/bin/sh\nERL_HOME=<path to otp top dir>\n")
            .expect("write script");
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "bashisms-test".to_string();
        pkg.files.clear();
        pkg.files.push(PkgFile {
            name: "/usr/share/doc/x/meas.sh.skel".to_string(),
            path: script.to_string_lossy().into_owned(),
            mode: 0o100644,
            magic: "POSIX shell script".to_string(),
            ..Default::default()
        });
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = BashismsCheck::with_tool_dir(Some(tools.path()));
        check.check_binary(&pkg, &config, &mut out);
        assert!(out.results().is_empty(), "template must stay silent");
    }

    #[test]
    fn reset_zeroes_checked_files() {
        let config = Config::default();
        let mut check = BashismsCheck::new(&config);
        check.checked_files = 5;
        check.reset();
        assert_eq!(check.checked_files(), Some(0));
    }
}
