//! `ShellSyntaxCheck` — bash syntax validity (`bash -n`) for bash scripts.
//!
//! The rpminspect `shellsyntax` idea: a syntax validity pass over the shell
//! scripts in the package, alongside `BashismsCheck` (which flags bashisms
//! and `dash -n` failures in `/bin/sh` scripts). This check covers the
//! scripts `BashismsCheck` never sees — `#!/bin/bash` files, whose magic is
//! `Bourne-Again shell script` — by running `bash -n` on each and emitting
//! `bash-syntax-error` (W) with the first line of the error when it fails.
//!
//! Like `BashismsCheck`, the check degrades gracefully when the tool is
//! absent (a no-op, debug-logged) instead of crashing, and skips polyglot
//! wrappers (a shell prologue handing execution to another interpreter)
//! and generator-template files (`.skel`, `.ww`, `.in`), whose `bash -n`
//! failure would be the other language's code or unrendered template text.

use std::path::Path;
use std::process::Output;

use crate::check::{Check, add_info};
use crate::checks::bashisms::{is_polyglot_wrapper, is_template_script};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;
use crate::pkg::pkgfile::is_reg;
use crate::tools::{Tool, ToolSource, test_source};

pub struct ShellSyntaxCheck {
    bash: Tool,
    checked_files: usize,
}

impl ShellSyntaxCheck {
    pub fn new(_config: &Config) -> Self {
        Self::with_tool_source(ToolSource::Path)
    }

    /// Probe for `bash` under `source`. Without it the check is a no-op.
    pub fn with_tool_source(source: ToolSource) -> Self {
        let (bash, _) = Tool::probe(&source, "bash", &["--version"]);
        Self {
            bash,
            checked_files: 0,
        }
    }

    /// Test entry point: `None` probes the live `PATH`, `Some(dir)`
    /// resolves `bash` under `dir`, so tests can drive the whole check
    /// against a fake tool without mutating the process environment.
    pub fn with_tool_dir(bin_dir: Option<&Path>) -> Self {
        Self::with_tool_source(test_source(bin_dir))
    }

    fn have_bash(&self) -> bool {
        self.bash.is_present()
    }

    /// The first line of the `bash -n` error for a failed run, or `None`
    /// when the run passed, the tool is absent, or the spawn failed.
    /// Pure classification of the run's output, split out so tests can
    /// drive it without subprocesses.
    fn classify(output: Option<Output>) -> Option<String> {
        let output = output?;
        if output.status.success() {
            return None;
        }
        let first = String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string);
        Some(first.unwrap_or_else(|| "bash -n reported a syntax error".to_string()))
    }

    /// Run `bash -n` on one script; `None` when bash is absent or the
    /// spawn failed.
    fn run_bash_n(&self, path: &str) -> Option<Output> {
        let mut cmd = self.bash.command()?;
        cmd.args(["-n", path]).env("LC_ALL", "C");
        cmd.output().ok()
    }

    /// The `bash -n` error detail for one script, if any.
    fn check_script(&self, path: &str) -> Option<String> {
        Self::classify(self.run_bash_n(path))
    }
}

impl Check for ShellSyntaxCheck {
    fn name(&self) -> &'static str {
        "ShellSyntaxCheck"
    }

    /// This check never emits errors (its only finding is a warning),
    /// so `--errors-only` skips it.
    fn max_severity(&self) -> Level {
        Level::Warning
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if !self.have_bash() {
            log::debug!("ShellSyntaxCheck: bash not found, skipping");
            return;
        }
        // Cache by md5 like BashismsCheck (kernel-source ships the same
        // script in several packages).
        let mut cache: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        for pkgfile in &pkg.files {
            // The reference counts every non-ghost file (files_re is `.*`)
            // and drops ghosts from the dispatch list, so a ghost script is
            // never handed to the tools.
            if pkg.ghost_files.contains(&pkgfile.name) {
                continue;
            }
            self.checked_files += 1;
            if !is_reg(pkgfile.mode) {
                continue;
            }
            if !pkgfile.magic.starts_with("Bourne-Again shell script") {
                continue;
            }
            if is_template_script(&pkgfile.name) {
                continue;
            }
            let key = pkgfile.md5.clone().unwrap_or_else(|| pkgfile.name.clone());
            let error = cache.entry(key).or_insert_with(|| {
                // Lossy read: a non-UTF-8 byte anywhere must not disable
                // the wrapper scan (the switch idioms are ASCII, and ASCII
                // bytes survive lossy conversion verbatim).
                match std::fs::read(&pkgfile.path) {
                    Ok(bytes) if is_polyglot_wrapper(&String::from_utf8_lossy(&bytes)) => None,
                    _ => self.check_script(&pkgfile.path),
                }
            });
            if let Some(detail) = error {
                add_info(
                    out,
                    Level::Warning,
                    pkg,
                    "bash-syntax-error",
                    &[pkgfile.name.as_str(), detail.as_str()],
                );
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

    /// A fake `bash -n` that always fails the way the real one does:
    /// exit 2 with the error (naming the checked file, `$2`) on stderr.
    #[cfg(unix)]
    fn failing_bash(dir: &std::path::Path) {
        fake_tool(
            dir,
            "bash",
            "echo \"$2: line 2: syntax error near unexpected token \\`then'\" >&2\nexit 2",
        );
    }

    #[cfg(unix)]
    fn exit_status(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    }

    #[cfg(unix)]
    fn output_with(code: i32, stderr: &str) -> Output {
        Output {
            status: exit_status(code),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[test]
    #[cfg(unix)]
    fn clean_run_is_quiet() {
        assert_eq!(ShellSyntaxCheck::classify(Some(output_with(0, ""))), None);
    }

    #[test]
    #[cfg(unix)]
    fn failure_returns_first_error_line() {
        assert_eq!(
            ShellSyntaxCheck::classify(Some(output_with(
                2,
                "/usr/bin/bad.sh: line 2: syntax error near unexpected token `then'\n/usr/bin/bad.sh: line 2: `if then'\n"
            ))),
            Some("/usr/bin/bad.sh: line 2: syntax error near unexpected token `then'".to_string())
        );
    }

    #[test]
    #[cfg(unix)]
    fn failure_without_stderr_falls_back() {
        assert_eq!(
            ShellSyntaxCheck::classify(Some(output_with(2, ""))),
            Some("bash -n reported a syntax error".to_string())
        );
    }

    #[test]
    fn missing_tool_is_quiet() {
        assert_eq!(ShellSyntaxCheck::classify(None), None);
    }

    /// A package holding a single script file, built on the fixture RPM
    /// the way the `BashismsCheck` tests do.
    fn pkg_with_script(name: &str, path: &std::path::Path, magic: &str) -> Pkg {
        let mut pkg = Pkg::open(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm"),
            &std::env::temp_dir(),
            true,
        )
        .expect("open fixture pkg");
        pkg.name = "shell-syntax-test".to_string();
        pkg.files.clear();
        pkg.files.push(PkgFile {
            name: name.to_string(),
            path: path.to_string_lossy().into_owned(),
            mode: 0o100755,
            magic: magic.to_string(),
            ..Default::default()
        });
        pkg
    }

    fn run_check(tools: &std::path::Path, pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = ShellSyntaxCheck::with_tool_dir(Some(tools));
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    /// Valid script, no finding: a fake `bash` exiting 0 stays silent.
    #[test]
    #[cfg(unix)]
    fn valid_bash_script_is_quiet() {
        let tools = tempfile::tempdir().expect("tmpdir");
        fake_tool(tools.path(), "bash", "exit 0");
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("good.sh");
        std::fs::write(&script, "#!/bin/bash\necho ok\n").expect("write script");
        let pkg = pkg_with_script(
            "/usr/bin/good.sh",
            &script,
            "Bourne-Again shell script, ASCII text executable",
        );
        assert!(run_check(tools.path(), &pkg).is_empty());
    }

    /// Invalid script: one `bash-syntax-error` (W), naming the script
    /// and surfacing the `bash -n` error.
    #[test]
    #[cfg(unix)]
    fn invalid_bash_script_reports_syntax_error() {
        let tools = tempfile::tempdir().expect("tmpdir");
        failing_bash(tools.path());
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("bad.sh");
        std::fs::write(&script, "#!/bin/bash\nif then\n").expect("write script");
        let pkg = pkg_with_script(
            "/usr/bin/bad.sh",
            &script,
            "Bourne-Again shell script, ASCII text executable",
        );
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = ShellSyntaxCheck::with_tool_dir(Some(tools.path()));
        check.check_binary(&pkg, &config, &mut out);
        let results = out.results().to_vec();
        assert_eq!(results.len(), 1, "one finding expected: {results:?}");
        let (name, line) = &results[0];
        assert_eq!(name, "bash-syntax-error");
        assert!(line.contains("/usr/bin/bad.sh"), "script lost: {line}");
        assert!(line.contains("syntax error"), "bash -n error lost: {line}");
        assert_eq!(out.result_levels(), &[Level::Warning]);
    }

    /// A `/bin/sh` script stays silent even when the fake `bash` exits 2:
    /// `BashismsCheck` owns those via `dash -n`, and no script is checked
    /// twice.
    #[test]
    #[cfg(unix)]
    fn sh_scripts_are_not_checked() {
        let tools = tempfile::tempdir().expect("tmpdir");
        failing_bash(tools.path());
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("plain.sh");
        std::fs::write(&script, "#!/bin/sh\nif then\n").expect("write script");
        let pkg = pkg_with_script(
            "/usr/bin/plain.sh",
            &script,
            "POSIX shell script, ASCII text executable",
        );
        assert!(
            run_check(tools.path(), &pkg).is_empty(),
            "sh script must stay with BashismsCheck"
        );
    }

    /// Without `bash` the check is a no-op, never an error.
    #[test]
    #[cfg(unix)]
    fn missing_bash_is_quiet() {
        let tools = tempfile::tempdir().expect("tmpdir");
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("bad.sh");
        std::fs::write(&script, "#!/bin/bash\nif then\n").expect("write script");
        let pkg = pkg_with_script(
            "/usr/bin/bad.sh",
            &script,
            "Bourne-Again shell script, ASCII text executable",
        );
        assert!(run_check(tools.path(), &pkg).is_empty());
    }

    /// A wrapper file emits nothing even when the fake `bash` exits 2.
    #[test]
    #[cfg(unix)]
    fn skips_wrapper() {
        let tools = tempfile::tempdir().expect("tmpdir");
        failing_bash(tools.path());
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("gui");
        std::fs::write(
            &script,
            "#!/bin/bash\nexec wish \"$0\" -- \"$@\"\nset appvers {1.0}\n",
        )
        .expect("write script");
        let pkg = pkg_with_script(
            "/usr/bin/gui",
            &script,
            "Bourne-Again shell script, ASCII text executable",
        );
        assert!(
            run_check(tools.path(), &pkg).is_empty(),
            "wrapper must stay silent"
        );
    }

    /// A template file emits nothing even when the fake `bash` exits 2.
    #[test]
    #[cfg(unix)]
    fn skips_template() {
        let tools = tempfile::tempdir().expect("tmpdir");
        failing_bash(tools.path());
        let scripts = tempfile::tempdir().expect("tmpdir");
        let script = scripts.path().join("meas.sh.skel");
        std::fs::write(&script, "#!/bin/bash\nERL_HOME=<path to otp top dir>\n")
            .expect("write script");
        let pkg = pkg_with_script(
            "/usr/share/doc/x/meas.sh.skel",
            &script,
            "Bourne-Again shell script, ASCII text executable",
        );
        assert!(
            run_check(tools.path(), &pkg).is_empty(),
            "template must stay silent"
        );
    }

    #[test]
    fn reset_zeroes_checked_files() {
        let config = Config::default();
        let mut check = ShellSyntaxCheck::new(&config);
        check.checked_files = 5;
        check.reset();
        assert_eq!(check.checked_files(), Some(0));
    }
}
