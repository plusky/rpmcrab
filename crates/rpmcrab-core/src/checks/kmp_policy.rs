//! `KMPPolicyCheck` — kernel module package (KMP) policy.
//!
//! Ported from `rpmlint/checks/KMPPolicyCheck.py`. Findings:
//! `kmp-missing-requires`, `kmp-excessive-enhances`, `kmp-missing-enhances`,
//! `kmp-excessive-supplements`, `kmp-missing-supplements`.
//!
//! `new` takes a `Config` only to satisfy the `Check` construction signature;
//! like the reference's `__init__`, it reads no config keys.

use fancy_regex::Regex;

use crate::check::{Check, add_info};
use crate::checks::shared::python_str_list;
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct KMPPolicyCheck {
    re_kmp_pkg: Regex,
}

impl KMPPolicyCheck {
    pub fn new(_config: &Config) -> Self {
        Self {
            // `\A`-anchored: the reference uses `re.match`.
            re_kmp_pkg: Regex::new(r"\A(?P<name>\S+)-kmp-(?P<kernel>\S+)").expect("static regex"),
        }
    }

    /// The kernel flavor from a KMP package name (`kernel-default` for
    /// `foo-kmp-default`), or `None` when the name is not a KMP package.
    fn kernel_flavor(re: &Regex, pkg_name: &str) -> Option<String> {
        let caps = re.captures(pkg_name).ok().flatten()?;
        let kernel = caps.name("kernel")?.as_str();
        Some(format!("kernel-{kernel}"))
    }
}

impl Check for KMPPolicyCheck {
    fn name(&self) -> &'static str {
        "KMPPolicyCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        if pkg.is_source {
            return;
        }
        let Some(kernel_flavor) = Self::kernel_flavor(&self.re_kmp_pkg, &pkg.name) else {
            return;
        };

        // Requires must name the specific kernel flavor.
        if !pkg.requires.iter().any(|d| d.name == kernel_flavor) {
            add_info(
                out,
                Level::Error,
                pkg,
                "kmp-missing-requires",
                &[&kernel_flavor],
            );
        }

        // Enhances: exactly the one kernel flavor.
        let kernel_enhances: Vec<&str> = pkg
            .enhances
            .iter()
            .filter(|e| e.name.starts_with("kernel-"))
            .map(|e| e.name.as_str())
            .collect();
        if kernel_enhances.len() > 1 {
            add_info(
                out,
                Level::Error,
                pkg,
                "kmp-excessive-enhances",
                &[&python_str_list(&kernel_enhances)],
            );
        }
        if !kernel_enhances.contains(&kernel_flavor.as_str()) {
            add_info(
                out,
                Level::Error,
                pkg,
                "kmp-missing-enhances",
                &[&kernel_flavor],
            );
        }

        // Supplements: a modalias(...) plus the kernel flavor supplement.
        let mut have_modalias = false;
        let mut have_proper_suppl = false;
        for s in &pkg.supplements {
            if s.name.starts_with("modalias(") {
                have_modalias = true;
                continue;
            }
            if s.name.starts_with(&format!("packageand({kernel_flavor}"))
                || s.name.starts_with(&format!("({kernel_flavor} and"))
            {
                have_proper_suppl = true;
                continue;
            }
            add_info(
                out,
                Level::Warning,
                pkg,
                "kmp-excessive-supplements",
                &[&s.name],
            );
        }
        if !have_modalias && !have_proper_suppl {
            add_info(out, Level::Error, pkg, "kmp-missing-supplements", &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::color::Color;
    use crate::pkg::dep::DepInfo;

    /// `Pkg` is header-backed with no test constructor, so open a tiny fixture
    /// and rewrite the public fields the check reads.
    fn fixture_pkg() -> Pkg {
        let rpm = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/parity/pkg/inputs/fcprobe-1-1.noarch.rpm");
        Pkg::open(&rpm, &std::env::temp_dir()).expect("open fixture pkg")
    }

    fn dep(name: &str) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            flags: 0,
            epoch: None,
            version: None,
            release: None,
        }
    }

    fn run(pkg: &Pkg) -> Vec<(String, String)> {
        let config = Config::default();
        let mut out = Filter::new(&config, Color::for_tty(false)).unwrap();
        let mut check = KMPPolicyCheck::new(&config);
        check.check_binary(pkg, &config, &mut out);
        out.results().to_vec()
    }

    fn has<'a>(results: &'a [(String, String)], name: &str) -> Vec<&'a str> {
        results
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, line)| line.as_str())
            .collect()
    }

    #[test]
    fn kmp_name_yields_kernel_flavor() {
        let check = KMPPolicyCheck::new(&Config::default());
        assert_eq!(
            KMPPolicyCheck::kernel_flavor(&check.re_kmp_pkg, "nvidia-kmp-default"),
            Some("kernel-default".to_string())
        );
    }

    #[test]
    fn non_kmp_name_is_none() {
        let check = KMPPolicyCheck::new(&Config::default());
        assert!(KMPPolicyCheck::kernel_flavor(&check.re_kmp_pkg, "vim").is_none());
    }

    // Mirrors the reference's test_kmp.py::test_kmp_noreq.
    #[test]
    fn kmp_without_requires_enhances_or_supplements() {
        let mut pkg = fixture_pkg();
        pkg.name = "noreq-kmp-default".to_string();
        let results = run(&pkg);

        let missing_requires = has(&results, "kmp-missing-requires");
        assert_eq!(missing_requires.len(), 1, "{results:?}");
        assert!(missing_requires[0].contains(": E: "));
        assert!(missing_requires[0].ends_with("kernel-default"));

        let missing_enhances = has(&results, "kmp-missing-enhances");
        assert_eq!(missing_enhances.len(), 1, "{results:?}");
        assert!(missing_enhances[0].ends_with("kernel-default"));

        assert_eq!(
            has(&results, "kmp-missing-supplements").len(),
            1,
            "{results:?}"
        );
    }

    // Mirrors test_kmp.py::test_kmp_enhances. The excessive-enhances detail is
    // Python's str(list), single quotes included.
    #[test]
    fn kmp_with_excessive_enhances() {
        let mut pkg = fixture_pkg();
        pkg.name = "excess-enhances-kmp-default".to_string();
        pkg.requires = vec![dep("kernel-default")];
        pkg.enhances = vec![dep("kernel-default"), dep("kernel-vanilla")];
        let results = run(&pkg);

        assert!(
            has(&results, "kmp-missing-requires").is_empty(),
            "{results:?}"
        );
        assert!(
            has(&results, "kmp-missing-enhances").is_empty(),
            "{results:?}"
        );

        let excessive = has(&results, "kmp-excessive-enhances");
        assert_eq!(excessive.len(), 1, "{results:?}");
        assert!(excessive[0].contains(": E: "), "level: {}", excessive[0]);
        assert!(
            excessive[0].contains("['kernel-default', 'kernel-vanilla']"),
            "detail: {}",
            excessive[0]
        );

        assert_eq!(
            has(&results, "kmp-missing-supplements").len(),
            1,
            "{results:?}"
        );
    }

    // Mirrors test_kmp.py::test_kmp_supplements.
    #[test]
    fn kmp_with_proper_supplement_is_quiet() {
        let mut pkg = fixture_pkg();
        pkg.name = "supplements-kmp-default".to_string();
        pkg.requires = vec![dep("kernel-default")];
        pkg.enhances = vec![dep("kernel-default")];
        pkg.supplements = vec![dep("(kernel-default and foo)")];
        let results = run(&pkg);
        assert!(results.is_empty(), "{results:?}");
    }
}
