//! `KMPPolicyCheck` — kernel module package (KMP) policy.
//!
//! Ported from `rpmlint/checks/KMPPolicyCheck.py`. Findings:
//! `kmp-missing-requires`, `kmp-excessive-enhances`, `kmp-missing-enhances`,
//! `kmp-excessive-supplements`, `kmp-missing-supplements`.

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
            re_kmp_pkg: Regex::new(r"(?P<name>\S+)-kmp-(?P<kernel>\S+)").expect("static regex"),
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
}
