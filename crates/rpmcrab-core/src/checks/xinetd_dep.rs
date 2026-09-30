//! `XinetdDepCheck` — requiring xinetd is obsolete.
//!
//! Ported from `rpmlint/checks/XinetdDepCheck.py`. One finding:
//! `obsolete-xinetd-requirement`.

use crate::check::{Check, add_info};
use crate::config::Config;
use crate::filter::Filter;
use crate::level::Level;
use crate::pkg::Pkg;

pub struct XinetdDepCheck;

impl XinetdDepCheck {
    pub fn new(_config: &Config) -> Self {
        Self
    }

    /// True when any requirement name is exactly `xinetd`.
    fn requires_xinetd<'a>(mut reqs: impl Iterator<Item = &'a str>) -> bool {
        reqs.any(|name| name == "xinetd")
    }
}

impl Check for XinetdDepCheck {
    fn name(&self) -> &'static str {
        "XinetdDepCheck"
    }

    fn check_binary(&mut self, pkg: &Pkg, _config: &Config, out: &mut Filter) {
        let reqs = pkg
            .requires
            .iter()
            .chain(pkg.prereq.iter())
            .map(|d| d.name.as_str());
        if Self::requires_xinetd(reqs) {
            add_info(out, Level::Error, pkg, "obsolete-xinetd-requirement", &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xinetd_require_is_flagged() {
        assert!(XinetdDepCheck::requires_xinetd(
            ["xinetd", "other"].into_iter()
        ));
    }

    #[test]
    fn xinetd_prereq_is_flagged() {
        assert!(XinetdDepCheck::requires_xinetd(
            ["other", "xinetd"].into_iter()
        ));
    }

    #[test]
    fn no_xinetd_is_quiet() {
        assert!(!XinetdDepCheck::requires_xinetd(
            ["systemd", "other"].into_iter()
        ));
    }

    #[test]
    fn xinetd_prefix_is_not_enough() {
        // The reference compares the bare name for equality.
        assert!(!XinetdDepCheck::requires_xinetd(["xinetd-foo"].into_iter()));
    }
}
