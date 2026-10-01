//! The TOML configuration loader and merger, byte-faithful to rpmlint's
//! `config.py` (`docs/DESIGN.md` §4.7, §4.8).
//!
//! The merged configuration is kept as a generic table because checks read
//! arbitrary keys (`ValidLicenses`, `ValidGroups`, …). The hot-path fields the
//! filter engine and renderer need are derived from it by [`Config::finalize`]
//! after every load step.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use fancy_regex::Regex;

/// The bundled base config (rpmlint's `configdefaults.toml`, same GPL-2.0
/// licence). It is always the lowest-precedence config (sort key 0). Recorded
/// in `conf_files` as `<builtin>`: rpmlint prints its real installed path, but
/// rpmcrab embeds the base. **Deliberate divergence** — at packaging time the
/// base becomes a real file (OBS) and this becomes its path; the placeholder is
/// an M1 convenience. The parity corpus sanitizes the config paths anyway.
const CONFIG_DEFAULTS: &str = include_str!("../data/configdefaults.toml");

/// Parsed rpmlint configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The full merged configuration table (arbitrary keys, for checks).
    pub configuration: toml::Table,
    /// The config files that were loaded, in final (sorted) load order. The
    /// bundled base is recorded as the literal `<builtin>`.
    pub conf_files: Vec<String>,
    /// rpmlintrc filter patterns (only these are audited for unused filters).
    pub rpmlintrc_filters: Vec<String>,
    /// The rpmlintrc files loaded (for the header's `rpmlintrc:` block).
    pub rpmlintrc_display: Vec<String>,
    /// `-s/--strict`.
    pub strict: bool,
    /// `-v/--verbose`/`--info`.
    pub info: bool,
    /// `-P/--permissive`. On openSUSE forced on unless `--strict`.
    pub permissive: bool,
    /// `-m/--mini-mode` (SUSE-only). Disables `TagsCheck` spellchecking and
    /// makes `SpecCheck` skip `_check_specfile_error`/`_check_invalid_url`
    /// (`docs/DESIGN.md` §4.10). Threaded through for the M3 checks.
    pub mini_mode: bool,

    // Derived from `configuration` by `finalize` (do not set by hand after load).
    /// `Checks`.
    pub checks: Vec<String>,
    /// `[Scoring]` — check name → raw badness value. Kept raw (not coerced to
    /// an integer) because Python coerces per finding at emit time
    /// (`filter.py` `int()`), so negatives/floats/bools/garbage behave
    /// per-finding. Coerced in `filter.rs`.
    pub scoring: HashMap<String, toml::Value>,
    /// `Filters`.
    pub filters: Vec<String>,
    /// `FilterErrorTitles`.
    pub filter_titles: Vec<String>,
    /// `BlockedFilters`.
    pub blocked_filters: Vec<String>,
    /// `BadnessThreshold` (default -1).
    pub badness_threshold: i64,
    /// Distribution flavor for flavor-gated check behavior (`docs/DESIGN.md`
    /// §4.11, `docs/flavor-implementation.md`): `"opensuse"` (default) or
    /// `"slfo"`. Derived from the `Flavor` TOML key by [`Config::finalize`];
    /// unknown values warn on stderr and fall back to `"opensuse"`.
    pub flavor: String,
}

impl Config {
    /// Derive the typed hot-path fields from `configuration`. Called after
    /// every load step (initial merge, rpmlintrc).
    pub fn finalize(&mut self) {
        self.checks = self.get_strings("Checks");
        self.filters = self.get_strings("Filters");
        self.filter_titles = self.get_strings("FilterErrorTitles");
        self.blocked_filters = self.get_strings("BlockedFilters");
        self.badness_threshold = self
            .configuration
            .get("BadnessThreshold")
            .and_then(toml::Value::as_integer)
            .unwrap_or(-1);
        self.scoring = self
            .configuration
            .get("Scoring")
            .and_then(toml::Value::as_table)
            .map(|t| t.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let flavor = self
            .configuration
            .get("Flavor")
            .and_then(toml::Value::as_str)
            .unwrap_or("opensuse")
            .to_ascii_lowercase();
        // Fail closed on config the code does not understand: warn and fall
        // back to the default flavor rather than guessing.
        self.flavor = match flavor.as_str() {
            "opensuse" | "slfo" => flavor,
            other => {
                eprintln!("warning: unknown Flavor {other:?}, falling back to \"opensuse\"");
                "opensuse".to_string()
            }
        };
    }

    /// True when the `slfo` flavor is selected (`docs/flavor-implementation.md`).
    pub fn is_slfo(&self) -> bool {
        self.flavor == "slfo"
    }

    /// Whether a `[[divergence]]` ledger entry applies under this config's
    /// flavor. An entry without a `flavor` key applies to every flavor; a
    /// `flavor = "slfo"` entry only excuses a difference on an slfo run. Under
    /// opensuse such an entry neither fails the comparison nor goes invisible:
    /// it simply does not apply (`docs/flavor-implementation.md`).
    pub fn divergence_applies(&self, entry_flavor: Option<&str>) -> bool {
        entry_flavor.is_none_or(|f| f == self.flavor)
    }

    /// `ExtractDir` — where payloads are unpacked. `""` (the default) means the
    /// system temp dir, resolved as rpmlint does in `lint.py`.
    pub fn extract_dir(&self) -> PathBuf {
        let d = self
            .configuration
            .get("ExtractDir")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        if d.is_empty() {
            std::env::temp_dir()
        } else {
            PathBuf::from(d)
        }
    }

    /// Read a top-level key as a list of strings (empty if absent/not a list).
    fn get_strings(&self, key: &str) -> Vec<String> {
        self.configuration
            .get(key)
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// rpmlint's `_sort_config_files` key: bundled defaults → 0, normal → 1,
/// `*.override.*` → 2. The override test is on the file NAME
/// (`'.override.' in config_file.name`), not the full path, so a parent
/// directory containing `.override.` does not misclassify the file.
fn sort_key(is_defaults: bool, name: &str) -> u8 {
    if is_defaults {
        0
    } else {
        let file_name = Path::new(name)
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        if file_name.contains(".override.") {
            2
        } else {
            1
        }
    }
}

/// rpmlint's `_merge_dictionaries`: recursive; lists union-append+dedup for
/// normal configs but are replaced wholesale for `*.override.*`; scalars are
/// overwritten by the later file.
fn merge_into(dest: &mut toml::Table, source: &toml::Table, override_: bool) {
    for (k, v) in source {
        match (dest.get_mut(k), v) {
            (Some(toml::Value::Table(d)), toml::Value::Table(s)) => merge_into(d, s, override_),
            // The reference gates the append on the destination being a list, not
            // on the incoming value's type, and then iterates whatever arrived.
            // An empty table therefore leaves the destination list intact —
            // `device-files-whitelist.toml` is followed by an empty
            // `[DeviceFilesWhitelist]` in opensuse.toml, and treating that as a
            // replace emptied the whitelist.
            (Some(toml::Value::Array(d)), v) if !override_ => {
                let items: Vec<toml::Value> = match v {
                    toml::Value::Array(a) => a.clone(),
                    toml::Value::Table(t) => t
                        .keys()
                        .map(|s| toml::Value::String(s.to_string()))
                        .collect(),
                    // `for item in "xyz"` walks the characters; the reference does not raise.
                    toml::Value::String(s) => s
                        .chars()
                        .map(|c| toml::Value::String(c.to_string()))
                        .collect(),
                    other => panic!(
                        "config: array key '{k}' is merged with a {other:?}, which the \
                         reference cannot iterate either (TypeError)"
                    ),
                };
                for item in items {
                    if !d.contains(&item) {
                        d.push(item);
                    }
                }
            }
            _ => {
                dest.insert(k.clone(), v.clone());
            }
        }
    }
}

/// The XDG config directories, as pyxdg builds them: `XDG_CONFIG_HOME` (or
/// `~/.config`) followed by each entry of `XDG_CONFIG_DIRS` (or `/etc/xdg`).
fn xdg_config_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(h) = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .map(|h| PathBuf::from(h).join(".config"))
        })
    {
        dirs.push(h);
    }
    let sys = std::env::var("XDG_CONFIG_DIRS").unwrap_or_else(|_| "/etc/xdg".to_string());
    for d in sys.split(':') {
        let p = PathBuf::from(d);
        if !d.is_empty() && !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    dirs
}

/// `.toml` files in a dir, sorted. `glob_star`: the XDG auto-load glob is
/// `*toml` (matches any name ending in `toml`, no dot required); a `-c`
/// directory uses `*.toml`.
/// `.toml` files in a dir. `star_glob`: the XDG auto-load glob is `*toml`
/// (any name ending in `toml`) and is SORTED (`config.py:87`); a `-c` directory
/// uses `*.toml` and is left in FILESYSTEM order (`_validate_conf_location`
/// uses unsorted `path.glob`), which the stable merge sort then preserves
/// within a key.
///
/// The `is_file()` filter is a **deliberate divergence**: Python's glob matches
/// a directory named `*.toml` and then crashes opening it; skipping
/// non-regular files is strictly more robust for a build gate.
fn glob_toml(dir: &Path, star_glob: bool, sort: bool) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = dir
        .read_dir()
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && if star_glob {
                            p.file_name()
                                .is_some_and(|n| n.to_string_lossy().ends_with("toml"))
                        } else {
                            p.extension().is_some_and(|e| e == "toml")
                        }
                })
                .collect()
        })
        .unwrap_or_default();
    if sort {
        found.sort();
    }
    found
}

/// Build the ordered config-file list (`find_configs`), merge them
/// (`load_config`), and return the resulting [`Config`].
///
/// `extra` is the `-c/--config` set (each a file or a directory of `*.toml`).
/// Autoloading of XDG dirs is skipped when `CONFIG_DISABLE_AUTOLOADING` or
/// `PYTEST_XDIST_TESTRUNUID` is set. An unparsable TOML file exits 4, as
/// rpmlint does.
pub fn load(extra: &[PathBuf]) -> Config {
    let autoload = std::env::var("PYTEST_XDIST_TESTRUNUID").is_err()
        && std::env::var("CONFIG_DISABLE_AUTOLOADING").is_err();
    load_inner(extra, &xdg_config_dirs(), autoload)
}

/// The env-independent core of [`load`], so tests can drive it without
/// process-global environment races.
fn load_inner(extra: &[PathBuf], xdg_dirs: &[PathBuf], autoload: bool) -> Config {
    // (is_defaults, display_path, Option<read path>); None read path = builtin.
    let mut entries: Vec<(bool, String, Option<PathBuf>)> =
        vec![(true, "<builtin>".to_string(), None)];

    if autoload {
        // reversed(xdg_config_dirs): least-preferred first.
        for dir in xdg_dirs.iter().rev() {
            let confdir = dir.join("rpmlint");
            if confdir.is_dir() {
                for p in glob_toml(&confdir, true, true) {
                    entries.push((false, p.display().to_string(), Some(p)));
                }
            }
        }
    }

    // -c/--config: file, or directory -> *.toml in filesystem order (unsorted).
    for path in extra {
        if path.is_dir() {
            for p in glob_toml(path, false, false) {
                entries.push((false, p.display().to_string(), Some(p)));
            }
        } else if path.exists() {
            entries.push((false, path.display().to_string(), Some(path.clone())));
        }
    }

    // load_config: stable sort by (defaults<normal<override), preserving
    // insertion order within a key.
    type Entry = (bool, String, Option<PathBuf>);
    let mut indexed: Vec<(usize, &Entry)> = entries.iter().enumerate().collect();
    indexed.sort_by_key(|(i, (is_def, name, _))| (sort_key(*is_def, name), *i));

    let mut cfg = Config::default();
    for (_, (is_def, display, path)) in indexed {
        let text = match path {
            None => CONFIG_DEFAULTS.to_string(),
            Some(p) => match std::fs::read_to_string(p) {
                Ok(t) => t,
                // Python's `open(cf, 'rb')` raises on an unreadable file
                // (traceback, exit 1); a build gate must not fail open.
                Err(e) => {
                    eprintln!(
                        "(none): E: fatal error while reading configuration file {display}: {e}"
                    );
                    std::process::exit(1);
                }
            },
        };
        let parsed: toml::Table = match toml::from_str(&text) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("(none): E: fatal error while parsing configuration file {display}: {e}");
                std::process::exit(4);
            }
        };
        // _is_override_config checks the file NAME, not the full path.
        let file_name = Path::new(display)
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        let is_override = !*is_def && file_name.contains(".override.");
        merge_into(&mut cfg.configuration, &parsed, is_override);
        cfg.conf_files.push(display.clone());
    }

    cfg.finalize();
    cfg
}

/// Split like Python `str.splitlines()`: on `\n`, `\r\n`, `\r`, and also
/// `\x0b`, `\x0c`, `\x1c`-`\x1e`, `\x85`, `\u2028`, `\u2029` (Rust's
/// `str::lines` only handles `\n` and `\r\n`).
fn splitlines(text: &str) -> Vec<&str> {
    text.split(|c| {
        matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        )
    })
    .collect()
}

/// The two `rpmlintrc` directives rpmlint recognises (`config.py`).
/// `setBadness` values land in `Scoring` as strings (int()'d at read time);
/// `addFilter` appends to `Filters` and is recorded for the unused-filter audit.
pub fn load_rpmlintrc(config: &mut Config, path: &Path) -> std::io::Result<()> {
    let re_filter =
        Regex::new(r#"^\s*addFilter\s*\(\s*r?["\'](.*)["\']\s*\)"#).expect("static regex");
    let re_badness = Regex::new(r#"\s*setBadness\s*\([\'"](.*)[\'"],\s*[\'"]?(\d+)[\'"]?\)"#)
        .expect("static regex");
    let text = std::fs::read_to_string(path)?;

    let mut filters = Vec::new();
    for line in splitlines(&text) {
        if let Ok(Some(m)) = re_filter.captures(line) {
            filters.push(m.get(1).expect("capture group").as_str().to_string());
        }
        if let Ok(Some(m)) = re_badness.captures(line) {
            let name = m.get(1).expect("capture group").as_str().to_string();
            let val = m.get(2).expect("capture group").as_str().to_string();
            config
                .configuration
                .entry("Scoring")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .expect("Scoring is a table")
                .insert(name, toml::Value::String(val));
        }
    }

    // self.configuration['Filters'] += filters
    let mut all = config.get_strings("Filters");
    all.extend(filters.iter().cloned());
    config.configuration.insert(
        "Filters".to_string(),
        toml::Value::Array(
            all.into_iter()
                .map(|s| toml::Value::String(s.to_string()))
                .collect(),
        ),
    );
    config.rpmlintrc_filters = filters;
    config.rpmlintrc_display.push(path.display().to_string());
    config.finalize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(t: &str) -> toml::Table {
        toml::from_str(t).unwrap()
    }

    #[test]
    fn merge_unions_lists_for_normal_configs() {
        let mut dest = table("Checks = [\"a\", \"b\"]");
        let src = table("Checks = [\"b\", \"c\"]");
        merge_into(&mut dest, &src, false);
        assert_eq!(
            dest["Checks"].as_array().unwrap(),
            &vec!["a", "b", "c"]
                .into_iter()
                .map(|s| toml::Value::String(s.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merge_keeps_list_when_a_later_table_is_empty() {
        // `device-files-whitelist.toml` is followed by an empty
        // `[DeviceFilesWhitelist]` in opensuse.toml. The reference gates the
        // append on the destination being a list and then iterates the incoming
        // value, so an empty table is a no-op and the list survives. Replacing
        // it emptied the whitelist and flagged every device file in every
        // package. Found while reviewing #47.
        let mut dest = table("W = [\"a\", \"b\"]");
        let src = table("[W]\n");
        merge_into(&mut dest, &src, false);
        assert_eq!(dest["W"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn merge_appends_keys_of_a_later_table_into_a_list() {
        // Same arm, non-empty table: Python's `for item in v` walks a dict's
        // keys, so the keys are appended.
        let mut dest = table("W = [\"a\"]");
        let src = table("[W]\nb = 1\n");
        merge_into(&mut dest, &src, false);
        assert_eq!(
            dest["W"].as_array().unwrap(),
            &["a".to_string(), "b".to_string()]
                .into_iter()
                .map(|s| toml::Value::String(s.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merge_appends_table_keys_in_document_order() {
        // The reference walks dict keys in insertion order, not sorted order.
        // Needs more than one key to discriminate the two.
        let mut dest = table("W = [\"a\"]");
        let src = table("[W]\nz = 1\nb = 2\nm = 3\n");
        merge_into(&mut dest, &src, false);
        assert_eq!(
            dest["W"].as_array().unwrap(),
            &["a", "z", "b", "m"]
                .into_iter()
                .map(|s| toml::Value::String(s.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merge_appends_characters_of_a_later_string() {
        // `for item in "xyz"` walks the characters; the reference does not raise.
        let mut dest = table("W = [\"a\"]");
        let src = table("W = \"xyz\"");
        merge_into(&mut dest, &src, false);
        assert_eq!(
            dest["W"].as_array().unwrap(),
            &["a", "x", "y", "z"]
                .into_iter()
                .map(|s| toml::Value::String(s.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    #[should_panic(expected = "which the reference cannot iterate either")]
    fn merge_panics_on_a_non_iterable_scalar() {
        let mut dest = table("W = [\"a\"]");
        let src = table("W = 42");
        merge_into(&mut dest, &src, false);
    }

    #[test]
    fn merge_still_replaces_a_list_with_a_later_table_for_override_configs() {
        let mut dest = table("W = [\"a\", \"b\"]");
        let src = table("[W]\n");
        merge_into(&mut dest, &src, true);
        assert!(dest["W"].is_table());
    }

    #[test]
    fn merge_replaces_lists_for_override_configs() {
        let mut dest = table("Checks = [\"a\", \"b\"]");
        let src = table("Checks = [\"b\", \"c\"]");
        merge_into(&mut dest, &src, true);
        assert_eq!(
            dest["Checks"].as_array().unwrap(),
            &vec!["b", "c"]
                .into_iter()
                .map(|s| toml::Value::String(s.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn merge_overwrites_scalars_and_recurses_tables() {
        let mut dest = table("BadnessThreshold = 999\n[Scoring]\na = 1");
        let src = table("BadnessThreshold = 5\n[Scoring]\nb = 2");
        merge_into(&mut dest, &src, false);
        assert_eq!(dest["BadnessThreshold"].as_integer().unwrap(), 5);
        assert_eq!(dest["Scoring"]["a"].as_integer().unwrap(), 1);
        assert_eq!(dest["Scoring"]["b"].as_integer().unwrap(), 2);
    }

    #[test]
    fn sort_key_orders_defaults_normal_override() {
        assert!(sort_key(true, "configdefaults.toml") < sort_key(false, "opensuse.toml"));
        assert!(sort_key(false, "opensuse.toml") < sort_key(false, "scoring-strict.override.toml"));
    }

    #[test]
    fn bundled_defaults_load_with_checks() {
        let cfg = load_inner(&[], &[], false);
        assert!(!cfg.checks.is_empty());
        assert_eq!(cfg.badness_threshold, -1);
        assert_eq!(cfg.conf_files, vec!["<builtin>".to_string()]);
    }

    #[test]
    fn xdg_configs_accumulate_checks_and_scoring() {
        let tmp = tempfile::tempdir().unwrap();
        let rpmlint_dir = tmp.path().join("xdg").join("rpmlint");
        std::fs::create_dir_all(&rpmlint_dir).unwrap();
        std::fs::write(
            rpmlint_dir.join("opensuse.toml"),
            "Checks = [\"BrandingPolicyCheck\"]\n[Scoring]\ninvalid-license = 100000",
        )
        .unwrap();
        let cfg = load_inner(&[], &[tmp.path().join("xdg")], true);
        // Base checks plus the openSUSE append, in load order.
        assert!(cfg.checks.contains(&"BrandingPolicyCheck".to_string()));
        assert_eq!(
            cfg.scoring.get("invalid-license"),
            Some(&toml::Value::Integer(100000))
        );
        // conf_files: builtin first, then the openSUSE file.
        assert_eq!(cfg.conf_files[0], "<builtin>");
        assert!(cfg.conf_files[1].ends_with("opensuse.toml"));
    }

    #[test]
    fn override_config_replaces_checks_list() {
        let tmp = tempfile::tempdir().unwrap();
        let rpmlint_dir = tmp.path().join("xdg").join("rpmlint");
        std::fs::create_dir_all(&rpmlint_dir).unwrap();
        std::fs::write(rpmlint_dir.join("opensuse.toml"), "Checks = [\"A\", \"B\"]").unwrap();
        std::fs::write(
            rpmlint_dir.join("scoring-strict.override.toml"),
            "Checks = [\"Only\"]",
        )
        .unwrap();
        let cfg = load_inner(&[], &[tmp.path().join("xdg")], true);
        // The override file merges last and replaces the list wholesale.
        assert_eq!(cfg.checks, vec!["Only".to_string()]);
    }

    #[test]
    fn rpmlintrc_scraper_handles_addfilter_and_setbadness() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join("pkg-rpmlintrc");
        std::fs::write(
            &rc,
            "setBadness('no-return-in-nonvoid-function', 0)\naddFilter('no-return-in-nonvoid-function')\n",
        )
        .unwrap();
        let mut cfg = load_inner(&[], &[], false);
        load_rpmlintrc(&mut cfg, &rc).unwrap();
        assert_eq!(
            cfg.scoring.get("no-return-in-nonvoid-function"),
            Some(&toml::Value::String("0".to_string()))
        );
        assert!(
            cfg.filters
                .contains(&"no-return-in-nonvoid-function".to_string())
        );
        assert_eq!(
            cfg.rpmlintrc_filters,
            vec!["no-return-in-nonvoid-function".to_string()]
        );
    }

    fn config_with_toml(toml_text: &str) -> Config {
        let tmp = tempfile::tempdir().unwrap();
        let rpmlint_dir = tmp.path().join("xdg").join("rpmlint");
        std::fs::create_dir_all(&rpmlint_dir).unwrap();
        std::fs::write(rpmlint_dir.join("flavor.toml"), toml_text).unwrap();
        load_inner(&[], &[tmp.path().join("xdg")], true)
    }

    #[test]
    fn flavor_defaults_to_opensuse() {
        let cfg = load_inner(&[], &[], false);
        assert_eq!(cfg.flavor, "opensuse");
        assert!(!cfg.is_slfo());
    }

    #[test]
    fn flavor_slfo_is_recognized() {
        let cfg = config_with_toml("Flavor = \"slfo\"\n");
        assert_eq!(cfg.flavor, "slfo");
        assert!(cfg.is_slfo());
    }

    #[test]
    fn flavor_value_is_case_insensitive() {
        let cfg = config_with_toml("Flavor = \"SLFO\"\n");
        assert_eq!(cfg.flavor, "slfo");
        assert!(cfg.is_slfo());
    }

    #[test]
    fn flavor_unknown_warns_and_falls_back_to_opensuse() {
        // The warning goes to stderr; fail closed means asserting the fallback.
        let cfg = config_with_toml("Flavor = \"sled\"\n");
        assert_eq!(cfg.flavor, "opensuse");
        assert!(!cfg.is_slfo());
    }

    #[test]
    fn divergence_applies_respects_entry_flavor() {
        // The corpus runner compares in the default flavor: an entry without a
        // flavor key applies everywhere, a slfo-gated entry only on slfo runs.
        let opensuse = load_inner(&[], &[], false);
        assert!(opensuse.divergence_applies(None));
        assert!(opensuse.divergence_applies(Some("opensuse")));
        assert!(!opensuse.divergence_applies(Some("slfo")));

        let slfo = config_with_toml("Flavor = \"slfo\"\n");
        assert!(slfo.divergence_applies(None));
        assert!(slfo.divergence_applies(Some("slfo")));
        assert!(!slfo.divergence_applies(Some("opensuse")));
    }
}
