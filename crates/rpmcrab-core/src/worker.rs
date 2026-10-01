//! The `-j` worker: check one package per task and return the structured
//! result for ordered replay (`rpmlint#1595`, `rpmlint/worker.py`).
//!
//! Rust has no GIL, so workers are threads, not processes: no pickling, no
//! IPC. The design is the same — check instances built once per worker, a
//! fresh [`Filter`] per package, per-package result collection, ordered
//! replay in the main thread, cross-package state exported per package and
//! merged before `after_checks`.

use std::any::Any;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;

use crate::check::Check;
use crate::color::Color;
use crate::config::Config;
use crate::filter::Filter;
use crate::lint::Durations;
use crate::pkg::spec::SpecPkg;
use crate::pkg::{Package, Pkg};

/// One package to check: a file path, or an installed package named by the
/// rpmdb query that found it. The rpmdb cannot cross threads (`PackageHeader`
/// is not `Send`), so each worker queries it per name and caches the handle
/// (`_installed_pkgs_cache`, `rpmlint#1595`); the main thread only enumerates
/// for the missing-name warnings.
pub enum Task {
    File(PathBuf),
    Installed { name: String, index: usize },
}

/// The structured per-package result (`worker.py:check_package`).
pub struct TaskResult {
    /// The package's findings, suppression already applied.
    pub filter: Filter,
    /// Per-check and per-phase durations, in first-occurrence order.
    pub durations: Durations,
    /// Per-check `checked_files` deltas for this package.
    pub checked_files: Vec<(String, usize)>,
    /// Exported cross-package state, per check name.
    pub states: Vec<(String, Box<dyn Any + Send>)>,
    /// Package name for the unused-rpmlintrc audit: the header name when the
    /// package opened, the path as passed when it did not (`_last_pkg`).
    pub pkg_name: String,
    pub pkg_arch: Option<String>,
    pub is_spec: bool,
    /// The display form used in the fatal message: the path for files, the
    /// package name for installed packages (`_replay_result`).
    pub display: String,
    /// Set when the package could not be read or checked; the run continues
    /// and fails with exit code 3 at the end.
    pub fatal: Option<String>,
}

/// A worker: check instances built once, reused for every package it handles.
pub struct Worker<'a> {
    config: &'a Config,
    checks: Vec<Box<dyn Check>>,
    color: Color,
    extract_dir: PathBuf,
    installed_db: Option<librpm::db::Db>,
}

impl<'a> Worker<'a> {
    pub fn new(config: &'a Config, checks: Vec<Box<dyn Check>>, color: Color) -> Self {
        Self {
            config,
            checks,
            color,
            extract_dir: config.extract_dir(),
            installed_db: None,
        }
    }

    /// Check one package (`worker.py:check_package`). A panic anywhere in the
    /// task becomes a fatal result, never a dead worker thread.
    pub fn check_package(&mut self, task: Task) -> TaskResult {
        let display = match &task {
            Task::File(path) => path.display().to_string(),
            Task::Installed { name, .. } => name.clone(),
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.check_package_inner(task, &display)
        })) {
            Ok(result) => result,
            Err(_) => TaskResult::fatal(
                self.fresh_filter(),
                display.clone(),
                display,
                None,
                false,
                "panic while checking the package".to_string(),
            ),
        }
    }

    /// Open the `index`-th package called `name` from the rpmdb, opening
    /// the database once per worker and reusing the handle.
    fn installed_pkg(&mut self, name: &str, index: usize) -> Result<Pkg, crate::pkg::PkgError> {
        if self.installed_db.is_none() {
            self.installed_db = Some(librpm::db::Db::open()?);
        }
        let db = self.installed_db.as_ref().expect("just opened");
        let (headers, _) =
            crate::pkg::installed::find_in(db, &[name.to_string()])?;
        let header = headers.into_iter().nth(index).ok_or_else(|| {
            crate::pkg::PkgError::Init(format!("installed package {name} vanished mid-run"))
        })?;
        Pkg::installed(header)
    }

    fn fresh_filter(&self) -> Filter {
        // The main filter already validated the patterns at startup, so this
        // cannot fail on the same configuration.
        Filter::new(self.config, self.color).expect("filter patterns validated at startup")
    }

    fn check_package_inner(&mut self, task: Task, display: &str) -> TaskResult {
        let mut filter = self.fresh_filter();
        // `files_before`: the run-lifetime counters before this package, so
        // the result carries only this package's delta (`rpmlint#1595`).
        let files_before: Vec<usize> = self
            .checks
            .iter()
            .map(|c| c.checked_files().unwrap_or(0))
            .collect();

        // Open the package; a failure is a fatal result and the remaining
        // packages still run.
        let (mut package, pkg_name, pkg_arch, is_spec) = match task {
            Task::File(path) => {
                let display_name = path.display().to_string();
                if path.extension().is_some_and(|e| e == "spec") {
                    match SpecPkg::open(&path) {
                        Ok(pkg) => (Package::Spec(pkg), display_name, None, true),
                        Err(e) => {
                            return TaskResult::fatal(
                                filter,
                                display.to_string(),
                                display_name,
                                None,
                                true,
                                format!("fatal error while reading {display}: {e}"),
                            );
                        }
                    }
                } else {
                    match Pkg::open(&path, &self.extract_dir) {
                        Ok(pkg) => {
                            let name = pkg.name.clone();
                            let arch =
                                (!pkg.arch.is_empty()).then(|| pkg.arch.clone());
                            (Package::Rpm(Box::new(pkg)), name, arch, false)
                        }
                        Err(e) => {
                            return TaskResult::fatal(
                                filter,
                                display.to_string(),
                                display_name,
                                None,
                                false,
                                format!("fatal error while reading {display}: {e}"),
                            );
                        }
                    }
                }
            }
            Task::Installed { name, index } => {
                let display_name = name.clone();
                match self.installed_pkg(&name, index) {
                    Ok(pkg) => {
                        let arch = (!pkg.arch.is_empty()).then(|| pkg.arch.clone());
                        (Package::Rpm(Box::new(pkg)), display_name, arch, false)
                    }
                    Err(e) => {
                        return TaskResult::fatal(
                            filter,
                            display.to_string(),
                            display_name,
                            None,
                            false,
                            format!("fatal error while reading {display}: {e}"),
                        );
                    }
                }
            }
        };

        // The package's own phase timings (`ExtractRpm`, `libmagic`) are
        // folded in before the checks run, so they survive a fatal check.
        let mut durations = Durations::default();
        if let Package::Rpm(pkg) = &package {
            for (phase, secs) in pkg.timers.iter() {
                durations.add(phase, secs);
            }
        }

        // The check dispatch runs inside `pkg::guarded`, so a librpm decoder
        // panic becomes a fatal read error instead of aborting the run.
        let checked = crate::pkg::guarded(|| {
            for check in &mut self.checks {
                let start = Instant::now();
                match &mut package {
                    Package::Rpm(pkg) => check.check(pkg, self.config, &mut filter),
                    Package::Spec(pkg) => check.check_spec(pkg, self.config, &mut filter),
                }
                durations.add(check.name(), start.elapsed().as_secs_f64());
            }
            Ok::<(), crate::pkg::PkgError>(())
        });
        if let Err(e) = checked {
            // Drop state accumulated before the failure so a package that
            // could not be checked never contributes to `after_checks`, and
            // reset so the next package on this worker starts clean.
            for check in &mut self.checks {
                let _ = check.export_state();
                check.reset();
            }
            return TaskResult::fatal(
                filter,
                display.to_string(),
                pkg_name,
                pkg_arch,
                is_spec,
                format!("fatal error while reading {display}: {e}"),
            );
        }

        let mut checked_files = Vec::new();
        let mut states = Vec::new();
        for (check, before) in self.checks.iter_mut().zip(files_before) {
            let now = check.checked_files().unwrap_or(0);
            if now > before {
                checked_files.push((check.name().to_string(), now - before));
            }
            // `export_state` also clears the exported state, so each result
            // only carries this package's contribution.
            if let Some(state) = check.export_state() {
                states.push((check.name().to_string(), state));
            }
        }
        // Restore per-package check state for the next package.
        for check in &mut self.checks {
            check.reset();
        }

        TaskResult {
            filter,
            durations,
            checked_files,
            states,
            pkg_name,
            pkg_arch,
            is_spec,
            display: display.to_string(),
            fatal: None,
        }
    }
}

impl TaskResult {
    fn fatal(
        filter: Filter,
        display: String,
        pkg_name: String,
        pkg_arch: Option<String>,
        is_spec: bool,
        msg: String,
    ) -> Self {
        Self {
            filter,
            durations: Durations::default(),
            checked_files: Vec::new(),
            states: Vec::new(),
            pkg_name,
            pkg_arch,
            is_spec,
            display,
            fatal: Some(msg),
        }
    }
}

/// Check packages, optionally on worker threads, returning the per-package
/// results in task order (`_check_packages`). `-j1` runs the same worker code
/// path in-process.
pub fn run_tasks(
    tasks: Vec<Task>,
    jobs: usize,
    config: &Config,
    make_checks: &dyn Fn() -> Vec<Box<dyn Check>>,
    color: Color,
) -> Vec<TaskResult> {
    // Never more workers than tasks, and never more than the machine's
    // parallelism: each worker builds a full check set up front, so excess
    // workers only burn memory and startup time, and check work is
    // CPU-bound, so workers beyond the CPU count add nothing.
    let max_parallel = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(usize::MAX);
    let jobs = jobs.max(1).min(tasks.len().max(1)).min(max_parallel);
    // Each worker's check set is built up front; the sets are moved into the
    // threads, so the factory itself is never shared between threads.
    let mut check_sets: Vec<Vec<Box<dyn Check>>> = (0..jobs).map(|_| make_checks()).collect();
    if jobs == 1 {
        let mut worker = Worker::new(
            config,
            check_sets.pop().expect("one set per worker"),
            color,
        );
        return tasks.into_iter().map(|t| worker.check_package(t)).collect();
    }
    let (result_tx, result_rx) = mpsc::channel::<(usize, TaskResult)>();
    std::thread::scope(|s| {
        let (task_tx, task_rx) = mpsc::channel::<(usize, Task)>();
        let task_rx = Arc::new(Mutex::new(task_rx));
        for _ in 0..jobs {
            let result_tx = result_tx.clone();
            let task_rx = Arc::clone(&task_rx);
            let checks = check_sets.pop().expect("one set per worker");
            s.spawn(move || {
                let mut worker = Worker::new(config, checks, color);
                // The lock is released before `check_package` runs: a
                // `while let` scrutinee temporary lives until the end of
                // the loop body, which would serialize the pool.
                loop {
                    let Ok((i, task)) =
                        task_rx.lock().unwrap_or_else(|e| e.into_inner()).recv()
                    else {
                        break;
                    };
                    let _ = result_tx.send((i, worker.check_package(task)));
                }
            });
        }
        for (i, task) in tasks.into_iter().enumerate() {
            let _ = task_tx.send((i, task));
        }
    });
    drop(result_tx);
    let mut results: Vec<(usize, TaskResult)> = result_rx.into_iter().collect();
    results.sort_by_key(|(i, _)| *i);
    results.into_iter().map(|(_, r)| r).collect()
}

