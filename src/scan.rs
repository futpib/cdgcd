use std::path::PathBuf;
use std::time::SystemTime;

use log::{debug, error, info, warn};

use crate::config::Config;
use crate::dump::{CoredumpFile, ParseError};
use crate::journal;
use crate::policy::{Decision, KeepReason, Policy, RemoveReason};

#[derive(Debug, Default)]
pub struct ScanReport {
    pub kept: Vec<(CoredumpFile, KeepReason)>,
    pub removed: Vec<(CoredumpFile, RemoveReason)>,
    pub would_remove: Vec<(CoredumpFile, RemoveReason)>,
    pub too_young: Vec<CoredumpFile>,
    pub unparseable: Vec<PathBuf>,
    pub errors: Vec<(PathBuf, std::io::Error)>,
}

pub struct Scanner<'a> {
    pub config: &'a Config,
    pub policy: &'a Policy,
}

impl<'a> Scanner<'a> {
    pub fn scan(&self) -> ScanReport {
        let mut report = ScanReport::default();
        let now = SystemTime::now();

        let entries = match std::fs::read_dir(&self.config.coredump_directory) {
            Ok(e) => e,
            Err(e) => {
                report
                    .errors
                    .push((self.config.coredump_directory.clone(), e));
                return report;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    report
                        .errors
                        .push((self.config.coredump_directory.clone(), e));
                    continue;
                }
            };
            let path = entry.path();

            let dump = match CoredumpFile::from_path(&path) {
                Ok(d) => d,
                Err(ParseError::NotACoredump) => {
                    debug!("skip non-coredump: {}", path.display());
                    report.unparseable.push(path);
                    continue;
                }
                Err(ParseError::BadField(field)) => {
                    warn!("bad {} field in {}", field, path.display());
                    report.unparseable.push(path);
                    continue;
                }
            };

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    report.errors.push((path, e));
                    continue;
                }
            };
            if let Ok(modified) = meta.modified()
                && let Ok(age) = now.duration_since(modified)
                && age < self.config.minimum_age
            {
                debug!("too young: {}", dump.path.display());
                report.too_young.push(dump);
                continue;
            }

            let executable_path = if self.policy.needs_executable_path()
                && !self.policy.matches_process_name(&dump.comm)
            {
                journal::lookup_executable_path(&dump.path)
            } else {
                None
            };

            match self.policy.evaluate(&dump, executable_path.as_deref()) {
                Decision::Keep(reason) => {
                    debug!("keep {}: {:?}", dump.path.display(), reason);
                    report.kept.push((dump, reason));
                }
                Decision::Remove(reason) => {
                    if self.config.dry_run {
                        info!("would remove {} ({:?})", dump.path.display(), reason);
                        report.would_remove.push((dump, reason));
                    } else {
                        match std::fs::remove_file(&dump.path) {
                            Ok(()) => {
                                info!("removed {} ({:?})", dump.path.display(), reason);
                                report.removed.push((dump, reason));
                            }
                            Err(e) => {
                                error!("remove {} failed: {}", dump.path.display(), e);
                                report.errors.push((dump.path.clone(), e));
                            }
                        }
                    }
                }
            }
        }

        report
    }
}
