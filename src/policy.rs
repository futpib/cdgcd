use crate::config::Config;
use crate::dump::CoredumpFile;

pub struct Policy {
    allow_process_name: Vec<glob::Pattern>,
    allow_executable_path: Vec<glob::Pattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Keep(KeepReason),
    Remove(RemoveReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepReason {
    AllowedByProcessName(String),
    AllowedByExecutablePath(String),
    NoRulesConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoveReason {
    NoMatch,
}

impl Policy {
    pub fn from_config(config: &Config) -> Result<Self, glob::PatternError> {
        let allow_process_name = config
            .allow_process_name
            .iter()
            .map(|p| glob::Pattern::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        let allow_executable_path = config
            .allow_executable_path
            .iter()
            .map(|p| glob::Pattern::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Policy {
            allow_process_name,
            allow_executable_path,
        })
    }

    pub fn has_rules(&self) -> bool {
        !self.allow_process_name.is_empty() || !self.allow_executable_path.is_empty()
    }

    pub fn needs_executable_path(&self) -> bool {
        !self.allow_executable_path.is_empty()
    }

    pub fn matches_process_name(&self, process_name: &str) -> bool {
        self.allow_process_name.iter().any(|p| p.matches(process_name))
    }

    pub fn evaluate(&self, dump: &CoredumpFile, executable_path: Option<&str>) -> Decision {
        if !self.has_rules() {
            return Decision::Keep(KeepReason::NoRulesConfigured);
        }
        for pat in &self.allow_process_name {
            if pat.matches(&dump.comm) {
                return Decision::Keep(KeepReason::AllowedByProcessName(
                    pat.as_str().to_string(),
                ));
            }
        }
        if let Some(executable_path) = executable_path {
            for pat in &self.allow_executable_path {
                if pat.matches(executable_path) {
                    return Decision::Keep(KeepReason::AllowedByExecutablePath(
                        pat.as_str().to_string(),
                    ));
                }
            }
        }
        Decision::Remove(RemoveReason::NoMatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    fn dump(comm: &str) -> CoredumpFile {
        CoredumpFile {
            path: PathBuf::from("/tmp/x"),
            comm: comm.to_string(),
            uid: 0,
            boot_id: "0".repeat(32),
            pid: 1,
            timestamp_micros: 0,
            extension: None,
        }
    }

    fn cfg(allow_process_name: &[&str], allow_executable_path: &[&str]) -> Config {
        Config {
            allow_process_name: allow_process_name.iter().map(|s| s.to_string()).collect(),
            allow_executable_path: allow_executable_path
                .iter()
                .map(|s| s.to_string())
                .collect(),
            coredump_directory: PathBuf::from("/var/lib/systemd/coredump"),
            idle_interval: Duration::from_secs(300),
            minimum_age: Duration::from_secs(30),
            dry_run: false,
        }
    }

    #[test]
    fn empty_policy_keeps_everything() {
        let p = Policy::from_config(&cfg(&[], &[])).unwrap();
        assert_eq!(
            p.evaluate(&dump("foo"), None),
            Decision::Keep(KeepReason::NoRulesConfigured)
        );
    }

    #[test]
    fn allow_process_name_glob_matches() {
        let p = Policy::from_config(&cfg(&["my*"], &[])).unwrap();
        assert!(matches!(
            p.evaluate(&dump("myapp"), None),
            Decision::Keep(KeepReason::AllowedByProcessName(_))
        ));
        assert_eq!(
            p.evaluate(&dump("other"), None),
            Decision::Remove(RemoveReason::NoMatch)
        );
    }

    #[test]
    fn allow_executable_path_uses_path_only() {
        let p = Policy::from_config(&cfg(&[], &["/opt/foo/*"])).unwrap();
        assert!(matches!(
            p.evaluate(&dump("anything"), Some("/opt/foo/bin/x")),
            Decision::Keep(KeepReason::AllowedByExecutablePath(_))
        ));
        assert_eq!(
            p.evaluate(&dump("anything"), Some("/usr/bin/x")),
            Decision::Remove(RemoveReason::NoMatch)
        );
        assert_eq!(
            p.evaluate(&dump("anything"), None),
            Decision::Remove(RemoveReason::NoMatch)
        );
    }

    #[test]
    fn process_name_wins_over_executable_path() {
        let p = Policy::from_config(&cfg(&["myapp"], &["/never/*"])).unwrap();
        assert!(matches!(
            p.evaluate(&dump("myapp"), Some("/usr/bin/x")),
            Decision::Keep(KeepReason::AllowedByProcessName(_))
        ));
    }
}
