use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

use log::{debug, error, info, warn};

use crate::config::Config;
use crate::dump::{CoredumpFile, ParseError};
use crate::journal::{self, JournalContext};
use crate::policy::Policy;

#[derive(Debug, Clone)]
pub enum Verdict {
    Keep { rule_name: String },
    Remove(RemoveReason),
}

#[derive(Debug, Clone)]
pub enum RemoveReason {
    NoRuleMatched,
    KeepCountExceeded { rule_name: String, keep_count: u32 },
}

#[derive(Debug)]
pub struct DumpVerdict {
    pub dump: CoredumpFile,
    pub verdict: Verdict,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub kept: Vec<DumpVerdict>,
    pub removed: Vec<DumpVerdict>,
    pub would_remove: Vec<DumpVerdict>,
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

        let entries = match std::fs::read_dir(&self.config.coredump_directory) {
            Ok(e) => e,
            Err(e) => {
                report
                    .errors
                    .push((self.config.coredump_directory.clone(), e));
                return report;
            }
        };

        let now = SystemTime::now();
        let mut classified: Vec<(CoredumpFile, Option<usize>)> = Vec::new();

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

            let rule_index = classify(self.policy, &dump);
            classified.push((dump, rule_index));
        }

        let over_cap = compute_keep_count_excess(self.policy, &classified);

        for (i, (dump, rule_index)) in classified.into_iter().enumerate() {
            let verdict = match rule_index {
                None => Verdict::Remove(RemoveReason::NoRuleMatched),
                Some(idx) => {
                    let rule = &self.policy.rules[idx];
                    if over_cap.contains(&i) {
                        Verdict::Remove(RemoveReason::KeepCountExceeded {
                            rule_name: rule.name.clone(),
                            keep_count: rule.keep_count.unwrap_or(0),
                        })
                    } else {
                        Verdict::Keep {
                            rule_name: rule.name.clone(),
                        }
                    }
                }
            };

            self.apply(dump, verdict, &mut report);
        }

        report
    }

    fn apply(&self, dump: CoredumpFile, verdict: Verdict, report: &mut ScanReport) {
        match &verdict {
            Verdict::Keep { rule_name } => {
                debug!("keep {} (rule {})", dump.path.display(), rule_name);
                report.kept.push(DumpVerdict { dump, verdict });
            }
            Verdict::Remove(reason) => {
                if self.config.dry_run {
                    info!("would remove {} ({:?})", dump.path.display(), reason);
                    report.would_remove.push(DumpVerdict { dump, verdict });
                } else {
                    match std::fs::remove_file(&dump.path) {
                        Ok(()) => {
                            info!("removed {} ({:?})", dump.path.display(), reason);
                            report.removed.push(DumpVerdict { dump, verdict });
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
}

pub fn classify(policy: &Policy, dump: &CoredumpFile) -> Option<usize> {
    let empty = JournalContext::default();
    let mut cache: Option<JournalContext> = None;
    for (idx, rule) in policy.rules.iter().enumerate() {
        if rule.needs_journal && cache.is_none() {
            cache = Some(journal::lookup(&dump.path));
        }
        let ctx = cache.as_ref().unwrap_or(&empty);
        if rule.matches(dump, ctx) {
            return Some(idx);
        }
    }
    None
}

pub fn compute_keep_count_excess(
    policy: &Policy,
    classified: &[(CoredumpFile, Option<usize>)],
) -> HashSet<usize> {
    let mut over_cap = HashSet::new();
    for (rule_idx, rule) in policy.rules.iter().enumerate() {
        let cap = match rule.keep_count {
            Some(n) => n as usize,
            None => continue,
        };
        let mut matching: Vec<usize> = classified
            .iter()
            .enumerate()
            .filter_map(|(i, (_, ri))| if *ri == Some(rule_idx) { Some(i) } else { None })
            .collect();
        matching.sort_by_key(|&i| std::cmp::Reverse(classified[i].0.timestamp_micros));
        for &i in matching.iter().skip(cap) {
            over_cap.insert(i);
        }
    }
    over_cap
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NamedRule, Rule};
    use std::path::PathBuf;
    use std::time::Duration;

    fn dump_at(comm: &str, ts: u64) -> CoredumpFile {
        CoredumpFile {
            path: PathBuf::from(format!("/tmp/{}-{}", comm, ts)),
            comm: comm.to_string(),
            uid: 0,
            boot_id: "0".repeat(32),
            pid: 1,
            timestamp_micros: ts,
            extension: None,
        }
    }

    fn rule_keeping(name: &str, comm: &str, keep_count: Option<u32>) -> NamedRule {
        NamedRule {
            name: name.to_string(),
            rule: Rule {
                process_name: vec![comm.to_string()],
                keep_count,
                ..Rule::default()
            },
        }
    }

    fn config(rules: Vec<NamedRule>) -> Config {
        Config {
            coredump_directory: PathBuf::from("/dev/null"),
            idle_interval: Duration::from_secs(300),
            minimum_age: Duration::from_secs(30),
            dry_run: false,
            rules,
        }
    }

    #[test]
    fn keep_count_keeps_newest() {
        let cfg = config(vec![rule_keeping("foo", "foo", Some(2))]);
        let policy = Policy::from_config(&cfg).unwrap();
        let classified = vec![
            (dump_at("foo", 100), Some(0)),
            (dump_at("foo", 200), Some(0)),
            (dump_at("foo", 300), Some(0)),
            (dump_at("foo", 50), Some(0)),
        ];
        let over_cap = compute_keep_count_excess(&policy, &classified);
        // newest two (300, 200) survive; 100 and 50 get capped
        assert!(!over_cap.contains(&1)); // ts=200
        assert!(!over_cap.contains(&2)); // ts=300
        assert!(over_cap.contains(&0)); // ts=100
        assert!(over_cap.contains(&3)); // ts=50
    }

    #[test]
    fn no_keep_count_means_unlimited() {
        let cfg = config(vec![rule_keeping("foo", "foo", None)]);
        let policy = Policy::from_config(&cfg).unwrap();
        let classified = vec![
            (dump_at("foo", 100), Some(0)),
            (dump_at("foo", 200), Some(0)),
        ];
        let over_cap = compute_keep_count_excess(&policy, &classified);
        assert!(over_cap.is_empty());
    }

    #[test]
    fn keep_count_per_rule_independent() {
        let cfg = config(vec![
            rule_keeping("foo", "foo", Some(1)),
            rule_keeping("bar", "bar", Some(2)),
        ]);
        let policy = Policy::from_config(&cfg).unwrap();
        let classified = vec![
            (dump_at("foo", 100), Some(0)),
            (dump_at("foo", 200), Some(0)),
            (dump_at("bar", 50), Some(1)),
            (dump_at("bar", 60), Some(1)),
            (dump_at("bar", 70), Some(1)),
        ];
        let over_cap = compute_keep_count_excess(&policy, &classified);
        // foo: keep 1 newest (ts=200), drop ts=100
        // bar: keep 2 newest (ts=70, 60), drop ts=50
        assert!(over_cap.contains(&0));
        assert!(!over_cap.contains(&1));
        assert!(over_cap.contains(&2));
        assert!(!over_cap.contains(&3));
        assert!(!over_cap.contains(&4));
    }
}
