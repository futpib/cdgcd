use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::SystemTime;

use log::{debug, error, info, warn};

use crate::config::Config;
use crate::dump::{CoredumpFile, ParseError};
use crate::journal::{self, JournalContext};
use crate::policy::Policy;
use crate::retain;

#[derive(Debug, Clone)]
pub enum Verdict {
    Keep { rule_name: String },
    KeepRetained,
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

#[derive(Debug)]
pub struct Classified {
    pub dump: CoredumpFile,
    pub rule_index: Option<usize>,
    pub journal_context: JournalContext,
    pub retained: bool,
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
        let mut classified: Vec<Classified> = Vec::new();
        let mut markers: HashSet<OsString> = HashSet::new();
        let mut candidate_entries: Vec<std::fs::DirEntry> = Vec::new();

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
            if let Some(dump_name) = retain::dump_name_for_marker(&entry.file_name()) {
                markers.insert(OsString::from(dump_name));
            } else {
                candidate_entries.push(entry);
            }
        }

        for entry in candidate_entries {
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

            let retained = markers.contains(&entry.file_name());
            let (rule_index, journal_context) = if retained {
                (None, JournalContext::default())
            } else {
                classify(self.policy, &dump)
            };
            classified.push(Classified {
                dump,
                rule_index,
                journal_context,
                retained,
            });
        }

        let over_cap = compute_keep_count_excess(self.policy, &classified);

        for (i, c) in classified.into_iter().enumerate() {
            let verdict = if c.retained {
                Verdict::KeepRetained
            } else {
                match c.rule_index {
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
                }
            };

            self.apply(c.dump, verdict, &mut report);
        }

        report
    }

    fn apply(&self, dump: CoredumpFile, verdict: Verdict, report: &mut ScanReport) {
        match &verdict {
            Verdict::Keep { rule_name } => {
                debug!("keep {} (rule {})", dump.path.display(), rule_name);
                report.kept.push(DumpVerdict { dump, verdict });
            }
            Verdict::KeepRetained => {
                debug!("keep {} (retain marker)", dump.path.display());
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

pub fn classify(policy: &Policy, dump: &CoredumpFile) -> (Option<usize>, JournalContext) {
    let empty = JournalContext::default();
    let mut cache: Option<JournalContext> = None;
    for (idx, rule) in policy.rules.iter().enumerate() {
        if rule.needs_journal && cache.is_none() {
            cache = Some(journal::lookup(&dump.path));
        }
        let ctx = cache.as_ref().unwrap_or(&empty);
        if rule.matches(dump, ctx) {
            return (Some(idx), cache.unwrap_or_default());
        }
    }
    (None, cache.unwrap_or_default())
}

pub fn compute_keep_count_excess(policy: &Policy, classified: &[Classified]) -> HashSet<usize> {
    let mut over_cap = HashSet::new();
    for (rule_idx, rule) in policy.rules.iter().enumerate() {
        let cap = match rule.keep_count {
            Some(n) => n as usize,
            None => continue,
        };
        let matching: Vec<usize> = classified
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                if c.retained {
                    None
                } else if c.rule_index == Some(rule_idx) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        if rule.group_by.is_empty() {
            mark_excess(&matching, classified, cap, &mut over_cap);
        } else {
            let mut groups: HashMap<Vec<Option<String>>, Vec<usize>> = HashMap::new();
            for i in matching {
                let key: Vec<Option<String>> = rule
                    .group_by
                    .iter()
                    .map(|f| f.extract(&classified[i].dump, &classified[i].journal_context))
                    .collect();
                groups.entry(key).or_default().push(i);
            }
            for (_, group) in groups {
                mark_excess(&group, classified, cap, &mut over_cap);
            }
        }
    }
    over_cap
}

fn mark_excess(
    indices: &[usize],
    classified: &[Classified],
    cap: usize,
    over_cap: &mut HashSet<usize>,
) {
    let mut sorted = indices.to_vec();
    sorted.sort_by_key(|&i| std::cmp::Reverse(classified[i].dump.timestamp_micros));
    for &i in sorted.iter().skip(cap) {
        over_cap.insert(i);
    }
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

    fn classified_at(comm: &str, ts: u64, rule_index: Option<usize>) -> Classified {
        Classified {
            dump: dump_at(comm, ts),
            rule_index,
            journal_context: JournalContext::default(),
            retained: false,
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
            classified_at("foo", 100, Some(0)),
            classified_at("foo", 200, Some(0)),
            classified_at("foo", 300, Some(0)),
            classified_at("foo", 50, Some(0)),
        ];
        let over_cap = compute_keep_count_excess(&policy, &classified);
        assert!(!over_cap.contains(&1));
        assert!(!over_cap.contains(&2));
        assert!(over_cap.contains(&0));
        assert!(over_cap.contains(&3));
    }

    #[test]
    fn no_keep_count_means_unlimited() {
        let cfg = config(vec![rule_keeping("foo", "foo", None)]);
        let policy = Policy::from_config(&cfg).unwrap();
        let classified = vec![
            classified_at("foo", 100, Some(0)),
            classified_at("foo", 200, Some(0)),
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
            classified_at("foo", 100, Some(0)),
            classified_at("foo", 200, Some(0)),
            classified_at("bar", 50, Some(1)),
            classified_at("bar", 60, Some(1)),
            classified_at("bar", 70, Some(1)),
        ];
        let over_cap = compute_keep_count_excess(&policy, &classified);
        assert!(over_cap.contains(&0));
        assert!(!over_cap.contains(&1));
        assert!(over_cap.contains(&2));
        assert!(!over_cap.contains(&3));
        assert!(!over_cap.contains(&4));
    }

    #[test]
    fn group_by_process_name_caps_per_comm() {
        let rule = NamedRule {
            name: "user".to_string(),
            rule: Rule {
                user_id: vec![0],
                group_by: vec!["process_name".to_string()],
                keep_count: Some(2),
                ..Rule::default()
            },
        };
        let policy = Policy::from_config(&config(vec![rule])).unwrap();
        let classified = vec![
            classified_at("foo", 100, Some(0)),
            classified_at("foo", 200, Some(0)),
            classified_at("foo", 300, Some(0)),
            classified_at("bar", 10, Some(0)),
            classified_at("bar", 20, Some(0)),
            classified_at("bar", 30, Some(0)),
        ];
        let over_cap = compute_keep_count_excess(&policy, &classified);
        // foo: keep ts=300, 200, drop ts=100
        // bar: keep ts=30, 20, drop ts=10
        assert!(over_cap.contains(&0));
        assert!(!over_cap.contains(&1));
        assert!(!over_cap.contains(&2));
        assert!(over_cap.contains(&3));
        assert!(!over_cap.contains(&4));
        assert!(!over_cap.contains(&5));
    }

    #[test]
    fn retained_dumps_skip_keep_count_cap() {
        let cfg = config(vec![rule_keeping("foo", "foo", Some(1))]);
        let policy = Policy::from_config(&cfg).unwrap();
        let mut classified = vec![
            classified_at("foo", 100, Some(0)),
            classified_at("foo", 200, Some(0)),
            classified_at("foo", 300, Some(0)),
        ];
        // pin the oldest — it should not count against the cap, and the newest one wins
        classified[0].retained = true;
        let over_cap = compute_keep_count_excess(&policy, &classified);
        // ts=300 (newest non-retained) survives the cap; ts=200 is over cap
        assert!(!over_cap.contains(&0), "retained dump never marked over-cap");
        assert!(over_cap.contains(&1), "ts=200 over cap (cap=1)");
        assert!(!over_cap.contains(&2), "ts=300 newest survives");
    }

    #[test]
    fn group_by_multi_field_uses_tuple() {
        let rule = NamedRule {
            name: "by_user_and_comm".to_string(),
            rule: Rule {
                group_by: vec!["process_name".to_string(), "user_id".to_string()],
                keep_count: Some(1),
                ..Rule::default()
            },
        };
        let policy = Policy::from_config(&config(vec![rule])).unwrap();
        let mut classified = vec![
            classified_at("foo", 100, Some(0)),
            classified_at("foo", 200, Some(0)),
            classified_at("foo", 300, Some(0)),
        ];
        // Same comm, different uids — should each survive (different group key)
        classified[0].dump.uid = 1;
        classified[1].dump.uid = 2;
        classified[2].dump.uid = 3;
        let over_cap = compute_keep_count_excess(&policy, &classified);
        assert!(over_cap.is_empty(), "different uids form different groups");
    }
}
