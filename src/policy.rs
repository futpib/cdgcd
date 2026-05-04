use crate::config::Config;
use crate::dump::{COMM_MAX_LEN, CoredumpFile};
use crate::journal::JournalContext;

#[derive(Debug)]
pub struct Policy {
    pub rules: Vec<CompiledRule>,
}

#[derive(Debug)]
pub struct CompiledRule {
    pub name: String,
    pub process_name: Vec<glob::Pattern>,
    pub executable_path: Vec<glob::Pattern>,
    pub command_line: Vec<glob::Pattern>,
    pub signal: Vec<String>,
    pub user_ids: Vec<u32>,
    pub group_by: Vec<GroupField>,
    pub keep_count: Option<u32>,
    pub needs_journal: bool,
    pub is_unconstrained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupField {
    ProcessName,
    UserId,
    ExecutablePath,
    CommandLine,
    Signal,
    BootId,
}

impl GroupField {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "process_name" => Self::ProcessName,
            "user_id" => Self::UserId,
            "executable_path" => Self::ExecutablePath,
            "command_line" => Self::CommandLine,
            "signal" => Self::Signal,
            "boot_id" => Self::BootId,
            _ => return None,
        })
    }

    fn needs_journal(&self) -> bool {
        matches!(
            self,
            Self::ExecutablePath | Self::CommandLine | Self::Signal
        )
    }

    pub fn extract(&self, dump: &CoredumpFile, context: &JournalContext) -> Option<String> {
        match self {
            Self::ProcessName => Some(dump.comm.clone()),
            Self::UserId => Some(dump.uid.to_string()),
            Self::ExecutablePath => context.executable_path.clone(),
            Self::CommandLine => context.command_line.clone(),
            Self::Signal => context.signal.clone(),
            Self::BootId => Some(dump.boot_id.clone()),
        }
    }
}

#[derive(Debug)]
pub enum PolicyError {
    Pattern(glob::PatternError),
    UnknownUser(String),
    UnknownGroupField(String),
    ProcessNameTooLong {
        rule_name: String,
        pattern: String,
        min_length: usize,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Pattern(e) => write!(f, "invalid glob: {}", e),
            PolicyError::UnknownUser(name) => write!(f, "unknown user: {}", name),
            PolicyError::UnknownGroupField(name) => write!(f, "unknown group_by field: {}", name),
            PolicyError::ProcessNameTooLong {
                rule_name,
                pattern,
                min_length,
            } => write!(
                f,
                "rule {} process_name pattern {:?} needs at least {} chars to match, \
                 but the kernel truncates `comm` to {} bytes — this pattern can never match",
                rule_name, pattern, min_length, COMM_MAX_LEN,
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<glob::PatternError> for PolicyError {
    fn from(value: glob::PatternError) -> Self {
        PolicyError::Pattern(value)
    }
}

impl Policy {
    pub fn from_config(config: &Config) -> Result<Self, PolicyError> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for named in &config.rules {
            rules.push(CompiledRule::from_rule(&named.name, &named.rule)?);
        }
        Ok(Policy { rules })
    }

    pub fn needs_journal(&self) -> bool {
        self.rules.iter().any(|r| r.needs_journal)
    }

    pub fn first_match(
        &self,
        dump: &CoredumpFile,
        context: &JournalContext,
    ) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.matches(dump, context))
    }
}

impl CompiledRule {
    fn from_rule(name: &str, rule: &crate::config::Rule) -> Result<Self, PolicyError> {
        for pattern in &rule.process_name {
            let min = glob_min_match_length(pattern);
            if min > COMM_MAX_LEN {
                return Err(PolicyError::ProcessNameTooLong {
                    rule_name: name.to_string(),
                    pattern: pattern.clone(),
                    min_length: min,
                });
            }
        }
        let process_name = compile_globs(&rule.process_name)?;
        let executable_path = compile_globs(&rule.executable_path)?;
        let command_line = compile_globs(&rule.command_line)?;

        let mut user_ids = rule.user_id.clone();
        for name in &rule.user_name {
            let uid = resolve_user_name(name).ok_or_else(|| PolicyError::UnknownUser(name.clone()))?;
            user_ids.push(uid);
        }
        user_ids.sort_unstable();
        user_ids.dedup();

        let mut group_by = Vec::with_capacity(rule.group_by.len());
        for field in &rule.group_by {
            group_by.push(
                GroupField::parse(field).ok_or_else(|| PolicyError::UnknownGroupField(field.clone()))?,
            );
        }

        let needs_journal = !executable_path.is_empty()
            || !command_line.is_empty()
            || !rule.signal.is_empty()
            || group_by.iter().any(|f| f.needs_journal());

        Ok(CompiledRule {
            name: name.to_string(),
            process_name,
            executable_path,
            command_line,
            signal: rule.signal.clone(),
            user_ids,
            group_by,
            keep_count: rule.keep_count,
            needs_journal,
            is_unconstrained: rule.is_empty(),
        })
    }

    pub fn matches(&self, dump: &CoredumpFile, context: &JournalContext) -> bool {
        if self.is_unconstrained {
            return true;
        }
        if !self.process_name.is_empty()
            && !self.process_name.iter().any(|p| p.matches(&dump.comm))
        {
            return false;
        }
        if !self.user_ids.is_empty() && !self.user_ids.contains(&dump.uid) {
            return false;
        }
        if !self.executable_path.is_empty() {
            let exe = match &context.executable_path {
                Some(s) => s.as_str(),
                None => return false,
            };
            if !self.executable_path.iter().any(|p| p.matches(exe)) {
                return false;
            }
        }
        if !self.command_line.is_empty() {
            let cmd = match &context.command_line {
                Some(s) => s.as_str(),
                None => return false,
            };
            if !self.command_line.iter().any(|p| p.matches(cmd)) {
                return false;
            }
        }
        if !self.signal.is_empty() {
            let sig = match &context.signal {
                Some(s) => s.as_str(),
                None => return false,
            };
            if !self.signal.iter().any(|s| s == sig) {
                return false;
            }
        }
        true
    }
}

fn compile_globs(patterns: &[String]) -> Result<Vec<glob::Pattern>, glob::PatternError> {
    patterns.iter().map(|p| glob::Pattern::new(p)).collect()
}

/// Minimum number of input characters a glob pattern must consume to match.
/// `*` contributes 0; `?` and character classes contribute 1; literals
/// contribute 1; `\<x>` is one literal character.
fn glob_min_match_length(pattern: &str) -> usize {
    let mut count = 0;
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '*' => {}
            '?' => count += 1,
            '\\' => {
                if chars.next().is_some() {
                    count += 1;
                }
            }
            '[' => {
                count += 1;
                for c in chars.by_ref() {
                    if c == ']' {
                        break;
                    }
                }
            }
            _ => count += 1,
        }
    }
    count
}

fn resolve_user_name(name: &str) -> Option<u32> {
    let cstring = std::ffi::CString::new(name).ok()?;
    let pwd = unsafe { libc::getpwnam(cstring.as_ptr()) };
    if pwd.is_null() {
        None
    } else {
        Some(unsafe { (*pwd).pw_uid })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NamedRule, Rule};
    use std::path::PathBuf;
    use std::time::Duration;

    fn dump(comm: &str, uid: u32) -> CoredumpFile {
        CoredumpFile {
            path: PathBuf::from(format!("/tmp/{}", comm)),
            comm: comm.to_string(),
            uid,
            boot_id: "0".repeat(32),
            pid: 1,
            timestamp_micros: 0,
            extension: None,
        }
    }

    fn config_with(rules: Vec<NamedRule>) -> Config {
        Config {
            coredump_directory: PathBuf::from("/var/lib/systemd/coredump"),
            idle_interval: Duration::from_secs(300),
            minimum_age: Duration::from_secs(30),
            dry_run: false,
            rules,
        }
    }

    fn rule(name: &str) -> NamedRule {
        NamedRule {
            name: name.to_string(),
            rule: Rule::default(),
        }
    }

    #[test]
    fn first_rule_wins() {
        let mut a = rule("a");
        a.rule.process_name = vec!["foo".into()];
        let mut b = rule("b");
        b.rule.process_name = vec!["foo".into()];

        let p = Policy::from_config(&config_with(vec![a, b])).unwrap();
        let m = p.first_match(&dump("foo", 0), &JournalContext::default()).unwrap();
        assert_eq!(m.name, "a");
    }

    #[test]
    fn unconstrained_rule_matches_everything() {
        let p = Policy::from_config(&config_with(vec![rule("catch_all")])).unwrap();
        assert!(
            p.first_match(&dump("anything", 999), &JournalContext::default())
                .is_some()
        );
    }

    #[test]
    fn fields_combine_with_and() {
        let mut r = rule("strict");
        r.rule.process_name = vec!["myapp".into()];
        r.rule.user_id = vec![1000];
        let p = Policy::from_config(&config_with(vec![r])).unwrap();
        assert!(p.first_match(&dump("myapp", 1000), &JournalContext::default()).is_some());
        assert!(p.first_match(&dump("myapp", 999), &JournalContext::default()).is_none());
        assert!(p.first_match(&dump("other", 1000), &JournalContext::default()).is_none());
    }

    #[test]
    fn array_within_field_is_or() {
        let mut r = rule("either");
        r.rule.process_name = vec!["a".into(), "b".into()];
        let p = Policy::from_config(&config_with(vec![r])).unwrap();
        assert!(p.first_match(&dump("a", 0), &JournalContext::default()).is_some());
        assert!(p.first_match(&dump("b", 0), &JournalContext::default()).is_some());
        assert!(p.first_match(&dump("c", 0), &JournalContext::default()).is_none());
    }

    #[test]
    fn executable_path_requires_journal_data() {
        let mut r = rule("by_exe");
        r.rule.executable_path = vec!["/opt/foo/*".into()];
        let p = Policy::from_config(&config_with(vec![r])).unwrap();
        assert!(p.needs_journal());

        let ctx_with = JournalContext {
            executable_path: Some("/opt/foo/bin/x".into()),
            ..JournalContext::default()
        };
        assert!(p.first_match(&dump("anything", 0), &ctx_with).is_some());
        assert!(p.first_match(&dump("anything", 0), &JournalContext::default()).is_none());
    }

    #[test]
    fn signal_match_is_exact() {
        let mut r = rule("sig");
        r.rule.signal = vec!["SIGSEGV".into()];
        let p = Policy::from_config(&config_with(vec![r])).unwrap();
        let ctx = JournalContext {
            signal: Some("SIGSEGV".into()),
            ..JournalContext::default()
        };
        assert!(p.first_match(&dump("x", 0), &ctx).is_some());
        let ctx_other = JournalContext {
            signal: Some("SIGABRT".into()),
            ..JournalContext::default()
        };
        assert!(p.first_match(&dump("x", 0), &ctx_other).is_none());
    }

    #[test]
    fn user_name_resolves_to_uid() {
        let mut r = rule("by_user");
        r.rule.user_name = vec!["root".into()];
        let p = Policy::from_config(&config_with(vec![r])).unwrap();
        assert!(p.rules[0].user_ids.contains(&0));
    }

    #[test]
    fn glob_min_match_length_basics() {
        assert_eq!(glob_min_match_length("myapp"), 5);
        assert_eq!(glob_min_match_length("my*"), 2);
        assert_eq!(glob_min_match_length("*app"), 3);
        assert_eq!(glob_min_match_length("my?"), 3);
        assert_eq!(glob_min_match_length("my[xyz]"), 3);
        assert_eq!(glob_min_match_length("my\\*"), 3);
        assert_eq!(glob_min_match_length("a*b*c*d"), 4);
    }

    #[test]
    fn over_long_process_name_is_rejected() {
        let mut r = rule("too-long");
        r.rule.process_name = vec!["this-name-is-definitely-too-long".to_string()];
        let err = Policy::from_config(&config_with(vec![r])).unwrap_err();
        assert!(matches!(err, PolicyError::ProcessNameTooLong { .. }));
    }

    #[test]
    fn over_long_with_trailing_wildcard_still_rejected() {
        let mut r = rule("prefix-long");
        // 22 literal chars + "*" — the literal prefix alone exceeds 15
        r.rule.process_name = vec!["gnome-shell-extension-*".to_string()];
        let err = Policy::from_config(&config_with(vec![r])).unwrap_err();
        assert!(matches!(err, PolicyError::ProcessNameTooLong { .. }));
    }

    #[test]
    fn fifteen_char_pattern_is_accepted() {
        let mut r = rule("at-limit");
        r.rule.process_name = vec!["a".repeat(15)];
        assert!(Policy::from_config(&config_with(vec![r])).is_ok());
    }

    #[test]
    fn unknown_user_is_an_error() {
        let mut r = rule("bad");
        r.rule.user_name = vec!["definitely-not-a-real-user-12345".into()];
        let err = Policy::from_config(&config_with(vec![r])).unwrap_err();
        assert!(matches!(err, PolicyError::UnknownUser(_)));
    }
}
