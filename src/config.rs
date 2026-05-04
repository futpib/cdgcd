use std::path::{Path, PathBuf};
use std::time::Duration;

use toml::Value;
use toml::value::Table;

#[derive(Debug, Clone)]
pub struct Config {
    pub coredump_directory: PathBuf,
    pub idle_interval: Duration,
    pub minimum_age: Duration,
    pub dry_run: bool,
    pub rules: Vec<NamedRule>,
}

#[derive(Debug, Clone)]
pub struct NamedRule {
    pub name: String,
    pub rule: Rule,
}

#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub process_name: Vec<String>,
    pub executable_path: Vec<String>,
    pub command_line: Vec<String>,
    pub signal: Vec<String>,
    pub user_id: Vec<u32>,
    pub user_name: Vec<String>,
    pub group_by: Vec<String>,
    pub keep_count: Option<u32>,
}

const TOP_LEVEL_KEYS: &[&str] = &[
    "coredump_directory",
    "idle_interval",
    "minimum_age",
    "dry_run",
    "rules",
];

const RULE_KEYS: &[&str] = &[
    "process_name",
    "executable_path",
    "command_line",
    "signal",
    "user_id",
    "user_name",
    "group_by",
    "keep_count",
];

pub const GROUP_BY_FIELDS: &[&str] = &[
    "process_name",
    "executable_path",
    "command_line",
    "signal",
    "user_id",
    "boot_id",
];

const DEFAULT_RULE_NAME: &str = "DEFAULT";

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let s = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        Self::parse(&s).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let value: Value = toml::from_str(s).map_err(|e| e.to_string())?;
        let table = value
            .as_table()
            .ok_or_else(|| "top level must be a table".to_string())?;

        check_known(table, TOP_LEVEL_KEYS, "top-level")?;

        let coredump_directory = parse_string(table, "coredump_directory")?
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/systemd/coredump"));
        let idle_interval = parse_duration(table, "idle_interval")?
            .unwrap_or_else(|| Duration::from_secs(5 * 60));
        let minimum_age =
            parse_duration(table, "minimum_age")?.unwrap_or_else(|| Duration::from_secs(30));
        let dry_run = parse_bool(table, "dry_run")?.unwrap_or(false);

        let mut rules = Vec::new();
        let mut default_rule = Rule::default();
        let mut has_default = false;

        if let Some(rules_value) = table.get("rules") {
            let rules_table = rules_value
                .as_table()
                .ok_or_else(|| "rules must be a table".to_string())?;
            if let Some(default_value) = rules_table.get(DEFAULT_RULE_NAME) {
                let default_table = default_value
                    .as_table()
                    .ok_or_else(|| "rules.DEFAULT must be a table".to_string())?;
                default_rule = parse_rule(default_table)
                    .map_err(|e| format!("rules.DEFAULT: {}", e))?;
                has_default = true;
            }
            for (name, rule_value) in rules_table {
                if name == DEFAULT_RULE_NAME {
                    continue;
                }
                let rule_table = rule_value
                    .as_table()
                    .ok_or_else(|| format!("rules.{} must be a table", name))?;
                let rule = parse_rule(rule_table)
                    .map_err(|e| format!("rules.{}: {}", name, e))?
                    .merge_default(&default_rule);
                rules.push(NamedRule {
                    name: name.clone(),
                    rule,
                });
            }
        }

        if has_default {
            rules.push(NamedRule {
                name: DEFAULT_RULE_NAME.to_string(),
                rule: default_rule,
            });
        }

        Ok(Config {
            coredump_directory,
            idle_interval,
            minimum_age,
            dry_run,
            rules,
        })
    }
}

impl Rule {
    fn merge_default(self, default: &Rule) -> Rule {
        Rule {
            process_name: pick(self.process_name, &default.process_name),
            executable_path: pick(self.executable_path, &default.executable_path),
            command_line: pick(self.command_line, &default.command_line),
            signal: pick(self.signal, &default.signal),
            user_id: pick_u32(self.user_id, &default.user_id),
            user_name: pick(self.user_name, &default.user_name),
            group_by: pick(self.group_by, &default.group_by),
            keep_count: self.keep_count.or(default.keep_count),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.process_name.is_empty()
            && self.executable_path.is_empty()
            && self.command_line.is_empty()
            && self.signal.is_empty()
            && self.user_id.is_empty()
            && self.user_name.is_empty()
    }

    pub fn needs_journal(&self) -> bool {
        !self.executable_path.is_empty()
            || !self.command_line.is_empty()
            || !self.signal.is_empty()
    }
}

fn pick(own: Vec<String>, default: &[String]) -> Vec<String> {
    if own.is_empty() {
        default.to_vec()
    } else {
        own
    }
}

fn pick_u32(own: Vec<u32>, default: &[u32]) -> Vec<u32> {
    if own.is_empty() {
        default.to_vec()
    } else {
        own
    }
}

fn parse_rule(table: &Table) -> Result<Rule, String> {
    check_known(table, RULE_KEYS, "rule")?;
    let group_by = parse_string_vec(table, "group_by")?;
    for field in &group_by {
        if !GROUP_BY_FIELDS.contains(&field.as_str()) {
            return Err(format!(
                "group_by: unknown field {:?} (allowed: {})",
                field,
                GROUP_BY_FIELDS.join(", ")
            ));
        }
    }
    Ok(Rule {
        process_name: parse_string_vec(table, "process_name")?,
        executable_path: parse_string_vec(table, "executable_path")?,
        command_line: parse_string_vec(table, "command_line")?,
        signal: parse_string_vec(table, "signal")?,
        user_id: parse_u32_vec(table, "user_id")?,
        user_name: parse_string_vec(table, "user_name")?,
        group_by,
        keep_count: parse_u32(table, "keep_count")?,
    })
}

fn check_known(table: &Table, known: &[&str], context: &str) -> Result<(), String> {
    for key in table.keys() {
        if !known.contains(&key.as_str()) {
            return Err(format!("unknown {} field: {}", context, key));
        }
    }
    Ok(())
}

fn parse_string(table: &Table, key: &str) -> Result<Option<String>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("{} must be a string", key)),
    }
}

fn parse_bool(table: &Table, key: &str) -> Result<Option<bool>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::Boolean(b)) => Ok(Some(*b)),
        Some(_) => Err(format!("{} must be a boolean", key)),
    }
}

fn parse_duration(table: &Table, key: &str) -> Result<Option<Duration>, String> {
    match parse_string(table, key)? {
        None => Ok(None),
        Some(s) => humantime::parse_duration(&s)
            .map(Some)
            .map_err(|e| format!("{}: {}", key, e)),
    }
}

fn parse_u32(table: &Table, key: &str) -> Result<Option<u32>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::Integer(n)) => u32::try_from(*n)
            .map(Some)
            .map_err(|_| format!("{} out of range", key)),
        Some(_) => Err(format!("{} must be an integer", key)),
    }
}

fn parse_string_vec(table: &Table, key: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| format!("{}: items must be strings", key))
            })
            .collect(),
        Some(_) => Err(format!("{} must be an array", key)),
    }
}

fn parse_u32_vec(table: &Table, key: &str) -> Result<Vec<u32>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_integer()
                    .ok_or_else(|| format!("{}: items must be integers", key))
                    .and_then(|n| {
                        u32::try_from(n).map_err(|_| format!("{}: {} out of range", key, n))
                    })
            })
            .collect(),
        Some(_) => Err(format!("{} must be an array", key)),
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(PathBuf, std::io::Error),
    Parse(PathBuf, String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(p, e) => write!(f, "read {}: {}", p.display(), e),
            ConfigError::Parse(p, e) => write!(f, "parse {}: {}", p.display(), e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let cfg = Config::parse(
            r#"
coredump_directory = "/tmp/dumps"
idle_interval = "1m"
minimum_age = "10s"
dry_run = true

[rules.myapp]
process_name = ["myapp"]
keep_count = 10
"#,
        )
        .unwrap();
        assert_eq!(cfg.coredump_directory, PathBuf::from("/tmp/dumps"));
        assert_eq!(cfg.idle_interval, Duration::from_secs(60));
        assert_eq!(cfg.minimum_age, Duration::from_secs(10));
        assert!(cfg.dry_run);
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].name, "myapp");
        assert_eq!(cfg.rules[0].rule.process_name, vec!["myapp".to_string()]);
        assert_eq!(cfg.rules[0].rule.keep_count, Some(10));
    }

    #[test]
    fn applies_defaults_when_empty() {
        let cfg = Config::parse("").unwrap();
        assert_eq!(
            cfg.coredump_directory,
            PathBuf::from("/var/lib/systemd/coredump")
        );
        assert_eq!(cfg.idle_interval, Duration::from_secs(300));
        assert_eq!(cfg.minimum_age, Duration::from_secs(30));
        assert!(!cfg.dry_run);
        assert!(cfg.rules.is_empty());
    }

    #[test]
    fn rules_preserve_source_order() {
        let cfg = Config::parse(
            r#"
[rules.zebra]
process_name = ["z"]

[rules.alpha]
process_name = ["a"]

[rules.middle]
process_name = ["m"]
"#,
        )
        .unwrap();
        let names: Vec<&str> = cfg.rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["zebra", "alpha", "middle"]);
    }

    #[test]
    fn merges_default_into_each_rule() {
        let cfg = Config::parse(
            r#"
[rules.DEFAULT]
user_id = [1000]
keep_count = 5

[rules.myapp]
process_name = ["myapp"]

[rules.override]
process_name = ["other"]
user_id = [42]
keep_count = 1
"#,
        )
        .unwrap();
        let myapp = cfg.rules.iter().find(|r| r.name == "myapp").unwrap();
        assert_eq!(myapp.rule.user_id, vec![1000]);
        assert_eq!(myapp.rule.keep_count, Some(5));

        let over = cfg.rules.iter().find(|r| r.name == "override").unwrap();
        assert_eq!(over.rule.user_id, vec![42]);
        assert_eq!(over.rule.keep_count, Some(1));
    }

    #[test]
    fn rejects_unknown_top_level() {
        assert!(Config::parse("nonsense_field = 1").is_err());
    }

    #[test]
    fn rejects_unknown_rule_field() {
        assert!(Config::parse("[rules.foo]\nbogus = 1").is_err());
    }

    #[test]
    fn group_by_field_must_be_known() {
        let err = Config::parse("[rules.foo]\ngroup_by = [\"bogus\"]\n").unwrap_err();
        assert!(err.contains("group_by"));
    }

    #[test]
    fn group_by_inherits_from_default() {
        let cfg = Config::parse(
            r#"
[rules.DEFAULT]
group_by = ["process_name"]
keep_count = 3

[rules.foo]
process_name = ["foo"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.rules[0].rule.group_by, vec!["process_name".to_string()]);
        assert_eq!(cfg.rules[0].rule.keep_count, Some(3));
    }

    #[test]
    fn default_section_is_appended_as_a_catch_all_rule() {
        let cfg = Config::parse(
            r#"
[rules.DEFAULT]
keep_count = 5
"#,
        )
        .unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].name, "DEFAULT");
        assert_eq!(cfg.rules[0].rule.keep_count, Some(5));
    }

    #[test]
    fn default_appended_after_named_rules() {
        let cfg = Config::parse(
            r#"
[rules.DEFAULT]
keep_count = 5

[rules.specific]
process_name = ["foo"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].name, "specific");
        assert_eq!(cfg.rules[1].name, "DEFAULT");
    }

    #[test]
    fn no_default_section_means_no_catch_all() {
        let cfg = Config::parse(
            r#"
[rules.foo]
process_name = ["foo"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.rules.len(), 1);
        assert_eq!(cfg.rules[0].name, "foo");
    }

    #[test]
    fn parses_keep_count_from_default_only() {
        let cfg = Config::parse(
            r#"
[rules.DEFAULT]
keep_count = 3

[rules.foo]
process_name = ["foo"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.rules[0].rule.keep_count, Some(3));
    }
}
