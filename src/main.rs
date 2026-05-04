#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use log::{error, warn};

use cdgcd::config::Config;
use cdgcd::dump::{CoredumpFile, ParseError};
use cdgcd::policy::Policy;
use cdgcd::retain;
use cdgcd::scan::{self, Classified, Scanner};
use cdgcd::{daemon, journal};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(long, default_value = "/etc/cdgcd.toml")]
    configuration_file: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the daemon (default if no subcommand given)
    Run,
    /// One-shot scan; exits non-zero if anything was deleted
    Scan,
    /// Print per-dump decision without acting
    Check,
}

fn main() -> ExitCode {
    env_logger::init();

    let args = Args::parse();

    let result = match args.command.unwrap_or(Command::Run) {
        Command::Run => cmd_run(&args.configuration_file),
        Command::Scan => cmd_scan(&args.configuration_file),
        Command::Check => cmd_check(&args.configuration_file),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            error!("{}", e);
            ExitCode::from(2)
        }
    }
}

fn cmd_run(configuration_file: &Path) -> std::io::Result<ExitCode> {
    let config = load_config(configuration_file)?;
    if config.rules.is_empty() {
        warn!(
            "no rules in {}; daemon would delete every dump",
            configuration_file.display()
        );
        return Err(std::io::Error::other(
            "refusing to run with no rules; define at least one [rules.<name>] section",
        ));
    }
    daemon::run(configuration_file.to_path_buf())?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_scan(configuration_file: &Path) -> std::io::Result<ExitCode> {
    let config = load_config(configuration_file)?;
    let policy = build_policy(&config)?;
    let scanner = Scanner {
        config: &config,
        policy: &policy,
    };
    let report = scanner.scan();
    for (p, e) in &report.errors {
        error!("{}: {}", p.display(), e);
    }
    let removed = report.removed.len() + report.would_remove.len();
    println!(
        "kept={} removed={} would_remove={} too_young={} unparseable={} errors={}",
        report.kept.len(),
        report.removed.len(),
        report.would_remove.len(),
        report.too_young.len(),
        report.unparseable.len(),
        report.errors.len()
    );
    if !report.errors.is_empty() {
        Ok(ExitCode::from(2))
    } else if removed > 0 {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn cmd_check(configuration_file: &Path) -> std::io::Result<ExitCode> {
    let config = load_config(configuration_file)?;
    let policy = build_policy(&config)?;
    let now = SystemTime::now();

    let mut classified: Vec<Classified> = Vec::new();
    let mut markers: std::collections::HashSet<std::ffi::OsString> =
        std::collections::HashSet::new();
    let mut candidate_entries: Vec<std::fs::DirEntry> = Vec::new();
    let entries = std::fs::read_dir(&config.coredump_directory)?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                error!("readdir: {}", e);
                continue;
            }
        };
        if let Some(name) = retain::dump_name_for_marker(&entry.file_name()) {
            markers.insert(std::ffi::OsString::from(name));
        } else {
            candidate_entries.push(entry);
        }
    }
    for entry in candidate_entries {
        let path = entry.path();
        let dump = match CoredumpFile::from_path(&path) {
            Ok(d) => d,
            Err(ParseError::NotACoredump) => continue,
            Err(ParseError::BadField(field)) => {
                println!("{}\tBAD\tfield={}", path.display(), field);
                continue;
            }
        };
        let too_young = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|m| now.duration_since(m).ok())
            .is_some_and(|age| age < config.minimum_age);
        if too_young {
            println!(
                "{}\tTOO_YOUNG\tprocess_name={}",
                dump.path.display(),
                dump.comm
            );
            continue;
        }
        let retained = markers.contains(&entry.file_name());
        let (rule_index, journal_context) = if retained {
            (None, journal::JournalContext::default())
        } else {
            scan::classify(&policy, &dump)
        };
        classified.push(Classified {
            dump,
            rule_index,
            journal_context,
            retained,
        });
    }

    let over_cap = scan::compute_keep_count_excess(&policy, &classified);

    for (i, c) in classified.iter().enumerate() {
        if c.retained {
            println!(
                "{}\tKEEP\tprocess_name={}\treason=Retained",
                c.dump.path.display(),
                c.dump.comm
            );
            continue;
        }
        match c.rule_index {
            None => println!(
                "{}\tREMOVE\tprocess_name={}\treason=NoRuleMatched",
                c.dump.path.display(),
                c.dump.comm
            ),
            Some(idx) => {
                let rule = &policy.rules[idx];
                if over_cap.contains(&i) {
                    println!(
                        "{}\tREMOVE\tprocess_name={}\treason=KeepCountExceeded\trule={}\tkeep_count={}",
                        c.dump.path.display(),
                        c.dump.comm,
                        rule.name,
                        rule.keep_count.unwrap_or(0)
                    );
                } else {
                    println!(
                        "{}\tKEEP\tprocess_name={}\trule={}",
                        c.dump.path.display(),
                        c.dump.comm,
                        rule.name
                    );
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn load_config(path: &Path) -> std::io::Result<Config> {
    Config::load(path).map_err(std::io::Error::other)
}

fn build_policy(config: &Config) -> std::io::Result<Policy> {
    Policy::from_config(config).map_err(std::io::Error::other)
}
