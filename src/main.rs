pub mod config;
pub mod daemon;
pub mod dump;
pub mod journal;
pub mod policy;
pub mod scan;
pub mod sd;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use clap::{Parser, Subcommand};
use log::{error, warn};

use crate::config::Config;
use crate::dump::{CoredumpFile, ParseError};
use crate::policy::{Decision, Policy};
use crate::scan::Scanner;

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
    if !has_rules(&config) {
        warn!(
            "no allow_process_name or allow_executable_path rules in {}; daemon would delete every dump",
            configuration_file.display()
        );
        return Err(std::io::Error::other(
            "refusing to run with no allow rules; set allow_process_name or allow_executable_path in configuration",
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

    let entries = std::fs::read_dir(&config.coredump_directory)?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                error!("readdir: {}", e);
                continue;
            }
        };
        let path = entry.path();
        let dump = match CoredumpFile::from_path(&path) {
            Ok(d) => d,
            Err(ParseError::NotACoredump) => continue,
            Err(ParseError::BadField(field)) => {
                println!("{}\tBAD_{}", path.display(), field.to_uppercase());
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
        let executable_path =
            if policy.needs_executable_path() && !policy.matches_process_name(&dump.comm) {
                journal::lookup_executable_path(&dump.path)
            } else {
                None
            };
        match policy.evaluate(&dump, executable_path.as_deref()) {
            Decision::Keep(reason) => println!(
                "{}\tKEEP\tprocess_name={}\texecutable_path={}\treason={:?}",
                dump.path.display(),
                dump.comm,
                executable_path.as_deref().unwrap_or("?"),
                reason
            ),
            Decision::Remove(reason) => println!(
                "{}\tREMOVE\tprocess_name={}\texecutable_path={}\treason={:?}",
                dump.path.display(),
                dump.comm,
                executable_path.as_deref().unwrap_or("?"),
                reason
            ),
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn load_config(path: &Path) -> std::io::Result<Config> {
    Config::load(path).map_err(std::io::Error::other)
}

fn build_policy(config: &Config) -> std::io::Result<Policy> {
    Policy::from_config(config)
        .map_err(|e| std::io::Error::other(format!("invalid pattern: {}", e)))
}

fn has_rules(config: &Config) -> bool {
    !config.allow_process_name.is_empty() || !config.allow_executable_path.is_empty()
}
