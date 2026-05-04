use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use cdgcd::config::Config;
use cdgcd::dump::CoredumpFile;
use cdgcd::retain;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(long, default_value = "/etc/cdgcd.toml")]
    configuration_file: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Mark a coredump as retained so cdgcd will not delete it.
    /// Without an argument, picks the most recent dump in the coredump
    /// directory.
    Retain {
        /// Coredump filename or path. If just a filename, it is looked up
        /// inside the configured coredump directory.
        coredump: Option<String>,
    },
}

fn main() -> ExitCode {
    env_logger::init();
    let args = Args::parse();
    let config = match Config::load(&args.configuration_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {}", e);
            return ExitCode::from(2);
        }
    };

    match args.command {
        Command::Retain { coredump } => match cmd_retain(&config, coredump.as_deref()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(CmdError::PermissionDenied) => ExitCode::from(1),
            Err(CmdError::NoDumps) => {
                eprintln!("no coredumps found in {}", config.coredump_directory.display());
                ExitCode::from(1)
            }
            Err(CmdError::Io(msg)) => {
                eprintln!("{}", msg);
                ExitCode::from(1)
            }
        },
    }
}

enum CmdError {
    PermissionDenied,
    NoDumps,
    Io(String),
}

fn cmd_retain(config: &Config, coredump_arg: Option<&str>) -> Result<(), CmdError> {
    let dump_path = resolve_dump_path(config, coredump_arg)?;
    let marker_path = retain::marker_path(&dump_path);

    if !dump_path.exists() {
        return Err(CmdError::Io(format!(
            "{} does not exist",
            dump_path.display()
        )));
    }

    match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&marker_path)
    {
        Ok(_) => {
            println!("retained {}", dump_path.display());
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            print_sudo_hints(&dump_path, &marker_path);
            Err(CmdError::PermissionDenied)
        }
        Err(e) => Err(CmdError::Io(format!(
            "create {}: {}",
            marker_path.display(),
            e
        ))),
    }
}

fn resolve_dump_path(config: &Config, arg: Option<&str>) -> Result<PathBuf, CmdError> {
    match arg {
        None => find_most_recent(&config.coredump_directory),
        Some(s) => {
            let path = Path::new(s);
            if path.is_absolute() {
                Ok(path.to_path_buf())
            } else if path.parent().is_some_and(|p| !p.as_os_str().is_empty()) {
                Ok(std::env::current_dir()
                    .map(|d| d.join(path))
                    .unwrap_or_else(|_| path.to_path_buf()))
            } else {
                Ok(config.coredump_directory.join(path))
            }
        }
    }
}

fn find_most_recent(directory: &Path) -> Result<PathBuf, CmdError> {
    let entries = std::fs::read_dir(directory)
        .map_err(|e| CmdError::Io(format!("read {}: {}", directory.display(), e)))?;
    let mut best: Option<CoredumpFile> = None;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Ok(dump) = CoredumpFile::from_path(&path) else {
            continue;
        };
        match &best {
            None => best = Some(dump),
            Some(b) if dump.timestamp_micros > b.timestamp_micros => best = Some(dump),
            _ => {}
        }
    }
    best.map(|d| d.path).ok_or(CmdError::NoDumps)
}

fn print_sudo_hints(dump_path: &Path, marker_path: &Path) {
    let dump_filename = dump_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| dump_path.display().to_string());
    eprintln!(
        "permission denied creating {}; try one of:",
        marker_path.display()
    );
    eprintln!("    sudo cdgcctl retain {}", dump_filename);
    eprintln!("    sudo touch {}", marker_path.display());
}
