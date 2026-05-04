use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use inotify::{Inotify, WatchMask};
use log::{debug, error, info, warn};
use signal_hook::consts::*;
use signal_hook::iterator::Signals;

use crate::config::Config;
use crate::policy::Policy;
use crate::scan::{ScanReport, Scanner};
use crate::sd;

enum Event {
    Inotify,
    InotifyFailed,
    Reload,
    ScanNow,
    Term,
}

pub fn run(config_path: PathBuf) -> std::io::Result<()> {
    let mut config = load_or_die(&config_path)?;
    let mut policy = build_policy(&config)?;

    let inotify = Inotify::init()?;
    inotify
        .watches()
        .add(
            &config.coredump_directory,
            WatchMask::CREATE | WatchMask::MOVED_TO | WatchMask::CLOSE_WRITE,
        )?;

    info!("watching {}", config.coredump_directory.display());
    sd::ready();

    log_report(&Scanner {
        config: &config,
        policy: &policy,
    }
    .scan());

    let (tx, rx) = mpsc::channel::<Event>();

    let signal_tx = tx.clone();
    let mut signals = Signals::new([SIGHUP, SIGUSR1, SIGTERM, SIGINT])?;
    let _signal_handle = thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            for sig in signals.forever() {
                let event = match sig {
                    SIGHUP => Event::Reload,
                    SIGUSR1 => Event::ScanNow,
                    SIGTERM | SIGINT => Event::Term,
                    _ => continue,
                };
                let terminating = matches!(event, Event::Term);
                if signal_tx.send(event).is_err() {
                    break;
                }
                if terminating {
                    break;
                }
            }
        })?;

    let inotify_tx = tx.clone();
    let _inotify_handle = thread::Builder::new()
        .name("inotify".into())
        .spawn(move || {
            let mut inotify = inotify;
            let mut buf = vec![0u8; 4096];
            loop {
                match inotify.read_events_blocking(&mut buf) {
                    Ok(events) => {
                        let count = events.count();
                        debug!("inotify: {} event(s)", count);
                        if inotify_tx.send(Event::Inotify).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("inotify read: {}", e);
                        let _ = inotify_tx.send(Event::InotifyFailed);
                        break;
                    }
                }
            }
        })?;

    drop(tx);

    let watchdog_interval = sd::watchdog_interval();
    let mut last_scan = Instant::now();

    loop {
        let timeout = next_wakeup(config.idle_interval, last_scan, watchdog_interval);
        let event = match rx.recv_timeout(timeout) {
            Ok(e) => Some(e),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                warn!("event channel closed; exiting");
                break;
            }
        };

        sd::watchdog();

        match event {
            Some(Event::Term) => {
                info!("shutting down");
                sd::stopping();
                break;
            }
            Some(Event::Reload) => {
                info!("reloading config from {}", config_path.display());
                match Config::load(&config_path) {
                    Ok(new) => match Policy::from_config(&new) {
                        Ok(new_policy) => {
                            if new.coredump_directory != config.coredump_directory {
                                warn!(
                                    "coredump_directory change requires restart: still watching {}",
                                    config.coredump_directory.display()
                                );
                            }
                            config = new;
                            policy = new_policy;
                            sd::status("config reloaded");
                        }
                        Err(e) => error!("reload: invalid policy: {}", e),
                    },
                    Err(e) => error!("reload failed: {}", e),
                }
            }
            Some(Event::Inotify) | Some(Event::ScanNow) => {
                let report = Scanner {
                    config: &config,
                    policy: &policy,
                }
                .scan();
                log_report(&report);
                last_scan = Instant::now();
            }
            Some(Event::InotifyFailed) => {
                error!("inotify thread exited; daemon cannot continue without it");
                sd::stopping();
                return Err(std::io::Error::other("inotify thread failed"));
            }
            None => {
                if last_scan.elapsed() >= config.idle_interval {
                    let report = Scanner {
                        config: &config,
                        policy: &policy,
                    }
                    .scan();
                    log_report(&report);
                    last_scan = Instant::now();
                }
            }
        }
    }

    Ok(())
}

fn next_wakeup(
    idle_interval: Duration,
    last_scan: Instant,
    watchdog_interval: Option<Duration>,
) -> Duration {
    let until_scan = idle_interval.saturating_sub(last_scan.elapsed());
    let candidate = match watchdog_interval {
        Some(wd) => wd.min(until_scan),
        None => until_scan,
    };
    candidate.max(Duration::from_millis(100))
}

fn load_or_die(path: &Path) -> std::io::Result<Config> {
    Config::load(path).map_err(std::io::Error::other)
}

fn build_policy(config: &Config) -> std::io::Result<Policy> {
    Policy::from_config(config).map_err(std::io::Error::other)
}

fn log_report(report: &ScanReport) {
    for (p, e) in &report.errors {
        error!("scan error {}: {}", p.display(), e);
    }
    debug!(
        "scan: kept={} removed={} would_remove={} too_young={} unparseable={} errors={}",
        report.kept.len(),
        report.removed.len(),
        report.would_remove.len(),
        report.too_young.len(),
        report.unparseable.len(),
        report.errors.len()
    );
}
