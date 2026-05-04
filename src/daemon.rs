use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use inotify::{Inotify, WatchMask};
use log::{debug, error, info, warn};

use crate::config::Config;
use crate::policy::Policy;
use crate::scan::{ScanReport, Scanner};
use crate::sd;

pub fn run(config_path: PathBuf) -> std::io::Result<()> {
    let mut config = load_or_die(&config_path)?;
    let mut policy = build_policy(&config)?;

    let reload = Arc::new(AtomicBool::new(false));
    let scan_now = Arc::new(AtomicBool::new(false));
    let term = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&reload))?;
    signal_hook::flag::register(signal_hook::consts::SIGUSR1, Arc::clone(&scan_now))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;

    let mut inotify = Inotify::init()?;
    inotify
        .watches()
        .add(
            &config.coredump_directory,
            WatchMask::CREATE | WatchMask::MOVED_TO | WatchMask::CLOSE_WRITE,
        )?;

    info!("watching {}", config.coredump_directory.display());
    sd::ready();

    let initial = run_scan(&config, &policy);
    log_report(&initial);

    let mut buf = vec![0u8; 4096];

    loop {
        if term.load(Ordering::SeqCst) {
            info!("shutting down");
            sd::stopping();
            break;
        }

        if reload.swap(false, Ordering::SeqCst) {
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
                    Err(e) => error!("reload: invalid pattern: {}", e),
                },
                Err(e) => error!("reload failed: {}", e),
            }
        }

        let timeout_ms =
            i32::try_from(config.idle_interval.as_millis()).unwrap_or(i32::MAX);
        let mut pollfd = libc::pollfd {
            fd: inotify.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            error!("poll: {}", err);
            return Err(err);
        }

        sd::watchdog();

        let mut should_scan = false;
        if n == 0 {
            should_scan = true;
        } else if pollfd.revents & libc::POLLIN != 0 {
            match inotify.read_events(&mut buf) {
                Ok(events) => {
                    let count = events.count();
                    debug!("inotify: {} event(s)", count);
                    should_scan = count > 0;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => warn!("inotify read: {}", e),
            }
        }

        if scan_now.swap(false, Ordering::SeqCst) {
            should_scan = true;
        }

        if should_scan {
            let report = run_scan(&config, &policy);
            log_report(&report);
        }
    }

    Ok(())
}

fn load_or_die(path: &Path) -> std::io::Result<Config> {
    Config::load(path).map_err(std::io::Error::other)
}

fn build_policy(config: &Config) -> std::io::Result<Policy> {
    Policy::from_config(config)
        .map_err(|e| std::io::Error::other(format!("invalid pattern: {}", e)))
}

fn run_scan(config: &Config, policy: &Policy) -> ScanReport {
    Scanner { config, policy }.scan()
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
