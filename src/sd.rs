use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Duration;

pub fn notify(message: &str) -> std::io::Result<()> {
    let socket_path = match std::env::var_os("NOTIFY_SOCKET") {
        Some(p) => p,
        None => return Ok(()),
    };
    let path = Path::new(&socket_path);
    let socket = UnixDatagram::unbound()?;
    socket.send_to(message.as_bytes(), path)?;
    Ok(())
}

pub fn ready() {
    let _ = notify("READY=1\nSTATUS=watching for coredumps\n");
}

pub fn watchdog() {
    let _ = notify("WATCHDOG=1\n");
}

pub fn stopping() {
    let _ = notify("STOPPING=1\n");
}

pub fn status(s: &str) {
    let _ = notify(&format!("STATUS={}\n", s));
}

/// Recommended interval between `WATCHDOG=1` pings, derived from the
/// `WATCHDOG_USEC` env var systemd sets when `WatchdogSec=` is configured.
/// systemd expects pings at least twice per `WatchdogSec=` window, so we
/// halve the value. Returns `None` when the daemon isn't running under a
/// systemd watchdog (env var unset, or `WATCHDOG_PID` mismatch).
pub fn watchdog_interval() -> Option<Duration> {
    let watchdog_pid: u32 = std::env::var("WATCHDOG_PID").ok()?.parse().ok()?;
    if watchdog_pid != std::process::id() {
        return None;
    }
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    Some(Duration::from_micros(usec / 2))
}
