use std::os::unix::net::UnixDatagram;
use std::path::Path;

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
