use std::path::Path;
use std::process::Command;

pub fn lookup_executable_path(coredump_path: &Path) -> Option<String> {
    let filter = format!("COREDUMP_FILENAME={}", coredump_path.display());
    let output = Command::new("journalctl")
        .args([
            "--quiet",
            "--no-pager",
            "--lines=1",
            "--output=cat",
            "--output-fields=COREDUMP_EXE",
        ])
        .arg(&filter)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = std::str::from_utf8(&output.stdout).ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}
