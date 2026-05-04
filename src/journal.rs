use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct JournalContext {
    pub executable_path: Option<String>,
    pub command_line: Option<String>,
    pub signal: Option<String>,
}

pub fn lookup(coredump_path: &Path) -> JournalContext {
    let filter = format!("COREDUMP_FILENAME={}", coredump_path.display());
    let output = match Command::new("journalctl")
        .args([
            "--quiet",
            "--no-pager",
            "--lines=1",
            "--output=export",
            "--output-fields=COREDUMP_EXE,COREDUMP_CMDLINE,COREDUMP_SIGNAL_NAME",
        ])
        .arg(&filter)
        .output()
    {
        Ok(o) => o,
        Err(_) => return JournalContext::default(),
    };
    if !output.status.success() {
        return JournalContext::default();
    }
    let text = match std::str::from_utf8(&output.stdout) {
        Ok(s) => s,
        Err(_) => return JournalContext::default(),
    };
    parse_export(text)
}

fn parse_export(text: &str) -> JournalContext {
    let mut ctx = JournalContext::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("COREDUMP_EXE=") {
            ctx.executable_path = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("COREDUMP_CMDLINE=") {
            ctx.command_line = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("COREDUMP_SIGNAL_NAME=") {
            ctx.signal = Some(v.to_string());
        }
    }
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_export_format() {
        let text = "\
__CURSOR=ignore
COREDUMP_EXE=/usr/bin/foo
COREDUMP_CMDLINE=/usr/bin/foo --flag value
COREDUMP_SIGNAL_NAME=SIGSEGV
__REALTIME_TIMESTAMP=ignore
";
        let ctx = parse_export(text);
        assert_eq!(ctx.executable_path.as_deref(), Some("/usr/bin/foo"));
        assert_eq!(
            ctx.command_line.as_deref(),
            Some("/usr/bin/foo --flag value")
        );
        assert_eq!(ctx.signal.as_deref(), Some("SIGSEGV"));
    }

    #[test]
    fn missing_fields_remain_none() {
        let ctx = parse_export("__CURSOR=foo\n");
        assert!(ctx.executable_path.is_none());
        assert!(ctx.command_line.is_none());
        assert!(ctx.signal.is_none());
    }
}
