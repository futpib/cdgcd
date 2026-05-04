use std::path::{Path, PathBuf};

/// Maximum printable length of a process name as captured by the kernel.
///
/// `/proc/PID/comm` is truncated to `TASK_COMM_LEN - 1` bytes; on Linux
/// `TASK_COMM_LEN` is 16 (one byte reserved for the trailing NUL — see
/// `include/linux/sched.h`), so the comm value that ends up in the
/// systemd-coredump filename is at most 15 bytes.
pub const COMM_MAX_LEN: usize = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoredumpFile {
    pub path: PathBuf,
    pub comm: String,
    pub uid: u32,
    pub boot_id: String,
    pub pid: u32,
    pub timestamp_micros: u64,
    pub extension: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    NotACoredump,
    BadField(&'static str),
}

impl CoredumpFile {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ParseError> {
        let path = path.as_ref();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(ParseError::NotACoredump)?;
        let mut dump = Self::from_name(name)?;
        dump.path = path.to_path_buf();
        Ok(dump)
    }

    pub fn from_name(name: &str) -> Result<Self, ParseError> {
        let parts: Vec<&str> = name.split('.').collect();
        if !(parts.len() == 6 || parts.len() == 7) {
            return Err(ParseError::NotACoredump);
        }
        if parts[0] != "core" {
            return Err(ParseError::NotACoredump);
        }
        let comm = unescape_comm(parts[1]);
        if comm.is_empty() {
            return Err(ParseError::BadField("comm"));
        }
        let uid: u32 = parts[2].parse().map_err(|_| ParseError::BadField("uid"))?;
        let boot_id = parts[3].to_string();
        if boot_id.len() != 32 || !boot_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError::BadField("boot_id"));
        }
        let pid: u32 = parts[4].parse().map_err(|_| ParseError::BadField("pid"))?;
        let timestamp_micros: u64 = parts[5]
            .parse()
            .map_err(|_| ParseError::BadField("timestamp"))?;
        let extension = parts.get(6).map(|s| s.to_string());
        Ok(CoredumpFile {
            path: PathBuf::from(name),
            comm,
            uid,
            boot_id,
            pid,
            timestamp_micros,
            extension,
        })
    }
}

fn unescape_comm(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 < bytes.len() + 1 && bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            let h1 = bytes[i + 2] as char;
            let h2 = bytes[i + 3] as char;
            if let (Some(d1), Some(d2)) = (h1.to_digit(16), h2.to_digit(16)) {
                out.push(((d1 * 16 + d2) as u8) as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uncompressed() {
        let dump = CoredumpFile::from_name(
            "core.myapp.1000.abcdef0123456789abcdef0123456789.4242.1700000000123456",
        )
        .unwrap();
        assert_eq!(dump.comm, "myapp");
        assert_eq!(dump.uid, 1000);
        assert_eq!(dump.boot_id, "abcdef0123456789abcdef0123456789");
        assert_eq!(dump.pid, 4242);
        assert_eq!(dump.timestamp_micros, 1700000000123456);
        assert_eq!(dump.extension, None);
    }

    #[test]
    fn parses_compressed() {
        let dump = CoredumpFile::from_name(
            "core.worker.0.0123456789abcdef0123456789abcdef.7.42.zst",
        )
        .unwrap();
        assert_eq!(dump.comm, "worker");
        assert_eq!(dump.extension.as_deref(), Some("zst"));
    }

    #[test]
    fn unescapes_comm() {
        let dump = CoredumpFile::from_name(
            "core.my\\x2eapp.0.0123456789abcdef0123456789abcdef.1.1.zst",
        )
        .unwrap();
        assert_eq!(dump.comm, "my.app");
    }

    #[test]
    fn rejects_non_coredump() {
        assert_eq!(
            CoredumpFile::from_name("README.md"),
            Err(ParseError::NotACoredump)
        );
        assert_eq!(
            CoredumpFile::from_name("not-a-core-file"),
            Err(ParseError::NotACoredump)
        );
    }

    #[test]
    fn rejects_bad_boot_id() {
        assert!(matches!(
            CoredumpFile::from_name("core.foo.0.short.1.1"),
            Err(ParseError::NotACoredump | ParseError::BadField(_))
        ));
        assert!(matches!(
            CoredumpFile::from_name("core.foo.0.zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.1.1"),
            Err(ParseError::BadField("boot_id"))
        ));
    }

    #[test]
    fn rejects_bad_uid() {
        assert!(matches!(
            CoredumpFile::from_name("core.foo.notnum.0123456789abcdef0123456789abcdef.1.1"),
            Err(ParseError::BadField("uid"))
        ));
    }
}
