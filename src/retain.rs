use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub const RETAIN_SUFFIX: &str = ".cdgc-retain";

pub fn marker_path(dump_path: &Path) -> PathBuf {
    let mut s = dump_path.as_os_str().to_os_string();
    s.push(RETAIN_SUFFIX);
    PathBuf::from(s)
}

pub fn dump_name_for_marker(marker_name: &OsStr) -> Option<&str> {
    marker_name.to_str().and_then(|s| s.strip_suffix(RETAIN_SUFFIX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_path_appends_suffix() {
        let p = marker_path(Path::new("/var/lib/coredump/core.foo.0.boot.1.123.zst"));
        assert_eq!(
            p.to_str().unwrap(),
            "/var/lib/coredump/core.foo.0.boot.1.123.zst.cdgc-retain"
        );
    }

    #[test]
    fn dump_name_for_marker_strips_suffix() {
        let dump = dump_name_for_marker(OsStr::new("core.foo.zst.cdgc-retain"));
        assert_eq!(dump, Some("core.foo.zst"));
    }

    #[test]
    fn non_marker_returns_none() {
        assert_eq!(dump_name_for_marker(OsStr::new("core.foo.zst")), None);
    }
}
