//! How a tool's program is confined while its tests run.

use std::path::Path;

/// Where the tool under test runs. The test-runner Lambda relies on its
/// environment (a subnet with no network path); a machine without that
/// isolation wraps the program in bubblewrap, or does not run tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confinement {
    /// As started: the environment confines it.
    Environment,
    /// Inside bubblewrap: no network and no other namespace shared, the
    /// system read-only, `/tmp` and `/home` empty, `HOME=/tmp`, and only
    /// the version's directory writable.
    Bubblewrap,
    /// Tools are not run here; each tool version gets a failed report that
    /// says why. Skills need no confinement and are checked anyway.
    Unavailable(String),
}

impl Confinement {
    /// Bubblewrap when `bwrap` runs here with every namespace unshared,
    /// otherwise unavailable with the reason.
    pub fn detect() -> Self {
        Self::detect_with("bwrap")
    }

    /// As [`Self::detect`], with the bubblewrap binary named.
    pub fn detect_with(bwrap: &str) -> Self {
        let probe = std::process::Command::new(bwrap)
            .args(["--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match probe {
            Ok(status) if status.success() => Self::Bubblewrap,
            Ok(status) => Self::Unavailable(format!("bubblewrap ({bwrap}) cannot unshare namespaces here ({status}); tools are not run")),
            Err(e) => Self::Unavailable(format!("bubblewrap ({bwrap}) is not available ({e}); tools are not run")),
        }
    }

    /// The program and arguments that run `program args…` in `dir` under
    /// this confinement.
    pub fn command(&self, dir: &Path, program: &str, args: &[String]) -> (String, Vec<String>) {
        match self {
            Self::Bubblewrap => {
                let dir = dir.display().to_string();
                let mut wrapped: Vec<String> =
                    ["--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/", "/"].into_iter().map(str::to_owned).collect();
                wrapped.extend(["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"].map(str::to_owned));
                if Path::new("/home").is_dir() {
                    wrapped.extend(["--tmpfs", "/home"].map(str::to_owned));
                }
                wrapped.extend(["--setenv", "HOME", "/tmp", "--bind", &dir, &dir, "--chdir", &dir, "--", program].map(str::to_owned));
                wrapped.extend(args.iter().cloned());
                ("bwrap".to_owned(), wrapped)
            }
            Self::Environment | Self::Unavailable(_) => (program.to_owned(), args.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::Confinement;

    #[test]
    fn wraps_the_command_in_bubblewrap_only_when_asked() {
        let args = vec!["count.py".to_owned()];
        let dir = Path::new("/work/acme_count/1.0.0");
        assert_eq!(Confinement::Environment.command(dir, "python3", &args), ("python3".to_owned(), args.clone()));
        let (program, wrapped) = Confinement::Bubblewrap.command(dir, "python3", &args);
        assert_eq!(program, "bwrap");
        assert_eq!(wrapped[..2], ["--unshare-all", "--die-with-parent"]);
        let tail = [
            "--bind",
            "/work/acme_count/1.0.0",
            "/work/acme_count/1.0.0",
            "--chdir",
            "/work/acme_count/1.0.0",
            "--",
            "python3",
            "count.py",
        ];
        assert!(wrapped.ends_with(&tail.map(str::to_owned)), "{wrapped:?}");
        assert!(wrapped.windows(3).any(|w| w == ["--setenv", "HOME", "/tmp"]), "{wrapped:?}");
        assert_eq!(Confinement::Unavailable("no".into()).command(dir, "python3", &args).0, "python3");
    }

    #[test]
    fn detects_a_missing_binary() {
        let missing = Confinement::detect_with("no-such-bwrap-axlr");
        assert!(matches!(&missing, Confinement::Unavailable(reason) if reason.contains("not available")), "{missing:?}");
        let failing = Confinement::detect_with("false");
        assert!(matches!(&failing, Confinement::Unavailable(reason) if reason.contains("cannot unshare")), "{failing:?}");
        assert!(matches!(Confinement::detect(), Confinement::Bubblewrap | Confinement::Unavailable(_)));
    }
}
