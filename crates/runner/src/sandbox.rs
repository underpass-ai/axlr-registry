//! Runs the program once, the way `axlr_run_tool` does.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use crate::{Limits, Outcome, RunnerError};

/// `program args...` in a directory, with `PATH` and `HOME` only.
#[derive(Debug, Clone)]
pub struct Sandbox {
    dir: PathBuf,
    program: String,
    args: Vec<String>,
    limits: Limits,
}

impl Sandbox {
    /// A sandbox for a tool's files in `dir`.
    pub fn new(dir: &Path, program: &str, args: &[String], limits: Limits) -> Self {
        Self { dir: dir.to_path_buf(), program: program.to_owned(), args: args.to_vec(), limits }
    }

    /// Runs the program with `input` as one JSON object on stdin.
    pub async fn run(&self, input: &serde_json::Value) -> Result<Outcome, RunnerError> {
        let spawn = |source| RunnerError::Spawn { program: self.program.clone(), source };
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .current_dir(&self.dir)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_owned()))
            .env("HOME", std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(spawn)?;
        let mut stdin = child.stdin.take().ok_or_else(|| spawn(std::io::Error::other("no stdin")))?;
        let stdout = child.stdout.take().ok_or_else(|| spawn(std::io::Error::other("no stdout")))?;
        let stderr = child.stderr.take().ok_or_else(|| spawn(std::io::Error::other("no stderr")))?;
        let cap = self.limits.output_cap;
        let input = serde_json::to_vec(input).expect("a JSON value serialises");
        // A tool that never reads stdin closes the pipe early; that is its
        // business, not a runner error.
        let feed = tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            drop(stdin);
        });
        let out = tokio::spawn(capped(stdout, cap));
        let err = tokio::spawn(capped(stderr, cap));
        let status = tokio::time::timeout(self.limits.case_timeout(), child.wait()).await;
        let (exit_code, timed_out) = match status {
            Ok(status) => (status.map_err(spawn)?.code(), false),
            Err(_) => {
                let _ = child.kill().await;
                (None, true)
            }
        };
        feed.abort();
        // Once the child is dead its pipes close and the readers finish.
        let (stdout, out_over) = out.await.map_err(|e| spawn(std::io::Error::other(e)))?;
        let (stderr, err_over) = err.await.map_err(|e| spawn(std::io::Error::other(e)))?;
        Ok(Outcome { exit_code, stdout, stderr, timed_out, truncated: out_over || err_over })
    }
}

/// Reads a pipe to its end, keeping the first `cap` bytes and saying
/// whether there were more. Draining the rest keeps the child from
/// blocking on a full pipe.
async fn capped<R: tokio::io::AsyncRead + Unpin>(mut pipe: R, cap: usize) -> (String, bool) {
    let mut kept = Vec::new();
    let mut over = false;
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
                if n > room {
                    over = true;
                }
            }
        }
    }
    (String::from_utf8_lossy(&kept).into_owned(), over)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::Sandbox;
    use crate::Limits;

    // Python adds LC_CTYPE itself when it coerces the C locale (PEP 538);
    // it is not something the runner passed.
    const ECHO: &str = "import json, os, sys\nd = json.load(sys.stdin)\nprint(json.dumps({'got': d, 'env': sorted(k for k in os.environ if not k.startswith('LC_'))}))\nsys.exit(d.get('exit', 0))\n";

    fn tool(code: &str) -> (tempfile::TempDir, Sandbox) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t.py"), code).unwrap();
        let sandbox = Sandbox::new(dir.path(), "python3", &["t.py".to_owned()], Limits::default());
        (dir, sandbox)
    }

    #[tokio::test]
    async fn feeds_stdin_and_clears_the_environment() {
        let (_dir, sandbox) = tool(ECHO);
        let out = sandbox.run(&json!({"a": 1})).await.unwrap();
        assert_eq!(out.exit_code, Some(0));
        let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
        assert_eq!(parsed["got"], json!({"a": 1}));
        assert_eq!(parsed["env"], json!(["HOME", "PATH"]));
        let out = sandbox.run(&json!({"exit": 3})).await.unwrap();
        assert_eq!(out.exit_code, Some(3));
        assert!(!out.timed_out && !out.truncated);
    }

    #[tokio::test]
    async fn times_out_and_caps_output() {
        let (dir, _) = tool("import time\ntime.sleep(5)\n");
        let quick = Limits { per_case: Duration::from_millis(300), ..Limits::DEFAULT };
        let sandbox = Sandbox::new(dir.path(), "python3", &["t.py".to_owned()], quick);
        let started = std::time::Instant::now();
        let out = sandbox.run(&json!({})).await.unwrap();
        assert!(out.timed_out && out.exit_code.is_none());
        assert!(started.elapsed() < Duration::from_secs(4), "the child was not killed");

        let (dir, _) = tool("import sys\nsys.stdout.write('x' * 5000)\nsys.stderr.write('e' * 10)\n");
        let small = Limits { output_cap: 1000, ..Limits::DEFAULT };
        let sandbox = Sandbox::new(dir.path(), "python3", &["t.py".to_owned()], small);
        let out = sandbox.run(&json!({})).await.unwrap();
        assert!(out.truncated);
        assert_eq!(out.stdout.len(), 1000);
        assert_eq!(out.stderr, "eeeeeeeeee");
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn a_missing_program_is_an_error_not_a_result() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), "no-such-program-axlr", &[], Limits::default());
        assert!(sandbox.run(&json!({})).await.is_err());
    }
}
