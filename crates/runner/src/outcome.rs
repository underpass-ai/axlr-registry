//! What running the program once produced.

/// The exit code and the captured output of one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The exit code; `None` when a signal ended the program.
    pub exit_code: Option<i32>,
    /// Stdout, at most the cap, decoded leniently.
    pub stdout: String,
    /// Stderr, at most the cap, decoded leniently.
    pub stderr: String,
    /// Whether the timeout killed it.
    pub timed_out: bool,
    /// Whether stdout or stderr went over the cap.
    pub truncated: bool,
}
