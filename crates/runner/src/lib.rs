//! Runs a tool version's `tests.json` the way the AXLR console's
//! `axlr_run_tool` runs the tool: `program args...` in the version's
//! directory, the case input as one JSON object on stdin, an environment of
//! exactly `PATH` and `HOME`, a timeout per case and a cap on the output.
//! The semantics of `tests.json` are those of the catalog's
//! `run_tests.py`: `exit` defaults to 0, `stdout_json` is a recursive subset
//! and `stdout_contains` a substring. One type per file.

mod case_result;
mod expectation;
mod limits;
mod outcome;
mod run_version;
mod runner_error;
mod sandbox;
mod suite_runner;
mod test_case;
mod test_run;
mod test_suite;

pub use case_result::CaseResult;
pub use expectation::Expectation;
pub use limits::Limits;
pub use outcome::Outcome;
pub use run_version::RunVersion;
pub use runner_error::RunnerError;
pub use sandbox::Sandbox;
pub use suite_runner::SuiteRunner;
pub use test_case::TestCase;
pub use test_run::TestRun;
pub use test_suite::TestSuite;
