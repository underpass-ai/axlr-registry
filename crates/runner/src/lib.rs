//! Runs a tool version's `tests.json` the way the AXLR console's
//! `axlr_run_tool` runs the tool: `program args...` in the version's
//! directory, the case input as one JSON object on stdin, an environment of
//! exactly `PATH` and `HOME`, a timeout per case and a cap on the output.
//! The semantics of `tests.json` are those of the catalog's
//! `run_tests.py`: `exit` defaults to 0, `stdout_json` is a recursive subset
//! and `stdout_contains` a substring. A skill runs nothing: its files are
//! checked deterministically ([`SkillCheck`]) and its `tests.json`, model
//! cases for the console, is checked for shape. One type per file.

mod case_result;
mod confinement;
mod expectation;
mod front_matter;
mod limits;
mod markdown_link;
mod outcome;
mod run_version;
mod runner_error;
mod sandbox;
mod skill_case;
mod skill_check;
mod skill_expectation;
mod skill_suite;
mod suite_runner;
mod test_case;
mod test_run;
mod test_suite;

pub use case_result::CaseResult;
pub use confinement::Confinement;
pub use expectation::Expectation;
pub use front_matter::FrontMatter;
pub use limits::Limits;
pub use markdown_link::MarkdownLink;
pub use outcome::Outcome;
pub use run_version::RunVersion;
pub use runner_error::RunnerError;
pub use sandbox::Sandbox;
pub use skill_case::SkillCase;
pub use skill_check::SkillCheck;
pub use skill_expectation::SkillExpectation;
pub use skill_suite::SkillSuite;
pub use suite_runner::SuiteRunner;
pub use test_case::TestCase;
pub use test_run::TestRun;
pub use test_suite::TestSuite;
