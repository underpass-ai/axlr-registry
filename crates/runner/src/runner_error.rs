//! Why a run could not happen at all (a case that fails is a result, not
//! an error).

/// A failure of the runner itself.
#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    /// `tests.json` does not parse.
    #[error("tests.json: {0}")]
    Suite(String),
    /// The program could not be started or its pipes read.
    #[error("{program}: {source}")]
    Spawn {
        /// The program.
        program: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
    /// The version's directory could not be prepared.
    #[error("workdir {path}: {source}")]
    Workdir {
        /// The path.
        path: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
}
