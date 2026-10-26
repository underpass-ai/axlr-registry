//! `axlr-registry-local`: parses the flags and runs the harness; the work
//! and its tests are in the library.

use clap::Parser as _;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let options = registry_local::LocalOptions::parse();
    match registry_local::run(options).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("axlr-registry-local: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
