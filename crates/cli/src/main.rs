//! The `axlr-registry` binary: parse, run, print.

use clap::Parser as _;

#[tokio::main]
async fn main() {
    match axlr_registry_cli::run(axlr_registry_cli::Cli::parse()).await {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("axlr-registry: {error}");
            std::process::exit(1);
        }
    }
}
