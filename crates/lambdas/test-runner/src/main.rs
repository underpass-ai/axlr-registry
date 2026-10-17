//! The test-runner Lambda: `publish-api` invokes it asynchronously with
//! `{"name": ..., "version": ...}` after a clean scan. It fetches the
//! version from quarantine, runs its `tests.json` under `/tmp` with the
//! `axlr_run_tool` contract and records the report (see `registry-runner`).
//! This file only wires; the work and its tests are in the runner crate.

use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_config::BehaviorVersion;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use registry_dynamodb::{DynamoAudit, DynamoTools, Table};
use registry_lambda::{Environment, SystemClock, TestRunRequest};
use registry_runner::{Limits, RunVersion, TestRun};
use registry_s3::{Bucket, S3Artifacts};

/// Where versions are unpacked; the only writable path in a Lambda.
const WORKDIR: &str = "/tmp/axlr-registry";
/// Kept free before the function's own deadline, to record the report.
const RECORD_MARGIN: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::tracing::init_default_subscriber();
    lambda_runtime::run(service_fn(handle)).await
}

async fn handle(event: LambdaEvent<TestRunRequest>) -> Result<serde_json::Value, Error> {
    let (request, context) = event.into_parts();
    let limits = Limits { deadline: Some(deadline(context.deadline)), ..Limits::DEFAULT };
    let run = wire_and_run(&request, limits).await?;
    println!("{}@{}: {}", request.name.as_str(), request.version, run.summary());
    Ok(serde_json::json!({
        "name": request.name.as_str(),
        "version": request.version.to_string(),
        "cases": run.results().len(),
        "passed": run.passed(),
    }))
}

/// The run's deadline from the function's, in milliseconds since the epoch.
fn deadline(function_deadline_ms: u64) -> Instant {
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
    let left = Duration::from_millis(function_deadline_ms.saturating_sub(now_ms)).saturating_sub(RECORD_MARGIN);
    Instant::now() + left
}

/// Builds the adapters from the function's environment (`TABLE_NAME`,
/// `ARTIFACTS_BUCKET`, set by the SAM template) and runs the version.
async fn wire_and_run(request: &TestRunRequest, limits: Limits) -> Result<TestRun, Error> {
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let table = Table::new(aws_sdk_dynamodb::Client::new(&config), Environment::required("TABLE_NAME")?);
    let artifacts = S3Artifacts::new(Bucket::new(aws_sdk_s3::Client::new(&config), Environment::required("ARTIFACTS_BUCKET")?));
    let tools = DynamoTools::new(table.clone());
    let audit = DynamoAudit::new(table);
    let runner =
        RunVersion { artifacts: &artifacts, tools: &tools, audit: &audit, clock: &SystemClock, workdir: Path::new(WORKDIR), limits };
    Ok(runner.execute(&request.name, &request.version).await?)
}
