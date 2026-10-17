//! `publish-api`: wires the DynamoDB, S3 and Lambda adapters to the
//! publisher routes. Configuration: `TABLE_NAME`, `ARTIFACTS_BUCKET`,
//! `TEST_RUNNER_FUNCTION`.

use aws_config::BehaviorVersion;
use lambda_http::{run, service_fn, Body, Error, Request, Response};
use registry_dynamodb::{DynamoAudit, DynamoIdempotency, DynamoNonces, DynamoPublishers, DynamoRates, DynamoTools, Table};
use registry_http::PublishApi;
use registry_lambda::{Environment, FunctionName, LambdaTestScheduler, SystemClock};
use registry_s3::{Bucket, S3Artifacts};

/// Everything built once per container.
struct Wiring {
    table: Table,
    bucket: Bucket,
    scheduler: LambdaTestScheduler,
}

/// Repositories are built per invocation, so the lock snapshots they take
/// never outlive the request.
async fn handle(wiring: &Wiring, request: Request) -> Result<Response<Body>, Error> {
    let publishers = DynamoPublishers::new(wiring.table.clone());
    let tools = DynamoTools::new(wiring.table.clone());
    let audit = DynamoAudit::new(wiring.table.clone());
    let idempotency = DynamoIdempotency::new(wiring.table.clone());
    let nonces = DynamoNonces::new(wiring.table.clone());
    let rates = DynamoRates::new(wiring.table.clone());
    let artifacts = S3Artifacts::new(wiring.bucket.clone());
    let api = PublishApi {
        publishers: &publishers,
        tools: &tools,
        artifacts: &artifacts,
        scheduler: &wiring.scheduler,
        audit: &audit,
        clock: &SystemClock,
        idempotency: &idempotency,
        nonces: &nonces,
        rates: &rates,
    };
    Ok(api.handle(request).await)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::tracing::init_default_subscriber();
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let wiring = Wiring {
        table: Table::new(aws_sdk_dynamodb::Client::new(&config), Environment::required("TABLE_NAME")?),
        bucket: Bucket::new(aws_sdk_s3::Client::new(&config), Environment::required("ARTIFACTS_BUCKET")?),
        scheduler: LambdaTestScheduler::new(
            aws_sdk_lambda::Client::new(&config),
            FunctionName::parse(&Environment::required("TEST_RUNNER_FUNCTION")?)?,
        ),
    };
    run(service_fn(|request| handle(&wiring, request))).await
}
