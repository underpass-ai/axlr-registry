//! `index-publisher`: invoked asynchronously by `admin-api` after an
//! approval, a yank or a key revocation (and by `POST /v1/index/publish`),
//! it copies every approved version to `published/` and writes the unsigned
//! canonical index to `staging/index.json` for the operator to sign.
//! Configuration: `TABLE_NAME`, `ARTIFACTS_BUCKET`, `CATALOG_NAME`.

use aws_config::BehaviorVersion;
use lambda_runtime::{run, service_fn, Error, LambdaEvent};
use registry_application::use_cases::PublishIndex;
use registry_dynamodb::{DynamoAudit, DynamoPublishers, DynamoTools, Table};
use registry_lambda::{Environment, SystemClock};
use registry_s3::{Bucket, S3Artifacts, S3Index};
use serde_json::Value;

/// Everything built once per container.
struct Wiring {
    catalog: String,
    table: Table,
    bucket: Bucket,
}

/// The payload is ignored: a rebuild is a rebuild. The answer counts what
/// the index carries.
async fn handle(wiring: &Wiring, _event: LambdaEvent<Value>) -> Result<Value, Error> {
    let publishers = DynamoPublishers::new(wiring.table.clone());
    let tools = DynamoTools::new(wiring.table.clone());
    let audit = DynamoAudit::new(wiring.table.clone());
    let artifacts = S3Artifacts::new(wiring.bucket.clone());
    let index = S3Index::new(wiring.bucket.clone());
    let publish = PublishIndex {
        catalog: &wiring.catalog,
        publishers: &publishers,
        tools: &tools,
        artifacts: &artifacts,
        index: &index,
        audit: &audit,
        clock: &SystemClock,
    };
    let built = publish.execute().await?;
    Ok(serde_json::json!({
        "catalog": built.catalog,
        "generated_at": built.generated_at,
        "tools": built.tools.len(),
        "revocations": built.revocations.len(),
        "revoked_keys": built.revoked_keys.len(),
    }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::tracing::init_default_subscriber();
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let wiring = Wiring {
        catalog: Environment::required("CATALOG_NAME")?,
        table: Table::new(aws_sdk_dynamodb::Client::new(&config), Environment::required("TABLE_NAME")?),
        bucket: Bucket::new(aws_sdk_s3::Client::new(&config), Environment::required("ARTIFACTS_BUCKET")?),
    };
    run(service_fn(|event| handle(&wiring, event))).await
}
