//! `admin-api`: wires the DynamoDB, S3 and Lambda adapters to the admin
//! routes behind mTLS. Configuration: `TABLE_NAME`, `ARTIFACTS_BUCKET`,
//! `INDEX_PUBLISHER_FUNCTION`, `INDEX_PUBLIC_KEY` (the registry's minisign
//! public key, the base64 line of its `.pub` file).

use aws_config::BehaviorVersion;
use lambda_http::{run, service_fn, Body, Error, Request, Response};
use registry_domain::RegistryPublicKey;
use registry_dynamodb::{DynamoAudit, DynamoPrincipals, DynamoPublishers, DynamoTools, Table};
use registry_http::AdminApi;
use registry_lambda::{Environment, FunctionName, LambdaIndexTrigger, SystemClock};
use registry_s3::{Bucket, S3Index};

/// Everything built once per container.
struct Wiring {
    registry_key: RegistryPublicKey,
    table: Table,
    bucket: Bucket,
    trigger: LambdaIndexTrigger,
}

/// Repositories are built per invocation, so the lock snapshots they take
/// never outlive the request.
async fn handle(wiring: &Wiring, request: Request) -> Result<Response<Body>, Error> {
    let principals = DynamoPrincipals::new(wiring.table.clone());
    let publishers = DynamoPublishers::new(wiring.table.clone());
    let tools = DynamoTools::new(wiring.table.clone());
    let audit = DynamoAudit::new(wiring.table.clone());
    let index = S3Index::new(wiring.bucket.clone());
    let api = AdminApi {
        registry_key: &wiring.registry_key,
        principals: &principals,
        publishers: &publishers,
        tools: &tools,
        index: &index,
        audit: &audit,
        clock: &SystemClock,
        trigger: &wiring.trigger,
    };
    Ok(api.handle(request).await)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    lambda_runtime::tracing::init_default_subscriber();
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let wiring = Wiring {
        registry_key: RegistryPublicKey::parse(&Environment::required("INDEX_PUBLIC_KEY")?)?,
        table: Table::new(aws_sdk_dynamodb::Client::new(&config), Environment::required("TABLE_NAME")?),
        bucket: Bucket::new(aws_sdk_s3::Client::new(&config), Environment::required("ARTIFACTS_BUCKET")?),
        trigger: LambdaIndexTrigger::new(
            aws_sdk_lambda::Client::new(&config),
            FunctionName::parse(&Environment::required("INDEX_PUBLISHER_FUNCTION")?)?,
        ),
    };
    run(service_fn(|request| handle(&wiring, request))).await
}
