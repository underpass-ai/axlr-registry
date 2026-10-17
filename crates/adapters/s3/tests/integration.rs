//! Against MinIO (`S3_ENDPOINT`, default `http://localhost:9000`, credentials
//! from the AWS environment variables). Ignored unless run with `--ignored`
//! and the `integration` feature; see the README for the Docker command.
#![cfg(feature = "integration")]

use std::collections::BTreeMap;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::Client;
use registry_application::ports::{ArtifactStore, IndexWriter};
use registry_domain::{Bundle, FileName, Status, ToolName, Version};
use registry_s3::{Bucket, ObjectKey, S3Artifacts, S3Index};

async fn bucket() -> Bucket {
    let endpoint = std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into());
    let shared = aws_config::defaults(BehaviorVersion::latest())
        .endpoint_url(endpoint)
        .region(Region::new("eu-west-1"))
        .credentials_provider(Credentials::new(
            std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_else(|_| "test".into()),
            std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_else(|_| "testtest".into()),
            None,
            None,
            "static",
        ))
        .load()
        .await;
    let config = aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
    let bucket = Bucket::new(Client::from_conf(config), format!("registry-it-{}", ulid::Ulid::new().to_string().to_lowercase()));
    bucket.ensure_exists().await.unwrap();
    bucket.ensure_exists().await.unwrap_or_else(|e| panic!("a second ensure_exists is not idempotent: {e}"));
    bucket
}

fn bundle(code: &str) -> registry_domain::ValidBundle {
    let manifest = serde_json::to_vec(&serde_json::json!({
        "name": "acme_count", "description": "Count things. Exactly.", "input_schema": {"type": "object"}, "program": "python3",
        "args": ["count.py"], "files": ["count.py", "helper.py"], "catalog": {"version": "1.0.0", "category": "data", "license": "MIT"}
    }))
    .unwrap();
    let files: BTreeMap<FileName, Vec<u8>> = [
        (FileName::parse("count.py").unwrap(), code.as_bytes().to_vec()),
        (FileName::parse("helper.py").unwrap(), b"def h():\n    return 1\n".to_vec()),
    ]
    .into();
    Bundle::new(manifest, files).validate().unwrap()
}

async fn object(bucket: &Bucket, key: &str) -> Option<(String, Vec<u8>)> {
    match bucket.client().get_object().bucket(bucket.name()).key(key).send().await {
        Ok(o) => Some((o.content_type.clone().unwrap_or_default(), o.body.collect().await.unwrap().into_bytes().to_vec())),
        Err(_) => None,
    }
}

#[tokio::test]
#[ignore = "needs MinIO"]
async fn uploads_land_in_quarantine_by_status_and_approved_ones_are_published() {
    let bucket = bucket().await;
    let store = S3Artifacts::new(bucket.clone());
    let name = ToolName::parse("acme_count").unwrap();
    let version = Version::parse("1.0.0").unwrap();
    assert!(store.publish(&name, &version).await.is_err(), "published a version that was never quarantined");

    let rejected = bundle("import socket\n");
    store.quarantine(&rejected, Status::Rejected).await.unwrap();
    assert!(object(&bucket, "quarantine/rejected/acme_count/1.0.0/count.py").await.is_some());
    assert!(object(&bucket, "quarantine/scanned/acme_count/1.0.0/count.py").await.is_none());

    let scanned = bundle("print(1)\n");
    store.quarantine(&scanned, Status::Scanned).await.unwrap();
    let (content_type, manifest) = object(&bucket, "quarantine/scanned/acme_count/1.0.0/manifest.json").await.unwrap();
    assert_eq!(manifest, scanned.manifest_bytes(), "the manifest's original bytes were not kept");
    assert_eq!(content_type, "application/json");
    // Something the runner leaves beside the files is never published.
    bucket
        .client()
        .put_object()
        .bucket(bucket.name())
        .key("quarantine/scanned/acme_count/1.0.0/tests.json")
        .body(aws_sdk_s3::primitives::ByteStream::from_static(b"[]"))
        .send()
        .await
        .unwrap();

    store.publish(&name, &version).await.unwrap();
    let prefix = ObjectKey::published_prefix(&name, &version);
    let (content_type, published) = object(&bucket, &format!("{prefix}manifest.json")).await.unwrap();
    assert_eq!(published, scanned.manifest_bytes());
    assert_eq!(content_type, "application/json");
    let (content_type, code) = object(&bucket, &format!("{prefix}count.py")).await.unwrap();
    assert_eq!(code, b"print(1)\n");
    assert_eq!(content_type, "text/plain; charset=utf-8");
    assert!(object(&bucket, &format!("{prefix}helper.py")).await.is_some());
    assert!(object(&bucket, &format!("{prefix}tests.json")).await.is_none(), "tests.json was published");
    store.publish(&name, &version).await.unwrap_or_else(|e| panic!("publishing twice is not idempotent: {e}"));
}

#[tokio::test]
#[ignore = "needs MinIO"]
async fn the_index_goes_to_staging_then_published_with_its_signature() {
    let bucket = bucket().await;
    let index = S3Index::new(bucket.clone());
    assert!(index.read_staging().await.unwrap().is_none());
    index.write_staging(b"{\"schema_version\":1}\n").await.unwrap();
    assert_eq!(index.read_staging().await.unwrap().unwrap(), b"{\"schema_version\":1}\n");
    assert!(object(&bucket, ObjectKey::PUBLISHED_INDEX).await.is_none());
    index.write_published(b"{\"schema_version\":1}\n", "untrusted comment: x\nsig\ntrusted comment: y\nglobal\n").await.unwrap();
    let (content_type, published) = object(&bucket, ObjectKey::PUBLISHED_INDEX).await.unwrap();
    assert_eq!((content_type.as_str(), published.as_slice()), ("application/json", &b"{\"schema_version\":1}\n"[..]));
    let (_, signature) = object(&bucket, ObjectKey::PUBLISHED_SIGNATURE).await.unwrap();
    assert!(signature.starts_with(b"untrusted comment: x\n"));
    assert!(index.read("nowhere/at/all").await.unwrap().is_none());
}
