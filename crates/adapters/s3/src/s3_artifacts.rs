//! The artifact store over S3.

use aws_sdk_s3::primitives::ByteStream;
use registry_application::ports::ArtifactStore;
use registry_application::ApplicationError;
use registry_domain::{Status, ToolName, ValidBundle, Version};

use crate::bucket::Bucket;
use crate::object_key::ObjectKey;
use crate::sdk_error::s3_error;

/// Writes uploads to quarantine and copies approved versions to published.
#[derive(Debug)]
pub struct S3Artifacts {
    bucket: Bucket,
}

impl S3Artifacts {
    /// Binds the store to a bucket.
    pub fn new(bucket: Bucket) -> Self {
        Self { bucket }
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), ApplicationError> {
        let file = key.rsplit('/').next().unwrap_or(key);
        self.bucket
            .client()
            .put_object()
            .bucket(self.bucket.name())
            .key(key)
            .content_type(ObjectKey::content_type(file))
            .body(ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| s3_error(&format!("put {key}"), e))?;
        Ok(())
    }

    /// Every key under a prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, ApplicationError> {
        let mut keys = Vec::new();
        let mut token = None;
        loop {
            let page = self
                .bucket
                .client()
                .list_objects_v2()
                .bucket(self.bucket.name())
                .prefix(prefix)
                .set_continuation_token(token)
                .send()
                .await
                .map_err(|e| s3_error(&format!("list {prefix}"), e))?;
            keys.extend(page.contents.unwrap_or_default().into_iter().filter_map(|o| o.key));
            token = page.next_continuation_token;
            if token.is_none() {
                break;
            }
        }
        Ok(keys)
    }
}

impl ArtifactStore for S3Artifacts {
    async fn quarantine(&self, bundle: &ValidBundle, status: Status) -> Result<(), ApplicationError> {
        let prefix = ObjectKey::quarantine_prefix(status, bundle.name(), bundle.version());
        self.put(&format!("{prefix}manifest.json"), bundle.manifest_bytes().to_vec()).await?;
        for (name, content) in bundle.files() {
            self.put(&format!("{prefix}{}", name.as_str()), content.clone()).await?;
        }
        Ok(())
    }

    async fn publish(&self, name: &ToolName, version: &Version) -> Result<(), ApplicationError> {
        let from = ObjectKey::quarantine_prefix(Status::Scanned, name, version);
        let to = ObjectKey::published_prefix(name, version);
        let keys = self.list(&from).await?;
        if keys.is_empty() {
            return Err(ApplicationError::port("s3", format!("nothing quarantined under {from}")));
        }
        for key in keys {
            let file = key.strip_prefix(&from).unwrap_or(&key);
            if file.is_empty() || file.contains('/') || file == "tests.json" {
                continue;
            }
            let target = format!("{to}{file}");
            self.bucket
                .client()
                .copy_object()
                .bucket(self.bucket.name())
                .copy_source(format!("{}/{key}", self.bucket.name()))
                .key(&target)
                .content_type(ObjectKey::content_type(file))
                .metadata_directive(aws_sdk_s3::types::MetadataDirective::Replace)
                .send()
                .await
                .map_err(|e| s3_error(&format!("copy {key} to {target}"), e))?;
        }
        Ok(())
    }
}
