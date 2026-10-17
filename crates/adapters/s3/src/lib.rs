//! S3 adapters: the artifact store (`quarantine/<status>/<name>/<version>/`
//! on upload, `published/tools/<name>/<version>/` on approval) and the index
//! writer (`staging/index.json` unsigned, `published/index.json` with its
//! `.minisig`). One type per file.

mod bucket;
mod object_key;
mod s3_artifacts;
mod s3_index;
mod sdk_error;

pub use bucket::Bucket;
pub use object_key::ObjectKey;
pub use s3_artifacts::S3Artifacts;
pub use s3_index::S3Index;
