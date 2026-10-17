//! Asks `index-publisher` to rebuild the index, asynchronously.

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::InvocationType;
use aws_sdk_lambda::Client;
use registry_application::ports::IndexTrigger;
use registry_application::ApplicationError;

use crate::function_name::FunctionName;
use crate::sdk_error::invoke_error;

/// The index trigger: an `Event` invoke with an empty object as payload.
#[derive(Debug)]
pub struct LambdaIndexTrigger {
    client: Client,
    function: FunctionName,
}

impl LambdaIndexTrigger {
    /// Binds the trigger to the publisher function.
    pub fn new(client: Client, function: FunctionName) -> Self {
        Self { client, function }
    }
}

impl IndexTrigger for LambdaIndexTrigger {
    async fn trigger(&self) -> Result<(), ApplicationError> {
        self.client
            .invoke()
            .function_name(self.function.as_str())
            .invocation_type(InvocationType::Event)
            .payload(Blob::new(b"{}".to_vec()))
            .send()
            .await
            .map_err(|e| invoke_error(self.function.as_str(), e))?;
        Ok(())
    }
}
