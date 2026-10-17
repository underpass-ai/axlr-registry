//! Schedules a test run by invoking `test-runner` asynchronously.

use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::types::InvocationType;
use aws_sdk_lambda::Client;
use registry_application::ports::TestScheduler;
use registry_application::ApplicationError;
use registry_domain::{ToolName, Version};

use crate::function_name::FunctionName;
use crate::sdk_error::invoke_error;
use crate::test_run_request::TestRunRequest;

/// The test scheduler: an `Event` invoke, so the upload returns before the
/// tests run.
#[derive(Debug)]
pub struct LambdaTestScheduler {
    client: Client,
    function: FunctionName,
}

impl LambdaTestScheduler {
    /// Binds the scheduler to the runner function.
    pub fn new(client: Client, function: FunctionName) -> Self {
        Self { client, function }
    }
}

impl TestScheduler for LambdaTestScheduler {
    async fn schedule(&self, name: &ToolName, version: &Version) -> Result<(), ApplicationError> {
        let payload = TestRunRequest { name: name.clone(), version: version.clone() }.to_payload()?;
        self.client
            .invoke()
            .function_name(self.function.as_str())
            .invocation_type(InvocationType::Event)
            .payload(Blob::new(payload))
            .send()
            .await
            .map_err(|e| invoke_error(self.function.as_str(), e))?;
        Ok(())
    }
}
