//! The invoke adapters against an endpoint nothing listens on: the request
//! is built and sent, and the failure comes back as a port error naming the
//! function. The success path needs a Lambda and is exercised by the
//! end-to-end test against the staging stack.

use aws_sdk_lambda::config::retry::RetryConfig;
use aws_sdk_lambda::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_lambda::Client;
use registry_application::ports::{IndexTrigger, TestScheduler};
use registry_application::ApplicationError;
use registry_domain::{ToolName, Version};
use registry_lambda::{FunctionName, LambdaIndexTrigger, LambdaTestScheduler};

fn unreachable_client() -> Client {
    let config = aws_sdk_lambda::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("eu-west-1"))
        .credentials_provider(Credentials::new("test", "testtest", None, None, "static"))
        .endpoint_url("http://127.0.0.1:9")
        .retry_config(RetryConfig::disabled())
        .build();
    Client::from_conf(config)
}

#[tokio::test]
async fn failures_are_port_errors_that_name_the_function() {
    let scheduler = LambdaTestScheduler::new(unreachable_client(), FunctionName::parse("registry-test-runner").unwrap());
    let error = scheduler.schedule(&ToolName::parse("acme_count").unwrap(), &Version::parse("1.0.0").unwrap()).await.unwrap_err();
    assert!(matches!(error, ApplicationError::Port { port: "lambda", .. }), "{error}");
    assert!(error.to_string().contains("registry-test-runner"), "{error}");

    let trigger = LambdaIndexTrigger::new(unreachable_client(), FunctionName::parse("registry-index-publisher").unwrap());
    let error = trigger.trigger().await.unwrap_err();
    assert!(matches!(error, ApplicationError::Port { port: "lambda", .. }), "{error}");
    assert!(error.to_string().contains("registry-index-publisher"), "{error}");
}
