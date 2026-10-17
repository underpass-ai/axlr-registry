//! Runs only with `-- --ignored` and the `REGISTRY_E2E_*` variables, from
//! the release job against the staging stack.

use std::path::Path;

use registry_e2e::{Scenario, Settings};

#[tokio::test]
#[ignore = "needs a deployed stack: set REGISTRY_E2E_* and run with --ignored"]
async fn a_signed_bundle_reaches_the_staging_index() {
    let Some(settings) = Settings::from_env() else {
        panic!("REGISTRY_E2E_PUBLISH_URL, REGISTRY_E2E_ADMIN_URL, REGISTRY_E2E_PUBLISHER_KEY and REGISTRY_E2E_CLIENT_CERT are required");
    };
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../domain/tests/fixtures/business_days");
    let entry = Scenario::new(settings).run(&fixture).await.expect("the scenario completes");
    assert_eq!(entry["reviewer"].as_str().map(str::is_empty), Some(false));
}
