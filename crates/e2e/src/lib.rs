//! The end-to-end scenario against a deployed stack, run by the release
//! job before promotion. The test in `tests/` is ignored by default; it
//! runs with `cargo test -p registry-e2e -- --ignored` and these variables:
//!
//! | Variable | Meaning |
//! |:--|:--|
//! | `REGISTRY_E2E_PUBLISH_URL` | `https://api.DOMAIN` |
//! | `REGISTRY_E2E_ADMIN_URL` | `https://admin.DOMAIN` |
//! | `REGISTRY_E2E_TOKEN` | a token scoped to `e2e_*` |
//! | `REGISTRY_E2E_PUBLISHER_KEY` | path to the publisher key file (`publisher keygen`) |
//! | `REGISTRY_E2E_CLIENT_CERT` | path to a reviewer-and-operator identity PEM |
//! | `REGISTRY_E2E_CA` | optional extra root to trust |

mod e2e_error;
mod scenario;
mod settings;

pub use e2e_error::E2eError;
pub use scenario::Scenario;
pub use settings::Settings;
