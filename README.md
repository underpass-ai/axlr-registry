# axlr-registry

The write side of the AXLR tool catalog: a small, safe artifact registry for pre-forged tools, run as Rust Lambdas on AWS for close to nothing. Publishers upload signed tool versions, the registry scans them, runs their tests in a network-less sandbox and keeps them for a human reviewer; approved versions are listed in a signed `index.json` that the AXLR console installs from with `/tools install`.

AXLR and this registry are sibling projects in separate repositories. This one never imports AXLR; the index format is the contract between them.

| Where | What |
|:--|:--|
| [`docs/domain.md`](docs/domain.md) | The domain: publishers, keys and scoped tokens, bundles and digests, publisher signatures, the policy scan, the version state machine, tools, the signed index, key revocation |
| [`docs/architecture.md`](docs/architecture.md) | Hosting (Lambda, DynamoDB, S3, CloudFront, Route 53, mTLS), data model, security, cost, code layout, tests, delivery |
| [`crates/domain`](crates/domain/) | The domain crate: pure, one type per file, every value a validated newtype |
| [`crates/application`](crates/application/) | Ports (traits) and use cases, one per file |
| [`crates/adapters/memory`](crates/adapters/memory/) | In-memory ports for tests |
| [`crates/lambdas/*`](crates/lambdas/) | The four Lambda entry points (`publish-api`, `admin-api`, `test-runner`, `index-publisher`); still placeholders |
| [`infra/template.yaml`](infra/template.yaml) | The SAM template |
| [`.github/workflows`](.github/workflows/) | `ci-dev` (every push), `ci-main` (merges: coverage gate, audit, integration, Lambda build), `release` (tags: build, staging, e2e, production) |

```bash
just check      # fmt, clippy -D warnings, cargo test --workspace
just coverage   # cargo llvm-cov, 80 % line gate (Lambda main.rs excluded)
just lambdas    # cargo lambda build --release --arm64 (needs cargo-lambda)
```

Status (17 Oct 2026): domain, application and in-memory adapters written and tested (line coverage 92 %); the DynamoDB, S3 and Lambda adapters, the test-runner image's handler, the CLI, the end-to-end test and the offline index signing step are not written; nothing is deployed, and the domain name and region are template parameters.
