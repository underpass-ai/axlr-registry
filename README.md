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
| [`crates/adapters/dynamodb`](crates/adapters/dynamodb/) | Publishers, tools, principals, the audit log and idempotency records over one DynamoDB table (condition expressions, a version lock per aggregate, GSI1 for the reviewer's queue) |
| [`crates/adapters/s3`](crates/adapters/s3/) | The artifact store (`quarantine/<status>/…`, `published/tools/…`) and the index writer (`staging/index.json`, `published/index.json` + `.minisig`) |
| [`crates/adapters/lambda`](crates/adapters/lambda/) | Asynchronous invokes of `test-runner` and `index-publisher`, the system clock, the environment |
| [`crates/adapters/http`](crates/adapters/http/) | Request and response mapping shared by the API Lambdas: bearer tokens, the upload body, the mTLS principal, errors to status codes, routing |
| [`crates/lambdas/*`](crates/lambdas/) | The four Lambda entry points: `publish-api`, `admin-api` and `index-publisher` wire the adapters above; `test-runner` is still a placeholder |
| [`infra/template.yaml`](infra/template.yaml) | The SAM template |
| [`.github/workflows`](.github/workflows/) | `ci-dev` (every push), `ci-main` (merges: coverage gate, audit, integration, Lambda build), `release` (tags: build, staging, e2e, production) |

```bash
just check         # fmt, clippy -D warnings, cargo test --workspace
just coverage      # cargo llvm-cov, 80 % line gate, offline (Lambda main.rs and the SDK-calling adapter files excluded)
just services      # DynamoDB Local on :8000 and MinIO on :9000 in Docker
just integration   # every test, the adapter integration tests included (needs the services)
just coverage-all  # the CI gate: everything under llvm-cov, only main.rs excluded
just lambdas       # cargo lambda build --release --arm64 (needs cargo-lambda)
```

## Routes

`api.DOMAIN` (bearer token, `publish-api`):

| Route | Body | Answer |
|:--|:--|:--|
| `POST /v1/versions` | `{manifest, files: {name: base64}, key_id, signature}` (base64 everywhere; `Idempotency-Key` header optional, replayed per token for a day) | `201` with the version, its status (`scanned` or `rejected`) and the scan findings |
| `GET /v1/versions/{name}/{version}` | | `200` with status, findings, test outcome and rejection reason |

`admin.DOMAIN` (mTLS; the principal is the client certificate's SHA-256, `admin-api`):

| Route | Body | Does |
|:--|:--|:--|
| `POST /v1/publishers` | `{id, public_key, namespaces}` | registers a publisher (operator) |
| `POST /v1/publishers/{id}/tokens` | `{scopes, expires_at?}` | issues a token, shown once (operator) |
| `POST /v1/publishers/{id}/keys/{key_id}/revoke` | `{mode: rotation \| compromise}` | revokes a key; compromise yanks what it signed; rebuilds the index (operator) |
| `POST /v1/versions/{name}/{version}/approve` \| `reject` \| `yank` | `{reason}` | the review decision; approve and yank rebuild the index (reviewer or operator) |
| `POST /v1/index/publish` | | asks `index-publisher` for a rebuild (operator) |
| `POST /v1/index/signature` | `{signature}` (the `.minisig` text over `staging/index.json`) | verifies it against `INDEX_PUBLIC_KEY` and publishes `published/index.json` and `.minisig` (operator) |

Statuses: domain `Invalid` 400, `Unauthorized` 401, `Forbidden` 403, `NotFound` 404, `Conflict` 409, a port failure 502, a body over 4 MiB 413; unknown JSON fields are refused.

## Integration tests

The DynamoDB and S3 adapters have tests against DynamoDB Local and MinIO, behind the `integration` cargo feature and marked `#[ignore]`, so a plain `cargo test` never needs Docker. Locally:

```bash
just services      # once; `just services-stop` removes the containers
just integration
```

They read `DYNAMODB_ENDPOINT` and `S3_ENDPOINT` (defaults `http://localhost:8000` and `http://localhost:9000`) and the usual `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (`test` / `testtest` for the containers above); every test creates its own table and bucket. The `ci-main` integration job runs the same tests under `cargo llvm-cov`, so the 80 % gate counts the SDK adapters.

Status (17 Oct 2026): domain, application, in-memory, DynamoDB, S3, Lambda and HTTP adapters written and tested, and `publish-api`, `admin-api` and `index-publisher` wired; the test-runner image's handler, the CLI, the end-to-end test, the CloudFront invalidation after a signed publish and the offline index signing step are not written; nothing is deployed, and the domain name, region and registry public key are template parameters.
