# axlr-registry

The write side of the AXLR tool catalog: a small, safe artifact registry for pre-forged tools, run as Rust Lambdas on AWS for close to nothing. Publishers upload signed tool versions, the registry scans them, runs their tests in a network-less sandbox and keeps them for a human reviewer; approved versions are listed in a signed `index.json` that the AXLR console installs from with `/tools install`.

AXLR and this registry are sibling projects in separate repositories. This one never imports AXLR; the index format is the contract between them.

| Where | What |
|:--|:--|
| [`docs/domain.md`](docs/domain.md) | The domain: publishers, keys and scoped tokens, bundles and digests, publisher signatures, the policy scan, the version state machine, tools, the signed index, key revocation |
| [`docs/architecture.md`](docs/architecture.md) | Hosting (Lambda, DynamoDB, S3, CloudFront, Route 53, mTLS), data model, security, cost, code layout, tests, delivery |
| [`crates/domain`](crates/domain/) | The domain crate: pure, one type per file, every value a validated newtype |
| [`crates/application`](crates/application/) | Ports (traits) and use cases, one per file |
| [`docs/api.md`](docs/api.md) | The HTTP routes and bodies as the CLI speaks them and the API Lambdas serve them, and the three the admin API does not serve yet |
| [`docs/operations.md`](docs/operations.md) | The offline CA, client certificates and their SHA-256, the truststore bucket and version, the us-east-1 CloudFront certificate, CA rotation |
| [`crates/adapters/memory`](crates/adapters/memory/) | In-memory ports for tests |
| [`crates/adapters/dynamodb`](crates/adapters/dynamodb/) | Publishers, tools, principals, the audit log and idempotency records over one DynamoDB table (condition expressions, a version lock per aggregate, GSI1 for the reviewer's queue) |
| [`crates/adapters/s3`](crates/adapters/s3/) | The artifact store (`quarantine/<status>/…`, `published/tools/…`) and the index writer (`staging/index.json`, `published/index.json` + `.minisig`) |
| [`crates/adapters/lambda`](crates/adapters/lambda/) | Asynchronous invokes of `test-runner` and `index-publisher`, the system clock, the environment |
| [`crates/adapters/http`](crates/adapters/http/) | Request and response mapping shared by the API Lambdas: bearer tokens, the upload body, the mTLS principal, errors to status codes, routing |
| [`crates/runner`](crates/runner/) | Runs a version's `tests.json` with the `axlr_run_tool` contract (PATH and HOME only, 30 s per case, 1 MiB per stream, a whole-run deadline) and records the report |
| [`crates/cli`](crates/cli/) | `axlr-registry`: the publisher, reviewer and operator command line |
| [`crates/lambdas/*`](crates/lambdas/) | The four Lambda entry points, each wiring the adapters above: `publish-api`, `admin-api`, `index-publisher` and `test-runner` (a container image with python3, bash and node) |
| [`scripts/ca.sh`](scripts/ca.sh) | The local parts of `docs/operations.md`: init, issue, fingerprint, truststore, rotate, retire |
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

Statuses: domain `Invalid` 400, `Unauthorized` 401, `Forbidden` 403, `NotFound` 404, `Conflict` 409, a port failure 502, a body over 4 MiB 413; unknown JSON fields are refused. The upload body also carries `tests` (`tests.json`, base64), stored beside the bundle for the runner. The full bodies, and the `GET /v1/versions?status=`, `GET /v1/versions/{name}/{version}` and `GET /v1/index/staging` admin routes the CLI calls but `admin-api` does not serve yet, are in [`docs/api.md`](docs/api.md).

## The command line

`cargo install --path crates/cli` installs `axlr-registry`. The admin commands take `--url https://admin.DOMAIN` and `--cert clients/<id>/identity.pem` (a client certificate from the private CA; `--ca` adds a private root for staging), or the environment variables `AXLR_REGISTRY_ADMIN_URL` and `AXLR_REGISTRY_CLIENT_CERT`.

| Command | Does |
|:--|:--|
| `publisher keygen [--out publisher.key]` | an Ed25519 key: the secret (mode 0600) and `<out>.pub`, which the operator registers |
| `publisher sign <tool dir> --key <key> [--out sig.json]` | validates the directory as the registry will (manifest, files, `tests.json` beside them) and prints the bundle digest and the signature |
| `publisher upload <tool dir> --token-file <file> --url https://api.DOMAIN (--key <key> \| --signature sig.json)` | `POST /v1/versions` with the manifest, files, tests and signature; prints the outcome |
| `review list [--status scanned]`, `review show <name> <version>` | the queue and one version's scan, tests and review |
| `review approve\|reject\|yank <name> <version> --reason …` | the decision |
| `operator register-publisher --id <id> --public-key <file.pub> --namespace <scope>…` | a publisher with its first key and namespaces |
| `operator issue-token --publisher <id> --scope <scope>… [--expires <RFC 3339>]` | a bearer token, shown once |
| `operator revoke-key --publisher <id> --key-id <16 hex> --mode rotation\|compromise` | revokes a key; compromise yanks what it signed |
| `operator publish-index` | rebuilds the unsigned index in staging |
| `operator fetch-index [--out index.json]` | downloads the staging index to sign |
| `operator sign-index <index.json> --key minisign.key [--password-file …] [--out …] [--trusted-comment …]` | signs it offline with the registry's minisign key, in the form the console verifies (`minisign -V` accepts it too) |
| `operator upload-signature <index.json.minisig>` | the API verifies the signature and publishes the index |

## Integration tests

The DynamoDB and S3 adapters have tests against DynamoDB Local and MinIO, behind the `integration` cargo feature and marked `#[ignore]`, so a plain `cargo test` never needs Docker. Locally:

```bash
just services      # once; `just services-stop` removes the containers
just integration
```

They read `DYNAMODB_ENDPOINT` and `S3_ENDPOINT` (defaults `http://localhost:8000` and `http://localhost:9000`) and the usual `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (`test` / `testtest` for the containers above); every test creates its own table and bucket. The `ci-main` integration job runs the same tests under `cargo llvm-cov`, so the 80 % gate counts the SDK adapters.

Status (17 Oct 2026): domain, application, in-memory, DynamoDB, S3, Lambda and HTTP adapters, the four Lambdas, the test runner and the CLI (with the offline index signing) written and tested; the admin API does not yet serve the reviewer's queue, the version detail or the staging index download that `review list`, `review show` and `operator fetch-index` call; the end-to-end test and the CloudFront invalidation after a signed publish are not written; nothing is deployed, and the domain name, region and registry public key are template parameters.
