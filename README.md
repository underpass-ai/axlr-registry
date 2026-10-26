# axlr-registry

The write side of the AXLR tool catalog: a small, safe artifact registry for pre-forged tools and skills, run as Rust Lambdas on AWS for close to nothing. Publishers upload signed tool and skill versions, the registry scans them, runs their tests in a network-less sandbox and keeps them for a human reviewer; approved versions are listed in a signed `index.json` that the AXLR console installs from with `/tools install`.

AXLR and this registry are sibling projects in separate repositories. This one never imports AXLR; the index format is the contract between them.

| Where | What |
|:--|:--|
| [`docs/domain.md`](docs/domain.md) | The domain: publishers and their keys, bundles and digests, publisher signatures, the policy scan, the version state machine, tools and skills, the signed index, key revocation |
| [`docs/architecture.md`](docs/architecture.md) | Hosting (Lambda, DynamoDB, S3, CloudFront, Route 53, mTLS), data model, security, cost, code layout, tests, delivery |
| [`crates/domain`](crates/domain/) | The domain crate: pure, one type per file, every value a validated newtype |
| [`crates/application`](crates/application/) | Ports (traits) and use cases, one per file |
| [`docs/api.md`](docs/api.md) | The HTTP routes and bodies as the CLI speaks them and the API Lambdas serve them: signed requests, enrolment, approval, rate limits |
| [`docs/client-identity.md`](docs/client-identity.md) | The client identity contract: one Ed25519 key per publisher, self-service enrolment, signed requests, per-key rate limits |
| [`docs/operations.md`](docs/operations.md) | The offline CA, client certificates and their SHA-256, the truststore bucket and version, the us-east-1 CloudFront certificate, CA rotation, publisher enrolment and approval |
| [`crates/adapters/memory`](crates/adapters/memory/) | In-memory ports for tests |
| [`crates/adapters/dynamodb`](crates/adapters/dynamodb/) | Publishers, tools, principals, the audit log, idempotency records, used nonces and rate windows over one DynamoDB table (condition expressions, a version lock per aggregate, GSI1 for the reviewer's queue, TTL on `expires_at`) |
| [`crates/adapters/s3`](crates/adapters/s3/) | The artifact store (`quarantine/<status>/…`, `published/tools/…`) and the index writer (`staging/index.json`, `published/index.json` + `.minisig`) |
| [`crates/adapters/lambda`](crates/adapters/lambda/) | Asynchronous invokes of `test-runner` and `index-publisher`, the system clock, the environment |
| [`crates/adapters/http`](crates/adapters/http/) | Request and response mapping shared by the API Lambdas: signed requests, the upload and enrolment bodies, the mTLS principal, errors to status codes (429 with `Retry-After`), routing |
| [`crates/runner`](crates/runner/) | Runs a tool version's `tests.json` with the `axlr_run_tool` contract (PATH and HOME only, 30 s per case, 1 MiB per stream, a whole-run deadline; under bubblewrap off Lambda) or checks a skill's files, and records the report |
| [`crates/cli`](crates/cli/) | `axlr-registry`: the publisher, reviewer and operator command line |
| [`crates/lambdas/*`](crates/lambdas/) | The four Lambda entry points, each wiring the adapters above: `publish-api`, `admin-api`, `index-publisher` and `test-runner` (a container image with python3, bash and node) |
| [`scripts/ca.sh`](scripts/ca.sh) | The local parts of `docs/operations.md`: init, issue, fingerprint, truststore, rotate, retire |
| [`crates/local`](crates/local/) | `axlr-registry-local`: the registry from memory on the loopback (publish API, signed catalog, inline tests, automatic review) for end-to-end runs without AWS; see `docs/operations.md`, "Local harness" |
| [`crates/e2e`](crates/e2e/) | The end-to-end scenario the release job runs against the staging stack (ignored unless `REGISTRY_E2E_*` is set) |
| [`infra/template.yaml`](infra/template.yaml) | The SAM template |
| [`.github/workflows`](.github/workflows/) | `ci-dev` (every push), `ci-main` (merges: coverage gate, audit, integration, Lambda build), `release` (tags: build, staging, e2e, production) |

```bash
just check         # fmt, clippy -D warnings, cargo test --workspace
just coverage      # cargo llvm-cov, 80 % line gate, offline (Lambda and harness main.rs and the SDK-calling adapter files excluded)
just local         # axlr-registry-local on 127.0.0.1:8787 (see docs/operations.md, "Local harness")
just services      # DynamoDB Local on :8000 and MinIO on :9000 in Docker
just integration   # every test, the adapter integration tests included (needs the services)
just coverage-all  # the CI gate: everything under llvm-cov, only main.rs excluded
just lambdas       # cargo lambda build --release --arm64 (needs cargo-lambda)
```

## Routes

`api.DOMAIN` (every request signed with the publisher's key: `X-AXLR-Key`, `X-AXLR-Timestamp`, `X-AXLR-Nonce`, `X-AXLR-Signature`; `publish-api`):

| Route | Body | Answer |
|:--|:--|:--|
| `POST /v1/publishers/enroll` | `{id, public_key, namespaces, contact}`, signed with the key being enrolled | `202` `{id, status: pending, namespaces}`; an operator approves it |
| `POST /v1/publishers/{id}/keys` | `{public_key}`, signed with one of the caller's keys | `201` `{id, key_id}` |
| `POST /v1/versions` | `{manifest, files: {name: base64}, key_id, signature}` (base64 everywhere; `Idempotency-Key` header optional, replayed per key for a day) | `201` with the version, its status (`scanned` or `rejected`) and the scan findings |
| `GET /v1/versions/{name}/{version}` | | `200` with status, findings, test outcome and rejection reason |

Refusals of a signed request: 401 `stale`, `unknown_key`, `bad_signature`, `replay`; 403 `pending`, `suspended`; 429 `rate_limited` with `Retry-After` (60 requests per minute and 20 uploads per day per key by default, 5 enrolments per hour per address).

`admin.DOMAIN` (mTLS; the principal is the client certificate's SHA-256, `admin-api`):

| Route | Body | Does |
|:--|:--|:--|
| `POST /v1/publishers` | `{id, public_key, namespaces, contact}` | registers a publisher, active at once (operator) |
| `POST /v1/publishers/{id}/approve` | `{namespaces?}` | activates a pending or suspended publisher, optionally keeping only some namespaces (operator) |
| `POST /v1/publishers/{id}/suspend` | `{reason?}` | blocks a publisher; its catalog entries stay (operator) |
| `POST /v1/publishers/{id}/namespaces` | `{namespaces}` | replaces its namespaces; `*` grants every name (operator) |
| `POST /v1/publishers/{id}/rate` | `{requests_per_minute?, uploads_per_day?}` | overrides its rate limits (operator) |
| `POST /v1/publishers/{id}/keys` | `{public_key}` | adds a key to the record, no signed request needed (operator) |
| `POST /v1/publishers/{id}/keys/{key_id}/revoke` | `{mode: rotation \| compromise}` | revokes a key; compromise yanks what it signed; rebuilds the index (operator) |
| `POST /v1/versions/{name}/{version}/approve` \| `reject` \| `yank` | `{reason}` | the review decision; approve and yank rebuild the index (reviewer or operator) |
| `POST /v1/index/publish` | | asks `index-publisher` for a rebuild (operator) |
| `POST /v1/index/signature` | `{signature}` (the `.minisig` text over `staging/index.json`) | verifies it against `INDEX_PUBLIC_KEY` and publishes `published/index.json` and `.minisig` (operator) |

Statuses: domain `Invalid` 400, `Unauthorized` 401, `Forbidden` 403, `NotFound` 404, `Conflict` 409, a port failure 502, a body over 4 MiB 413; unknown JSON fields are refused. The upload body also carries `tests` (`tests.json`, base64), stored beside the bundle for the runner. The full bodies and the signed-request message are in [`docs/api.md`](docs/api.md).

## The command line

`cargo install --path crates/cli` installs `axlr-registry`. The admin commands take `--url https://admin.DOMAIN` and `--cert clients/<id>/identity.pem` (a client certificate from the private CA; `--ca` adds a private root for staging), or the environment variables `AXLR_REGISTRY_ADMIN_URL` and `AXLR_REGISTRY_CLIENT_CERT`.

| Command | Does |
|:--|:--|
| `publisher keygen [--out publisher.key]` | an Ed25519 key: the secret (mode 0600) and `<out>.pub`; it signs bundles and every request |
| `publisher identity --key <key>` | the public key and key id |
| `publisher enroll --id <id> --namespace <scope>… --contact <email> --key <key> --url https://api.DOMAIN` | self-service enrolment, pending until an operator approves it |
| `publisher sign <tool dir> --key <key> [--out sig.json]` | validates the directory as the registry will (manifest, files, `tests.json` beside them) and prints the bundle digest and the signature |
| `publisher upload <tool dir> --key <key> --url https://api.DOMAIN [--signature sig.json]` | `POST /v1/versions` with the manifest, files, tests and signature; prints the outcome |
| `publisher status <name> <version> --key <key> --url https://api.DOMAIN` | what became of an upload |
| `review list [--status scanned]`, `review show <name> <version>` | the queue and one version's scan, tests and review |
| `review approve\|reject\|yank <name> <version> --reason …` | the decision |
| `operator register-publisher --id <id> --public-key <file.pub> --namespace <scope>… --contact <email>` | a publisher the operator vouches for, active at once |
| `operator approve-publisher --id <id> [--namespace <scope>…]` | activates an enrolled (or suspended) publisher, optionally keeping only some namespaces |
| `operator suspend-publisher --id <id> [--reason …]` | blocks a publisher |
| `operator set-namespaces --id <id> --namespace <scope>…` | replaces its namespaces, widening or narrowing them; `--namespace '*'` grants every name |
| `operator set-rate --publisher <id> [--requests-per-minute N] [--uploads-per-day N]` | overrides its rate limits; an omitted flag restores the default |
| `operator add-key --publisher <id> --public-key <file.pub>` | adds a key to a publisher's record without a signed request (its only key is lost) |
| `operator revoke-key --publisher <id> --key-id <16 hex> --mode rotation\|compromise` | revokes a key; compromise yanks what it signed |
| `operator publish-index` | rebuilds the unsigned index in staging |
| `operator fetch-index [--out index.json]` | downloads the staging index to sign |
| `operator sign-index <index.json> --key minisign.key [--password-file …] [--out …] [--trusted-comment …]` | signs it offline with the registry's minisign key, in the form the console verifies (`minisign -V` accepts it too) |
| `operator upload-signature <index.json.minisig>` | the API verifies the signature and publishes the index |

## The local harness

`cargo run -p registry-local -- --publisher-id <id> --publisher-key <base64 public key>` runs `axlr-registry-local`: the publish API, the signed catalog (`index.json`, `.minisig`, `tools/…`, `skills/…`) and `POST /local/approve|yank/{name}/{version}` on one loopback port, from memory. It prints the `base_url` and the `public_key` a console's catalog settings take. Details in [`docs/operations.md`](docs/operations.md), "Local harness".

## Integration tests

The DynamoDB and S3 adapters have tests against DynamoDB Local and MinIO, behind the `integration` cargo feature and marked `#[ignore]`, so a plain `cargo test` never needs Docker. Locally:

```bash
just services      # once; `just services-stop` removes the containers
just integration
```

They read `DYNAMODB_ENDPOINT` and `S3_ENDPOINT` (defaults `http://localhost:8000` and `http://localhost:9000`) and the usual `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (`test` / `testtest` for the containers above); every test creates its own table and bucket. The `ci-main` integration job runs the same tests under `cargo llvm-cov`, so the 80 % gate counts the SDK adapters.

Status (19 Oct 2026): deployed. Release v0.3.5 (18 Oct) runs the stacks `axlr-registry-staging` and `axlr-registry-production` in eu-south-2; production serves the signed catalog at `https://registry.underpassai.com` (159 tools), the publish API at `https://api.registry.underpassai.com` and the admin API at `https://admin.registry.underpassai.com`. The release job runs the end-to-end test against staging before it promotes to production; production has no end-to-end run of its own. The admin API serves the reviewer's queue, the version detail and the staging index download. Still missing: the CloudFront invalidation after a signed publish (the stack grants `cloudfront:CreateInvalidation`, no code calls it yet).
