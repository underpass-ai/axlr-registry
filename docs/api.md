# The HTTP API as the CLI speaks it

Status: 17 Oct 2026. The routes are implemented by `crates/adapters/http` (`PublishRoute`, `AdminRoute` and the request and response types there) and spoken by the `axlr-registry` CLI (`crates/cli`), whose tests pin the bodies against a mock server. A change on either side is a change here first. Errors are a non-2xx status with a JSON body `{"error": "…"}`, which the CLI prints as `the registry answered <status>: <body>`.

## Publish API: `https://api.DOMAIN`, bearer token

Every request carries `Authorization: Bearer <token>` (32 to 256 visible ASCII characters), the token the operator issued; the registry keeps only its digest. An `Idempotency-Key` header makes a retried upload return the first answer.

### `POST /v1/versions`: submit a version

Body (`application/json`); contents are base64 so the bytes the digests cover travel exactly:

```json
{
  "manifest": "<base64 of manifest.json>",
  "files": { "count.py": "<base64>" },
  "tests": "<base64 of tests.json>",
  "key_id": "0123456789abcdef",
  "signature": "<base64 of the 64-byte Ed25519 signature over 'axlr-tool-bundle-v1\\n<bundle sha256>'>"
}
```

`files` holds exactly the names the manifest lists. `tests` is optional and is not part of the signed bundle; without it the version is accepted, gets a failed test report and cannot be approved. The server runs `SubmitVersion` (token scope, bundle validation, signature, policy scan, quarantine, test scheduling) and answers `201`:

```json
{ "name": "acme_count", "version": "1.0.0", "status": "scanned", "findings": [] }
```

`status` is `scanned` or `rejected` (a blocking finding, listed in `findings` with its rule, file, line and severity).

### `GET /v1/versions/{name}/{version}`: the publisher's view

`200` with `name`, `version`, `status`, `submitted_at`, `findings`, `tests_passed` (null until the runner reports), `failed_tests` and `rejected_reason`. The token must cover the name.

## Admin API: `https://admin.DOMAIN`, client certificate

Mutual TLS with a certificate from the private CA (`operations.md`); API Gateway refuses anything else before the Lambda runs. The Lambda maps the certificate's SHA-256 to a principal and its role: `reviewer` for the review routes, `operator` for all of them. Every served admin route is a `POST`.

| Method and path | Body | Answer | Use case |
|:--|:--|:--|:--|
| `POST /v1/versions/{name}/{version}/approve` | `{"reason": "…"}` (may be empty) | `200` `{"name", "version", "status": "approved", "index_rebuild": "scheduled"}`; `409` when the scan blocks, the tests have not passed or the status is not `scanned`; `401` when the reviewer is the publisher | `ApproveVersion` |
| `POST /v1/versions/{name}/{version}/reject` | `{"reason": "…"}` (required) | `200` `{…, "status": "rejected", "index_rebuild": "not needed"}` | `RejectVersion` |
| `POST /v1/versions/{name}/{version}/yank` | `{"reason": "…"}` (required) | `200` `{…, "status": "yanked", "index_rebuild": "scheduled"}`; `409` unless approved | `YankVersion` |
| `POST /v1/publishers` | `{"id": "acme", "public_key": "<base64 32-byte Ed25519 key>", "namespaces": ["acme_*"]}` | `201` `{"id"}` | `RegisterPublisher` |
| `POST /v1/publishers/{id}/tokens` | `{"scopes": ["acme_*"], "expires_at": "2027-01-01T00:00:00Z" \| null}` | `201` `{"token": "<shown once>", "digest": "<sha256>", "expires_at"}` | `IssueToken` |
| `POST /v1/publishers/{id}/keys/{key_id}/revoke` | `{"mode": "rotation" \| "compromise"}` (compromise when absent) | `200` `{"yanked": <count>, "index_rebuild"}` | `RevokeKey` |
| `POST /v1/index/publish` | | `202` `{"index_rebuild": "scheduled"}` after invoking `index-publisher`; operators only | `PublishIndex` through the trigger |
| `POST /v1/index/signature` | `{"signature": "<the four lines of index.json.minisig>"}` | `200` `{"published": true, "index_sha256"}`; `400` when the signature does not verify against the staging index and the registry's minisign public key | `PublishSignedIndex` |

The signature the operator uploads is what `axlr-registry operator sign-index` writes: minisign's prehashed form (`ED`, BLAKE2b-512 of the index), the key id, the trusted comment and the global signature, the form the AXLR console's `minisign.go` verifies and `minisign -V` accepts.

### Routes the CLI calls that `admin-api` does not serve yet

| Method and path | Called by | Expected answer |
|:--|:--|:--|
| `GET /v1/versions?status=scanned` | `review list` | `200` a list of version reports (the same shape as `GET /v1/versions/{name}/{version}` below), oldest submission first; `status` any of the five, `scanned` (the default) being the reviewer's queue (GSI1); `400` for another value |
| `GET /v1/versions/{name}/{version}` | `review show` | `200` `{name, version, status, submitted_at, findings, tests_passed, failed_tests, rejected_reason}`; `404` when unknown |
| `GET /v1/index/staging` | `operator fetch-index` | `200` the unsigned canonical `index.json` bytes (`application/json`), read from `staging/index.json`; `404` before the first publish; operators only |

Until they exist the CLI gets a `404`; a reviewer can still approve a version named by the publisher, and the operator can read `staging/index.json` from the bucket. Adding them is a follow-up in `AdminRoute` and `AdminApi`.

## Who calls what

```text
publisher   keygen ─► operator register-publisher (public key) ─► operator issue-token
publisher   sign / upload ──────────────────────────► publish-api ─► test-runner
reviewer    list / show / approve / reject / yank ──► admin-api
operator    publish-index ─► fetch-index ─► sign-index (offline) ─► upload-signature ─► published/
```
