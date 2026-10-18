# The HTTP API as the CLI speaks it

Status: 17 Oct 2026. The routes are implemented by `crates/adapters/http` (`PublishRoute`, `AdminRoute` and the request and response types there) and spoken by the `axlr-registry` CLI (`crates/cli`), whose tests pin the bodies against a mock server. A change on either side is a change here first. Errors are a non-2xx status with a JSON body `{"error": "…"}`, which the CLI prints as `the registry answered <status>: <body>`.

## Publish API: `https://api.DOMAIN`, signed requests

Every request is signed with the publisher's Ed25519 key, as [`client-identity.md`](client-identity.md) §3 specifies; there are no bearer tokens and `Authorization` is ignored. The four headers:

| Header | Value |
|:--|:--|
| `X-AXLR-Key` | the key id (the first 16 hex characters of SHA-256 over the 32-byte public key) |
| `X-AXLR-Timestamp` | seconds since the Unix epoch, decimal |
| `X-AXLR-Nonce` | 16 random bytes, base64, never reused with the same key |
| `X-AXLR-Signature` | Ed25519 over the message below, base64 (64 bytes) |

The signed message, UTF-8, each line ended by `\n`: `axlr-request-v1`, the method in upper case, the path (no query), the query string exactly as sent (empty when none), the SHA-256 of the body in lowercase hex (`e3b0c442…b855` for no body), the timestamp, the nonce. The registry's `RequestSignature` and the CLI's `PublishClient` both implement it; the domain tests pin the message and a signature vector.

The checks run in this order, each with its status and, from the timestamp on, a `code` in the error body: the AXLR client gate (403), the header shape (400), the timestamp within ±300 s of the registry's clock (401 `stale`), the key known and active and its publisher active (401 `unknown_key`, 403 `pending`, 403 `suspended`; an enrolment skips this step and verifies with the key in its body), the signature (401 `bad_signature`), the nonce unseen for that key in the last 10 minutes (401 `replay`), the rate windows (429 `rate_limited` with `Retry-After` in seconds), then the route (404, 405). An `Idempotency-Key` header makes a retried upload return the first answer; keys are scoped to the signing key.

Rate limits per key, fixed windows aligned to the clock in UTC: 60 signed requests per minute and 20 uploads (`POST /v1/versions`) per day by default, which the operator may override per publisher (`POST /v1/publishers/{id}/rate`); enrolments are counted per source address, 5 per hour.

### `POST /v1/publishers/enroll`: self-service enrolment

Signed with the key being enrolled, which proves possession. Body:

```json
{"id": "acme", "public_key": "<base64, 32 bytes>", "namespaces": ["acme_*"], "contact": "ops@acme.example"}
```

`202 {"id": "acme", "status": "pending", "namespaces": ["acme_*"]}`. A pending publisher may do nothing else until an operator approves it (`approve-publisher`). Re-enrolling a pending id replaces the request, with the same key or a new one. `409` when the id is taken by an active or suspended publisher, or when the key already belongs to another publisher; `400` on an invalid id, key, namespace or contact. The e2e publisher and anyone the operator vouches for skip this: `operator register-publisher` creates them active.

### `POST /v1/publishers/{id}/keys`: another key for your own record

Signed with one of the publisher's active keys; `{id}` must be the caller's own id (`403` otherwise). Body `{"public_key": "<base64, 32 bytes>"}`; `201 {"id", "key_id"}`; `409` when the key is already registered.

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

`files` holds exactly the names the manifest lists. `tests` is optional and is not part of the signed bundle; without it the version is accepted, gets a failed test report and cannot be approved. The server runs `SubmitVersion` (the name inside the publisher's namespaces, bundle validation, the bundle signature with an active key, policy scan, quarantine, test scheduling) and answers `201`:

```json
{ "name": "acme_count", "version": "1.0.0", "status": "scanned", "findings": [] }
```

`status` is `scanned` or `rejected` (a blocking finding, listed in `findings` with its rule, file, line and severity).

### `GET /v1/versions/{name}/{version}`: the publisher's view

`200` with `name`, `version`, `status`, `submitted_at`, `findings`, `tests_passed` (null until the runner reports), `failed_tests` and `rejected_reason`. The name must be inside the caller's namespaces (`401` otherwise).

## Admin API: `https://admin.DOMAIN`, client certificate

Mutual TLS with a certificate from the private CA (`operations.md`); API Gateway refuses anything else before the Lambda runs. The Lambda maps the certificate's SHA-256 to a principal and its role: `reviewer` for the review routes, `operator` for all of them. Every served admin route is a `POST`.

| Method and path | Body | Answer | Use case |
|:--|:--|:--|:--|
| `POST /v1/versions/{name}/{version}/approve` | `{"reason": "…"}` (may be empty) | `200` `{"name", "version", "status": "approved", "index_rebuild": "scheduled"}`; `409` when the scan blocks, the tests have not passed or the status is not `scanned`; `401` when the reviewer is the publisher | `ApproveVersion` |
| `POST /v1/versions/{name}/{version}/reject` | `{"reason": "…"}` (required) | `200` `{…, "status": "rejected", "index_rebuild": "not needed"}` | `RejectVersion` |
| `POST /v1/versions/{name}/{version}/yank` | `{"reason": "…"}` (required) | `200` `{…, "status": "yanked", "index_rebuild": "scheduled"}`; `409` unless approved | `YankVersion` |
| `POST /v1/publishers` | `{"id": "acme", "public_key": "<base64 32-byte Ed25519 key>", "namespaces": ["acme_*"], "contact": "ops@acme.example"}` | `201` `{"id", "status": "active", "namespaces"}`: a publisher the operator vouches for, active without enrolment | `RegisterPublisher` |
| `POST /v1/publishers/{id}/approve` | `{"namespaces": ["acme_*"]}` (optional: keep only these, a subset of the enrolled ones) or an empty body | `200` `{"id", "status": "active", "namespaces"}`; `409` when already active; `400` when a namespace widens the enrolled ones; `404` | `ApprovePublisher` (also reactivates a suspended publisher) |
| `POST /v1/publishers/{id}/suspend` | `{"reason": "…"}` (may be empty or absent) | `200` `{"id", "status": "suspended", "namespaces"}`; `409` unless active | `SuspendPublisher` |
| `POST /v1/publishers/{id}/namespaces` | `{"namespaces": ["*"]}` (exact names, prefixes ending in `*`, or `*` alone for every name; at least one) | `200` `{"id", "status", "namespaces"}` the namespaces in force, status unchanged; `400` on none or an invalid scope; `404` unknown publisher | `SetPublisherNamespaces` |
| `POST /v1/publishers/{id}/rate` | `{"requests_per_minute": 600, "uploads_per_day": null}` (a `null` or absent limit restores the default) | `200` `{"id", "requests_per_minute", "uploads_per_day"}` the limits in force; `400` on zero | `SetPublisherRate` |
| `POST /v1/publishers/{id}/keys` | `{"public_key": "<base64 32-byte Ed25519 key>"}` | `201` `{"id", "key_id"}`: another key on the record, no request signed by its keys needed (a publisher whose only key is lost); `409` when the key is already registered; `404`; operators only | `AddPublisherKeyAsOperator` |
| `POST /v1/publishers/{id}/keys/{key_id}/revoke` | `{"mode": "rotation" \| "compromise"}` (compromise when absent) | `200` `{"yanked": <count>, "index_rebuild"}` | `RevokeKey` |
| `POST /v1/index/publish` | | `202` `{"index_rebuild": "scheduled"}` after invoking `index-publisher`; operators only | `PublishIndex` through the trigger |
| `POST /v1/index/signature` | `{"signature": "<the four lines of index.json.minisig>"}` | `200` `{"published": true, "index_sha256"}`; `400` when the signature does not verify against the staging index and the registry's minisign public key | `PublishSignedIndex` |

The signature the operator uploads is what `axlr-registry operator sign-index` writes: minisign's prehashed form (`ED`, BLAKE2b-512 of the index), the key id, the trusted comment and the global signature, the form the AXLR console's `minisign.go` verifies and `minisign -V` accepts.

The three `GET` routes the CLI's `review list`, `review show` and `operator fetch-index` call are served too: `GET /v1/versions[?status=]` (the reviewer's queue, oldest first, `scanned` by default; `400` for another value), `GET /v1/versions/{name}/{version}` (the same report as the publisher's view; `404` when unknown) and `GET /v1/index/staging` (the unsigned canonical `index.json`; `404` before the first publish; operators only).

### Not served yet

Not verified against a deployed stack: that API Gateway hands the Lambda the query string exactly as sent (no publish route carries one today).

## Who calls what

```text
publisher   keygen ─► enroll (signed with the new key) ─► operator approve-publisher
            (or: operator register-publisher with the public key, active at once)
publisher   sign / upload / status (every request signed) ─► publish-api ─► test-runner
reviewer    list / show / approve / reject / yank ──► admin-api
operator    publish-index ─► fetch-index ─► sign-index (offline) ─► upload-signature ─► published/
```
