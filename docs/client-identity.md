# Client identity: one key per person, signed requests, per-key rate limits

Status: decided with Tirso on 17 Oct 2026; §6 implemented on 18 Oct 2026 (`docs/api.md` has the routes as served, the operator `add-key` of §2 included since 18 Oct 2026; the staging stack has not been re-bootstrapped). This replaces bearer tokens on the publish API; the admin API keeps mTLS, the catalog stays static behind CloudFront. The AXLR console and the `axlr-registry` CLI are the two clients; both follow this contract exactly, so the registry and the console can be built in parallel against it.

## 1. The key

- Every client holds one Ed25519 key pair. The console creates it on `/tools keygen` or, when none exists, on the first `/tools publish`, under its private state (`<state>/axlr/registry/client.key`, mode 0600, never in the workspace); the CLI creates it with `publisher keygen`. The same key signs bundles (already the case) and, from now on, every request.
- `key_id` = the first 16 hex characters of SHA-256 over the 32-byte public key (`KeyId::of`). A publisher may hold several keys (rotation); each is active or revoked.
- The registry never sees a private key. Losing one means enrolling a new key; a leaked one is revoked by the operator (`revoke-key`, rotation or compromise, as today).

## 2. Enrolment (self-service, pending until an operator approves)

`POST /v1/publishers/enroll`, public (behind the AXLR client gate and the web ACL), signed with the key being enrolled, which proves possession:

```json
{"id": "acme", "public_key": "<base64, 32 bytes>", "namespaces": ["acme_*"], "contact": "ops@acme.example"}
```

- `202 {"id": "acme", "status": "pending"}`; `409` when the id is taken by an active publisher; `400` on an invalid id, key, or namespace, and on the namespace `*` (every name), which only an operator grants (`POST /v1/publishers/{id}/namespaces` on the admin API, or registration).
- A pending publisher may do nothing else. `POST /v1/publishers/{id}/approve` (admin, operator) activates it, optionally narrowing `namespaces`; `POST /v1/publishers/{id}/suspend` blocks it (uploads refused, catalog entries untouched). States: `pending → active ⇄ suspended`.
- Re-enrolling an id that is pending replaces the pending request (same key or a new one); an active id cannot be re-enrolled, only given a new key by the operator (`add-key`) or by a signed `POST /v1/publishers/{id}/keys` from one of its active keys.

## 3. Signed requests (every call to `api.DOMAIN`)

Headers:

| Header | Value |
|:--|:--|
| `X-AXLR-Key` | the `key_id` |
| `X-AXLR-Timestamp` | seconds since the Unix epoch, decimal |
| `X-AXLR-Nonce` | 16 random bytes, base64 |
| `X-AXLR-Signature` | Ed25519 over the message below, base64 (64 bytes) |

Message (UTF-8, each line ended by `\n`):

```
axlr-request-v1
<METHOD in upper case>
<path, starting with /, no query>
<query string exactly as sent, or empty>
<SHA-256 of the body, lowercase hex; the hash of the empty body when there is none>
<timestamp>
<nonce>
```

Checks, in this order, each with its status: AXLR client gate (403), header shape (400), timestamp within ±300 s of the registry's clock (401 `stale`), key known and active and its publisher active, or the request is an enrolment (401 / 403 `pending` / `suspended`), signature (401), nonce unseen for that key in the last 10 minutes (401 `replay`; nonces are stored with a TTL), rate limit (429), then the route. Bearer tokens are gone: `Authorization` is ignored.

## 4. Rate limits per key

Fixed windows counted in DynamoDB with conditional increments (one write per request, items expire by TTL):

| Window | Default | Scope |
|:--|:--|:--|
| requests per minute | 60 | every signed request |
| uploads per day (UTC) | 20 | `POST /v1/versions` |
| enrolments per hour per IP | 5 | `POST /v1/publishers/enroll` (no key yet; keyed by source IP) |

A publisher record may override its two limits (`rate.requests_per_minute`, `rate.uploads_per_day`), set by the operator. `429` carries `Retry-After` in seconds. The web ACL's per-IP rule (1,000 per five minutes) stays as the anonymous first barrier, and the gateway's stage throttling as the global one.

## 5. What the console does

- `/tools keygen` creates the key and prints the public key and key id; `/tools identity` shows them.
- `/tools enroll <publisher id> <namespace>…` signs and sends the enrolment, and shows "pending: an operator of <catalog> must approve it".
- `/tools publish <tool>` builds the bundle from `.axlr/tools/<tool>/` plus `tests.json` and the manifest's `catalog` block, signs the bundle and the request, uploads, and then polls `GET /v1/versions/{name}/{version}` (also signed) until the scan and the sandbox tests settle, showing the findings.
- The catalog settings gain nothing: reads stay unauthenticated behind the client gate and the index signature.

## 6. What the registry changes

Domain: `PublisherStatus` (pending, active, suspended), `RequestSignature` (the canonical message, sign and verify), `Nonce`, `RateLimit` and `RateWindow` values; `Publisher` loses tokens and gains status, contact and rate overrides; `KeyId` unchanged. Application: ports `NonceStore` and `RateCounter`; use cases `EnrollPublisher`, `ApprovePublisher`, `SuspendPublisher`, `AddPublisherKey`, `AuthenticateRequest` (the ordered checks of §3, returning the publisher and key), and `SubmitVersion` / `QueryVersion` taking the authenticated publisher instead of a token; `IssueToken` and `Token` removed. HTTP: `SignedRequest` replaces `BearerToken`; the enrol and key routes; `429` with `Retry-After`. DynamoDB: `NONCE#<key id>#<nonce>` and `RATE#<key id>#<window>` items with TTL; the table gets a TTL attribute `expires_at`. CLI: `publisher enroll`, `publisher identity`; `PublishClient` signs every request; `operator approve-publisher`, `suspend-publisher`, `set-rate`. The e2e scenario enrols nothing (its publisher is pre-approved) and signs its requests. `docs/api.md` and `docs/operations.md` updated; the staging stack re-bootstrapped (the e2e publisher keeps its key; the token secret is deleted).
