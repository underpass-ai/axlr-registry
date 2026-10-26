# Tool registry domain: a small artifact manager for pre-forged tools

Status: proposed (17 Oct 2026); the Rust crate [`crates/domain`](../crates/domain/) implements the model below, one type per file, with its invariants tested; [`crates/application`](../crates/application/) holds the ports and use cases. The hosting is in [`architecture.md`](architecture.md). Decided with Tirso on 17 Oct 2026: publisher identity is one Ed25519 key per publisher that signs bundles and requests (no tokens, no delegated OAuth; [`client-identity.md`](client-identity.md)); one channel, `official`, in the first version; the registry is a separate `axlr-registry` binary with file state, and the key that signs the index is kept off the server. This repository is the registry service; the console side (install, `/tools`, the signed-index client) lives in the AXLR repository, whose `docs/plans/2026-10-16-tool-registry-design.md` describes the read side and `docs/plans/2026-10-16-prebuilt-tools-catalog.md` the tools. The two are sibling projects: this one never imports AXLR, and the index format is the contract between them.

## Intent

The console already installs tools from a static `index.json` signed with a minisign Ed25519 key (`/tools install` in the AXLR console). This registry is the write side that produces that index: a publisher uploads a tool version, the registry checks it, a reviewer approves it, and the registry publishes a new signed index. Simple, useful and safe means:

- a version is immutable, a correction is a new version, and a withdrawal travels in the signed index so every console marks what it installed;
- two signatures with two trust roots: the publisher signs the bundle (provenance), the registry signs the index (what the console trusts);
- "reviewed" is a verdict with a reviewer and a time, never a proof: no scanner shows that a Python or bash file is harmless. The registry does what is deterministic (policy scan, sandboxed tests, immutable digests, a human gate) and says exactly that on the install card.

## Bounded context

The registry owns publishers, tools, versions, reviews and index snapshots. It does not own installation (the console's forged-tools registry), execution (`axlr_run_tool`) or the catalog site (generated from the index). The console reads only the published index and files; it never talks to the write API.

## Model

| Aggregate or value | Fields | Invariants |
|:--|:--|:--|
| `PublisherID` | `[a-z0-9][a-z0-9-]{1,31}` | unique |
| `Publisher` | status (`pending → active ⇄ suspended`), contact, keys (`KeyID` = first 16 hex of SHA-256 of the public key, Ed25519 public key, active or revoked), namespaces (exact names, `prefix_*`, or `*` for every name), rate overrides | only an active publisher publishes, and only names inside its namespaces; an approval may narrow the namespaces, never widen them; `*` is granted only by an operator (registration or `set_namespaces`), never by enrolment; a revoked key never verifies again; a key id belongs to one publisher |
| `RequestSignature` | key id, timestamp, `Nonce` (16 bytes), 64-byte Ed25519 signature over the canonical request (`axlr-request-v1`, method, path, query, body SHA-256, timestamp, nonce) | fresh within ±300 s; a nonce is accepted once per key; verifies with an active key of an active publisher |
| `RateLimit`, `RateWindow` | a positive count; a minute, hour or UTC-day window aligned to the clock | 60 requests per minute and 20 uploads per day per key unless overridden, 5 enrolments per hour per address |
| `ToolName` | the forged-tool rule `^[a-z][a-z0-9_]{1,47}$` | one owner for life; a name is reserved to its publisher at the first accepted submission |
| `Version` | semver `MAJOR.MINOR.PATCH` | a new version is strictly greater than every version the tool already has, approved or not |
| `Kind` | `tool` or `skill`, read from the manifest's `kind`; absent is `tool` | a name is one kind for life (see "Skills") |
| `Bundle` | `manifest.json` bytes plus one to eight files | the manifest is a forged tool plus its `catalog` block (`ToolManifest`), or a skill's (`SkillManifest`, see "Skills"); a tool's `args` names one of the files; file names are `[A-Za-z0-9_.-]+` with no path; text only (no NUL byte), at most 256 KiB each; `BundleDigest` = SHA-256 of the canonical listing `manifest <digest>` then `file <name> <digest>` sorted |
| `PublisherSignature` | key id, 64-byte Ed25519 signature over `axlr-tool-bundle-v1\n<bundle digest>` | verifies with an active key of the submitting publisher at submission time |
| `ToolVersion` | name, version, publisher, manifest digest, file digests, bundle digest, signature, category, summary…, status, scan, tests, review | status machine: `submitted → scanned → approved \| rejected`, `approved → yanked`; a yank keeps the record and carries a reason |
| `ScanReport` | findings (rule, file, line, severity `block` or `warn`, detail) | `block` findings reject the version automatically; `warn` findings are shown to the reviewer and on the card |
| `TestReport` | cases, passed, failed; produced by the sandbox adapter from a tool's `tests.json`, or by the skill checks | approval needs every case passed |
| `Review` | reviewer, decision, reason, time | the reviewer is not the publisher; approval needs a clean scan and a passing test report |
| `IndexSnapshot` | `schema_version`, `catalog`, `generated_at`, `tools[]` (the client's entry fields plus `publisher`, `publisher_key_id`, `bundle_sha256`, `signature`, `reviewed_at`, `reviewer`), `skills[]` (see "Skills"), `revocations[]` (name, version, reason, time), `revoked_keys[]` | built only from approved, non-yanked versions; its canonical bytes are what the registry key signs |

### Policy scan (deterministic, in the domain)

Rules run over every file by the manifest's `program`:

| Rule | Python | bash | node | Severity |
|:--|:--|:--|:--|:--|
| network | `socket`, `urllib`, `http.client`, `requests`, `ftplib`, `smtplib` | `curl`, `wget`, `nc`, `ssh`, `/dev/tcp` | `require("net"/"http"/"https"/"dns")`, `fetch(` | `block` when the manifest says `network: false`, `warn` otherwise |
| process | `subprocess`, `os.system`, `os.exec*`, `os.popen`, `ctypes`, `multiprocessing` | `eval`, `exec` of a variable, `ssh` | `child_process` | `block` |
| dynamic code | `eval(`, `exec(`, `compile(`, `__import__(`, `importlib` | `eval`, `source <(` | `eval(`, `new Function(` | `block` |
| obfuscation | base64 or hex blobs of 200+ characters, `\x` escape density | `base64 -d`, blobs | blobs, `Buffer.from(..., "base64")` | `block` |
| escape the workspace | `os.environ`, `expanduser("~")`, absolute `/home`, `/etc`, `..` segments | `$HOME`, `~`, absolute paths, `rm -rf` | `process.env`, `os.homedir()` | `warn` |
| binary or oversized file | a NUL byte, more than 256 KiB | | | `block` |

A scan is a pure function of the bundle, so the same bundle always yields the same report and the reviewer can reproduce it.

## Skills

A catalog entry is a tool or a skill. A skill is guidance the model opens on demand (`axlr_skill` in the console): a few text files and the tools the procedure expects, with no program. Everything else is shared with tools: the name space and its ownership, the bundle and its digests, the publisher signature, the version lifecycle, the review, the index and its signature, and revocations. The aggregate keeps its name, `Tool`, and stands for a catalog entry of either kind.

```json
{"kind": "skill", "name": "incident_triage", "description": "Triage a production incident from its logs: timeline, blast radius, first hypothesis, next check.",
 "files": ["SKILL.md", "checklist.md"], "tools": ["local_read", "local_search", "log_summarise"],
 "catalog": {"version": "1.0.0", "category": "programming", "tags": ["sre", "incident"], "license": "MIT", "source": "original"}}
```

| Field | Rule |
|:--|:--|
| `kind` | `skill`. A manifest without `kind`, or with `kind: tool`, is a tool and reads exactly as before skills; any other value is refused |
| `name` | the `ToolName` rule, in the same name space as tools: one owner for life, and one kind for life. `Tool::add` refuses a version of the other kind with `<name> is a tool; a skill needs another name` (and the reverse) |
| `description` | 1 to 1024 characters, not blank |
| `files` | one to eight flat names (`FileName`), `SKILL.md` among them; text (no NUL byte), at most 256 KiB each, as a tool's |
| `tools` | zero to 32 distinct `ToolReference`s, `^[a-z][a-z0-9_]{0,63}(/[A-Za-z0-9_.-]{1,64})?$`: a built-in or catalog tool, or an MCP tool as `server/tool`. Informative: nothing is installed with the skill |
| `catalog` | `version`, `category` and `license` required, `tags` and `source` optional, as a tool's; `requires` empty or absent, `network` false or absent, `example` absent |

Unknown fields are refused for either kind, so a manifest is one kind, and since the bundle digest covers the manifest, a tool's signature cannot be presented as a skill's. In the crate, `Manifest` is an enum over `ToolManifest` and `SkillManifest`; only a tool has a program.

**Scan.** A skill runs nothing, so the program rules do not apply. Every line of every file, Markdown headings included, goes through the obfuscation rule (base64 or hex blobs of 200 characters or more, runs of `\x` escapes), which blocks.

**Checks instead of tests.** The runner starts no program for a skill and needs no sandbox. It records a report of five cases, each a deterministic check over the quarantined files (`SkillCheck` in the runner crate):

| Case | Passes when |
|:--|:--|
| `SKILL.md` | the file is present and valid UTF-8 |
| `front_matter` | `SKILL.md` does not open with a `---` line, or its front matter is closed by another `---` line and its `name:`, when present, is the manifest's name |
| `links` | every inline Markdown link in `SKILL.md` whose target has no scheme and is not absolute names one of the bundle's files, once a `#anchor` or `?query` and a leading `./` are removed; fenced code blocks are skipped |
| `tools` | every `tools` entry is a well-formed tool reference |
| `tests.json` | there is none, or it is a non-empty list of `{name, prompt, expect}` with distinct, non-blank names, a non-blank prompt, and `expect` keys only from `tools` and `answer_contains` (lists of strings) |

The registry has no model, so it does not run a skill's cases; `tests.json` stays in quarantine beside the bundle, as a tool's does, unsigned and never published. A skill without `tests.json` passes on the other checks and is approvable; a tool without tests is still not.

**Index.** `skills[]` sits beside `tools[]`, always present and empty when no skill is approved; entries are built from approved, non-yanked skill versions and sorted by name then version. A skill entry has exactly `name`, `version`, `category`, `tags`, `summary`, `license`, `manifest` (`skills/<name>/<version>/manifest.json`), `manifest_sha256`, `files`, `tools`, `updated_at`, `publisher`, `publisher_key_id`, `bundle_sha256`, `signature`, `reviewed_at`, `reviewer` and `warnings` (omitted when empty): no `program`, `requires` or `network`. Yanked skill versions go to the shared `revocations` (a name is unique across kinds). Tool entries are unchanged, and a console from before skills ignores `skills`.

**Layout.** The same DynamoDB items and quarantine prefixes as tools. The stored manifest of a skill carries `"kind": "skill"`; a tool's is stored without `kind`, byte for byte as before, so items written before skills read as tools. An approved skill's manifest and files are published under `published/skills/<name>/<version>/` and served as `skills/<name>/<version>/…`. The version reports (`GET /v1/versions/{name}/{version}` for the publisher and the reviewer, and the reviewer's queue) carry `kind`.

## Commands, events and who may run them

| Command | Actor | Preconditions | Result and event |
|:--|:--|:--|:--|
| `RegisterPublisher` | registry operator | id unused | active `Publisher` with its first key, namespaces and contact; `PublisherRegistered` |
| `EnrollPublisher` | the publisher, signed with the key being enrolled | id unused or pending | pending `Publisher`; `PublisherEnrolled` |
| `ApprovePublisher`, `SuspendPublisher`, `SetPublisherRate` | operator | pending or suspended → active; active → suspended | status or limits changed; `PublisherApproved` / `PublisherSuspended` |
| `AddPublisherKey` | the publisher, signed with one of its keys | key id unused | another key; `KeyAdded` |
| `AddPublisherKeyAsOperator` | operator | key id unused by another publisher | another key on any publisher's record, for a lost key; audited as `add_key` |
| `AuthenticateRequest` | registry, before every publish route | the ordered checks of `client-identity.md` §3 | the publisher and the key, or the exact refusal |
| `RevokeKey` | operator | | `KeyRevoked` (carried in the next index) |
| `Submit` | publisher (authenticated request) | publisher active and the name inside its namespaces; name unowned or owned by this publisher; version greater than the latest; bundle valid; signature verifies | `ToolVersion` in `submitted`; `VersionSubmitted` |
| `Scan` | registry (automatic) | `submitted` | `scanned` with the report, or `rejected` when a finding blocks; `VersionScanned` / `VersionRejected` |
| `RunTests` | registry (sandbox adapter: bubblewrap, no network, `PATH` and `HOME` only) | `scanned` | `TestReport` attached; `TestsRecorded` |
| `Approve`, `Reject` | reviewer (a principal with the `reviewer` role, not the publisher) | `scanned`, clean, tests passed | `approved` / `rejected`; `VersionApproved` / `VersionRejected` |
| `Yank` | reviewer or operator | `approved` | `yanked` with the reason; `VersionYanked` |
| `PublishIndex` | registry, after every approval or yank | | `IndexSnapshot` canonical bytes handed to the signing port; `IndexPublished` with the index digest |

Authentication and roles live in the adapters and use cases (an HTTP API with signed requests for publishers and mTLS for reviewers and the operator): the adapter enforces who may call which command, and the domain enforces state, ownership, signatures and the rule that a reviewer is not the version's publisher. The registry key never sits on the API host: `PublishIndex` writes the unsigned canonical index and a separate signing step (a CLI with the key, or a CI job) produces `index.json.minisig`; the console refuses an index without a valid signature, so an unsigned publish is harmless.

## Key revocation: rotation or compromise

`RevokeKey` has two uses and the operator says which:

- **Rotation** (the publisher adds a new key and retires the old one): versions signed with the old key stay listed; their signatures were valid when made, and the index carries the key in `revoked_keys` so a console can tell a signature made before the revocation from one it should no longer accept.
- **Compromise**: every version signed with the key is yanked in the same operation, with the reason, and the next index carries both the revocations and the key. Nothing signed with a compromised key stays installable.

The default is compromise: an operator who only means to rotate says so.

## Work this implies on the AXLR side

The console's catalog client reads the entry fields through `updated_at` and ignores the rest. For the registry's safety properties to reach the person, the console needs to: honour `revocations` (mark an installed version `broken` with the reason, refuse to run it, offer the newer version) and `revoked_keys`; show the publisher and reviewer on the install card; and verify the publisher signature over the bundle digest as a second check beside the index signature. Until then the registry's guarantees stop at the index.

## Layout

The registry serves `tools/<name>/<version>/manifest.json` and the files beside it, one directory per version, so an old version's files never change; skills are served the same way under `skills/<name>/<version>/`. The static catalog repository in AXLR serves `tools/<category>/<name>/`; the console follows the `manifest` path in the index either way. The versioned layout is canonical for anything the registry publishes.

## What is deliberately left out

Multiple channels, delegated identity (GitHub), download counts, dependency resolution between tools, and automatic approval. Each is additive; none is needed to be safe.

## Verification

`cargo test --workspace` covers: the publisher status machine and namespace narrowing, the canonical request message and a pinned signature vector, every check of a signed request in order with the minute, day and per-address windows, revoked keys, bundle validation (path traversal, `args` outside the files, nine files, a binary file), signature verification and tampering, every scan rule with the block/warn split by the `network` declaration, the version state machine (approval refused without a clean scan or passing tests or by the publisher, yank only when approved, version ordering, immutability), the index (only approved and non-yanked versions, revocations carried, canonical bytes stable and carrying the fields the console client reads), and skills (the manifest rules and `kind` dispatch, a name keeping its kind, the obfuscation-only scan, the five checks, the `skills` list with exactly its fields, publication under `skills/`, and a stored tool manifest unchanged).
