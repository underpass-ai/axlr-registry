# axlr-registry

The write side of the AXLR tool catalog: a small, safe artifact registry for pre-forged tools. Publishers upload signed tool versions, the registry scans them, runs their tests in a sandbox and keeps them for a human reviewer; approved versions are listed in a signed `index.json` that the AXLR console installs from with `/tools install`.

AXLR and this registry are sibling projects in separate repositories. This one never imports AXLR; the index format is the contract between them.

| Directory | Content |
|:--|:--|
| [`domain/`](domain/) | The model: publishers, keys and scoped tokens, bundles and their digests, publisher signatures, the policy scan, the version state machine (`submitted → scanned → approved \| rejected`, `approved → yanked`), tools and their ownership, the index builder |
| [`docs/domain.md`](docs/domain.md) | The design: intent, bounded context, model, scan rules, commands, roles, what is left out |

Not written yet: the HTTP API, the file store, the sandbox test runner (bubblewrap, no network), the reviewer and operator CLI, and the offline index signing step (minisign, with the key kept off the server).

```bash
go test ./...
```
