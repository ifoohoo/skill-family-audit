# agent-method-registry

[中文](README.zh-CN.md)

Deterministic registry for agent method catalog resolution, provider verification, and CLI
diagnostics.

`agent-method-registry` helps agentic coding projects maintain a canonical catalog of methods
(skills/workflows), resolve providers with filesystem verification, and diagnose registry health.
It is designed for deterministic local use with CLI tools, Node libraries, and CI pipelines.

The v2 protocol (available since 0.2.0) also provides the runtime side of a skill-family SPI: it validates
implementation descriptors, verifies installed bundles against trusted inventory, projects
capabilities, applies explicit project bindings, performs strict Method Query resolution, and
produces a content-bound run method lock.

## Family API and SPI model

The Java analogy is intentionally limited:

- a Family API is similar to a Java interface or API contract;
- a family implementation descriptor is similar to an `implements` declaration;
- trusted inventory, project binding, and registry resolution together play a role similar to a
  constrained SPI/`ServiceLoader`;
- this package is not JVM bytecode verification and does not use a Java classloader.

`artifact-chain-help` may render known Family APIs and the registry capability projection. In a
configured project, `where-am-i` is the user-facing trigger that combines project facts with that
projection to recommend what to do next and which skill to use. An external planner may query the
registry directly when it already has a structured Method Query, but it must still provide the
project-facts/context/proof/version-lock preflight evidence required by the calling system.

Provider state is orthogonal: **installed does not mean enabled, compatible, trusted, or uniquely
resolved**. All contract-backed services use strict resolution. Zero or multiple eligible
candidates fail closed; the registry never selects the first entry, the highest version, or an
undeclared builtin fallback.

Recommendation entries carry an `executable` boolean derived from the same six-state gate that
prepare uses. `executable: true` means all six orthogonal states are simultaneously satisfied
(INSTALLED, ENABLED, COMPATIBLE, VERIFIED, EXPLICIT_BINDING, project-binding). Consumers such as
`where-am-i` only need to read `executable`; they must not recompute the six-state logic.
`UNIQUE_COMPATIBLE` entries appear in recommendation output but are always `executable: false`.

The Cycle 4 projection path consumes a Family API that its authority has already compiled and
validated, including its immutable revision digest. It deterministically classifies supported
identities as `STANDARD`, `THIRD_PARTY`, or `PROJECT`; this classification is not authority
authentication. The registry checks every implementation and binding against that identity, but
does not mint authority or re-implement the Family API schema. Full third-party/project
authority-source attestations are a separate protocol and are not silently inferred from a prefix.
Project-owned implementations must carry an explicit `projectAuthority` through inventory,
binding, projection, run lock, and preflight re-verification.

The canonical identity pairs are:

```text
STANDARD     artifact.<family>-family
             artifact.<family>.<service>

THIRD_PARTY  <reverse-domain>.<family>-family
             <reverse-domain>.<family>.<service>

PROJECT      project.<authority>.<family>-family
             project.<authority>.<family>.<service>
             projectAuthority = project.<authority>
```

For compatibility, existing v2 service IDs that retain `-family` in the service namespace remain
valid. New documents should use the canonical suffix-free service namespace shown above.

## Install

```bash
npm install agent-method-registry
```

Node.js `>=22.0.0` is required.

## Quick Start

```javascript
import {
  validateCatalog,
  validateProjectOverlay,
  buildEffectiveIndex,
  queryEffectiveIndex,
  resolveEntry,
  verifyProvider,
  diagnoseRegistry,
} from 'agent-method-registry';
```

## Public API

The package exposes exactly **7 functions** plus `ERROR_CODES` and domain types:

| Function | Purpose |
|----------|---------|
| `validateCatalog` | Validate a v1 catalog or explicitly discriminated v2 implementation/inventory/run-lock/migration-plan document |
| `validateProjectOverlay` | Validate a v1 project overlay or a v2 project binding/projection document |
| `buildEffectiveIndex` | Build a deterministic v1 index or v2 capability projection |
| `queryEffectiveIndex` | Query a v1 index, recommend v2 services, or prepare an authorized v2 execution |
| `resolveEntry` | Resolve v1 providers or perform v2 strict resolution and create a run method lock |
| `verifyProvider` | Verify v1 paths or v2 inventory/bundle/run-lock evidence against the filesystem |
| `diagnoseRegistry` | Diagnose schema, projection, snapshot, binding, provider, lock, and migration health |

TypeScript overloads preserve the v1 result types when a v1 catalog, overlay, or index input is
passed. Published schemas are addressable through package subpaths such as
`agent-method-registry/schemas/implementation.schema.json` without adding runtime functions.

### v2 producer flow

Independent families do not copy Registry digest algorithms. Two existing functions accept
candidate facts and return complete documents normalized, validated, and signed by the Registry:

```javascript
const projection = buildEffectiveIndex({
  familyApi,
  implementations,
  inventoryEntries: discoveredInstallations,
  bindings,
});

const query = queryEffectiveIndex({
  index: projection.index,
  purpose: 'prepare', // use 'recommendation' for read-only discovery
  methodQueryCandidate: {
    mode: 'standard',
    intent: 'author',
    kind: 'workflow',
    projectFactsEvidence,
    authorization,
  },
});
```

`inventoryEntries` must be a non-empty array; on success, `preparedInventory` has passed the
authoritative Inventory validator. A `methodQueryCandidate` has exactly five top-level fields;
its complete `projectFactsEvidence` envelope is content-verified before the Registry derives the
target artifact, contract revision, evidence digest, candidate services, fresh snapshot, and query
digest. Recommendation results expose provider-state metadata and never contain a handle. A
successful prepare additionally proves installation, enablement, compatibility, trust, explicit
project binding, and authorization before the process-local `preparedQueryHandle` is issued. The
caller then passes it with an exact `serviceIdentity` to `resolveEntry`, receives a
`runMethodLock`, and re-verifies the filesystem with `verifyProvider` before execution.

Recommendation entries expose an `executable` boolean. When `executable` is true, the entry's six
orthogonal status fields are the unique executable combination; when false, the status fields
report the actual provider state. The `executable` flag and the prepare gate are derived from the
same shared function inside the Registry; callers must not recompute them.

`observed` reports only safely read realpaths and the actual bundle digest; it is not a trust
decision. Installation is not enablement either: binding, conformance, authorization, and
provider re-verification remain fail closed.

## CLI

```bash
# Validate catalog files
agent-method-registry validate --catalog catalog.yaml --project overlay.yaml

# Build effective index
agent-method-registry index --catalog catalog.yaml --out index.json

# Query the index
agent-method-registry query --index index.json
agent-method-registry query --index index.json --domain artifact --kind workflow

# v2 recommendation query: candidate is the single query source and no handle is returned
agent-method-registry query --index projection.json --candidate candidate.json

# Resolve a specific entry
agent-method-registry resolve --index index.json --ref my-plugin.entity.author --host claude-code --plugin-root ./plugins/my-plugin

# Preview a v1-to-v2 migration. Review the plan and collisions before apply.
agent-method-registry migrate --catalog catalog.yaml --project project.yaml \
  --migration-context migration-context.json --dry-run --out-plan migration-plan.json \
  --transaction-root .
```

The v1 catalog/overlay/query/resolve protocol remains supported. v2 migration supports explicit
dry-run, apply, and snapshot-backed rollback. Do not apply a generated plan until its mappings,
bindings, source digests, and collision report have been reviewed.
Rollback also verifies that every target is still byte-identical to the apply output. Later user
changes cause the whole rollback to fail before any target is restored or deleted.

All CLI commands output a single JSON envelope to stdout:

```json
{
  "ok": true,
  "data": { "..." },
  "diagnostics": []
}
```

Exit codes: `0` = success, `1` = data/index/entry error, `2` = malformed invocation.

## Safety

<!-- release-skill:capability:safe-first-command -->
A safe first command is `agent-method-registry --help`: it is read-only and writes nothing.
Likewise, `validate`, `query`, `resolve`, and `diagnose` only read the inputs you name.

<!-- release-skill:capability:external-write-boundary -->
External-write boundary: this package is deterministic and local. It makes no network calls and
performs no external writes. The only file writes are the ones you explicitly request: `--out`
(index), `--out-plan` (migration plan), and migration `--apply` confined to `--transaction-root`.

## License

[Apache-2.0](LICENSE)

See [NOTICE](NOTICE) for attribution.
