# Installation

## Requirements

- Node.js `>=22.0.0`

## npm

```bash
npm install agent-method-registry
```

## pnpm

```bash
pnpm add agent-method-registry
```

## CLI Usage

After installation, the CLI is available as `agent-method-registry`:

```bash
npx agent-method-registry validate --catalog catalog.yaml
npx agent-method-registry query --index index.json
```

## Skill-family adoption (v2 protocol, available since 0.2.0)

Installing a family plugin only adds an inventory candidate. It does not enable, trust, or bind the
implementation. A project adopting a v2 family should:

1. validate the Family API with the API authority/compiler facade;
2. validate the family implementation descriptor and trusted host inventory;
3. inspect the generated capability projection;
4. create an explicit project binding when required;
5. use `where-am-i` for project-aware next-step and skill recommendations;
6. execute contract-backed services only through a fresh Method Query and strict run method lock.

If a planner queries the registry directly, it may skip natural-language triage only. It must not
skip the project-facts/context/proof/version-lock preflight required to construct the Method Query.

For v2 library consumers, discovery is a candidate-to-prepared-document flow:

```javascript
const built = buildEffectiveIndex({
  familyApi,
  implementations,
  inventoryEntries,
  bindings,
});

const queried = queryEffectiveIndex({
  index: built.index,
  purpose: 'prepare', // use 'recommendation' for read-only discovery
  methodQueryCandidate: {
    mode: 'standard',
    intent: 'review',
    kind: 'workflow',
    projectFactsEvidence,
    authorization: { sideEffectBudget: 'write-review-result', granted: true },
  },
});
```

`projectFactsEvidence` is the complete, content-bound envelope produced during project
orientation. The Registry verifies its digest and derives `targetArtifact`,
`contractRevisionDigest`, and `projectFactsEvidenceDigest`; consumers must not repeat those facts
outside the envelope. Do not compute inventory snapshots, bundle digests, or Method Query digests
in the consumer. Use `preparedInventory` and `verifyProvider(...).observed`. Recommendation exposes
provider-state metadata without a handle. Each recommendation entry carries an `executable`
boolean derived from the same six-state gate as prepare; consumers only need to read `executable`
and must not recompute the six-state logic. Prepare issues the process-local
`preparedQueryHandle` only after installation, enablement, compatibility, trust, explicit project
binding, and authorization all pass. Missing or tampered evidence, empty inventory, stale
snapshots, unbound providers, insufficient budgets, and bundle drift are rejected rather than
filled with fallback evidence.

For v1 projects, preview conversion before any write:

```bash
npx agent-method-registry migrate \
  --catalog agent-methods/catalog.yaml \
  --project agent-methods/project.yaml \
  --migration-context agent-methods/migration-context.json \
  --dry-run \
  --out-plan agent-methods/migration-plan.json \
  --transaction-root .
```

Review unresolved mappings, collisions, provider selectors, conformance evidence, and source
digests. Apply requires the unchanged plan; rollback requires the explicit, untampered snapshot
and byte-identical apply outputs. If a target changed after apply, rollback fails before changing
any file.

## Programmatic Usage

```javascript
import { validateCatalog, buildEffectiveIndex, queryEffectiveIndex } from 'agent-method-registry';

// Validate a catalog
const result = validateCatalog(catalogData);
if (!result.ok) {
  console.error(result.diagnostics);
}

// Build effective index
const index = buildEffectiveIndex({ catalogs: [catalogData] });
if (index.ok) {
  // Query
  const query = queryEffectiveIndex({ index: index.index, domain: 'artifact' });
}
```

The package root intentionally remains limited to seven runtime functions plus `ERROR_CODES`.
Schemas and CLI migration surfaces do not add hidden root functions.

The v2 document discriminators are mandatory: `v2-implementation`, `v2-inventory`, `v2-binding`,
`v2-projection`, `v2-run-lock`, and `v2-migration-plan`. Each generated projection and run lock can
be round-tripped through `validateProjectOverlay` or `validateCatalog`. Family-level and
service-level mixed bindings must carry deterministic conformance evidence; mixed services also
require an interop TCK digest declared by every selected implementation. Binding scope and
side-effect budget are enforced again during strict resolve.

`apiRecognition` is a namespace classification (`STANDARD`, `THIRD_PARTY`, or `PROJECT`), not an
authority signature. Supply only Family APIs already validated by their authority compiler.
Project-owned implementations must declare `projectAuthority`; the same value is fixed through
inventory, binding, projection, run lock, and re-verification. A later authority/source attestation
protocol may prove who is entitled to publish a third-party or project namespace without changing
these provider identities.

Use matching API and service namespaces:

```text
artifact.<family>-family              → artifact.<family>.<service>
<reverse-domain>.<family>-family      → <reverse-domain>.<family>.<service>
project.<authority>.<family>-family   → project.<authority>.<family>.<service>
```

Existing v2 service IDs that retain `-family` before the service segment continue to work, but new
documents should use the suffix-free service namespace.

Public schemas are exported as package subpaths, for example:

```text
agent-method-registry/schemas/implementation.schema.json
agent-method-registry/schemas/projection.schema.json
```
