/**
 * skill-family-contracts: the single authority for machine-readable structures,
 * protocols, stable error codes, and the protocol-name registry.
 *
 * v1 is frozen: eighteen top-level object schemas (the migration-manifest
 * contract was added in 1.1.0; the report-model and report-binding contracts
 * were added in 1.2.0; eight host-integration contracts were added in 1.3.0;
 * two durable-state contracts were added in 1.4.0), one kernel protocol, a closed set of nine mechanical
 * check types, and a bounded mandatory rule set. Validation is implemented
 * entirely on Ajv (dialect-aware), never on a hand-written schema-subset
 * interpreter.
 */

export const CONTRACT_OBJECTS = Object.freeze([
  "project-manifest",
  "profile-descriptor",
  "managed-file-lock",
  "operation-request",
  "operation-result",
  "migration-manifest",
  "report-model",
  "report-binding",
  "host-descriptor",
  "host-registry",
  "adapter-source",
  "host-capability-fact",
  "host-probe-result",
  "adapter-build-manifest",
  "host-operation-plan",
  "host-operation-receipt",
  "state-event-envelope",
  "state-snapshot-metadata",
]);

export const CONTRACT_BOUNDARY = Object.freeze({
  owns: ["machine-readable structures", "kernel protocol", "stable error codes"],
  doesNotOwn: ["generation", "semantic audit", "release state", "remote writes"],
});

/** Contracts package version: 1.4.0 adds the business-neutral durable-state structures. */
export const CONTRACTS_VERSION = "1.4.0";

export {
  ContractsError,
  ERROR_CODES,
  errorCodeRegistry,
  errorCodeInfo,
  isRegisteredErrorCode,
  assertRegisteredErrorCode,
  stableError,
} from "./errors.mjs";

export {
  loadRegistry,
  listSchemas,
  listProtocols,
  findSchemaRegistration,
  findSchemaByObject,
  findProtocol,
  registerSchema,
  registerProtocol,
} from "./registry.mjs";

export {
  SUPPORTED_DIALECTS,
  VALIDATION_POLICIES,
  detectDialect,
  compileSchema,
  validateDocument,
} from "./validator.mjs";

export { loadKernelProtocol, findOperation, checkOperation } from "./kernel.mjs";

export {
  CHECK_TYPES,
  MANDATORY_RULES,
  RULE_BUDGET,
  runChecks,
  collectUnresolvedRefs,
} from "./checker.mjs";

export {
  listFixtures,
  fixtureClasses,
  verifyFixture,
  verifyAllFixtures,
} from "./fixtures.mjs";

// Audit consumption surface (FND-060): versioned, read-only projection for
// independent audit consumers. Additive only; the dependency direction stays
// Audit -> Contracts (this module never imports audit-owned artifacts).
export {
  AUDIT_SURFACE_VERSION,
  AUDIT_DIGEST_ALGORITHMS,
  canonicalJson,
  digestDocument,
  describeAuditSurface,
  digestAuditSurface,
} from "./audit-surface.mjs";
