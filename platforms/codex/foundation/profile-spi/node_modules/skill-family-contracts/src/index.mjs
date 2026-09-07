/**
 * skill-family-contracts: the single authority for machine-readable structures,
 * protocols, stable error codes, and the protocol-name registry.
 *
 * v1 is frozen: forty-five top-level object schemas (the migration-manifest
 * contract was added in 1.1.0; the report-model and report-binding contracts
 * were added in 1.2.0; eight host-integration contracts were added in 1.3.0;
 * two durable-state contracts were added in 1.4.0; the token-estimate-result
 * and surface-scan-policy contracts were added in the same 1.4.0 delivery;
 * the declared-read-surface-result and structured-scan-policy contracts were
 * added in 1.5.0 per FND-ADR-010 / FND-ADR-011; the timeout-policy and
 * watchdog-termination-envelope contracts were appended under the same 1.5.0
 * version per FND-ADR-012, append-only without a version bump; the
 * public-boundary-declaration, platform-difference-registry,
 * observation-scope, profile-adoption-declaration, audit-baseline-pin and
 * token-estimate-record contracts were added in 1.6.0 per the audit
 * remediation C5 delivery; the project-profile contract was added in 1.7.0
 * per FND-ADR-013; the source-authority-receipt contract was added in 1.8.0;
 * filesystem operation contracts were added in 1.9.0; the stable host
 * descriptor, probe-result and operation-plan semantics and peer adapter
 * verification contracts were extended in 1.10.0; host verification candidate
 * contracts were added in 1.11.0; the plugin verification pair and the
 * filesystem-tree-observation contract were added in 1.13.0; the consumer
 * contract vector and capability-adoption contracts were added in 1.14.0;
 * executable identity, symlink record, and host directory verification
 * contracts were appended in the same 1.14.0 delivery; the 1.15.0 protocol
 * coordinate freezes that forty-five-object surface and its audit baseline),
 * one kernel protocol, a closed set of nine
 * mechanical check types, and a bounded mandatory rule set. Validation is
 * implemented entirely on Ajv (dialect-aware), never on a hand-written
 * schema-subset interpreter.
 */

export const CONTRACT_OBJECTS = Object.freeze([
  "project-manifest",
  "profile-descriptor",
  "project-profile",
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
  "token-estimate-result",
  "surface-scan-policy",
  "declared-read-surface-result",
  "structured-scan-policy",
  "timeout-policy",
  "watchdog-termination-envelope",
  "public-boundary-declaration",
  "platform-difference-registry",
  "observation-scope",
  "profile-adoption-declaration",
  "audit-baseline-pin",
  "token-estimate-record",
  "source-authority-receipt",
  "filesystem-root-binding",
  "fixed-set-publication-manifest",
  "fixed-set-publication-receipt",
  "adapter-peer-verification-request",
  "adapter-peer-verification-result",
  "host-verification-request",
  "host-verification-result",
  "plugin-verification-request",
  "plugin-verification-result",
  "filesystem-tree-observation",
  "executable-identity-observation",
  "skill-family-directory-verification-request",
  "skill-family-directory-verification-result",
]);

export const CONTRACT_BOUNDARY = Object.freeze({
  owns: ["machine-readable structures", "kernel protocol", "stable error codes"],
  doesNotOwn: ["generation", "semantic audit", "release state", "remote writes"],
});

/** Contracts package version: 1.15.0 freezes the 45-object Foundation surface. */
export const CONTRACTS_VERSION = "1.15.0";

export {
  CAPABILITY_MATURITY_LEVELS,
  CANDIDATE_PROMOTION_POLICY,
  HISTORICAL_CANDIDATE_MIGRATION_POLICY,
  describeCandidatePromotionPolicy,
  describeHistoricalCandidateMigrationPolicy,
} from "./stability.mjs";

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

export {
  FOUNDATION_PACKAGE_VERSION,
  SFC1013,
  CONSUMER_CONTRACT_VECTOR_SCHEMA_ID,
  listConsumerContractVectors,
  verifyConsumerContractVector,
} from "./consumer-contract-vectors.mjs";

// Minimal consumption contract of the token estimate record (SG-33, audit
// friction F1): which field carries the numeric estimate, the degraded
// bare-integer shape, and the fail-closed refusal semantics. Pure functions;
// the harness re-exports them next to estimateTokens.
export {
  TOKEN_ESTIMATE_CONSUMPTION,
  TOKEN_ESTIMATE_CONSUMPTION_REASONS,
  TOKEN_ESTIMATE_CONSUMPTION_ERROR_KIND,
  consumeTokenEstimate,
  consumeTokenEstimateStrict,
} from "./token-estimate-consumption.mjs";

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
  BASELINE_PIN_KINDS,
  SCHEMA_ID_NAMESPACE,
  describeBaselinePinFacts,
  describeBaselinePin,
  verifyBaselinePin,
} from "./audit-surface.mjs";

// External source authority is supplied by a caller-owned receipt. Contracts
// validates its closed shape and exact subject binding, but never discovers,
// executes, resumes, or publishes the referenced source.
export {
  SOURCE_AUTHORITY_RECEIPT_SCHEMA_ID,
  validateSourceAuthorityReceipt,
  parseSourceAuthorityReceipt,
} from "./source-authority.mjs";
