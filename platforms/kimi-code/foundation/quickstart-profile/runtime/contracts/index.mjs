// Fixed bundle surface: the exact stable contracts exports consumed by the
// projected quickstart harness, re-exported from mechanically projected sources.
export {
  ContractsError,
  ERROR_CODES,
  errorCodeRegistry,
  errorCodeInfo,
  isRegisteredErrorCode,
  assertRegisteredErrorCode,
  stableError,
} from "./errors.mjs";
export { canonicalJson, digestDocument } from "./canonical.mjs";
export { SESSION_TRACE_BUNDLE_SCHEMA_ID, SESSION_TRACE_BUNDLE_KIND, verifySessionTraceBundleInvariants } from "./session-trace-bundle-invariants.mjs";
export { ORCHESTRATION_BLUEPRINT_SCHEMA_ID, ORCHESTRATION_BLUEPRINT_KIND, verifyOrchestrationBlueprintStructure } from "./orchestration-blueprint-structure.mjs";
