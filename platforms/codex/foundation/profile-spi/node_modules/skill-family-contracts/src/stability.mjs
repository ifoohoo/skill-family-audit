/**
 * Capability maturity and historical-candidate migration policy.
 *
 * New capabilities use a maturity-neutral canonical identity from their first
 * candidate release. Historical candidate-labelled entrypoints migrate once
 * to that identity; later promotion cannot require another consumer change.
 */

export const CAPABILITY_MATURITY_LEVELS = Object.freeze([
  "experimental",
  "candidate",
  "stable",
  "deprecated",
]);

export const CANDIDATE_PROMOTION_POLICY = Object.freeze({
  policyVersion: 1,
  transition: "candidate-to-stable",
  canonicalIdentity: "preserve",
  canonicalEntrypoint: "preserve",
  operationName: "preserve",
  schemaId: "preserve",
  requestShape: "preserve",
  resultShape: "preserve",
  errorSemantics: "preserve",
  dependencyPinUpdate: "required-to-adopt-new-foundation-release",
  consumerSourceChange: "forbidden-from-canonical-entrypoint",
  consumerProjectionRebuild: "not-required-by-maturity-label-alone",
  boundInputProjectionRebuild: "follow-existing-projection-contract",
  newCandidateEntrypointNaming: "maturity-neutral",
  legacyCandidateEntrypoint: "deprecated-migrate-once",
  legacyCandidateEntrypointRemoval: "separate-major-with-exit-evidence",
  publishedArtifactMutation: "forbidden",
});

export const HISTORICAL_CANDIDATE_MIGRATION_POLICY = Object.freeze({
  policyVersion: 1,
  transition: "legacy-candidate-entrypoint-to-canonical-entrypoint",
  consumerMigration: "required-once",
  compatibilityWindow: "until-separate-major-removal",
  runtimeWarning: "forbidden",
  canonicalAndLegacyImplementation: "same-source",
  canonicalAndLegacySchemaValidation: "same-compiled-validator",
  removalRequires: Object.freeze([
    "published-deprecation",
    "consumer-exit-evidence",
    "separate-major-decision",
  ]),
});

export function describeCandidatePromotionPolicy() {
  return structuredClone(CANDIDATE_PROMOTION_POLICY);
}

export function describeHistoricalCandidateMigrationPolicy() {
  return structuredClone(HISTORICAL_CANDIDATE_MIGRATION_POLICY);
}
