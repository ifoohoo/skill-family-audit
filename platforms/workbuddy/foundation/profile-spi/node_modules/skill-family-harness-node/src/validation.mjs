import {
  ContractsError,
  SUPPORTED_DIALECTS,
  VALIDATION_POLICIES,
  compileSchema,
  findSchemaRegistration,
  validateDocument,
} from "skill-family-contracts";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";

/**
 * Dialect-aware schema validation with cached validators.
 *
 * The harness never re-implements schema interpretation: dialect routing
 * (draft-07 vs 2020-12 Ajv classes), Ajv instance caching per
 * dialect|policy, and the package-schema pre-registration all live in
 * skill-family-contracts. This layer only (1) resolves the dialect for a
 * registered schema when the caller does not override it, (2) caches the
 * compiled validate function per schema|dialect|policy, and (3) normalizes
 * every failure into the contracts result shape with registered codes.
 */

const validatorCache = new Map(); // `${schemaId}|${dialect}|${policy}` -> validate fn

function unsupportedPolicyResult(policy) {
  return {
    valid: false,
    errorCode: "SFC2004",
    errors: [
      {
        message: `unsupported validation policy: ${policy}`,
        params: { kind: HARNESS_ERROR_KINDS.UNSUPPORTED_POLICY },
      },
    ],
    data: undefined,
  };
}

/**
 * Resolves { schemaId, dialect, policy } against the frozen registry.
 * Returns { ok: true, schemaId, dialect, policy, registration } or
 * { ok: false, errorCode, message } with a registered code:
 * SFC1002 unknown $id, SFC1006 unsupported dialect, SFC2004 unknown policy.
 */
export function resolveSchemaContext({ schemaId, dialect, policy = "strict" } = {}) {
  if (typeof schemaId !== "string" || schemaId.length === 0) {
    return { ok: false, errorCode: "SFC1002", message: "schemaId must be a non-empty string" };
  }
  const registration = findSchemaRegistration(schemaId);
  if (!registration) {
    return { ok: false, errorCode: "SFC1002", message: `unknown schema $id: ${schemaId}` };
  }
  const resolvedDialect = dialect ?? registration.dialect;
  if (!Object.hasOwn(SUPPORTED_DIALECTS, resolvedDialect)) {
    return { ok: false, errorCode: "SFC1006", message: `unsupported dialect: ${resolvedDialect}` };
  }
  if (!Object.hasOwn(VALIDATION_POLICIES, policy)) {
    return { ok: false, errorCode: "SFC2004", message: `unsupported validation policy: ${policy}` };
  }
  return { ok: true, schemaId, dialect: resolvedDialect, policy, registration };
}

/**
 * Returns the cached compiled validator for a registered schema.
 * Dialect routing and Ajv instance caching are delegated to contracts; this
 * cache keeps the compiled validate function per schema|dialect|policy so a
 * repeated call never recompiles. Throws ContractsError/HarnessError with
 * registered codes (SFC1002, SFC1006, SFC1012) on failure.
 */
export function getValidator({ schemaId, dialect, policy = "strict" } = {}) {
  const context = resolveSchemaContext({ schemaId, dialect, policy });
  if (!context.ok) {
    if (context.errorCode === "SFC2004") {
      throw mechanismError(HARNESS_ERROR_KINDS.UNSUPPORTED_POLICY, context.message);
    }
    throw new ContractsError(context.errorCode, context.message, { schemaId });
  }
  const key = `${context.schemaId}|${context.dialect}|${context.policy}`;
  const cached = validatorCache.get(key);
  if (cached) return cached;
  const validate = compileSchema({ schemaId: context.schemaId }, { dialect: context.dialect, policy: context.policy });
  validatorCache.set(key, validate);
  return validate;
}

/** Number of cached validators (observability for tests and diagnostics). */
export function validatorCacheSize() {
  return validatorCache.size;
}

/**
 * Validates one document against a registered schema.
 * Never mutates caller input; returns the contracts result shape
 * { valid, errorCode, errors, data } where data is the normalized copy.
 * errorCode is one of null, SFC1001, SFC1002, SFC1006, SFC1012, or
 * SFC2004 (unknown policy) — all registered codes.
 */
export function validateContractDocument(document, { schemaId, dialect, policy = "strict" } = {}) {
  const context = resolveSchemaContext({ schemaId, dialect, policy });
  if (!context.ok) {
    if (context.errorCode === "SFC2004") {
      return unsupportedPolicyResult(policy);
    }
    return {
      valid: false,
      errorCode: context.errorCode,
      errors: [{ message: context.message }],
      data: undefined,
    };
  }
  return validateDocument(document, {
    schemaId: context.schemaId,
    dialect: context.dialect,
    policy: context.policy,
  });
}
