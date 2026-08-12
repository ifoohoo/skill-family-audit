import standaloneValidators from "./runtime/generated/standalone-map.mjs";
import { findNonJsonValue, normalizeValidationError } from "./runtime/json-boundary.mjs";

/** Every schema $id compiled into this bundle (Foundation graph + consumer schemas). */
export function listValidatableSchemaIds() {
  return Object.keys(standaloneValidators).sort();
}

/**
 * Validates one document against the schema registered under schemaId.
 * Unknown $ids are a caller error (TypeError). Validation never mutates the
 * caller input; the returned errors carry only plain JSON fields and expose
 * no validator instance or shared mutable state.
 */
export function validateBySchemaId(schemaId, document) {
  if (typeof schemaId !== "string" || !Object.hasOwn(standaloneValidators, schemaId)) {
    throw new TypeError(`validateBySchemaId: unknown schema $id: ${String(schemaId)}`);
  }
  const target = document === undefined ? null : document;
  const jsonIssue = findNonJsonValue(target);
  if (jsonIssue) {
    return {
      valid: false,
      errors: [
        {
          keyword: "json-value",
          instancePath: jsonIssue.instancePath,
          schemaPath: "#",
          message: `value is not representable as JSON: ${jsonIssue.reason}`,
          params: { reason: jsonIssue.reason },
        },
      ],
    };
  }
  const validate = standaloneValidators[schemaId];
  const clone = structuredClone(target);
  const valid = validate(clone) === true;
  return {
    valid,
    errors: valid ? [] : normalizeValidationError(validate.errors),
  };
}
