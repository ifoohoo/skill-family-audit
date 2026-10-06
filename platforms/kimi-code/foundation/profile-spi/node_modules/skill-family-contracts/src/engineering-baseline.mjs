import { ContractsError } from "./errors.mjs";
import { digestDocument } from "./audit-surface.mjs";
import { preflightJsonData } from "./inert-json.mjs";
import { validateDocument } from "./validator.mjs";

/** Public schema identity for the business-neutral engineering baseline. */
export const ENGINEERING_BASELINE_SCHEMA_ID =
  "https://contracts.skill-family.example/v1/engineering-baseline.json";

/** Public envelope kind for the business-neutral engineering baseline. */
export const ENGINEERING_BASELINE_KIND = "skill-family.engineering-baseline";

const BASELINE_FIELDS = Object.freeze([
  "schemaVersion",
  "kind",
  "provider",
  "id",
  "version",
  "digest",
  "canonicalRuleRefs",
  "referenceImplementation",
]);

function semanticFailure(message, instancePath, params = {}) {
  return {
    valid: false,
    errorCode: "SFC1001",
    errors: [{
      keyword: "engineeringBaseline",
      instancePath,
      schemaPath: `${ENGINEERING_BASELINE_SCHEMA_ID}#semantic`,
      message,
      params,
    }],
    data: undefined,
  };
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function compareRuleId(left, right) {
  const leftCodePoints = Array.from(left, (character) => character.codePointAt(0));
  const rightCodePoints = Array.from(right, (character) => character.codePointAt(0));
  const length = Math.min(leftCodePoints.length, rightCodePoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftCodePoints[index] !== rightCodePoints[index]) {
      return leftCodePoints[index] < rightCodePoints[index] ? -1 : 1;
    }
  }
  return leftCodePoints.length - rightCodePoints.length;
}

function validateCanonicalRuleRefs(refs) {
  for (let index = 1; index < refs.length; index += 1) {
    const previous = refs[index - 1].id;
    const current = refs[index].id;
    if (previous === current) {
      return semanticFailure(
        "canonicalRuleRefs must contain unique lineage ids",
        `/canonicalRuleRefs/${index}/id`,
        { id: current },
      );
    }
    if (compareRuleId(previous, current) > 0) {
      return semanticFailure(
        "canonicalRuleRefs must be sorted by lineage id",
        `/canonicalRuleRefs/${index}/id`,
        { previous, current },
      );
    }
  }
  return null;
}

function validateDigest(data) {
  const { digest, ...withoutDigest } = data;
  const expected = digestDocument(withoutDigest);
  if (digest !== expected) {
    return semanticFailure(
      "digest must equal the sha256 digest of canonical JSON with digest omitted",
      "/digest",
      { expected, received: digest },
    );
  }
  return null;
}

/**
 * Validates one engineering baseline without mutating caller input.
 * In addition to the registered JSON Schema, the function checks canonical
 * rule-lineage ordering and the self-binding SHA-256 digest. Both semantic
 * failures use the existing SFC1001 validation code.
 */
export function validateEngineeringBaseline(baseline) {
  const preflight = preflightJsonData(baseline, "", {
    keyword: "engineeringBaseline",
    schemaId: ENGINEERING_BASELINE_SCHEMA_ID,
    label: "engineering baseline",
  });
  if (!preflight.valid) return preflight;
  const result = validateDocument(preflight.data, {
    schemaId: ENGINEERING_BASELINE_SCHEMA_ID,
    dialect: "2020-12",
    policy: "strict",
  });
  if (!result.valid) return result;
  return validateCanonicalRuleRefs(result.data.canonicalRuleRefs)
    ?? validateDigest(result.data)
    ?? result;
}

function requireDescriptionOptions(options) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("describeEngineeringBaseline: options must be an object");
  }
  for (const key of ["provider", "id", "version", "canonicalRuleRefs", "referenceImplementation"]) {
    if (options[key] === undefined) {
      throw new TypeError(`describeEngineeringBaseline: missing required option \"${key}\"`);
    }
  }
}

/**
 * Builds a deterministic engineering baseline document and derives its digest
 * with the existing Contracts canonical JSON primitive. The returned document
 * is deeply frozen; provider-owned rule semantics are never interpreted.
 */
export function describeEngineeringBaseline(options) {
  const preflight = preflightJsonData(options, "", {
    keyword: "engineeringBaseline",
    schemaId: ENGINEERING_BASELINE_SCHEMA_ID,
    label: "engineering baseline",
  });
  if (!preflight.valid) {
    throw new ContractsError(
      preflight.errorCode ?? "SFC1001",
      `describeEngineeringBaseline: invalid input: ${preflight.errors[0]?.message ?? "validation failed"}`,
      { errors: preflight.errors },
    );
  }
  const safeOptions = preflight.data;
  requireDescriptionOptions(safeOptions);
  const canonicalRuleRefs = [...safeOptions.canonicalRuleRefs]
    .sort((left, right) => compareRuleId(left.id, right.id));
  for (let index = 1; index < canonicalRuleRefs.length; index += 1) {
    if (canonicalRuleRefs[index - 1].id === canonicalRuleRefs[index].id) {
      throw new ContractsError(
        "SFC1001",
        `describeEngineeringBaseline: duplicate canonical rule lineage id: ${canonicalRuleRefs[index].id}`,
        { instancePath: `/canonicalRuleRefs/${index}/id`, id: canonicalRuleRefs[index].id },
      );
    }
  }
  const withoutDigest = {
    schemaVersion: 1,
    kind: ENGINEERING_BASELINE_KIND,
    provider: structuredClone(safeOptions.provider),
    id: structuredClone(safeOptions.id),
    version: structuredClone(safeOptions.version),
    canonicalRuleRefs,
    referenceImplementation: structuredClone(safeOptions.referenceImplementation),
  };
  const baseline = {
    ...withoutDigest,
    digest: digestDocument(withoutDigest),
  };
  const result = validateEngineeringBaseline(baseline);
  if (!result.valid) {
    throw new ContractsError(
      result.errorCode ?? "SFC1001",
      `describeEngineeringBaseline: generated baseline is invalid: ${result.errors[0]?.message ?? "validation failed"}`,
      { errors: result.errors },
    );
  }
  return deepFreeze(result.data);
}

export { BASELINE_FIELDS };
