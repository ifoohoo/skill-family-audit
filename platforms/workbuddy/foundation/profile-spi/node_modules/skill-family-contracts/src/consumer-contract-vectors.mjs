import { readFileSync } from "node:fs";
import { ContractsError } from "./errors.mjs";
import { validateDocument } from "./validator.mjs";

/** Exact Foundation release coordinate consumed by public contract vectors. */
export const FOUNDATION_PACKAGE_VERSION = "0.15.0";
/** Stable identity for all vector/package identity mismatches. */
export const SFC1013 = "SFC1013";
/** Public Schema identity carried by every consumer contract vector. */
export const CONSUMER_CONTRACT_VECTOR_SCHEMA_ID =
  "https://contracts.skill-family.example/v1/consumer-contract-vector.json";

const VECTOR_SCHEMA = JSON.parse(readFileSync(
  new URL("./schemas/consumer-contract-vector.schema.json", import.meta.url),
  "utf8",
));
const VECTOR_REGISTRY = deepFreeze(JSON.parse(readFileSync(
  new URL("./consumer-contract-vectors.json", import.meta.url),
  "utf8",
)));
const VECTOR_SETS = new Map(
  VECTOR_REGISTRY.sets.map((set) => [`${set.capabilityId}\0${set.vectorSetId}`, set]),
);

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function requireOptions(options, api) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError(`${api}: options must be an object`);
  }
  for (const key of ["capabilityId", "foundationVersion"]) {
    if (typeof options[key] !== "string" || options[key].length === 0) {
      throw new TypeError(`${api}: ${key} must be a non-empty string`);
    }
  }
  if (options.vectorSetId !== undefined &&
      (typeof options.vectorSetId !== "string" || options.vectorSetId.length === 0)) {
    throw new TypeError(`${api}: vectorSetId must be a non-empty string when provided`);
  }
}

function assertInstalledVersion(foundationVersion, api) {
  if (foundationVersion !== FOUNDATION_PACKAGE_VERSION) {
    throw new ContractsError(
      SFC1013,
      `${api}: Foundation package version mismatch (expected ${FOUNDATION_PACKAGE_VERSION}, received ${foundationVersion})`,
      { expected: FOUNDATION_PACKAGE_VERSION, received: foundationVersion },
    );
  }
}

function shapeResult(vector) {
  const result = validateDocument(vector, { schema: VECTOR_SCHEMA, dialect: "2020-12", policy: "strict" });
  return {
    valid: result.valid,
    errorCode: result.valid ? null : result.errorCode,
    errors: result.errors,
  };
}

function structurallyEqual(left, right) {
  if (Object.is(left, right)) return true;
  if (left === null || right === null || typeof left !== typeof right) return false;
  if (typeof left !== "object") return false;
  if (Array.isArray(left) !== Array.isArray(right)) return false;
  if (Array.isArray(left)) {
    return left.length === right.length && left.every((value, index) => structurallyEqual(value, right[index]));
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && structurallyEqual(left[key], right[key]));
}

function compareVectorIds(left, right) {
  const a = Array.from(left.vectorId, (character) => character.codePointAt(0));
  const b = Array.from(right.vectorId, (character) => character.codePointAt(0));
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  }
  return a.length - b.length;
}

function mismatch(vector, code, observed = null) {
  return {
    vectorId: typeof vector?.vectorId === "string" ? vector.vectorId : null,
    ok: false,
    expected: vector?.expected,
    observed,
    mismatchCode: code,
  };
}

/**
 * Returns a deterministic, deeply frozen view of the requested public vectors.
 * Unknown capabilities and sets intentionally return an empty frozen array.
 */
export function listConsumerContractVectors(options) {
  requireOptions(options, "listConsumerContractVectors");
  assertInstalledVersion(options.foundationVersion, "listConsumerContractVectors");
  const set = options.vectorSetId === undefined
    ? [...VECTOR_REGISTRY.sets].find((candidate) => candidate.capabilityId === options.capabilityId)
    : VECTOR_SETS.get(`${options.capabilityId}\0${options.vectorSetId}`);
  if (!set) return Object.freeze([]);
  const vectors = [...set.vectors]
    .sort(compareVectorIds);
  return Object.freeze(vectors);
}

/**
 * Validates vector identity and public structure without invoking a consumer,
 * Harness, fake, or host. Identity mismatches are reported fail-closed.
 */
export function verifyConsumerContractVector(vector, options) {
  requireOptions(options, "verifyConsumerContractVector");
  if (options.foundationVersion !== FOUNDATION_PACKAGE_VERSION) {
    return mismatch(vector, SFC1013);
  }
  if (!vector || typeof vector !== "object" || Array.isArray(vector)) {
    return mismatch(vector, "SFC1001", { valid: false, errorCode: "SFC1001" });
  }
  const shape = shapeResult(vector);
  if (!shape.valid) return mismatch(vector, shape.errorCode, shape);
  const identityMatches = vector.capabilityId === options.capabilityId &&
    vector.foundationVersion === options.foundationVersion &&
    (options.vectorSetId === undefined || vector.vectorSetId === options.vectorSetId);
  const set = VECTOR_SETS.get(`${vector.capabilityId}\0${vector.vectorSetId}`);
  const official = set?.vectors.find((candidate) => candidate.vectorId === vector.vectorId);
  if (!identityMatches || !official || !structurallyEqual(vector, official)) {
    return mismatch(vector, SFC1013);
  }
  return {
    vectorId: vector.vectorId,
    ok: true,
    expected: vector.expected,
    observed: shape,
    mismatchCode: null,
  };
}
