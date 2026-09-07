import { readFileSync } from "node:fs";
import standaloneValidators from "../generated/standalone-map.mjs";

/**
 * Candidate quickstart profile v2 (unstable).
 *
 * Unlike v1, the collection is registered under its canonical $ids in one
 * dialect-matching Ajv instance: task and result reference the v2 Resource
 * schema and the stable operation-request/operation-result envelopes by $ref,
 * and no $ref is rewritten into a local $def. Canonical candidate schemas
 * stay absent from the stable registry on purpose; the finite migration map
 * below preserves the historical candidate-labelled identities in projected
 * Bundle dispatch without copying Schema documents.
 */

const documents = Object.freeze({
  protocol: load("../../schemas/foundation/protocol.json"),
  resource: load("../../schemas/foundation/resource.schema.json"),
  task: load("../../schemas/foundation/task.schema.json"),
  result: load("../../schemas/foundation/result.schema.json"),
  inventory: load("../../schemas/foundation/consumer-schema-inventory.schema.json"),
  surfaceInventory: load("../../schemas/foundation/harness-surface-inventory.schema.json"),
});

const BATCH_SCHEMAS = Object.freeze({
  request: load(new URL("../../schemas/foundation/schema-validation-batch-request.schema.json", import.meta.url)),
  result: load(new URL("../../schemas/foundation/schema-validation-batch-result.schema.json", import.meta.url)),
});

const VALIDATE_KINDS = Object.freeze(["resource", "task", "result"]);
const INVENTORY_KIND = "inventory";
const SURFACE_INVENTORY_KIND = "surfaceInventory";
const SURFACE_DETECTORS_KIND = "surfaceDetectors";

/**
 * Finite migration map for Schema identities published before 0.10.0.
 *
 * Values are the only canonical identities. The keys remain accepted by the
 * managed Bundle during the compatibility window, but no second Schema copy
 * or mutable alias registry is created.
 */
export const HISTORICAL_CANDIDATE_SCHEMA_ID_MIGRATIONS = Object.freeze({
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/resource.json":
    "https://contracts.skill-family.example/quickstart-profile/v2/resource.json",
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/task.json":
    "https://contracts.skill-family.example/quickstart-profile/v2/task.json",
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/result.json":
    "https://contracts.skill-family.example/quickstart-profile/v2/result.json",
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/consumer-schema-inventory.json":
    "https://contracts.skill-family.example/quickstart-profile/v2/consumer-schema-inventory.json",
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/harness-surface-inventory.json":
    "https://contracts.skill-family.example/quickstart-profile/v2/harness-surface-inventory.json",
  "https://contracts.skill-family.example/candidate/quickstart-profile/v2/harness-surface-detectors.json":
    "https://contracts.skill-family.example/quickstart-profile/v2/harness-surface-detectors.json",
  "https://contracts.skill-family.example/candidate/foundation-mechanisms/v1/schema-validation-batch-request.json":
    "https://contracts.skill-family.example/foundation-mechanisms/v1/schema-validation-batch-request.json",
  "https://contracts.skill-family.example/candidate/foundation-mechanisms/v1/schema-validation-batch-result.json":
    "https://contracts.skill-family.example/foundation-mechanisms/v1/schema-validation-batch-result.json",
});

const SURFACE_DETECTORS_SCHEMA_ID =
  "https://contracts.skill-family.example/quickstart-profile/v2/harness-surface-detectors.json";

const STABLE_ENVELOPE_IDS = Object.freeze([
  "https://contracts.skill-family.example/v1/operation-request.json",
  "https://contracts.skill-family.example/v1/operation-result.json",
]);

function load(name) {
  return Object.freeze(
    JSON.parse(readFileSync(new URL(name, import.meta.url), "utf8")),
  );
}

export const QUICKSTART_PROFILE_ID = "quickstart-profile";
export const QUICKSTART_PROFILE_VERSION = 2;
export const QUICKSTART_PROTOCOL = Object.freeze({
  name: documents.protocol.name,
  version: documents.protocol.version,
});
export const QUICKSTART_OPERATION = Object.freeze(
  documents.protocol.operations.map((operation) => operation.name),
);
export const CONSUMER_SCHEMA_INVENTORY_KIND = "skill-family.consumer-schema-inventory";
export const HARNESS_SURFACE_INVENTORY_KIND = "skill-family.harness-surface-inventory";
export const HARNESS_SURFACE_DETECTORS_KIND = "skill-family.harness-surface-detectors";

/** The frozen candidate protocol definition document (not a JSON Schema). */
export function loadQuickstartProtocol() {
  return structuredClone(documents.protocol);
}

/** Candidate-maturity schemas. They are deliberately absent from registry.json. */
export function quickstartProfileSchemas() {
  return structuredClone({
    resource: documents.resource,
    task: documents.task,
    result: documents.result,
  });
}

/** Enumerates the collection as registry-style entries ($id + document). */
export function listQuickstartProfileSchemas() {
  return VALIDATE_KINDS.map((kind) => ({
    kind,
    $id: documents[kind].$id,
    document: structuredClone(documents[kind]),
  }));
}

/** Candidate-maturity build-time contract; it is not a Quickstart runtime document. */
export function loadConsumerSchemaInventorySchema() {
  return structuredClone(documents.inventory);
}

export function loadHarnessSurfaceInventorySchema() {
  return structuredClone(documents.surfaceInventory);
}

export function loadSchemaValidationBatchRequestSchema() {
  return structuredClone(BATCH_SCHEMAS.request);
}

export function loadSchemaValidationBatchResultSchema() {
  return structuredClone(BATCH_SCHEMAS.result);
}

// The stable envelopes declare a date-time format; the candidate instance
// must define it identically so the envelopes compile under validateFormats.
const DATE_TIME_PATTERN =
  /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])[Tt]([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?([Zz]|[+-]([01]\d|2[0-3]):[0-5]\d)$/;

function isValidDateTime(value) {
  if (typeof value !== "string" || !DATE_TIME_PATTERN.test(value)) return false;
  const [datePart] = value.split(/[Tt]/, 1);
  const [year, month, day] = datePart.split("-").map(Number);
  const roundTrip = new Date(Date.UTC(year, month - 1, day));
  return (
    roundTrip.getUTCFullYear() === year &&
    roundTrip.getUTCMonth() === month - 1 &&
    roundTrip.getUTCDate() === day
  );
}

let collection = null;

function getCollection() {
  if (collection) return collection;
  const bound = {};
  for (const [kind, schemaId] of [
    ...[...VALIDATE_KINDS, INVENTORY_KIND, SURFACE_INVENTORY_KIND]
      .map((kind) => [kind, documents[kind].$id]),
    [SURFACE_DETECTORS_KIND, SURFACE_DETECTORS_SCHEMA_ID],
  ]) {
    const validate = standaloneValidators[schemaId];
    if (typeof validate !== "function") {
      throw new Error(
        `standalone validator is missing the quickstart profile schema: ${schemaId}`,
      );
    }
    bound[kind] = validate;
  }
  collection = Object.freeze(bound);
  return collection;
}

function normalizeErrors(ajvErrors) {
  if (!ajvErrors) return [];
  return ajvErrors.map((error) => ({
    keyword: error.keyword,
    instancePath: error.instancePath,
    schemaPath: error.schemaPath,
    message: error.message,
    params: error.params,
  }));
}

function escapePointerSegment(segment) {
  return String(segment).replaceAll("~", "~0").replaceAll("/", "~1");
}

const ARRAY_INDEX_PATTERN = /^(0|[1-9]\d*)$/;

// Inspects own properties through descriptors only, so accessors are refused
// without ever being invoked. JSON would drop symbol-keyed and non-enumerable
// properties silently and execute accessors, so all three classes fail closed.
function probeObjectMembers(value, instancePath, ancestors) {
  const symbolKeys = Object.getOwnPropertySymbols(value);
  if (symbolKeys.length > 0) {
    return {
      instancePath: `${instancePath}/${escapePointerSegment(String(symbolKeys[0]))}`,
      reason: "symbol-keyed property",
    };
  }
  const isArray = Array.isArray(value);
  let arrayLength = 0;
  if (isArray) {
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (!lengthDescriptor || lengthDescriptor.get || lengthDescriptor.set) {
      return { instancePath: `${instancePath}/length`, reason: "accessor property" };
    }
    arrayLength = lengthDescriptor.value;
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    if (isArray && key === "length") continue;
    const memberPath = `${instancePath}/${escapePointerSegment(key)}`;
    if (isArray && (!ARRAY_INDEX_PATTERN.test(key) || Number(key) >= arrayLength)) {
      return { instancePath: memberPath, reason: "non-index array property" };
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor) continue;
    if (descriptor.get || descriptor.set) {
      return { instancePath: memberPath, reason: "accessor property" };
    }
    if (!descriptor.enumerable) {
      return { instancePath: memberPath, reason: "non-enumerable property" };
    }
    const issue = probeJsonValue(descriptor.value, memberPath, ancestors);
    if (issue) return issue;
  }
  return null;
}

function probeJsonValue(value, instancePath, ancestors) {
  if (value === null) return null;
  const type = typeof value;
  if (type === "boolean" || type === "string") return null;
  if (type === "number") {
    return Number.isFinite(value) ? null : { instancePath, reason: "non-finite number" };
  }
  if (type === "bigint") return { instancePath, reason: "bigint" };
  if (type === "undefined") return { instancePath, reason: "undefined" };
  if (type === "function" || type === "symbol") return { instancePath, reason: type };
  if (type !== "object") return { instancePath, reason: type };
  const isArray = Array.isArray(value);
  if (!isArray) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      return {
        instancePath,
        reason: `non-plain object (${Object.prototype.toString.call(value)})`,
      };
    }
  }
  if (ancestors.has(value)) return { instancePath, reason: "circular reference" };
  ancestors.add(value);
  const issue = probeObjectMembers(value, instancePath, ancestors);
  ancestors.delete(value);
  return issue;
}

/**
 * Deep JSON-safety probe for candidate documents and caller-owned values.
 * Pure JSON data is null, booleans, finite numbers, strings, arrays, and
 * plain objects. Anything else (bigint, undefined, function, symbol,
 * non-finite number, non-plain object, circular reference) is reported as
 * { instancePath, reason } at the first offending location, instead of
 * surviving into structuredClone, digestDocument, or JSON.stringify where it
 * would throw or silently drift. Own properties JSON would ignore or execute
 * are refused the same way: symbol-keyed and non-enumerable properties are
 * dropped by serialization and accessors would be executed, so the probe
 * rejects them through descriptors without invoking any accessor. Repeated
 * references to the same JSON-safe object stay accepted when acyclic; only
 * true cycles fail closed. Returns null when the value is pure JSON.
 */
export function findNonJsonValue(value) {
  return probeJsonValue(value, "", new Set());
}

/**
 * Validates one candidate profile document against the collection registered
 * under real $ids. Returns { valid, errorCode, errors, data } with the same
 * shape as the stable validateDocument; data is a normalized deep copy and
 * caller input is never mutated. Documents containing non-JSON values are
 * refused deterministically before any clone or serialization.
 */
export function validateQuickstartProfileDocument(kind, document) {
  if (!VALIDATE_KINDS.includes(kind)) {
    throw new TypeError(`unknown quickstart profile document kind: ${String(kind)}`);
  }
  const target = document === undefined ? null : document;
  const jsonIssue = findNonJsonValue(target);
  if (jsonIssue) {
    return {
      valid: false,
      errorCode: "SFC1001",
      errors: [
        {
          keyword: "json-value",
          instancePath: jsonIssue.instancePath,
          schemaPath: "#",
          message: `value is not representable as JSON: ${jsonIssue.reason}`,
          params: { reason: jsonIssue.reason },
        },
      ],
      data: null,
    };
  }
  const validate = getCollection()[kind];
  const data = structuredClone(target);
  const valid = validate(data) === true;
  return {
    valid,
    errorCode: valid ? null : "SFC1001",
    errors: valid ? [] : normalizeErrors(validate.errors),
    data,
  };
}

/** Validate the complete consumer-side Schema ownership inventory. */
export function validateConsumerSchemaInventoryDocument(document) {
  const target = document === undefined ? null : document;
  const jsonIssue = findNonJsonValue(target);
  if (jsonIssue) {
    return {
      valid: false,
      errorCode: "SFC1001",
      errors: [{
        keyword: "json-value",
        instancePath: jsonIssue.instancePath,
        schemaPath: "#",
        message: `value is not representable as JSON: ${jsonIssue.reason}`,
        params: { reason: jsonIssue.reason },
      }],
      data: null,
    };
  }
  const data = structuredClone(target);
  const validate = getCollection()[INVENTORY_KIND];
  const valid = validate(data) === true;
  return {
    valid,
    errorCode: valid ? null : "SFC1001",
    errors: valid ? [] : normalizeErrors(validate.errors),
    data,
  };
}

export function validateHarnessSurfaceInventoryDocument(document) {
  const target = document === undefined ? null : document;
  const jsonIssue = findNonJsonValue(target);
  if (jsonIssue) {
    return {
      valid: false,
      errorCode: "SFC1001",
      errors: [{ keyword: "json-value", instancePath: jsonIssue.instancePath, schemaPath: "#", message: jsonIssue.reason, params: { reason: jsonIssue.reason } }],
      data: null,
    };
  }
  const data = structuredClone(target);
  const validate = getCollection()[SURFACE_INVENTORY_KIND];
  const valid = validate(data) === true;
  return { valid, errorCode: valid ? null : "SFC1001", errors: valid ? [] : normalizeErrors(validate.errors), data };
}

/** Validate explicit Harness detector clauses without changing receipt v1. */
export function validateHarnessSurfaceDetectorDocument(document) {
  const target = document === undefined ? null : document;
  const jsonIssue = findNonJsonValue(target);
  if (jsonIssue) {
    return {
      valid: false,
      errorCode: "SFC1001",
      errors: [{ keyword: "json-value", instancePath: jsonIssue.instancePath, schemaPath: "#", message: jsonIssue.reason, params: { reason: jsonIssue.reason } }],
      data: null,
    };
  }
  const data = structuredClone(target);
  const validate = getCollection()[SURFACE_DETECTORS_KIND];
  const valid = validate(data) === true;
  return { valid, errorCode: valid ? null : "SFC1001", errors: valid ? [] : normalizeErrors(validate.errors), data };
}
