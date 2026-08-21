import { readFileSync } from "node:fs";
import Ajv from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import { ContractsError } from "./errors.mjs";
import { loadRegistry, findSchemaRegistration } from "./registry.mjs";

/**
 * Dialect-aware validation built entirely on Ajv (no schema-subset interpreter).
 *
 * Dialects (draft detection): the $schema URI of a schema maps to a dialect
 * name; each dialect routes to its Ajv class.
 * Policies: named option profiles mapped straight onto Ajv options
 * (coercion, defaults, formats). Validation never mutates caller input;
 * the normalized copy is returned as result.data.
 */

export const SUPPORTED_DIALECTS = Object.freeze({
  "draft-07": Object.freeze({
    metaSchemaUri: "http://json-schema.org/draft-07/schema#",
  }),
  "2020-12": Object.freeze({
    metaSchemaUri: "https://json-schema.org/draft/2020-12/schema",
  }),
});

const DIALECT_CONSTRUCTORS = Object.freeze({
  "draft-07": Ajv,
  "2020-12": Ajv2020,
});

export const VALIDATION_POLICIES = Object.freeze({
  strict: Object.freeze({
    coerceTypes: false,
    useDefaults: false,
    allErrors: true,
    validateFormats: true,
  }),
  tolerant: Object.freeze({
    coerceTypes: "array",
    useDefaults: true,
    allErrors: true,
    validateFormats: true,
  }),
});

/** Detects the dialect of a schema document from its $schema URI; null when unknown/absent. */
export function detectDialect(schema) {
  const uri = schema && schema.$schema;
  if (typeof uri !== "string") return null;
  for (const [name, info] of Object.entries(SUPPORTED_DIALECTS)) {
    if (info.metaSchemaUri === uri) return name;
  }
  return null;
}

/** RFC 3339 date-time with calendar-correct day-of-month checking. */
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

const instanceCache = new Map(); // `${dialect}|${policy}` -> Ajv instance
const packageSchemasCache = { loaded: null };

function loadPackageSchemas() {
  if (packageSchemasCache.loaded) return packageSchemasCache.loaded;
  const registry = loadRegistry();
  const schemas = registry.schemas.map((entry) => ({
    registration: entry,
    // Registry file paths are package-root relative; this module sits in src/.
    document: JSON.parse(readFileSync(new URL(`../${entry.file}`, import.meta.url), "utf8")),
  }));
  packageSchemasCache.loaded = schemas;
  return schemas;
}

function getInstance(dialect, policy) {
  const key = `${dialect}|${policy}`;
  const cached = instanceCache.get(key);
  if (cached) return cached;
  const Constructor = DIALECT_CONSTRUCTORS[dialect];
  const ajv = new Constructor({
    ...VALIDATION_POLICIES[policy],
    strict: true,
  });
  ajv.addFormat("date-time", { type: "string", validate: isValidDateTime });
  // Pre-register package schemas whose declared dialect matches this instance,
  // so cross-schema $refs resolve and compile errors surface here.
  for (const { document } of loadPackageSchemas()) {
    if (detectDialect(document) === dialect) {
      ajv.addSchema(document);
    }
  }
  instanceCache.set(key, ajv);
  return ajv;
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

/**
 * Compiles a schema under a dialect + policy and returns the Ajv validate function.
 * Target is { schema } (document) or { schemaId } (registered $id).
 * Throws ContractsError: SFC1006 unsupported dialect, SFC1002 unknown $id,
 * SFC1012 schema does not compile.
 */
export function compileSchema(target, { dialect, policy = "strict" } = {}) {
  if (!DIALECT_CONSTRUCTORS[dialect]) {
    throw new ContractsError("SFC1006", `unsupported dialect: ${dialect}`, { dialect });
  }
  if (!VALIDATION_POLICIES[policy]) {
    throw new TypeError(`compileSchema: unknown validation policy: ${policy}`);
  }
  let validate;
  try {
    // Instance construction pre-registers package schemas; a broken schema
    // surfaces here as a compile failure too.
    const ajv = getInstance(dialect, policy);
    if (target.schema) {
      // A schema already registered under its $id is reused as-is; recompiling
      // the same $id in one Ajv instance is rejected by Ajv itself.
      const existing = target.schema.$id ? ajv.getSchema(target.schema.$id) : undefined;
      validate = existing ?? ajv.compile(target.schema);
    } else {
      validate = ajv.getSchema(target.schemaId);
    }
  } catch (cause) {
    if (cause instanceof ContractsError) throw cause;
    throw new ContractsError(
      "SFC1012",
      `schema does not compile under dialect "${dialect}": ${cause.message}`,
      { cause: String(cause.message) },
    );
  }
  if (!validate) {
    throw new ContractsError("SFC1002", `unknown schema $id: ${target.schemaId}`, {
      schemaId: target.schemaId,
    });
  }
  return validate;
}

/**
 * Validates one document.
 *
 * Options:
 * - schemaId: registered $id to validate against, or
 * - schema:   an explicit schema document (synthetic checks);
 * - dialect:  supported dialect name;
 * - policy:   "strict" (default) or "tolerant".
 *
 * Returns { valid, errorCode, errors, data }. errorCode is null on success and
 * otherwise one of SFC1001 (invalid), SFC1002 (unknown $id), SFC1006
 * (unsupported dialect), SFC1012 (schema does not compile). data is a
 * normalized deep copy (defaults/coercion applied only under tolerant policy);
 * caller input is never mutated.
 */
export function validateDocument(document, { schemaId, schema, dialect, policy = "strict" } = {}) {
  if (!DIALECT_CONSTRUCTORS[dialect]) {
    return {
      valid: false,
      errorCode: "SFC1006",
      errors: [{ message: `unsupported dialect: ${dialect}` }],
      data: undefined,
    };
  }
  if (!schema && !findSchemaRegistration(schemaId)) {
    return {
      valid: false,
      errorCode: "SFC1002",
      errors: [{ message: `unknown schema $id: ${schemaId}` }],
      data: undefined,
    };
  }
  let validate;
  try {
    validate = compileSchema(schema ? { schema } : { schemaId }, { dialect, policy });
  } catch (cause) {
    if (cause instanceof ContractsError) {
      return {
        valid: false,
        errorCode: cause.code,
        errors: [{ message: cause.message }],
        data: undefined,
      };
    }
    throw cause;
  }
  const data = structuredClone(document === undefined ? null : document);
  const valid = validate(data) === true;
  return {
    valid,
    errorCode: valid ? null : "SFC1001",
    errors: valid ? [] : normalizeErrors(validate.errors),
    data,
  };
}
