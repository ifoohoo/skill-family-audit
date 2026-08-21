import { readFileSync } from "node:fs";
import Ajv from "ajv";

function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const val = obj[key];
    if (val !== null && typeof val === 'object' && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

/**
 * Frozen v1 kernel protocol access: states, transitions, and the operation
 * vocabulary with per-operation params contracts.
 *
 * checkOperation enforces the kernel-level intake for a request payload:
 * unknown operation -> SFC2002; params violating the frozen params contract
 * -> SFC2003. Envelope validation itself is the operation-request schema's job.
 */

const KERNEL = deepFreeze(JSON.parse(
  readFileSync(new URL("./kernel-protocol.json", import.meta.url), "utf8"),
));

const paramsAjv = new Ajv({ allErrors: true, strict: true });
const paramsValidators = new Map();

/** The frozen kernel protocol document. */
export function loadKernelProtocol() {
  return KERNEL;
}

/** Operation registration entry for a name, or null. */
export function findOperation(name, kernel = KERNEL) {
  return kernel.operations.find((operation) => operation.name === name) ?? null;
}

/**
 * Checks an operation name + params against the frozen kernel vocabulary.
 * Returns { ok, code, errors }: code is null, "SFC2002", or "SFC2003".
 */
export function checkOperation(operation, params) {
  const entry = findOperation(operation);
  if (!entry) {
    return {
      ok: false,
      code: "SFC2002",
      errors: [{ message: `unknown operation: ${operation}` }],
    };
  }
  let validate = paramsValidators.get(entry.name);
  if (!validate) {
    validate = paramsAjv.compile(entry.params);
    paramsValidators.set(entry.name, validate);
  }
  const ok = validate(params) === true;
  return {
    ok,
    code: ok ? null : "SFC2003",
    errors: ok
      ? []
      : (validate.errors ?? []).map((error) => ({
          keyword: error.keyword,
          instancePath: error.instancePath,
          message: error.message,
          params: error.params,
        })),
  };
}
