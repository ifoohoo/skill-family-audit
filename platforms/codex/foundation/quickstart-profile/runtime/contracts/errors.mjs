import { readFileSync } from "node:fs";

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
 * Frozen stable error codes for Contracts v1.
 *
 * The registry file (error-codes.json) is the single source of truth; codes are
 * append-only and never reused. SFC1xxx covers contracts-authority failures,
 * SFC2xxx covers kernel-operation failures, SFC3xxx covers report-contract
 * failures (digest binding, mandatory elements, fact drift).
 */

const ERROR_REGISTRY = deepFreeze(JSON.parse(
  readFileSync(new URL("./error-codes.json", import.meta.url), "utf8"),
));

const CODE_INDEX = new Map(ERROR_REGISTRY.codes.map((entry) => [entry.code, entry]));

/** Error carrying one frozen stable code plus structured details. */
export class ContractsError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = "ContractsError";
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

/** All frozen error codes, in registry order. */
export const ERROR_CODES = Object.freeze(ERROR_REGISTRY.codes.map((entry) => entry.code));

/** Full registry document (policy + codes). */
export function errorCodeRegistry() {
  return ERROR_REGISTRY;
}

/** Info entry ({code, name, category, stableSince, meaning}) or null. */
export function errorCodeInfo(code) {
  return CODE_INDEX.get(code) ?? null;
}

/** Whether a code exists in the frozen registry. */
export function isRegisteredErrorCode(code) {
  return CODE_INDEX.has(code);
}

/** Throws SFC1009 when a code is not registered. */
export function assertRegisteredErrorCode(code) {
  if (!CODE_INDEX.has(code)) {
    throw new ContractsError("SFC1009", `unregistered error code: ${code}`, { code });
  }
}

/** Builds a plain stable-coded error entry suitable for operation-result.errors. */
export function stableError(code, message, details) {
  assertRegisteredErrorCode(code);
  if (typeof message !== "string" || message.length === 0) {
    throw new TypeError("stableError: message must be a non-empty string");
  }
  return details === undefined
    ? { code, message }
    : { code, message, details };
}
