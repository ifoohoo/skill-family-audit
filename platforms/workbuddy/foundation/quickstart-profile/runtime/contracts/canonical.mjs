import { createHash } from "node:crypto";

/** Frozen digest algorithm set; v1 freezes exactly one algorithm. */
export const AUDIT_DIGEST_ALGORITHMS = Object.freeze(["sha256"]);

/**
 * Canonical JSON serialization: the deterministic byte form used for all
 * audit digests. Object keys are sorted lexicographically at every level,
 * arrays keep their order, and only JSON data types are accepted. Any
 * non-JSON value (undefined, function, symbol, bigint, non-finite number)
 * raises a TypeError instead of silently serializing.
 */
export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value) {
  if (value === null) return null;
  const type = typeof value;
  if (type === "string" || type === "boolean") return value;
  if (type === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("canonicalJson: non-finite numbers are not JSON data");
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (type === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) {
      const child = value[key];
      const childType = typeof child;
      if (child === undefined || childType === "function" || childType === "symbol") {
        throw new TypeError(`canonicalJson: non-JSON value at key "${key}"`);
      }
      sorted[key] = canonicalize(child);
    }
    return sorted;
  }
  throw new TypeError(`canonicalJson: unsupported value type "${type}"`);
}

/**
 * Digests one JSON value: SHA-256 hex over its canonical serialization.
 * The algorithm set is frozen (v1: sha256 only); an unknown algorithm is a
 * caller error (TypeError), never a silent fallback.
 */
export function digestDocument(value, { algorithm = "sha256" } = {}) {
  if (!AUDIT_DIGEST_ALGORITHMS.includes(algorithm)) {
    throw new TypeError(`digestDocument: unsupported algorithm: ${algorithm}`);
  }
  return createHash(algorithm).update(canonicalJson(value), "utf8").digest("hex");
}
