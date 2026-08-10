import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { errorCodeRegistry } from "./errors.mjs";
import { loadRegistry } from "./registry.mjs";
import { loadKernelProtocol } from "./kernel.mjs";
import { CHECK_TYPES, MANDATORY_RULES, RULE_BUDGET } from "./checker.mjs";
import { SUPPORTED_DIALECTS, VALIDATION_POLICIES } from "./validator.mjs";

/**
 * Versioned audit consumption surface (audit 消费接口).
 *
 * This module is the minimal, read-only interface an independent audit
 * consumer uses to pin and verify the exact Contracts it consumes. It is a
 * pure projection of the frozen Contracts authority:
 *
 * - it exposes the frozen documents (registry, error codes, rules, kernel
 *   protocol, schema documents) together with canonical SHA-256 digests;
 * - it exposes the frozen engine parameters (check types, mandatory rules,
 *   rule budget, validation policies, supported dialects) an audit needs to
 *   detect a weakened check engine;
 * - it provides deterministic canonicalization and digest primitives.
 *
 * Boundary: this module only reads Contracts-owned artifacts and exports
 * frozen values. It accepts no callbacks, registers nothing, and never
 * imports audit-owned artifacts; the dependency direction stays
 * Audit -> Contracts and can never be reversed by this interface.
 */

/** Version of the audit consumption surface itself; independent of CONTRACTS_VERSION. */
export const AUDIT_SURFACE_VERSION = 1;

/** Frozen digest algorithm set; v1 freezes exactly one algorithm. */
export const AUDIT_DIGEST_ALGORITHMS = Object.freeze(["sha256"]);

const SURFACE_KIND = "skill-family.audit-surface";

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

function loadPackageJson(relativePath) {
  return JSON.parse(readFileSync(new URL(`../${relativePath}`, import.meta.url), "utf8"));
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

/**
 * Materializes the frozen audit consumption surface as a deeply frozen
 * document. Every field is derived from Contracts-owned artifacts at call
 * time; no audit-provided input is accepted.
 *
 * Shape (all fields mandatory):
 * - schemaVersion, kind, auditSurfaceVersion, contractsVersion;
 * - contractObjects: the registered top-level objects, registry order;
 * - registry / errorCodes / rules / kernelProtocol: full frozen documents;
 * - schemas: registry entries plus each schema document's digest;
 * - digests: canonical SHA-256 digests of the four frozen documents;
 * - checkTypes, mandatoryRuleIds, ruleBudget: frozen engine facts;
 * - validationPolicies, supportedDialects: frozen engine parameters.
 */
export function describeAuditSurface() {
  const registry = structuredClone(loadRegistry());
  const errorCodes = structuredClone(errorCodeRegistry());
  const rules = loadPackageJson("src/rules.json");
  const kernelProtocol = structuredClone(loadKernelProtocol());

  const schemas = registry.schemas.map((entry) => {
    const document = loadPackageJson(entry.file);
    return {
      ...entry,
      digest: {
        algorithm: "sha256",
        value: digestDocument(document),
      },
    };
  });

  const surface = {
    schemaVersion: 1,
    kind: SURFACE_KIND,
    auditSurfaceVersion: AUDIT_SURFACE_VERSION,
    contractsVersion: registry.contractsVersion,
    contractObjects: registry.schemas.map((entry) => entry.object),
    registry,
    errorCodes,
    rules,
    kernelProtocol,
    schemas,
    digests: {
      registry: { algorithm: "sha256", value: digestDocument(registry) },
      errorCodes: { algorithm: "sha256", value: digestDocument(errorCodes) },
      rules: { algorithm: "sha256", value: digestDocument(rules) },
      kernelProtocol: { algorithm: "sha256", value: digestDocument(kernelProtocol) },
    },
    checkTypes: [...CHECK_TYPES],
    mandatoryRuleIds: MANDATORY_RULES.map((rule) => rule.ruleId),
    ruleBudget: { ...RULE_BUDGET },
    validationPolicies: VALIDATION_POLICIES,
    supportedDialects: Object.keys(SUPPORTED_DIALECTS).sort(),
  };
  return deepFreeze(surface);
}

/**
 * Digests one materialized audit surface (default: the live surface).
 * An independent audit pins this value for a version-approved Contracts
 * release and treats any later mismatch as baseline drift.
 */
export function digestAuditSurface(surface = describeAuditSurface()) {
  return digestDocument(surface);
}
