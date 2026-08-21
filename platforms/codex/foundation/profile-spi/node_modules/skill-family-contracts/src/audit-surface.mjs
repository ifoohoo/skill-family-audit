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

/* -------------------------------------------------------------------------
 * Baseline pin contract mechanics (GAP-5 / SG-28, FVD-005 lineage).
 *
 * A baseline pin is the frozen document an independent audit uses to verify
 * the exact Contracts surface it consumes (see the audit-baseline-pin
 * contract). The pin carries three compatibility coordinates —
 * contractsVersion, auditSurfaceVersion and surfaceDigest — plus
 * per-document digests and the frozen engine facts. Two audit-namespace
 * finding codes classify any failure:
 *
 * - AUD-LOCK-001 (lock verification failed): the pin document itself is
 *   unusable — wrong envelope, missing sections, or an unsupported digest
 *   algorithm. The live surface is never compared against a malformed pin.
 * - AUD-BASE-001 (baseline drift): the pin is well-formed but the live
 *   surface no longer matches it — a coordinate, digest, or fact mismatch.
 *
 * Both functions below are pure projections of Contracts-owned artifacts;
 * they accept no callbacks and never import audit-owned artifacts.
 * ---------------------------------------------------------------------- */

/** The audit-baseline-pin contract kind and its pre-1.6.0 legacy spelling. */
export const BASELINE_PIN_KINDS = Object.freeze([
  "skill-family.audit-baseline-pin",
  "skill-family.audit.baseline-pin",
]);

/** Frozen $id namespace prefix of every registered schema. */
export const SCHEMA_ID_NAMESPACE = "https://contracts.skill-family.example/v1/";

const PIN_DATE_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/;
const PIN_HEX_64 = /^[0-9a-f]{64}$/;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Derives the frozen engine facts of one audit surface in the exact shape
 * the audit-baseline-pin contract freezes for the facts section.
 */
export function describeBaselinePinFacts(surface = describeAuditSurface()) {
  return deepFreeze({
    contractObjects: [...surface.contractObjects],
    checkTypes: [...surface.checkTypes],
    mandatoryRuleIds: [...surface.mandatoryRuleIds],
    ruleBudget: { ...surface.ruleBudget },
    errorCodes: surface.errorCodes.codes.map((entry) => entry.code),
    kernelOperations: surface.kernelProtocol.operations.map((operation) => operation.name),
    kernelTerminalStates: [...surface.kernelProtocol.terminalStates].sort(),
    validationPolicies: structuredClone(surface.validationPolicies),
    supportedDialects: [...surface.supportedDialects],
    errorCodeStabilityPolicy: surface.errorCodes.policy.stability,
    schemaIdNamespace: SCHEMA_ID_NAMESPACE,
  });
}

/**
 * Materializes a complete audit-baseline-pin document for one audit surface
 * (default: the live surface). Pure and deterministic given its inputs:
 *
 * - frozenAt (mandatory): the calendar date (YYYY-MM-DD) of the freeze;
 * - note (mandatory): the human provenance note;
 * - supersedes (optional): file name of the predecessor pin (FVD-005 lineage);
 * - provenance (default "product-compatibility-fixture"): authorship class;
 * - surface (default describeAuditSurface()): the surface being pinned.
 *
 * Every digest and fact is derived mechanically from the surface; the result
 * is deeply frozen and conforms to the registered audit-baseline-pin schema.
 */
export function describeBaselinePin({
  frozenAt,
  note,
  supersedes = null,
  provenance = "product-compatibility-fixture",
  surface = describeAuditSurface(),
} = {}) {
  if (typeof frozenAt !== "string" || !PIN_DATE_PATTERN.test(frozenAt)) {
    throw new TypeError("describeBaselinePin: frozenAt must be a YYYY-MM-DD date string");
  }
  if (typeof note !== "string" || note.length === 0) {
    throw new TypeError("describeBaselinePin: note must be a non-empty string");
  }
  if (supersedes !== null && typeof supersedes !== "string") {
    throw new TypeError("describeBaselinePin: supersedes must be null or a string");
  }
  const schemaDigests = {};
  for (const entry of surface.schemas) {
    schemaDigests[entry.$id] = entry.digest.value;
  }
  const pin = {
    schemaVersion: 1,
    kind: "skill-family.audit-baseline-pin",
    provenance,
    frozenAt,
    contractsVersion: surface.contractsVersion,
    auditSurfaceVersion: surface.auditSurfaceVersion,
    digestAlgorithm: "sha256",
    note,
    surfaceDigest: digestAuditSurface(surface),
    documentDigests: {
      registry: surface.digests.registry.value,
      errorCodes: surface.digests.errorCodes.value,
      rules: surface.digests.rules.value,
      kernelProtocol: surface.digests.kernelProtocol.value,
    },
    schemaDigests,
    facts: describeBaselinePinFacts(surface),
  };
  if (supersedes !== null) pin.supersedes = supersedes;
  return deepFreeze(pin);
}

/**
 * Verifies one baseline pin document against one audit surface (default:
 * the live surface). Pure function; returns a deeply frozen
 * { ok, findings } where every finding is { code, field, message } and
 * code is the audit-namespace AUD-LOCK-001 (pin unusable) or AUD-BASE-001
 * (baseline drift). Findings preserve the deterministic check order:
 * envelope, algorithm, sections, coordinates, digests, facts.
 */
export function verifyBaselinePin(pin, { surface = describeAuditSurface() } = {}) {
  const findings = [];
  const lock = (field, message) => findings.push({ code: "AUD-LOCK-001", field, message });
  const drift = (field, message) => findings.push({ code: "AUD-BASE-001", field, message });

  if (!isPlainObject(pin)) {
    lock("pin", "baseline pin must be a JSON object");
    return deepFreeze({ ok: false, findings });
  }
  if (!BASELINE_PIN_KINDS.includes(pin.kind)) {
    lock("kind", `unexpected baseline pin kind: ${JSON.stringify(pin.kind)}`);
  }
  if (!AUDIT_DIGEST_ALGORITHMS.includes(pin.digestAlgorithm)) {
    lock("digestAlgorithm", `unsupported digest algorithm: ${JSON.stringify(pin.digestAlgorithm)}`);
    return deepFreeze({ ok: false, findings });
  }
  for (const section of ["surfaceDigest", "documentDigests", "schemaDigests", "facts"]) {
    if (pin[section] === undefined) lock(section, `baseline pin is missing the ${section} section`);
  }
  if (findings.length > 0) return deepFreeze({ ok: false, findings });

  if (pin.contractsVersion !== surface.contractsVersion) {
    drift(
      "contractsVersion",
      `pin freezes contracts ${pin.contractsVersion} but the live surface is ${surface.contractsVersion}`,
    );
  }
  if (pin.auditSurfaceVersion !== surface.auditSurfaceVersion) {
    drift(
      "auditSurfaceVersion",
      `pin freezes audit surface v${pin.auditSurfaceVersion} but the live surface is v${surface.auditSurfaceVersion}`,
    );
  }
  if (!PIN_HEX_64.test(pin.surfaceDigest ?? "")) {
    lock("surfaceDigest", "surfaceDigest must be a 64-char lowercase sha256 hex string");
    return deepFreeze({ ok: false, findings });
  }
  if (pin.surfaceDigest !== digestAuditSurface(surface)) {
    drift("surfaceDigest", "audit surface digest does not match the pinned baseline");
  }

  for (const document of ["registry", "errorCodes", "rules", "kernelProtocol"]) {
    const pinned = pin.documentDigests?.[document];
    if (typeof pinned !== "string" || !PIN_HEX_64.test(pinned)) {
      lock(`documentDigests.${document}`, "document digest must be a 64-char lowercase sha256 hex string");
      continue;
    }
    if (pinned !== surface.digests[document].value) {
      drift(`documentDigests.${document}`, `${document} digest does not match the pinned baseline`);
    }
  }

  const liveSchemaDigests = Object.fromEntries(
    surface.schemas.map((entry) => [entry.$id, entry.digest.value]),
  );
  const pinnedSchemaDigests = isPlainObject(pin.schemaDigests) ? pin.schemaDigests : {};
  for (const [$id, value] of Object.entries(liveSchemaDigests)) {
    if (pinnedSchemaDigests[$id] !== value) {
      drift(`schemaDigests.${$id}`, "schema digest missing or drifted");
    }
  }
  for (const $id of Object.keys(pinnedSchemaDigests)) {
    if (!Object.hasOwn(liveSchemaDigests, $id)) {
      drift(`schemaDigests.${$id}`, "pin carries a schema digest absent from the live registry");
    }
  }

  const liveFacts = describeBaselinePinFacts(surface);
  const pinnedFacts = isPlainObject(pin.facts) ? pin.facts : {};
  for (const key of Object.keys(liveFacts)) {
    if (canonicalJson(pinnedFacts[key] ?? null) !== canonicalJson(liveFacts[key])) {
      drift(`facts.${key}`, "pinned engine fact does not match the live audit surface");
    }
  }
  for (const key of Object.keys(pinnedFacts)) {
    if (!Object.hasOwn(liveFacts, key)) {
      drift(`facts.${key}`, "pin carries an engine fact unknown to the live audit surface");
    }
  }

  return deepFreeze({ ok: findings.length === 0, findings });
}
