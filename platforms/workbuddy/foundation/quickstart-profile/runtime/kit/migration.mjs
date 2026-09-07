import { lstat, readFile } from "node:fs/promises";
import { TextDecoder } from "node:util";
import { HarnessError } from "../harness/errors.mjs";
import { readFileContained, resolveContained } from "../harness/paths.mjs";
import { validateBySchemaId } from "../../validators.mjs";
import { normalizeRelPath, readOptionalJson } from "./workspace.mjs";

function validateContractDocument(document, { schemaId } = {}) {
  const outcome = validateBySchemaId(schemaId, document);
  return {
    valid: outcome.valid,
    errorCode: outcome.valid ? null : "SFC1001",
    errors: outcome.errors,
    data: outcome.valid ? structuredClone(document) : undefined,
  };
}

const UTF8_STRICT_DECODER = new TextDecoder("utf-8", { fatal: true });
const USE_ID_RE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;

function isString(value) {
  return typeof value === "string";
}

function codePointLength(value) {
  return Array.from(value).length;
}

function textError(value, label, maxLength, required = true) {
  if (!isString(value)) return `${label} must be a string`;
  if (required && value.length === 0) return `${label} must not be empty`;
  if (codePointLength(value) > maxLength) return `${label} exceeds ${maxLength} characters`;
  if (value !== value.trim()) return `${label} must equal trim()`;
  if (value.includes("\0")) return `${label} must not contain NUL`;
  return null;
}

function stringArrayErrors(value, label, { min, max, itemMax, required = true } = {}) {
  if (!Array.isArray(value)) return [`${label} must be an array`];
  const errors = [];
  if (required && value.length < min) errors.push(`${label} must contain at least ${min} item(s)`);
  if (value.length > max) errors.push(`${label} must contain at most ${max} item(s)`);
  const seen = new Set();
  for (const [index, item] of value.entries()) {
    const error = textError(item, `${label}[${index}]`, itemMax);
    if (error) errors.push(error);
    if (isString(item) && seen.has(item)) errors.push(`${label} must not contain duplicate items`);
    if (isString(item)) seen.add(item);
  }
  return errors;
}

/** Shared item-level capabilityUse validator for temporary and migration uses. */
export function validateCapabilityUse(value) {
  const errors = [];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { valid: false, errors: ["capabilityUse must be an object"] };
  }
  const allowed = new Set(["useId", "problemStatement", "constraints", "retainedGuarantees", "catalogFilters"]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`unknown field ${key}`);
  if (!isString(value.useId) || !USE_ID_RE.test(value.useId) || value.useId.length > 80) {
    errors.push("useId must match the capability use id pattern and be at most 80 characters");
  }
  const problemError = textError(value.problemStatement, "problemStatement", 1000);
  if (problemError) errors.push(problemError);
  errors.push(...stringArrayErrors(value.constraints, "constraints", { min: 0, max: 20, itemMax: 500, required: false }));
  errors.push(...stringArrayErrors(value.retainedGuarantees, "retainedGuarantees", { min: 1, max: 20, itemMax: 500 }));
  if (value.catalogFilters !== undefined) {
    errors.push(...stringArrayErrors(value.catalogFilters, "catalogFilters", { min: 0, max: 20, itemMax: 200, required: false }));
    if (Array.isArray(value.catalogFilters)) {
      const normalized = new Set();
      for (const filter of value.catalogFilters) {
        if (!isString(filter)) continue;
        const folded = filter.normalize("NFC").replace(/[A-Z]/gu, (character) => character.toLowerCase());
        if (normalized.has(folded)) errors.push("catalogFilters must be unique after NFC and ASCII case folding");
        normalized.add(folded);
      }
    }
  }
  return { valid: errors.length === 0, errors };
}

/** Shared uses-array validator, including stable useId uniqueness. */
export function validateCapabilityUses(value) {
  if (!Array.isArray(value)) return { valid: false, errors: ["capabilityUses must be an array"] };
  const errors = [];
  if (value.length < 1 || value.length > 200) errors.push("capabilityUses must contain 1..200 items");
  const useIds = new Set();
  for (const [index, use] of value.entries()) {
    const outcome = validateCapabilityUse(use);
    for (const error of outcome.errors) errors.push(`capabilityUses[${index}]: ${error}`);
    if (isString(use?.useId)) {
      if (useIds.has(use.useId)) errors.push(`capabilityUses[${index}]: duplicate useId ${use.useId}`);
      useIds.add(use.useId);
    }
  }
  return { valid: errors.length === 0, errors };
}

// Contracts/Ajv counts JSON Schema maxLength in UTF-16 code units. Capability
// use text is a Kit-owned boundary and counts Unicode code points instead, so
// validate the real values above and give Contracts an equivalent structural
// document with short ASCII text for its remaining manifest checks.
function capabilityManifestForContractValidation(manifest) {
  if (!manifest || !Array.isArray(manifest.capabilityUses)) return manifest;
  const capabilityUses = manifest.capabilityUses.map((use, useIndex) => ({
    ...use,
    problemStatement: `problem-${useIndex}`,
    constraints: use.constraints.map((_, index) => `constraint-${useIndex}-${index}`),
    retainedGuarantees: use.retainedGuarantees.map((_, index) => `guarantee-${useIndex}-${index}`),
    ...(use.catalogFilters === undefined
      ? {}
      : { catalogFilters: use.catalogFilters.map((_, index) => `filter-${useIndex}-${index}`) }),
  }));
  return { ...manifest, capabilityUses };
}

/**
 * Migration closure facts for adopt-plan (FND-070, formalized by the
 * migration manifest contract).
 *
 * Everything here is strictly read-only and pure: adoption never mutates
 * the target, and completion is a judgement computed from filesystem facts
 * plus the target's own migration manifest. The kit never deletes legacy
 * implementations itself — it only reports whether they have exited.
 *
 * The target declares its migration state in `skill-family.migration.json`,
 * which is a formal Contract (migration-manifest, Contracts 1.1.1):
 *
 *   {
 *     "schemaVersion": 1,
 *     "kind": "skill-family.migration-manifest",
 *     "legacyInfra": [ { "path": "scripts/old-validator.mjs", "replacedBy": "sf-kit check" } ],
 *     "exceptions": [ { "owner": "...", "reason": "...", "deadline": "2026-12-31", "migrationTarget": "..." } ]
 *   }
 *
 * The manifest loader distinguishes missing / parse-failed / schema-invalid /
 * valid; only a valid manifest counts as declared. Temporary exceptions are
 * only accepted when all four fields are present and non-blank; a missing
 * field fails the plan (conflict), an expired deadline is never auto-renewed
 * (risk + completion blocker). Every user-provided legacy path is assessed
 * through harness containment: escapes fail closed and never reveal whether
 * an outside path exists.
 */

/** Where a target declares its legacy exit list and temporary exceptions. */
export const MIGRATION_MANIFEST_PATH = "skill-family.migration.json";

export const MIGRATION_MANIFEST_KIND = "skill-family.migration-manifest";

/** Registered schema $id of the migration-manifest contract. */
export const MIGRATION_MANIFEST_SCHEMA_ID = "https://contracts.skill-family.example/v1/migration-manifest.json";

/** Loader outcome vocabulary: exactly one state per manifest file. */
export const MIGRATION_MANIFEST_STATES = Object.freeze([
  "missing",
  "parse-failed",
  "schema-invalid",
  "valid",
]);

/** Every temporary exception must carry all four fields; one missing fails. */
export const EXCEPTION_REQUIRED_FIELDS = Object.freeze([
  "owner",
  "reason",
  "deadline",
  "migrationTarget",
]);

/**
 * Loads and validates the target's migration manifest against the formal
 * migration-manifest contract (read-only). Returns:
 *   { status: "missing" }                              — no manifest file;
 *   { status: "parse-failed" }                         — not parseable JSON;
 *   { status: "schema-invalid", problems }             — contract violation;
 *   { status: "valid", manifest }                      — contract-conforming.
 * Only "valid" counts as a declared manifest for planning and completion.
 */
export async function loadMigrationManifestState(root) {
  const result = await readOptionalJson(root, MIGRATION_MANIFEST_PATH);
  if (!result.ok) {
    return { status: result.reason === "missing" ? "missing" : "parse-failed" };
  }
  const uses = Array.isArray(result.value?.capabilityUses) ? validateCapabilityUses(result.value.capabilityUses) : null;
  if (uses && !uses.valid) {
    return {
      status: "schema-invalid",
      problems: uses.errors,
      errorCode: "SFC1001",
    };
  }
  const outcome = validateContractDocument(capabilityManifestForContractValidation(result.value), { schemaId: MIGRATION_MANIFEST_SCHEMA_ID });
  if (!outcome.valid) {
    return {
      status: "schema-invalid",
      problems: outcome.errors.map((error) => error.message ?? "schema violation"),
      errorCode: outcome.errorCode,
    };
  }
  return { status: "valid", manifest: result.value };
}

/**
 * Loads the target's migration manifest (read-only, tolerant). Kept for
 * callers that only need the parsed object: returns it when the manifest is
 * contract-valid, otherwise null. Prefer loadMigrationManifestState, which
 * distinguishes every failure state.
 */
export async function loadMigrationManifest(root) {
  const state = await loadMigrationManifestState(root);
  return state.status === "valid" ? state.manifest : null;
}

/**
 * Validates one temporary exception. Returns finding descriptors:
 * - { kind: "exception-incomplete", missing } when any required field is absent/blank;
 * - { kind: "exception-invalid-deadline" } when deadline is not parseable;
 * - { kind: "exception-expired" } when the deadline lies before `nowMs`.
 * Expired exceptions are never renewed by tooling; they simply keep blocking.
 */
export function validateException(exception, index, nowMs) {
  const missing = EXCEPTION_REQUIRED_FIELDS.filter(
    (field) => typeof exception?.[field] !== "string" || exception[field].trim() === "",
  );
  if (missing.length > 0) {
    return [{ index, kind: "exception-incomplete", missing }];
  }
  const deadlineMs = Date.parse(exception.deadline);
  if (Number.isNaN(deadlineMs)) {
    return [{ index, kind: "exception-invalid-deadline", deadline: exception.deadline }];
  }
  if (deadlineMs < nowMs) {
    return [{ index, kind: "exception-expired", deadline: exception.deadline }];
  }
  return [];
}

/**
 * Embedded repositories: only a nested `.git` entry is repository evidence
 * (read-only Git evidence probe). A `.git` directory below the target root, or a `.git` *file*
 * (the gitfile form used by submodules and linked worktrees), both count;
 * `node_modules` and any other opaque directory is never repository
 * evidence. The target's own root `.git` is not a nested repository. The
 * plan reports the containing paths as risks; adoption never operates
 * inside a nested repository.
 */
export function findNestedRepositories(entries) {
  const repositories = [];
  for (const entry of entries) {
    const segments = entry.path.split("/");
    if (segments[segments.length - 1] !== ".git") continue;
    if (entry.path === ".git") continue;
    const isGitDirectory = entry.kind === "directory-opaque";
    const isGitFile = entry.kind === "file"; // gitfile: submodule/worktree link
    if (isGitDirectory || isGitFile) repositories.push(segments.slice(0, -1).join("/"));
  }
  return repositories.sort();
}

/**
 * Assesses the legacy exit list: one entry per declared legacy path with
 * status "present" (still on disk), "absent" (already removed) or "invalid"
 * (path rejected by harness containment or unreadable — fail-closed).
 *
 * Path containment: every user-provided path is resolved through
 * the harness containment layer, which rejects absolute paths, `..`
 * traversal, Windows drive/UNC/backslash forms and symlink escapes BEFORE
 * any outside access; an invalid entry therefore never reveals whether a
 * path outside the target root exists. Nothing is deleted by this function.
 */
export async function assessLegacyExitList(root, legacyItems) {
  const list = [];
  if (!Array.isArray(legacyItems)) return list;
  for (const item of legacyItems) {
    if (!item || typeof item.path !== "string" || item.path.trim() === "") {
      list.push({ path: null, replacedBy: null, status: "invalid", invalidKind: "malformed-entry" });
      continue;
    }
    const rel = normalizeRelPath(item.path);
    const replacedBy = typeof item.replacedBy === "string" && item.replacedBy.trim() !== "" ? item.replacedBy : null;
    if (replacedBy === null) {
      list.push({ path: rel, replacedBy: null, status: "invalid", invalidKind: "empty-replaced-by" });
      continue;
    }
    let resolved;
    try {
      resolved = await resolveContained(root, rel);
    } catch (cause) {
      // Containment rejection (traversal, absolute/UNC/drive forms, symlink
      // escape) is decided without probing outside the root: fail closed and
      // report the stable harness kind, never an existence oracle.
      list.push({
        path: rel,
        replacedBy,
        status: "invalid",
        invalidKind: cause instanceof HarnessError && cause.details?.kind ? cause.details.kind : "containment-rejected",
      });
      continue;
    }
    let status = "absent";
    try {
      await lstat(resolved);
      status = "present";
    } catch {
      status = "absent";
    }
    list.push({ path: rel, replacedBy, status });
  }
  return list;
}

/**
 * Assesses the legacy reference exit list: for each declared reference,
 * checks whether the exact literal `text` still appears in the retained file.
 *
 * Returns one entry per declared reference with:
 *   status: "absent"   — the literal text is not found (0 occurrences); file
 *                        missing also counts as absent (the text is gone);
 *   status: "present"  — the literal text appears one or more times;
 *   status: "invalid"  — path rejected by containment, file contains
 *                        invalid UTF-8 bytes, unreadable, or is a directory.
 *
 * UTF-8 decoding is strict: any invalid byte sequence fails closed with
 * `invalidKind: "invalid-utf8"` instead of silently replacing bad bytes
 * with U+FFFD. This prevents false "absent" verdicts when the file
 * contains corrupted text that would otherwise mask the literal search.
 *
 * The `occurrenceCount` field is reported for "present" and "absent" entries
 * without leaking file contents. Paths are resolved through harness
 * containment (fail-closed on escape).
 */
export async function assessLegacyReferences(root, legacyRefs) {
  const list = [];
  if (!Array.isArray(legacyRefs)) return list;
  for (const ref of legacyRefs) {
    if (!ref || typeof ref.path !== "string" || ref.path.trim() === "") {
      list.push({ path: null, text: null, replacedBy: null, status: "invalid", invalidKind: "malformed-entry", occurrenceCount: 0 });
      continue;
    }
    const rel = normalizeRelPath(ref.path);
    const text = typeof ref.text === "string" ? ref.text : null;
    if (text === null || text === "") {
      list.push({ path: rel, text: null, replacedBy: null, status: "invalid", invalidKind: "empty-text", occurrenceCount: 0 });
      continue;
    }
    const replacedBy = typeof ref.replacedBy === "string" && ref.replacedBy.trim() !== "" ? ref.replacedBy : null;
    if (replacedBy === null) {
      list.push({ path: rel, text, replacedBy: null, status: "invalid", invalidKind: "empty-replaced-by", occurrenceCount: 0 });
      continue;
    }
    let resolved;
    try {
      resolved = await resolveContained(root, rel);
    } catch (cause) {
      list.push({
        path: rel,
        text,
        replacedBy,
        status: "invalid",
        invalidKind: cause instanceof HarnessError && cause.details?.kind ? cause.details.kind : "containment-rejected",
        occurrenceCount: 0,
      });
      continue;
    }
    let bytes;
    try {
      bytes = await readFile(resolved);
    } catch (cause) {
      if (cause && cause.code === "ENOENT") {
        // File missing: the old text is absent by definition.
        list.push({ path: rel, text, replacedBy, status: "absent", occurrenceCount: 0 });
        continue;
      }
      // Directory, unreadable, or other failure: fail-closed as invalid.
      list.push({
        path: rel,
        text,
        replacedBy,
        status: "invalid",
        invalidKind: cause && cause.code === "EISDIR" ? "is-directory" : "unreadable",
        occurrenceCount: 0,
      });
      continue;
    }
    // Strict UTF-8 decode: reject any invalid byte sequences instead of
    // replacing them with U+FFFD. This prevents silent data corruption
    // when assessing whether legacy text has truly exited a file.
    let content;
    try {
      content = UTF8_STRICT_DECODER.decode(bytes);
    } catch {
      list.push({
        path: rel,
        text,
        replacedBy,
        status: "invalid",
        invalidKind: "invalid-utf8",
        occurrenceCount: 0,
      });
      continue;
    }
    // Strict UTF-8 decode succeeded. Exact literal match: count
    // non-overlapping occurrences.
    let count = 0;
    let fromIndex = 0;
    while (true) {
      const idx = content.indexOf(text, fromIndex);
      if (idx === -1) break;
      count++;
      fromIndex = idx + text.length;
    }
    const status = count === 0 ? "absent" : "present";
    list.push({ path: rel, text, replacedBy, status, occurrenceCount: count });
  }
  return list;
}

/**
 * Migration state machine. States advance monotonically as facts
 * are proven; completion is the final state only. No tool ever advances a
 * state by writing — states are judgements over read-only evidence.
 *
 *   not-declared  no contract-valid migration manifest exists;
 *   declared      a contract-valid manifest exists, adoption unproven;
 *   adopted       Foundation bytes proven on disk (digests match), no
 *                 pending write actions, every legacy entry exited, no
 *                 invalid/expired exceptions, no unresolved conflicts;
 *   verified      adopted, and the Foundation check gate is green;
 *   complete      verified, and all four verification evidence documents
 *                 (unit, integration, consumer, independent audit) exist
 *                 with matching project identity.
 */
export const MIGRATION_STATES = Object.freeze([
  "not-declared",
  "declared",
  "adopted",
  "verified",
  "complete",
]);

/** Every Foundation package a complete migration must bind exactly. */
export const REQUIRED_FOUNDATION_PACKAGES = Object.freeze([
  "skill-family-contracts",
  "skill-family-harness-node",
  "skill-family-engineering-kit",
]);

/** The only dispositions a migration use may record. */
export const CAPABILITY_DISPOSITIONS = Object.freeze([
  "direct-adoption",
  "compatibility-layer",
  "keep-business",
  "foundation-gap",
]);

/** The fixed, Foundation-owned consumer verification statement. */
export const CONSUMER_VERIFICATION_NOT_EVALUATED = Object.freeze({
  claim: null,
  evaluatedByFoundation: false,
  reason: "consumer-owned-test-result-not-evaluated",
});

/**
 * Checks the cross-document facts owned by Kit for capability adoption.
 * Contracts validates shapes; this function validates relationships and
 * deliberately returns findings instead of throwing.  The input is the
 * already validated manifest plus the assessment generated from that same
 * manifest, so it never needs (or accepts) an Audit finding or schema.
 */
export function assessCapabilityMigration({ manifest, assessment, profileCapabilities = [] } = {}) {
  const uses = Array.isArray(manifest?.capabilityUses) ? manifest.capabilityUses : [];
  if (uses.length === 0) {
    return { blockers: [], decisionsByUse: new Map(), byUse: new Map(), legacyByUse: new Map() };
  }
  const decisions = Array.isArray(manifest?.capabilityDecisions) ? manifest.capabilityDecisions : [];
  const usesById = new Map(uses.map((use) => [use.useId, use]));
  const decisionsByUse = new Map();
  const records = [];
  const useOrder = new Map(uses.map((use, index) => [use.useId, index]));

  // T60 has one narrow finding projection. Keep its ordering local to this
  // function: known uses follow manifest order, then the eight SPEC classes,
  // then a stable relationship key. Unknown-use records come last.
  const add = (category, useId, relationKey, message) => {
    records.push({
      category,
      useId: useId ?? "<unknown>",
      relationKey: String(relationKey),
      message: `capability ${useId ?? "<unknown>"}: ${message}`,
    });
  };

  for (const decision of decisions) {
    if (!usesById.has(decision?.useId)) {
      add(2, decision?.useId, `decision:${decision?.disposition ?? "missing"}:${decision?.targetCapability ?? ""}`, `decision references unknown use ${decision?.useId ?? "<missing>"}`);
      continue;
    }
    const existing = decisionsByUse.get(decision.useId) ?? [];
    existing.push(decision);
    decisionsByUse.set(decision.useId, existing);
  }
  for (const use of uses) {
    const entries = decisionsByUse.get(use.useId) ?? [];
    if (entries.length === 0) {
      add(1, use.useId, "decision:none", "no unique decision");
      continue;
    }
    if (entries.length > 1) {
      for (const decision of entries) {
        add(2, use.useId, `decision:${decision?.disposition ?? "missing"}:${decision?.targetCapability ?? ""}`, "multiple decisions are declared");
      }
      continue;
    }
    const [decision] = entries;
    if (!CAPABILITY_DISPOSITIONS.includes(decision?.disposition)) {
      add(2, use.useId, `decision:${decision?.disposition ?? "missing"}:${decision?.targetCapability ?? ""}`, "decision has an invalid disposition");
      continue;
    }
    if (decision.disposition === "keep-business" || decision.disposition === "foundation-gap") continue;

    const target = decision.targetCapability;
    const views = [
      ...(assessment?.scopeCapabilities ?? []),
      ...(assessment?.scopeBoundaries ?? []),
    ];
    const inScope = (candidate) => assessment?.scope === "all"
      || !Array.isArray(candidate?.adoptionScopes)
      || candidate.adoptionScopes.includes(assessment?.scope);
    const capability = views.find((candidate) => candidate.id === target && inScope(candidate));
    if (!capability) {
      // A capability may exist in the bundled catalog but be outside this
      // manifest's declared scope.  Keep that distinction observable.
      const anywhere = (assessment?.allCapabilities ?? []).find((candidate) => candidate.id === target);
      add(3, use.useId, `target:${target ?? ""}`, anywhere ? `target ${target} is outside the evaluation scope` : `target ${target} is unknown`);
    } else if (capability.stability === "unsupported") {
      add(3, use.useId, `target:${target}`, `target ${target} is unsupported`);
    } else if (capability.available !== true || capability.stability !== "stable") {
      add(3, use.useId, `target:${target}`, `target ${target} is not stable and available`);
    }
    if (!profileCapabilities.includes(target)) add(4, use.useId, `target:${target ?? ""}`, `target ${target} is not declared by the project Profile`);
  }

  const legacyByUse = new Map(uses.map((use) => [use.useId, { infra: [], references: [] }]));
  const checkLegacy = (items, kind) => {
    for (const item of items ?? []) {
      const useId = item?.useId;
      if (!useId || !usesById.has(useId)) {
        const relationKey = kind === "legacyInfra"
          ? `legacyInfra:${item?.path ?? ""}`
          : `legacyReferences:${item?.path ?? ""}:${item?.text ?? ""}`;
        add(5, useId, relationKey, `${kind} entry references an unknown use`);
        if (kind === "legacyInfra" && (!isString(item?.recoveryRef) || item.recoveryRef.trim() === "")) {
          add(8, useId, relationKey, "legacyInfra entry is missing recoveryRef");
        }
        continue;
      }
      const destination = legacyByUse.get(useId)[kind === "legacyInfra" ? "infra" : "references"];
      const relationKey = kind === "legacyInfra"
        ? `legacyInfra:${item?.path ?? ""}`
        : `legacyReferences:${item?.path ?? ""}:${item?.text ?? ""}`;
      if (!destination.some((candidate) => (
        kind === "legacyInfra"
          ? candidate?.path === item?.path
          : candidate?.path === item?.path && candidate?.text === item?.text
      ))) destination.push(item);
      const entryDecisions = decisionsByUse.get(useId) ?? [];
      const decision = entryDecisions.length === 1 ? entryDecisions[0] : null;
      if (item.replacedBy === null || item.replacedBy === undefined) {
        add(5, useId, relationKey, `${kind} entry has nullable replacement`);
      }
      if (decision?.disposition === "keep-business" || decision?.disposition === "foundation-gap") {
        add(7, useId, `${relationKey}:${decision.disposition}`, `${kind} entry is incorrectly linked to ${decision.disposition}`);
      } else if (
        decision &&
        (decision.disposition === "direct-adoption" || decision.disposition === "compatibility-layer") &&
        typeof item.replacedBy === "string" &&
        item.replacedBy !== decision.targetCapability
      ) {
        add(6, useId, `${relationKey}:${decision.targetCapability}`, `${kind} replacement does not match target ${decision.targetCapability}`);
      }
      if (kind === "legacyInfra" && (!isString(item.recoveryRef) || item.recoveryRef.trim() === "")) {
        add(8, useId, relationKey, "legacyInfra entry is missing recoveryRef");
      }
    }
  };
  checkLegacy(manifest?.legacyInfra, "legacyInfra");
  checkLegacy(manifest?.legacyReferences, "legacyReferences");
  const unique = new Map();
  for (const record of records) {
    const key = `${record.category}|${record.useId}|${record.relationKey}`;
    if (!unique.has(key)) unique.set(key, record);
  }
  const sorted = [...unique.values()].sort((left, right) => {
    const leftKnown = useOrder.has(left.useId);
    const rightKnown = useOrder.has(right.useId);
    if (leftKnown !== rightKnown) return leftKnown ? -1 : 1;
    if (leftKnown && useOrder.get(left.useId) !== useOrder.get(right.useId)) {
      return useOrder.get(left.useId) - useOrder.get(right.useId);
    }
    if (!leftKnown && !rightKnown) {
      const byUse = left.useId < right.useId ? -1 : left.useId > right.useId ? 1 : 0;
      const byRelation = left.relationKey < right.relationKey ? -1 : left.relationKey > right.relationKey ? 1 : 0;
      return byUse || byRelation || left.category - right.category;
    }
    if (left.category !== right.category) return left.category - right.category;
    const byUse = left.useId < right.useId ? -1 : left.useId > right.useId ? 1 : 0;
    return byUse || (left.relationKey < right.relationKey ? -1 : left.relationKey > right.relationKey ? 1 : 0);
  });
  const byUse = new Map(uses.map((use) => [use.useId, []]));
  for (const record of sorted) if (byUse.has(record.useId)) byUse.get(record.useId).push(record.message);
  return { blockers: sorted.map((record) => record.message), decisionsByUse, byUse, legacyByUse };
}

/** The four evidence kinds a complete migration must prove. */
export const VERIFICATION_EVIDENCE_KINDS = Object.freeze([
  "unit",
  "integration",
  "consumer",
  "independentAudit",
]);

/**
 * Assesses the adoption binding declared by a contract-valid manifest
 * (pure): the adopted profile id must equal the planned profile id, and
 * every required Foundation package must be pinned to an exact version and
 * sha256 digest. Returns { profileDeclared, profileMatches, covered,
 * missingPackages }.
 */
export function assessAdoptionBinding(manifest, plannedProfileId) {
  const declared = typeof manifest?.targetProfile === "string" && manifest.targetProfile.trim() !== "";
  const profileMatches = declared && manifest.targetProfile === plannedProfileId;
  const packages = Array.isArray(manifest?.foundationPackages) ? manifest.foundationPackages : [];
  const boundNames = new Set(
    packages
      .filter(
        (pkg) =>
          pkg &&
          typeof pkg.name === "string" &&
          typeof pkg.version === "string" &&
          /^[0-9]+\.[0-9]+\.[0-9]+$/.test(pkg.version) &&
          typeof pkg.digest === "string" &&
          /^sha256:[a-f0-9]{64}$/.test(pkg.digest),
      )
      .map((pkg) => pkg.name),
  );
  const missingPackages = REQUIRED_FOUNDATION_PACKAGES.filter((name) => !boundNames.has(name));
  return { profileDeclared: declared, profileMatches, covered: [...boundNames].sort(), missingPackages };
}

/**
 * Assesses the four verification evidence documents declared by the manifest
 * (read-only, fail-closed). For each kind the outcome is one of:
 *   undeclared       the manifest declares no path for this kind;
 *   invalid-path     the path escapes containment (never an existence oracle);
 *   missing          the declared file does not exist;
 *   unreadable       not parseable JSON — evidence must be machine-checkable;
 *   identity-mismatch  parses, but its projectId does not match the plan;
 *   proven           exists and its projectId matches the plan's project id.
 */
export async function assessVerificationEvidence(rootAbs, verification, plannedProjectId) {
  const declared = verification && typeof verification === "object" ? verification : {};
  const facts = [];
  for (const kind of VERIFICATION_EVIDENCE_KINDS) {
    const rel = declared[kind];
    if (typeof rel !== "string" || rel.trim() === "") {
      facts.push({ kind, path: null, status: "undeclared" });
      continue;
    }
    const pathValue = normalizeRelPath(rel);
    let bytes;
    try {
      // Contained read: rejection or absence both fail closed without
      // revealing anything about paths outside the target root.
      bytes = await readFileContained(rootAbs, pathValue);
    } catch {
      facts.push({ kind, path: pathValue, status: "invalid-path" });
      continue;
    }
    if (bytes === null) {
      facts.push({ kind, path: pathValue, status: "missing" });
      continue;
    }
    let document;
    try {
      document = JSON.parse(bytes.toString("utf8"));
    } catch {
      facts.push({ kind, path: pathValue, status: "unreadable" });
      continue;
    }
    if (!document || document.projectId !== plannedProjectId) {
      facts.push({ kind, path: pathValue, status: "identity-mismatch" });
      continue;
    }
    facts.push({ kind, path: pathValue, status: "proven" });
  }
  return facts;
}

/**
 * Migration completion gate (pure). Completion requires ALL of:
 * - a contract-valid declared migration manifest;
 * - the adoption binding proven: the declared targetProfile equals the
 *   planned profile id and every required Foundation package is pinned to
 *   an exact version plus sha256 digest;
 * - the Project Manifest, managed lock, identity record and every managed
 *   skeleton file present on disk with matching digests (adoptionProof);
 * - no pending create/replace/project action left in the writeSet;
 * - the Foundation check gate green;
 * - every legacy implementation removed or provably absent — an invalid
 *   (containment-rejected or malformed) entry fails closed like a present
 *   one; dual-track wiring alone is not completion;
 * - every declared legacy reference absent from its retained file — an
 *   invalid (containment-rejected, unreadable, malformed) entry fails
 *   closed like a present one;
 * - no incomplete/invalid/expired temporary exceptions;
 * - no unresolved adoption conflicts;
 * - all four verification evidence documents proven with matching identity.
 *
 * Returns { complete, state, blockers } where state is one of
 * MIGRATION_STATES and blockers are stable, human-readable strings.
 * Inputs that are absent are judged exactly like failed proofs: this gate
 * only ever advances on presented evidence.
 */
export function evaluateMigrationCompletion({
  manifestDeclared,
  legacyExitList,
  legacyReferenceExitList,
  exceptionFindings,
  conflicts,
  binding,
  adoptionProof,
  pendingWrites = 0,
  checkGreen,
  verificationFacts,
  capabilityBlockers = [],
}) {
  const adoptionBlockers = [];
  const verificationBlockers = [];
  const evidenceBlockers = [];

  if (binding) {
    if (!binding.profileMatches) {
      adoptionBlockers.push(
        binding.profileDeclared
          ? "declared targetProfile does not match the planned profile id"
          : "no targetProfile binding declared in the migration manifest",
      );
    }
    if (binding.missingPackages?.length > 0) {
      adoptionBlockers.push(
        `Foundation packages not bound to exact version+digest: ${binding.missingPackages.join(", ")}`,
      );
    }
  } else {
    adoptionBlockers.push("adoption binding not assessed");
  }

  if (adoptionProof) {
    if (adoptionProof.missing?.length > 0) {
      adoptionBlockers.push(
        `${adoptionProof.missing.length} managed skeleton file(s) absent on disk: ${adoptionProof.missing.join(", ")}`,
      );
    }
    if (adoptionProof.mismatched?.length > 0) {
      adoptionBlockers.push(
        `${adoptionProof.mismatched.length} managed file(s) drifted from the planned digests: ${adoptionProof.mismatched.join(", ")}`,
      );
    }
  } else {
    adoptionBlockers.push("adoption proof not assessed");
  }

  const pending = typeof pendingWrites === "number" ? pendingWrites : (pendingWrites ?? []).length;
  if (pending > 0) {
    adoptionBlockers.push(`${pending} pending write action(s) remain in the writeSet`);
  }

  for (const item of legacyExitList ?? []) {
    if (item.status === "present") {
      adoptionBlockers.push(`legacy implementation still present: ${item.path}`);
    } else if (item.status === "invalid") {
      adoptionBlockers.push(`legacy entry cannot be verified (fail-closed): ${item.path ?? "<malformed>"} (${item.invalidKind ?? "unknown"})`);
    }
  }
  for (const ref of legacyReferenceExitList ?? []) {
    if (ref.status === "present") {
      adoptionBlockers.push(`legacy reference still present in ${ref.path}: ${ref.occurrenceCount} occurrence(s)`);
    } else if (ref.status === "invalid") {
      adoptionBlockers.push(`legacy reference cannot be verified (fail-closed): ${ref.path ?? "<malformed>"} (${ref.invalidKind ?? "unknown"})`);
    }
  }
  for (const finding of exceptionFindings ?? []) {
    if (finding.kind === "exception-incomplete") {
      adoptionBlockers.push(`exception #${finding.index} missing required fields: ${finding.missing.join(", ")}`);
    } else if (finding.kind === "exception-invalid-deadline") {
      adoptionBlockers.push(`exception #${finding.index} has an unparseable deadline: ${finding.deadline}`);
    } else if (finding.kind === "exception-expired") {
      adoptionBlockers.push(`exception #${finding.index} expired at ${finding.deadline}; tooling never renews exceptions`);
    }
  }
  if ((conflicts ?? []).length > 0) {
    adoptionBlockers.push(`${conflicts.length} unresolved adoption conflict(s) remain`);
  }
  // Capability blockers are relationship facts from the new manifest
  // extension. They intentionally join the existing adoption bucket so the
  // five-state migration closure remains unchanged.
  adoptionBlockers.push(...capabilityBlockers);

  if (checkGreen !== true) {
    verificationBlockers.push("the Foundation check gate is not green");
  }

  for (const fact of verificationFacts ?? []) {
    if (fact.status === "proven") continue;
    evidenceBlockers.push(`verification evidence ${fact.kind} is ${fact.status}${fact.path ? ` (${fact.path})` : ""}`);
  }
  if (!Array.isArray(verificationFacts)) {
    evidenceBlockers.push("verification evidence not assessed");
  }

  let state = "not-declared";
  if (manifestDeclared) {
    if (adoptionBlockers.length > 0) state = "declared";
    else if (verificationBlockers.length > 0) state = "adopted";
    else if (evidenceBlockers.length > 0) state = "verified";
    else state = "complete";
  }

  const blockers = [];
  if (!manifestDeclared) {
    blockers.push(`no contract-valid migration manifest declared at ${MIGRATION_MANIFEST_PATH}`);
  }
  blockers.push(...adoptionBlockers, ...verificationBlockers, ...evidenceBlockers);
  return { complete: state === "complete", state, blockers };
}
