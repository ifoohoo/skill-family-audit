import { readFile } from "node:fs/promises";
import path from "node:path";

// Read-only consumption of the common core. The SPI loader depends on
// contracts (structures, validation, frozen base version) and harness
// (contained reads and path containment) only; it never modifies either,
// and the core never imports this module (verified by an independent scan).
//
// Data-only Profile SPI: verification never executes profile-provided code. There is no
// dynamic import of any target file anywhere in this module: SPI entrypoints
// are JSON data resources read through the harness containment layer and
// parsed deterministically. Executable module entrypoints are refused as
// behavior injection before any of their bytes are interpreted.
import {
  CONTRACT_OBJECTS,
  CONTRACTS_VERSION,
  loadKernelProtocol,
  loadRegistry,
  validateDocument,
} from "skill-family-contracts";
import { digestBytes, readFileContained, resolveContained } from "skill-family-harness-node";

const SPI_DEFINITION = JSON.parse(
  await readFile(new URL("./extension-spi.json", import.meta.url), "utf8"),
);

// SPI v3 type definitions for the optional `adoption` and `overrides`
// descriptor sections (remediation handoff D-8/D-6). The contracts package
// stays untouched: the loader composes these $defs onto the contracts
// profile-descriptor schema at load time and validates descriptors against
// the composed schema.
const ADOPTION_TYPE_DEFINITIONS = JSON.parse(
  await readFile(new URL("./profile-adoption.schema.json", import.meta.url), "utf8"),
);

// Local rule baseline catalog: the only verification input for the
// tightening-only override checks. Keeping it inside the SPI avoids any hard
// dependency on the audit repository (remediation handoff C3).
const RULE_BASELINE_CATALOG = JSON.parse(
  await readFile(new URL("./rule-baseline-catalog.json", import.meta.url), "utf8"),
);

const BASE_DESCRIPTOR_SCHEMA = JSON.parse(
  await readFile(
    new URL("./profile-descriptor.schema.json", import.meta.url),
    "utf8",
  ),
);

const PROJECT_PROFILE_SCHEMA = JSON.parse(
  await readFile(
    new URL("./project-profile.schema.json", import.meta.url),
    "utf8",
  ),
);

export const PROJECT_PROFILE_SCHEMA_ID = PROJECT_PROFILE_SCHEMA.$id;

export function loadProjectProfileSchema() {
  return structuredClone(PROJECT_PROFILE_SCHEMA);
}

/** $id of the SPI-composed descriptor schema (distinct from the contracts $id on purpose). */
export const EXTENDED_DESCRIPTOR_SCHEMA_ID = SPI_DEFINITION.descriptor.extendedSchemaId;

/**
 * Composes the SPI v3 extended descriptor schema: the frozen contracts
 * profile-descriptor schema plus the optional top-level `adoption` and
 * `overrides` sections defined by profiles/spi/profile-adoption.schema.json.
 * Returns a fresh document on every call; callers never mutate it.
 */
export function loadExtendedDescriptorSchema() {
  const extended = structuredClone(BASE_DESCRIPTOR_SCHEMA);
  extended.$id = EXTENDED_DESCRIPTOR_SCHEMA_ID;
  extended.$defs = structuredClone(ADOPTION_TYPE_DEFINITIONS.$defs);
  extended.properties.adoption = { $ref: "#/$defs/adoption" };
  extended.properties.overrides = { $ref: "#/$defs/overrides" };
  return extended;
}

/** The frozen rule baseline catalog consumed by the overrides-policy checks. */
export function loadRuleBaselineCatalog() {
  return RULE_BASELINE_CATALOG;
}

/** Frozen SPI result codes: SPE0000 plus SPE1001..SPE1008. */
export const SPI_RESULT_CODES = Object.freeze(
  Object.fromEntries(SPI_DEFINITION.resultCodes.map((entry) => [entry.code, entry.name])),
);

/** Ids of the extension points this SPI opens. Everything else is closed. */
export const OPEN_EXTENSION_POINT_IDS = Object.freeze(
  SPI_DEFINITION.extensionPoints.map((point) => point.id),
);

function buildCoreOwnedExactTargets() {
  const registry = loadRegistry();
  const kernel = loadKernelProtocol();
  const names = new Set();
  // Static declarations from the SPI definition (cross-checked by audit).
  for (const name of SPI_DEFINITION.coreOwned.packages) names.add(name);
  for (const name of SPI_DEFINITION.coreOwned.commands) names.add(name);
  // Dynamic facts derived from contracts itself (cannot drift).
  for (const name of CONTRACT_OBJECTS) names.add(name);
  for (const schema of registry.schemas) {
    names.add(schema.$id);
    names.add(schema.object);
  }
  for (const protocol of registry.protocols) names.add(protocol.name);
  for (const operation of kernel.operations) names.add(operation.name);
  return Object.freeze([...names].sort());
}

/** Exact core-owned target names (packages, commands, contracts objects, $ids, protocols, kernel operations). */
export const CORE_OWNED_TARGETS = buildCoreOwnedExactTargets();

const NAMESPACE_PREFIXES = Object.freeze([...SPI_DEFINITION.coreOwned.namespacePrefixes]);
const DECLARATION_SHAPE = SPI_DEFINITION.declarationShape;
const ENTRYPOINT_RULES = SPI_DEFINITION.entrypointRules;

/** Extensions that mark a declaration as an executable module (forbidden). */
const EXECUTABLE_MODULE_EXTENSIONS = Object.freeze([...ENTRYPOINT_RULES.deniedExecutableExtensions]);

function result(code, extra) {
  return { ok: code === "SPE0000", code, name: SPI_RESULT_CODES[code], ...extra };
}

/** True when a difference target is path-like (slash-separated simple segments). */
function isPathLikeTarget(target) {
  return typeof target === "string" && /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/.test(target) && target.includes("/");
}

function isCoreOwnedName(name) {
  if (CORE_OWNED_TARGETS.includes(name)) return true;
  return NAMESPACE_PREFIXES.some((prefix) => name.startsWith(prefix));
}

function isPlainData(value, keyPath) {
  const type = typeof value;
  if (type === "function" || type === "symbol" || type === "bigint" || type === "undefined") {
    return { ok: false, keyPath, valueType: type };
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const child = isPlainData(value[index], `${keyPath}[${index}]`);
      if (!child.ok) return child;
    }
    return { ok: true };
  }
  if (value && type === "object") {
    for (const [key, child] of Object.entries(value)) {
      const childResult = isPlainData(child, keyPath === "" ? key : `${keyPath}.${key}`);
      if (!childResult.ok) return childResult;
    }
    return { ok: true };
  }
  return { ok: true };
}

function deepEqualJsonRoundTrip(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    return false;
  }
  if (serialized === undefined) return false;
  return JSON.stringify(JSON.parse(serialized)) === serialized;
}

/**
 * GK-4 digest discipline migrated to the lightweight adoption contract
 * (remediation handoff D-8): every digest declared inside a profile is
 * compared against the REAL file bytes.
 *
 * Verifies the foundation_pin of one adoption declaration: each pinned
 * package artifact is read through the harness containment layer inside the
 * profile write set and its actual sha256 is compared with the declared
 * digest. Read-only; never writes, never executes.
 *
 * Returns { ok, algorithm, results } where each result carries
 * { package, path, declaredSha256, actualSha256, status } with status one of
 * "verified" | "artifact-unreadable" | "digest-mismatch".
 */
export async function verifyAdoptionDigests({ profileRoot, adoption } = {}) {
  if (typeof profileRoot !== "string" || profileRoot.length === 0) {
    throw new TypeError("verifyAdoptionDigests: profileRoot must be a non-empty path string");
  }
  const packages = adoption?.foundation_pin?.packages;
  if (packages === null || typeof packages !== "object" || Array.isArray(packages)) {
    throw new TypeError("verifyAdoptionDigests: adoption.foundation_pin.packages must be an object");
  }
  const results = [];
  let ok = true;
  for (const [name, pin] of Object.entries(packages).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    let bytes;
    try {
      bytes = await readFileContained(profileRoot, pin.path);
    } catch (cause) {
      ok = false;
      results.push({
        package: name,
        path: pin.path,
        declaredSha256: pin.sha256,
        actualSha256: null,
        status: "artifact-unreadable",
        containmentKind: cause?.details?.kind ?? "unknown",
      });
      continue;
    }
    const actualSha256 = digestBytes(bytes);
    if (actualSha256 === pin.sha256) {
      results.push({ package: name, path: pin.path, declaredSha256: pin.sha256, actualSha256, status: "verified" });
    } else {
      ok = false;
      results.push({ package: name, path: pin.path, declaredSha256: pin.sha256, actualSha256, status: "digest-mismatch" });
    }
  }
  return { ok, algorithm: "sha256", results };
}

/**
 * Tightening-only override policy (remediation handoff D-6), checked against
 * the local rule baseline catalog — no hard dependency on the audit repo.
 *
 * Pure function: returns { ok, findings[] }. Finding kinds:
 *   duplicate-override      the same rule/parameter pair is declared twice
 *   unknown-rule-id         rule id absent from the frozen catalog
 *   unknown-parameter       parameter not registered for that rule
 *   non-integer-value       integer-typed parameter given a non-integer
 *   override-not-tightening value does not strictly tighten the baseline in
 *                           the parameter's declared direction (relaxation
 *                           and equality are both refused)
 */
export function assessOverridesPolicy(overrides) {
  const findings = [];
  if (!Array.isArray(overrides)) return { ok: true, findings };
  const catalogRules = new Map(RULE_BASELINE_CATALOG.rules.map((rule) => [rule.ruleId, rule]));
  const seen = new Set();
  for (const [index, override] of overrides.entries()) {
    const ruleId = override?.ruleId;
    const parameterName = override?.parameter;
    const key = `${ruleId}#${parameterName}`;
    if (seen.has(key)) {
      findings.push({ kind: "duplicate-override", index, ruleId, parameter: parameterName });
      continue;
    }
    seen.add(key);
    const rule = catalogRules.get(ruleId);
    if (!rule) {
      findings.push({ kind: "unknown-rule-id", index, ruleId });
      continue;
    }
    const parameter = (rule.parameters ?? []).find((entry) => entry.parameter === parameterName);
    if (!parameter) {
      findings.push({ kind: "unknown-parameter", index, ruleId, parameter: parameterName });
      continue;
    }
    const value = override?.value;
    if (parameter.valueType === "integer" && !Number.isInteger(value)) {
      findings.push({ kind: "non-integer-value", index, ruleId, parameter: parameterName, value });
      continue;
    }
    const tightens =
      parameter.tighteningDirection === "not-increase"
        ? value < parameter.baselineValue
        : parameter.tighteningDirection === "not-decrease"
          ? value > parameter.baselineValue
          : false;
    if (!tightens) {
      findings.push({
        kind: "override-not-tightening",
        index,
        ruleId,
        parameter: parameterName,
        baselineValue: parameter.baselineValue,
        tighteningDirection: parameter.tighteningDirection,
        declaredValue: value,
      });
    }
  }
  return { ok: findings.length === 0, findings };
}

/**
 * Verifies one profile against the frozen SPI.
 *
 * Options:
 * - profileRoot: absolute path of the profile directory (its write-set root);
 * - descriptorRelPath: descriptor file inside the profile root
 *   (default "profile.json").
 *
 * Deterministic pipeline: descriptor-schema -> base-version ->
 * core-target-scan -> write-set-containment -> resource-presence ->
 * declaration-shape -> adoption-pin-digests -> overrides-policy. The first
 * failing step decides the stable result code:
 *
 *   SPE1001 descriptor invalid (schema/parse; carries observedCode). Since
 *           SPI v3 the descriptor is validated against the SPI-composed
 *           extended schema that admits the optional `adoption` and
 *           `overrides` sections; adoption field completeness and pin
 *           format are schema-checked here.
 *   SPE1005 base contracts version mismatch
 *   SPE1004 core reverse dependency (core-owned target, unopened
 *           override/removal, behavior injection through a module)
 *   SPE1003 write-set escape (path-like declaration leaves the profile root)
 *   SPE1002 missing resource (entrypoint absent, not parseable as a JSON
 *           data resource, or not satisfying its own declaration)
 *   SPE1006 adoption pin unverified (declared adoption section only): a
 *           pinned artifact is absent/unreadable inside the write set or its
 *           real sha256 differs from the declared digest (GK-4 discipline)
 *   SPE1007 override policy violation (declared overrides only): unknown
 *           rule id, unknown parameter, duplicate, or a value that does not
 *           strictly tighten the frozen catalog baseline
 *   SPE0000 admitted
 *
 * Read-only and execution-free: this function never writes anywhere and
 * never executes, imports, or evaluates any target-provided file.
 */
export async function verifyProfile({ profileRoot, descriptorRelPath } = {}) {
  if (typeof profileRoot !== "string" || profileRoot.length === 0) {
    throw new TypeError("verifyProfile: profileRoot must be a non-empty path string");
  }
  const relPath = descriptorRelPath ?? SPI_DEFINITION.descriptor.file;
  const steps = [];

  // 1. descriptor-schema -------------------------------------------------
  let raw;
  try {
    raw = await readFileContained(profileRoot, relPath, { encoding: "utf8" });
  } catch (cause) {
    return result("SPE1001", {
      reason: "descriptor-unreadable",
      details: { kind: cause?.details?.kind ?? "unknown", descriptor: relPath },
      steps,
    });
  }
  let descriptor;
  try {
    descriptor = JSON.parse(raw);
  } catch {
    return result("SPE1001", { reason: "descriptor-parse-failed", details: { descriptor: relPath }, steps });
  }
  const validation = validateDocument(descriptor, {
    schema: loadExtendedDescriptorSchema(),
    dialect: SPI_DEFINITION.projectProfile.dialect,
    policy: SPI_DEFINITION.projectProfile.policy,
  });
  if (!validation.valid) {
    return result("SPE1001", {
      reason: "descriptor-schema-invalid",
      details: { observedCode: validation.errorCode, errors: validation.errors.slice(0, 5) },
      steps,
    });
  }
  steps.push("descriptor-schema");
  const document = validation.data;
  const profileId = document.profile.id;

  // 2. base-version ------------------------------------------------------
  if (document.base.contractsVersion !== CONTRACTS_VERSION) {
    return result("SPE1005", {
      profileId,
      details: { declared: document.base.contractsVersion, expected: CONTRACTS_VERSION },
      steps,
    });
  }
  steps.push("base-version");

  const differences = document.differences ?? [];
  const spiEntries = document.spi ?? [];

  // 3. core-target-scan ----------------------------------------------------
  for (const difference of differences) {
    if (isCoreOwnedName(difference.target)) {
      return result("SPE1004", {
        profileId,
        reason: "core-owned-target",
        details: { differenceId: difference.id, target: difference.target, kind: difference.kind },
        steps,
      });
    }
    if (difference.kind !== "adds" && !OPEN_EXTENSION_POINT_IDS.includes(difference.target)) {
      return result("SPE1004", {
        profileId,
        reason: "target-not-open-for-override",
        details: { differenceId: difference.id, target: difference.target, kind: difference.kind },
        steps,
      });
    }
  }
  for (const entry of spiEntries) {
    if (isCoreOwnedName(entry.id)) {
      return result("SPE1004", {
        profileId,
        reason: "core-owned-spi-id",
        details: { spiId: entry.id },
        steps,
      });
    }
  }
  steps.push("core-target-scan");

  // 4. write-set-containment -----------------------------------------------
  const pathLikeDeclarations = [
    ...spiEntries.map((entry) => ({ source: "spi-entrypoint", id: entry.id, path: entry.entrypoint })),
    ...differences
      .filter((difference) => isPathLikeTarget(difference.target))
      .map((difference) => ({ source: "difference-target", id: difference.id, path: difference.target })),
  ];
  for (const declaration of pathLikeDeclarations) {
    try {
      await resolveContained(profileRoot, declaration.path);
    } catch (cause) {
      return result("SPE1003", {
        profileId,
        reason: "path-escapes-profile-write-set",
        details: {
          source: declaration.source,
          declarationId: declaration.id,
          path: declaration.path,
          containmentKind: cause?.details?.kind ?? "unknown",
        },
        steps,
      });
    }
  }
  steps.push("write-set-containment");

  // 5+6. resource-presence + declaration-shape ------------------------------
  // Data-only Profile SPI: entrypoints are JSON data resources. The loader reads them
  // through the containment layer and parses them; nothing is ever imported,
  // required, evaluated, or executed. An entrypoint declared as an
  // executable module is behavior injection and is refused before any of
  // its content is interpreted.
  for (const entry of spiEntries) {
    const extension = path.posix.extname(entry.entrypoint.split("/").pop() ?? "").toLowerCase();
    if (EXECUTABLE_MODULE_EXTENSIONS.includes(extension)) {
      return result("SPE1004", {
        profileId,
        reason: "entrypoint-is-executable-module",
        details: { spiId: entry.id, path: entry.entrypoint, extension },
        steps,
      });
    }

    let rawEntrypoint;
    try {
      rawEntrypoint = await readFileContained(profileRoot, entry.entrypoint, { encoding: "utf8" });
    } catch (cause) {
      return result("SPE1002", {
        profileId,
        reason: "entrypoint-missing",
        details: { spiId: entry.id, path: entry.entrypoint, containmentKind: cause?.details?.kind ?? "unknown" },
        steps,
      });
    }

    let exported;
    try {
      exported = JSON.parse(rawEntrypoint);
    } catch {
      exported = null;
    }
    if (exported === null || typeof exported !== "object" || Array.isArray(exported)) {
      return result("SPE1002", {
        profileId,
        reason: "entrypoint-not-a-json-data-resource",
        details: { spiId: entry.id, path: entry.entrypoint },
        steps,
      });
    }
    const keys = Object.keys(exported).sort();
    const allowed = [...DECLARATION_SHAPE.allowedKeySet].sort();
    if (keys.join("\0") !== allowed.join("\0")) {
      return result("SPE1002", {
        profileId,
        reason: "declaration-shape-keys",
        details: { spiId: entry.id, path: entry.entrypoint, keys, allowed },
        steps,
      });
    }
    if (exported.id !== entry.id || exported.spiVersion !== entry.version) {
      return result("SPE1002", {
        profileId,
        reason: "declaration-mismatch",
        details: {
          spiId: entry.id,
          path: entry.entrypoint,
          exportedId: exported.id,
          exportedSpiVersion: exported.spiVersion,
          declaredVersion: entry.version,
        },
        steps,
      });
    }
    if (!OPEN_EXTENSION_POINT_IDS.includes(exported.extensionPoint)) {
      return result("SPE1004", {
        profileId,
        reason: "extension-point-not-open",
        details: { spiId: entry.id, path: entry.entrypoint, extensionPoint: exported.extensionPoint },
        steps,
      });
    }
    // JSON.parse guarantees plain data (no callables, symbols, getters or
    // proxies can survive parsing); the checks below stay as defense in
    // depth and as the stable contract for any future parser.
    const dataCheck = isPlainData(exported, "");
    if (!dataCheck.ok) {
      return result("SPE1004", {
        profileId,
        reason: "non-data-value-in-declaration",
        details: { spiId: entry.id, path: entry.entrypoint, keyPath: dataCheck.keyPath, valueType: dataCheck.valueType },
        steps,
      });
    }
    if (!deepEqualJsonRoundTrip(exported)) {
      return result("SPE1004", {
        profileId,
        reason: "declaration-not-json-stable",
        details: { spiId: entry.id, path: entry.entrypoint },
        steps,
      });
    }
  }
  steps.push("resource-presence", "declaration-shape");

  // 7. adoption-pin-digests (optional section) ----------------------------
  // GK-4 digest discipline on the lightweight adoption contract: every
  // digest declared in the profile is compared against real file bytes
  // inside the profile write set. Absent only when no adoption is declared.
  if (document.adoption !== undefined) {
    const digestReport = await verifyAdoptionDigests({ profileRoot, adoption: document.adoption });
    if (!digestReport.ok) {
      const failed = digestReport.results.find((entry) => entry.status !== "verified");
      return result("SPE1006", {
        profileId,
        reason: failed.status === "artifact-unreadable" ? "pin-artifact-unreadable" : "pin-digest-mismatch",
        details: {
          package: failed.package,
          path: failed.path,
          declaredSha256: failed.declaredSha256,
          actualSha256: failed.actualSha256,
          containmentKind: failed.containmentKind ?? null,
        },
        steps,
      });
    }
    steps.push("adoption-pin-digests");
  }

  // 8. overrides-policy (optional section) ---------------------------------
  // Tightening-only self-tightening declarations (D-6), verified against the
  // local rule baseline catalog: rule id existence, registered parameter,
  // no duplicates, and strict tightening in the declared direction.
  const overrides = document.overrides ?? [];
  if (overrides.length > 0) {
    const assessment = assessOverridesPolicy(overrides);
    if (!assessment.ok) {
      const [finding] = assessment.findings;
      return result("SPE1007", {
        profileId,
        reason: finding.kind,
        details: { ...finding },
        steps,
      });
    }
    steps.push("overrides-policy");
  }

  return result("SPE0000", {
    profileId,
    details: {
      differences: differences.length,
      spiEntries: spiEntries.length,
      differenceTargets: differences.map((difference) => difference.target),
      adoptionDeclared: document.adoption !== undefined,
      overrides: overrides.length,
    },
    steps,
  });
}

/**
 * Verifies the project-level adoption declaration emitted by scaffold.
 * This intake is deliberately separate from verifyProfile: a project profile
 * declares the adopting workspace, while a descriptor declares a provider.
 */
export async function verifyProjectProfile({ projectRoot, profileRelPath } = {}) {
  if (typeof projectRoot !== "string" || projectRoot.length === 0) {
    throw new TypeError("verifyProjectProfile: projectRoot must be a non-empty path string");
  }
  const relPath = profileRelPath ?? "profile.json";
  const projectSteps = [];
  let raw;
  try {
    raw = await readFileContained(projectRoot, relPath, { encoding: "utf8" });
  } catch (cause) {
    return result("SPE1008", { reason: "project-profile-unreadable", details: { kind: cause?.details?.kind ?? "unknown", profile: relPath }, steps: projectSteps });
  }
  let document;
  try {
    document = JSON.parse(raw);
  } catch {
    return result("SPE1008", { reason: "project-profile-parse-failed", details: { profile: relPath }, steps: projectSteps });
  }
  const validation = validateDocument(document, {
    schema: loadProjectProfileSchema(),
    dialect: SPI_DEFINITION.descriptor.dialect,
    policy: SPI_DEFINITION.descriptor.policy,
  });
  if (!validation.valid) {
    return result("SPE1008", {
      reason: "project-profile-schema-invalid",
      details: { observedCode: validation.errorCode, errors: validation.errors.slice(0, 5) },
      steps: projectSteps,
    });
  }
  projectSteps.push("project-profile-schema");
  const projectProfile = validation.data;
  let digestReport;
  try {
    digestReport = await verifyAdoptionDigests({ profileRoot: projectRoot, adoption: projectProfile.adoption });
  } catch (cause) {
    return result("SPE1008", { reason: "project-profile-adoption-invalid", details: { message: cause?.message ?? String(cause) }, steps: projectSteps });
  }
  if (!digestReport.ok) {
    const failed = digestReport.results.find((entry) => entry.status !== "verified");
    return result("SPE1006", {
      reason: failed.status === "artifact-unreadable" ? "pin-artifact-unreadable" : "pin-digest-mismatch",
      details: { package: failed.package, path: failed.path, declaredSha256: failed.declaredSha256, actualSha256: failed.actualSha256, containmentKind: failed.containmentKind ?? null },
      steps: projectSteps,
    });
  }
  projectSteps.push("adoption-pin-digests");
  const assessment = assessOverridesPolicy(projectProfile.overrides);
  if (!assessment.ok) {
    const [finding] = assessment.findings;
    return result("SPE1007", { reason: finding.kind, details: { ...finding }, steps: projectSteps });
  }
  projectSteps.push("overrides-policy");
  return result("SPE0000", {
    projectId: projectProfile.project.id,
    details: { adoptionDeclared: true, overrides: projectProfile.overrides.length },
    steps: projectSteps,
  });
}

/** The frozen SPI definition document. */
export function loadSpiDefinition() {
  return SPI_DEFINITION;
}
