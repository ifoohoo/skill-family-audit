import { canonicalJson, digestDocument, isRegisteredErrorCode } from "../contracts/index.mjs";
import {
  QUICKSTART_PROTOCOL,
  findNonJsonValue,
  validateConsumerSchemaInventoryDocument,
  validateHarnessSurfaceDetectorDocument,
  validateHarnessSurfaceInventoryDocument,
  validateQuickstartProfileDocument,
} from "../contracts-candidate/index.mjs";
import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { computeResourceClosure, digestBytes } from "./closure.mjs";
import { HARNESS_ERROR_KINDS, HarnessError, mechanismError } from "./errors.mjs";
import { resolveContained } from "./paths.mjs";

/**
 * Candidate quickstart profile v2 mechanisms (unstable).
 *
 * The harness only interprets mechanism constraints: contained reads, real
 * byte digests, profile validation, and per-field Task/Result binding. The
 * single operation is the business-neutral execute-method; params.method,
 * params.parameters, and domainResult are caller-owned and never read here.
 */

const QUICKSTART_OPERATION = "execute-method";
const RESULT_STATES = Object.freeze(["succeeded", "failed", "rejected"]);
const CORRELATION_FIELDS = Object.freeze(["run", "stage", "attempt"]);
const ERROR_ENTRY_FIELDS = new Set(["code", "message", "path", "details"]);
const FOUNDATION_PROJECTION_FILE = "foundation-projection.json";
const MANAGED_CLI_NAMES = Object.freeze(["adoption-cli.mjs", "mechanisms-cli.mjs"]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function assertSupportedBundleRuntime(runtimeVersion) {
  const match = /^(?:v)?(\d+)\.(\d+)\.(\d+)$/.exec(runtimeVersion ?? "");
  const [major, minor, patchVersion] = match ? match.slice(1).map(Number) : [];
  if (
    major !== 22 ||
    minor < 22 ||
    (minor === 22 && patchVersion < 2)
  ) {
    throw new TypeError(
      `verifyManagedBundleIdentity: Node.js runtime must satisfy >=22.22.2 <23; received ${String(runtimeVersion)}`,
    );
  }
}

function assertManagedPayloadPath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.includes("\\") ||
    path.posix.isAbsolute(value) ||
    path.posix.normalize(value) !== value ||
    value.split("/").some((segment) => segment === "." || segment === ".." || segment.length === 0)
  ) {
    throw new TypeError(`verifyManagedBundleIdentity: invalid managed payload path: ${String(value)}`);
  }
  return value;
}

async function listManagedBundleFiles(bundleRoot) {
  const files = [];
  async function walk(absDir, prefix) {
    const entries = await readdir(absDir, { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absPath = path.join(absDir, entry.name);
      if (entry.isSymbolicLink()) {
        throw new TypeError(`verifyManagedBundleIdentity: managed Bundle contains a symbolic link: ${relPath}`);
      }
      if (entry.isDirectory()) await walk(absPath, relPath);
      else if (entry.isFile() && relPath !== FOUNDATION_PROJECTION_FILE) files.push(relPath);
      else if (!entry.isFile()) {
        throw new TypeError(`verifyManagedBundleIdentity: unsupported managed Bundle member: ${relPath}`);
      }
    }
  }
  await walk(bundleRoot, "");
  return files.sort();
}

/**
 * Self-verifies one managed Quickstart Bundle CLI from its own file URL.
 *
 * The CLI path is supplied only by the trusted CLI module through
 * `import.meta.url`; stdin callers cannot select a path, module or export.
 * The check binds the complete neighboring payload, this CLI's bytes, and the
 * exact Node runtime before any fixed operation is dispatched.
 */
export async function verifyManagedBundleIdentity({
  cliUrl,
  cliName,
  runtimeVersion = process.version,
  runtimeExecPath = process.execPath,
} = {}) {
  if (!MANAGED_CLI_NAMES.includes(cliName)) {
    throw new TypeError(`verifyManagedBundleIdentity: unknown managed CLI: ${String(cliName)}`);
  }
  assertSupportedBundleRuntime(runtimeVersion);
  if (typeof cliUrl !== "string" || !cliUrl.startsWith("file:")) {
    throw new TypeError("verifyManagedBundleIdentity: cliUrl must be the trusted CLI file URL");
  }
  const cliPath = await realpath(fileURLToPath(cliUrl));
  if (path.basename(cliPath) !== cliName || !(await lstat(cliPath)).isFile()) {
    throw new TypeError("verifyManagedBundleIdentity: CLI identity does not match its managed path");
  }
  const bundleRoot = path.dirname(cliPath);
  const provenancePath = path.join(bundleRoot, FOUNDATION_PROJECTION_FILE);
  const provenanceStat = await lstat(provenancePath);
  if (!provenanceStat.isFile() || provenanceStat.isSymbolicLink()) {
    throw new TypeError("verifyManagedBundleIdentity: neighboring projection provenance must be a regular file");
  }
  const provenanceBytes = await readFile(provenancePath);
  let provenance;
  try {
    provenance = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(provenanceBytes));
  } catch {
    throw new TypeError("verifyManagedBundleIdentity: neighboring projection provenance is not valid UTF-8 JSON");
  }
  if (
    provenance?.schemaVersion !== 1 ||
    provenance?.kind !== "skill-family.foundation-projection" ||
    provenance?.payload?.digestAlgorithm !== "sha256" ||
    !Array.isArray(provenance.payload.files) ||
    !SHA256_PATTERN.test(provenance.payload.digest ?? "")
  ) {
    throw new TypeError("verifyManagedBundleIdentity: neighboring projection provenance has an invalid identity");
  }
  const declaredPaths = [];
  const declaredDigests = new Map();
  for (const record of provenance.payload.files) {
    if (
      record === null ||
      typeof record !== "object" ||
      Array.isArray(record) ||
      Object.keys(record).sort().join(",") !== "path,sha256" ||
      !SHA256_PATTERN.test(record.sha256 ?? "")
    ) {
      throw new TypeError("verifyManagedBundleIdentity: projection payload contains an invalid member record");
    }
    const relPath = assertManagedPayloadPath(record.path);
    if (declaredDigests.has(relPath)) {
      throw new TypeError(`verifyManagedBundleIdentity: duplicate projection payload member: ${relPath}`);
    }
    declaredPaths.push(relPath);
    declaredDigests.set(relPath, record.sha256);
  }
  const sortedDeclaredPaths = [...declaredPaths].sort();
  if (canonicalJson(declaredPaths) !== canonicalJson(sortedDeclaredPaths)) {
    throw new TypeError("verifyManagedBundleIdentity: projection payload members are not canonically ordered");
  }
  const actualPaths = await listManagedBundleFiles(bundleRoot);
  if (canonicalJson(actualPaths) !== canonicalJson(sortedDeclaredPaths)) {
    throw new TypeError("verifyManagedBundleIdentity: projection payload is not the complete neighboring file set");
  }
  for (const relPath of actualPaths) {
    const memberPath = path.join(bundleRoot, relPath);
    const memberStat = await lstat(memberPath);
    if (!memberStat.isFile() || memberStat.isSymbolicLink()) {
      throw new TypeError(`verifyManagedBundleIdentity: projection payload member is not a regular file: ${relPath}`);
    }
    const actualDigest = digestBytes(await readFile(memberPath));
    if (actualDigest !== declaredDigests.get(relPath)) {
      throw new TypeError(`verifyManagedBundleIdentity: projection payload member digest mismatch: ${relPath}`);
    }
  }
  if (!declaredDigests.has(cliName)) {
    throw new TypeError(`verifyManagedBundleIdentity: projection payload does not manage ${cliName}`);
  }
  if (digestDocument(provenance.payload.files) !== provenance.payload.digest) {
    throw new TypeError("verifyManagedBundleIdentity: projection payload digest mismatch");
  }
  const runtimePath = await realpath(runtimeExecPath);
  if (!path.isAbsolute(runtimePath) || !(await lstat(runtimePath)).isFile()) {
    throw new TypeError("verifyManagedBundleIdentity: Node.js runtime identity is not an absolute regular file");
  }
  return {
    valid: true,
    cli: {
      name: cliName,
      path: cliPath,
      sha256: declaredDigests.get(cliName),
    },
    runtime: {
      name: "node",
      version: runtimeVersion.startsWith("v") ? runtimeVersion : `v${runtimeVersion}`,
      execPath: runtimePath,
    },
    projection: {
      kind: provenance.kind,
      profile: structuredClone(provenance.profile),
      provenanceSha256: digestBytes(provenanceBytes),
      payloadDigest: provenance.payload.digest,
    },
  };
}

function invalidInventory(message, details = {}) {
  return mechanismError(
    HARNESS_ERROR_KINDS.INVALID_RESULT,
    message,
    { category: "consumer-schema-inventory", ...details },
  );
}

async function discoverSchemaFiles(root, relDir) {
  const rootReal = await realpath(root);
  const start = await resolveContained(rootReal, relDir);
  const found = [];
  async function walk(absDir, prefix) {
    const entries = await readdir(absDir, { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absPath = path.join(absDir, entry.name);
      if (entry.isSymbolicLink()) {
        throw invalidInventory("consumer schema roots must not contain symbolic links", { path: relPath });
      }
      if (entry.isDirectory()) await walk(absPath, relPath);
      else if (entry.isFile() && entry.name.endsWith(".schema.json")) found.push(relPath);
    }
  }
  await walk(start, relDir);
  return found;
}

/**
 * Proves that an inventory accounts for every local *.schema.json under its
 * declared roots, binds each entry to the file's real $id, and partitions the
 * set into Foundation Bundle inputs or explicitly retained consumer assets.
 */
export async function verifyConsumerSchemaInventory({ root, inventory } = {}) {
  const outcome = validateConsumerSchemaInventoryDocument(inventory);
  if (!outcome.valid) {
    throw invalidInventory("consumer schema inventory violates its candidate contract", {
      findings: outcome.errors,
    });
  }
  const normalized = outcome.data;
  const discovered = [];
  for (const schemaRoot of [...normalized.schemaRoots].sort()) {
    discovered.push(...await discoverSchemaFiles(root, schemaRoot));
  }
  discovered.sort();
  if (new Set(discovered).size !== discovered.length) {
    throw invalidInventory("consumer schema roots overlap", { discovered });
  }
  const records = [...normalized.schemas].sort((a, b) => (a.path < b.path ? -1 : 1));
  const declared = records.map((record) => record.path);
  if (new Set(declared).size !== declared.length) {
    throw invalidInventory("consumer schema inventory contains a duplicate path", { declared });
  }
  const missing = discovered.filter((file) => !declared.includes(file));
  const stale = declared.filter((file) => !discovered.includes(file));
  if (missing.length > 0 || stale.length > 0) {
    throw invalidInventory("consumer schema inventory is not a complete local inventory", { missing, stale });
  }
  const ids = new Set();
  for (const record of records) {
    let document;
    try {
      document = JSON.parse(await readFile(await resolveContained(root, record.path), "utf8"));
    } catch (cause) {
      throw invalidInventory("consumer schema cannot be read as JSON", {
        path: record.path,
        cause: cause?.code ?? cause?.name,
      });
    }
    if (document.$id !== record.$id) {
      throw invalidInventory("consumer schema inventory $id does not match the local file", {
        path: record.path,
        declared: record.$id,
        actual: document.$id,
      });
    }
    if (ids.has(record.$id)) {
      throw invalidInventory("consumer schema inventory contains a duplicate $id", { $id: record.$id });
    }
    ids.add(record.$id);
  }
  return {
    valid: true,
    schemaPaths: declared,
    bundleSchemaPaths: records
      .filter((record) => record.disposition === "foundation-bundle")
      .map((record) => record.path),
    retainedSchemas: records
      .filter((record) => record.disposition === "consumer-retained")
      .map((record) => structuredClone(record)),
  };
}

const DETECTOR_ID_PATTERN = /^[a-z][a-z0-9.-]*$/;
const SURFACE_TYPE_PATTERN = /^[a-z][a-z0-9-]*$/;

function normalizeSurfaceDetectors(detectors) {
  if (!Array.isArray(detectors) || detectors.length === 0) {
    throw new TypeError("scanHarnessSurfaceInventory: detectors must be a non-empty array");
  }
  const explicitDocument = {
    schemaVersion: 1,
    kind: "skill-family.harness-surface-detectors",
    detectors: detectors.filter((detector) => detector?.match !== undefined),
  };
  if (explicitDocument.detectors.length > 0) {
    const outcome = validateHarnessSurfaceDetectorDocument(explicitDocument);
    if (!outcome.valid) {
      throw invalidInventory("explicit Harness surface detectors violate their contract", {
        findings: outcome.errors,
      });
    }
  }
  const normalized = detectors.map((detector) => {
    if (
      detector === null || typeof detector !== "object" || Array.isArray(detector) ||
      !DETECTOR_ID_PATTERN.test(detector.detectorId ?? "") ||
      !SURFACE_TYPE_PATTERN.test(detector.surfaceType ?? "")
    ) {
      throw new TypeError("scanHarnessSurfaceInventory: detectorId and surfaceType must be stable identifiers");
    }
    const usesExplicit = detector.match !== undefined;
    const usesLegacy = detector.pathSuffixes !== undefined || detector.pathFragments !== undefined;
    if (usesExplicit && usesLegacy) {
      throw invalidInventory("Harness surface detector cannot mix explicit and legacy match fields", {
        detectorId: detector.detectorId,
      });
    }
    const pathSuffixes = detector.pathSuffixes ?? [];
    const pathFragments = detector.pathFragments ?? [];
    if (
      !Array.isArray(pathSuffixes) || !Array.isArray(pathFragments) ||
      [...pathSuffixes, ...pathFragments].some((value) => typeof value !== "string" || value.length === 0) ||
      (!usesExplicit && pathSuffixes.length + pathFragments.length === 0)
    ) {
      throw new TypeError("scanHarnessSurfaceInventory: each detector needs a non-empty path rule");
    }
    return Object.freeze({
      detectorId: detector.detectorId,
      surfaceType: detector.surfaceType,
      match: usesExplicit ? Object.freeze(structuredClone(detector.match)) : null,
      pathSuffixes: Object.freeze([...new Set(pathSuffixes)].sort()),
      pathFragments: Object.freeze([...new Set(pathFragments)].sort()),
    });
  });
  const ids = normalized.map((detector) => detector.detectorId);
  if (new Set(ids).size !== ids.length) {
    throw new TypeError("scanHarnessSurfaceInventory: detectorId values must be unique");
  }
  return normalized.sort((a, b) => (a.detectorId < b.detectorId ? -1 : 1));
}

function detectorMatches(detector, relPath) {
  if (detector.match !== null) {
    const clauses = detector.match.anyOf ?? [detector.match];
    return clauses.some((clause) => clause.allOf.every((predicate) => {
      if (predicate.pathSuffix !== undefined) return relPath.endsWith(predicate.pathSuffix);
      if (predicate.pathFragment !== undefined) return relPath.includes(predicate.pathFragment);
      return relPath === predicate.pathPrefix || relPath.startsWith(`${predicate.pathPrefix}/`);
    }));
  }
  return detector.pathSuffixes.some((suffix) => relPath.endsWith(suffix)) ||
    detector.pathFragments.some((fragment) => relPath.includes(fragment));
}

async function scanSurfaceFiles(root, scanRoot, detectors) {
  if (scanRoot !== "." && (typeof scanRoot !== "string" || scanRoot.length === 0)) {
    throw new TypeError("scanHarnessSurfaceInventory: scanRoot must be '.' or a contained path");
  }
  const start = scanRoot === "." ? await realpath(root) : await resolveContained(root, scanRoot);
  const surfaces = [];
  async function walk(absDir, prefix) {
    const entries = await readdir(absDir, { withFileTypes: true });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const relPath = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absPath = path.join(absDir, entry.name);
      if (entry.isSymbolicLink()) {
        throw invalidInventory("harness surface scan refuses symbolic links", { path: relPath });
      }
      if (entry.isDirectory()) {
        await walk(absPath, relPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const matches = detectors.filter((detector) => detectorMatches(detector, relPath));
      if (matches.length > 1) {
        throw invalidInventory("harness surface detectors overlap", {
          path: relPath,
          detectorIds: matches.map((detector) => detector.detectorId),
        });
      }
      if (matches.length === 0) continue;
      const detector = matches[0];
      const bytes = await readFile(absPath);
      surfaces.push({
        surfaceId: `${detector.surfaceType}:${relPath}`,
        surfaceType: detector.surfaceType,
        path: relPath,
        evidence: { sha256: digestBytes(bytes), detectorId: detector.detectorId },
      });
    }
  }
  await walk(start, scanRoot === "." ? "" : scanRoot);
  return surfaces.sort((a, b) => (a.surfaceId < b.surfaceId ? -1 : 1));
}

function surfaceInventoryDigest(receipt) {
  const digestInput = { ...receipt };
  delete digestInput.inventoryDigest;
  return digestDocument(digestInput);
}

/** Produce a deterministic, exhaustive, domain-neutral Harness surface receipt. */
export async function scanHarnessSurfaceInventory({ root, scanRoot, detectors } = {}) {
  const normalizedDetectors = normalizeSurfaceDetectors(detectors);
  const surfaces = await scanSurfaceFiles(root, scanRoot, normalizedDetectors);
  const receipt = {
    schemaVersion: 1,
    kind: "skill-family.harness-surface-inventory",
    scanRoot,
    exhaustive: true,
    surfaces,
  };
  receipt.inventoryDigest = surfaceInventoryDigest(receipt);
  const outcome = validateHarnessSurfaceInventoryDocument(receipt);
  if (!outcome.valid) {
    throw invalidInventory("generated harness surface inventory violates its contract", { findings: outcome.errors });
  }
  return outcome.data;
}

/** Re-scan and require exact receipt equality; callers need no local hash/path implementation. */
export async function verifyHarnessSurfaceInventory({ root, inventory, detectors } = {}) {
  const outcome = validateHarnessSurfaceInventoryDocument(inventory);
  if (!outcome.valid || inventory.inventoryDigest !== surfaceInventoryDigest(inventory)) {
    throw invalidInventory("harness surface inventory receipt is invalid or digest-drifted", {
      findings: outcome.errors,
    });
  }
  const actual = await scanHarnessSurfaceInventory({ root, scanRoot: inventory.scanRoot, detectors });
  if (canonicalJson(actual) !== canonicalJson(inventory)) {
    throw invalidInventory("harness surface inventory no longer matches the exhaustive scan", {
      expectedDigest: inventory.inventoryDigest,
      actualDigest: actual.inventoryDigest,
    });
  }
  return { valid: true, inventoryDigest: actual.inventoryDigest, surfaceCount: actual.surfaces.length };
}

const FOUNDATION_MECHANISM_OPERATIONS = Object.freeze([
  "validate-by-schema-id",
  "canonical-json",
  "digest-document",
  "resource-closure",
  "resolve-contained",
  "create-task",
  "wrap-result",
  "verify-exchange",
]);

function findUnsafeInteger(value, instancePath = "") {
  if (typeof value === "number") {
    return Number.isInteger(value) && !Number.isSafeInteger(value) ? instancePath : null;
  }
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const issue = findUnsafeInteger(value[index], `${instancePath}/${index}`);
      if (issue !== null) return issue;
    }
    return null;
  }
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      const issue = findUnsafeInteger(
        value[key],
        `${instancePath}/${key.replaceAll("~", "~0").replaceAll("/", "~1")}`,
      );
      if (issue !== null) return issue;
    }
  }
  return null;
}

/**
 * Fixed, business-neutral mechanism bridge for consumers that cannot import
 * several Foundation modules directly. validateBySchemaId is injected only
 * by the trusted offline Bundle; callers cannot name arbitrary functions.
 */
export async function invokeFoundationMechanism(request, { validateBySchemaId } = {}) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("invokeFoundationMechanism: request must be an object");
  }
  assertJsonValue("invokeFoundationMechanism", "request", request);
  const { operation, params } = request;
  if (!FOUNDATION_MECHANISM_OPERATIONS.includes(operation)) {
    throw new TypeError(`invokeFoundationMechanism: unknown operation: ${String(operation)}`);
  }
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new TypeError("invokeFoundationMechanism: params must be an object");
  }
  if (operation === "validate-by-schema-id") {
    if (typeof validateBySchemaId !== "function") {
      throw new TypeError("invokeFoundationMechanism: validate-by-schema-id requires the trusted Bundle validator");
    }
    return validateBySchemaId(params.schemaId, params.document);
  }
  if (operation === "canonical-json") {
    if (Object.keys(params).length !== 1 || !Object.hasOwn(params, "document")) {
      throw new TypeError("invokeFoundationMechanism: canonical-json params must contain exactly document");
    }
    const unsafeIntegerPath = findUnsafeInteger(params.document);
    if (unsafeIntegerPath !== null) {
      throw new TypeError(
        "invokeFoundationMechanism: canonical-json document contains an unsafe integer" +
          (unsafeIntegerPath ? ` at ${unsafeIntegerPath}` : ""),
      );
    }
    return { text: canonicalJson(params.document) };
  }
  if (operation === "digest-document") {
    return { digest: digestDocument(params.document) };
  }
  if (operation === "resource-closure") {
    return computeResourceClosure({ root: params.root, resources: params.resources });
  }
  if (operation === "create-task") {
    return createQuickstartTask(params);
  }
  if (operation === "wrap-result") {
    return wrapQuickstartResult(params);
  }
  if (operation === "verify-exchange") {
    return verifyQuickstartExchange(params);
  }
  await resolveContained(params.root, params.path);
  return { path: params.path, contained: true };
}

function invalidProfile(kind, outcome) {
  return mechanismError(
    HARNESS_ERROR_KINDS.INVALID_RESULT,
    `quickstart ${kind} violates the Foundation candidate profile`,
    { category: "profile", profileKind: kind, findings: outcome.errors },
  );
}

function assertProfile(kind, document) {
  const outcome = validateQuickstartProfileDocument(kind, document);
  if (!outcome.valid) throw invalidProfile(kind, outcome);
  return outcome.data;
}

/**
 * Caller-owned values must be pure JSON before they enter any Task or
 * Result: this refuses BigInt and friends before structuredClone,
 * digestDocument, or JSON.stringify could throw or silently drift.
 */
function assertJsonValue(caller, label, value) {
  const issue = findNonJsonValue(value);
  if (issue) {
    throw new TypeError(
      `${caller}: ${label} must be a JSON value; found ${issue.reason}` +
        (issue.instancePath ? ` at ${issue.instancePath}` : ""),
    );
  }
}

function containedPath(resource, roleDescription) {
  const relPath = resource?.location?.path;
  if (typeof relPath !== "string") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `the quickstart ${roleDescription} Resource must use a contained relative path`,
      { category: "resource-location", resourceId: resource?.id },
    );
  }
  return relPath;
}

/** Create one observation Resource from the actual contained file bytes. */
export async function createObservationResource({ root, path, id = "observation" } = {}) {
  const closure = await computeResourceClosure({
    root,
    resources: [{ path, role: "input" }],
  });
  const record = closure.resources[0];
  const resource = {
    schemaVersion: 1,
    kind: "skill-family.resource",
    id,
    location: { path: record.path },
    role: "observation",
    digest: { algorithm: "sha256", value: record.sha256 },
  };
  return assertProfile("resource", resource);
}

/**
 * Recomputes the real byte digest of one path-backed Resource and compares it
 * with the declared digest. URI-backed Resources are structurally checked
 * only: Foundation never fetches URIs.
 */
export async function verifyResourceBytes({ root, resource } = {}) {
  const normalized = assertProfile("resource", resource);
  const relPath = normalized.location.path;
  if (typeof relPath !== "string") {
    return { resource: normalized, byteDigest: null };
  }
  const closure = await computeResourceClosure({
    root,
    resources: [{ path: relPath, role: "input" }],
  });
  const actual = closure.resources[0].sha256;
  if (actual !== normalized.digest.value) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `quickstart ${normalized.role} Resource digest does not match its current bytes`,
      {
        category: "resource-bytes",
        role: normalized.role,
        resourceId: normalized.id,
        expected: normalized.digest.value,
        actual,
      },
    );
  }
  return { resource: normalized, byteDigest: actual };
}

/** Verify the single observation Resource: role, path-backed location, bytes. */
export async function verifyObservationResource({ root, resource } = {}) {
  const normalized = assertProfile("resource", resource);
  if (normalized.role !== "observation") {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      "quickstart task input must have the observation role",
      { category: "resource-role", resourceId: normalized.id, role: normalized.role },
    );
  }
  containedPath(normalized, "observation");
  const { byteDigest } = await verifyResourceBytes({ root, resource: normalized });
  return { resource: normalized, byteDigest };
}

/** Build a candidate v2 Task inside the stable operation-request envelope. */
export async function createQuickstartTask({
  root,
  observationPath,
  observationId = "observation",
  operationId,
  method,
  parameters = {},
  run,
  stage,
  attempt,
} = {}) {
  assertJsonValue("createQuickstartTask", "parameters", parameters);
  const observation = await createObservationResource({
    root,
    path: observationPath,
    id: observationId,
  });
  const task = {
    schemaVersion: 1,
    kind: "skill-family.operation-request",
    protocol: { ...QUICKSTART_PROTOCOL },
    operationId,
    operation: QUICKSTART_OPERATION,
    params: {
      method,
      parameters: structuredClone(parameters),
      inputs: [observation],
      correlation: { run, stage, attempt },
    },
  };
  return assertProfile("task", task);
}

function normalizeErrorEntries(errors) {
  if (!Array.isArray(errors) || errors.length === 0) {
    throw new TypeError(
      "wrapQuickstartResult: failed and rejected results require at least one error entry",
    );
  }
  assertJsonValue("wrapQuickstartResult", "errors", errors);
  return errors.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(`wrapQuickstartResult: error entry ${index} must be an object`);
    }
    const extraField = Object.keys(entry).find((field) => !ERROR_ENTRY_FIELDS.has(field));
    if (extraField !== undefined) {
      throw new TypeError(
        `wrapQuickstartResult: error entry ${index} has unsupported field ${extraField}`,
      );
    }
    const { code, message, path, details } = entry;
    if (typeof code !== "string" || !isRegisteredErrorCode(code)) {
      throw new TypeError(
        `wrapQuickstartResult: error entry ${index} code must be registered in the frozen contracts error registry`,
      );
    }
    if (typeof message !== "string" || message.length === 0) {
      throw new TypeError(
        `wrapQuickstartResult: error entry ${index} must carry a non-empty message`,
      );
    }
    if (path !== undefined) {
      assertJsonValue("wrapQuickstartResult", `error entry ${index} path`, path);
    }
    if (details !== undefined) {
      assertJsonValue("wrapQuickstartResult", `error entry ${index} details`, details);
    }
    const normalized = { code, message };
    if (path !== undefined) normalized.path = path;
    if (details !== undefined) normalized.details = structuredClone(details);
    return normalized;
  });
}

/**
 * Wrap one terminal Result for the candidate protocol. succeeded builds the
 * full outputs envelope (summary, outputs, evidence, domainResult,
 * taskBinding with exactly one evidenceBindings entry per evidence
 * Resource); failed and rejected always carry null outputs and at least one
 * registry-registered error.
 */
export function wrapQuickstartResult({
  task,
  state = "succeeded",
  summary,
  outputs = [],
  evidence = [],
  domainResult,
  errors,
} = {}) {
  const normalizedTask = assertProfile("task", task);
  if (!RESULT_STATES.includes(state)) {
    throw new TypeError(
      `wrapQuickstartResult: state must be one of ${RESULT_STATES.join(", ")}`,
    );
  }
  const observation = normalizedTask.params.inputs[0];
  const base = {
    schemaVersion: 1,
    kind: "skill-family.operation-result",
    protocol: structuredClone(normalizedTask.protocol),
    operationId: normalizedTask.operationId,
    operation: normalizedTask.operation,
    state,
  };
  if (state !== "succeeded") {
    for (const [name, value] of [
      ["summary", summary],
      ["outputs", outputs],
      ["evidence", evidence],
      ["domainResult", domainResult],
    ]) {
      const untouched =
        (name === "outputs" || name === "evidence") && Array.isArray(value) && value.length === 0;
      if (!untouched && value !== undefined) {
        throw new TypeError(
          `wrapQuickstartResult: ${state} results never carry ${name}; outputs must be null`,
        );
      }
    }
    return assertProfile("result", {
      ...base,
      outputs: null,
      errors: normalizeErrorEntries(errors),
    });
  }
  if (typeof summary !== "string" || summary.length === 0) {
    throw new TypeError("wrapQuickstartResult: succeeded results require a non-empty summary");
  }
  assertJsonValue("wrapQuickstartResult", "outputs", outputs);
  assertJsonValue("wrapQuickstartResult", "evidence", evidence);
  assertJsonValue("wrapQuickstartResult", "domainResult", domainResult);
  const normalizedEvidence = structuredClone(evidence);
  const correlation = structuredClone(normalizedTask.params.correlation);
  return assertProfile("result", {
    ...base,
    outputs: {
      summary,
      outputs: structuredClone(outputs),
      evidence: normalizedEvidence,
      domainResult: structuredClone(domainResult),
      taskBinding: {
        operationId: normalizedTask.operationId,
        taskDigest: digestDocument(normalizedTask),
        observationId: observation.id,
        observationDigest: observation.digest.value,
        correlation,
        evidenceBindings: normalizedEvidence.map((resource) => ({
          resourceId: resource?.id,
          operationId: normalizedTask.operationId,
          observationId: observation.id,
          correlation: structuredClone(correlation),
        })),
      },
    },
    errors: [],
  });
}

/**
 * Per-field correlation comparison: run, stage, and attempt mismatches are
 * reported as distinguishable paths instead of one opaque binding mismatch.
 */
function correlationMismatches(actual, expected, prefix) {
  const mismatches = [];
  for (const field of CORRELATION_FIELDS) {
    if (actual[field] !== expected[field]) mismatches.push(`${prefix}.${field}`);
  }
  return mismatches;
}

/**
 * Cross-checks taskBinding.evidenceBindings against the declared evidence
 * Resources: exactly one entry per evidence Resource id, each echoing the
 * exact operationId, observationId, and run/stage/attempt of this Task.
 */
function evidenceBindingMismatches(bindings, evidenceResources, normalizedTask, observation) {
  const mismatches = [];
  const evidenceIds = new Set(evidenceResources.map((resource) => resource.id));
  const bound = new Set();
  bindings.forEach((entry, index) => {
    const { resourceId } = entry;
    if (!evidenceIds.has(resourceId)) {
      mismatches.push(`binding.evidenceBindings.extra:${resourceId}`);
      return;
    }
    if (bound.has(resourceId)) {
      mismatches.push(`binding.evidenceBindings.duplicate:${resourceId}`);
      return;
    }
    bound.add(resourceId);
    const prefix = `binding.evidenceBindings[${index}]`;
    if (entry.operationId !== normalizedTask.operationId) {
      mismatches.push(`${prefix}.operationId`);
    }
    if (entry.observationId !== observation.id) {
      mismatches.push(`${prefix}.observationId`);
    }
    mismatches.push(
      ...correlationMismatches(entry.correlation, normalizedTask.params.correlation, `${prefix}.correlation`),
    );
  });
  for (const resourceId of [...evidenceIds].filter((id) => !bound.has(id)).sort()) {
    mismatches.push(`binding.evidenceBindings.missing:${resourceId}`);
  }
  return mismatches;
}

/**
 * Fail-closed exchange assertion. It validates both candidate profiles,
 * refuses duplicate Resource ids across the Task observation and all
 * output/evidence Resources, recomputes the real bytes of every path-backed
 * Resource, and proves the result echoes and binds the exact
 * protocol/operation/operationId/Task-digest/observation/correlation fields
 * plus one evidenceBindings entry per evidence Resource. No retry or
 * lifecycle state is introduced and no Result file is written.
 */
export async function assertQuickstartExchange({ root, task, result } = {}) {
  const normalizedTask = assertProfile("task", task);
  const normalizedResult = assertProfile("result", result);

  const mismatches = [];
  if (canonicalJson(normalizedResult.protocol) !== canonicalJson(normalizedTask.protocol)) {
    mismatches.push("protocol");
  }
  if (normalizedResult.operation !== normalizedTask.operation) mismatches.push("operation");
  if (normalizedResult.operationId !== normalizedTask.operationId) mismatches.push("operationId");

  const observation = normalizedTask.params.inputs[0];
  if (normalizedResult.state === "succeeded") {
    const declared = [
      observation,
      ...normalizedResult.outputs.outputs,
      ...normalizedResult.outputs.evidence,
    ];
    const seen = new Set();
    for (const resource of declared) {
      if (seen.has(resource.id)) {
        throw mechanismError(
          HARNESS_ERROR_KINDS.INVALID_RESULT,
          `quickstart result declares a duplicate Resource id: ${resource.id}`,
          { category: "duplicate-resource-id", resourceId: resource.id },
        );
      }
      seen.add(resource.id);
    }

    const binding = normalizedResult.outputs?.taskBinding;
    if (!binding) {
      mismatches.push("taskBinding");
    } else {
      if (binding.operationId !== normalizedTask.operationId) {
        mismatches.push("binding.operationId");
      }
      if (binding.taskDigest !== digestDocument(normalizedTask)) {
        mismatches.push("binding.taskDigest");
      }
      if (binding.observationId !== observation.id) mismatches.push("binding.observationId");
      if (binding.observationDigest !== observation.digest.value) {
        mismatches.push("binding.observationDigest");
      }
      mismatches.push(
        ...correlationMismatches(
          binding.correlation,
          normalizedTask.params.correlation,
          "binding.correlation",
        ),
      );
      mismatches.push(
        ...evidenceBindingMismatches(
          binding.evidenceBindings,
          normalizedResult.outputs.evidence,
          normalizedTask,
          observation,
        ),
      );
    }
  }
  if (mismatches.length > 0) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_RESULT,
      `quickstart result does not bind the exact task: ${mismatches.join(", ")}`,
      { category: "binding", mismatches },
    );
  }

  await verifyObservationResource({ root, resource: observation });

  if (normalizedResult.state === "succeeded") {
    const declared = [
      ...normalizedResult.outputs.outputs,
      ...normalizedResult.outputs.evidence,
    ];
    for (const resource of declared) {
      await verifyResourceBytes({ root, resource });
    }
  }

  return {
    valid: true,
    state: normalizedResult.state,
    taskDigest: digestDocument(normalizedTask),
    observationDigest: observation.digest.value,
  };
}

/**
 * Non-throwing form for callers that need a structured finding. Every
 * failure resolves to code SFC2004 with a deterministic string details.kind
 * and details.category: HarnessError paths from the closure and containment
 * machinery (missing-resource, path, symlink escapes) keep their stable kind
 * and every useful detail field, ordinary TypeErrors and omitted inputs fall
 * back to the invalid-result/unexpected-failure pair.
 */
export async function verifyQuickstartExchange(input) {
  try {
    return await assertQuickstartExchange(input);
  } catch (cause) {
    const message =
      cause instanceof Error && typeof cause.message === "string" && cause.message.length > 0
        ? cause.message
        : String(cause);
    if (cause instanceof HarnessError) {
      const rawDetails =
        cause.details && typeof cause.details === "object" ? cause.details : {};
      const kind =
        typeof rawDetails.kind === "string" && rawDetails.kind.length > 0
          ? rawDetails.kind
          : HARNESS_ERROR_KINDS.EXECUTION_FAILED;
      const category =
        typeof rawDetails.category === "string" && rawDetails.category.length > 0
          ? rawDetails.category
          : "resource-closure";
      return {
        valid: false,
        code: "SFC2004",
        message,
        details: { ...rawDetails, kind, category },
      };
    }
    return {
      valid: false,
      code: "SFC2004",
      message,
      details: {
        kind: HARNESS_ERROR_KINDS.INVALID_RESULT,
        category: "unexpected-failure",
      },
    };
  }
}

// Candidate consumers may use these generic Foundation mechanisms directly.
// They are thin exports of the stable implementations, not parallel algorithms.
export { canonicalJson, computeResourceClosure, digestBytes, digestDocument };
