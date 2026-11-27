import {
  buildEffectiveIndex,
  computeContentHash,
  queryEffectiveIndex,
  resolveEntry,
  validateCatalog,
  validateEffectiveIndex,
  validateProjectOverlay
} from "./chunk-VJKMVB7M.js";

// src/cli.ts
import { readFileSync as readFileSync2, writeFileSync as writeFileSync2, existsSync as existsSync2, mkdirSync as mkdirSync2 } from "fs";
import { parse as yamlParse } from "yaml";
import { resolve as resolve2, dirname as dirname2, relative as relative2, isAbsolute as isAbsolute2 } from "path";

// src/v2/migration.ts
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  renameSync,
  unlinkSync,
  lstatSync,
  realpathSync
} from "fs";
import { resolve, relative, isAbsolute, dirname, basename } from "path";
var CONVERSION_ALGORITHM_VERSION = "2.0.0";
function generateSyntheticIdentity(entry) {
  const canonicalInput = {
    ref: entry.ref,
    provider: {
      scope: entry.provider.scope,
      plugin: entry.provider.plugin ?? null,
      skill: entry.provider.skill
    },
    kind: entry.kind
  };
  const syntheticDigest = computeContentHash(canonicalInput);
  const suffix = syntheticDigest.slice("sha256:".length, "sha256:".length + 16);
  return {
    v1Ref: entry.ref,
    familyImplementationId: `synthetic.family.${suffix}`,
    serviceImplementationId: `synthetic.service.${suffix}`,
    syntheticDigest,
    provenance: `v1:${entry.provider.scope}:${entry.provider.plugin ?? "project"}`,
    conversionAlgorithmVersion: CONVERSION_ALGORITHM_VERSION
  };
}
function convertOverrideToBinding(override, mapping) {
  if (override.ref !== mapping.ref) throw new Error(`Migration mapping ref mismatch: ${override.ref} != ${mapping.ref}`);
  const sourceDigest = computeContentHash(override);
  const v2Binding = {
    familyId: mapping.familyId,
    apiIdentity: { ...mapping.apiIdentity },
    implementationIdentity: { ...mapping.implementationIdentity },
    providerSelector: { ...mapping.providerSelector },
    selectionSource: "synthetic-migration",
    conformanceEvidence: { ...mapping.conformanceEvidence }
  };
  const conversionDigest = computeContentHash({
    sourceDigest,
    v2Binding,
    targetPath: mapping.targetPath,
    conversionAlgorithmVersion: CONVERSION_ALGORITHM_VERSION
  });
  return {
    v1Ref: override.ref,
    v2Binding,
    sourceDigest,
    conversionAlgorithmVersion: CONVERSION_ALGORITHM_VERSION,
    conversionDigest
  };
}
function detectCollisions(syntheticIds, bindingConversions, existingV2Entries) {
  const collisions = [];
  for (const synId of syntheticIds) {
    if (existingV2Entries.some(
      (existing) => existing.familyImplementationId === synId.familyImplementationId && existing.serviceImplementationId === synId.serviceImplementationId
    )) {
      collisions.push({
        ref: synId.v1Ref,
        type: "identity-collision",
        details: `Synthetic identity ${synId.familyImplementationId}/${synId.serviceImplementationId} already exists`
      });
    }
  }
  const byFamily = /* @__PURE__ */ new Map();
  for (const conversion of bindingConversions) {
    const ids = byFamily.get(conversion.v2Binding.familyId) ?? /* @__PURE__ */ new Set();
    ids.add(`${conversion.v2Binding.implementationIdentity.familyImplementationId}@${conversion.v2Binding.implementationIdentity.version}`);
    byFamily.set(conversion.v2Binding.familyId, ids);
  }
  for (const [familyId, ids] of byFamily) {
    if (ids.size > 1) {
      collisions.push({
        ref: familyId,
        type: "unsafe-aggregation",
        details: `Family ${familyId} maps to ${ids.size} implementations; choose one atomic family release`
      });
    }
  }
  return { hasCollisions: collisions.length > 0, collisions };
}
function computeMigrationPlanDigest(plan) {
  const { planDigest: _ignored, ...withoutSelf } = plan;
  return computeContentHash(withoutSelf);
}
function generateMigrationPlan(v1Entries, v1Overrides, context) {
  const syntheticIdentities = v1Entries.map(generateSyntheticIdentity).sort((a, b) => a.v1Ref.localeCompare(b.v1Ref));
  const bindingConversions = [];
  const unresolved = [];
  const targetFiles = {};
  for (const override of [...v1Overrides].sort((a, b) => a.ref.localeCompare(b.ref))) {
    const mapping = context.mappings.find((candidate) => candidate.ref === override.ref);
    if (!mapping) {
      unresolved.push({ ref: override.ref, type: "unresolved-mapping", details: "No explicit migration mapping was supplied" });
      continue;
    }
    const conversion = convertOverrideToBinding(override, mapping);
    bindingConversions.push(conversion);
    if (Object.hasOwn(targetFiles, mapping.targetPath)) {
      unresolved.push({ ref: override.ref, type: "binding-collision", details: `Multiple conversions target ${mapping.targetPath}` });
    } else {
      targetFiles[mapping.targetPath] = { documentKind: "v2-binding", schemaVersion: 2, bindings: [conversion.v2Binding] };
    }
  }
  const collisionReport = detectCollisions(syntheticIdentities, bindingConversions, []);
  collisionReport.collisions.push(...unresolved);
  collisionReport.hasCollisions = collisionReport.collisions.length > 0;
  const draft = {
    documentKind: "v2-migration-plan",
    schemaVersion: 2,
    syntheticIdentities,
    bindingConversions,
    collisionReport,
    sourceManifest: [...context.sourceManifest].sort((a, b) => a.path.localeCompare(b.path)),
    targetFiles: Object.fromEntries(Object.entries(targetFiles).sort(([a], [b]) => a.localeCompare(b)))
  };
  return { ...draft, planDigest: computeMigrationPlanDigest(draft) };
}
function nearestExistingAncestor(path) {
  let cursor = path;
  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return cursor;
}
function validateTransactionPath(targetPath, transactionRoot) {
  if (isAbsolute(targetPath) || targetPath.split(/[\\/]+/).includes("..")) {
    return { ok: false, reason: `Target path must be relative and must not contain ..: ${targetPath}` };
  }
  const resolvedRoot = realpathSync(transactionRoot);
  const resolvedTarget = resolve(resolvedRoot, targetPath);
  const relFromRoot = relative(resolvedRoot, resolvedTarget);
  if (relFromRoot.startsWith("..") || isAbsolute(relFromRoot)) {
    return { ok: false, reason: `Target path escapes transaction root: ${targetPath}` };
  }
  const ancestor = nearestExistingAncestor(resolvedTarget);
  const realAncestor = realpathSync(ancestor);
  const relAncestor = relative(resolvedRoot, realAncestor);
  if (relAncestor.startsWith("..") || isAbsolute(relAncestor)) {
    return { ok: false, reason: `Target path crosses a symlink outside transaction root: ${targetPath}` };
  }
  if (existsSync(resolvedTarget) && lstatSync(resolvedTarget).isSymbolicLink()) {
    return { ok: false, reason: `Target path must not be a symlink: ${targetPath}` };
  }
  return { ok: true };
}
function generateMigrationSnapshot(plan, transactionRoot, timestamp) {
  const originalBytes = {};
  const appliedDigests = {};
  for (const filePath of Object.keys(plan.targetFiles)) {
    const check = validateTransactionPath(filePath, transactionRoot);
    if (!check.ok) throw new Error(check.reason);
    const fullPath = resolve(transactionRoot, filePath);
    originalBytes[filePath] = existsSync(fullPath) ? readFileSync(fullPath).toString("base64") : "__NOT_EXISTS__";
    const appliedBytes = Buffer.from(JSON.stringify(plan.targetFiles[filePath], null, 2) + "\n", "utf-8");
    appliedDigests[filePath] = computeContentHash(appliedBytes.toString("base64"));
  }
  const snapshotDigest = computeContentHash({ planDigest: plan.planDigest, originalBytes, appliedDigests, timestamp });
  return { schemaVersion: 2, snapshotDigest, timestamp, planDigest: plan.planDigest, originalBytes, appliedDigests };
}
function applyMigrationPlan(plan, transactionRoot, timestamp) {
  if (computeMigrationPlanDigest(plan) !== plan.planDigest) {
    return { ok: false, diagnostics: [{ code: "SNAPSHOT_TAMPERED", severity: "error", message: "Migration plan digest mismatch" }] };
  }
  if (plan.collisionReport.hasCollisions || plan.collisionReport.collisions.length > 0) {
    return { ok: false, diagnostics: [{ code: "COLLISION_DETECTED", severity: "error", message: "Migration plan contains collisions or unresolved mappings" }] };
  }
  for (const source of plan.sourceManifest) {
    const check = validateTransactionPath(source.path, transactionRoot);
    if (!check.ok) return { ok: false, diagnostics: [{ code: "OUTPUT_WRITE_FAILED", severity: "error", message: check.reason }] };
    const fullPath = resolve(transactionRoot, source.path);
    if (!existsSync(fullPath) || computeContentHash(readFileSync(fullPath).toString("base64")) !== source.digest) {
      return { ok: false, diagnostics: [{ code: "SNAPSHOT_TAMPERED", severity: "error", message: `Migration source drift: ${source.path}` }] };
    }
  }
  for (const filePath of Object.keys(plan.targetFiles)) {
    const check = validateTransactionPath(filePath, transactionRoot);
    if (!check.ok) return { ok: false, diagnostics: [{ code: "OUTPUT_WRITE_FAILED", severity: "error", message: check.reason }] };
  }
  let snapshot;
  const writtenPaths = [];
  try {
    snapshot = generateMigrationSnapshot(plan, transactionRoot, timestamp);
    for (const [filePath, content] of Object.entries(plan.targetFiles)) {
      const fullPath = resolve(transactionRoot, filePath);
      mkdirSync(dirname(fullPath), { recursive: true });
      const tempPath = resolve(dirname(fullPath), `.${basename(fullPath)}.migration-${process.pid}`);
      writeFileSync(tempPath, JSON.stringify(content, null, 2) + "\n", "utf-8");
      renameSync(tempPath, fullPath);
      writtenPaths.push(filePath);
    }
  } catch (error) {
    if (snapshot) restoreSnapshotPaths(snapshot, transactionRoot, writtenPaths);
    return { ok: false, diagnostics: [{ code: "OUTPUT_WRITE_FAILED", severity: "error", message: error instanceof Error ? error.message : String(error) }] };
  }
  return { ok: true, snapshot, diagnostics: [] };
}
function rollbackMigration(snapshot, transactionRoot) {
  const recomputed = computeContentHash({
    planDigest: snapshot.planDigest,
    originalBytes: snapshot.originalBytes,
    appliedDigests: snapshot.appliedDigests,
    timestamp: snapshot.timestamp
  });
  if (recomputed !== snapshot.snapshotDigest) {
    return { ok: false, restoredPaths: [], diagnostics: [{ code: "SNAPSHOT_TAMPERED", severity: "error", message: "Snapshot digest mismatch" }] };
  }
  for (const [filePath, expectedDigest] of Object.entries(snapshot.appliedDigests)) {
    const check = validateTransactionPath(filePath, transactionRoot);
    if (!check.ok) return { ok: false, restoredPaths: [], diagnostics: [{ code: "OUTPUT_WRITE_FAILED", severity: "error", message: check.reason }] };
    const fullPath = resolve(transactionRoot, filePath);
    if (!existsSync(fullPath)) {
      return { ok: false, restoredPaths: [], diagnostics: [{ code: "SNAPSHOT_TAMPERED", severity: "error", message: `Rollback target drift: ${filePath} no longer exists` }] };
    }
    const actualDigest = computeContentHash(readFileSync(fullPath).toString("base64"));
    if (actualDigest !== expectedDigest) {
      return { ok: false, restoredPaths: [], diagnostics: [{ code: "SNAPSHOT_TAMPERED", severity: "error", message: `Rollback target drift: ${filePath} changed after migration apply` }] };
    }
  }
  const restoredPaths = restoreSnapshotPaths(snapshot, transactionRoot, Object.keys(snapshot.originalBytes));
  return { ok: true, restoredPaths, diagnostics: [] };
}
function restoreSnapshotPaths(snapshot, transactionRoot, paths) {
  const restoredPaths = [];
  for (const filePath of paths) {
    const base64Content = snapshot.originalBytes[filePath];
    if (base64Content === void 0) continue;
    const fullPath = resolve(transactionRoot, filePath);
    if (base64Content === "__NOT_EXISTS__") {
      if (existsSync(fullPath)) unlinkSync(fullPath);
    } else {
      mkdirSync(dirname(fullPath), { recursive: true });
      writeFileSync(fullPath, Buffer.from(base64Content, "base64"));
    }
    restoredPaths.push(filePath);
  }
  return restoredPaths;
}

// src/cli.ts
function parseArgs(argv) {
  const args = argv.slice(2);
  const positional = [];
  const flags = {};
  let command;
  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const flagName = arg.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
        const value = args[i + 1];
        if (!flags[flagName]) flags[flagName] = [];
        flags[flagName].push(value);
        i += 2;
      } else {
        if (!flags[flagName]) flags[flagName] = [];
        flags[flagName].push("");
        i += 1;
      }
    } else {
      positional.push(arg);
      i += 1;
    }
  }
  command = positional[0];
  return { command, positional, flags };
}
function hasFlag(parsed, name) {
  return name in parsed.flags;
}
function getFlag(parsed, name) {
  return parsed.flags[name]?.[0];
}
function getAllFlags(parsed, name) {
  return parsed.flags[name] ?? [];
}
var ExitError = class extends Error {
  constructor(exitCode) {
    super(`process.exit(${exitCode})`);
    this.exitCode = exitCode;
    this.name = "ExitError";
  }
  exitCode;
};
function emit(envelope, exitCode) {
  process.stdout.write(JSON.stringify(envelope) + "\n");
  process.exit(exitCode);
  throw new ExitError(exitCode);
}
function readInput(filePath) {
  let raw;
  try {
    raw = readFileSync2(filePath, "utf-8");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      diagnostics: [
        {
          code: "INPUT_READ_FAILED",
          severity: "error",
          message: `Failed to read ${filePath}: ${message}`
        }
      ]
    };
  }
  try {
    const isYaml = filePath.endsWith(".yaml") || filePath.endsWith(".yml");
    const data = isYaml ? yamlParse(raw) : JSON.parse(raw);
    return { ok: true, data };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      diagnostics: [
        {
          code: "INPUT_READ_FAILED",
          severity: "error",
          message: `Failed to parse ${filePath}: ${message}`
        }
      ]
    };
  }
}
function writeOutput(filePath, data) {
  try {
    writeFileSync2(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
    return { ok: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      diagnostics: [
        {
          code: "OUTPUT_WRITE_FAILED",
          severity: "error",
          message: `Failed to write ${filePath}: ${message}`
        }
      ]
    };
  }
}
function usageError(message) {
  emit(
    { ok: false, diagnostics: [{ code: "CLI_USAGE_ERROR", severity: "error", message }] },
    2
  );
}
function requireFlag(parsed, name) {
  if (!hasFlag(parsed, name)) {
    usageError(`Missing required --${name} flag`);
  }
  const values = getAllFlags(parsed, name);
  if (values.length > 1) {
    usageError(`Duplicate --${name} flag`);
  }
  if (values[0] === "") {
    usageError(`--${name} requires a value`);
  }
  return values[0];
}
function optionalSingleton(parsed, name) {
  if (!hasFlag(parsed, name)) return void 0;
  const values = getAllFlags(parsed, name);
  if (values.length > 1) {
    usageError(`Duplicate --${name} flag`);
  }
  if (values[0] === "") {
    usageError(`--${name} requires a value`);
  }
  return values[0];
}
var QUERY_ALLOWED_FLAGS = /* @__PURE__ */ new Set([
  "index",
  "candidate",
  "domain",
  "artifact-type",
  "intent",
  "kind",
  "limit",
  "format"
]);
var RESOLVE_ALLOWED_FLAGS = /* @__PURE__ */ new Set([
  "index",
  "ref",
  "host",
  "plugin-root",
  "project-root"
]);
function rejectUnknownFlags(parsed, allowed) {
  for (const flag of Object.keys(parsed.flags)) {
    if (!allowed.has(flag)) {
      usageError(`Unknown flag: --${flag}`);
    }
  }
}
function rejectExtraPositionals(parsed, maxPositionals) {
  if (parsed.positional.length > maxPositionals) {
    usageError(`Unexpected argument: ${parsed.positional[maxPositionals]}`);
  }
}
function requireNonEmptyRepeated(parsed, name) {
  const values = getAllFlags(parsed, name);
  for (const v of values) {
    if (v === "") {
      usageError(`--${name} requires a value`);
    }
  }
  return values;
}
function stripHashPrefix(hash) {
  const idx = hash.indexOf(":");
  return idx >= 0 ? hash.slice(idx + 1) : hash;
}
function cmdValidate(parsed) {
  const catalogPaths = requireNonEmptyRepeated(parsed, "catalog");
  if (catalogPaths.length === 0) {
    emit(
      {
        ok: false,
        diagnostics: [
          {
            code: "CLI_USAGE_ERROR",
            severity: "error",
            message: "validate requires at least one --catalog <file>"
          }
        ]
      },
      2
    );
  }
  const allDiagnostics = [];
  for (const catalogPath of catalogPaths) {
    const input = readInput(catalogPath);
    if (!input.ok) {
      allDiagnostics.push(...input.diagnostics);
      continue;
    }
    const result = validateCatalog(input.data);
    if (!result.ok) {
      allDiagnostics.push(...result.diagnostics);
    }
  }
  if (hasFlag(parsed, "project")) {
    const projectPath = getFlag(parsed, "project");
    const input = readInput(projectPath);
    if (!input.ok) {
      allDiagnostics.push(...input.diagnostics);
    } else {
      const result = validateProjectOverlay(input.data);
      if (!result.ok) {
        allDiagnostics.push(...result.diagnostics);
      }
    }
  }
  if (allDiagnostics.length > 0) {
    emit({ ok: false, diagnostics: allDiagnostics }, 1);
  }
  emit({ ok: true, data: null, diagnostics: [] }, 0);
}
function cmdIndex(parsed) {
  const catalogPaths = requireNonEmptyRepeated(parsed, "catalog");
  if (catalogPaths.length === 0) {
    emit(
      {
        ok: false,
        diagnostics: [
          {
            code: "CLI_USAGE_ERROR",
            severity: "error",
            message: "index requires at least one --catalog <file>"
          }
        ]
      },
      2
    );
  }
  const catalogDatas = [];
  const readDiagnostics = [];
  for (const catalogPath of catalogPaths) {
    const input = readInput(catalogPath);
    if (!input.ok) {
      readDiagnostics.push(...input.diagnostics);
    } else {
      catalogDatas.push(input.data);
    }
  }
  if (readDiagnostics.length > 0) {
    emit({ ok: false, diagnostics: readDiagnostics }, 1);
  }
  let projectData;
  if (hasFlag(parsed, "project")) {
    const projectPath = getFlag(parsed, "project");
    const input = readInput(projectPath);
    if (!input.ok) {
      emit({ ok: false, diagnostics: input.diagnostics }, 1);
    }
    projectData = input.ok ? input.data : void 0;
  }
  const result = buildEffectiveIndex({
    catalogs: catalogDatas,
    project: projectData
  });
  if (!result.ok) {
    emit({ ok: false, diagnostics: result.diagnostics }, 1);
  }
  if (hasFlag(parsed, "out")) {
    const outPath = getFlag(parsed, "out");
    const writeResult = writeOutput(outPath, result.index);
    if (!writeResult.ok) {
      emit({ ok: false, diagnostics: writeResult.diagnostics }, 1);
    }
  }
  emit({ ok: true, data: result.index, diagnostics: [] }, 0);
}
var V1_FILTER_FLAGS = ["domain", "artifact-type", "intent", "kind", "limit", "format"];
function cmdQuery(parsed) {
  rejectUnknownFlags(parsed, QUERY_ALLOWED_FLAGS);
  rejectExtraPositionals(parsed, 1);
  const indexPath = requireFlag(parsed, "index");
  const candidatePath = optionalSingleton(parsed, "candidate");
  if (candidatePath !== void 0) {
    const conflicts = V1_FILTER_FLAGS.filter((f) => hasFlag(parsed, f));
    if (conflicts.length > 0) {
      usageError(
        `--candidate conflicts with v1 filter flags: ${conflicts.map((f) => `--${f}`).join(", ")}. v2 candidate queries derive intent, kind and filters from the candidate file.`
      );
    }
  }
  const domain = optionalSingleton(parsed, "domain");
  const artifactType = optionalSingleton(parsed, "artifact-type");
  const intent = optionalSingleton(parsed, "intent");
  const kindStr = optionalSingleton(parsed, "kind");
  const limitStr = optionalSingleton(parsed, "limit");
  const formatStr = optionalSingleton(parsed, "format");
  if (kindStr !== void 0 && kindStr !== "workflow" && kindStr !== "operation") {
    usageError(`Invalid --kind value: ${JSON.stringify(kindStr)}. Must be 'workflow' or 'operation'`);
  }
  const kind = kindStr;
  if (formatStr !== void 0 && formatStr !== "compact" && formatStr !== "full") {
    usageError(`Invalid --format value: ${JSON.stringify(formatStr)}. Must be 'compact' or 'full'`);
  }
  const format = formatStr;
  let limit;
  if (limitStr !== void 0) {
    const parsed_limit = Number(limitStr);
    if (!Number.isInteger(parsed_limit) || parsed_limit < 1 || parsed_limit > 8) {
      usageError(`Invalid --limit value: ${JSON.stringify(limitStr)}. Must be an integer between 1 and 8`);
    }
    limit = parsed_limit;
  }
  const input = readInput(indexPath);
  if (!input.ok) {
    emit({ ok: false, diagnostics: input.diagnostics }, 1);
  }
  let methodQueryCandidate;
  if (candidatePath !== void 0) {
    const candidateInput = readInput(candidatePath);
    if (!candidateInput.ok) emit({ ok: false, diagnostics: candidateInput.diagnostics }, 1);
    methodQueryCandidate = candidateInput.data;
  }
  const filters = {
    ...domain !== void 0 ? { domain } : {},
    ...artifactType !== void 0 ? { artifactType } : {},
    ...intent !== void 0 ? { intent } : {},
    ...kind !== void 0 ? { kind } : {},
    ...limit !== void 0 ? { limit } : {},
    ...format !== void 0 ? { format } : {}
  };
  const rawIndex = input.data;
  let result;
  if ("documentKind" in rawIndex && rawIndex.documentKind === "v2-projection") {
    result = queryEffectiveIndex({
      index: rawIndex,
      purpose: "recommendation",
      methodQueryCandidate,
      ...filters
    });
  } else {
    result = queryEffectiveIndex({ index: rawIndex, ...filters });
  }
  if (!result.ok) {
    emit({ ok: false, diagnostics: result.diagnostics }, 1);
  }
  const hasOnlyInfoDiagnostics = result.diagnostics.every((d) => d.severity === "info");
  emit(
    { ok: true, data: result.data ?? null, diagnostics: result.diagnostics },
    hasOnlyInfoDiagnostics ? 0 : 1
  );
}
function cmdResolve(parsed) {
  rejectUnknownFlags(parsed, RESOLVE_ALLOWED_FLAGS);
  rejectExtraPositionals(parsed, 1);
  const indexPath = requireFlag(parsed, "index");
  const ref = requireFlag(parsed, "ref");
  const hostStr = requireFlag(parsed, "host");
  if (hostStr !== "claude-code" && hostStr !== "codex") {
    usageError(`Invalid --host value: ${JSON.stringify(hostStr)}. Must be 'claude-code' or 'codex'`);
  }
  const host = hostStr;
  const pluginRootValues = requireNonEmptyRepeated(parsed, "plugin-root");
  const projectRootValues = requireNonEmptyRepeated(parsed, "project-root");
  const input = readInput(indexPath);
  if (!input.ok) {
    emit({ ok: false, diagnostics: input.diagnostics }, 1);
  }
  const index = input.data;
  const indexValidation = validateEffectiveIndex(index);
  if (!indexValidation.ok) {
    emit({ ok: false, diagnostics: indexValidation.diagnostics }, 1);
  }
  const entry = index.entries.find((e) => e.ref === ref);
  if (!entry) {
    const disabled = index.disabledEntries?.find((e) => e.ref === ref);
    if (disabled) {
      emit({
        ok: false,
        diagnostics: [{
          code: "ENTRY_DISABLED",
          severity: "error",
          message: `Entry "${ref}" is disabled by ${disabled.disabledBy}`,
          source: { label: "<external>" }
        }]
      }, 1);
    }
    emit({
      ok: false,
      diagnostics: [{
        code: "ENTRY_NOT_FOUND",
        severity: "error",
        message: `Entry "${ref}" not found in effective index`,
        source: { label: "<external>" }
      }]
    }, 1);
  }
  let pluginRoots;
  if (pluginRootValues.length > 0 && entry.provider.scope === "plugin") {
    pluginRoots = { [entry.provider.plugin]: pluginRootValues };
  }
  const projectRoots = projectRootValues.length > 0 ? projectRootValues : void 0;
  const result = resolveEntry({
    index,
    ref,
    host,
    ...pluginRoots !== void 0 ? { pluginRoots } : {},
    ...projectRoots !== void 0 ? { projectRoots } : {},
    strictProvider: true
  });
  if (!result.ok) {
    emit({ ok: false, diagnostics: result.diagnostics }, 1);
  }
  const verification = {
    status: result.data.verification?.status ?? "unverified",
    host,
    diagnostics: result.data.verification?.diagnostics ?? []
  };
  const indexInputs = index.inputs;
  const catalogsHashes = {};
  for (const cat of indexInputs.catalogs) {
    catalogsHashes[cat.id] = stripHashPrefix(cat.contentHash);
  }
  const indexContentHashes = {
    catalogs: catalogsHashes,
    project: stripHashPrefix(indexInputs.projectContentHash)
  };
  emit(
    {
      ok: true,
      data: {
        entry: result.data.entry,
        verification,
        index_content_hashes: indexContentHashes
      },
      diagnostics: result.diagnostics
    },
    0
  );
}
var MIGRATE_ALLOWED_FLAGS = /* @__PURE__ */ new Set([
  "catalog",
  "project",
  "dry-run",
  "apply",
  "plan",
  "rollback",
  "snapshot",
  "out-plan",
  "out-snapshot",
  "transaction-root",
  "migration-context"
]);
function cmdMigrate(parsed) {
  rejectUnknownFlags(parsed, MIGRATE_ALLOWED_FLAGS);
  rejectExtraPositionals(parsed, 1);
  const isDryRun = hasFlag(parsed, "dry-run");
  const isApply = hasFlag(parsed, "apply");
  const isRollback = hasFlag(parsed, "rollback");
  const modeCount = [isDryRun, isApply, isRollback].filter(Boolean).length;
  if (modeCount === 0) {
    usageError("migrate requires one of: --dry-run, --apply, --rollback");
  }
  if (modeCount > 1) {
    usageError("migrate accepts only one of: --dry-run, --apply, --rollback");
  }
  const transactionRoot = optionalSingleton(parsed, "transaction-root") ? resolve2(optionalSingleton(parsed, "transaction-root")) : process.cwd();
  if (isDryRun) {
    cmdMigrateDryRun(parsed, transactionRoot);
  } else if (isApply) {
    cmdMigrateApply(parsed, transactionRoot);
  } else {
    cmdMigrateRollback(parsed, transactionRoot);
  }
}
function cmdMigrateDryRun(parsed, transactionRoot) {
  const catalogPaths = requireNonEmptyRepeated(parsed, "catalog");
  if (catalogPaths.length === 0) {
    usageError("migrate --dry-run requires at least one --catalog <file>");
  }
  const outPlanPath = optionalSingleton(parsed, "out-plan");
  const contextPath = requireFlag(parsed, "migration-context");
  const catalogDatas = [];
  const readDiags = [];
  for (const path of catalogPaths) {
    const input = readInput(path);
    if (!input.ok) {
      readDiags.push(...input.diagnostics);
    } else {
      catalogDatas.push(input.data);
    }
  }
  if (readDiags.length > 0) {
    emit({ ok: false, diagnostics: readDiags }, 1);
  }
  const v1Entries = [];
  const v1Overrides = [];
  for (const raw of catalogDatas) {
    const data = raw;
    const entries = data.entries;
    if (entries) {
      for (const entry of entries) {
        v1Entries.push({
          ref: entry.ref,
          provider: entry.provider,
          kind: entry.kind,
          summary: entry.summary
        });
      }
    }
  }
  const contextInput = readInput(contextPath);
  if (!contextInput.ok) emit({ ok: false, diagnostics: contextInput.diagnostics }, 1);
  const rawContext = contextInput.data;
  if (!rawContext || !Array.isArray(rawContext.mappings)) {
    emit({ ok: false, diagnostics: [{ code: "INVALID_MIGRATION_PLAN", severity: "error", message: "migration context requires mappings[]" }] }, 1);
  }
  if (hasFlag(parsed, "project")) {
    const projectPath = getFlag(parsed, "project");
    const input = readInput(projectPath);
    if (input.ok) {
      const overlay = input.data;
      const overrides = overlay.overrides;
      if (overrides) {
        for (const [ref, override] of Object.entries(overrides)) {
          v1Overrides.push({
            ref,
            provider: override.provider
          });
        }
      }
    }
  }
  const sourcePaths = [...catalogPaths];
  if (hasFlag(parsed, "project")) sourcePaths.push(getFlag(parsed, "project"));
  sourcePaths.push(contextPath);
  const sourceManifest = sourcePaths.map((sourcePath) => {
    const absolute = resolve2(sourcePath);
    const rel = relative2(resolve2(transactionRoot), absolute);
    if (rel.startsWith("..") || isAbsolute2(rel)) {
      emit({ ok: false, diagnostics: [{ code: "OUTPUT_WRITE_FAILED", severity: "error", message: `Migration source is outside transaction root: ${sourcePath}` }] }, 1);
    }
    return { path: rel, digest: computeContentHash(readFileSync2(absolute).toString("base64")) };
  });
  const plan = generateMigrationPlan(v1Entries, v1Overrides, {
    mappings: rawContext.mappings,
    sourceManifest
  });
  const diagnostics = [];
  if (plan.collisionReport.hasCollisions) {
    for (const collision of plan.collisionReport.collisions) {
      diagnostics.push({
        code: "COLLISION_DETECTED",
        severity: "warn",
        message: `[${collision.type}] ${collision.details}`,
        source: { label: "<project>" }
      });
    }
  }
  if (outPlanPath) {
    const resolvedPath = resolve2(transactionRoot, outPlanPath);
    const dirCheck = validateTransactionPath(outPlanPath, transactionRoot);
    if (!dirCheck.ok) {
      emit({ ok: false, diagnostics: [{ code: "OUTPUT_WRITE_FAILED", severity: "error", message: dirCheck.reason }] }, 1);
    }
    const dir = dirname2(resolvedPath);
    if (!existsSync2(dir)) {
      mkdirSync2(dir, { recursive: true });
    }
    writeFileSync2(resolvedPath, JSON.stringify(plan, null, 2) + "\n", "utf-8");
  }
  emit({
    ok: true,
    data: {
      plan,
      effectiveIndexHash: computeContentHash(plan),
      collisionCount: plan.collisionReport.collisions.length
    },
    diagnostics
  }, 0);
}
function cmdMigrateApply(parsed, transactionRoot) {
  const planPath = requireFlag(parsed, "plan");
  const snapshotPath = optionalSingleton(parsed, "out-snapshot") ?? "migration-snapshot.json";
  const snapshotCheck = validateTransactionPath(snapshotPath, transactionRoot);
  if (!snapshotCheck.ok) emit({ ok: false, diagnostics: [{ code: "OUTPUT_WRITE_FAILED", severity: "error", message: snapshotCheck.reason }] }, 1);
  const planInput = readInput(planPath);
  if (!planInput.ok) {
    emit({ ok: false, diagnostics: planInput.diagnostics }, 1);
  }
  const plan = planInput.data;
  const collisionReport = plan.collisionReport;
  if (collisionReport.hasCollisions && collisionReport.collisions.length > 0) {
    emit({
      ok: false,
      diagnostics: collisionReport.collisions.map((c) => ({
        code: "COLLISION_DETECTED",
        severity: "error",
        message: `[${c.type}] ${c.details}`,
        source: { label: "<project>" }
      }))
    }, 1);
  }
  const result = applyMigrationPlan(
    plan,
    transactionRoot,
    (/* @__PURE__ */ new Date()).toISOString()
  );
  if (!result.ok) {
    emit({ ok: false, diagnostics: result.diagnostics }, 1);
  }
  const resolvedSnapshot = resolve2(transactionRoot, snapshotPath);
  const snapDir = dirname2(resolvedSnapshot);
  if (!existsSync2(snapDir)) {
    mkdirSync2(snapDir, { recursive: true });
  }
  writeFileSync2(resolvedSnapshot, JSON.stringify(result.snapshot, null, 2) + "\n", "utf-8");
  emit({
    ok: true,
    data: {
      snapshot: result.snapshot,
      appliedFiles: Object.keys(plan.targetFiles),
      snapshotPath: resolvedSnapshot
    },
    diagnostics: []
  }, 0);
}
function cmdMigrateRollback(parsed, transactionRoot) {
  const snapshotPath = requireFlag(parsed, "snapshot");
  const snapshotInput = readInput(snapshotPath);
  if (!snapshotInput.ok) {
    emit({ ok: false, diagnostics: snapshotInput.diagnostics }, 1);
  }
  const snapshot = snapshotInput.data;
  const result = rollbackMigration(snapshot, transactionRoot);
  if (!result.ok) {
    emit({ ok: false, diagnostics: result.diagnostics }, 1);
  }
  emit({
    ok: true,
    data: {
      restoredPaths: result.restoredPaths
    },
    diagnostics: []
  }, 0);
}
function run(argv) {
  const parsed = parseArgs(argv);
  switch (parsed.command) {
    case "validate":
      cmdValidate(parsed);
      break;
    case "index":
      cmdIndex(parsed);
      break;
    case "query":
      cmdQuery(parsed);
      break;
    case "resolve":
      cmdResolve(parsed);
      break;
    case "migrate":
      cmdMigrate(parsed);
      break;
    default:
      emit(
        {
          ok: false,
          diagnostics: [
            {
              code: "CLI_USAGE_ERROR",
              severity: "error",
              message: parsed.command ? `Unknown command: ${parsed.command}` : "No command specified. Use: validate | index | query | resolve | migrate"
            }
          ]
        },
        2
      );
  }
}

export {
  parseArgs,
  hasFlag,
  getFlag,
  getAllFlags,
  ExitError,
  emit,
  readInput,
  writeOutput,
  run
};
