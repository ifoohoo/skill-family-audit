import {
  buildEffectiveIndex,
  computeContentHash,
  queryEffectiveIndex,
  resolveEntry,
  validateBinding,
  validateCatalog,
  validateImplementationDescriptor,
  validateInventory,
  validateMigrationPlan,
  validateProjectOverlay,
  validateProjection,
  validateRunLock,
  verifyProvider
} from "./chunk-VJKMVB7M.js";

// src/errors/codes.ts
var ERROR_CODES = [
  "SCHEMA_VERSION_UNSUPPORTED",
  "INVALID_CATALOG",
  "INVALID_PROJECT_OVERLAY",
  "INVALID_EFFECTIVE_INDEX",
  "INVALID_DIAGNOSTIC_ENVELOPE",
  "DUPLICATE_CATALOG_ID",
  "DUPLICATE_DEFAULT_PROVIDER",
  "DUPLICATE_PROJECT_ENTRY",
  "UNKNOWN_OVERRIDE_REF",
  "INVALID_OVERRIDE_TARGET",
  "INVALID_OVERRIDE_PROVIDER",
  "UNKNOWN_DISABLED_REF",
  "PROVIDER_NOT_FOUND",
  "AMBIGUOUS_PROVIDER",
  "PROVIDER_UNVERIFIED",
  "HOST_REQUIRED",
  "ENTRY_DISABLED",
  "ENTRY_NOT_FOUND",
  "NO_QUERY_MATCH",
  "AMBIGUOUS_QUERY_MATCH",
  "INVALID_QUERY",
  "INPUT_READ_FAILED",
  "OUTPUT_WRITE_FAILED",
  "STALE_EFFECTIVE_INDEX",
  "CLI_USAGE_ERROR",
  // v2 error codes
  "INVALID_IMPLEMENTATION_DESCRIPTOR",
  "INVALID_INVENTORY",
  "INVALID_BINDING",
  "INVALID_PROJECTION",
  "INVALID_RUN_LOCK",
  "INVALID_MIGRATION_PLAN",
  "INVALID_METHOD_QUERY",
  "PROVIDER_REJECTED",
  "BUNDLE_DIGEST_MISMATCH",
  "LOCK_INCONSISTENCY",
  "RESOLUTION_NONE",
  "RESOLUTION_AMBIGUOUS",
  "SIDE_EFFECT_UNAUTHORIZED",
  "SIDE_EFFECT_BUDGET_EXCEEDED",
  "BINDING_INVALID",
  "COLLISION_DETECTED",
  "SNAPSHOT_MISSING",
  "SNAPSHOT_TAMPERED",
  "MIGRATION_PLAN_DRIFT",
  "DOCUMENT_KIND_MISMATCH",
  "MUTUALLY_EXCLUSIVE_INPUTS",
  "INVALID_INVENTORY_ENTRY",
  "DUPLICATE_INVENTORY_ENTRY",
  "CONFLICTING_INVENTORY_ENTRY",
  "HOST_MISMATCH",
  "NOT_EXECUTABLE"
];

// src/doctor/checks.ts
function makeDiagnostic(code, severity, message) {
  return { code, severity, message };
}
function runSchemaCheck(input) {
  const diags = [];
  let target;
  for (const raw of input.catalogs) {
    const result = validateCatalog(raw);
    if (!result.ok) {
      diags.push(...result.diagnostics);
      const rawObj = raw;
      const catalog = rawObj?.catalog;
      if (typeof catalog?.id === "string") {
        target = catalog.id;
      }
    }
  }
  if (input.project !== void 0) {
    const result = validateProjectOverlay(input.project);
    if (!result.ok) {
      diags.push(...result.diagnostics);
    }
  }
  return {
    id: "schema",
    status: diags.length > 0 ? "fail" : "pass",
    diagnostics: diags,
    target
  };
}
function runMergeCheck(input, schemaPassed) {
  if (!schemaPassed) {
    return {
      id: "merge",
      status: "pass",
      // Will be overridden by overall ok=false from schema
      diagnostics: []
    };
  }
  const ids = /* @__PURE__ */ new Map();
  for (const raw of input.catalogs) {
    const rawObj = raw;
    const catalog = rawObj?.catalog;
    if (typeof catalog?.id === "string") {
      ids.set(catalog.id, (ids.get(catalog.id) ?? 0) + 1);
    }
  }
  const diags = [];
  for (const [id, count] of ids) {
    if (count > 1) {
      diags.push(makeDiagnostic("DUPLICATE_CATALOG_ID", "error", `Duplicate catalog id: ${id}`));
    }
  }
  return {
    id: "merge",
    status: diags.length > 0 ? "fail" : "pass",
    diagnostics: diags
  };
}
function runFreshnessCheck(input, schemaPassed) {
  if (!schemaPassed || !input.existingIndex) {
    return {
      id: "freshness",
      status: "unverified",
      diagnostics: []
    };
  }
  const validatedCatalogs = [];
  for (const raw of input.catalogs) {
    const result = validateCatalog(raw);
    if (!result.ok) {
      return { id: "freshness", status: "unverified", diagnostics: [] };
    }
    validatedCatalogs.push(result.data);
  }
  let projectData;
  if (input.project !== void 0) {
    const result = validateProjectOverlay(input.project);
    if (!result.ok) {
      return { id: "freshness", status: "unverified", diagnostics: [] };
    }
    projectData = result.data;
  }
  const existingHashes = input.existingIndex.inputs;
  const diags = [];
  const currentCatalogInputs = validatedCatalogs.map((c) => ({ id: c.catalog.id, version: c.catalog.version, contentHash: computeContentHash(c) })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  if (currentCatalogInputs.length !== existingHashes.catalogs.length) {
    diags.push(makeDiagnostic("STALE_EFFECTIVE_INDEX", "error", "Catalog count mismatch"));
    return { id: "freshness", status: "fail", diagnostics: diags };
  }
  for (let i = 0; i < currentCatalogInputs.length; i++) {
    const current = currentCatalogInputs[i];
    const existing = existingHashes.catalogs[i];
    if (current.id !== existing.id || current.contentHash !== existing.contentHash) {
      diags.push(makeDiagnostic("STALE_EFFECTIVE_INDEX", "error", `Catalog ${current.id} content hash mismatch`));
    }
  }
  const currentProjectHash = projectData ? computeContentHash(projectData) : computeContentHash(null);
  if (currentProjectHash !== existingHashes.projectContentHash) {
    diags.push(makeDiagnostic("STALE_EFFECTIVE_INDEX", "error", "Project overlay content hash mismatch"));
  }
  return {
    id: "freshness",
    status: diags.length > 0 ? "fail" : "pass",
    diagnostics: diags
  };
}
function runProviderCheck(input, existingIndex) {
  if (!existingIndex || !input.host) {
    const hasRootsNoHost = !input.host && (input.pluginRoots && Object.keys(input.pluginRoots).length > 0 || input.projectRoots && input.projectRoots.length > 0 || input.strictProvider);
    if (hasRootsNoHost) {
      return {
        id: "provider",
        status: "fail",
        diagnostics: [makeDiagnostic("HOST_REQUIRED", "error", "host is required when roots or strictProvider are provided")]
      };
    }
    return {
      id: "provider",
      status: "unverified",
      diagnostics: []
    };
  }
  const hasRoots = input.pluginRoots && Object.keys(input.pluginRoots).length > 0 || input.projectRoots && input.projectRoots.length > 0;
  if (input.strictProvider && !hasRoots) {
    return {
      id: "provider",
      status: "fail",
      diagnostics: [makeDiagnostic(
        "PROVIDER_UNVERIFIED",
        "error",
        "strictProvider requires roots for all entries"
      )]
    };
  }
  if (!hasRoots) {
    return {
      id: "provider",
      status: "unverified",
      diagnostics: []
    };
  }
  const diags = [];
  let target;
  for (const entry of existingIndex.entries) {
    const result = verifyProvider({
      host: input.host,
      pluginRoots: input.pluginRoots,
      projectRoots: input.projectRoots,
      provider: entry.provider
    });
    if (result.status === "not-found") {
      diags.push(...result.diagnostics);
      target = entry.ref;
    } else if (result.status === "ambiguous") {
      diags.push(...result.diagnostics);
      target = entry.ref;
    } else if (result.status === "unverified" && input.strictProvider) {
      diags.push(makeDiagnostic(
        "PROVIDER_UNVERIFIED",
        "error",
        `Provider for "${entry.ref}" could not be verified`
      ));
      target = entry.ref;
    }
  }
  return {
    id: "provider",
    status: diags.length > 0 ? "fail" : "pass",
    diagnostics: diags,
    target
  };
}
function runV2SchemaCheck(input) {
  if (!input.v2) {
    return { id: "v2-schema", status: "unverified", diagnostics: [] };
  }
  const diags = [];
  let target;
  for (const raw of input.v2.implementations ?? []) {
    const result = validateImplementationDescriptor(raw);
    if (!result.ok) {
      diags.push(...result.diagnostics);
      target = "implementation";
    }
  }
  if (input.v2.inventory) {
    const result = validateInventory(input.v2.inventory);
    if (!result.ok) {
      diags.push(...result.diagnostics);
      target = "inventory";
    }
  }
  if (input.v2.bindings) {
    const result = validateBinding(input.v2.bindings);
    if (!result.ok) {
      diags.push(...result.diagnostics);
      target = "binding";
    }
  }
  if (input.v2.runLock) {
    const result = validateRunLock(input.v2.runLock);
    if (!result.ok) {
      diags.push(...result.diagnostics);
      target = "run-lock";
    }
  }
  if (input.v2.projection) {
    const result = validateProjection(input.v2.projection);
    if (!result.ok) {
      diags.push(...result.diagnostics);
      target = "projection";
    }
  }
  if (input.v2.migrationPlan) {
    const result = validateMigrationPlan(input.v2.migrationPlan);
    if (!result.ok) {
      diags.push(...result.diagnostics);
      target = "migration-plan";
    }
  }
  return {
    id: "v2-schema",
    status: diags.length > 0 ? "fail" : "pass",
    diagnostics: diags,
    target
  };
}
function runV2ProjectionCheck(input) {
  if (!input.v2?.projection) {
    return { id: "v2-projection", status: "unverified", diagnostics: [] };
  }
  const diags = [];
  const projection = input.v2.projection;
  const validation = validateProjection(projection);
  if (!validation.ok) diags.push(...validation.diagnostics);
  if (input.v2.familyApi && input.v2.implementations && input.v2.inventory) {
    const rebuilt = buildEffectiveIndex({
      familyApi: input.v2.familyApi,
      implementations: input.v2.implementations,
      inventory: input.v2.inventory,
      bindings: input.v2.bindings
    });
    if (!rebuilt.ok) {
      diags.push(...rebuilt.diagnostics);
    } else if (rebuilt.index.snapshotDigest !== projection.snapshotDigest) {
      diags.push(makeDiagnostic("INVALID_PROJECTION", "error", "Projection does not match a fresh rebuild from API/implementation/inventory/binding inputs"));
    }
  }
  if (input.v2.implementations && input.v2.implementations.length > 0) {
    const sortedImplementations = [...input.v2.implementations].sort(
      (a, b) => `${a.familyImplementationId}@${a.version}`.localeCompare(`${b.familyImplementationId}@${b.version}`)
    );
    const actualImplDigest = computeContentHash(sortedImplementations);
    if (projection.inputs.implementationDigest !== actualImplDigest) {
      diags.push({
        code: "INVALID_PROJECTION",
        severity: "error",
        message: `Projection implementationDigest drift: expected ${actualImplDigest}, got ${projection.inputs.implementationDigest}`,
        source: { label: "<index>" }
      });
    }
  }
  if (input.v2.runLock && input.v2.inventory) {
    const lock = input.v2.runLock;
    const inventory = input.v2.inventory;
    const inventoryEntry = inventory.entries.find(
      (entry) => entry.pluginId === lock.provider.pluginId && entry.version === lock.implementationVersion
    );
    if (!inventoryEntry) {
      diags.push(makeDiagnostic("LOCK_INCONSISTENCY", "error", "Run lock provider is missing from current inventory"));
    } else {
      const reverify = verifyProvider({
        host: inventoryEntry.host === "claude-code" ? "claude-code" : "codex",
        runLock: { ...lock, inventoryEntry }
      });
      if (reverify.status !== "verified") diags.push(...reverify.diagnostics);
    }
    if (lock.indexDigest !== projection.snapshotDigest) {
      diags.push(makeDiagnostic("LOCK_INCONSISTENCY", "error", "Run lock indexDigest does not match projection snapshotDigest"));
    }
  }
  return {
    id: "v2-projection",
    status: diags.length > 0 ? "fail" : "pass",
    diagnostics: diags
  };
}
function runV2SnapshotCheck(input) {
  if (!input.v2?.projection) {
    return { id: "v2-snapshot", status: "unverified", diagnostics: [] };
  }
  const diags = [];
  const projection = input.v2.projection;
  const expectedSnapshot = computeContentHash({ inputs: projection.inputs, entries: projection.entries });
  if (projection.snapshotDigest !== expectedSnapshot) {
    diags.push({
      code: "SNAPSHOT_TAMPERED",
      severity: "error",
      message: `Projection snapshotDigest mismatch: expected ${expectedSnapshot}`,
      source: { label: "<index>" }
    });
  }
  return {
    id: "v2-snapshot",
    status: diags.length > 0 ? "fail" : "pass",
    diagnostics: diags
  };
}
function diagnoseRegistry(input) {
  const checks = [];
  const schemaCheck = runSchemaCheck(input);
  checks.push(schemaCheck);
  const schemaPassed = schemaCheck.status === "pass";
  const mergeCheck = runMergeCheck(input, schemaPassed);
  checks.push(mergeCheck);
  const freshnessCheck = runFreshnessCheck(input, schemaPassed);
  checks.push(freshnessCheck);
  const providerCheck = runProviderCheck(input, schemaPassed ? input.existingIndex : void 0);
  checks.push(providerCheck);
  const v2SchemaCheck = runV2SchemaCheck(input);
  checks.push(v2SchemaCheck);
  const v2ProjectionCheck = runV2ProjectionCheck(input);
  checks.push(v2ProjectionCheck);
  const v2SnapshotCheck = runV2SnapshotCheck(input);
  checks.push(v2SnapshotCheck);
  const allDiagnostics = checks.flatMap((c) => c.diagnostics);
  const ok = !allDiagnostics.some((d) => d.severity === "error");
  return { ok, checks, diagnostics: allDiagnostics };
}
export {
  ERROR_CODES,
  buildEffectiveIndex,
  diagnoseRegistry,
  queryEffectiveIndex,
  resolveEntry,
  validateCatalog,
  validateProjectOverlay,
  verifyProvider
};
