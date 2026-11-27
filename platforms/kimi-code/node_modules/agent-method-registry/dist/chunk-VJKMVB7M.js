// src/canonicalize/content-hash.ts
import { createHash } from "crypto";

// protocol/canonical-json-v1.mjs
import { runInNewContext } from "vm";
import { types as utilTypes } from "util";
var primordials = runInNewContext(`({
  getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
  getPrototypeOf: Object.getPrototypeOf,
  ownKeys: Reflect.ownKeys,
  isArray: Array.isArray,
  isFinite: Number.isFinite,
  isInteger: Number.isInteger
})`);
var objectPrototype = primordials.getPrototypeOf({});
var arrayPrototype = primordials.getPrototypeOf([]);
var bannedPrototypes = /* @__PURE__ */ new Map([
  [Date.prototype, "Date"],
  [RegExp.prototype, "RegExp"],
  [Map.prototype, "Map"],
  [Set.prototype, "Set"],
  [WeakMap.prototype, "WeakMap"],
  [WeakSet.prototype, "WeakSet"],
  [Promise.prototype, "Promise"],
  [Error.prototype, "Error"]
]);
function nextAncestors(ancestors, value) {
  const next = new Array(ancestors.length + 1);
  for (let index = 0; index < ancestors.length; index += 1) next[index] = ancestors[index];
  next[ancestors.length] = value;
  return next;
}
function isArrayIndex(key, length) {
  if (key === "") return false;
  const numeric = Number(key);
  return primordials.isInteger(numeric) && numeric >= 0 && numeric < length && String(numeric) === key;
}
function cloneStrictJsonData(value, ancestors = []) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!primordials.isFinite(value)) throw new TypeError(`Canonical JSON rejects ${String(value)}`);
    return value;
  }
  if (typeof value !== "object") {
    const label = typeof value === "bigint" ? "BigInt" : typeof value === "symbol" ? "Symbol" : typeof value === "function" ? "function" : "undefined";
    throw new TypeError(`Canonical JSON rejects ${label}`);
  }
  if (utilTypes.isProxy(value)) throw new TypeError("Proxy value rejected");
  for (let index = 0; index < ancestors.length; index += 1) {
    if (ancestors[index] === value) throw new TypeError("circular reference rejected");
  }
  const isArray = primordials.isArray(value);
  const prototype = primordials.getPrototypeOf(value);
  if (prototype !== (isArray ? arrayPrototype : objectPrototype) && !(prototype === null && !isArray)) {
    const banned = bannedPrototypes.get(prototype);
    if (banned) throw new TypeError(`Canonical JSON rejects ${banned}`);
    throw new TypeError("custom prototype rejected");
  }
  const keys = primordials.ownKeys(value);
  for (const key of keys) {
    if (typeof key === "symbol") throw new TypeError("symbol-keyed property rejected");
  }
  const next = nextAncestors(ancestors, value);
  if (isArray) {
    const lengthDescriptor = primordials.getOwnPropertyDescriptor(value, "length");
    if (!lengthDescriptor || !("value" in lengthDescriptor) || !primordials.isInteger(lengthDescriptor.value)) {
      throw new TypeError("invalid array length rejected");
    }
    const length = lengthDescriptor.value;
    const output2 = new Array(length);
    for (let index = 0; index < length; index += 1) {
      const descriptor = primordials.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
        throw new TypeError("sparse array or accessor element rejected");
      }
      output2[index] = cloneStrictJsonData(descriptor.value, next);
    }
    for (const key of keys) {
      if (key !== "length" && !isArrayIndex(key, length)) {
        throw new TypeError("extra array property rejected");
      }
    }
    return output2;
  }
  const output = /* @__PURE__ */ Object.create(null);
  for (const key of keys) {
    const descriptor = primordials.getOwnPropertyDescriptor(value, key);
    if (!descriptor) throw new TypeError(`missing property descriptor "${key}" rejected`);
    if (!("value" in descriptor)) {
      throw new TypeError(`accessor property "${key}" rejected`);
    }
    if (descriptor.enumerable !== true) {
      throw new TypeError(`non-enumerable field "${key}" rejected`);
    }
    output[key] = cloneStrictJsonData(descriptor.value, next);
  }
  return output;
}
function sortObjectKeys(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortObjectKeys);
  const output = /* @__PURE__ */ Object.create(null);
  for (const key of Object.keys(value).sort()) output[key] = sortObjectKeys(value[key]);
  return output;
}
function canonicalizeJson(value) {
  return sortObjectKeys(cloneStrictJsonData(value));
}
function canonicalStringify(value) {
  return JSON.stringify(canonicalizeJson(value));
}

// src/canonicalize/content-hash.ts
function computeContentHash(data) {
  const canonical = canonicalStringify(data);
  const hash = createHash("sha256").update(canonical).digest("hex");
  return `sha256:${hash}`;
}

// src/validate/input.ts
import { createRequire } from "module";
import { readFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
var require2 = createRequire(import.meta.url);
var AjvConstructor = require2("ajv");
var addFormatsFn = require2("ajv-formats");
var __dirname = dirname(fileURLToPath(import.meta.url));
var SCHEMAS_DIR = (() => {
  const srcPath = resolve(__dirname, "../../schemas");
  if (existsSync(srcPath)) return srcPath;
  const distPath = resolve(__dirname, "../schemas");
  return distPath;
})();
var ajv = new AjvConstructor({ allErrors: true, strict: true });
addFormatsFn(ajv);
var schemaCache = /* @__PURE__ */ new Map();
function getValidator(schemaName) {
  const cached = schemaCache.get(schemaName);
  if (cached) return cached;
  const raw = readFileSync(resolve(SCHEMAS_DIR, `${schemaName}.schema.json`), "utf-8");
  const schema = JSON.parse(raw);
  const validator = ajv.compile(schema);
  schemaCache.set(schemaName, validator);
  return validator;
}
function validateAgainstSchema(schemaName, data, failureCode) {
  const validate = getValidator(schemaName);
  const valid = validate(data);
  if (valid) {
    return { valid: true, diagnostics: [], data };
  }
  const diagnostics = (validate.errors || []).map((err) => ({
    code: failureCode,
    severity: "error",
    message: `${err.instancePath || "/"} ${err.message || "validation failed"}`,
    source: {
      label: schemaName === "project" ? "<project>" : schemaName === "diagnostic-envelope" ? "<external>" : "<index>"
    }
  }));
  return { valid: false, diagnostics };
}

// src/v2/schema-validators.ts
import { isAbsolute, win32 } from "path";

// src/v2/identity.ts
function v2diag(code, message) {
  return { code, severity: "error", message, source: { label: "<index>" } };
}
function classifyApiRecognition(apiId) {
  if (apiId.startsWith("artifact.")) {
    return /^artifact\.[a-z][a-z0-9-]*-family$/.test(apiId) ? "STANDARD" : void 0;
  }
  if (apiId.startsWith("project.")) {
    return /^project\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*-family$/.test(apiId) ? "PROJECT" : void 0;
  }
  if (/^(?:[a-z][a-z0-9-]*\.){2,}[a-z][a-z0-9-]*-family$/.test(apiId)) return "THIRD_PARTY";
  return void 0;
}
function familyIdFromApiId(apiId) {
  const finalSegment = apiId.split(".").at(-1);
  return finalSegment?.endsWith("-family") ? finalSegment.slice(0, -"-family".length) : void 0;
}
function projectAuthorityFromApiId(apiId) {
  const match = apiId.match(/^project\.([a-z][a-z0-9-]*)\.[a-z][a-z0-9-]*-family$/);
  return match ? `project.${match[1]}` : void 0;
}
function validateServiceIdFamily(serviceId, apiId) {
  const recognition = classifyApiRecognition(apiId);
  if (!recognition) {
    return v2diag("INVALID_PROJECTION", `Cannot validate serviceId: apiId "${apiId}" is not a recognized family API`);
  }
  const canonicalPrefix = `${apiId.slice(0, -"-family".length)}.`;
  const compatiblePrefixes = [canonicalPrefix, `${apiId}.`];
  const matchesFamily = compatiblePrefixes.some((prefix) => {
    if (!serviceId.startsWith(prefix)) return false;
    return /^[a-z][a-z0-9-]*$/.test(serviceId.slice(prefix.length));
  });
  if (!matchesFamily) {
    return v2diag(
      "INVALID_PROJECTION",
      `${recognition} serviceId "${serviceId}" does not belong to family API "${apiId}" (expected prefix "${canonicalPrefix}")`
    );
  }
  if (recognition === "THIRD_PARTY") {
    if (serviceId.startsWith("artifact.") || serviceId.startsWith("project.")) {
      return v2diag(
        "INVALID_PROJECTION",
        `THIRD_PARTY serviceId "${serviceId}" must not use reserved "artifact" or "project" prefix`
      );
    }
  }
  return void 0;
}
function validateProjectAuthorityConsistency(projectAuthority, apiId, entityLabel) {
  const expectedAuthority = projectAuthorityFromApiId(apiId);
  if (!expectedAuthority) return void 0;
  if (projectAuthority !== expectedAuthority) {
    return v2diag(
      "INVALID_PROJECTION",
      `${entityLabel} projectAuthority "${projectAuthority ?? ""}" does not match API identity "${expectedAuthority}" for "${apiId}"`
    );
  }
  return void 0;
}

// src/v2/schema-validators.ts
function diag(code, message, pointer) {
  return {
    code,
    severity: "error",
    message,
    source: { label: "<index>", pointer }
  };
}
function checkImplementationNoApiSignature(data) {
  const diagnostics = [];
  const raw = data;
  const forbidden = ["accepts", "produces", "sideEffectCeiling", "mixSafe"];
  for (const key of forbidden) {
    if (key in raw) {
      diagnostics.push(
        diag(
          "INVALID_IMPLEMENTATION_DESCRIPTOR",
          `Implementation descriptor must not contain API signature field "${key}"`,
          `/${key}`
        )
      );
    }
  }
  return diagnostics;
}
function checkImplementationServiceKeys(data) {
  const diagnostics = [];
  for (const [serviceId, svc] of Object.entries(data.services)) {
    if (svc.skill.includes("..")) {
      diagnostics.push(
        diag(
          "INVALID_IMPLEMENTATION_DESCRIPTOR",
          `services.${serviceId}.skill must not contain ".."`,
          `/services/${serviceId}/skill`
        )
      );
    }
    if (svc.skill.startsWith("/")) {
      diagnostics.push(
        diag(
          "INVALID_IMPLEMENTATION_DESCRIPTOR",
          `services.${serviceId}.skill must be a relative path`,
          `/services/${serviceId}/skill`
        )
      );
    }
    if (!svc.serviceImplementationId.includes(".")) {
      diagnostics.push(
        diag(
          "INVALID_IMPLEMENTATION_DESCRIPTOR",
          `services.${serviceId}.serviceImplementationId must be a reverse-domain identifier`,
          `/services/${serviceId}/serviceImplementationId`
        )
      );
    }
  }
  return diagnostics;
}
function checkImplementationAuthority(data) {
  const isProject = data.lifecycle.ownership === "project-local";
  if (isProject && !data.projectAuthority) {
    return [diag("INVALID_IMPLEMENTATION_DESCRIPTOR", "Project implementation must declare projectAuthority", "/projectAuthority")];
  }
  if (!isProject && data.projectAuthority) {
    return [diag("INVALID_IMPLEMENTATION_DESCRIPTOR", "Only project implementations may declare projectAuthority", "/projectAuthority")];
  }
  return [];
}
function checkImplementationIdentity(data) {
  const diagnostics = [];
  for (const serviceId of Object.keys(data.services)) {
    const identityDiagnostic = validateServiceIdFamily(serviceId, data.implements.apiId);
    if (identityDiagnostic) {
      diagnostics.push(diag(
        "INVALID_IMPLEMENTATION_DESCRIPTOR",
        identityDiagnostic.message,
        `/services/${serviceId}`
      ));
    }
  }
  const authorityDiagnostic = validateProjectAuthorityConsistency(
    data.projectAuthority,
    data.implements.apiId,
    `Implementation ${data.familyImplementationId}@${data.version}`
  );
  if (authorityDiagnostic) {
    diagnostics.push(diag(
      "INVALID_IMPLEMENTATION_DESCRIPTOR",
      authorityDiagnostic.message,
      "/projectAuthority"
    ));
  }
  return diagnostics;
}
function validateImplementationDescriptor(data) {
  const schemaResult = validateAgainstSchema("implementation", data, "INVALID_IMPLEMENTATION_DESCRIPTOR");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const desc = schemaResult.data;
  const diagnostics = [];
  diagnostics.push(...checkImplementationNoApiSignature(desc));
  diagnostics.push(...checkImplementationServiceKeys(desc));
  diagnostics.push(...checkImplementationAuthority(desc));
  diagnostics.push(...checkImplementationIdentity(desc));
  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return { ok: true, data: desc, diagnostics: [] };
}
function checkInventoryPaths(data) {
  const diagnostics = [];
  for (let i = 0; i < data.entries.length; i++) {
    const entry = data.entries[i];
    if (!isAbsolute(entry.canonicalRoot) && !win32.isAbsolute(entry.canonicalRoot)) {
      diagnostics.push(
        diag(
          "INVALID_INVENTORY",
          `entries[${i}].canonicalRoot must be an absolute path`,
          `/entries/${i}/canonicalRoot`
        )
      );
    }
  }
  const sortedEntries = [...data.entries].sort(compareInventoryEntries);
  const expectedSnapshot = computeContentHash({ entries: sortedEntries });
  if (data.snapshotDigest !== expectedSnapshot) {
    diagnostics.push(diag("SNAPSHOT_TAMPERED", `Inventory snapshot digest mismatch: expected ${expectedSnapshot}`, "/snapshotDigest"));
  }
  return diagnostics;
}
function validateInventory(data) {
  const schemaResult = validateAgainstSchema("inventory", data, "INVALID_INVENTORY");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const inv = schemaResult.data;
  const deduplicatedEntries = [...new Map(
    inv.entries.map((entry) => [inventoryEntryKey(entry), entry])
  ).values()].sort(compareInventoryEntries);
  const normalized = { ...inv, entries: deduplicatedEntries };
  const diagnostics = [];
  diagnostics.push(...checkInventoryPaths(normalized));
  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return { ok: true, data: normalized, diagnostics: [] };
}
function inventoryEntryKey(entry) {
  return [
    entry.pluginId,
    entry.projectAuthority ?? "",
    entry.version,
    entry.canonicalRoot,
    entry.packageDigest,
    entry.provenance,
    entry.host
  ].join("\0");
}
function compareInventoryEntries(a, b) {
  return inventoryEntryKey(a).localeCompare(inventoryEntryKey(b));
}
function checkBindingSelectorPaths(data) {
  const diagnostics = [];
  const selectors = [
    ...data.bindings.map((binding, index) => ({ selector: binding.providerSelector, pointer: `/bindings/${index}` })),
    ...(data.serviceBindings ?? []).map((binding, index) => ({ selector: binding.providerSelector, pointer: `/serviceBindings/${index}` }))
  ];
  for (const { selector, pointer } of selectors) {
    const canonicalRoot = selector.canonicalRoot;
    if (!isAbsolute(canonicalRoot) || canonicalRoot.split(/[\\/]+/).includes("..")) {
      diagnostics.push(diag(
        "INVALID_BINDING",
        `${pointer}.providerSelector.canonicalRoot must be an absolute path without ".."`,
        `${pointer}/providerSelector/canonicalRoot`
      ));
    }
    if (!selector.host) {
      diagnostics.push(diag("INVALID_BINDING", `${pointer}.providerSelector.host is required for exact host binding`, `${pointer}/providerSelector/host`));
    }
    if (selector.scope === "project" && !selector.projectAuthority) {
      diagnostics.push(diag("INVALID_BINDING", `${pointer}.providerSelector.projectAuthority is required for project scope`, `${pointer}/providerSelector/projectAuthority`));
    }
    if (selector.scope === "plugin" && selector.projectAuthority) {
      diagnostics.push(diag("INVALID_BINDING", `${pointer}.providerSelector.projectAuthority is forbidden for plugin scope`, `${pointer}/providerSelector/projectAuthority`));
    }
  }
  return diagnostics;
}
function checkBindingIdentity(data) {
  const diagnostics = [];
  const bindings = [
    ...data.bindings.map((binding, index) => ({
      binding,
      pointer: `/bindings/${index}`,
      serviceId: void 0
    })),
    ...(data.serviceBindings ?? []).map((binding, index) => ({
      binding,
      pointer: `/serviceBindings/${index}`,
      serviceId: binding.serviceId
    }))
  ];
  for (const { binding, pointer, serviceId } of bindings) {
    const { apiId } = binding.apiIdentity;
    if (binding.familyId !== familyIdFromApiId(apiId)) {
      diagnostics.push(diag(
        "INVALID_BINDING",
        `${pointer}.familyId does not match API identity "${apiId}"`,
        `${pointer}/familyId`
      ));
    }
    if (serviceId) {
      const identityDiagnostic = validateServiceIdFamily(serviceId, apiId);
      if (identityDiagnostic) {
        diagnostics.push(diag(
          "INVALID_BINDING",
          identityDiagnostic.message,
          `${pointer}/serviceId`
        ));
      }
    }
    const authorityDiagnostic = validateProjectAuthorityConsistency(
      binding.providerSelector.projectAuthority,
      apiId,
      `${pointer}.providerSelector`
    );
    if (authorityDiagnostic) {
      diagnostics.push(diag(
        "INVALID_BINDING",
        authorityDiagnostic.message,
        `${pointer}/providerSelector/projectAuthority`
      ));
    }
  }
  return diagnostics;
}
function validateBinding(data) {
  const schemaResult = validateAgainstSchema("binding", data, "INVALID_BINDING");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const binding = schemaResult.data;
  const diagnostics = [];
  diagnostics.push(...checkBindingSelectorPaths(binding));
  diagnostics.push(...checkBindingIdentity(binding));
  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return { ok: true, data: binding, diagnostics: [] };
}
function validateProjection(data) {
  const schemaResult = validateAgainstSchema("projection", data, "INVALID_PROJECTION");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const projection = schemaResult.data;
  const diagnostics = [];
  const computedSnapshot = computeContentHash({ inputs: projection.inputs, entries: projection.entries });
  if (computedSnapshot !== projection.snapshotDigest) {
    diagnostics.push(diag("SNAPSHOT_TAMPERED", `Projection snapshot digest mismatch: expected ${computedSnapshot}`, "/snapshotDigest"));
  }
  for (let index = 0; index < projection.entries.length; index++) {
    const entry = projection.entries[index];
    const pointer = `/entries/${index}`;
    if (entry.apiId !== projection.inputs.familyApiId || entry.apiMajor !== projection.inputs.familyApiMajor || entry.apiRevisionDigest !== projection.inputs.apiRevisionDigest) {
      diagnostics.push(diag(
        "INVALID_PROJECTION",
        `Projection entry API identity does not match projection inputs for ${entry.serviceId}`,
        pointer
      ));
    }
    if (entry.ref !== entry.serviceId) {
      diagnostics.push(diag(
        "INVALID_PROJECTION",
        `Projection ref must equal serviceId for ${entry.serviceId}`,
        `${pointer}/ref`
      ));
    }
    const recognition = classifyApiRecognition(entry.apiId);
    if (!recognition || recognition !== entry.apiRecognition) {
      diagnostics.push(diag(
        "INVALID_PROJECTION",
        `apiRecognition ${entry.apiRecognition} does not match API identity "${entry.apiId}"`,
        `${pointer}/apiRecognition`
      ));
    }
    const serviceIdentityDiagnostic = validateServiceIdFamily(entry.serviceId, entry.apiId);
    if (serviceIdentityDiagnostic) {
      diagnostics.push(diag(
        "INVALID_PROJECTION",
        serviceIdentityDiagnostic.message,
        `${pointer}/serviceId`
      ));
    }
    for (const candidate of entry.candidates) {
      if (candidate.serviceId !== entry.serviceId || candidate.apiId !== entry.apiId || candidate.apiMajor !== entry.apiMajor || candidate.apiRevisionDigest !== entry.apiRevisionDigest) {
        diagnostics.push(diag("INVALID_PROJECTION", `Candidate identity does not match projection entry ${entry.serviceId}`, pointer));
      }
      if (candidate.installation === "INSTALLED" && !candidate.provider) {
        diagnostics.push(diag("INVALID_PROJECTION", `Installed candidate lacks provider evidence for ${entry.serviceId}`, pointer));
      }
      if (candidate.trust === "VERIFIED" && (!candidate.provider || !candidate.verificationAttestationDigest)) {
        diagnostics.push(diag("INVALID_PROJECTION", `VERIFIED candidate lacks verifier attestation for ${entry.serviceId}`, pointer));
      }
      if (candidate.provider?.scope === "project" && !candidate.provider.projectAuthority) {
        diagnostics.push(diag("INVALID_PROJECTION", `Project candidate lacks projectAuthority for ${entry.serviceId}`, pointer));
      }
      if (candidate.provider?.scope === "plugin" && candidate.provider.projectAuthority) {
        diagnostics.push(diag("INVALID_PROJECTION", `Plugin candidate must not declare projectAuthority for ${entry.serviceId}`, pointer));
      }
      if (candidate.provider) {
        const authorityDiagnostic = validateProjectAuthorityConsistency(
          candidate.provider.projectAuthority,
          candidate.apiId,
          `Candidate ${candidate.familyImplementationId}@${candidate.version}`
        );
        if (authorityDiagnostic) {
          diagnostics.push(diag(
            "INVALID_PROJECTION",
            authorityDiagnostic.message,
            `${pointer}/candidates`
          ));
        }
      }
    }
    const installed = entry.candidates.filter((candidate) => candidate.installation === "INSTALLED");
    const enabled = entry.candidates.filter((candidate) => candidate.enablement === "ENABLED");
    const verified = entry.candidates.filter((candidate) => candidate.trust === "VERIFIED");
    const eligibleEnabled = entry.candidates.filter(
      (candidate) => candidate.installation === "INSTALLED" && candidate.enablement === "ENABLED" && candidate.compatibility === "COMPATIBLE" && candidate.trust === "VERIFIED"
    );
    const eligibleInstalled = entry.candidates.filter(
      (candidate) => candidate.installation === "INSTALLED" && candidate.compatibility === "COMPATIBLE" && candidate.trust === "VERIFIED"
    );
    const expectedCompatibility = entry.candidates.length === 0 ? "UNKNOWN" : entry.candidates.some((candidate) => candidate.compatibility === "COMPATIBLE") ? "COMPATIBLE" : "INCOMPATIBLE";
    if ((installed.length > 0 ? "INSTALLED" : "NOT_INSTALLED") !== entry.installation || (enabled.length > 0 ? "ENABLED" : "NOT_ENABLED") !== entry.enablement || expectedCompatibility !== entry.compatibility || (verified.length > 0 ? "VERIFIED" : entry.candidates.some((candidate) => candidate.trust === "REJECTED") ? "REJECTED" : "UNVERIFIED") !== entry.trust) {
      diagnostics.push(diag("INVALID_PROJECTION", `Aggregate state does not match candidates for ${entry.serviceId}`, pointer));
    }
    const allowedResolutions = eligibleEnabled.length === 1 ? ["EXPLICIT_BINDING"] : eligibleEnabled.length > 1 ? ["AMBIGUOUS"] : eligibleInstalled.length === 0 ? ["NONE"] : eligibleInstalled.length === 1 ? ["UNIQUE_COMPATIBLE", "NONE"] : ["AMBIGUOUS", "NONE"];
    if (!allowedResolutions.includes(entry.resolution)) {
      diagnostics.push(diag("INVALID_PROJECTION", `Resolution ${entry.resolution} does not match candidates; expected one of ${allowedResolutions.join(", ")}`, pointer));
    }
    if (entry.selectedCandidateId !== void 0) {
      const selected = eligibleEnabled.filter((candidate) => computeContentHash({
        familyImplementationId: candidate.familyImplementationId,
        serviceImplementationId: candidate.serviceImplementationId,
        version: candidate.version,
        provider: candidate.provider ?? null
      }) === entry.selectedCandidateId);
      if (selected.length !== 1 || entry.resolution !== "EXPLICIT_BINDING") {
        diagnostics.push(diag("INVALID_PROJECTION", `selectedCandidateId is not a unique eligible candidate for ${entry.serviceId}`, pointer));
      }
    }
  }
  return diagnostics.length > 0 ? { ok: false, diagnostics } : { ok: true, data: projection, diagnostics: [] };
}
function validateRunLock(data) {
  const schemaResult = validateAgainstSchema("run-lock", data, "INVALID_RUN_LOCK");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const lock = schemaResult.data;
  const digestFields = [
    ["apiRevisionDigest", lock.apiRevisionDigest],
    ["provider.packageDigest", lock.provider.packageDigest],
    ["bundleDigest", lock.bundleDigest],
    ["artifactContractRevisionDigest", lock.artifactContractRevisionDigest],
    ["sourceDigest", lock.sourceDigest],
    ["bindingDigest", lock.bindingDigest],
    ["indexDigest", lock.indexDigest],
    ["queryDigest", lock.queryDigest],
    ["projectFactsEvidenceDigest", lock.projectFactsEvidenceDigest],
    ["conformanceAttestationDigest", lock.conformanceAttestationDigest]
  ];
  const zeroDigest = `sha256:${"0".repeat(64)}`;
  const diagnostics = digestFields.filter(([, digest]) => digest === zeroDigest).map(([field]) => diag("INVALID_RUN_LOCK", `Run method lock field ${field} must not use the all-zero placeholder digest`));
  if (lock.provider.scope === "project" && !lock.provider.projectAuthority) {
    diagnostics.push(diag("INVALID_RUN_LOCK", "Project run lock provider must declare projectAuthority", "/provider/projectAuthority"));
  }
  if (lock.provider.scope === "plugin" && lock.provider.projectAuthority) {
    diagnostics.push(diag("INVALID_RUN_LOCK", "Plugin run lock provider must not declare projectAuthority", "/provider/projectAuthority"));
  }
  const serviceIdentityDiagnostic = validateServiceIdFamily(lock.serviceId, lock.apiId);
  if (serviceIdentityDiagnostic) {
    diagnostics.push(diag(
      "INVALID_RUN_LOCK",
      serviceIdentityDiagnostic.message,
      "/serviceId"
    ));
  }
  const authorityDiagnostic = validateProjectAuthorityConsistency(
    lock.provider.projectAuthority,
    lock.apiId,
    "Run method lock provider"
  );
  if (authorityDiagnostic) {
    diagnostics.push(diag(
      "INVALID_RUN_LOCK",
      authorityDiagnostic.message,
      "/provider/projectAuthority"
    ));
  }
  return diagnostics.length > 0 ? { ok: false, diagnostics } : { ok: true, data: lock, diagnostics: [] };
}
function checkMigrationCollision(data) {
  const diagnostics = [];
  if (data.collisionReport.hasCollisions && data.collisionReport.collisions.length === 0) {
    diagnostics.push(
      diag(
        "INVALID_MIGRATION_PLAN",
        "collisionReport.hasCollisions is true but collisions array is empty",
        "/collisionReport/hasCollisions"
      )
    );
  }
  return diagnostics;
}
function validateMigrationPlan(data) {
  const schemaResult = validateAgainstSchema("migration-plan", data, "INVALID_MIGRATION_PLAN");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const plan = schemaResult.data;
  const diagnostics = [];
  diagnostics.push(...checkMigrationCollision(plan));
  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return { ok: true, data: plan, diagnostics: [] };
}

// src/schema/catalog.ts
function diag2(code, message, pointer) {
  return {
    code,
    severity: "error",
    message,
    source: { label: "<index>", pointer }
  };
}
function checkSchemaVersion(data) {
  if (data.schemaVersion !== 1) {
    return diag2(
      "SCHEMA_VERSION_UNSUPPORTED",
      `schemaVersion must be 1, got ${JSON.stringify(data.schemaVersion)}`
    );
  }
  return void 0;
}
function checkProviderDiscriminatedUnion(entries) {
  const diagnostics = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const provider = entry.provider;
    if (provider.scope !== "plugin") {
      diagnostics.push(
        diag2(
          "INVALID_CATALOG",
          `entries[${i}].provider.scope must be "plugin", got "${provider.scope}"`,
          `/entries/${i}/provider/scope`
        )
      );
    }
  }
  return diagnostics;
}
function checkPluginMatchesCatalogId(catalogId, entries) {
  const diagnostics = [];
  for (let i = 0; i < entries.length; i++) {
    const provider = entries[i].provider;
    if (provider.scope === "plugin" && provider.plugin !== catalogId) {
      diagnostics.push(
        diag2(
          "INVALID_CATALOG",
          `entries[${i}].provider.plugin "${provider.plugin}" must equal catalog.id "${catalogId}"`,
          `/entries/${i}/provider/plugin`
        )
      );
    }
  }
  return diagnostics;
}
function checkSideEffectsConflict(entries) {
  const diagnostics = [];
  for (let i = 0; i < entries.length; i++) {
    const effects = entries[i].sideEffects;
    const hasReadOnly = effects.includes("read-only");
    const hasWrite = effects.includes("write-project-artifacts") || effects.includes("external-state-change");
    if (hasReadOnly && hasWrite) {
      diagnostics.push(
        diag2(
          "INVALID_CATALOG",
          `entries[${i}].sideEffects: "read-only" cannot coexist with write side effects`,
          `/entries/${i}/sideEffects`
        )
      );
    }
  }
  return diagnostics;
}
function checkRefUniqueness(entries) {
  const diagnostics = [];
  const seen = /* @__PURE__ */ new Set();
  for (let i = 0; i < entries.length; i++) {
    const ref = entries[i].ref;
    if (seen.has(ref)) {
      diagnostics.push(
        diag2(
          "INVALID_CATALOG",
          `entries[${i}].ref "${ref}" is duplicated`,
          `/entries/${i}/ref`
        )
      );
    }
    seen.add(ref);
  }
  return diagnostics;
}
function checkSummaryCodePoints(entries) {
  const diagnostics = [];
  for (let i = 0; i < entries.length; i++) {
    const summary = entries[i].summary;
    const len = [...summary].length;
    if (len > 160) {
      diagnostics.push(
        diag2(
          "INVALID_CATALOG",
          `entries[${i}].summary exceeds 160 code points (got ${len})`,
          `/entries/${i}/summary`
        )
      );
    }
  }
  return diagnostics;
}
function checkCompactProjectionLimit(entries) {
  const diagnostics = [];
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const projection = JSON.stringify({ ref: entry.ref, kind: entry.kind, summary: entry.summary });
    const len = [...projection].length;
    if (len > 400) {
      diagnostics.push(
        diag2(
          "INVALID_CATALOG",
          `entries[${i}] compact projection exceeds 400 code points (got ${len})`,
          `/entries/${i}`
        )
      );
    }
  }
  return diagnostics;
}
function validateCatalog(data) {
  if (data != null && typeof data === "object") {
    const obj = data;
    const documentKind = obj.documentKind;
    if (documentKind === "v2-implementation") {
      const result = validateImplementationDescriptor(data);
      return {
        ok: result.ok,
        data: result.data,
        diagnostics: result.diagnostics
      };
    }
    if (documentKind === "v2-inventory") {
      const result = validateInventory(data);
      return {
        ok: result.ok,
        data: result.data,
        diagnostics: result.diagnostics
      };
    }
    if (documentKind === "v2-run-lock") {
      const result = validateRunLock(data);
      return {
        ok: result.ok,
        data: result.data,
        diagnostics: result.diagnostics
      };
    }
    if (documentKind === "v2-migration-plan") {
      const result = validateMigrationPlan(data);
      return {
        ok: result.ok,
        data: result.data,
        diagnostics: result.diagnostics
      };
    }
    if (documentKind !== void 0 && documentKind !== "v2-implementation" && documentKind !== "v2-inventory" && documentKind !== "v2-run-lock" && documentKind !== "v2-migration-plan") {
      return {
        ok: false,
        diagnostics: [{
          code: "DOCUMENT_KIND_MISMATCH",
          severity: "error",
          message: `Unknown documentKind: ${JSON.stringify(documentKind)}`,
          source: { label: "<index>" }
        }]
      };
    }
  }
  if (data != null && typeof data === "object") {
    const schemaVersionDiag = checkSchemaVersion(data);
    if (schemaVersionDiag) {
      return { ok: false, diagnostics: [schemaVersionDiag] };
    }
  }
  const schemaResult = validateAgainstSchema("catalog", data, "INVALID_CATALOG");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const catalogData = schemaResult.data;
  const diagnostics = [];
  diagnostics.push(...checkProviderDiscriminatedUnion(catalogData.entries));
  diagnostics.push(...checkPluginMatchesCatalogId(catalogData.catalog.id, catalogData.entries));
  diagnostics.push(...checkSideEffectsConflict(catalogData.entries));
  diagnostics.push(...checkRefUniqueness(catalogData.entries));
  diagnostics.push(...checkSummaryCodePoints(catalogData.entries));
  diagnostics.push(...checkCompactProjectionLimit(catalogData.entries));
  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return { ok: true, data: catalogData, diagnostics: [] };
}

// src/schema/project.ts
function diag3(code, message, pointer) {
  return {
    code,
    severity: "error",
    message,
    source: { label: "<project>", pointer }
  };
}
function checkSchemaVersion2(data) {
  if (data.schemaVersion !== 1) {
    return diag3(
      "SCHEMA_VERSION_UNSUPPORTED",
      `schemaVersion must be 1, got ${JSON.stringify(data.schemaVersion)}`
    );
  }
  return void 0;
}
function checkProjectEntryProviders(entries) {
  const diagnostics = [];
  for (let i = 0; i < entries.length; i++) {
    const provider = entries[i].provider;
    if (provider.scope !== "project") {
      diagnostics.push(
        diag3(
          "INVALID_PROJECT_OVERLAY",
          `entries[${i}].provider.scope must be "project", got "${provider.scope}"`,
          `/entries/${i}/provider/scope`
        )
      );
    }
    if ("plugin" in provider) {
      diagnostics.push(
        diag3(
          "INVALID_PROJECT_OVERLAY",
          `entries[${i}].provider must not have "plugin" field for project scope`,
          `/entries/${i}/provider`
        )
      );
    }
  }
  return diagnostics;
}
function checkOverrideProviders(overrides) {
  const diagnostics = [];
  for (const [ref, override] of Object.entries(overrides)) {
    const provider = override.provider;
    if (provider.scope !== "project") {
      diagnostics.push(
        diag3(
          "INVALID_OVERRIDE_PROVIDER",
          `overrides["${ref}"].provider.scope must be "project", got "${provider.scope}"`,
          `/overrides/${ref}/provider/scope`
        )
      );
    }
    if ("plugin" in provider) {
      diagnostics.push(
        diag3(
          "INVALID_OVERRIDE_PROVIDER",
          `overrides["${ref}"].provider must not have "plugin" field for project scope`,
          `/overrides/${ref}/provider`
        )
      );
    }
  }
  return diagnostics;
}
function checkOverrideTargets(entries, overrides) {
  const diagnostics = [];
  const projectEntryRefs = new Set(entries.map((e) => e.ref));
  for (const ref of Object.keys(overrides)) {
    if (projectEntryRefs.has(ref)) {
      diagnostics.push(
        diag3(
          "INVALID_OVERRIDE_TARGET",
          `overrides["${ref}"] targets a project entry ref; only catalog entries can be overridden`,
          `/overrides/${ref}`
        )
      );
    }
  }
  return diagnostics;
}
function validateProjectOverlay(data) {
  if (data != null && typeof data === "object") {
    const obj = data;
    const documentKind = obj.documentKind;
    if (documentKind === "v2-binding") {
      const result = validateBinding(data);
      return {
        ok: result.ok,
        data: result.data,
        diagnostics: result.diagnostics
      };
    }
    if (documentKind === "v2-projection") {
      const result = validateProjection(data);
      return {
        ok: result.ok,
        data: result.data,
        diagnostics: result.diagnostics
      };
    }
    if (documentKind !== void 0 && documentKind !== "v2-binding" && documentKind !== "v2-projection") {
      return {
        ok: false,
        diagnostics: [{
          code: "DOCUMENT_KIND_MISMATCH",
          severity: "error",
          message: `Unknown documentKind for project overlay: ${JSON.stringify(documentKind)}`,
          source: { label: "<project>" }
        }]
      };
    }
  }
  if (data != null && typeof data === "object") {
    const schemaVersionDiag = checkSchemaVersion2(data);
    if (schemaVersionDiag) {
      return { ok: false, diagnostics: [schemaVersionDiag] };
    }
  }
  const schemaResult = validateAgainstSchema("project", data, "INVALID_PROJECT_OVERLAY");
  if (!schemaResult.valid) {
    return { ok: false, diagnostics: schemaResult.diagnostics };
  }
  const overlayData = schemaResult.data;
  const diagnostics = [];
  if (overlayData.entries) {
    diagnostics.push(...checkProjectEntryProviders(overlayData.entries));
  }
  if (overlayData.overrides) {
    diagnostics.push(...checkOverrideProviders(overlayData.overrides));
    if (overlayData.entries) {
      diagnostics.push(...checkOverrideTargets(overlayData.entries, overlayData.overrides));
    }
  }
  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return { ok: true, data: overlayData, diagnostics: [] };
}

// src/provider/verify.ts
import { existsSync as existsSync2, realpathSync as realpathSync2, statSync as statSync2 } from "fs";
import { join as join2, isAbsolute as isAbsolute3, relative as relative2 } from "path";

// src/v2/bundle-digest.ts
import { createHash as createHash2 } from "crypto";
import { readdirSync, readFileSync as readFileSync2, statSync, lstatSync, readlinkSync, realpathSync } from "fs";
import { join, relative, posix, isAbsolute as isAbsolute2, resolve as resolve2, normalize } from "path";
function computeBundleTreeDigest(root, roots) {
  const entries = [];
  const canonicalRoot = realpathSync(root);
  const seenRoots = /* @__PURE__ */ new Set();
  for (const rootDir of roots) {
    if (isAbsolute2(rootDir) || rootDir.split(/[\\/]+/).includes("..")) {
      throw new Error(`Bundle root must be a contained relative path: ${rootDir}`);
    }
    const normalizedRoot = normalize(rootDir).replaceAll("\\", "/").replace(/^\.\//, "");
    if (!normalizedRoot || normalizedRoot === ".") {
      throw new Error("Bundle root must name a directory below canonicalRoot");
    }
    const absRoot = resolve2(canonicalRoot, normalizedRoot);
    const rel = relative(canonicalRoot, absRoot);
    if (rel.startsWith("..") || isAbsolute2(rel)) {
      throw new Error(`Bundle root escapes canonicalRoot: ${rootDir}`);
    }
    if (seenRoots.has(absRoot)) {
      throw new Error(`Duplicate normalized bundle root: ${rootDir}`);
    }
    seenRoots.add(absRoot);
    const rootStat = lstatSync(absRoot);
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
      throw new Error(`Bundle root must be a real directory: ${rootDir}`);
    }
    walkBundleDir(canonicalRoot, absRoot, entries);
  }
  entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const canonical = entries.map((e) => `${e.path}	${e.type}	${e.contentHash}`).join("\n");
  const hash = createHash2("sha256").update(canonical).digest("hex");
  return `sha256:${hash}`;
}
function walkBundleDir(bundleRoot, dir, entries) {
  let items;
  items = readdirSync(dir);
  for (const item of items) {
    const absPath = join(dir, item);
    const relPath = posix.normalize(relative(bundleRoot, absPath).replaceAll("\\", "/"));
    if (relPath.startsWith("..")) {
      throw new Error(`Bundle entry escapes root: ${relPath}`);
    }
    const lstat = lstatSync(absPath);
    if (lstat.isSymbolicLink()) {
      const target = readlinkSync(absPath);
      const resolvedTarget = isAbsolute2(target) ? target : resolve2(dir, target);
      const resolvedRel = relative(bundleRoot, resolvedTarget);
      if (resolvedRel.startsWith("..") || isAbsolute2(resolvedRel)) {
        throw new Error(`Symlink ${relPath} escapes bundle root, pointing to ${resolvedTarget}`);
      }
      let finalTarget;
      try {
        finalTarget = realpathSync(absPath);
      } catch {
        throw new Error(`Dangling or unreadable symlink in bundle: ${relPath}`);
      }
      const finalRel = relative(bundleRoot, finalTarget);
      if (finalRel.startsWith("..") || isAbsolute2(finalRel)) {
        throw new Error(`Symlink ${relPath} ultimately escapes bundle root, resolving to ${finalTarget}`);
      }
      try {
        const targetStat = statSync(absPath);
        if (targetStat.isDirectory()) {
          throw new Error(`Symlink ${relPath} points to a directory, not a regular file`);
        }
        const content = readFileSync2(absPath);
        const contentHash = createHash2("sha256").update(content).digest("hex");
        entries.push({ path: relPath, type: "symlink-file", contentHash });
      } catch (err) {
        if (err instanceof Error && (err.message.includes("escapes") || err.message.includes("directory"))) throw err;
        throw new Error(`Dangling or unreadable symlink in bundle: ${relPath}`);
      }
    } else if (lstat.isDirectory()) {
      walkBundleDir(bundleRoot, absPath, entries);
    } else if (lstat.isFile()) {
      const content = readFileSync2(absPath);
      const contentHash = createHash2("sha256").update(content).digest("hex");
      entries.push({ path: relPath, type: "file", contentHash });
    }
  }
}

// src/provider/verify.ts
function diag4(code, message) {
  return {
    code,
    severity: "error",
    message,
    source: { label: "<external>" }
  };
}
function checkSkillMd(dir, skill) {
  const skillPath = join2(dir, skill, "SKILL.md");
  return existsSync2(skillPath);
}
function resolveCanonical(dir, skill) {
  const skillPath = join2(dir, skill, "SKILL.md");
  return realpathSync2(skillPath);
}
function verifyProvider(input) {
  const rawInput = input;
  const suppliedModes = [rawInput.provider, rawInput.v2, rawInput.runLock].filter((value) => value !== void 0).length;
  if (suppliedModes !== 1) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", "verifyProvider requires exactly one of provider, v2, or runLock")]
    };
  }
  if (rawInput.v2 !== void 0) {
    const v2Input = input;
    if (!v2Input.host) {
      return {
        status: "not-found",
        diagnostics: [diag4("HOST_REQUIRED", "host is required for v2 provider verification")]
      };
    }
    return verifyProviderV2Path(v2Input.v2, v2Input.host);
  }
  if (rawInput.runLock !== void 0) {
    const runLockInput = input;
    if (!runLockInput.host) {
      return {
        status: "not-found",
        diagnostics: [diag4("HOST_REQUIRED", "host is required for run-lock verification")]
      };
    }
    return verifyRunLock(runLockInput.runLock, runLockInput.host);
  }
  const { host, pluginRoots, projectRoots, provider } = input;
  const hasRoots = pluginRoots && Object.keys(pluginRoots).length > 0 || projectRoots && projectRoots.length > 0;
  if (hasRoots && !host) {
    return {
      status: "not-found",
      diagnostics: [diag4("HOST_REQUIRED", "host is required when roots are provided")]
    };
  }
  let dirs;
  if (provider.scope === "plugin") {
    const pluginProvider = provider;
    const roots = pluginRoots?.[pluginProvider.plugin];
    if (!roots || roots.length === 0) {
      return { status: "unverified", diagnostics: [] };
    }
    dirs = roots;
  } else {
    if (!projectRoots || projectRoots.length === 0) {
      return { status: "unverified", diagnostics: [] };
    }
    dirs = projectRoots;
  }
  const canonicalPaths = /* @__PURE__ */ new Set();
  for (const dir of dirs) {
    if (checkSkillMd(dir, provider.skill)) {
      try {
        const canonical = resolveCanonical(dir, provider.skill);
        canonicalPaths.add(canonical);
      } catch {
        const fallback = join2(dir, provider.skill, "SKILL.md");
        canonicalPaths.add(fallback);
      }
    }
  }
  if (canonicalPaths.size === 0) {
    return {
      status: "not-found",
      diagnostics: [
        diag4(
          "PROVIDER_NOT_FOUND",
          `SKILL.md not found for skill "${provider.skill}" in any root`
        )
      ]
    };
  }
  if (canonicalPaths.size === 1) {
    return { status: "verified", diagnostics: [] };
  }
  return {
    status: "ambiguous",
    diagnostics: [
      diag4(
        "AMBIGUOUS_PROVIDER",
        `Multiple SKILL.md files found for skill "${provider.skill}" across roots`
      )
    ]
  };
}
function verifyRunLock(lock, callerHost) {
  if (lock.provider.host !== callerHost) {
    return {
      status: "not-found",
      diagnostics: [diag4("HOST_MISMATCH", `Caller host "${callerHost}" does not match run lock provider host "${lock.provider.host}"`)]
    };
  }
  const { inventoryEntry: _inventory, ...lockDocument } = lock;
  const validation = validateRunLock(lockDocument);
  if (!validation.ok) {
    return { status: "not-found", diagnostics: validation.diagnostics };
  }
  const { canonicalRoot, skillPath } = lock.provider;
  const inventory = lock.inventoryEntry;
  if (inventory.pluginId !== lock.provider.pluginId || inventory.projectAuthority !== lock.provider.projectAuthority || inventory.host !== lock.provider.host || inventory.canonicalRoot !== canonicalRoot || inventory.version !== lock.implementationVersion || inventory.packageDigest !== lock.provider.packageDigest || inventory.provenance !== lock.provider.provenance) {
    return {
      status: "not-found",
      diagnostics: [diag4("LOCK_INCONSISTENCY", "Run lock provider identity/host/package/provenance no longer matches trusted inventory")]
    };
  }
  if (!existsSync2(canonicalRoot)) {
    return {
      status: "not-found",
      diagnostics: [diag4("LOCK_INCONSISTENCY", `Lock provider canonicalRoot does not exist: ${canonicalRoot}`)]
    };
  }
  const skillMdPath = join2(canonicalRoot, skillPath, "SKILL.md");
  if (!existsSync2(skillMdPath)) {
    return {
      status: "not-found",
      diagnostics: [diag4("LOCK_INCONSISTENCY", `SKILL.md not found at ${skillMdPath} during reverify`)]
    };
  }
  let realPath;
  try {
    realPath = realpathSync2(skillMdPath);
  } catch {
    return {
      status: "not-found",
      diagnostics: [diag4("LOCK_INCONSISTENCY", `Cannot resolve realpath for ${skillMdPath}`)]
    };
  }
  let realCanonicalRoot;
  try {
    realCanonicalRoot = realpathSync2(canonicalRoot);
  } catch {
    return {
      status: "not-found",
      diagnostics: [diag4("LOCK_INCONSISTENCY", `Cannot resolve realpath for lock provider root ${canonicalRoot}`)]
    };
  }
  const relativeRealPath = relative2(realCanonicalRoot, realPath);
  if (relativeRealPath.startsWith("..") || isAbsolute3(relativeRealPath)) {
    return {
      status: "not-found",
      diagnostics: [diag4("LOCK_INCONSISTENCY", `Realpath escape detected during reverify: ${skillMdPath} resolves outside canonical root`)]
    };
  }
  try {
    const stat = statSync2(skillMdPath);
    if (!stat.isFile()) {
      return {
        status: "not-found",
        diagnostics: [diag4("LOCK_INCONSISTENCY", `Provider skill path is not a regular file: ${skillMdPath}`)]
      };
    }
  } catch {
    return {
      status: "not-found",
      diagnostics: [diag4("LOCK_INCONSISTENCY", `Cannot stat ${skillMdPath}`)]
    };
  }
  let actualBundleDigest;
  try {
    actualBundleDigest = computeBundleTreeDigest(canonicalRoot, lock.bundleRoots);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: "not-found",
      diagnostics: [diag4("BUNDLE_DIGEST_MISMATCH", `Bundle recompute failed: ${message}`)]
    };
  }
  if (actualBundleDigest !== lock.bundleDigest) {
    return {
      status: "not-found",
      diagnostics: [{
        code: "BUNDLE_DIGEST_MISMATCH",
        severity: "error",
        message: `Bundle digest drift detected: actual ${actualBundleDigest}, lock declares ${lock.bundleDigest}`,
        source: { label: "<external>" }
      }]
    };
  }
  return { status: "verified", diagnostics: [] };
}
function verifyProviderV2Path(v2, callerHost) {
  const { implementation, inventoryEntry, providerInstance, inventorySnapshot } = v2;
  if (inventoryEntry.host !== callerHost) {
    return {
      status: "not-found",
      diagnostics: [diag4("HOST_MISMATCH", `Caller host "${callerHost}" does not match inventory host "${inventoryEntry.host}"`)]
    };
  }
  if (providerInstance.host && providerInstance.host !== callerHost) {
    return {
      status: "not-found",
      diagnostics: [diag4("HOST_MISMATCH", `Caller host "${callerHost}" does not match provider instance host "${providerInstance.host}"`)]
    };
  }
  const { canonicalRoot, skillPath } = providerInstance;
  if (skillPath.includes("..")) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Provider skillPath must not contain "..": ${skillPath}`)]
    };
  }
  if (isAbsolute3(skillPath)) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Provider skillPath must be relative: ${skillPath}`)]
    };
  }
  if (!existsSync2(canonicalRoot)) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Provider canonicalRoot does not exist: ${canonicalRoot}`)]
    };
  }
  const skillMdPath = join2(canonicalRoot, skillPath, "SKILL.md");
  if (!existsSync2(skillMdPath)) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `SKILL.md not found at ${skillMdPath}`)]
    };
  }
  let realPath;
  try {
    realPath = realpathSync2(skillMdPath);
  } catch {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Cannot resolve realpath for ${skillMdPath}`)]
    };
  }
  let realCanonicalRoot;
  try {
    realCanonicalRoot = realpathSync2(canonicalRoot);
  } catch {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Cannot resolve realpath for provider root ${canonicalRoot}`)]
    };
  }
  const relativeRealPath = relative2(realCanonicalRoot, realPath);
  if (relativeRealPath.startsWith("..") || isAbsolute3(relativeRealPath)) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Realpath escape detected: ${skillMdPath} resolves outside canonical root`)]
    };
  }
  try {
    const stat = statSync2(skillMdPath);
    if (!stat.isFile()) {
      return {
        status: "not-found",
        diagnostics: [diag4("PROVIDER_REJECTED", `Provider skill path is not a regular file: ${skillMdPath}`)]
      };
    }
  } catch {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Cannot stat ${skillMdPath}`)]
    };
  }
  let actualBundleDigest;
  try {
    actualBundleDigest = computeBundleTreeDigest(realCanonicalRoot, implementation.bundle.roots);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      status: "not-found",
      diagnostics: [{
        code: "BUNDLE_DIGEST_MISMATCH",
        severity: "error",
        message: `Bundle tree digest computation failed: ${message}`,
        source: { label: "<external>" }
      }]
    };
  }
  const observed = {
    canonicalRoot: realCanonicalRoot,
    skillRealpath: realPath,
    bundleDigest: actualBundleDigest
  };
  if (inventoryEntry.pluginId !== implementation.pluginId || providerInstance.pluginId !== implementation.pluginId) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Inventory/provider pluginId does not exactly match implementation pluginId "${implementation.pluginId}"`)],
      observed
    };
  }
  if (inventoryEntry.projectAuthority !== implementation.projectAuthority || providerInstance.projectAuthority !== implementation.projectAuthority) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", "Inventory/provider projectAuthority does not match implementation authority")],
      observed
    };
  }
  if (inventoryEntry.version !== implementation.version) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", `Inventory version "${inventoryEntry.version}" does not match implementation version "${implementation.version}"`)],
      observed
    };
  }
  if (inventorySnapshot.freshness !== "fresh") {
    return {
      status: "not-found",
      diagnostics: [diag4("SNAPSHOT_TAMPERED", `Inventory snapshot is ${inventorySnapshot.freshness} for "${inventoryEntry.pluginId}"`)],
      observed
    };
  }
  const inventoryDigestPattern = /^sha256:[a-f0-9]{64}$/;
  if (!inventoryDigestPattern.test(inventorySnapshot.digest)) {
    return { status: "not-found", diagnostics: [diag4("SNAPSHOT_TAMPERED", "Inventory snapshot digest is invalid")], observed };
  }
  if (providerInstance.canonicalRoot !== inventoryEntry.canonicalRoot || providerInstance.projectAuthority !== inventoryEntry.projectAuthority || providerInstance.host !== inventoryEntry.host || providerInstance.packageDigest !== inventoryEntry.packageDigest || providerInstance.provenance !== inventoryEntry.provenance) {
    return {
      status: "not-found",
      diagnostics: [diag4("PROVIDER_REJECTED", "Provider instance does not match trusted inventory host, root, package, or provenance")],
      observed
    };
  }
  if (actualBundleDigest !== implementation.bundle.treeDigest) {
    return {
      status: "not-found",
      diagnostics: [{
        code: "BUNDLE_DIGEST_MISMATCH",
        severity: "error",
        message: `Bundle digest mismatch: actual computed ${actualBundleDigest}, implementation declares ${implementation.bundle.treeDigest}`,
        source: { label: "<external>" }
      }],
      observed
    };
  }
  if (actualBundleDigest !== providerInstance.bundleDigest) {
    return {
      status: "not-found",
      diagnostics: [{
        code: "BUNDLE_DIGEST_MISMATCH",
        severity: "error",
        message: `Bundle digest mismatch: actual computed ${actualBundleDigest}, provider declares ${providerInstance.bundleDigest}`,
        source: { label: "<external>" }
      }],
      observed
    };
  }
  return { status: "verified", diagnostics: [], observed };
}

// src/resolver/merge.ts
function mergeCatalogs(catalogs) {
  const entries = /* @__PURE__ */ new Map();
  const sourceMap = /* @__PURE__ */ new Map();
  const diagnostics = [];
  const idSet = /* @__PURE__ */ new Map();
  for (let i = 0; i < catalogs.length; i++) {
    const id = catalogs[i].catalog.id;
    const prev = idSet.get(id);
    if (prev !== void 0) {
      diagnostics.push({
        code: "DUPLICATE_CATALOG_ID",
        severity: "error",
        message: `Duplicate catalog.id "${id}" at index ${i} (first seen at index ${prev})`,
        source: { label: `<catalog:${id}>` }
      });
    }
    idSet.set(id, i);
  }
  if (diagnostics.length > 0) {
    return { entries, sourceMap, diagnostics };
  }
  for (const catalog of catalogs) {
    const sourceLabel = `<catalog:${catalog.catalog.id}>`;
    for (const entry of catalog.entries) {
      const existing = entries.get(entry.ref);
      if (existing) {
        diagnostics.push({
          code: "DUPLICATE_DEFAULT_PROVIDER",
          severity: "error",
          message: `Duplicate default provider for ref "${entry.ref}" in catalog "${catalog.catalog.id}"; first defined in "${sourceMap.get(entry.ref)}"`,
          source: { label: sourceLabel }
        });
      } else {
        entries.set(entry.ref, entry);
        sourceMap.set(entry.ref, catalog.catalog.id);
      }
    }
  }
  return { entries, sourceMap, diagnostics };
}

// src/resolver/overlay.ts
function applyOverlay(merged, sourceMap, overlay) {
  const entries = new Map(merged);
  const disabledEntries = [];
  const diagnostics = [];
  const projectEntries = overlay.entries ?? [];
  const overrides = overlay.overrides ?? {};
  const disabled = overlay.disabled ?? [];
  for (const entry of projectEntries) {
    if (merged.has(entry.ref)) {
      diagnostics.push({
        code: "DUPLICATE_PROJECT_ENTRY",
        severity: "error",
        message: `Project entry ref "${entry.ref}" duplicates an existing catalog ref; use "overrides" instead`,
        source: { label: "<project>" }
      });
    } else {
      entries.set(entry.ref, entry);
      sourceMap.set(entry.ref, "project");
    }
  }
  if (diagnostics.length > 0) {
    return { entries, disabledEntries, diagnostics };
  }
  for (const [ref, override] of Object.entries(overrides)) {
    if (!merged.has(ref)) {
      if (entries.has(ref)) {
        diagnostics.push({
          code: "INVALID_OVERRIDE_TARGET",
          severity: "error",
          message: `Override for "${ref}" targets a project entry; project entries cannot be overridden`,
          source: { label: "<project>" }
        });
      } else {
        diagnostics.push({
          code: "UNKNOWN_OVERRIDE_REF",
          severity: "error",
          message: `Override targets non-existent ref "${ref}"`,
          source: { label: "<project>" }
        });
      }
    } else {
      const provider = override.provider;
      if (provider.scope !== "project") {
        diagnostics.push({
          code: "INVALID_OVERRIDE_PROVIDER",
          severity: "error",
          message: `Override for "${ref}" provider must have scope "project", got "${provider.scope}"`,
          source: { label: "<project>" }
        });
      } else if ("plugin" in provider) {
        diagnostics.push({
          code: "INVALID_OVERRIDE_PROVIDER",
          severity: "error",
          message: `Override for "${ref}" provider must not have "plugin" field for project scope`,
          source: { label: "<project>" }
        });
      } else {
        const existing = entries.get(ref);
        entries.set(ref, { ...existing, provider });
      }
    }
  }
  if (diagnostics.length > 0) {
    return { entries, disabledEntries, diagnostics };
  }
  for (const ref of disabled) {
    const entry = entries.get(ref);
    if (!entry) {
      diagnostics.push({
        code: "UNKNOWN_DISABLED_REF",
        severity: "error",
        message: `Disabled targets non-existent ref "${ref}"`,
        source: { label: "<project>" }
      });
    } else {
      const sourceCatalog = sourceMap.get(ref) ?? "project";
      disabledEntries.push({
        ref,
        provider: { ...entry.provider },
        sourceCatalog,
        disabledBy: "agent-methods.yaml"
      });
      entries.delete(ref);
    }
  }
  return { entries, disabledEntries, diagnostics };
}

// src/v2/side-effects.ts
var ALLOWED_BY_BUDGET = {
  none: /* @__PURE__ */ new Set(["none"]),
  "read-only": /* @__PURE__ */ new Set(["none", "read-only"]),
  "write-authorized-artifacts": /* @__PURE__ */ new Set(["none", "read-only", "write-authorized-artifacts"]),
  "write-review-result": /* @__PURE__ */ new Set(["none", "read-only", "write-review-result"]),
  "write-project-artifacts": /* @__PURE__ */ new Set([
    "none",
    "read-only",
    "write-authorized-artifacts",
    "write-review-result",
    "write-project-artifacts"
  ])
};
function budgetAllows(budget, requested) {
  return ALLOWED_BY_BUDGET[budget]?.has(requested) ?? false;
}

// src/resolver/index.ts
var SUPPORTED_HOSTS = /* @__PURE__ */ new Set(["codex", "claude-code"]);
function v2diag2(code, message) {
  return { code, severity: "error", message, source: { label: "<index>" } };
}
function projectionCandidateSortKey(candidate) {
  return [
    candidate.familyImplementationId,
    candidate.version,
    candidate.provider?.pluginId ?? "",
    candidate.provider?.projectAuthority ?? "",
    candidate.provider?.canonicalRoot ?? "",
    candidate.provider?.packageDigest ?? "",
    candidate.provider?.provenance ?? ""
  ].join("\0");
}
function projectionCandidateIdentity(candidate) {
  return computeContentHash({
    familyImplementationId: candidate.familyImplementationId,
    serviceImplementationId: candidate.serviceImplementationId,
    version: candidate.version,
    provider: candidate.provider ?? null
  });
}
function buildEffectiveIndex(input) {
  if (input.familyApi !== void 0) {
    return buildV2Projection(input);
  }
  const allDiagnostics = [];
  const catalogs = input.catalogs ?? [];
  if (catalogs.length === 0) {
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_CATALOG",
        severity: "error",
        message: "At least one catalog is required",
        source: { label: "<index>" }
      }]
    };
  }
  const validatedCatalogs = [];
  for (let i = 0; i < catalogs.length; i++) {
    const result = validateCatalog(catalogs[i]);
    if (!result.ok) {
      allDiagnostics.push(...result.diagnostics);
    } else {
      validatedCatalogs.push(result.data);
    }
  }
  if (allDiagnostics.length > 0) {
    return { ok: false, diagnostics: allDiagnostics };
  }
  const mergeResult = mergeCatalogs(validatedCatalogs);
  if (mergeResult.diagnostics.length > 0) {
    return { ok: false, diagnostics: mergeResult.diagnostics };
  }
  let overlayResult = null;
  let projectData;
  if (input.project !== void 0) {
    const result = validateProjectOverlay(input.project);
    if (!result.ok) {
      return { ok: false, diagnostics: result.diagnostics };
    }
    projectData = result.data;
    overlayResult = applyOverlay(mergeResult.entries, mergeResult.sourceMap, projectData);
    if (overlayResult.diagnostics.length > 0) {
      return { ok: false, diagnostics: overlayResult.diagnostics };
    }
  }
  const finalEntries = overlayResult?.entries ?? mergeResult.entries;
  const sortedEntries = [...finalEntries.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([ref, entry]) => {
    const sourceCatalog = mergeResult.sourceMap.get(ref) ?? "project";
    const provenance = { sourceCatalog };
    if (overlayResult && projectData?.overrides?.[ref]) {
      provenance.overriddenBy = "agent-methods.yaml";
    }
    return { ...entry, provenance };
  });
  const sortedDisabled = (overlayResult?.disabledEntries ?? []).sort((a, b) => a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0);
  const catalogInputs = validatedCatalogs.map((c) => ({
    id: c.catalog.id,
    version: c.catalog.version,
    contentHash: computeContentHash(c)
  })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  const index = {
    schemaVersion: 1,
    inputs: {
      catalogs: catalogInputs,
      projectContentHash: projectData ? computeContentHash(projectData) : computeContentHash(null)
    },
    entries: sortedEntries,
    disabledEntries: sortedDisabled
  };
  return { ok: true, index, diagnostics: [] };
}
function findMatchingInventoryEntries(impl, inventoryData) {
  if (!inventoryData) return [];
  return inventoryData.entries.filter(
    (e) => e.pluginId === impl.pluginId && e.version === impl.version && (impl.lifecycle.ownership !== "project-local" || e.projectAuthority === impl.projectAuthority)
  );
}
function installationKey(entry) {
  return [
    entry.pluginId,
    entry.projectAuthority ?? "",
    entry.version,
    entry.host,
    entry.canonicalRoot
  ].join("\0");
}
function inventoryCanonicalKey(entry) {
  return [
    entry.pluginId,
    entry.projectAuthority ?? "",
    entry.version,
    entry.host,
    entry.canonicalRoot,
    entry.packageDigest,
    entry.provenance
  ].join("\0");
}
function validateInventoryEntries(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    return {
      ok: false,
      diagnostics: [v2diag2(
        "INVALID_INVENTORY_ENTRY",
        "inventoryEntries must be a non-empty array of inventory entry objects"
      )]
    };
  }
  const validatedEntries = [];
  for (let i = 0; i < candidates.length; i++) {
    if (candidates[i] === null || typeof candidates[i] !== "object" || Array.isArray(candidates[i])) {
      return {
        ok: false,
        diagnostics: [v2diag2(
          "INVALID_INVENTORY_ENTRY",
          `inventoryEntries[${i}] must be an object`
        )]
      };
    }
    const singleSnapshot = computeContentHash({ entries: [candidates[i]] });
    const wrapper = {
      documentKind: "v2-inventory",
      schemaVersion: 2,
      snapshotDigest: singleSnapshot,
      snapshotFreshness: "fresh",
      entries: [candidates[i]]
    };
    const invResult = validateInventory(wrapper);
    if (!invResult.ok) {
      const remappedDiagnostics = invResult.diagnostics.map(
        (d) => d.code === "INVALID_INVENTORY" ? { ...d, code: "INVALID_INVENTORY_ENTRY" } : d
      );
      return { ok: false, diagnostics: remappedDiagnostics };
    }
    const entry = invResult.data.entries[0];
    if (!SUPPORTED_HOSTS.has(entry.host)) {
      return {
        ok: false,
        diagnostics: [
          v2diag2(
            "INVALID_INVENTORY_ENTRY",
            `inventoryEntries[${i}].host "${entry.host}" is not supported; allowed: ${[...SUPPORTED_HOSTS].join(", ")}`
          )
        ]
      };
    }
    validatedEntries.push(entry);
  }
  const seenCanonical = /* @__PURE__ */ new Set();
  const seenInstallations = /* @__PURE__ */ new Map();
  for (let i = 0; i < validatedEntries.length; i++) {
    const canonicalKey = inventoryCanonicalKey(validatedEntries[i]);
    if (seenCanonical.has(canonicalKey)) {
      return {
        ok: false,
        diagnostics: [
          v2diag2("DUPLICATE_INVENTORY_ENTRY", `inventoryEntries[${i}] is an exact duplicate of another entry`)
        ]
      };
    }
    seenCanonical.add(canonicalKey);
    const instKey = installationKey(validatedEntries[i]);
    const existing = seenInstallations.get(instKey);
    if (existing) {
      if (existing.packageDigest !== validatedEntries[i].packageDigest || existing.provenance !== validatedEntries[i].provenance) {
        return {
          ok: false,
          diagnostics: [
            v2diag2(
              "CONFLICTING_INVENTORY_ENTRY",
              `inventoryEntries[${i}] conflicts with another entry for the same provider locator (${validatedEntries[i].pluginId}@${validatedEntries[i].version} on ${validatedEntries[i].host} at ${validatedEntries[i].canonicalRoot}): different packageDigest or provenance`
            )
          ]
        };
      }
    } else {
      seenInstallations.set(instKey, validatedEntries[i]);
    }
  }
  const sorted = [...validatedEntries].sort((a, b) => {
    const left = inventoryCanonicalKey(a);
    const right = inventoryCanonicalKey(b);
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const snapshotDigest = computeContentHash({ entries: sorted });
  const data = {
    documentKind: "v2-inventory",
    schemaVersion: 2,
    snapshotDigest,
    snapshotFreshness: "fresh",
    entries: sorted
  };
  const authoritative = validateInventory(data);
  if (!authoritative.ok) {
    return { ok: false, diagnostics: authoritative.diagnostics };
  }
  return { ok: true, data: authoritative.data };
}
function computeProjectionEntry(serviceId, serviceKind, serviceIntents, serviceSummary, sideEffectCeiling, mixSafe, apiId, apiMajor, apiRevisionDigest, implementations, inventoryData, bindingData) {
  const diagnostics = [];
  const candidates = [];
  for (const impl of implementations) {
    if (impl.implements.apiId !== apiId || impl.implements.apiMajor !== apiMajor) continue;
    const svcImpl = impl.services[serviceId];
    if (!svcImpl) continue;
    const matchingInventory = findMatchingInventoryEntries(impl, inventoryData);
    const providerInstances = matchingInventory.length > 0 ? matchingInventory : [void 0];
    for (const invEntry of providerInstances) {
      let trust2 = "UNVERIFIED";
      let verificationAttestationDigest = null;
      let skillPath = svcImpl.skill;
      if (invEntry) {
        const supportedHost = invEntry.host === "claude-code" || invEntry.host === "codex" ? invEntry.host : void 0;
        const declaredHostSupport = supportedHost ? impl.hostSupport?.[supportedHost] : void 0;
        if (!supportedHost || impl.hostSupport && (!declaredHostSupport || declaredHostSupport.available === false)) {
          candidates.push({
            impl,
            svcImpl,
            invEntry,
            isInstalled: true,
            trust: "REJECTED",
            verificationAttestationDigest: null,
            skillPath
          });
          continue;
        }
        skillPath = declaredHostSupport?.skillPath ?? svcImpl.skill;
        const providerInstance = {
          scope: impl.lifecycle.ownership === "project-local" ? "project" : "plugin",
          pluginId: impl.pluginId,
          ...impl.projectAuthority ? { projectAuthority: impl.projectAuthority } : {},
          host: invEntry.host,
          canonicalRoot: invEntry.canonicalRoot,
          skillPath,
          packageDigest: invEntry.packageDigest,
          bundleDigest: impl.bundle.treeDigest,
          provenance: invEntry.provenance
        };
        const verification = verifyProvider({
          host: supportedHost,
          v2: {
            implementation: impl,
            inventoryEntry: invEntry,
            providerInstance,
            inventorySnapshot: {
              digest: inventoryData.snapshotDigest,
              freshness: inventoryData.snapshotFreshness
            }
          }
        });
        trust2 = verification.status === "verified" ? "VERIFIED" : "REJECTED";
        if (trust2 === "VERIFIED") {
          verificationAttestationDigest = computeContentHash({
            pluginId: impl.pluginId,
            projectAuthority: impl.projectAuthority ?? null,
            version: impl.version,
            canonicalRoot: invEntry.canonicalRoot,
            packageDigest: invEntry.packageDigest,
            bundleDigest: impl.bundle.treeDigest,
            provenance: invEntry.provenance,
            inventorySnapshotDigest: inventoryData.snapshotDigest
          });
        }
      }
      candidates.push({
        impl,
        svcImpl,
        invEntry,
        isInstalled: !!invEntry,
        trust: trust2,
        verificationAttestationDigest,
        skillPath
      });
    }
  }
  const familyBindings = (bindingData?.bindings ?? []).filter(
    (b) => b.apiIdentity.apiId === apiId && b.apiIdentity.apiMajor === apiMajor
  );
  const serviceBindings = (bindingData?.serviceBindings ?? []).filter(
    (b) => b.serviceId === serviceId && b.apiIdentity.apiId === apiId && b.apiIdentity.apiMajor === apiMajor
  );
  if (serviceBindings.length > 0 && !mixSafe) {
    diagnostics.push(v2diag2("BINDING_INVALID", `Service-level binding is forbidden because "${serviceId}" is not mixSafe`));
  }
  const interopAttestations = new Set(serviceBindings.map((binding) => binding.interopTckAttestation));
  if (interopAttestations.size > 1) {
    diagnostics.push(v2diag2("BINDING_INVALID", `Service bindings for "${serviceId}" do not share one interop TCK attestation`));
  }
  const matchingBindings = [...familyBindings, ...serviceBindings];
  const validBindings = [];
  if (matchingBindings.length > 1) {
    diagnostics.push({
      code: "BINDING_INVALID",
      severity: "warn",
      message: `Family "${apiId}" has ${matchingBindings.length} bindings; projection is AMBIGUOUS until one atomic family release is selected`,
      source: { label: "<index>" }
    });
  }
  for (const binding of matchingBindings) {
    if (binding.familyId !== familyIdFromApiId(apiId)) {
      diagnostics.push(v2diag2("BINDING_INVALID", `Binding familyId does not match API ${apiId}`));
      continue;
    }
    if (binding.apiIdentity.apiRevisionDigest !== apiRevisionDigest) {
      diagnostics.push({
        code: "BINDING_INVALID",
        severity: "error",
        message: `Binding apiRevisionDigest mismatch for "${serviceId}": expected ${apiRevisionDigest}, got ${binding.apiIdentity.apiRevisionDigest}`,
        source: { label: "<index>" }
      });
      continue;
    }
    const boundImpl = candidates.find(
      (c) => c.impl.familyImplementationId === binding.implementationIdentity.familyImplementationId && c.impl.version === binding.implementationIdentity.version && c.invEntry !== void 0 && binding.providerSelector.pluginId === c.impl.pluginId && binding.providerSelector.scope === (c.impl.lifecycle.ownership === "project-local" ? "project" : "plugin") && binding.providerSelector.projectAuthority === c.impl.projectAuthority && binding.providerSelector.host === c.invEntry.host && binding.providerSelector.canonicalRoot === c.invEntry.canonicalRoot && binding.providerSelector.packageDigest === c.invEntry.packageDigest && binding.providerSelector.bundleDigest === c.impl.bundle.treeDigest && binding.providerSelector.provenance === c.invEntry.provenance
    );
    if (!boundImpl || !boundImpl.invEntry) {
      diagnostics.push({
        code: "BINDING_INVALID",
        severity: "error",
        message: `Binding references unknown implementation ${binding.implementationIdentity.familyImplementationId}@${binding.implementationIdentity.version} for "${serviceId}"`,
        source: { label: "<index>" }
      });
      continue;
    }
    if (boundImpl.impl.implements.apiRevisionDigest !== apiRevisionDigest) {
      diagnostics.push(v2diag2("BINDING_INVALID", `Implementation API revision mismatch for "${serviceId}"`));
      continue;
    }
    const attestation = boundImpl.impl.conformance.deterministicAttestation;
    if (!attestation || binding.conformanceEvidence.deterministicAttestation !== attestation) {
      diagnostics.push(v2diag2("BINDING_INVALID", `Binding conformance attestation mismatch for "${serviceId}"`));
      continue;
    }
    if (serviceBindings.includes(binding) && (!mixSafe || !binding.interopTckAttestation)) {
      continue;
    }
    if (serviceBindings.includes(binding)) {
      const tck = binding.interopTckAttestation;
      if (!(boundImpl.impl.conformance.interopTckAttestations ?? []).includes(tck)) {
        diagnostics.push(v2diag2("BINDING_INVALID", `Implementation ${boundImpl.impl.familyImplementationId}@${boundImpl.impl.version} has not attested interop TCK ${tck}`));
        continue;
      }
    }
    validBindings.push(binding);
  }
  const installedCandidates = candidates.filter((c) => c.isInstalled);
  const isWriteService = sideEffectCeiling && sideEffectCeiling.startsWith("write");
  const enabledCandidates = candidates.filter((c) => {
    if (!c.isInstalled) return false;
    const binding = validBindings.find(
      (b) => b.implementationIdentity.familyImplementationId === c.impl.familyImplementationId && b.implementationIdentity.version === c.impl.version && c.invEntry !== void 0 && b.providerSelector.pluginId === c.impl.pluginId && b.providerSelector.scope === (c.impl.lifecycle.ownership === "project-local" ? "project" : "plugin") && b.providerSelector.projectAuthority === c.impl.projectAuthority && b.providerSelector.host === c.invEntry.host && b.providerSelector.canonicalRoot === c.invEntry.canonicalRoot && b.providerSelector.packageDigest === c.invEntry.packageDigest && b.providerSelector.bundleDigest === c.impl.bundle.treeDigest && b.providerSelector.provenance === c.invEntry.provenance
    );
    if (!binding) return false;
    if (binding.authorization && (isWriteService && binding.authorization.granted !== true || !budgetAllows(binding.authorization.sideEffectBudget, sideEffectCeiling ?? "none"))) {
      return false;
    }
    return true;
  });
  const installation = installedCandidates.length > 0 ? "INSTALLED" : "NOT_INSTALLED";
  const enablement = enabledCandidates.length > 0 ? "ENABLED" : "NOT_ENABLED";
  const compatibility = candidates.length > 0 ? candidates.some((c) => c.impl.implements.apiRevisionDigest === apiRevisionDigest) ? "COMPATIBLE" : "INCOMPATIBLE" : "UNKNOWN";
  const trustedCandidates = candidates.filter((c) => c.trust === "VERIFIED");
  const trust = trustedCandidates.length > 0 ? "VERIFIED" : candidates.some((c) => c.trust === "REJECTED") ? "REJECTED" : "UNVERIFIED";
  let resolution = "NONE";
  let selectionSource = null;
  const resolvableEnabled = enabledCandidates.filter(
    (c) => c.trust === "VERIFIED" && c.impl.implements.apiRevisionDigest === apiRevisionDigest
  );
  const resolvableInstalled = installedCandidates.filter(
    (c) => c.trust === "VERIFIED" && c.impl.implements.apiRevisionDigest === apiRevisionDigest
  );
  if (resolvableEnabled.length === 1 && validBindings.length === 1) {
    resolution = "EXPLICIT_BINDING";
    selectionSource = "project-binding";
  } else if (resolvableEnabled.length > 1 || validBindings.length > 1) {
    resolution = "AMBIGUOUS";
    selectionSource = "project-binding";
  } else if (resolvableInstalled.length === 1 && validBindings.length === 0) {
    resolution = "UNIQUE_COMPATIBLE";
    selectionSource = "unique-compatible";
  } else if (resolvableInstalled.length > 1 && validBindings.length === 0) {
    resolution = "AMBIGUOUS";
  }
  const projectionCandidates = candidates.map((c) => {
    const isEnabled = enabledCandidates.includes(c);
    const candInstallation = c.isInstalled ? "INSTALLED" : "NOT_INSTALLED";
    const candEnablement = isEnabled ? "ENABLED" : "NOT_ENABLED";
    const candCompatibility = c.impl.implements.apiRevisionDigest === apiRevisionDigest ? "COMPATIBLE" : "INCOMPATIBLE";
    const provider = c.invEntry ? {
      scope: c.impl.lifecycle.ownership === "project-local" ? "project" : "plugin",
      pluginId: c.impl.pluginId,
      ...c.impl.projectAuthority ? { projectAuthority: c.impl.projectAuthority } : {},
      host: c.invEntry.host,
      canonicalRoot: c.invEntry.canonicalRoot,
      skillPath: c.skillPath,
      packageDigest: c.invEntry.packageDigest,
      bundleDigest: c.impl.bundle.treeDigest,
      provenance: c.invEntry.provenance
    } : void 0;
    const authorization = validBindings.find(
      (binding) => binding.implementationIdentity.familyImplementationId === c.impl.familyImplementationId && binding.implementationIdentity.version === c.impl.version && c.invEntry !== void 0 && binding.providerSelector.scope === (c.impl.lifecycle.ownership === "project-local" ? "project" : "plugin") && binding.providerSelector.pluginId === c.impl.pluginId && binding.providerSelector.projectAuthority === c.impl.projectAuthority && binding.providerSelector.host === c.invEntry.host && binding.providerSelector.canonicalRoot === c.invEntry.canonicalRoot && binding.providerSelector.packageDigest === c.invEntry.packageDigest && binding.providerSelector.bundleDigest === c.impl.bundle.treeDigest && binding.providerSelector.provenance === c.invEntry.provenance
    )?.authorization;
    return {
      serviceId,
      apiId,
      apiMajor,
      apiRevisionDigest,
      familyImplementationId: c.impl.familyImplementationId,
      serviceImplementationId: c.svcImpl.serviceImplementationId,
      version: c.impl.version,
      ...provider ? { provider } : {},
      bundleRoots: [...c.impl.bundle.roots].sort(),
      installation: candInstallation,
      enablement: candEnablement,
      compatibility: candCompatibility,
      trust: c.trust,
      conformanceAttestation: c.impl.conformance.deterministicAttestation,
      verificationAttestationDigest: c.verificationAttestationDigest,
      ...authorization ? { authorization } : {}
    };
  }).sort((a, b) => projectionCandidateSortKey(a).localeCompare(projectionCandidateSortKey(b)));
  const selectedCandidate = resolvableEnabled.length === 1 ? resolvableEnabled[0] : void 0;
  const selectedProjectionCandidate = selectedCandidate ? projectionCandidates.find(
    (candidate) => candidate.familyImplementationId === selectedCandidate.impl.familyImplementationId && candidate.serviceImplementationId === selectedCandidate.svcImpl.serviceImplementationId && candidate.version === selectedCandidate.impl.version && candidate.provider?.host === selectedCandidate.invEntry?.host && candidate.provider?.canonicalRoot === selectedCandidate.invEntry?.canonicalRoot
  ) : void 0;
  const selectedCandidateId = selectedProjectionCandidate ? projectionCandidateIdentity(selectedProjectionCandidate) : void 0;
  return {
    entry: {
      ref: serviceId,
      serviceId,
      apiId,
      apiMajor,
      apiRevisionDigest,
      kind: serviceKind,
      intents: [...serviceIntents].sort(),
      summary: serviceSummary,
      ...sideEffectCeiling ? { sideEffectCeiling } : {},
      mixSafe,
      apiRecognition: classifyApiRecognition(apiId),
      installation,
      enablement,
      compatibility,
      trust,
      resolution,
      selectionSource,
      ...selectedCandidateId ? { selectedCandidateId } : {},
      candidates: projectionCandidates
    },
    diagnostics
  };
}
function buildV2Projection(input) {
  const allDiagnostics = [];
  const familyApi = input.familyApi;
  if (!familyApi || typeof familyApi !== "object") {
    return {
      ok: false,
      diagnostics: [v2diag2("INVALID_PROJECTION", "familyApi is required for v2 projection")]
    };
  }
  const api = familyApi.api;
  const services = familyApi.services;
  if (!api || !services) {
    return {
      ok: false,
      diagnostics: [v2diag2("INVALID_PROJECTION", "familyApi must have api and services fields")]
    };
  }
  const apiId = api.id;
  const apiMajor = api.major;
  const apiRevisionDigest = api.revisionDigest;
  const apiRecognition = classifyApiRecognition(apiId);
  if (!apiRecognition) {
    return { ok: false, diagnostics: [v2diag2("INVALID_PROJECTION", `Family API identity has an unsupported authority namespace: ${String(apiId)}`)] };
  }
  const implementations = [];
  for (const raw of input.implementations ?? []) {
    const result = validateImplementationDescriptor(raw);
    if (!result.ok) {
      allDiagnostics.push(...result.diagnostics);
    } else {
      implementations.push(result.data);
    }
  }
  if (allDiagnostics.length > 0) {
    return { ok: false, diagnostics: allDiagnostics };
  }
  implementations.sort(
    (a, b) => `${a.familyImplementationId}@${a.version}`.localeCompare(`${b.familyImplementationId}@${b.version}`)
  );
  let inventoryData;
  let preparedInventory;
  if (input.inventory !== void 0 && input.inventoryEntries !== void 0) {
    return {
      ok: false,
      diagnostics: [v2diag2("MUTUALLY_EXCLUSIVE_INPUTS", "inventory and inventoryEntries are mutually exclusive; provide one")]
    };
  }
  if (input.inventory !== void 0) {
    const result = validateInventory(input.inventory);
    if (!result.ok) {
      return { ok: false, diagnostics: result.diagnostics };
    }
    inventoryData = result.data;
    inventoryData.entries = [...inventoryData.entries].sort(
      (a, b) => `${a.pluginId}@${a.version}`.localeCompare(`${b.pluginId}@${b.version}`)
    );
    const computedInventorySnapshot = computeContentHash({ entries: inventoryData.entries });
    if (inventoryData.snapshotFreshness !== "fresh" || inventoryData.snapshotDigest !== computedInventorySnapshot) {
      return {
        ok: false,
        diagnostics: [v2diag2("SNAPSHOT_TAMPERED", `Inventory snapshot is not fresh or digest does not match canonical entries`)]
      };
    }
  } else if (input.inventoryEntries !== void 0) {
    const result = validateInventoryEntries(input.inventoryEntries);
    if (!result.ok) {
      return { ok: false, diagnostics: result.diagnostics };
    }
    preparedInventory = result.data;
    inventoryData = preparedInventory;
  }
  let bindingData;
  if (input.bindings !== void 0) {
    const result = validateBinding(input.bindings);
    if (!result.ok) {
      return { ok: false, diagnostics: result.diagnostics };
    }
    bindingData = result.data;
    if ((bindingData.serviceBindings?.length ?? 0) > 0) {
      const apiServices = new Map(services.map((service) => [service.id, service]));
      const tck = new Set(bindingData.serviceBindings.map((binding) => binding.interopTckAttestation));
      if (tck.size !== 1) {
        return { ok: false, diagnostics: [v2diag2("BINDING_INVALID", "All mixed service bindings must share one interop TCK attestation")] };
      }
      for (const binding of bindingData.serviceBindings) {
        const service = apiServices.get(binding.serviceId);
        if (!service || service.mixSafe !== true) {
          return { ok: false, diagnostics: [v2diag2("BINDING_INVALID", `Service ${binding.serviceId} is unknown or not mixSafe`)] };
        }
      }
    }
  }
  const projectionEntries = [];
  for (const service of services) {
    const serviceId = service.id;
    const serviceKind = service.kind;
    const svcFamilyDiag = validateServiceIdFamily(serviceId, apiId);
    if (svcFamilyDiag) {
      allDiagnostics.push(svcFamilyDiag);
      continue;
    }
    const serviceIntents = service.intents ?? [];
    const serviceSummary = service.summary ?? "";
    const sideEffectCeiling = service.sideEffectCeiling ?? void 0;
    const mixSafe = service.mixSafe === true;
    const { entry, diagnostics } = computeProjectionEntry(
      serviceId,
      serviceKind,
      serviceIntents,
      serviceSummary,
      sideEffectCeiling,
      mixSafe,
      apiId,
      apiMajor,
      apiRevisionDigest,
      implementations,
      inventoryData,
      bindingData
    );
    allDiagnostics.push(...diagnostics);
    projectionEntries.push(entry);
  }
  if (allDiagnostics.some((d) => d.severity === "error")) {
    return { ok: false, diagnostics: allDiagnostics };
  }
  const implDigest = implementations.length > 0 ? computeContentHash(implementations) : computeContentHash(null);
  const invDigest = inventoryData ? computeContentHash(inventoryData) : computeContentHash(null);
  const bindDigest = bindingData ? computeContentHash(bindingData) : computeContentHash(null);
  const sortedEntries = projectionEntries.sort((a, b) => a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0);
  const inputs = {
    familyApiId: apiId,
    familyApiMajor: apiMajor,
    apiRevisionDigest,
    implementationDigest: implDigest,
    inventoryDigest: invDigest,
    bindingDigest: bindDigest
  };
  const snapshotDigest = computeContentHash({ inputs, entries: sortedEntries });
  const projection = {
    documentKind: "v2-projection",
    schemaVersion: 2,
    inputs,
    snapshotDigest,
    entries: sortedEntries
  };
  const validation = validateProjection(projection);
  if (!validation.ok) return { ok: false, diagnostics: validation.diagnostics };
  return { ok: true, index: validation.data, preparedInventory, diagnostics: allDiagnostics };
}

// src/schema/effective.ts
function validateEffectiveIndex(data) {
  const result = validateAgainstSchema("effective-index", data, "INVALID_EFFECTIVE_INDEX");
  if (!result.valid) {
    return { ok: false, diagnostics: result.diagnostics };
  }
  return { ok: true, data: result.data, diagnostics: [] };
}

// src/v2/protocol-digest.ts
import { createHash as createHash3 } from "crypto";
function stableProtocolStringify(value) {
  if (value === null || value === void 0) return String(value);
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableProtocolStringify(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const object = value;
    return `{${Object.keys(object).sort().map(
      (key) => `${JSON.stringify(key)}:${stableProtocolStringify(object[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}
function computeProtocolDigest(value) {
  return `sha256:${createHash3("sha256").update(stableProtocolStringify(value)).digest("hex")}`;
}

// src/capability-store.ts
import { runInNewContext as runInNewContext2 } from "vm";
import { types as utilTypes2 } from "util";
var primordials2 = runInNewContext2(`({
  getOwnPropertyDescriptor: Object.getOwnPropertyDescriptor,
  getPrototypeOf: Object.getPrototypeOf,
  freeze: Object.freeze,
  isFrozen: Object.isFrozen,
  ownKeys: Reflect.ownKeys,
  isArray: Array.isArray,
  isFinite: Number.isFinite,
  isInteger: Number.isInteger
})`);
var objectPrototype2 = primordials2.getPrototypeOf({});
var arrayPrototype2 = primordials2.getPrototypeOf([]);
var readPrivatePayload = () => void 0;
var constructPreparedHandle = () => {
  throw new TypeError("prepared-query handle constructor is not initialized");
};
function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !primordials2.isFrozen(value)) {
    for (const key of primordials2.ownKeys(value)) {
      const descriptor = primordials2.getOwnPropertyDescriptor(value, key);
      if (descriptor && "value" in descriptor && descriptor.value !== null && typeof descriptor.value === "object") {
        deepFreeze(descriptor.value);
      }
    }
    primordials2.freeze(value);
  }
  return value;
}
function hasPropertyWithoutReading(value, key) {
  if (value === null || typeof value !== "object") return false;
  if (utilTypes2.isProxy(value)) throw new TypeError("Proxy value rejected");
  let current = value;
  while (current !== null) {
    if (primordials2.getOwnPropertyDescriptor(current, key)) return true;
    current = primordials2.getPrototypeOf(current);
  }
  return false;
}
function cloneStrictRecordWithOpaque(value, opaqueKeys) {
  if (value === null || typeof value !== "object" || primordials2.isArray(value)) {
    throw new TypeError("plain record required");
  }
  if (utilTypes2.isProxy(value)) throw new TypeError("Proxy value rejected");
  if (primordials2.getPrototypeOf(value) !== objectPrototype2) throw new TypeError("custom prototype rejected");
  const output = {};
  for (const key of primordials2.ownKeys(value)) {
    if (typeof key === "symbol") throw new TypeError("symbol-keyed property rejected");
    const descriptor = primordials2.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new TypeError(`accessor or hidden property "${key}" rejected`);
    }
    let opaque = false;
    for (let index = 0; index < opaqueKeys.length; index += 1) {
      if (opaqueKeys[index] === key) {
        opaque = true;
        break;
      }
    }
    if (opaque) {
      if (descriptor.value === void 0) throw new TypeError(`undefined opaque property "${key}" rejected`);
      output[key] = descriptor.value;
    } else {
      output[key] = cloneStrictJsonData(descriptor.value);
    }
  }
  return output;
}
var PreparedMethodQueryHandle = class _PreparedMethodQueryHandle {
  #payload;
  static #constructing = false;
  get candidateServices() {
    return deepFreeze(cloneStrictJsonData(this.#payload.candidateServices));
  }
  static {
    readPrivatePayload = (value) => {
      if (typeof value !== "object" || value === null) return void 0;
      try {
        return value.#payload;
      } catch {
        return void 0;
      }
    };
    constructPreparedHandle = (payload) => {
      _PreparedMethodQueryHandle.#constructing = true;
      try {
        return new _PreparedMethodQueryHandle(payload);
      } finally {
        _PreparedMethodQueryHandle.#constructing = false;
      }
    };
  }
  constructor(payload) {
    if (!_PreparedMethodQueryHandle.#constructing) throw new TypeError("illegal prepared-query handle construction");
    this.#payload = payload;
  }
  /** Return a detached diagnostic snapshot, never the authority payload. */
  data() {
    return deepFreeze(cloneStrictJsonData(this.#payload));
  }
};
primordials2.freeze(PreparedMethodQueryHandle.prototype);
primordials2.freeze(PreparedMethodQueryHandle);
function createPreparedQueryHandle(payload) {
  const snapshot = deepFreeze(cloneStrictJsonData(payload));
  const handle = constructPreparedHandle(snapshot);
  return primordials2.freeze(handle);
}
function getPreparedQueryPayload(handle) {
  return readPrivatePayload(handle);
}

// src/query/engine.ts
var SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
var PROJECT_FACTS_KEYS = /* @__PURE__ */ new Set([
  "schemaVersion",
  "projectRoot",
  "configDigest",
  "policyDigest",
  "artifactGraphSummary",
  "targetArtifact",
  "contractRevisionDigest",
  "proofStatus",
  "versionLockStatus",
  "sourcesFreshness",
  "bindingFreshness",
  "evidenceDigest"
]);
var REQUIRED_PROJECT_FACTS_KEYS = [...PROJECT_FACTS_KEYS].filter((key) => key !== "policyDigest");
var GRAPH_SUMMARY_KEYS = /* @__PURE__ */ new Set(["artifactCount", "edgeCount", "contextTargets"]);
var TARGET_ARTIFACT_KEYS = /* @__PURE__ */ new Set(["type", "id"]);
var PROOF_STATUSES = /* @__PURE__ */ new Set(["present", "missing", "stale"]);
var FRESHNESS_STATUSES = /* @__PURE__ */ new Set(["fresh", "stale", "missing"]);
var METHOD_QUERY_INTENTS = /* @__PURE__ */ new Set(["default", "help", "author", "review", "repair", "route", "audit", "generate", "batch"]);
var SIDE_EFFECT_BUDGETS = /* @__PURE__ */ new Set(["none", "read-only", "write-authorized-artifacts", "write-review-result", "write-project-artifacts"]);
var AUTHORIZATION_KEYS = /* @__PURE__ */ new Set(["sideEffectBudget", "granted"]);
function isEntryExecutable(entry) {
  return entry.installation === "INSTALLED" && entry.enablement === "ENABLED" && entry.compatibility === "COMPATIBLE" && entry.trust === "VERIFIED" && entry.resolution === "EXPLICIT_BINDING" && entry.selectionSource === "project-binding";
}
function isPlainJsonObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  if (Object.getOwnPropertySymbols(value).length > 0) return false;
  return Object.values(Object.getOwnPropertyDescriptors(value)).every(
    (descriptor) => "value" in descriptor && descriptor.enumerable
  );
}
function hasExactKeys(value, allowed, required) {
  const keys = Object.keys(value);
  return keys.every((key) => allowed.has(key)) && required.every((key) => Object.hasOwn(value, key));
}
function invalidProjectFacts(pointer = "/projectFactsEvidence") {
  return [{
    code: "INVALID_METHOD_QUERY",
    severity: "error",
    message: "Project Facts Evidence is invalid",
    source: { label: "<index>", pointer }
  }];
}
function validateProjectFactsEvidence(value) {
  if (!isPlainJsonObject(value) || !hasExactKeys(value, PROJECT_FACTS_KEYS, REQUIRED_PROJECT_FACTS_KEYS)) {
    return { ok: false, diagnostics: invalidProjectFacts() };
  }
  if (value.schemaVersion !== 1 || typeof value.projectRoot !== "string" || value.projectRoot.length === 0 || typeof value.configDigest !== "string" || !SHA256_PATTERN.test(value.configDigest) || Object.hasOwn(value, "policyDigest") && value.policyDigest !== null && (typeof value.policyDigest !== "string" || !SHA256_PATTERN.test(value.policyDigest)) || typeof value.contractRevisionDigest !== "string" || !SHA256_PATTERN.test(value.contractRevisionDigest) || typeof value.evidenceDigest !== "string" || !SHA256_PATTERN.test(value.evidenceDigest)) {
    return { ok: false, diagnostics: invalidProjectFacts() };
  }
  if (!isPlainJsonObject(value.artifactGraphSummary) || !hasExactKeys(value.artifactGraphSummary, GRAPH_SUMMARY_KEYS, [...GRAPH_SUMMARY_KEYS]) || !Number.isInteger(value.artifactGraphSummary.artifactCount) || value.artifactGraphSummary.artifactCount < 0 || !Number.isInteger(value.artifactGraphSummary.edgeCount) || value.artifactGraphSummary.edgeCount < 0 || !Array.isArray(value.artifactGraphSummary.contextTargets) || !value.artifactGraphSummary.contextTargets.every((target) => typeof target === "string") || !value.artifactGraphSummary.contextTargets.every((target, index, targets) => index === 0 || targets[index - 1] < target)) {
    return { ok: false, diagnostics: invalidProjectFacts("/projectFactsEvidence/artifactGraphSummary") };
  }
  if (!isPlainJsonObject(value.targetArtifact) || !hasExactKeys(value.targetArtifact, TARGET_ARTIFACT_KEYS, [...TARGET_ARTIFACT_KEYS]) || typeof value.targetArtifact.type !== "string" || value.targetArtifact.type.length === 0 || typeof value.targetArtifact.id !== "string" || value.targetArtifact.id.length === 0) {
    return { ok: false, diagnostics: invalidProjectFacts("/projectFactsEvidence/targetArtifact") };
  }
  if (typeof value.proofStatus !== "string" || !PROOF_STATUSES.has(value.proofStatus) || typeof value.versionLockStatus !== "string" || !FRESHNESS_STATUSES.has(value.versionLockStatus) || typeof value.sourcesFreshness !== "string" || !FRESHNESS_STATUSES.has(value.sourcesFreshness) || typeof value.bindingFreshness !== "string" || !FRESHNESS_STATUSES.has(value.bindingFreshness)) {
    return { ok: false, diagnostics: invalidProjectFacts() };
  }
  const { evidenceDigest: _discarded, ...content } = value;
  let computedDigest;
  try {
    computedDigest = computeContentHash(content);
  } catch {
    return { ok: false, diagnostics: invalidProjectFacts() };
  }
  if (computedDigest !== value.evidenceDigest) {
    return { ok: false, diagnostics: invalidProjectFacts("/projectFactsEvidence/evidenceDigest") };
  }
  return { ok: true, envelope: value };
}
var DEFAULT_LIMIT = 8;
var VALID_FORMATS = /* @__PURE__ */ new Set(["compact", "full"]);
function queryEffectiveIndex(input) {
  const diagnostics = [];
  try {
    if (hasPropertyWithoutReading(input, "methodQuery")) {
      return {
        ok: false,
        diagnostics: [{
          code: "INVALID_METHOD_QUERY",
          severity: "error",
          message: "Public query does not accept caller-supplied full Method Query; provide methodQueryCandidate only",
          source: { label: "<index>" }
        }]
      };
    }
    input = cloneStrictJsonData(input);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid query input";
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `Public query input must be strict JSON data: ${reason}`,
        source: { label: "<index>" }
      }]
    };
  }
  if ("schemaVersion" in input.index && input.index.schemaVersion === 2) {
    return queryV2Projection(input);
  }
  const indexValidation = validateEffectiveIndex(input.index);
  if (!indexValidation.ok) {
    return { ok: false, diagnostics: indexValidation.diagnostics };
  }
  const limit = input.limit ?? DEFAULT_LIMIT;
  if (input.limit !== void 0) {
    if (!Number.isInteger(limit) || limit <= 0) {
      return {
        ok: false,
        diagnostics: [{
          code: "INVALID_QUERY",
          severity: "error",
          message: `Invalid limit: must be a positive integer, got ${input.limit}`
        }]
      };
    }
  }
  const format = input.format ?? "compact";
  if (input.format !== void 0 && !VALID_FORMATS.has(input.format)) {
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_QUERY",
        severity: "error",
        message: `Invalid format: must be 'compact' or 'full', got '${input.format}'`
      }]
    };
  }
  const v1Index = input.index;
  let filtered = v1Index.entries;
  if (input.domain !== void 0) {
    filtered = filtered.filter((e) => e.match.domains.includes(input.domain));
  }
  if (input.artifactType !== void 0) {
    filtered = filtered.filter((e) => e.match.artifactTypes.includes(input.artifactType));
  }
  if (input.intent !== void 0) {
    filtered = filtered.filter((e) => e.match.intents.includes(input.intent));
  }
  if (input.kind !== void 0) {
    filtered = filtered.filter((e) => e.kind === input.kind);
  }
  const limited = filtered.slice(0, limit);
  if (limited.length === 0) {
    diagnostics.push({
      code: "NO_QUERY_MATCH",
      severity: "info",
      message: "No entries matched the query filters"
    });
  }
  if (format === "compact") {
    const entries = limited.map((e) => ({
      ref: e.ref,
      kind: e.kind,
      summary: e.summary
    }));
    return { ok: true, data: { entries }, diagnostics };
  }
  return { ok: true, data: { entries: limited }, diagnostics };
}
function validateMethodQuery(methodQuery, projection) {
  const diagnostics = [];
  const schemaResult = validateAgainstSchema("method-query", methodQuery, "INVALID_METHOD_QUERY");
  if (!schemaResult.valid) return schemaResult.diagnostics;
  const recomputedSnapshot = computeContentHash({ inputs: projection.inputs, entries: projection.entries });
  if (recomputedSnapshot !== projection.snapshotDigest) {
    diagnostics.push({
      code: "SNAPSHOT_TAMPERED",
      severity: "error",
      message: "Projection snapshot digest mismatch",
      source: { label: "<index>" }
    });
  }
  if (methodQuery.registrySnapshot.freshness !== "fresh") {
    diagnostics.push({
      code: "SNAPSHOT_TAMPERED",
      severity: "error",
      message: `Registry snapshot is ${methodQuery.registrySnapshot.freshness}, expected fresh`,
      source: { label: "<index>" }
    });
  }
  if (methodQuery.registrySnapshot.digest !== projection.snapshotDigest) {
    diagnostics.push({
      code: "SNAPSHOT_TAMPERED",
      severity: "error",
      message: "Registry snapshot digest mismatch",
      source: { label: "<index>" }
    });
  }
  for (const candidate of methodQuery.candidateServices) {
    const familyDiag = validateServiceIdFamily(candidate.serviceId, candidate.apiId);
    if (familyDiag) {
      diagnostics.push({
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `Method Query candidate identity mismatch: ${familyDiag.message}`,
        source: { label: "<index>" }
      });
    }
  }
  for (const candidate of methodQuery.candidateServices) {
    const projEntry = projection.entries.find((e) => e.serviceId === candidate.serviceId);
    if (!projEntry) {
      diagnostics.push({
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `Method Query references unknown service "${candidate.serviceId}"`,
        source: { label: "<index>" }
      });
      continue;
    }
    if (candidate.apiRevisionDigest !== projection.inputs.apiRevisionDigest) {
      diagnostics.push({
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `Method Query apiRevisionDigest mismatch for "${candidate.serviceId}"`,
        source: { label: "<index>" }
      });
    }
    if (candidate.apiId !== projEntry.apiId || candidate.apiMajor !== projEntry.apiMajor || candidate.apiRevisionDigest !== projEntry.apiRevisionDigest) {
      diagnostics.push({
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `Method Query API identity mismatch for "${candidate.serviceId}"`,
        source: { label: "<index>" }
      });
    }
    if (projEntry.kind !== methodQuery.kind) {
      diagnostics.push({
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `Method Query candidate "${candidate.serviceId}" has kind "${projEntry.kind}" but query targets kind "${methodQuery.kind}"`,
        source: { label: "<index>" }
      });
    }
    if (!projEntry.intents.includes(methodQuery.intent)) {
      diagnostics.push({
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `Method Query intent "${methodQuery.intent}" is not declared by "${candidate.serviceId}"`,
        source: { label: "<index>" }
      });
    }
  }
  const computedQueryDigest = computeProtocolDigest({
    schemaVersion: methodQuery.schemaVersion,
    mode: methodQuery.mode,
    candidateServices: methodQuery.candidateServices,
    intent: methodQuery.intent,
    kind: methodQuery.kind,
    targetArtifact: methodQuery.targetArtifact,
    contractRevisionDigest: methodQuery.contractRevisionDigest,
    projectFactsEvidenceDigest: methodQuery.projectFactsEvidenceDigest,
    authorization: methodQuery.authorization,
    registrySnapshot: methodQuery.registrySnapshot
  });
  if (methodQuery.queryDigest !== computedQueryDigest) {
    diagnostics.push({
      code: "INVALID_METHOD_QUERY",
      severity: "error",
      message: "Method Query digest mismatch",
      source: { label: "<index>" }
    });
  }
  return diagnostics;
}
function queryV2Projection(input) {
  const diagnostics = [];
  let projection;
  let candidate;
  try {
    projection = cloneStrictJsonData(input.index);
    if (!input.methodQueryCandidate) {
      throw new TypeError("methodQueryCandidate must be an own data property");
    }
    candidate = cloneStrictJsonData(input.methodQueryCandidate);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "unknown strict-data violation";
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `v2 query input must be strict JSON data without accessors or caller-owned mutable references: ${reason}`,
        source: { label: "<index>" }
      }]
    };
  }
  const limit = input.limit ?? DEFAULT_LIMIT;
  const format = input.format ?? "compact";
  const purpose = input.purpose;
  if (!purpose || purpose !== "recommendation" && purpose !== "prepare") {
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `v2 query requires purpose 'recommendation' or 'prepare'; got ${JSON.stringify(purpose)}`,
        source: { label: "<index>" }
      }]
    };
  }
  const forbiddenFilters = ["domain", "artifactType", "intent", "kind", "limit", "format"];
  const suppliedFilters = forbiddenFilters.filter((filter) => Object.hasOwn(input, filter));
  if (suppliedFilters.length > 0) {
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: `v2 candidate is the single query source; legacy query filters are forbidden: ${suppliedFilters.join(", ")}`,
        source: { label: "<index>" }
      }]
    };
  }
  if ("methodQuery" in input) {
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: "Public query does not accept caller-supplied full Method Query; provide methodQueryCandidate only",
        source: { label: "<index>" }
      }]
    };
  }
  const projectionValidation = validateProjection(projection);
  if (!projectionValidation.ok) {
    return { ok: false, diagnostics: projectionValidation.diagnostics };
  }
  if (!candidate) {
    return {
      ok: false,
      diagnostics: [{
        code: "INVALID_METHOD_QUERY",
        severity: "error",
        message: "v2 projection query requires a methodQueryCandidate; bare filters and full Method Query are not supported",
        source: { label: "<index>" }
      }]
    };
  }
  {
    const ALLOWED_CANDIDATE_KEYS = /* @__PURE__ */ new Set([
      "mode",
      "intent",
      "kind",
      "projectFactsEvidence",
      "authorization"
    ]);
    const candidateObj = candidate;
    const candidateKeys = Object.keys(candidateObj);
    const extraKeys = candidateKeys.filter((k) => !ALLOWED_CANDIDATE_KEYS.has(k));
    const missingKeys = [...ALLOWED_CANDIDATE_KEYS].filter((k) => !(k in candidateObj));
    if (extraKeys.length > 0 || missingKeys.length > 0) {
      return {
        ok: false,
        preparedQueryHandle: void 0,
        diagnostics: [{
          code: "INVALID_METHOD_QUERY",
          severity: "error",
          message: `methodQueryCandidate has unexpected fields: [${extraKeys.join(", ")}]; missing fields: [${missingKeys.join(", ")}]. Allowed: [${[...ALLOWED_CANDIDATE_KEYS].join(", ")}]`,
          source: { label: "<index>" }
        }]
      };
    }
    const authorization = candidateObj.authorization;
    if (candidateObj.mode !== "standard" || typeof candidateObj.intent !== "string" || !METHOD_QUERY_INTENTS.has(candidateObj.intent) || candidateObj.kind !== "workflow" && candidateObj.kind !== "operation" || !isPlainJsonObject(authorization) || !hasExactKeys(authorization, AUTHORIZATION_KEYS, [...AUTHORIZATION_KEYS]) || typeof authorization.sideEffectBudget !== "string" || !SIDE_EFFECT_BUDGETS.has(authorization.sideEffectBudget) || typeof authorization.granted !== "boolean") {
      return {
        ok: false,
        diagnostics: [{
          code: "INVALID_METHOD_QUERY",
          severity: "error",
          message: "methodQueryCandidate mode, intent, kind, or authorization is invalid",
          source: { label: "<index>" }
        }]
      };
    }
  }
  const evidenceValidation = validateProjectFactsEvidence(candidate.projectFactsEvidence);
  if (!evidenceValidation.ok) {
    return { ok: false, diagnostics: evidenceValidation.diagnostics };
  }
  const envelope = evidenceValidation.envelope;
  const matchingServices = projection.entries.filter(
    (e) => e.kind === candidate.kind && e.intents.includes(candidate.intent)
  );
  if (purpose === "recommendation") {
    if (matchingServices.length === 0) {
      return {
        ok: true,
        data: { entries: [] },
        diagnostics: [{
          code: "NO_QUERY_MATCH",
          severity: "info",
          message: `No projection entries match candidate intent "${candidate.intent}" and kind "${candidate.kind}"`,
          source: { label: "<index>" }
        }]
      };
    }
    if (matchingServices.length > 1) {
      diagnostics.push({
        code: "AMBIGUOUS_QUERY_MATCH",
        severity: "info",
        message: `${matchingServices.length} projection entries match intent "${candidate.intent}" and kind "${candidate.kind}"`,
        source: { label: "<index>" }
      });
    }
    const recommendationEntries = matchingServices.map((e) => {
      const executable = isEntryExecutable(e);
      const base = {
        ref: e.ref,
        serviceId: e.serviceId,
        apiId: e.apiId,
        apiMajor: e.apiMajor,
        apiRevisionDigest: e.apiRevisionDigest,
        kind: e.kind,
        summary: e.summary,
        sideEffectCeiling: e.sideEffectCeiling ?? "none"
      };
      if (executable) {
        return {
          ...base,
          executable: true,
          installation: "INSTALLED",
          enablement: "ENABLED",
          compatibility: "COMPATIBLE",
          trust: "VERIFIED",
          resolution: "EXPLICIT_BINDING",
          selectionSource: "project-binding"
        };
      }
      return {
        ...base,
        executable: false,
        installation: e.installation,
        enablement: e.enablement,
        compatibility: e.compatibility,
        trust: e.trust,
        resolution: e.resolution,
        selectionSource: e.selectionSource
      };
    });
    return { ok: true, data: { entries: recommendationEntries }, diagnostics };
  }
  if (matchingServices.length === 0) {
    return {
      ok: false,
      diagnostics: [{
        code: "NO_QUERY_MATCH",
        severity: "info",
        message: `No projection entries match candidate intent "${candidate.intent}" and kind "${candidate.kind}"`,
        source: { label: "<index>" }
      }]
    };
  }
  for (const entry of matchingServices) {
    if (!isEntryExecutable(entry)) {
      const violations = [];
      if (entry.installation !== "INSTALLED") violations.push(`installation=${entry.installation}`);
      if (entry.enablement !== "ENABLED") violations.push(`enablement=${entry.enablement}`);
      if (entry.compatibility !== "COMPATIBLE") violations.push(`compatibility=${entry.compatibility}`);
      if (entry.trust !== "VERIFIED") violations.push(`trust=${entry.trust}`);
      if (entry.resolution !== "EXPLICIT_BINDING") violations.push(`resolution=${entry.resolution}`);
      if (entry.selectionSource !== "project-binding") violations.push(`selectionSource=${String(entry.selectionSource)}`);
      return {
        ok: false,
        preparedQueryHandle: void 0,
        diagnostics: [{
          code: "NOT_EXECUTABLE",
          severity: "error",
          message: `Service "${entry.serviceId}" is not executable for prepare: ${violations.join(", ")}`,
          source: { label: "<index>" }
        }]
      };
    }
  }
  let methodQuery;
  {
    const candidateServices = matchingServices.map((entry) => ({
      serviceId: entry.serviceId,
      apiId: entry.apiId,
      apiMajor: entry.apiMajor,
      apiRevisionDigest: entry.apiRevisionDigest
    })).sort((left, right) => {
      const leftKey = `${left.serviceId}\0${left.apiId}\0${left.apiMajor}\0${left.apiRevisionDigest}`;
      const rightKey = `${right.serviceId}\0${right.apiId}\0${right.apiMajor}\0${right.apiRevisionDigest}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    });
    for (const entry of matchingServices) {
      const ceiling = entry.sideEffectCeiling ?? "none";
      if (ceiling !== "none" && ceiling !== "read-only") {
        if (!candidate.authorization || !candidate.authorization.granted) {
          return {
            ok: false,
            diagnostics: [{
              code: "INVALID_METHOD_QUERY",
              severity: "error",
              message: `Service "${entry.serviceId}" requires write authorization but candidate authorization.granted is false`,
              source: { label: "<index>" }
            }]
          };
        }
      }
      if (candidate.authorization && !budgetAllows(candidate.authorization.sideEffectBudget, ceiling)) {
        return {
          ok: false,
          diagnostics: [{
            code: "INVALID_METHOD_QUERY",
            severity: "error",
            message: `Authorization budget "${candidate.authorization.sideEffectBudget}" does not permit service ceiling "${ceiling}" for "${entry.serviceId}"`,
            source: { label: "<index>" }
          }]
        };
      }
    }
    const builtQuery = {
      schemaVersion: 1,
      mode: candidate.mode,
      candidateServices,
      intent: candidate.intent,
      kind: candidate.kind,
      targetArtifact: envelope.targetArtifact,
      contractRevisionDigest: envelope.contractRevisionDigest,
      projectFactsEvidenceDigest: envelope.evidenceDigest,
      authorization: candidate.authorization,
      registrySnapshot: {
        digest: projection.snapshotDigest,
        freshness: "fresh"
      }
    };
    const queryDigest = computeProtocolDigest(builtQuery);
    methodQuery = { ...builtQuery, queryDigest };
  }
  const methodDiags = validateMethodQuery(methodQuery, projection);
  if (methodDiags.some((d) => d.severity === "error")) {
    return { ok: false, diagnostics: methodDiags };
  }
  diagnostics.push(...methodDiags);
  let filtered = projection.entries;
  if (methodQuery.kind !== void 0) {
    filtered = filtered.filter((e) => e.kind === methodQuery.kind);
  }
  const candidateServiceIds = new Set(methodQuery.candidateServices.map((c) => c.serviceId));
  filtered = filtered.filter((e) => candidateServiceIds.has(e.serviceId));
  const limited = filtered.slice(0, limit);
  if (limited.length === 0) {
    diagnostics.push({
      code: "NO_QUERY_MATCH",
      severity: "info",
      message: "No entries matched the query filters"
    });
  }
  const preparedQueryHandle = createPreparedQueryHandle(methodQuery);
  if (format === "compact") {
    const entries = limited.map((e) => ({
      ref: e.ref,
      kind: e.kind,
      summary: e.summary
    }));
    return { ok: true, data: { entries }, preparedQueryHandle, diagnostics };
  }
  return { ok: true, data: { entries: limited }, preparedQueryHandle, diagnostics };
}

// src/v2/run-lock.ts
function createRunLock(input) {
  return {
    documentKind: "v2-run-lock",
    schemaVersion: 2,
    serviceId: input.serviceId,
    apiId: input.apiId,
    apiMajor: input.apiMajor,
    apiRevisionDigest: input.apiRevisionDigest,
    familyImplementationId: input.familyImplementationId,
    serviceImplementationId: input.serviceImplementationId,
    implementationVersion: input.implementationVersion,
    provider: {
      scope: input.provider.scope,
      pluginId: input.provider.pluginId,
      ...input.provider.projectAuthority ? { projectAuthority: input.provider.projectAuthority } : {},
      host: input.provider.host,
      canonicalRoot: input.provider.canonicalRoot,
      skillPath: input.provider.skillPath,
      packageDigest: input.provider.packageDigest,
      provenance: input.provider.provenance
    },
    bundleRoots: [...input.bundleRoots],
    bundleDigest: input.bundleDigest,
    artifactContractRevisionDigest: input.artifactContractRevisionDigest,
    sourceDigest: input.sourceDigest,
    bindingDigest: input.bindingDigest,
    indexDigest: input.indexDigest,
    queryDigest: input.queryDigest,
    projectFactsEvidenceDigest: input.projectFactsEvidenceDigest,
    conformanceAttestationDigest: input.conformanceAttestationDigest,
    sideEffectSummary: {
      ceiling: input.sideEffectSummary.ceiling,
      budget: input.sideEffectSummary.budget,
      authorized: input.sideEffectSummary.authorized
    }
  };
}

// src/provider/resolve.ts
function resolveEntry(input) {
  try {
    if (hasPropertyWithoutReading(input, "methodQuery")) {
      return {
        ok: false,
        diagnostics: [diag4("INVALID_METHOD_QUERY", "Public resolve does not accept caller-supplied methodQuery; use preparedQueryHandle from queryEffectiveIndex")]
      };
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid resolve input";
    return {
      ok: false,
      diagnostics: [diag4("INVALID_METHOD_QUERY", `Public resolve input must be a strict data record: ${reason}`)]
    };
  }
  let safeInput;
  try {
    safeInput = cloneStrictRecordWithOpaque(input, ["preparedQueryHandle"]);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid resolve input";
    return {
      ok: false,
      diagnostics: [diag4("INVALID_METHOD_QUERY", `Public resolve input must be a strict data record: ${reason}`)]
    };
  }
  const { index, ref, host, pluginRoots, projectRoots, strictProvider } = safeInput;
  const hasRoots = pluginRoots && Object.keys(pluginRoots).length > 0 || projectRoots && projectRoots.length > 0;
  const needsHost = hasRoots || strictProvider;
  if (needsHost && !host) {
    return {
      ok: false,
      diagnostics: [
        diag4(
          "HOST_REQUIRED",
          "host is required when roots or strictProvider are provided"
        )
      ]
    };
  }
  if ("schemaVersion" in index && index.schemaVersion === 2) {
    return resolveV2Entry(index, ref, host, safeInput.preparedQueryHandle, safeInput.serviceIdentity);
  }
  const v1Index = index;
  const validationResult = validateEffectiveIndex(v1Index);
  if (!validationResult.ok) {
    return {
      ok: false,
      diagnostics: validationResult.diagnostics
    };
  }
  const disabled = v1Index.disabledEntries.find((e) => e.ref === ref);
  if (disabled) {
    return {
      ok: false,
      diagnostics: [
        diag4(
          "ENTRY_DISABLED",
          `Entry "${ref}" is disabled by ${disabled.disabledBy}`
        )
      ]
    };
  }
  const entry = v1Index.entries.find((e) => e.ref === ref);
  if (!entry) {
    return {
      ok: false,
      diagnostics: [
        diag4("ENTRY_NOT_FOUND", `Entry "${ref}" not found in effective index`)
      ]
    };
  }
  if (!host) {
    return { ok: true, data: { entry }, diagnostics: [] };
  }
  if (!hasRoots && !strictProvider) {
    return { ok: true, data: { entry }, diagnostics: [] };
  }
  const verificationResult = verifyProvider({
    host,
    pluginRoots,
    projectRoots,
    provider: entry.provider
  });
  const verification = {
    status: verificationResult.status,
    diagnostics: verificationResult.diagnostics
  };
  if (verificationResult.status === "not-found" && hasRoots) {
    return {
      ok: false,
      diagnostics: verificationResult.diagnostics
    };
  }
  if (verificationResult.status === "ambiguous" && hasRoots) {
    return {
      ok: false,
      diagnostics: verificationResult.diagnostics
    };
  }
  if (strictProvider && verificationResult.status === "unverified") {
    return {
      ok: false,
      diagnostics: [
        diag4(
          "PROVIDER_UNVERIFIED",
          `Provider for "${ref}" could not be verified; roots not available for plugin "${entry.provider.scope === "plugin" ? entry.provider.plugin : "project"}"`
        )
      ]
    };
  }
  return { ok: true, data: { entry, verification }, diagnostics: [] };
}
function resolveV2Entry(projection, ref, host, preparedQueryHandle, serviceIdentity) {
  const methodQuery = preparedQueryHandle ? getPreparedQueryPayload(preparedQueryHandle) : void 0;
  if (!methodQuery || !serviceIdentity) {
    return {
      ok: false,
      diagnostics: [diag4("INVALID_METHOD_QUERY", "v2 resolve requires a Registry-produced preparedQueryHandle and explicit service identity")]
    };
  }
  if (!host) {
    return {
      ok: false,
      diagnostics: [diag4("HOST_REQUIRED", "v2 strict resolve requires host to disambiguate provider identity")]
    };
  }
  const projectionValidation = validateProjection(projection);
  if (!projectionValidation.ok) {
    return { ok: false, diagnostics: projectionValidation.diagnostics };
  }
  if (methodQuery.registrySnapshot.digest !== projection.snapshotDigest) {
    return { ok: false, diagnostics: [diag4("SNAPSHOT_TAMPERED", "Method Query registry snapshot digest mismatch")] };
  }
  if (methodQuery.registrySnapshot.freshness !== "fresh") {
    return { ok: false, diagnostics: [diag4("SNAPSHOT_TAMPERED", `Registry snapshot is ${methodQuery.registrySnapshot.freshness}, expected fresh`)] };
  }
  const entry = projection.entries.find((e) => e.ref === ref);
  if (!entry) {
    return {
      ok: false,
      diagnostics: [
        diag4("ENTRY_NOT_FOUND", `Entry "${ref}" not found in v2 projection`)
      ]
    };
  }
  if (serviceIdentity.serviceId !== entry.serviceId || serviceIdentity.apiId !== entry.apiId || serviceIdentity.apiMajor !== entry.apiMajor || serviceIdentity.apiRevisionDigest !== entry.apiRevisionDigest || !methodQuery.candidateServices.some(
    (candidate) => candidate.serviceId === serviceIdentity.serviceId && candidate.apiId === serviceIdentity.apiId && candidate.apiMajor === serviceIdentity.apiMajor && candidate.apiRevisionDigest === serviceIdentity.apiRevisionDigest
  )) {
    return { ok: false, diagnostics: [diag4("INVALID_METHOD_QUERY", `Method Query does not authorize exact service identity "${ref}"`)] };
  }
  if (!entry.intents.includes(methodQuery.intent) || entry.kind !== methodQuery.kind) {
    return { ok: false, diagnostics: [diag4("INVALID_METHOD_QUERY", `Method Query intent/kind does not match service "${ref}"`)] };
  }
  if (entry.resolution === "NONE") {
    return {
      ok: false,
      diagnostics: [{
        code: "RESOLUTION_NONE",
        severity: "error",
        message: `No compatible provider found for "${ref}". Installation: ${entry.installation}, Trust: ${entry.trust}`,
        source: { label: "<index>" },
        suggestion: "Install the family implementation and verify the provider"
      }]
    };
  }
  if (entry.resolution === "AMBIGUOUS") {
    return {
      ok: false,
      diagnostics: [{
        code: "RESOLUTION_AMBIGUOUS",
        severity: "error",
        message: `Multiple compatible providers found for "${ref}". Use project binding to disambiguate.`,
        source: { label: "<index>" }
      }]
    };
  }
  if (entry.installation === "NOT_INSTALLED") {
    return {
      ok: false,
      diagnostics: [{
        code: "RESOLUTION_NONE",
        severity: "error",
        message: `Provider for "${ref}" is not installed. Resolution: ${entry.resolution}`,
        source: { label: "<index>" }
      }]
    };
  }
  if (entry.enablement === "NOT_ENABLED") {
    return {
      ok: false,
      diagnostics: [{
        code: "RESOLUTION_NONE",
        severity: "error",
        message: `Provider for "${ref}" is installed but not enabled. No explicit binding.`,
        source: { label: "<index>" },
        suggestion: "Add a project binding to enable this provider"
      }]
    };
  }
  const ceiling = entry.sideEffectCeiling ?? "read-only";
  if (!budgetAllows(methodQuery.authorization.sideEffectBudget, ceiling)) {
    return { ok: false, diagnostics: [diag4("INVALID_METHOD_QUERY", `Authorization budget "${methodQuery.authorization.sideEffectBudget}" does not permit service ceiling "${ceiling}"`)] };
  }
  if (ceiling !== "none" && ceiling !== "read-only" && methodQuery.authorization.granted !== true) {
    return { ok: false, diagnostics: [diag4("INVALID_METHOD_QUERY", `Write service "${ref}" requires explicit authorization`)] };
  }
  const eligibleCandidates = entry.candidates.filter(
    (c) => c.installation === "INSTALLED" && c.enablement === "ENABLED" && c.compatibility === "COMPATIBLE" && c.trust === "VERIFIED" && c.verificationAttestationDigest !== null
  );
  const selectedCandidate = eligibleCandidates.length === 1 ? eligibleCandidates[0] : void 0;
  if (!selectedCandidate) {
    return {
      ok: false,
      diagnostics: [{
        code: "RESOLUTION_NONE",
        severity: "error",
        message: `Strict resolve requires exactly one installed+enabled+compatible+VERIFIED candidate for "${ref}"; found ${eligibleCandidates.length}`,
        source: { label: "<index>" }
      }]
    };
  }
  if (!selectedCandidate.provider || !selectedCandidate.conformanceAttestation) {
    return { ok: false, diagnostics: [diag4("PROVIDER_UNVERIFIED", `Selected provider evidence is incomplete for "${ref}"`)] };
  }
  if (selectedCandidate.provider.host !== host) {
    return {
      ok: false,
      diagnostics: [diag4("HOST_MISMATCH", `Resolve host "${host}" does not match selected provider host "${selectedCandidate.provider.host}" for "${ref}"`)]
    };
  }
  if (selectedCandidate.authorization) {
    if (!budgetAllows(selectedCandidate.authorization.sideEffectBudget, methodQuery.authorization.sideEffectBudget)) {
      return { ok: false, diagnostics: [diag4(
        "INVALID_METHOD_QUERY",
        `Method Query budget "${methodQuery.authorization.sideEffectBudget}" exceeds project binding budget "${selectedCandidate.authorization.sideEffectBudget}"`
      )] };
    }
    if (ceiling !== "none" && ceiling !== "read-only" && selectedCandidate.authorization.granted !== true) {
      return { ok: false, diagnostics: [diag4("INVALID_METHOD_QUERY", `Project binding does not authorize write service "${ref}"`)] };
    }
  }
  const lock = createRunLock({
    serviceId: entry.serviceId,
    apiId: entry.apiId,
    apiMajor: projection.inputs.familyApiMajor,
    apiRevisionDigest: projection.inputs.apiRevisionDigest,
    familyImplementationId: selectedCandidate.familyImplementationId,
    serviceImplementationId: selectedCandidate.serviceImplementationId,
    implementationVersion: selectedCandidate.version,
    provider: {
      scope: selectedCandidate.provider.scope,
      pluginId: selectedCandidate.provider.pluginId,
      projectAuthority: selectedCandidate.provider.projectAuthority,
      host: selectedCandidate.provider.host,
      canonicalRoot: selectedCandidate.provider.canonicalRoot,
      skillPath: selectedCandidate.provider.skillPath,
      packageDigest: selectedCandidate.provider.packageDigest,
      provenance: selectedCandidate.provider.provenance
    },
    bundleRoots: selectedCandidate.bundleRoots,
    bundleDigest: selectedCandidate.provider.bundleDigest,
    artifactContractRevisionDigest: methodQuery.contractRevisionDigest,
    sourceDigest: computeContentHash({
      familyApiId: projection.inputs.familyApiId,
      apiRevisionDigest: projection.inputs.apiRevisionDigest,
      implementationDigest: projection.inputs.implementationDigest,
      inventoryDigest: projection.inputs.inventoryDigest
    }),
    bindingDigest: projection.inputs.bindingDigest,
    indexDigest: projection.snapshotDigest,
    queryDigest: methodQuery.queryDigest,
    projectFactsEvidenceDigest: methodQuery.projectFactsEvidenceDigest,
    conformanceAttestationDigest: selectedCandidate.conformanceAttestation,
    sideEffectSummary: {
      ceiling,
      budget: methodQuery.authorization.sideEffectBudget,
      authorized: methodQuery.authorization.granted
    }
  });
  return { ok: true, data: { entry, runMethodLock: lock }, diagnostics: [] };
}

export {
  computeContentHash,
  validateImplementationDescriptor,
  validateInventory,
  validateBinding,
  validateProjection,
  validateRunLock,
  validateMigrationPlan,
  validateCatalog,
  validateProjectOverlay,
  verifyProvider,
  buildEffectiveIndex,
  validateEffectiveIndex,
  queryEffectiveIndex,
  resolveEntry
};
