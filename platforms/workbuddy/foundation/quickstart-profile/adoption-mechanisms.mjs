import {
  assessAdoptionBinding,
  assessLegacyExitList,
  assessLegacyReferences,
  loadMigrationManifestState,
} from "./runtime/kit/migration.mjs";
import {
  verifyHarnessSurfaceInventory,
  verifyManagedBundleIdentity,
} from "./runtime/harness/quickstart-profile.mjs";

export { verifyManagedBundleIdentity };

const ADOPTION_OPERATIONS = Object.freeze([
  "load-migration-manifest-state",
  "assess-adoption-binding",
  "assess-legacy-exit-list",
  "assess-legacy-references",
  "verify-harness-surface-inventory",
]);

const FORBIDDEN_ROUTING_KEYS = new Set(["entry", "module", "export", "pathToFileURL"]);

function assertNoRoutingKeys(value, path = "params") {
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoRoutingKeys(item, `${path}/${index}`));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_ROUTING_KEYS.has(key)) {
      throw new TypeError(`invokeFoundationAdoption: caller routing key is forbidden at ${path}/${key}`);
    }
    assertNoRoutingKeys(child, `${path}/${key}`);
  }
}

/** Fixed, read-only adoption bridge; callers cannot select code or exports. */
export async function invokeFoundationAdoption(request) {
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("invokeFoundationAdoption: request must be an object");
  }
  const requestKeys = Object.keys(request).sort();
  if (requestKeys.length !== 2 || requestKeys[0] !== "operation" || requestKeys[1] !== "params") {
    throw new TypeError("invokeFoundationAdoption: request must contain exactly operation and params");
  }
  const { operation, params } = request;
  if (!ADOPTION_OPERATIONS.includes(operation)) {
    throw new TypeError(`invokeFoundationAdoption: unknown operation: ${String(operation)}`);
  }
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new TypeError("invokeFoundationAdoption: params must be an object");
  }
  assertNoRoutingKeys(params);
  switch (operation) {
    case "load-migration-manifest-state":
      return loadMigrationManifestState(params.root);
    case "assess-adoption-binding":
      return assessAdoptionBinding(params.manifest, params.profileId);
    case "assess-legacy-exit-list":
      return assessLegacyExitList(params.root, params.legacyItems);
    case "assess-legacy-references":
      return assessLegacyReferences(params.root, params.legacyReferences);
    case "verify-harness-surface-inventory":
      return verifyHarnessSurfaceInventory(params);
    default:
      throw new TypeError("invokeFoundationAdoption: unreachable operation");
  }
}
