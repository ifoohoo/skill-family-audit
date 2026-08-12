import { createHash } from "node:crypto";
import path from "node:path";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { resolveContained, readFileContained } from "./paths.mjs";

/**
 * Resource closure and digests.
 *
 * A closure bounds the read/write scope of an operation: the normalized,
 * containment-verified set of input and output resources, each with a
 * deterministic sha256 content digest, plus one digest over the whole set.
 *
 * Determinism rules: entries are de-duplicated on their normalized relative
 * path, sorted by UTF-16 code units, and serialized with a fixed key order;
 * equal resource sets always produce the equal closure digest.
 */

const CLOSURE_KIND = "skill-family.resource-closure";
const CLOSURE_SCHEMA_VERSION = 1;
const DIGEST_ALGORITHM = "sha256";
const ROLES = Object.freeze(["input", "output"]);

/** sha256 hex digest of raw bytes. */
export function digestBytes(bytes) {
  return createHash(DIGEST_ALGORITHM).update(bytes).digest("hex");
}

function normalizeResourcePath(relPath) {
  if (typeof relPath !== "string" || relPath.length === 0 || relPath.includes("\0")) {
    throw new TypeError("computeResourceClosure: every resource path must be a non-empty string");
  }
  const normalized = path.posix.normalize(relPath.replaceAll("\\", "/"));
  if (normalized === ".." || normalized.startsWith("../") || path.posix.isAbsolute(normalized)) {
    // Lexical escape inside a closure declaration: reject before any IO.
    throw mechanismError(
      HARNESS_ERROR_KINDS.PATH_TRAVERSAL,
      "closure resource path leaves the workspace root",
      { input: relPath },
    );
  }
  return normalized === "." ? "" : normalized;
}

/**
 * Computes the resource closure of `resources` relative to `root`.
 *
 * resources: [{ path, role }] with role "input" | "output".
 *  - input entries must exist; their bytes are read through the containment
 *    layer and digested (missing input => SFC2004 missing-resource).
 *  - output entries may not exist yet; existing outputs are digested,
 *    absent outputs are recorded with exists=false and digest=null.
 *
 * Returns { schemaVersion, kind, digestAlgorithm, digest, resources } where
 * resources is the sorted array of { path, role, exists, sha256 }.
 */
export async function computeResourceClosure({ root, resources } = {}) {
  if (!root || typeof root !== "string") {
    throw new TypeError("computeResourceClosure: root must be a directory path string");
  }
  if (!Array.isArray(resources)) {
    throw new TypeError("computeResourceClosure: resources must be an array");
  }
  const byPath = new Map();
  for (const entry of resources) {
    if (!entry || typeof entry !== "object") {
      throw new TypeError("computeResourceClosure: every resource entry must be an object");
    }
    if (!ROLES.includes(entry.role)) {
      throw new TypeError(
        `computeResourceClosure: role must be one of ${ROLES.join(", ")}`,
      );
    }
    const normalized = normalizeResourcePath(entry.path);
    if (normalized === "") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.INVALID_PATH,
        "closure resource path must address a resource strictly inside the workspace root",
      );
    }
    const existing = byPath.get(normalized);
    if (existing && existing.role !== entry.role) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.CLOSURE_CONFLICT,
        `resource declared with conflicting roles: ${normalized}`,
        { path: normalized },
      );
    }
    if (!existing) {
      byPath.set(normalized, { path: normalized, role: entry.role });
    }
  }

  const records = [];
  for (const normalized of [...byPath.keys()].sort()) {
    const record = byPath.get(normalized);
    // Containment proof: resolve through the same layer as every other
    // filesystem access (traversal, symlink, and realpath checks included).
    await resolveContained(root, normalized);
    if (record.role === "input") {
      const bytes = await readFileContained(root, normalized);
      records.push({ path: normalized, role: record.role, exists: true, sha256: digestBytes(bytes) });
    } else {
      let bytes;
      try {
        bytes = await readFileContained(root, normalized);
      } catch (cause) {
        if (cause && cause.details && cause.details.kind === HARNESS_ERROR_KINDS.MISSING_RESOURCE) {
          records.push({ path: normalized, role: record.role, exists: false, sha256: null });
          continue;
        }
        throw cause;
      }
      records.push({ path: normalized, role: record.role, exists: true, sha256: digestBytes(bytes) });
    }
  }

  const canonical = JSON.stringify({
    kind: CLOSURE_KIND,
    schemaVersion: CLOSURE_SCHEMA_VERSION,
    digestAlgorithm: DIGEST_ALGORITHM,
    resources: records.map((record) => ({
      path: record.path,
      role: record.role,
      exists: record.exists,
      sha256: record.sha256,
    })),
  });
  return {
    schemaVersion: CLOSURE_SCHEMA_VERSION,
    kind: CLOSURE_KIND,
    digestAlgorithm: DIGEST_ALGORITHM,
    digest: digestBytes(Buffer.from(canonical, "utf8")),
    resources: records,
  };
}

/**
 * Whether a closure already bounds `relPath` (lexical normalization only, no
 * filesystem access).
 */
export function closureContains(closure, relPath) {
  if (!closure || !Array.isArray(closure.resources)) {
    throw new TypeError("closureContains: closure must be a computed closure object");
  }
  let normalized;
  try {
    normalized = normalizeResourcePath(relPath);
  } catch {
    return false;
  }
  if (normalized === "") return false;
  return closure.resources.some((record) => record.path === normalized);
}
