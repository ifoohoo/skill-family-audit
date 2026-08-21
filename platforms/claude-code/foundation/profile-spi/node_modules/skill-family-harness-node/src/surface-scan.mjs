import { findSchemaByObject } from "skill-family-contracts";
import path from "node:path";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { readFileContained, resolveContained } from "./paths.mjs";
import { validateContractDocument } from "./validation.mjs";

const POLICY_SCHEMA_ID = findSchemaByObject("surface-scan-policy").$id;

/**
 * Generic strategy-driven surface scanner.
 *
 * The scanner consumes a surface-scan-policy contract document, applies its
 * pathPatterns against scanned relative paths and its contentPatterns
 * against scanned file contents, and fails closed on the first hit
 * (surface-scan-violation). An invalid policy or a pattern that does not
 * compile is scan-policy-invalid: a scanner that cannot run must fail, not
 * skip.
 *
 * allowedUses is carried and echoed only: the foundation never interprets
 * what an allowed use means, and a pattern hit is never weakened by it.
 * Consumers that need exemptions implement them at their own layer.
 *
 * The scanner keeps no state between calls: injecting patterns into a
 * policy and scanning again yields byte-identical results once the
 * injection is removed (injection self-test).
 */

export async function scanSurface({ root, relPaths, policy, encoding = "utf8" } = {}) {
  if (typeof root !== "string" || root.length === 0) {
    throw new TypeError("scanSurface: root must be a non-empty path");
  }
  if (!Array.isArray(relPaths)) {
    throw new TypeError("scanSurface: relPaths must be an array of root-relative path strings");
  }
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new TypeError("scanSurface: policy must be a surface-scan-policy contract document");
  }
  const checked = validateContractDocument(policy, { schemaId: POLICY_SCHEMA_ID });
  if (!checked.valid) {
    throw mechanismError(HARNESS_ERROR_KINDS.SCAN_POLICY_INVALID, "surface-scan policy document is invalid", {
      errors: checked.errors,
    });
  }

  let pathPatterns;
  let contentPatterns;
  try {
    pathPatterns = policy.pathPatterns.map((source) => new RegExp(source));
    contentPatterns = policy.contentPatterns.map((source) => new RegExp(source));
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.SCAN_POLICY_INVALID,
      "surface-scan policy pattern does not compile",
      { cause: cause && cause.message ? cause.message : String(cause) },
    );
  }

  const scanned = [];
  let bytes = 0;
  for (const relPath of relPaths) {
    if (typeof relPath !== "string" || relPath.length === 0) {
      throw new TypeError("scanSurface: every relPath entry must be a non-empty string");
    }
    await resolveContained(root, relPath);
    // A missing scanned resource fails closed too: the consumer declared the
    // surface, and an unsatisfiable scan list must not silently shrink it.
    const readResult = await readFileContained(root, relPath, { encoding });
    const text = Buffer.isBuffer(readResult) ? readResult.toString("utf8") : readResult;
    bytes += Buffer.byteLength(text, "utf8");
    scanned.push(relPath.split(path.sep).join("/"));
    for (const regex of pathPatterns) {
      if (regex.test(relPath.split(path.sep).join("/"))) {
        throw mechanismError(HARNESS_ERROR_KINDS.SURFACE_SCAN_VIOLATION, "scan matched a forbidden path pattern", {
          path: relPath.split(path.sep).join("/"),
          pattern: regex.source,
          kindOfHit: "path",
        });
      }
    }
    for (const regex of contentPatterns) {
      if (regex.test(text)) {
        throw mechanismError(HARNESS_ERROR_KINDS.SURFACE_SCAN_VIOLATION, "scan matched a forbidden content pattern", {
          path: relPath.split(path.sep).join("/"),
          pattern: regex.source,
          kindOfHit: "content",
        });
      }
    }
  }
  return Object.freeze({ scanned, bytes, policy: structuredClone(policy) });
}
