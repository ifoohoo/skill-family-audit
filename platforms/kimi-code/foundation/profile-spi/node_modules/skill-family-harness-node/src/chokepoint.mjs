import path from "node:path";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { readFileContained, resolveContained } from "./paths.mjs";

/**
 * Generic read-path chokepoint.
 *
 * A read chokepoint concentrates every consumer read of a protected area
 * into one admission check: the requested target must live inside one of
 * the consumer-declared allowed roots, and — when the consumer injects an
 * identity predicate — the caller identity must be admitted. Out-of-bounds
 * targets and unauthorized identities are refused with the stable
 * read-chokepoint-rejected kind (under the registered SFC2004 code).
 *
 * Foundation owns the mechanism only: the allow-root set and the identity
 * rule are consumer-owned, and the harness never interprets any private
 * identity or path semantics.
 */

function reject(message, details) {
  return mechanismError(HARNESS_ERROR_KINDS.READ_CHOKEPOINT_REJECTED, message, details);
}

/**
 * Creates a read chokepoint handle.
 *
 * @param {string[]} allowRoots   non-empty set of absolute directory paths
 *                                that reads may address.
 * @param {(identity: {root, relPath, absolute}) => boolean} [allowIdentity]
 *                                optional consumer identity predicate;
 *                                a false return refuses the read.
 */
export function createReadChokepoint({ allowRoots, allowIdentity } = {}) {
  if (!Array.isArray(allowRoots) || allowRoots.length === 0) {
    throw new TypeError("createReadChokepoint: allowRoots must be a non-empty array of absolute directory paths");
  }
  const roots = allowRoots.map((root) => {
    if (typeof root !== "string" || root.length === 0) {
      throw new TypeError("createReadChokepoint: every allowRoot must be a non-empty path string");
    }
    return path.resolve(root);
  });
  if (allowIdentity !== undefined && typeof allowIdentity !== "function") {
    throw new TypeError("createReadChokepoint: allowIdentity must be a function or undefined");
  }

  /**
   * Proves that one read request is admitted. Input is either an absolute
   * path string or `{ root, relPath }`. Throws read-chokepoint-rejected on
   * any out-of-bounds or unauthorized request.
   * Returns `{ root, relPath, absolute }` for identity predicates and reads.
   */
  async function assertReadAllowed(input) {
    let root = null;
    let relPath = null;
    let absolute;
    if (typeof input === "string") {
      absolute = path.resolve(input);
      for (const candidate of roots) {
        // Lexical containment first; canonical containment (including
        // symlink-prefixed roots such as /var -> /private/var on macOS) is
        // proven by the same resolveContained classification the
        // { root, relPath } branch uses, so both input forms agree.
        const rel = path.relative(candidate, absolute);
        if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) continue;
        try {
          const resolved = await resolveContained(candidate, rel);
          root = candidate;
          relPath = rel;
          absolute = resolved;
          break;
        } catch {
          // The candidate does not safely contain the target (traversal or
          // link escape): try the next allowed root before rejecting.
        }
      }
      if (root === null) {
        throw reject("read target is outside every allowed root", { target: "<opaque>" });
      }
    } else if (input && typeof input === "object" && typeof input.root === "string" && typeof input.relPath === "string") {
      root = path.resolve(input.root);
      if (!roots.includes(root)) {
        throw reject("read root is not in the allowed root set", { root: "<opaque>" });
      }
      relPath = input.relPath;
      absolute = await resolveContained(root, relPath);
    } else {
      throw new TypeError("read input must be an absolute path string or { root, relPath }");
    }

    const identity = { root, relPath, absolute };
    if (allowIdentity !== undefined && allowIdentity(identity) !== true) {
      throw reject("read identity is not authorized by the consumer identity rule", {
        root: "<opaque>",
        relPath: relPath ?? "<opaque>",
      });
    }
    return identity;
  }

  /** Contained read through the chokepoint; Buffer, or string with encoding "utf8". */
  async function read(input, options) {
    const identity = await assertReadAllowed(input);
    if (typeof input === "string") {
      return readFileContained(path.dirname(identity.absolute), path.basename(identity.absolute), options);
    }
    return readFileContained(identity.root, identity.relPath, options);
  }

  return Object.freeze({ assertReadAllowed, read });
}
