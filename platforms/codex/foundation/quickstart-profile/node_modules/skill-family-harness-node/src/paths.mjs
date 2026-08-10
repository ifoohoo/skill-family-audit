import { lstat, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";

/**
 * Path containment.
 *
 * Every filesystem operation in the harness goes through resolveContained,
 * which rejects three escape classes with stable, distinct kinds (all under
 * the registered SFC2004 code):
 *
 * 1. path-traversal   — the lexically resolved target leaves the root
 *                       (`..` segments, or any absolute input).
 * 2. symlink-escape   — the final path component is a symbolic link whose
 *                       real target lies outside the root.
 * 3. realpath-escape  — the canonical (realpath) resolution of the target,
 *                       including intermediate directories, lies outside the
 *                       canonical root; this catches symlinked intermediate
 *                       directories and chained links.
 *
 * Inputs that only make sense on another operating system (Windows drive
 * paths, UNC paths, backslash separators on POSIX) are rejected before any
 * resolution: ambiguous inputs never reach the filesystem.
 *
 * The containment guarantee is evaluated at call time (TOCTOU note: a
 * process that can mutate the workspace between the check and the follow-up
 * filesystem call is outside this mechanism's control; the guarantee is that
 * the harness itself never performs an unchecked access).
 */

const WINDOWS_DRIVE_PATTERN = /^[A-Za-z]:/;
const WINDOWS_UNC_PATTERN = /^\\\\/;
const POSIX_UNC_PATTERN = /^\/\//;

/**
 * Classifies one candidate relative path without touching the filesystem.
 * Returns { ok: true } or { ok: false, kind } where kind is one of the
 * stable HARNESS_ERROR_KINDS values. Pure function of (input, platform), so
 * the Windows-facing rules are testable on any host.
 */
export function classifyPathInput(input, platform = process.platform) {
  if (typeof input !== "string") {
    return { ok: false, kind: HARNESS_ERROR_KINDS.INVALID_PATH };
  }
  if (input.length === 0) {
    return { ok: false, kind: HARNESS_ERROR_KINDS.INVALID_PATH };
  }
  if (input.includes("\0")) {
    return { ok: false, kind: HARNESS_ERROR_KINDS.INVALID_PATH };
  }
  if (platform === "win32") {
    // Native separators are fine on Windows; containment is decided by the
    // lexical + real checks. UNC paths address remote machines and are never
    // containable; rooted paths (`\x`, `/x`, `<drive>:\x`) are absolute.
    if (WINDOWS_UNC_PATTERN.test(input)) {
      return { ok: false, kind: HARNESS_ERROR_KINDS.UNC_PATH };
    }
    if (input.startsWith("\\") || input.startsWith("/")) {
      return { ok: false, kind: HARNESS_ERROR_KINDS.ABSOLUTE_PATH };
    }
    if (WINDOWS_DRIVE_PATTERN.test(input)) {
      // `<drive>:\x` is absolute; the root-relative check would reject it too, but
      // the explicit kind keeps the interception observable.
      if (input.charAt(1) === ":" && /[\\/]/.test(input.charAt(2))) {
        return { ok: false, kind: HARNESS_ERROR_KINDS.ABSOLUTE_PATH };
      }
      // Drive-relative forms (`C:foo`) depend on a per-drive working
      // directory that this runtime never tracks: ambiguous, therefore
      // rejected.
      return { ok: false, kind: HARNESS_ERROR_KINDS.WINDOWS_DRIVE_PATH };
    }
    return { ok: true };
  }
  // POSIX (and every non-Windows host): a path is root-relative or nothing.
  if (WINDOWS_DRIVE_PATTERN.test(input)) {
    return { ok: false, kind: HARNESS_ERROR_KINDS.WINDOWS_DRIVE_PATH };
  }
  if (WINDOWS_UNC_PATTERN.test(input)) {
    return { ok: false, kind: HARNESS_ERROR_KINDS.UNC_PATH };
  }
  if (POSIX_UNC_PATTERN.test(input)) {
    return { ok: false, kind: HARNESS_ERROR_KINDS.UNC_PATH };
  }
  if (input.includes("\\")) {
    // Backslash is a Windows separator; on POSIX it would silently become
    // part of a filename. Cross-platform inputs must be unambiguous.
    return { ok: false, kind: HARNESS_ERROR_KINDS.WINDOWS_PATH };
  }
  if (path.posix.isAbsolute(input)) {
    return { ok: false, kind: HARNESS_ERROR_KINDS.ABSOLUTE_PATH };
  }
  return { ok: true };
}

function insideRoot(rootReal, candidate) {
  const rel = path.relative(rootReal, candidate);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

// Anchors may coincide with the root itself (e.g. a top-level file whose
// deepest existing ancestor is the workspace root); targets may not.
function insideOrEqualRoot(rootReal, candidate) {
  const rel = path.relative(rootReal, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

async function canonicalRoot(root) {
  let rootReal;
  try {
    rootReal = await realpath(root);
  } catch {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_ROOT,
      "workspace root does not resolve to an existing path",
      { root: "<opaque>" },
    );
  }
  let rootStat;
  try {
    rootStat = await stat(rootReal);
  } catch {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_ROOT,
      "workspace root cannot be inspected",
      { root: "<opaque>" },
    );
  }
  if (!rootStat.isDirectory()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_ROOT,
      "workspace root is not a directory",
      { root: "<opaque>" },
    );
  }
  return rootReal;
}

async function deepestExistingAncestor(rootReal, absPath) {
  let current = absPath;
  const missing = [];
  while (current.length >= rootReal.length) {
    try {
      await lstat(current);
      return { anchor: current, missing };
    } catch {
      missing.unshift(path.basename(current));
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  // Unreachable for paths lexically inside an existing root; keep a coded
  // failure instead of a crash.
  throw mechanismError(
    HARNESS_ERROR_KINDS.INVALID_ROOT,
    "workspace root disappeared during containment resolution",
  );
}

/**
 * Resolves `relPath` against `root` and proves the target stays inside.
 * Returns the absolute, lexically resolved path (strictly inside the root).
 * Throws HarnessError (SFC2004) with a stable details.kind on any violation.
 */
export async function resolveContained(root, relPath) {
  const classification = classifyPathInput(relPath);
  if (!classification.ok) {
    throw mechanismError(
      classification.kind,
      `path rejected before resolution (kind: ${classification.kind})`,
      { input: typeof relPath === "string" ? relPath : typeof relPath },
    );
  }
  const rootReal = await canonicalRoot(root);
  const resolved = path.resolve(rootReal, relPath);
  if (resolved === rootReal) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_PATH,
      "path must address a resource strictly inside the workspace root",
    );
  }
  if (!insideRoot(rootReal, resolved)) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.PATH_TRAVERSAL,
      "resolved path leaves the workspace root",
      { input: relPath },
    );
  }

  // Escape class 2: the final component itself is a symlink pointing out.
  let finalStat;
  try {
    finalStat = await lstat(resolved);
  } catch (cause) {
    if (cause && cause.code !== "ENOENT" && cause.code !== "ENOTDIR") {
      throw mechanismError(HARNESS_ERROR_KINDS.READ_FAILED, `path cannot be inspected: ${cause.code}`);
    }
    finalStat = null;
  }
  if (finalStat && finalStat.isSymbolicLink()) {
    let realTarget;
    try {
      realTarget = await realpath(resolved);
    } catch {
      // A broken symlink has no determinable target: never usable.
      throw mechanismError(
        HARNESS_ERROR_KINDS.SYMLINK_ESCAPE,
        "symbolic link target does not resolve; treated as an escape",
        { input: relPath },
      );
    }
    if (!insideRoot(rootReal, realTarget)) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.SYMLINK_ESCAPE,
        "final path component is a symbolic link escaping the workspace root",
        { input: relPath },
      );
    }
  }

  // Escape class 3: canonical resolution (any intermediate symlink chain)
  // must stay inside the canonical root.
  const { anchor, missing } = await deepestExistingAncestor(rootReal, resolved);
  let anchorReal;
  try {
    anchorReal = await realpath(anchor);
  } catch {
    throw mechanismError(
      HARNESS_ERROR_KINDS.REALPATH_ESCAPE,
      "anchor directory vanished during canonical resolution",
      { input: relPath },
    );
  }
  if (!insideOrEqualRoot(rootReal, anchorReal)) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.REALPATH_ESCAPE,
      "canonical anchor of the target lies outside the workspace root",
      { input: relPath },
    );
  }
  const canonical = path.join(anchorReal, ...missing);
  if (!insideRoot(rootReal, canonical)) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.REALPATH_ESCAPE,
      "canonical target path leaves the workspace root",
      { input: relPath },
    );
  }
  return resolved;
}

/**
 * Contained read. Returns the file content as a Buffer (utf8 string when
 * encoding is "utf8"). Missing resources surface as SFC2004 with the stable
 * missing-resource kind instead of a raw fs error.
 */
export async function readFileContained(root, relPath, { encoding } = {}) {
  const target = await resolveContained(root, relPath);
  try {
    return encoding === undefined
      ? await readFile(target)
      : await readFile(target, encoding);
  } catch (cause) {
    if (cause && cause.code === "ENOENT") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.MISSING_RESOURCE,
        "contained resource does not exist",
        { input: relPath },
      );
    }
    if (cause && cause.code === "EISDIR") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.READ_FAILED,
        "contained resource is a directory",
        { input: relPath },
      );
    }
    throw mechanismError(
      HARNESS_ERROR_KINDS.READ_FAILED,
      `contained read failed: ${cause && cause.code ? cause.code : "unknown"}`,
      { input: relPath },
    );
  }
}
