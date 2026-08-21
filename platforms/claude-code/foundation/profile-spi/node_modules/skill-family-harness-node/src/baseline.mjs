import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";

/**
 * Frozen-baseline materialization.
 *
 * materializeBaseline copies a frozen baseline directory into a fresh
 * temporary directory and proves byte fidelity twice: once before copying
 * (the source digest must equal the frozen digest) and once after copying
 * (the copy must still equal the frozen digest, which also catches any
 * baseline change that happened mid-materialization). Symbolic links are
 * rejected anywhere inside the baseline: a baseline is a real directory
 * tree whose bytes are the contract.
 *
 * Fail-closed semantics: any digest mismatch, any mid-materialization
 * change, and any guard rejection abort before the workspace is delivered;
 * the partial copy is removed.
 *
 * The test hook `beforePostDigest` is module-level test instrumentation in
 * the same spirit as __setStateStoreTestHooks: it is deliberately not
 * re-exported by index.mjs.
 */

const TEST_HOOKS = { beforePostDigest: undefined };

/** Test-only hook registry. Never imported through the public surface. */
export function __setBaselineTestHooks(hooks) {
  if (hooks === null) {
    TEST_HOOKS.beforePostDigest = undefined;
    return;
  }
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) {
    throw new TypeError("baseline test hooks must be an object or null");
  }
  const hook = hooks.beforePostDigest;
  TEST_HOOKS.beforePostDigest = typeof hook === "function" ? hook : undefined;
}

async function runTestHook(name, root) {
  const hook = TEST_HOOKS[name];
  if (hook !== undefined) await hook(root);
}

const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Deterministic directory digest: SHA-256 over a canonical listing of the
 * tree. Relative paths use "/" separators, entries are visited in sorted
 * order, and each entry contributes its relative path and its own file
 * SHA-256. Symlinks and non-regular entries are rejected. An empty tree has
 * the SHA-256 of the empty string.
 */
export async function computeDirectoryDigest(rootDir) {
  if (typeof rootDir !== "string" || rootDir.length === 0) {
    throw new TypeError("computeDirectoryDigest: rootDir must be a non-empty path");
  }
  const entries = await collectTree(rootDir);
  const hasher = createHash("sha256");
  for (const entry of entries) {
    const fileDigest = createHash("sha256").update(entry.bytes).digest("hex");
    hasher.update(`${entry.rel}\n${fileDigest}\n`);
  }
  return hasher.digest("hex");
}

async function collectTree(rootDir) {
  const entries = [];
  async function walk(relative, absolute) {
    let stats;
    try {
      stats = await lstat(absolute);
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.BASELINE_MISMATCH,
        "baseline entry cannot be inspected",
        { path: relative, code: cause && cause.code ? cause.code : "unknown" },
      );
    }
    if (stats.isSymbolicLink()) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.INVALID_ROOT,
        "baseline must be a real directory tree without symbolic links",
        { path: relative },
      );
    }
    if (stats.isDirectory()) {
      let names;
      try {
        names = await readdir(absolute);
      } catch (cause) {
        throw mechanismError(
          HARNESS_ERROR_KINDS.BASELINE_MISMATCH,
          "baseline directory cannot be listed",
          { path: relative, code: cause && cause.code ? cause.code : "unknown" },
        );
      }
      names.sort();
      for (const name of names) {
        await walk(relative === "" ? name : `${relative}/${name}`, path.join(absolute, name));
      }
      return;
    }
    if (stats.isFile()) {
      let bytes;
      try {
        bytes = await readFile(absolute);
      } catch (cause) {
        throw mechanismError(
          HARNESS_ERROR_KINDS.BASELINE_MISMATCH,
          "baseline file cannot be read",
          { path: relative, code: cause && cause.code ? cause.code : "unknown" },
        );
      }
      entries.push({ rel: relative, bytes });
      return;
    }
    throw mechanismError(
      HARNESS_ERROR_KINDS.INVALID_ROOT,
      "baseline entry is neither a regular file nor a directory",
      { path: relative },
    );
  }
  await walk("", rootDir);
  return entries;
}

async function copyTree(rootDir, targetRoot) {
  const entries = await collectTree(rootDir);
  for (const entry of entries) {
    const segments = entry.rel.split("/");
    const dest = path.join(targetRoot, ...segments);
    await mkdir(path.dirname(dest), { recursive: true });
    await writeFile(dest, entry.bytes);
  }
}

/**
 * Materializes a frozen baseline into a fresh temporary directory.
 * Returns the absolute root path of the copy. The caller owns the returned
 * directory and is responsible for cleanup (TemporaryWorkspace.fromBaseline
 * wires this into the workspace lifecycle).
 */
export async function materializeBaseline({ baselineDir, baselineDigest, prefix = "sf-baseline-" } = {}) {
  if (typeof baselineDir !== "string" || baselineDir.length === 0) {
    throw new TypeError("materializeBaseline: baselineDir must be a non-empty path");
  }
  if (typeof baselineDigest !== "string" || !DIGEST_PATTERN.test(baselineDigest)) {
    throw new TypeError("materializeBaseline: baselineDigest must be a 64-character lowercase sha256 hex digest");
  }
  if (typeof prefix !== "string" || prefix.length === 0 || prefix.includes("/") || prefix.includes("\0")) {
    throw new TypeError("materializeBaseline: prefix must be a non-empty, separator-free string");
  }

  const preDigest = await computeDirectoryDigest(baselineDir);
  if (preDigest !== baselineDigest) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.BASELINE_MISMATCH,
      "baseline directory digest does not match the frozen baseline digest",
      { expected: baselineDigest, observed: preDigest, phase: "pre-materialization" },
    );
  }

  let root;
  try {
    root = await mkdtemp(path.join(os.tmpdir(), prefix));
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.WORKSPACE_CREATE_FAILED,
      `cannot create baseline workspace: ${cause && cause.code ? cause.code : "unknown"}`,
    );
  }
  try {
    await copyTree(baselineDir, root);
    await runTestHook("beforePostDigest", root);
    // Post-materialization fidelity is checked on both sides: the copy must
    // equal the frozen digest (copy corruption), and the source must still
    // equal the frozen digest (any baseline change while materializing).
    const copyDigest = await computeDirectoryDigest(root);
    const sourceDigest = await computeDirectoryDigest(baselineDir);
    if (copyDigest !== baselineDigest || sourceDigest !== baselineDigest) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.BASELINE_MISMATCH,
        "post-materialization digest does not match the frozen baseline digest",
        {
          expected: baselineDigest,
          copyDigest,
          sourceDigest,
          phase: "post-materialization",
        },
      );
    }
    return root;
  } catch (cause) {
    await rm(root, { recursive: true, force: true, maxRetries: 3 }).catch(() => {});
    throw cause;
  }
}
