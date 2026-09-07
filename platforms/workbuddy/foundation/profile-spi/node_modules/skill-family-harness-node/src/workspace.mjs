import fsPromises from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { materializeBaseline } from "./baseline.mjs";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { readFileContained, resolveContained } from "./paths.mjs";
import { writeFileAtomic } from "./atomic.mjs";

const CLEANUP_OPTIONS = { recursive: true, force: true, maxRetries: 3 };

async function canonicalizeCreatedRoot(root, label) {
  try {
    return await fsPromises.realpath(root);
  } catch (cause) {
    // The root was created/materialized before canonicalization failed. Keep
    // the existing create-failed contract while reporting cleanup failure as
    // part of the same mechanism error instead of hiding it.
    let cleanupCode;
    try {
      await fsPromises.rm(root, CLEANUP_OPTIONS);
    } catch (cleanupCause) {
      cleanupCode = cleanupCause && cleanupCause.code ? cleanupCause.code : "unknown";
    }
    const code = cause && cause.code ? cause.code : "unknown";
    throw mechanismError(
      HARNESS_ERROR_KINDS.WORKSPACE_CREATE_FAILED,
      `cannot canonicalize ${label}: ${code}`,
      {
        code,
        ...(cleanupCode ? { cleanup: { code: cleanupCode } } : {}),
      },
    );
  }
}

async function createCanonicalTemporaryRoot(prefix, label) {
  let root;
  try {
    root = await fsPromises.mkdtemp(path.join(os.tmpdir(), prefix));
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.WORKSPACE_CREATE_FAILED,
      `cannot create ${label}: ${cause && cause.code ? cause.code : "unknown"}`,
    );
  }
  return canonicalizeCreatedRoot(root, label);
}

/**
 * Auto-cleaning temporary workspaces.
 *
 * A TemporaryWorkspace owns one mkdtemp directory under the operating
 * system's temporary directory. Every access goes through the containment
 * layer, and dispose() removes the whole tree. withTemporaryWorkspace
 * guarantees cleanup on the exception path as well.
 */
export class TemporaryWorkspace {
  #root;
  #disposed;

  constructor(root) {
    this.#root = root;
    this.#disposed = false;
  }

  /** Creates a fresh workspace: { prefix } optional, default "sf-harness-". */
  static async create({ prefix = "sf-harness-" } = {}) {
    if (typeof prefix !== "string" || prefix.length === 0 || prefix.includes("/") || prefix.includes("\0")) {
      throw new TypeError("TemporaryWorkspace.create: prefix must be a non-empty, separator-free string");
    }
    const root = await createCanonicalTemporaryRoot(prefix, "temporary workspace");
    return new TemporaryWorkspace(root);
  }

  /**
   * Materializes a frozen baseline into a fresh workspace (FND-ADR-009).
   *
   * The baseline digest is recomputed before materialization (mismatch fails
   * closed with baseline-mismatch) and again after copying (catching any
   * mid-materialization change or copy corruption). The resulting workspace
   * keeps the standard containment semantics; its directory is unique via
   * the mkdtemp random suffix.
   *
   * `contentGuard(predicate)` runs after materialization and before
   * delivery; the consumer injects residual-content judgment. The default
   * (no guard) is to ALLOW: byte fidelity is the mechanism contract, and
   * "what counts as residual" is consumer-owned. A rejecting guard fails
   * closed with content-guard-rejected and the copy is disposed.
   */
  static async fromBaseline({ baselineDir, baselineDigest, prefix = "sf-baseline-", contentGuard } = {}) {
    if (contentGuard !== undefined && typeof contentGuard !== "function") {
      throw new TypeError("TemporaryWorkspace.fromBaseline: contentGuard must be a function or undefined");
    }
    const materializedRoot = await materializeBaseline({ baselineDir, baselineDigest, prefix });
    const root = await canonicalizeCreatedRoot(materializedRoot, "baseline workspace");
    const workspace = new TemporaryWorkspace(root);
    if (contentGuard === undefined) return workspace;
    try {
      await contentGuard(workspace);
      return workspace;
    } catch (cause) {
      await workspace.dispose().catch(() => {});
      if (cause && cause.details?.kind === HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED) throw cause;
      throw mechanismError(
        HARNESS_ERROR_KINDS.CONTENT_GUARD_REJECTED,
        "content guard rejected the materialized baseline workspace",
        { cause: cause && cause.message ? cause.message : String(cause) },
      );
    }
  }

  /** Absolute workspace root (a system temporary directory). */
  get root() {
    return this.#root;
  }

  get disposed() {
    return this.#disposed;
  }

  #assertAlive() {
    if (this.#disposed) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.WORKSPACE_DISPOSED,
        "temporary workspace is already disposed",
      );
    }
  }

  /** Containment-checked resolution of a workspace-relative path. */
  async resolve(relPath) {
    this.#assertAlive();
    return resolveContained(this.#root, relPath);
  }

  /** Atomic contained write; returns the absolute target path. */
  async writeFile(relPath, data, options) {
    this.#assertAlive();
    return writeFileAtomic(this.#root, relPath, data, options);
  }

  /** Contained read; returns Buffer, or string when encoding is "utf8". */
  async readFile(relPath, options) {
    this.#assertAlive();
    return readFileContained(this.#root, relPath, options);
  }

  /**
   * Removes the workspace tree. Idempotent; a disposal failure surfaces as
   * SFC2004 (workspace-dispose-failed) but never resurrects the workspace.
   */
  async dispose() {
    if (this.#disposed) return;
    this.#disposed = true;
    try {
      await fsPromises.rm(this.#root, { recursive: true, force: true, maxRetries: 3 });
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.WORKSPACE_DISPOSE_FAILED,
        `temporary workspace cleanup failed: ${cause && cause.code ? cause.code : "unknown"}`,
      );
    }
  }

  /** Resource-management hook (`await using workspace` where supported). */
  async [Symbol.asyncDispose]() {
    await this.dispose();
  }
}

/**
 * Creates a TemporaryWorkspace under the system temporary directory.
 * Passing `{ baseline: { dir, digest, prefix, contentGuard } }` materializes
 * a frozen baseline instead of an empty directory (equivalent to
 * TemporaryWorkspace.fromBaseline).
 */
export async function createTemporaryWorkspace(options) {
  if (options && options.baseline !== undefined) {
    const baseline = options.baseline;
    if (!baseline || typeof baseline !== "object" || Array.isArray(baseline)) {
      throw new TypeError("createTemporaryWorkspace: options.baseline must be an object");
    }
    return TemporaryWorkspace.fromBaseline({
      baselineDir: baseline.baselineDir,
      baselineDigest: baseline.baselineDigest,
      prefix: baseline.prefix ?? options.prefix,
      contentGuard: baseline.contentGuard,
    });
  }
  return TemporaryWorkspace.create(options);
}

/**
 * Runs `fn(workspace)` on a fresh workspace and disposes it afterwards,
 * whether fn returns or throws. Returns fn's result.
 */
export async function withTemporaryWorkspace(fn, options) {
  if (typeof fn !== "function") {
    throw new TypeError("withTemporaryWorkspace: fn must be a function");
  }
  const workspace = await createTemporaryWorkspace(options);
  try {
    return await fn(workspace);
  } finally {
    await workspace.dispose();
  }
}
