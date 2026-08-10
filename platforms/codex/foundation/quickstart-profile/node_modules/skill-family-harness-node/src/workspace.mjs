import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { readFileContained, resolveContained } from "./paths.mjs";
import { writeFileAtomic } from "./atomic.mjs";

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
    try {
      const root = await mkdtemp(path.join(os.tmpdir(), prefix));
      return new TemporaryWorkspace(root);
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.WORKSPACE_CREATE_FAILED,
        `cannot create temporary workspace: ${cause && cause.code ? cause.code : "unknown"}`,
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
      await rm(this.#root, { recursive: true, force: true, maxRetries: 3 });
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

/** Creates a TemporaryWorkspace under the system temporary directory. */
export async function createTemporaryWorkspace(options) {
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
