import { lstat, mkdir, open, realpath, rename, rm } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import path from "node:path";
import process from "node:process";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { resolveContained } from "./paths.mjs";

/**
 * Atomic contained writes.
 *
 * Guarantees:
 * - The target path is containment-checked first (path traversal, symlink
 *   escape, realpath escape all reject before any write happens).
 * - Content is written to a fresh temporary file in the target's own
 *   directory (same filesystem), fsynced, then renamed over the target.
 *   rename is atomic on POSIX, so readers observe either the complete old
 *   content or the complete new content, never a partial file.
 * - On any failure the temporary file is removed and the target keeps its
 *   previous content (or stays absent). A failed write never leaves a
 *   half-written target behind.
 */

function assertWritableData(data) {
  const ok =
    typeof data === "string" ||
    Buffer.isBuffer(data) ||
    ArrayBuffer.isView(data) ||
    data instanceof ArrayBuffer;
  if (!ok) {
    throw new TypeError(
      "writeFileAtomic: data must be a string, Buffer, TypedArray, DataView, or ArrayBuffer",
    );
  }
}

async function removeQuiet(candidate) {
  try {
    await rm(candidate, { force: true });
  } catch {
    // Cleanup is best-effort; the original failure is the one that counts.
  }
}

/**
 * Atomically writes `data` to `relPath` inside `root`.
 * Options: { mode } (file mode for a newly created target, default 0o644).
 * Returns the absolute contained target path that was written.
 * Throws HarnessError (SFC2004) with a stable details.kind on failure.
 */
export async function writeFileAtomic(root, relPath, data, { mode = 0o644 } = {}) {
  assertWritableData(data);
  let target = await resolveContained(root, relPath);
  // When the final component is a symlink to a contained target, write to the
  // real target: rename would otherwise replace the link itself instead of
  // updating the resource it points at. resolveContained already proved the
  // real target stays inside the root.
  try {
    const finalStat = await lstat(target);
    if (finalStat.isSymbolicLink()) {
      target = await realpath(target);
    }
  } catch {
    // Not yet existing: the lexical target is the write destination.
  }
  const dir = path.dirname(target);
  try {
    await mkdir(dir, { recursive: true });
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED,
      `cannot prepare contained directory: ${cause && cause.code ? cause.code : "unknown"}`,
      { input: relPath },
    );
  }
  const tmpName = `.${path.basename(target)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  const tmpPath = path.join(dir, tmpName);
  let handle = null;
  try {
    // wx => O_CREAT|O_EXCL: the temporary name is fresh and never clobbers.
    handle = await open(tmpPath, "wx", mode);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(tmpPath, target);
  } catch (cause) {
    if (handle) {
      try {
        await handle.close();
      } catch {
        // Closing on the error path is best-effort.
      }
    }
    await removeQuiet(tmpPath);
    throw mechanismError(
      HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED,
      `atomic write failed: ${cause && cause.code ? cause.code : "unknown"}`,
      { input: relPath },
    );
  }
  // Best-effort directory fsync so the rename itself is durable; platforms
  // without directory fsync simply skip it.
  try {
    const dirHandle = await open(dir, "r");
    try {
      await dirHandle.sync();
    } finally {
      await dirHandle.close();
    }
  } catch {
    // Durability hardening only; the atomicity guarantee already holds.
  }
  return target;
}
