import { createHash, randomBytes } from "node:crypto";
import { constants as FS_CONSTANTS } from "node:fs";
import { link, lstat, mkdir, open, realpath, rename, rm, unlink } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { HARNESS_ERROR_KINDS, mechanismError } from "./errors.mjs";
import { resolveContained } from "./paths.mjs";

/**
 * `writeFileAtomic` is the compatibility convenience writer. It provides an
 * atomic namespace replacement, but deliberately does not claim exclusive
 * publication, strict post-commit verification, or durable directory sync.
 * Callers that require those guarantees must use `publishFileExclusive` or
 * `replaceFileAtomic`.
 */

let testHooks = null;

function assertWritableData(data, operation) {
  const ok =
    typeof data === "string" ||
    Buffer.isBuffer(data) ||
    ArrayBuffer.isView(data) ||
    data instanceof ArrayBuffer;
  if (!ok) {
    throw new TypeError(
      `${operation}: data must be a string, Buffer, TypedArray, DataView, or ArrayBuffer`,
    );
  }
}

function normalizeMode(mode) {
  if (!Number.isInteger(mode) || mode < 0 || mode > 0o777) {
    throw new TypeError("file mode must be an integer between 0 and 0o777");
  }
  return mode;
}

function bytesOf(data) {
  if (typeof data === "string") return Buffer.from(data);
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

async function snapshotRegularTarget(target, expectedStats = null) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  const before = await lstat(target);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.nlink !== 1 ||
    (expectedStats !== null && !sameIdentity(before, expectedStats))
  ) {
    return null;
  }
  const handle = await open(target, FS_CONSTANTS.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened) || !opened.isFile() || opened.nlink !== 1) return null;
    const bytes = await handle.readFile();
    return {
      stats: opened,
      mode: opened.mode & 0o777,
      sha256: digest(bytes),
      bytes: bytes.length,
    };
  } finally {
    await handle.close();
  }
}

async function removeQuiet(candidate) {
  try {
    await rm(candidate, { force: true });
  } catch {
    // Compatibility cleanup is intentionally best-effort.
  }
}

async function runTestHook(name, context) {
  if (typeof testHooks?.[name] === "function") await testHooks[name](context);
}

async function strictTarget(root, relPath, { target = "optional" } = {}) {
  const lexical = await resolveContained(root, relPath);
  const rootReal = await realpath(root);
  const relative = path.relative(rootReal, lexical);
  const segments = relative.split(path.sep);
  let cursor = rootReal;
  for (let index = 0; index < segments.length - 1; index += 1) {
    cursor = path.join(cursor, segments[index]);
    let stats;
    try {
      stats = await lstat(cursor);
    } catch (cause) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.INVALID_ROOT,
        "strict file operation requires every parent directory to exist",
        { input: relPath, code: cause?.code },
      );
    }
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
        "strict file operation requires real intermediate directories",
        { input: relPath },
      );
    }
  }
  let stats = null;
  try {
    stats = await lstat(lexical);
  } catch (cause) {
    if (cause?.code !== "ENOENT") throw cause;
  }
  if (stats?.isSymbolicLink()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict file operation refuses a symbolic-link target",
      { input: relPath },
    );
  }
  if (target === "absent" && stats !== null) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT,
      "exclusive publication target already exists",
      { input: relPath, publicationState: "not-published" },
    );
  }
  let targetFingerprint = null;
  if (target === "regular") {
    if (stats === null || !stats.isFile() || stats.nlink !== 1) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
        "atomic replacement requires one existing ordinary file",
        { input: relPath, publicationState: "not-published" },
      );
    }
    targetFingerprint = await snapshotRegularTarget(lexical, stats);
    if (targetFingerprint === null) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
        "atomic replacement target changed during initial inspection",
        { input: relPath, publicationState: "not-published" },
      );
    }
  }
  if (target === "regular-or-absent") {
    if (stats !== null && (!stats.isFile() || stats.nlink !== 1)) {
      throw mechanismError(
        HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
        "atomic publication requires an absent target or one existing ordinary file",
        { input: relPath, publicationState: "not-published" },
      );
    }
    if (stats !== null) {
      targetFingerprint = await snapshotRegularTarget(lexical, stats);
      if (targetFingerprint === null) {
        throw mechanismError(
          HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
          "atomic publication target changed during initial inspection",
          { input: relPath, publicationState: "not-published" },
        );
      }
    }
  }
  const directory = path.dirname(lexical);
  const directoryStats = await lstat(directory);
  if (directoryStats.isSymbolicLink() || !directoryStats.isDirectory()) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict file operation requires a real parent directory",
      { input: relPath },
    );
  }
  return {
    targetPath: lexical,
    targetStats: stats,
    targetFingerprint,
    directory,
    directoryStats,
    directoryReal: await realpath(directory),
  };
}

async function revalidateDirectory(directory, expectedStats, expectedReal, relPath) {
  const current = await lstat(directory);
  const currentMode = current.mode & 0o777;
  const expectedMode = expectedStats.mode & 0o777;
  if (
    current.isSymbolicLink() ||
    !current.isDirectory() ||
    !sameIdentity(current, expectedStats) ||
    currentMode !== expectedMode ||
    (await realpath(directory)) !== expectedReal
  ) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.UNSAFE_STATE_ENTRY,
      "strict file operation parent identity or mode changed before commit",
      { input: relPath },
    );
  }
}

async function writeFresh(file, data, mode) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  const handle = await open(
    file,
    FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | noFollow,
    mode,
  );
  try {
    await handle.writeFile(data);
    await handle.sync();
    const stats = await handle.stat();
    if (!stats.isFile() || stats.nlink !== 1) throw new Error("staging entry is not one ordinary file");
    return stats;
  } finally {
    await handle.close();
  }
}

async function syncDirectoryStrict(directory) {
  const handle = await open(directory, FS_CONSTANTS.O_RDONLY);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function inspectPublished(target, expectedBytes, expectedMode) {
  const noFollow = FS_CONSTANTS.O_NOFOLLOW ?? 0;
  const before = await lstat(target);
  if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) return null;
  const handle = await open(target, FS_CONSTANTS.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened) || !opened.isFile() || opened.nlink !== 1) return null;
    const actual = await handle.readFile();
    if (!actual.equals(expectedBytes) || (opened.mode & 0o777) !== expectedMode) return null;
    return opened;
  } finally {
    await handle.close();
  }
}

function strictFailure(kind, operation, cause, relPath, committed, verified) {
  return mechanismError(
    kind,
    `${operation} failed: ${cause?.code ?? cause?.message ?? "unknown"}`,
    {
      input: relPath,
      phase: committed ? "post-commit" : "pre-commit",
      publicationState: committed ? (verified ? "published" : "indeterminate") : "not-published",
    },
  );
}

/**
 * Creates one file without replacing any existing directory entry. The
 * parent must already exist and contain no symlink components. The returned
 * receipt is emitted only after byte/mode/identity verification and directory
 * fsync have completed.
 */
export async function publishFileExclusive(root, relPath, data, { mode = 0o644 } = {}) {
  assertWritableData(data, "publishFileExclusive");
  const normalizedMode = normalizeMode(mode);
  const bytes = bytesOf(data);
  const { targetPath, directory, directoryStats, directoryReal } = await strictTarget(root, relPath, {
    target: "absent",
  });
  const staging = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid}.${randomBytes(12).toString("hex")}.publish`,
  );
  let committed = false;
  let verified = false;
  try {
    await writeFresh(staging, bytes, normalizedMode);
    await runTestHook("beforeExclusiveCommit", { targetPath, staging, directory });
    await revalidateDirectory(directory, directoryStats, directoryReal, relPath);
    await link(staging, targetPath);
    committed = true;
    await runTestHook("afterExclusiveCommit", { targetPath, staging });
    await unlink(staging);
    const published = await inspectPublished(targetPath, bytes, normalizedMode);
    if (published === null) throw new Error("published target failed identity, byte, or mode verification");
    verified = true;
    await runTestHook("beforeExclusiveDirectorySync", { targetPath, directory });
    await syncDirectoryStrict(directory);
    return Object.freeze({
      path: targetPath,
      publicationState: "published",
      sha256: digest(bytes),
      bytes: bytes.length,
      mode: normalizedMode,
    });
  } catch (cause) {
    if (!committed && cause?.code === "EEXIST") {
      throw mechanismError(
        HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLISH_CONFLICT,
        "exclusive publication target already exists",
        { input: relPath, phase: "pre-commit", publicationState: "not-published" },
      );
    }
    throw strictFailure(
      HARNESS_ERROR_KINDS.EXCLUSIVE_PUBLICATION_FAILED,
      "exclusive publication",
      cause,
      relPath,
      committed,
      verified,
    );
  } finally {
    await unlink(staging).catch(() => {});
  }
}

/**
 * Atomically replaces one existing ordinary file. Unlike `writeFileAtomic`,
 * success is reported only after the committed target is re-opened without
 * symlink following, verified byte-for-byte and by mode, and its directory is
 * fsynced. A post-rename failure carries an explicit published/indeterminate
 * publicationState and never claims rollback.
 */
export async function replaceFileAtomic(root, relPath, data, { mode = 0o644 } = {}) {
  assertWritableData(data, "replaceFileAtomic");
  const normalizedMode = normalizeMode(mode);
  const bytes = bytesOf(data);
  const { targetPath, targetStats, targetFingerprint, directory, directoryStats, directoryReal } = await strictTarget(
    root,
    relPath,
    { target: "regular" },
  );
  const staging = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid}.${randomBytes(12).toString("hex")}.replace`,
  );
  let committed = false;
  let verified = false;
  try {
    await writeFresh(staging, bytes, normalizedMode);
    await runTestHook("beforeReplaceCommit", { targetPath, staging, directory });
    await revalidateDirectory(directory, directoryStats, directoryReal, relPath);
    const current = await snapshotRegularTarget(targetPath, targetStats);
    if (
      current === null ||
      current.mode !== targetFingerprint.mode ||
      current.bytes !== targetFingerprint.bytes ||
      current.sha256 !== targetFingerprint.sha256
    ) {
      throw new Error("replacement target changed before commit");
    }
    await rename(staging, targetPath);
    committed = true;
    await runTestHook("afterReplaceCommit", { targetPath });
    const published = await inspectPublished(targetPath, bytes, normalizedMode);
    if (published === null) throw new Error("replaced target failed identity, byte, or mode verification");
    verified = true;
    await runTestHook("beforeReplaceDirectorySync", { targetPath, directory });
    await syncDirectoryStrict(directory);
    return Object.freeze({
      path: targetPath,
      publicationState: "published",
      sha256: digest(bytes),
      bytes: bytes.length,
      mode: normalizedMode,
    });
  } catch (cause) {
    throw strictFailure(
      HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
      "atomic replacement",
      cause,
      relPath,
      committed,
      verified,
    );
  } finally {
    await unlink(staging).catch(() => {});
  }
}

/**
 * Strictly publishes one ordinary file, creating it when absent and replacing
 * it when already present, in a single no-follow operation. Symlinks and
 * directories are refused, every parent must already exist, and the target
 * fingerprint (when present) is re-verified immediately before commit.
 */
export async function publishFileOrReplace(root, relPath, data, { mode = 0o644 } = {}) {
  assertWritableData(data, "publishFileOrReplace");
  const normalizedMode = normalizeMode(mode);
  const bytes = bytesOf(data);
  const { targetPath, targetStats, targetFingerprint, directory, directoryStats, directoryReal } = await strictTarget(
    root,
    relPath,
    { target: "regular-or-absent" },
  );
  const staging = path.join(
    directory,
    `.${path.basename(targetPath)}.${process.pid}.${randomBytes(12).toString("hex")}.publish-or-replace`,
  );
  let committed = false;
  let verified = false;
  try {
    await writeFresh(staging, bytes, normalizedMode);
    await runTestHook("beforePublishOrReplaceCommit", { targetPath, staging, directory });
    await revalidateDirectory(directory, directoryStats, directoryReal, relPath);
    if (targetFingerprint !== null) {
      const current = await snapshotRegularTarget(targetPath, targetStats);
      if (
        current === null ||
        current.mode !== targetFingerprint.mode ||
        current.bytes !== targetFingerprint.bytes ||
        current.sha256 !== targetFingerprint.sha256
      ) {
        throw new Error("publication target changed before commit");
      }
    }
    await rename(staging, targetPath);
    committed = true;
    await runTestHook("afterPublishOrReplaceCommit", { targetPath });
    const published = await inspectPublished(targetPath, bytes, normalizedMode);
    if (published === null) throw new Error("published target failed identity, byte, or mode verification");
    verified = true;
    await runTestHook("beforePublishOrReplaceDirectorySync", { targetPath, directory });
    await syncDirectoryStrict(directory);
    return Object.freeze({
      path: targetPath,
      publicationState: "published",
      sha256: digest(bytes),
      bytes: bytes.length,
      mode: normalizedMode,
    });
  } catch (cause) {
    throw strictFailure(
      HARNESS_ERROR_KINDS.ATOMIC_REPLACE_FAILED,
      "atomic publication",
      cause,
      relPath,
      committed,
      verified,
    );
  } finally {
    await unlink(staging).catch(() => {});
  }
}

/** Test-only hooks. Deliberately not re-exported from the package index. */
export function __setAtomicTestHooks(hooks) {
  if (hooks !== null && (!hooks || typeof hooks !== "object" || Array.isArray(hooks))) {
    throw new TypeError("atomic test hooks must be an object or null");
  }
  testHooks = hooks;
}

/** Compatibility writer; see the module-level guarantee boundary above. */
export async function writeFileAtomic(root, relPath, data, { mode = 0o644 } = {}) {
  assertWritableData(data, "writeFileAtomic");
  let target = await resolveContained(root, relPath);
  try {
    const finalStat = await lstat(target);
    if (finalStat.isSymbolicLink()) target = await realpath(target);
  } catch {
    // Not yet existing: the lexical target is the write destination.
  }
  const dir = path.dirname(target);
  try {
    await mkdir(dir, { recursive: true });
  } catch (cause) {
    throw mechanismError(
      HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED,
      `cannot prepare contained directory: ${cause?.code ?? "unknown"}`,
      { input: relPath },
    );
  }
  const tmpPath = path.join(
    dir,
    `.${path.basename(target)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  let handle = null;
  try {
    handle = await open(tmpPath, "wx", mode);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(tmpPath, target);
  } catch (cause) {
    if (handle) await handle.close().catch(() => {});
    await removeQuiet(tmpPath);
    throw mechanismError(
      HARNESS_ERROR_KINDS.ATOMIC_WRITE_FAILED,
      `atomic write failed: ${cause?.code ?? "unknown"}`,
      { input: relPath },
    );
  }
  try {
    const dirHandle = await open(dir, "r");
    try {
      await dirHandle.sync();
    } finally {
      await dirHandle.close();
    }
  } catch {
    // Compatibility API intentionally does not claim durable directory sync.
  }
  return target;
}
